package store

import (
	"database/sql"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func localDomainOwnerActivateTx(tx *sql.Tx, a *hubAppNodeActor, in HubLocalDomainInput, c wire.AppNodeRequestContext, claims e2ee.OwnerLocalDomainRequestClaims) (any, string, error) {
	q, ok := in.Body.(wire.LocalDomainActivate)
	if !ok {
		return nil, "", ErrHubAccountRejected
	}
	p, err := readLocalDomain(tx, claims.PolicyID)
	if err != nil || p == nil || p.policy.OwnerID != a.scope.OwnerID || p.state != wire.LocalDomainPrepared || p.revision != claims.ExpectedRevision || p.policy.Epoch != claims.PolicyEpoch || !appNodeBefore(in.At, p.proofExpires) {
		return nil, "", ErrHubAccountRejected
	}
	digest, err := e2ee.LocalDomainPolicyDigest(p.policy)
	if err != nil || digest != claims.PolicyDigest {
		return nil, "", ErrHubAccountRejected
	}
	policy, err := e2ee.VerifyOwnerLocalDomainPolicy(a.scope.OwnerPublic, q.PolicyProof, in.At)
	if err != nil || !reflect.DeepEqual(policy, p.policy) || localDomainRootNodeAuthorityTx(tx, policy, in.Hub, in.NodeControlPublic, in.At) != nil {
		return nil, "", ErrHubAccountRejected
	}
	// The original report and prepare intent fix the nonrenewable activation
	// deadline; new reports or account logins cannot extend this challenge.
	if _, err = e2ee.VerifyLocalDomainUserReport(policy.Node, p.report, in.At); err != nil {
		return nil, "", ErrHubAccountRejected
	}
	var trust string
	if tx.QueryRow(`SELECT trust_domain_id FROM principals WHERE id=? AND owner_id=id AND kind='human' AND status='active'`, policy.OwnerID).Scan(&trust) != nil || trust == "" {
		return nil, "", ErrHubAccountRejected
	}
	if policy.CreateNetwork {
		if _, err = createNetworkTx(tx, Network{ID: policy.NetworkID, HubID: policy.HubID, OwnerID: policy.OwnerID, Name: policy.NetworkName, State: NetworkStateActive}, in.At); err != nil {
			return nil, "", err
		}
	} else {
		var count int
		if tx.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=? AND hub_id=? AND owner_id=? AND state='ACTIVE'`, policy.NetworkID, policy.HubID, policy.OwnerID).Scan(&count) != nil || count != 1 {
			return nil, "", ErrHubAccountRejected
		}
	}
	if _, err = insertGroupWithOwnerMembershipTx(tx, Group{ID: policy.GroupID, NetworkID: policy.NetworkID, OwnerPrincipalID: policy.OwnerID, TrustDomainID: trust, Name: policy.GroupName, State: GroupStateActive, ContextPolicy: "group_scoped", Purpose: "Explicit Node/user local collaboration domain", Revision: 1, Version: 1}, in.At, policy.ExpiresAt); err != nil {
		return nil, "", err
	}
	updated, err := tx.Exec(`UPDATE hub_local_domains_v1 SET state='ACTIVE',revision=revision+1,policy_proof=? WHERE policy_id=? AND state='PREPARED' AND revision=? AND policy_proof IS NULL`, q.PolicyProof, policy.PolicyID, p.revision)
	if err != nil {
		return nil, "", err
	}
	if n, e := updated.RowsAffected(); e != nil || n != 1 {
		return nil, "", ErrHubAccountRejected
	}
	p.state = wire.LocalDomainActive
	p.revision++
	p.proof = append([]byte(nil), q.PolicyProof...)
	d, err := localDomainDescriptionTx(tx, p, in.At)
	if err != nil {
		return nil, "", err
	}
	r := localDomainResult(in, c, wire.OperationLocalDomainActivate, wire.AppNodeCompleted, "", p)
	r.Description = &d
	return r, policy.PolicyID, nil
}

func localDomainOwnerRevokeTx(tx *sql.Tx, a *hubAppNodeActor, in HubLocalDomainInput, c wire.AppNodeRequestContext, claims e2ee.OwnerLocalDomainRequestClaims) (any, string, error) {
	p, err := readLocalDomain(tx, claims.PolicyID)
	if err != nil || p == nil || p.policy.OwnerID != a.scope.OwnerID || p.policy.Epoch != claims.PolicyEpoch || p.revision != claims.ExpectedRevision {
		return nil, "", ErrHubAccountRejected
	}
	digest, err := e2ee.LocalDomainPolicyDigest(p.policy)
	if err != nil || digest != claims.PolicyDigest {
		return nil, "", ErrHubAccountRejected
	}
	state, reason := wire.LocalDomainRevoked, "OWNER_REVOKED"
	if len(p.proof) == 0 {
		state, reason = wire.LocalDomainExpired, "OWNER_CANCELLED"
	}
	if err = localDomainTerminateTx(tx, p, state, reason, in.At); err != nil {
		return nil, "", err
	}
	d, err := localDomainDescriptionTx(tx, p, in.At)
	if err != nil {
		return nil, "", err
	}
	r := localDomainResult(in, c, wire.OperationLocalDomainRevoke, wire.AppNodeCompleted, "", p)
	r.Description = &d
	return r, p.policy.PolicyID, nil
}

func localDomainOwnerStatusTx(tx *sql.Tx, in HubLocalDomainInput, c wire.AppNodeRequestContext, claims e2ee.OwnerLocalDomainRequestClaims, nonce string, seal HubLocalDomainSeal) (localDomainReceipt, error) {
	r := localDomainResult(in, c, wire.OperationLocalDomainStatus, wire.AppNodeCompleted, "", nil)
	if claims.PolicyID != "" {
		p, err := readLocalDomain(tx, claims.PolicyID)
		if err != nil {
			return localDomainReceipt{}, err
		}
		if p == nil || p.policy.OwnerID != c.OwnerID {
			return localDomainOwnerFenceTx(tx, in, c, wire.OperationLocalDomainStatus, nonce, "READ_EXPIRED", wire.AppNodeReadExpired, seal)
		}
		if err = localDomainExpireTx(tx, p, in.At); err != nil {
			return localDomainReceipt{}, err
		}
		if p.state == wire.LocalDomainActive && localDomainPolicyAuthorityTx(tx, p, in.Hub, in.NodeControlPublic, in.At) != nil {
			if err = localDomainTerminateTx(tx, p, wire.LocalDomainRevoked, "AUTHORITY_REVOKED", in.At); err != nil {
				return localDomainReceipt{}, err
			}
		}
		d, err := localDomainDescriptionTx(tx, p, in.At)
		if err != nil {
			return localDomainReceipt{}, err
		}
		r.PolicyID = p.policy.PolicyID
		r.PolicyEpoch = p.policy.Epoch
		r.Description = &d
	} else {
		r.NodeID = claims.NodeID
		rows, err := tx.Query(`SELECT policy_id FROM hub_local_domains_v1 WHERE owner_id=? AND node_id=? AND policy_id>? ORDER BY policy_id LIMIT 65`, c.OwnerID, claims.NodeID, claims.Cursor)
		if err != nil {
			return localDomainReceipt{}, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		re := rows.Err()
		rows.Close()
		if err != nil {
			return localDomainReceipt{}, err
		}
		if re != nil {
			return localDomainReceipt{}, re
		}
		var candidates []wire.LocalDomainDescription
		for _, id := range ids {
			p, e := readLocalDomain(tx, id)
			if e != nil {
				return localDomainReceipt{}, e
			}
			if e = localDomainExpireTx(tx, p, in.At); e != nil {
				return localDomainReceipt{}, e
			}
			if p.state == wire.LocalDomainActive && localDomainPolicyAuthorityTx(tx, p, in.Hub, in.NodeControlPublic, in.At) != nil {
				if e = localDomainTerminateTx(tx, p, wire.LocalDomainRevoked, "AUTHORITY_REVOKED", in.At); e != nil {
					return localDomainReceipt{}, e
				}
			}
			d, e := localDomainDescriptionTx(tx, p, in.At)
			if e != nil {
				return localDomainReceipt{}, e
			}
			candidates = append(candidates, d)
		}
		r, err = wire.BuildLocalDomainStatusPage(r, candidates, false)
		if err != nil {
			return localDomainReceipt{}, err
		}
	}
	packet, err := seal(r)
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = localDomainOwnerSaveTx(tx, c, wire.OperationLocalDomainStatus, r.PolicyID, wire.LocalDomainPacketDigest(in.Packet), nonce, wire.AppNodeCompleted, packet, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: wire.AppNodeCompleted, policy: r.PolicyID}, nil
}

func localDomainOwnerReconcileTx(tx *sql.Tx, a *hubAppNodeActor, in HubLocalDomainInput, seal HubLocalDomainSeal) (localDomainReceipt, error) {
	q, ok := in.Body.(wire.LocalDomainReconcileRequest)
	if !ok || in.Original == nil || in.OriginalSeal == nil || !localDomainFresh(q.Context, in.At) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	original := *in.Original
	original.At = in.At
	original.Now = nil
	op, c, _, _, err := localDomainInput(original)
	if err != nil || op == wire.OperationLocalDomainReconcile || c.OwnerID != a.scope.OwnerID || c.DeviceID != a.scope.DeviceID || c.AccountID != a.scope.AccountID || !reflect.DeepEqual(original.Device, in.Device) || wire.LocalDomainPacketDigest(q.OriginalPacket) != wire.LocalDomainPacketDigest(original.Packet) {
		return localDomainReceipt{}, ErrHubAccountRejected
	}
	r, err := localDomainOwnerProcessTx(tx, a, original, in.OriginalSeal, true)
	if err != nil {
		return localDomainReceipt{}, err
	}
	body := wire.LocalDomainReconciled{Format: wire.LocalDomainFormat, RequestID: q.Context.RequestID, RequestPacketDigest: wire.LocalDomainPacketDigest(in.Packet), HubID: q.Context.HubID, OwnerID: q.Context.OwnerID, DeviceID: q.Context.DeviceID, OriginalOperation: op, OriginalRequestID: c.RequestID, OriginalPacketDigest: wire.LocalDomainPacketDigest(original.Packet), State: r.state, ReceiptPacket: r.packet, ObservedAt: appNodeStamp(in.At)}
	packet, err := seal(body)
	if err != nil {
		return localDomainReceipt{}, err
	}
	if err = localDomainOwnerSaveTx(tx, q.Context, wire.OperationLocalDomainReconcile, r.policy, wire.LocalDomainPacketDigest(in.Packet), AccountDigest("local-domain-owner-nonce", q.Context.ClientNonce), r.state, packet, in.At); err != nil {
		return localDomainReceipt{}, err
	}
	return localDomainReceipt{packet: packet, state: r.state, policy: r.policy}, nil
}
