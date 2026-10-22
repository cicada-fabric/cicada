package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func localDomainSelectedTx(tx *sql.Tx, s wire.LocalDomainSelection, in HubLocalDomainNodeInput, b *NodeControlKeyBinding) (*hubLocalDomain, error) {
	p, err := readLocalDomain(tx, s.PolicyID)
	if err != nil || p == nil || p.policy.OwnerID != b.OwnerID || p.policy.Node.NodeID != b.NodeID || p.policy.Epoch != s.PolicyEpoch {
		return nil, ErrNetworkPermission
	}
	digest, err := e2ee.LocalDomainPolicyDigest(p.policy)
	if err != nil || digest != s.PolicyDigest {
		return nil, ErrNetworkPermission
	}
	if err = localDomainExpireTx(tx, p, in.At); err != nil {
		return nil, err
	}
	if err = localDomainPolicyAuthorityTx(tx, p, in.Hub, in.NodeControlPublic, in.At); err != nil {
		return nil, err
	}
	return p, nil
}

func localDomainNodeEffectTx(tx *sql.Tx, in HubLocalDomainNodeInput, rpc NodeControlRPCInput) (any, error) {
	b, err := localDomainNodeCurrentTx(tx, in, rpc)
	if err != nil {
		return nil, err
	}
	switch q := in.Body.(type) {
	case wire.LocalDomainNodeAvailable:
		return localDomainAvailableTx(tx, in, b, q)
	case wire.LocalDomainNodeJoin:
		p, err := localDomainSelectedTx(tx, q.Selection, in, b)
		if err != nil || p.policy.LocalUserScope != q.LocalUserScope {
			return nil, ErrNetworkPermission
		}
		return localDomainJoinTx(tx, in, rpc, p, q)
	case wire.LocalDomainNodeDescribe:
		p, err := localDomainSelectedTx(tx, q.Selection, in, b)
		if err != nil || p.policy.LocalUserScope != q.LocalUserScope {
			return nil, ErrNetworkPermission
		}
		return localDomainDescriptionTx(tx, p, in.At)
	case wire.LocalDomainNodeKeyPrepare:
		p, err := localDomainSelectedTx(tx, q.Selection, in, b)
		if err != nil {
			return nil, err
		}
		return localDomainKeyPrepareTx(tx, in, p, q)
	case wire.LocalDomainNodeKeyComplete:
		p, err := localDomainSelectedTx(tx, q.Selection, in, b)
		if err != nil {
			return nil, err
		}
		return localDomainKeyCompleteTx(tx, in, p, q)
	}
	return nil, ErrHubAccountRejected
}

func localDomainAvailableTx(tx *sql.Tx, in HubLocalDomainNodeInput, b *NodeControlKeyBinding, q wire.LocalDomainNodeAvailable) (any, error) {
	report, err := e2ee.VerifyLocalDomainUserReport(appNodeBindingPublic(*b), q.LocalUserReport, in.At)
	if err != nil || report.LocalUserScope != q.LocalUserScope {
		return nil, ErrHubAccountRejected
	}
	var previous string
	err = tx.QueryRow(`SELECT issued_at FROM hub_local_domain_user_reports_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, b.OwnerBindingID, b.NodeKeyEpoch).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if previous != "" {
		old, e := time.Parse(time.RFC3339Nano, previous)
		issued, ie := time.Parse(time.RFC3339Nano, report.IssuedAt)
		if e != nil || ie != nil || issued.Before(old) {
			return nil, ErrHubAccountRejected
		}
	}
	if _, err = tx.Exec(`INSERT INTO hub_local_domain_user_reports_v1 VALUES(?,?,?,?,?,?,?) ON CONFLICT(owner_binding_id,node_key_epoch) DO UPDATE SET local_user_scope=excluded.local_user_scope,report=excluded.report,issued_at=excluded.issued_at,expires_at=excluded.expires_at,observed_at=excluded.observed_at`, b.OwnerBindingID, b.NodeKeyEpoch, q.LocalUserScope, q.LocalUserReport, report.IssuedAt, report.ExpiresAt, appNodeStamp(in.At)); err != nil {
		return nil, err
	}
	result := wire.LocalDomainNodeAvailableResult{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: q.LocalUserScope, Policies: []wire.LocalDomainDescription{}, ObservedAt: appNodeStamp(in.At)}
	var id string
	err = tx.QueryRow(`SELECT policy_id FROM hub_local_domains_v1 WHERE owner_id=? AND node_id=? AND local_user_scope=? AND state='ACTIVE'`, b.OwnerID, b.NodeID, q.LocalUserScope).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := readLocalDomain(tx, id)
	if err != nil {
		return nil, err
	}
	if err = localDomainExpireTx(tx, p, in.At); err != nil {
		return nil, err
	}
	if p.state != wire.LocalDomainActive {
		return result, nil
	}
	if localDomainPolicyAuthorityTx(tx, p, in.Hub, in.NodeControlPublic, in.At) != nil {
		if err = localDomainTerminateTx(tx, p, wire.LocalDomainRevoked, "AUTHORITY_REVOKED", in.At); err != nil {
			return nil, err
		}
		return result, nil
	}
	d, err := localDomainDescriptionTx(tx, p, in.At)
	if err != nil {
		return nil, err
	}
	result.Policies = append(result.Policies, d)
	return result, nil
}
