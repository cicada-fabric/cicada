package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Callers authenticate/decrypt Packet with the registered App key before this
// entry point. Body is that exact decoded packet, not caller-supplied authority.
// Seal runs inside the writer transaction so effect and exact ciphertext receipt
// commit together. A failed seal/commit leaves neither an effect nor a counter.
type HubAppNodeAuthorityInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Device            e2ee.PublicIdentity
	Packet            []byte
	Body              any
	At                time.Time
	Original          *HubAppNodeAuthorityInput
	OriginalSeal      HubAppNodeSeal
	OriginalClient    *HubAppNodeClientInput
}
type HubAppNodeSeal func(body any) ([]byte, error)

func appNodeAuthorityFields(body any) (wire.AppNodeRequestContext, []byte, string, string, error) {
	switch v := body.(type) {
	case wire.AppNodePrepare:
		var p e2ee.OwnerAppNodePreview
		if json.Unmarshal(v.OwnerIntent, &p) != nil {
			return wire.AppNodeRequestContext{}, nil, "", "", ErrHubAccountRejected
		}
		return v.Context, v.SessionToken, wire.OperationAppNodePrepare, p.Claims.GrantID, nil
	case wire.AppNodeComplete:
		var p e2ee.OwnerAppNodeGrant
		if json.Unmarshal(v.OwnerGrant, &p) != nil {
			return wire.AppNodeRequestContext{}, nil, "", "", ErrHubAccountRejected
		}
		return v.Context, v.SessionToken, wire.OperationAppNodeComplete, p.Claims.GrantID, nil
	case wire.AppNodeStatusRequest:
		return v.Context, v.SessionToken, wire.OperationAppNodeStatus, v.GrantID, nil
	case wire.AppNodeCancel:
		return v.Context, v.SessionToken, wire.OperationAppNodeCancel, v.GrantID, nil
	case wire.AppNodeReconcileRequest:
		return v.Context, nil, wire.OperationAppNodeReconcile, v.GrantID, nil
	}
	return wire.AppNodeRequestContext{}, nil, "", "", ErrHubAccountRejected
}

func appNodeInputRoute(in HubAppNodeAuthorityInput) (wire.AppNodeRequestContext, []byte, string, string, error) {
	c, token, op, grant, err := appNodeAuthorityFields(in.Body)
	if err != nil || in.At.IsZero() || len(c.ClientNonce) != wire.NonceBytes || c.AccountEpoch == 0 || c.DeviceEpoch == 0 {
		return c, nil, "", "", ErrHubAccountRejected
	}
	p, err := wire.PreflightRequest(in.Packet, op)
	if err != nil {
		return c, nil, "", "", ErrHubAccountRejected
	}
	_, route, err := wire.RequestRoute(in.Hub, c.OwnerID, c.DeviceID, c.RequestID, op, wire.HandshakeEpoch, in.Device)
	if err != nil || route != p.Packet.Route || !reflect.DeepEqual(in.Device, p.SenderPublicIdentity) || c.HubID != in.Hub.HubID {
		return c, nil, "", "", ErrHubAccountRejected
	}
	return c, token, op, grant, nil
}

func appNodeFresh(c wire.AppNodeRequestContext, at time.Time) bool {
	issued, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	return err == nil && appNodeStamp(issued) == c.IssuedAt && !issued.After(at.Add(30*time.Second)) && at.Before(issued.Add(wire.MaxSessionRequestLifetime))
}

func appNodeCached(tx *sql.Tx, owner, device, id, operation, digest string, at time.Time) ([]byte, string, error) {
	var packet []byte
	var oldOp, oldDigest, state string
	err := tx.QueryRow(`SELECT operation,request_digest,state,response_packet FROM hub_app_node_operations_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, owner, device, id).Scan(&oldOp, &oldDigest, &state, &packet)
	if err == nil {
		if oldOp != operation || oldDigest != digest {
			return nil, "", ErrHubAccountRejected
		}
		return packet, state, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	var created string
	err = tx.QueryRow(`SELECT operation,request_digest,state,response_packet,created_at FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, owner, device, id).Scan(&oldOp, &oldDigest, &state, &packet, &created)
	if err == nil {
		if oldOp != operation || oldDigest != digest {
			return nil, "", ErrHubAccountRejected
		}
		t, e := time.Parse(time.RFC3339Nano, created)
		if e == nil && at.Before(t.Add(wire.AppNodeReadCacheLifetime)) {
			return packet, state, nil
		}
		return nil, "", nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	return nil, "", err
}

func appNodeSaveReceipt(tx *sql.Tx, c wire.AppNodeRequestContext, op, digest, state, nonce string, packet []byte, at time.Time) error {
	if len(packet) == 0 || len(packet) > wire.MaxAppNodeReceiptBytes {
		return ErrHubAccountRejected
	}
	_, err := tx.Exec(`INSERT INTO hub_app_node_operations_v1(owner_id,device_id,operation_id,operation,kind,request_digest,state,nonce_digest,response_packet,created_at) VALUES(?,?,?,?,'APP_NODE_AUTHORITY',?,?,?,?,?)`, c.OwnerID, c.DeviceID, c.RequestID, op, digest, state, nonce, packet, appNodeStamp(at))
	return err
}
func appNodeSaveRead(tx *sql.Tx, c wire.AppNodeRequestContext, op, digest, state string, packet []byte, at time.Time) error {
	if len(packet) == 0 || len(packet) > wire.MaxPacketBytes {
		return ErrHubAccountRejected
	}
	// Parse dates in Go rather than compare variable-precision RFC3339 strings.
	rows, err := tx.Query(`SELECT operation_id,created_at FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=? ORDER BY rowid DESC`, c.OwnerID, c.DeviceID)
	if err != nil {
		return err
	}
	var drop []string
	kept := 0
	for rows.Next() {
		var id, stamp string
		if err = rows.Scan(&id, &stamp); err != nil {
			break
		}
		t, e := time.Parse(time.RFC3339Nano, stamp)
		if e != nil || !at.Before(t.Add(wire.AppNodeReadCacheLifetime)) || kept >= wire.MaxAppNodeReadCacheEntriesPerDevice-1 || id == c.RequestID {
			drop = append(drop, id)
		} else {
			kept++
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	for _, id := range drop {
		if _, err = tx.Exec(`DELETE FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, id); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO hub_app_node_reads_v1(owner_id,device_id,operation_id,operation,request_digest,state,response_packet,created_at) VALUES(?,?,?,?,?,?,?,?)`, c.OwnerID, c.DeviceID, c.RequestID, op, digest, state, packet, appNodeStamp(at))
	return err
}

func appNodeNonce(tx *sql.Tx, c wire.AppNodeRequestContext) (string, error) {
	digest := AccountDigest("client-nonce", c.ClientNonce)
	used, err := hubAccountNonceUsed(tx, c.AccountID, c.DeviceID, digest)
	if err != nil {
		return "", err
	}
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_app_node_operations_v1 WHERE owner_id=? AND device_id=? AND nonce_digest=?`, c.OwnerID, c.DeviceID, digest).Scan(&n); err != nil {
		return "", err
	}
	if used || n != 0 {
		return "", ErrHubAccountRejected
	}
	return digest, nil
}

func (s *Store) ProcessHubAppNodeAuthority(in HubAppNodeAuthorityInput, seal HubAppNodeSeal) ([]byte, error) {
	if s.requireOwnerSetupStartupAllowed() != nil || seal == nil {
		return nil, ErrHubAccountRejected
	}
	c, token, op, _, err := appNodeInputRoute(in)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := appNodeActor(tx, in.Hub, c.DeviceID, in.Device, token, in.At)
	if err != nil {
		return nil, err
	}
	if c.AccountID != a.scope.AccountID || c.OwnerID != a.scope.OwnerID || c.Origin != a.scope.Origin {
		return nil, ErrHubAccountRejected
	}
	if op != wire.OperationAppNodeStatus && op != wire.OperationAppNodeReconcile {
		if err = appNodeRefresh(tx, a, in.At); err != nil {
			return nil, err
		}
	}
	packet, err := appNodeAuthority(tx, a, in, seal, false)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func appNodeAuthority(tx *sql.Tx, a *hubAppNodeActor, in HubAppNodeAuthorityInput, seal HubAppNodeSeal, fence bool) ([]byte, error) {
	c, _, op, grantID, err := appNodeInputRoute(in)
	if err != nil {
		return nil, err
	}
	digest := wire.AppNodePacketDigest(in.Packet)
	if packet, _, err := appNodeCached(tx, c.OwnerID, c.DeviceID, c.RequestID, op, digest, in.At); err != nil || len(packet) > 0 {
		return packet, err
	}
	result := func(state, code string) (wire.AppNodeResult, error) {
		snap, e := appNodeSnapshot(tx, a, grantID, in.At)
		return wire.AppNodeResult{Format: wire.AppNodeResultFormat, Operation: op, RequestID: c.RequestID, RequestPacketDigest: digest, State: state, ErrorCode: code, Authority: snap, ObservedAt: appNodeStamp(in.At)}, e
	}
	nonce := ""
	finish := func(body any, state string, read bool) ([]byte, error) {
		packet, e := seal(body)
		if e != nil {
			return nil, e
		}
		if read {
			e = appNodeSaveRead(tx, c, op, digest, state, packet, in.At)
		} else {
			e = appNodeSaveReceipt(tx, c, op, digest, state, nonce, packet, in.At)
		}
		return packet, e
	}
	reject := func(code string) ([]byte, error) {
		v, e := result(wire.AppNodeRejectedFenced, code)
		if e != nil {
			return nil, e
		}
		v.Authority.AllowedOperations = []string{}
		v.Authority.RemainingConfirmations = 0
		return finish(v, wire.AppNodeRejectedFenced, false)
	}
	if op == wire.OperationAppNodeReconcile {
		return appNodeReconcile(tx, a, in, seal)
	}
	if op == wire.OperationAppNodeStatus {
		v, e := result(wire.AppNodeCompleted, "")
		if e != nil {
			return nil, e
		}
		if c.AccountEpoch != a.scope.AccountEpoch || c.DeviceEpoch != a.scope.DeviceEpoch {
			v.Authority.LoginRequired = true
			v.Authority.AllowedOperations = []string{}
			v.Authority.RemainingConfirmations = 0
		}
		if fence || !appNodeFresh(c, in.At) {
			v.State, v.ErrorCode = wire.AppNodeReadExpired, wire.AppNodeReadExpired
			v.Authority.AllowedOperations = []string{}
			v.Authority.RemainingConfirmations = 0
		} else if v.Authority.State == wire.AppNodeActive && !v.Authority.LoginRequired {
			v.Node, e = appNodeObservation(tx, a, v.Authority.ConfirmationProvenanceID, in.NodeControlPublic, in.At)
			if e != nil {
				return nil, e
			}
		}
		return finish(v, v.State, true)
	}
	nonce, err = appNodeNonce(tx, c)
	if err != nil {
		nonce = ""
		return reject("REPLAY_CONFLICT")
	}
	if fence {
		return reject("INVALID_REQUEST")
	}
	if !appNodeFresh(c, in.At) {
		return reject("PROOF_EXPIRED")
	}
	if !a.source {
		return reject("ROOT_UNAVAILABLE")
	}
	if c.AccountEpoch != a.scope.AccountEpoch || c.DeviceEpoch != a.scope.DeviceEpoch {
		return reject("SCOPE_MISMATCH")
	}
	if a.session == nil {
		return reject("SESSION_REQUIRED")
	}
	h, err := appNodeHead(tx, c.OwnerID, c.DeviceID)
	if err != nil {
		return nil, err
	}
	if h.version >= math.MaxInt64 {
		return reject("AUTHORITY_CONFLICT")
	}
	switch req := in.Body.(type) {
	case wire.AppNodePrepare:
		intent, e := e2ee.VerifyOwnerAppNodePreview(a.scope.OwnerPublic, req.OwnerIntent, in.At)
		if e != nil || wire.ValidateAppNodePreviewClaims(intent, in.Hub, in.At) != nil || !appNodeScopeCurrent(a, intent.Scope) || intent.Scope.HeadVersion != h.version || intent.RequestID != c.RequestID || intent.Nonce != hex.EncodeToString(c.ClientNonce) || intent.IssuedAt != c.IssuedAt {
			return reject("SCOPE_MISMATCH")
		}
		var pending int
		if e = tx.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1 WHERE owner_id=? AND device_id=? AND state='PREPARED'`, c.OwnerID, c.DeviceID).Scan(&pending); e != nil {
			return nil, e
		}
		if pending > 0 {
			return reject("AUTHORITY_CONFLICT")
		}
		claims := e2ee.OwnerAppNodeGrantClaims{Scope: intent.Scope, GrantID: intent.GrantID, ExpectedHeadVersion: h.version, PrepareRequestID: c.RequestID, PreparePacketDigest: digest, PreviewProofDigest: wire.AppNodeProofDigest(req.OwnerIntent), ReadNodeStatus: true, PreparedAt: appNodeStamp(in.At), LeaseExpiresAt: appNodeStamp(in.At.Add(wire.AppNodeLeaseLifetime))}
		claims.Scope.HeadVersion = h.version + 1
		serverNonce, e := wire.NewNonce()
		if e != nil {
			return nil, e
		}
		claims.ServerNonce = hex.EncodeToString(serverNonce)
		proofEnd := in.At.Add(wire.MaxAppNodeProofLifetime)
		sessionEnd, _ := time.Parse(time.RFC3339Nano, a.session.ExpiresAt)
		if sessionEnd.Before(proofEnd) {
			proofEnd = sessionEnd
		}
		switch req.Target.Kind {
		case wire.AppNodeTargetInitial:
			if intent.Purpose != e2ee.OwnerAppNodePreviewPurpose || req.Target.PreviousGrantID != "" || h.provenance != "" {
				return reject("AUTHORITY_CONFLICT")
			}
			if h.latest != "" {
				old, e := appNodeGrant(tx, c.OwnerID, c.DeviceID, h.latest)
				if e != nil {
					return nil, e
				}
				if old == nil || old.provenance != "" || !appNodeSameSecurity(a.scope, old.claims.Scope) || (old.state != wire.AppNodeExpired && old.state != wire.AppNodeSessionEnded && !(old.state == wire.AppNodeCancelled && old.reason == "SELF_CANCEL")) {
					return reject("AUTHORITY_CONFLICT")
				}
			}
			code, e := wire.AppNodeCodeDigest(c.HubID, req.Target.Code)
			if e != nil || code != intent.CodeDigest {
				return reject("SCOPE_MISMATCH")
			}
			n, e := appNodeCandidate(tx, code, in.Hub, in.NodeControlPublic, in.At)
			if e != nil {
				return reject("CANDIDATE_UNAVAILABLE")
			}
			claims.Purpose, claims.Profile, claims.Candidate, claims.ConfirmationLimit, claims.AllowedOperations = e2ee.OwnerAppNodeGrantPurpose, wire.AppNodeProfileInitial, n, 1, wire.AppNodeAllowedOperations()
			end, _ := time.Parse(time.RFC3339Nano, n.ExpiresAt)
			if end.Before(proofEnd) {
				proofEnd = end
			}
		case wire.AppNodeTargetPrevious:
			if intent.Purpose != e2ee.OwnerAppNodeStatusPreviewPurpose || req.Target.Code != "" || req.Target.PreviousGrantID != h.latest || intent.PreviousGrantID != h.latest || h.provenance == "" {
				return reject("AUTHORITY_CONFLICT")
			}
			old, e := appNodeGrant(tx, c.OwnerID, c.DeviceID, h.latest)
			if e != nil {
				return nil, e
			}
			if old == nil || !appNodeSameSecurity(a.scope, old.claims.Scope) || old.state == wire.AppNodePrepared || (old.state == wire.AppNodeRevoked) || (old.state == wire.AppNodeCancelled && old.reason != "SELF_CANCEL") {
				return reject("AUTHORITY_REVOKED")
			}
			if old.state != wire.AppNodeExpired && old.state != wire.AppNodeSessionEnded && !(old.state == wire.AppNodeCancelled && old.reason == "SELF_CANCEL") && !(old.state == wire.AppNodeActive && old.claims.Scope.AccountSessionID != a.session.ID) {
				return reject("AUTHORITY_CONFLICT")
			}
			binding, e := appNodeProvenBinding(tx, a, h.provenance, in.NodeControlPublic)
			if e != nil {
				return reject("CANDIDATE_CHANGED")
			}
			public := appNodeBindingPublic(*binding)
			claims.Purpose, claims.Profile, claims.PreviousGrantID, claims.ConfirmationProvenanceID, claims.Binding, claims.AllowedOperations = e2ee.OwnerAppNodeStatusGrantPurpose, wire.AppNodeProfileStatus, h.latest, h.provenance, &public, wire.AppNodeStatusAllowedOperations()
		default:
			return reject("INVALID_REQUEST")
		}
		claims.ProofExpiresAt = appNodeStamp(proofEnd)
		if wire.ValidateAppNodeGrantClaims(claims, in.Hub, in.At) != nil {
			return reject("INVALID_REQUEST")
		}
		raw, e := json.Marshal(claims)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(`INSERT INTO hub_app_node_grants_v1(grant_id,account_id,owner_id,device_id,claims_json,state,remaining,provenance_id,created_at) VALUES(?,?,?,?,?,'PREPARED',?,?,?)`, claims.GrantID, c.AccountID, c.OwnerID, c.DeviceID, string(raw), claims.ConfirmationLimit, claims.ConfirmationProvenanceID, appNodeStamp(in.At)); e != nil {
			return nil, e
		}
		return finish(wire.AppNodeChallenge{Format: wire.AppNodeChallengeFormat, RequestID: c.RequestID, RequestPacketDigest: digest, Claims: claims, ObservedAt: appNodeStamp(in.At)}, wire.AppNodeCompleted, false)
	case wire.AppNodeComplete:
		claims, e := e2ee.VerifyOwnerAppNodeGrant(a.scope.OwnerPublic, req.OwnerGrant, in.At)
		if e != nil || wire.ValidateAppNodeGrantClaims(claims, in.Hub, in.At) != nil || !appNodeScopeCurrent(a, claims.Scope) {
			return reject("SCOPE_MISMATCH")
		}
		g, e := appNodeGrant(tx, c.OwnerID, c.DeviceID, claims.GrantID)
		if e != nil {
			return nil, e
		}
		if g == nil || g.state != wire.AppNodePrepared || !reflect.DeepEqual(g.claims, claims) || claims.ExpectedHeadVersion != h.version {
			return reject("AUTHORITY_CONFLICT")
		}
		if claims.Candidate != nil {
			candidate, e := appNodeCandidate(tx, claims.Candidate.CodeDigest, in.Hub, in.NodeControlPublic, in.At)
			if e != nil || !reflect.DeepEqual(candidate, claims.Candidate) {
				return reject("CANDIDATE_CHANGED")
			}
		} else {
			binding, e := appNodeProvenBinding(tx, a, claims.ConfirmationProvenanceID, in.NodeControlPublic)
			if e != nil || !reflect.DeepEqual(appNodeBindingPublic(*binding), *claims.Binding) {
				return reject("CANDIDATE_CHANGED")
			}
		}
		if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='REVOKED',reason='SUPERSEDED' WHERE owner_id=? AND device_id=? AND state='ACTIVE'`, c.OwnerID, c.DeviceID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='ACTIVE',owner_proof=? WHERE grant_id=? AND state='PREPARED'`, req.OwnerGrant, claims.GrantID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(`INSERT INTO hub_app_node_heads_v1(owner_id,device_id,head_version,latest_grant_id,provenance_id) VALUES(?,?,?,?,?) ON CONFLICT(owner_id,device_id) DO UPDATE SET head_version=excluded.head_version,latest_grant_id=excluded.latest_grant_id,provenance_id=excluded.provenance_id`, c.OwnerID, c.DeviceID, claims.Scope.HeadVersion, claims.GrantID, claims.ConfirmationProvenanceID); e != nil {
			return nil, e
		}
	case wire.AppNodeCancel:
		if req.ExpectedHeadVersion != h.version {
			return reject("AUTHORITY_CONFLICT")
		}
		g, e := appNodeGrant(tx, c.OwnerID, c.DeviceID, req.GrantID)
		if e != nil {
			return nil, e
		}
		if g == nil || !appNodeScopeCurrent(a, g.claims.Scope) || (g.state != wire.AppNodeActive && g.state != wire.AppNodePrepared) {
			return reject("AUTHORITY_CONFLICT")
		}
		if g.state == wire.AppNodeActive {
			if h.latest != req.GrantID {
				return reject("AUTHORITY_CONFLICT")
			}
			if _, e = tx.Exec(`UPDATE hub_app_node_heads_v1 SET head_version=head_version+1 WHERE owner_id=? AND device_id=? AND head_version=?`, c.OwnerID, c.DeviceID, h.version); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='CANCELLED',reason='HEAD_CANCELLED' WHERE owner_id=? AND device_id=? AND state='PREPARED'`, c.OwnerID, c.DeviceID); e != nil {
				return nil, e
			}
		}
		if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='CANCELLED',reason='SELF_CANCEL' WHERE grant_id=?`, req.GrantID); e != nil {
			return nil, e
		}
	default:
		return reject("INVALID_REQUEST")
	}
	v, err := result(wire.AppNodeCompleted, "")
	if err != nil {
		return nil, err
	}
	return finish(v, wire.AppNodeCompleted, false)
}
