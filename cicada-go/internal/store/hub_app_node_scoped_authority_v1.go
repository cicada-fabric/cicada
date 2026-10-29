package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
type HubAppNodeScopedAuthorityInput struct {
	Hub               wire.HubIdentity
	NodeControlPublic e2ee.PublicIdentity
	Device            e2ee.PublicIdentity
	Packet            []byte
	Body              any
	At                time.Time
	// Now is a trusted process clock sampled only after writer/Tx acquisition.
	// Nil preserves the explicit At seam used by deterministic Store fixtures.
	Now            func() time.Time
	Original       *HubAppNodeScopedAuthorityInput
	OriginalSeal   HubAppNodeScopedSeal
	OriginalClient *HubAppNodeClientInput
}
type HubAppNodeScopedSeal func(body any) ([]byte, error)

func appNodeScopedAuthorityFields(body any) (wire.AppNodeRequestContext, []byte, string, string, error) {
	switch v := body.(type) {
	case wire.AppNodeScopedPrepare:
		var p e2ee.OwnerAppNodeScopedPreview
		if json.Unmarshal(v.OwnerIntent, &p) != nil {
			return wire.AppNodeRequestContext{}, nil, "", "", ErrHubAccountRejected
		}
		return v.Context, v.SessionToken, wire.OperationAppNodeScopedPrepare, p.Claims.GrantID, nil
	case wire.AppNodeScopedComplete:
		var p e2ee.OwnerAppNodeScopedGrant
		if json.Unmarshal(v.OwnerGrant, &p) != nil {
			return wire.AppNodeRequestContext{}, nil, "", "", ErrHubAccountRejected
		}
		return v.Context, v.SessionToken, wire.OperationAppNodeScopedComplete, p.Claims.GrantID, nil
	case wire.AppNodeScopedStatus:
		return v.Context, v.SessionToken, wire.OperationAppNodeScopedStatus, v.GrantID, nil
	case wire.AppNodeScopedCancel:
		return v.Context, v.SessionToken, wire.OperationAppNodeScopedCancel, v.GrantID, nil
	case wire.AppNodeScopedReconcile:
		return v.Context, nil, wire.OperationAppNodeScopedReconcile, v.GrantID, nil
	}
	return wire.AppNodeRequestContext{}, nil, "", "", ErrHubAccountRejected
}

func appNodeScopedInputRoute(in HubAppNodeScopedAuthorityInput) (wire.AppNodeRequestContext, []byte, string, string, error) {
	c, token, op, grant, err := appNodeScopedAuthorityFields(in.Body)
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

func (s *Store) ProcessHubAppNodeScopedAuthority(in HubAppNodeScopedAuthorityInput, seal HubAppNodeScopedSeal) ([]byte, error) {
	if s.requireOwnerSetupStartupAllowed() != nil || seal == nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = appNodeScopedWriterLock(tx); err != nil {
		return nil, err
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	c, token, op, _, err := appNodeScopedInputRoute(in)
	if err != nil {
		return nil, err
	}
	base, err := appNodeActor(tx, in.Hub, c.DeviceID, in.Device, token, in.At)
	if err != nil {
		return nil, err
	}
	if c.AccountID != base.scope.AccountID || c.OwnerID != base.scope.OwnerID || c.Origin != base.scope.Origin {
		return nil, ErrHubAccountRejected
	}
	node, err := appNodeScopedInputNode(tx, in)
	if err != nil {
		return nil, err
	}
	a := appNodeScopedActorFromBase(base, node)
	if q, ok := in.Body.(wire.AppNodeScopedStatus); ok && q.Target.CandidateCode != "" && (!base.source || base.session == nil || c.AccountEpoch != base.scope.AccountEpoch || c.DeviceEpoch != base.scope.DeviceEpoch) {
		return nil, ErrHubAccountRejected
	}
	if op != wire.OperationAppNodeScopedStatus && op != wire.OperationAppNodeScopedReconcile {
		if err = appNodeRefresh(tx, base, in.At); err != nil {
			return nil, err
		}
	}
	packet, err := appNodeScopedAuthority(tx, a, in, seal, false)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

func appNodeScopedAuthority(tx *sql.Tx, a *hubAppNodeScopedActor, in HubAppNodeScopedAuthorityInput, seal HubAppNodeScopedSeal, fence bool) ([]byte, error) {
	c, _, op, grantID, err := appNodeScopedInputRoute(in)
	if err != nil {
		return nil, err
	}
	node, err := appNodeScopedInputNode(tx, in)
	if err != nil || node != a.scope.AuthorityNodeID {
		return nil, ErrHubAccountRejected
	}
	digest := wire.AppNodeScopedPacketDigest(in.Packet)
	if packet, _, err := appNodeCached(tx, c.OwnerID, c.DeviceID, c.RequestID, op, digest, in.At); err != nil || len(packet) > 0 {
		return packet, err
	}
	result := func(state, code string) (wire.AppNodeScopedResult, error) {
		snap, e := appNodeScopedSnapshot(tx, a, grantID, in.At)
		return wire.AppNodeScopedResult{Format: wire.AppNodeScopedResultFormat, Operation: op, RequestID: c.RequestID, RequestPacketDigest: digest, State: state, ErrorCode: code, Authority: snap, ObservedAt: appNodeStamp(in.At)}, e
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
		v, e := result(wire.AppNodeScopedRejectedFenced, code)
		if e != nil {
			return nil, e
		}
		v.Authority.AllowedOperations = []string{}
		v.Authority.RemainingConfirmations = 0
		return finish(v, wire.AppNodeScopedRejectedFenced, false)
	}
	if op == wire.OperationAppNodeScopedReconcile {
		return appNodeScopedReconcile(tx, a, in, seal)
	}
	if op == wire.OperationAppNodeScopedStatus {
		v, e := result(wire.AppNodeScopedCompleted, "")
		if e != nil {
			return nil, e
		}
		if c.AccountEpoch != a.scope.AccountEpoch || c.DeviceEpoch != a.scope.DeviceEpoch {
			v.Authority.LoginRequired = true
			v.Authority.AllowedOperations = []string{}
			v.Authority.RemainingConfirmations = 0
		}
		if fence || !appNodeFresh(c, in.At) {
			v.State, v.ErrorCode = wire.AppNodeScopedReadExpired, wire.AppNodeScopedReadExpired
			v.Authority.AllowedOperations = []string{}
			v.Authority.RemainingConfirmations = 0
		} else if v.Authority.State == wire.AppNodeScopedActive && !v.Authority.LoginRequired {
			v.Node, e = appNodeScopedObservation(tx, a, v.Authority.ConfirmationProvenanceID, in.NodeControlPublic, in.At)
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
	if err := nodePairClientSlotGuardTx(tx, c.OwnerID, c.DeviceID, a.counters.SessionEpoch); err != nil {
		return reject("AUTHORITY_CONFLICT")
	}
	h, err := appNodeScopedHead(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID)
	if err != nil {
		return nil, err
	}
	if h.version >= math.MaxInt64 {
		return reject("AUTHORITY_CONFLICT")
	}
	switch req := in.Body.(type) {
	case wire.AppNodeScopedPrepare:
		intent, e := e2ee.VerifyOwnerAppNodeScopedPreview(a.scope.OwnerPublic, req.OwnerIntent, in.At)
		if e != nil || wire.ValidateAppNodeScopedPreviewClaims(intent, in.Hub, in.At) != nil || !appNodeScopedScopeCurrent(a, intent.Scope) || intent.Scope.HeadVersion != h.version || intent.RequestID != c.RequestID || intent.Nonce != hex.EncodeToString(c.ClientNonce) || intent.IssuedAt != c.IssuedAt {
			return reject("SCOPE_MISMATCH")
		}
		var pending int
		if e = tx.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1 WHERE owner_id=? AND device_id=? AND state='PREPARED'`, c.OwnerID, c.DeviceID).Scan(&pending); e != nil {
			return nil, e
		}
		if pending > 0 {
			return reject("AUTHORITY_CONFLICT")
		}
		claims := e2ee.OwnerAppNodeScopedGrantClaims{Scope: intent.Scope, GrantID: intent.GrantID, ExpectedHeadVersion: h.version, PrepareRequestID: c.RequestID, PreparePacketDigest: digest, PreviewProofDigest: wire.AppNodeScopedProofDigest(req.OwnerIntent), ReadNodeStatus: true, PreparedAt: appNodeStamp(in.At), LeaseExpiresAt: appNodeStamp(in.At.Add(wire.AppNodeScopedLeaseLifetime))}
		claims.Scope.HeadVersion = h.version + 1
		serverNonce, e := wire.NewNonce()
		if e != nil {
			return nil, e
		}
		claims.ServerNonce = hex.EncodeToString(serverNonce)
		proofEnd := in.At.Add(wire.MaxAppNodeScopedProofLifetime)
		sessionEnd, _ := time.Parse(time.RFC3339Nano, a.session.ExpiresAt)
		if sessionEnd.Before(proofEnd) {
			proofEnd = sessionEnd
		}
		switch req.Target.Kind {
		case wire.AppNodeScopedTargetInitial:
			if intent.Purpose != e2ee.OwnerAppNodeScopedPreviewPurpose || req.Target.PreviousGrantID != "" || h.provenance != "" {
				return reject("AUTHORITY_CONFLICT")
			}
			if h.latest != "" {
				old, e := appNodeScopedGrant(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, h.latest)
				if e != nil {
					return nil, e
				}
				if old == nil || old.provenance != "" || !appNodeScopedSameSecurity(a.scope, old.claims.Scope) || (old.state != wire.AppNodeScopedExpired && old.state != wire.AppNodeScopedSessionEnded && !(old.state == wire.AppNodeScopedCancelled && old.reason == "SELF_CANCEL")) {
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
			allowed, e := appNodeCandidateNamespaceAllowed(tx, n, "NODE_V1")
			if e != nil || !allowed {
				return reject("CANDIDATE_UNAVAILABLE")
			}
			allowed, e = appNodeInitialNamespaceAllowed(tx, c.OwnerID, c.DeviceID, n.NodeID, "NODE_V1")
			if e != nil {
				return nil, e
			}
			if !allowed {
				return reject("AUTHORITY_CONFLICT")
			}
			if n.NodeID != a.scope.AuthorityNodeID {
				return reject("SCOPE_MISMATCH")
			}
			claims.Purpose, claims.Profile, claims.Candidate, claims.ConfirmationLimit, claims.AllowedOperations = e2ee.OwnerAppNodeScopedGrantPurpose, wire.AppNodeScopedProfileInitial, n, 1, wire.AppNodeScopedAllowedOperations()
			end, _ := time.Parse(time.RFC3339Nano, n.ExpiresAt)
			if end.Before(proofEnd) {
				proofEnd = end
			}
		case wire.AppNodeScopedTargetPrevious:
			if intent.Purpose != e2ee.OwnerAppNodeScopedStatusPreviewPurpose || req.Target.Code != "" || req.Target.PreviousGrantID != h.latest || intent.PreviousGrantID != h.latest || h.provenance == "" {
				return reject("AUTHORITY_CONFLICT")
			}
			old, e := appNodeScopedGrant(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, h.latest)
			if e != nil {
				return nil, e
			}
			if old == nil || !appNodeScopedSameSecurity(a.scope, old.claims.Scope) || old.state == wire.AppNodeScopedPrepared || (old.state == wire.AppNodeScopedRevoked) || (old.state == wire.AppNodeScopedCancelled && old.reason != "SELF_CANCEL") {
				return reject("AUTHORITY_REVOKED")
			}
			if old.state != wire.AppNodeScopedExpired && old.state != wire.AppNodeScopedSessionEnded && !(old.state == wire.AppNodeScopedCancelled && old.reason == "SELF_CANCEL") && !(old.state == wire.AppNodeScopedActive && old.claims.Scope.AccountSessionID != a.session.ID) {
				return reject("AUTHORITY_CONFLICT")
			}
			binding, e := appNodeScopedProvenBinding(tx, a, h.provenance, in.NodeControlPublic)
			if e != nil {
				return reject("CANDIDATE_CHANGED")
			}
			public := appNodeBindingPublic(*binding)
			claims.Purpose, claims.Profile, claims.PreviousGrantID, claims.ConfirmationProvenanceID, claims.Binding, claims.AllowedOperations = e2ee.OwnerAppNodeScopedStatusGrantPurpose, wire.AppNodeScopedProfileStatus, h.latest, h.provenance, &public, wire.AppNodeScopedStatusAllowedOperations()
		default:
			return reject("INVALID_REQUEST")
		}
		claims.ProofExpiresAt = appNodeStamp(proofEnd)
		if wire.ValidateAppNodeScopedGrantClaims(claims, in.Hub, in.At) != nil {
			return reject("INVALID_REQUEST")
		}
		raw, e := json.Marshal(claims)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(`INSERT INTO hub_app_node_grants_v1(grant_id,account_id,owner_id,device_id,claims_json,state,remaining,provenance_id,created_at,authority_kind,authority_node_id) VALUES(?,?,?,?,?,'PREPARED',?,?,?,'NODE_V1',?)`, claims.GrantID, c.AccountID, c.OwnerID, c.DeviceID, string(raw), claims.ConfirmationLimit, claims.ConfirmationProvenanceID, appNodeStamp(in.At), a.scope.AuthorityNodeID); e != nil {
			return nil, e
		}
		return finish(wire.AppNodeScopedChallenge{Format: wire.AppNodeScopedChallengeFormat, RequestID: c.RequestID, RequestPacketDigest: digest, Claims: claims, ObservedAt: appNodeStamp(in.At)}, wire.AppNodeScopedCompleted, false)
	case wire.AppNodeScopedComplete:
		claims, e := e2ee.VerifyOwnerAppNodeScopedGrant(a.scope.OwnerPublic, req.OwnerGrant, in.At)
		if e != nil || wire.ValidateAppNodeScopedGrantClaims(claims, in.Hub, in.At) != nil || !appNodeScopedScopeCurrent(a, claims.Scope) {
			return reject("SCOPE_MISMATCH")
		}
		g, e := appNodeScopedGrant(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, claims.GrantID)
		if e != nil {
			return nil, e
		}
		if g == nil || g.state != wire.AppNodeScopedPrepared || !reflect.DeepEqual(g.claims, claims) || claims.ExpectedHeadVersion != h.version {
			return reject("AUTHORITY_CONFLICT")
		}
		if claims.Candidate != nil {
			candidate, e := appNodeCandidate(tx, claims.Candidate.CodeDigest, in.Hub, in.NodeControlPublic, in.At)
			if e != nil || !reflect.DeepEqual(candidate, claims.Candidate) {
				return reject("CANDIDATE_CHANGED")
			}
		} else {
			binding, e := appNodeScopedProvenBinding(tx, a, claims.ConfirmationProvenanceID, in.NodeControlPublic)
			if e != nil || !reflect.DeepEqual(appNodeBindingPublic(*binding), *claims.Binding) {
				return reject("CANDIDATE_CHANGED")
			}
		}
		if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='REVOKED',reason='SUPERSEDED' WHERE authority_kind='NODE_V1' AND authority_node_id=? AND owner_id=? AND device_id=? AND state='ACTIVE'`, a.scope.AuthorityNodeID, c.OwnerID, c.DeviceID); e != nil {
			return nil, e
		}
		if e = appNodeScopedOneRow(tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='ACTIVE',owner_proof=? WHERE authority_kind='NODE_V1' AND authority_node_id=? AND grant_id=? AND state='PREPARED'`, req.OwnerGrant, a.scope.AuthorityNodeID, claims.GrantID)); e != nil {
			return nil, e
		}
		if e = appNodeScopedOneRow(tx.Exec(`INSERT INTO hub_app_node_scoped_heads_v1(owner_id,device_id,authority_node_id,head_version,latest_grant_id,provenance_id) VALUES(?,?,?,?,?,?) ON CONFLICT(owner_id,device_id,authority_node_id) DO UPDATE SET head_version=excluded.head_version,latest_grant_id=excluded.latest_grant_id,provenance_id=excluded.provenance_id WHERE hub_app_node_scoped_heads_v1.head_version=? AND hub_app_node_scoped_heads_v1.latest_grant_id=? AND hub_app_node_scoped_heads_v1.provenance_id=?`, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, claims.Scope.HeadVersion, claims.GrantID, claims.ConfirmationProvenanceID, h.version, h.latest, h.provenance)); e != nil {
			return nil, e
		}
	case wire.AppNodeScopedCancel:
		if req.ExpectedHeadVersion != h.version {
			return reject("AUTHORITY_CONFLICT")
		}
		g, e := appNodeScopedGrant(tx, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, req.GrantID)
		if e != nil {
			return nil, e
		}
		if g == nil || !appNodeScopedScopeCurrent(a, g.claims.Scope) || (g.state != wire.AppNodeScopedActive && g.state != wire.AppNodeScopedPrepared) {
			return reject("AUTHORITY_CONFLICT")
		}
		if g.state == wire.AppNodeScopedActive {
			if h.latest != req.GrantID {
				return reject("AUTHORITY_CONFLICT")
			}
			if e = appNodeScopedOneRow(tx.Exec(`UPDATE hub_app_node_scoped_heads_v1 SET head_version=head_version+1 WHERE owner_id=? AND device_id=? AND authority_node_id=? AND head_version=? AND latest_grant_id=?`, c.OwnerID, c.DeviceID, a.scope.AuthorityNodeID, h.version, req.GrantID)); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='CANCELLED',reason='HEAD_CANCELLED' WHERE authority_kind='NODE_V1' AND authority_node_id=? AND owner_id=? AND device_id=? AND state='PREPARED'`, a.scope.AuthorityNodeID, c.OwnerID, c.DeviceID); e != nil {
				return nil, e
			}
		}
		if e = appNodeScopedOneRow(tx.Exec(`UPDATE hub_app_node_grants_v1 SET state='CANCELLED',reason='SELF_CANCEL' WHERE authority_kind='NODE_V1' AND authority_node_id=? AND grant_id=? AND state=?`, a.scope.AuthorityNodeID, req.GrantID, g.state)); e != nil {
			return nil, e
		}
	default:
		return reject("INVALID_REQUEST")
	}
	v, err := result(wire.AppNodeScopedCompleted, "")
	if err != nil {
		return nil, err
	}
	return finish(v, wire.AppNodeScopedCompleted, false)
}
