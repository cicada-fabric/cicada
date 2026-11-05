package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"reflect"
	"time"
)

type HubThreadCollaborationInput = HubEndpointGroupsInput
type HubThreadCollaborationSeal = HubEndpointGroupsSeal

func threadCollaborationOwnerFields(body any) (op string, c wire.AppNodeRequestContext, token, proof []byte, b any) {
	switch q := body.(type) {
	case wire.ThreadCollaborationOwnerReadRequest:
		return wire.OperationThreadCollaborationOwnerRead, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case wire.ThreadCollaborationOwnerPrepareRequest:
		return wire.OperationThreadCollaborationOwnerPrepare, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case wire.ThreadCollaborationOwnerApplyRequest:
		return wire.OperationThreadCollaborationOwnerApply, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case wire.ThreadCollaborationOwnerStatusRequest:
		return wire.OperationThreadCollaborationOwnerStatus, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case wire.ThreadCollaborationOwnerReconcileRequest:
		return wire.OperationThreadCollaborationOwnerReconcile, q.Context, q.SessionToken, q.OwnerProof, q.Body
	}
	return
}
func threadCollaborationOwnerInput(tx *sql.Tx, in HubThreadCollaborationInput) (endpointGroupsOwnerRequest, error) {
	op, c, token, proof, _ := threadCollaborationOwnerFields(in.Body)
	if in.At.IsZero() || wire.ValidateThreadCollaborationOwnerRequest(in.Body, in.Hub, time.Time{}) != nil {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	p, err := wire.PreflightRequest(in.Packet, op)
	_, route, re := wire.RequestRoute(in.Hub, c.OwnerID, c.DeviceID, c.RequestID, op, wire.HandshakeEpoch, in.Device)
	if err != nil || re != nil || p.Packet.Route != route || !reflect.DeepEqual(p.SenderPublicIdentity, in.Device) {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	var signed e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(proof, &signed) != nil || !reflect.DeepEqual(signed.Claims.Scope.DevicePublic, in.Device) {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	key, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`, c.OwnerID, signed.Claims.Scope.OwnerPublic.ID))
	if err != nil || !reflect.DeepEqual(key.Public, signed.Claims.Scope.OwnerPublic) {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(key.Public, proof, wire.ThreadCollaborationOwnerPurpose(op), time.Time{})
	if err != nil {
		return endpointGroupsOwnerRequest{}, ErrHubAccountRejected
	}
	return endpointGroupsOwnerRequest{op: op, c: c, token: token, proof: proof, claims: claims, digest: wire.ThreadCollaborationOwnerPacketDigest(in.Packet), nonce: AccountDigest("thread-collaboration-owner-nonce", c.ClientNonce)}, nil
}
func threadCollaborationOwnerResult(in HubThreadCollaborationInput, q endpointGroupsOwnerRequest) wire.ThreadCollaborationOwnerResult {
	return wire.ThreadCollaborationOwnerResult{Format: wire.ThreadCollaborationOwnerResultFormat, ContractRevision: wire.ThreadCollaborationContractRevision, HubID: q.c.HubID, OwnerID: q.c.OwnerID, DeviceID: q.c.DeviceID, RequestID: q.c.RequestID, RequestPacketDigest: q.digest, ObservedAt: appNodeStamp(in.At), OperationID: q.c.RequestID, OriginalPacketDigest: q.digest, State: "COMPLETED"}
}
func threadCollaborationOwnerSavedTx(tx *sql.Tx, q endpointGroupsOwnerRequest) ([]byte, error) {
	var op, digest, account string
	var packet []byte
	err := tx.QueryRow(`SELECT operation,request_digest,account_id,response_packet FROM thread_collaboration_owner_originals_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, q.c.OwnerID, q.c.DeviceID, q.c.RequestID).Scan(&op, &digest, &account, &packet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if op != q.op || digest != q.digest || account != q.c.AccountID {
		return nil, ErrHubEndpointGroupsPacketConflict
	}
	if len(packet) == 0 {
		return nil, ErrHubEndpointGroupsOutcomeUncertain
	}
	return packet, nil
}
func threadCollaborationOwnerSaveTx(tx *sql.Tx, in HubThreadCollaborationInput, q endpointGroupsOwnerRequest, result wire.ThreadCollaborationOwnerResult, seal HubThreadCollaborationSeal) ([]byte, error) {
	packet, err := seal(result)
	if err != nil {
		return nil, err
	}
	s := q.claims.Scope
	_, err = tx.Exec(`INSERT INTO thread_collaboration_owner_originals_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, q.c.OwnerID, q.c.DeviceID, q.c.RequestID, q.op, q.digest, q.c.AccountID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, q.nonce, packet, appNodeStamp(in.At))
	return packet, err
}
func threadCollaborationOwnerNetworkTx(tx *sql.Tx, hub, owner, network string) error {
	var count int
	if tx.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=? AND hub_id=? AND owner_id=? AND state='ACTIVE' AND context_policy=''`, network, hub, owner).Scan(&count) != nil || count != 1 {
		return ErrNetworkPermission
	}
	return nil
}
func (s *Store) ProcessHubThreadCollaboration(in HubThreadCollaborationInput, seal HubThreadCollaborationSeal) ([]byte, error) {
	if seal == nil || s.requireOwnerSetupStartupAllowed() != nil {
		return nil, ErrHubAccountRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE thread_collaboration_guard_v1 SET touched_at=touched_at WHERE id=1`); err != nil {
		return nil, err
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	if err = threadCollaborationGCTx(tx, in.At); err != nil {
		return nil, err
	}
	q, err := threadCollaborationOwnerInput(tx, in)
	if err != nil {
		return nil, err
	}
	a, err := appNodeActor(tx, in.Hub, q.c.DeviceID, in.Device, q.token, in.At)
	if err != nil || a.scope.OwnerID != q.c.OwnerID || a.scope.AccountID != q.c.AccountID || !endpointGroupsOwnerAccountCurrentTx(tx, a, q.claims, in.At) {
		return nil, ErrHubAccountRejected
	}
	recovery := q.op == wire.OperationThreadCollaborationOwnerStatus || q.op == wire.OperationThreadCollaborationOwnerReconcile
	if !recovery && (!appNodeScopeCurrent(a, q.claims.Scope) || a.root != wire.RootActiveState || !a.source) {
		return nil, ErrHubAccountRejected
	}
	old, err := threadCollaborationOwnerSavedTx(tx, q)
	if err != nil || len(old) != 0 {
		return old, err
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM thread_collaboration_owner_originals_v1`).Scan(&count); err != nil {
		return nil, err
	}
	if count >= threadCollaborationOriginalCapacity {
		return nil, ErrHubOwnerDiagnosticsFull
	}
	if err = endpointGroupsOwnerRateTx(tx, a.scope, in.At); err != nil {
		return nil, err
	}
	// An already used nonce with a different original ID never reaches effects.
	if err = tx.QueryRow(`SELECT count(*) FROM thread_collaboration_owner_originals_v1 WHERE owner_id=? AND device_id=? AND account_epoch=? AND device_epoch=? AND owner_key_version=? AND nonce_digest=?`, q.c.OwnerID, q.c.DeviceID, q.claims.Scope.AccountEpoch, q.claims.Scope.DeviceEpoch, q.claims.Scope.OwnerKeyVersion, q.nonce).Scan(&count); err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, ErrHubEndpointGroupsPacketConflict
	}
	result := threadCollaborationOwnerResult(in, q)
	_, _, _, _, body := threadCollaborationOwnerFields(in.Body)
	if recovery {
		var original endpointGroupsOwnerRequest
		switch b := body.(type) {
		case wire.ThreadCollaborationOwnerStatusBody:
			original = q
			original.op = wire.OperationThreadCollaborationOwnerApply
			original.c.RequestID = b.OperationID
			original.digest = b.OriginalPacketDigest
		case wire.ThreadCollaborationOwnerReconcileBody:
			if in.Original == nil || in.OriginalSeal == nil || !reflect.DeepEqual(in.Original.Packet, b.OriginalPacket) {
				return nil, ErrHubAccountRejected
			}
			o := *in.Original
			o.At = in.At
			original, err = threadCollaborationOwnerInput(tx, o)
			if err != nil || original.c.OwnerID != q.c.OwnerID || original.c.DeviceID != q.c.DeviceID || original.c.AccountID != q.c.AccountID || original.op == wire.OperationThreadCollaborationOwnerReconcile {
				return nil, ErrHubAccountRejected
			}
		default:
			return nil, ErrHubAccountRejected
		}
		result.OperationID, result.OriginalPacketDigest = original.c.RequestID, original.digest
		var receipt []byte
		unavailable := false
		receipt, err = threadCollaborationOwnerSavedTx(tx, original)
		if err != nil {
			return nil, err
		}
		if len(receipt) == 0 && in.Original != nil {
			// Reconcile closes an unseen original with a signed no-effect fence.
			// It never executes the original body after timeout/review expiry.
			if original.op != wire.OperationThreadCollaborationOwnerApply && e2ee.ValidateOwnerEndpointGroupsRequest(original.claims, in.At) != nil {
				// An expired diagnostic may have been lawfully reclaimed. Absence
				// is not proof that its old read/prepare was never performed.
				unavailable = true
			} else {
				if err = threadCollaborationFenceReviewTx(tx, *in.Original, original); err != nil {
					return nil, err
				}
				fenced := threadCollaborationOwnerResult(in, original)
				fenced.State = "ORIGINAL_NOT_APPLIED"
				fenced.ErrorCode = "ORIGINAL_NOT_ADMITTED"
				originalIn := *in.Original
				originalIn.At = in.At
				receipt, err = threadCollaborationOwnerSaveTx(tx, originalIn, original, fenced, in.OriginalSeal)
				if err != nil {
					return nil, err
				}
			}
		}
		if unavailable {
			result.State = "REJECTED"
			result.ErrorCode = wire.ThreadCollaborationErrorReceiptUnavailable
		} else if len(receipt) == 0 {
			result.State = "ORIGINAL_OUTCOME_UNCERTAIN"
			result.ErrorCode = wire.ThreadCollaborationErrorOriginalUncertain
		} else {
			result.State = "ORIGINAL_RECEIPT"
			result.ReceiptPacket = receipt
		}
	} else {
		// Domain denials are retained as original responses. SQL/sealing errors
		// roll back the entire transaction, including review consumption.
		switch b := body.(type) {
		case wire.ThreadCollaborationOwnerReadBody:
			result.Read, err = threadCollaborationOwnerReadTx(tx, in, q, b)
		case wire.ThreadCollaborationOwnerPrepareBody:
			result.Review, err = threadCollaborationOwnerPrepareTx(tx, in, q, b)
		case wire.ThreadCollaborationOwnerApplyBody:
			err = threadCollaborationOwnerApplyTx(tx, in, q, b, &result)
		default:
			return nil, ErrHubAccountRejected
		}
		if err != nil {
			code := threadCollaborationErrorCode(err)
			if code == wire.ThreadCollaborationErrorAuthorizationRequired && !errors.Is(err, ErrNetworkPermission) {
				return nil, err
			}
			result = threadCollaborationOwnerResult(in, q)
			result.State = "REJECTED"
			result.ErrorCode = code
		}
	}
	packet, err := threadCollaborationOwnerSaveTx(tx, in, q, result, seal)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}

// A no-effect reconciliation consumes the exact unused review credential too.
// A consumed review with a missing original receipt is uncertain, never absence.
func threadCollaborationFenceReviewTx(tx *sql.Tx, in HubThreadCollaborationInput, original endpointGroupsOwnerRequest) error {
	q, ok := in.Body.(wire.ThreadCollaborationOwnerApplyRequest)
	if !ok {
		return nil
	}
	var raw, state, consumed string
	err := tx.QueryRow(`SELECT review_json,state,consumed_id FROM thread_collaboration_owner_reviews_v1 WHERE review_id=? AND owner_id=? AND account_id=? AND device_id=?`, q.Body.ReviewID, original.c.OwnerID, original.c.AccountID, original.c.DeviceID).Scan(&raw, &state, &consumed)
	if err != nil {
		return ErrHubEndpointGroupsOutcomeUncertain
	}
	var review wire.ThreadCollaborationOwnerReview
	if json.Unmarshal([]byte(raw), &review) != nil {
		return ErrHubEndpointGroupsOutcomeUncertain
	}
	digest, err := wire.ThreadCollaborationOwnerReviewDigest(review)
	if err != nil {
		return ErrHubEndpointGroupsOutcomeUncertain
	}
	if digest != q.Body.ReviewDigest {
		return nil
	}
	if state == "CONSUMED" {
		if consumed == original.c.RequestID {
			return ErrHubEndpointGroupsOutcomeUncertain
		}
		return nil
	}
	if state != "PREPARED" || consumed != "" {
		return ErrHubEndpointGroupsOutcomeUncertain
	}
	_, err = tx.Exec(`UPDATE thread_collaboration_owner_reviews_v1 SET state='CONSUMED',consumed_id=? WHERE review_id=? AND state='PREPARED' AND consumed_id=''`, original.c.RequestID, q.Body.ReviewID)
	return err
}

func threadCollaborationOwnerReadTx(tx *sql.Tx, in HubThreadCollaborationInput, q endpointGroupsOwnerRequest, b wire.ThreadCollaborationOwnerReadBody) (*wire.ThreadCollaborationOwnerReadResult, error) {
	if threadCollaborationOwnerNetworkTx(tx, in.Hub.HubID, q.c.OwnerID, b.NetworkID) != nil {
		return nil, ErrNetworkPermission
	}
	out := &wire.ThreadCollaborationOwnerReadResult{HubID: in.Hub.HubID, NetworkID: b.NetworkID, View: b.View, ObservedAt: appNodeStamp(in.At)}
	if b.View == "GROUP_LOCKS" {
		g, err := endpointGroupsGroupTx(tx, q.c.OwnerID, b.NetworkID, b.GroupID)
		if err != nil {
			return nil, ErrNetworkPermission
		}
		out.Group = &wire.ThreadCollaborationGroupCard{GroupID: g.ID, NetworkID: g.NetworkID, Name: g.Name, GroupVersion: uint64(g.Version)}
		scope := wire.GroupLockScope{HubID: in.Hub.HubID, NetworkID: b.NetworkID, GroupID: b.GroupID}
		p, err := threadCollaborationPolicyTx(tx, scope)
		if err != nil {
			return nil, err
		}
		out.GroupPolicy = p
		if p != nil {
			v, err := threadCollaborationSlotsTx(tx, scope, *p, in.At)
			if err != nil {
				return nil, err
			}
			out.GroupSlots = &v
		}
		return out, nil
	}
	limit := int(b.Limit)
	if limit == 0 {
		limit = wire.MaxThreadCollaborationPageRows
	}
	scope := in.Hub.HubID + ":" + q.c.OwnerID + ":" + b.NetworkID + ":" + b.NodeID
	after, err := endpointGroupsCursorAfter(b.Cursor, scope, "threads-v1")
	if err != nil {
		return nil, ErrNetworkPermission
	}
	query := `SELECT endpoint_id FROM hub_endpoint_groups_registrations_v1 WHERE owner_id=? AND network_id=? AND endpoint_id>?`
	args := []any{q.c.OwnerID, b.NetworkID, after}
	if b.NodeID != "" {
		query += ` AND node_id=?`
		args = append(args, b.NodeID)
	}
	if b.EndpointID != "" {
		query += ` AND endpoint_id=?`
		args = append(args, b.EndpointID)
	}
	query += ` ORDER BY endpoint_id LIMIT ?`
	args = append(args, limit+1)
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	ids := []string{}
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
		return nil, err
	}
	if re != nil {
		return nil, re
	}
	if len(ids) > limit {
		out.NextCursor = endpointGroupsPageCursor(scope, "threads-v1", ids[limit-1])
		ids = ids[:limit]
	}
	for _, id := range ids {
		r, err := endpointGroupsRegistrationTx(tx, id)
		if err != nil || r == nil {
			return nil, ErrNetworkPermission
		}
		v, err := threadCollaborationScopeTx(tx, r, in.At)
		if err != nil {
			return nil, err
		}
		out.Threads = append(out.Threads, v)
	}
	if b.View == "THREAD_SCOPE" && len(out.Threads) != 1 {
		return nil, ErrNetworkPermission
	}
	return out, nil
}

func threadCollaborationOwnerCheckTx(tx *sql.Tx, in HubThreadCollaborationInput, q endpointGroupsOwnerRequest, b wire.ThreadCollaborationOwnerPrepareBody, target string) (*hubEndpointGroupsRegistration, *Group, error) {
	if b.Role != nil {
		want := b.Role
		if want.ExpectedClassificationRevision >= 1<<63-1 {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorAtLimit)
		}
		r, err := endpointGroupsRegistrationTx(tx, want.EndpointID)
		if err != nil || r == nil || r.anchor.Registration.OwnerID != q.c.OwnerID || r.anchor.Registration.NodeID != want.NodeID || r.anchor.NetworkID != want.NetworkID || r.anchor.RegistrationDigest != want.RegistrationDigest || threadCollaborationSource(r) != want.Source || endpointGroupsRegistrationCurrentTx(tx, r, in.At) != nil {
			return nil, nil, ErrNetworkPermission
		}
		v, err := threadCollaborationScopeTx(tx, r, in.At)
		if err != nil {
			return nil, nil, err
		}
		if v.State == "NETWORK_CONFLICT" || v.ClassificationRevision != want.ExpectedClassificationRevision || v.RelationsRevision != want.ExpectedRelationsRevision {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorVersionConflict)
		}
		if want.Classification == wire.ThreadClassificationWorker && v.ActiveGroupCount > 1 {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorWorkerGroupLimit)
		}
		return r, nil, nil
	}
	var network, group string
	if b.Policy != nil {
		if b.Policy.ExpectedPolicyRevision >= 1<<63-1 {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorAtLimit)
		}
		network = b.Policy.NetworkID
		group = b.Policy.GroupID
	} else if b.Clear != nil {
		if b.Clear.ExpectedVersion >= 1<<63-1 {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorAtLimit)
		}
		network = b.Clear.Scope.NetworkID
		group = b.Clear.Scope.GroupID
		if b.Clear.Scope.HubID != in.Hub.HubID {
			return nil, nil, ErrNetworkPermission
		}
	} else {
		return nil, nil, ErrNetworkPermission
	}
	if threadCollaborationOwnerNetworkTx(tx, in.Hub.HubID, q.c.OwnerID, network) != nil {
		return nil, nil, ErrNetworkPermission
	}
	if b.Action == wire.ThreadCollaborationCreateGroupWithPolicy {
		return nil, nil, nil
	}
	g, err := endpointGroupsGroupTx(tx, q.c.OwnerID, network, group)
	if err != nil {
		return nil, nil, ErrNetworkPermission
	}
	scope := wire.GroupLockScope{HubID: in.Hub.HubID, NetworkID: network, GroupID: group}
	p, err := threadCollaborationPolicyTx(tx, scope)
	if err != nil {
		return nil, nil, err
	}
	if b.Policy != nil {
		revision := uint64(0)
		if p != nil {
			revision = p.Revision
		}
		if uint64(g.Version) != b.Policy.ExpectedGroupVersion || revision != b.Policy.ExpectedPolicyRevision {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorVersionConflict)
		}
	} else {
		if p == nil {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorPolicyRequired)
		}
		v, err := threadCollaborationSlotsTx(tx, scope, *p, in.At)
		if err != nil {
			return nil, nil, err
		}
		s := v.Slots[int(b.Clear.Slot)-1]
		if s.State != "HELD" || s.Version != b.Clear.ExpectedVersion || s.Generation != b.Clear.Generation || s.Holder == nil || *s.Holder != b.Clear.ExpectedHolder {
			return nil, nil, errors.New(wire.ThreadCollaborationErrorVersionConflict)
		}
	}
	return nil, g, nil
}

func threadCollaborationOwnerPrepareTx(tx *sql.Tx, in HubThreadCollaborationInput, q endpointGroupsOwnerRequest, b wire.ThreadCollaborationOwnerPrepareBody) (*wire.ThreadCollaborationOwnerReview, error) {
	if _, _, err := threadCollaborationOwnerCheckTx(tx, in, q, b, ""); err != nil {
		return nil, err
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM thread_collaboration_owner_reviews_v1 WHERE owner_id=? AND device_id=? AND state='PREPARED' AND julianday(expires_at)>julianday(?)`, q.c.OwnerID, q.c.DeviceID, appNodeStamp(in.At)).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 64 {
		return nil, errors.New(wire.ThreadCollaborationErrorAtLimit)
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return nil, err
	}
	digest, err := wire.ThreadCollaborationOwnerBodyDigest(b)
	if err != nil {
		return nil, err
	}
	end := in.At.Add(5 * time.Minute)
	proofEnd, _ := time.Parse(time.RFC3339Nano, q.claims.ExpiresAt)
	if proofEnd.Before(end) {
		end = proofEnd
	}
	r := &wire.ThreadCollaborationOwnerReview{HubID: in.Hub.HubID, OwnerID: q.c.OwnerID, DeviceID: q.c.DeviceID, PrepareRequestID: q.c.RequestID, PreparePacketDigest: q.digest, ObservedAt: appNodeStamp(in.At), ReviewID: id, Action: b.Action, BodyDigest: digest, ExpiresAt: appNodeStamp(end), Prepared: b}
	if b.Policy != nil {
		r.TargetGroupID = b.Policy.GroupID
		if b.Action == wire.ThreadCollaborationCreateGroupWithPolicy {
			r.TargetGroupID, err = wire.NewRequestID()
			if err != nil {
				return nil, err
			}
		}
	} else if b.Clear != nil {
		r.TargetGroupID = b.Clear.Scope.GroupID
	}
	if _, err = wire.ThreadCollaborationOwnerReviewDigest(*r); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	s := q.claims.Scope
	_, err = tx.Exec(`INSERT INTO thread_collaboration_owner_reviews_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, q.c.OwnerID, q.c.AccountID, q.c.DeviceID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, string(raw), q.proof, r.ExpiresAt, "PREPARED", "", appNodeStamp(in.At))
	return r, err
}

func threadCollaborationOwnerApplyTx(tx *sql.Tx, in HubThreadCollaborationInput, q endpointGroupsOwnerRequest, b wire.ThreadCollaborationOwnerApplyBody, out *wire.ThreadCollaborationOwnerResult) error {
	var owner, account, device, raw, end, state, consumed string
	var ae, de, ov uint64
	var proof []byte
	err := tx.QueryRow(`SELECT owner_id,account_id,device_id,account_epoch,device_epoch,owner_key_version,review_json,prepare_proof,expires_at,state,consumed_id FROM thread_collaboration_owner_reviews_v1 WHERE review_id=?`, b.ReviewID).Scan(&owner, &account, &device, &ae, &de, &ov, &raw, &proof, &end, &state, &consumed)
	if err != nil || owner != q.c.OwnerID || account != q.c.AccountID || device != q.c.DeviceID || ae != q.claims.Scope.AccountEpoch || de != q.claims.Scope.DeviceEpoch || ov != q.claims.Scope.OwnerKeyVersion || state != "PREPARED" || consumed != "" || !appNodeBefore(in.At, end) {
		return ErrNetworkPermission
	}
	var review wire.ThreadCollaborationOwnerReview
	if json.Unmarshal([]byte(raw), &review) != nil {
		return ErrHubEndpointGroupsOutcomeUncertain
	}
	digest, err := wire.ThreadCollaborationOwnerReviewDigest(review)
	if err != nil || digest != b.ReviewDigest {
		return ErrNetworkPermission
	}
	// Recheck the retained exact Owner proof against current root key/version.
	var signed e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(proof, &signed) != nil || !reflect.DeepEqual(signed.Claims.Scope.OwnerPublic, q.claims.Scope.OwnerPublic) || signed.Claims.Scope.OwnerKeyVersion != ov || e2ee.ValidateOwnerEndpointGroupsRequest(signed.Claims, in.At) != nil {
		return ErrNetworkPermission
	}
	preparedDigest, e := wire.ThreadCollaborationOwnerRequestBodyDigest(review.Prepared)
	if e != nil || signed.Claims.BodyDigest != preparedDigest || signed.Claims.RequestID != review.PrepareRequestID {
		return ErrNetworkPermission
	}
	if _, err = e2ee.VerifyOwnerEndpointGroupsRequest(q.claims.Scope.OwnerPublic, proof, wire.ThreadCollaborationOwnerPurpose(wire.OperationThreadCollaborationOwnerPrepare), in.At); err != nil {
		return ErrNetworkPermission
	}
	r, g, err := threadCollaborationOwnerCheckTx(tx, in, q, review.Prepared, review.TargetGroupID)
	if err != nil {
		return err
	}
	body := review.Prepared
	switch body.Action {
	case wire.ThreadCollaborationSetClassification:
		want := body.Role
		stamp := appNodeStamp(in.At)
		_, err = tx.Exec(`INSERT INTO thread_classifications_v1 VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(registration_id) DO UPDATE SET classification=excluded.classification,revision=excluded.revision,updated_at=excluded.updated_at`, want.Source.RegistrationID, want.Source.SourceEpoch, want.EndpointID, q.c.OwnerID, want.NodeID, want.NetworkID, want.Classification, want.ExpectedClassificationRevision+1, stamp, stamp)
		if err == nil {
			v, e := threadCollaborationScopeTx(tx, r, in.At)
			err = e
			out.Thread = &v
		}
	case wire.ThreadCollaborationCreateGroupWithPolicy, wire.ThreadCollaborationEnableGroupPolicy, wire.ThreadCollaborationRevokeGroupPolicy:
		want := body.Policy
		if body.Action == wire.ThreadCollaborationCreateGroupWithPolicy {
			var trust string
			if tx.QueryRow(`SELECT trust_domain_id FROM principals WHERE id=? AND kind='human' AND status='active'`, q.c.OwnerID).Scan(&trust) != nil {
				return ErrNetworkPermission
			}
			g, err = insertGroupWithOwnerMembershipTx(tx, Group{ID: review.TargetGroupID, NetworkID: want.NetworkID, OwnerPrincipalID: q.c.OwnerID, TrustDomainID: trust, Name: want.Name, State: GroupStateActive, ContextPolicy: "group_scoped", Version: 1, Revision: 1}, in.At, "")
			if err != nil {
				return err
			}
		}
		scope := wire.GroupLockScope{HubID: in.Hub.HubID, NetworkID: want.NetworkID, GroupID: g.ID}
		old, e := threadCollaborationPolicyTx(tx, scope)
		if e != nil {
			return e
		}
		id := ""
		if old != nil {
			id = old.PolicyID
		} else {
			id, err = wire.NewRequestID()
			if err != nil {
				return err
			}
		}
		state := "ENABLED"
		if body.Action == wire.ThreadCollaborationRevokeGroupPolicy {
			state = "REVOKED"
		}
		p := wire.GroupCoordinationPolicy{Format: wire.GroupCoordinationPolicyFormat, HubID: in.Hub.HubID, NetworkID: want.NetworkID, GroupID: g.ID, PolicyID: id, Revision: want.ExpectedPolicyRevision + 1, State: state, SlotCount: 8, Rights: wire.GroupCoordinationRights(), OwnerConsentDigest: q.digest}
		encoded, e := json.Marshal(p)
		if e != nil {
			return e
		}
		stamp := appNodeStamp(in.At)
		_, err = tx.Exec(`INSERT INTO group_coordination_policies_v1 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET revision=excluded.revision,state=excluded.state,policy_json=excluded.policy_json,updated_at=excluded.updated_at`, g.ID, q.c.OwnerID, want.NetworkID, id, p.Revision, p.State, string(encoded), stamp, stamp)
		if err == nil && old == nil {
			for slot := 1; slot <= 8; slot++ {
				if _, err = tx.Exec(`INSERT INTO group_lock_slots_v1 VALUES(?,?,'FREE',1,0,'','','')`, g.ID, slot); err != nil {
					break
				}
			}
		}
		out.Policy = &p
	case wire.ThreadCollaborationClearOneSlot:
		want := body.Clear
		_, err = tx.Exec(`UPDATE group_lock_slots_v1 SET state='FREE',version=version+1,holder_json='',note='',expires_at='' WHERE group_id=? AND slot=? AND version=? AND generation=? AND state='HELD'`, want.Scope.GroupID, want.Slot, want.ExpectedVersion, want.Generation)
		out.Lock = &wire.GroupLockReceipt{Format: wire.GroupLockReceiptFormat, Scope: want.Scope, OperationID: q.c.RequestID, RequestDigest: q.digest, Slot: want.Slot, AppliedVersion: want.ExpectedVersion + 1, Generation: want.Generation, Outcome: "OWNER_CLEARED", ObservedAt: appNodeStamp(in.At)}
	default:
		return ErrNetworkPermission
	}
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE thread_collaboration_owner_reviews_v1 SET state='CONSUMED',consumed_id=? WHERE review_id=? AND state='PREPARED' AND consumed_id=''`, q.c.RequestID, b.ReviewID)
	if err != nil {
		return err
	}
	if n, e := res.RowsAffected(); e != nil || n != 1 {
		return ErrNetworkPermission
	}
	return nil
}
