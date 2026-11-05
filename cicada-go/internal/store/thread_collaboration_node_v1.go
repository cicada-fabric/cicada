package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"reflect"
)

type HubThreadCollaborationNodeInput = HubLocalDomainNodeInput
type HubThreadCollaborationNodeOutput = HubLocalDomainNodeOutput
type HubThreadCollaborationNodeSeal = HubLocalDomainNodeSeal

func (s *Store) ProcessHubThreadCollaborationNode(in HubThreadCollaborationNodeInput, seal HubThreadCollaborationNodeSeal) ([]byte, error) {
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
	if in.At.IsZero() {
		return nil, ErrHubAccountRejected
	}
	if err = threadCollaborationGCTx(tx, in.At); err != nil {
		return nil, err
	}
	p, err := nodewire.DecodePacket(in.Packet)
	if err != nil || p.Route.HubID != in.Hub.HubID || p.Route.Direction != nodewire.DirectionRequest {
		return nil, ErrHubAccountRejected
	}
	raw, err := json.Marshal(in.Body)
	if err != nil {
		return nil, err
	}
	body, err := wire.DecodeThreadCollaborationNodeBody(p.Route.Operation, raw)
	if err != nil || !reflect.DeepEqual(body, in.Body) {
		return nil, ErrHubAccountRejected
	}
	r := p.Route
	digest := sha256.Sum256(in.Packet)
	rpc := NodeControlRPCInput{CredentialDigest: in.CredentialDigest, NodeID: r.NodeID, BindingID: r.BindingID, BindingVersion: r.BindingVersion, NodeKeyID: r.SenderKeyID, NodeKeyEpoch: r.NodeKeyEpoch, Sequence: r.Sequence, OperationID: r.OperationID, Operation: r.Operation, RequestDigest: hex.EncodeToString(digest[:])}
	b, err := localDomainNodeCurrentTx(tx, in, rpc)
	if err != nil {
		return nil, err
	}
	var endpoint string
	var scope wire.GroupLockScope
	var request any
	switch q := body.(type) {
	case wire.ThreadScopeNodeRead:
		endpoint = q.EndpointID
		scope.NetworkID = q.NetworkID
	case wire.GroupLocksNodeRead:
		endpoint = q.EndpointID
		scope = q.Scope
	case wire.GroupLocksNodeAcquire:
		endpoint = q.EndpointID
		scope = q.Request.Scope
		request = q.Request
	case wire.GroupLocksNodeRenew:
		endpoint = q.EndpointID
		scope = q.Request.Scope
		request = q.Request
	case wire.GroupLocksNodeRelease:
		endpoint = q.EndpointID
		scope = q.Request.Scope
		request = q.Request
	default:
		return nil, ErrHubAccountRejected
	}
	reg, authErr := endpointGroupsNodeRegistrationTx(tx, in, b, endpoint)
	var policy *wire.GroupCoordinationPolicy
	var caller wire.GroupLockHolder
	if authErr == nil && (scope.NetworkID != reg.anchor.NetworkID || scope.HubID != "" && scope.HubID != in.Hub.HubID) {
		authErr = ErrNetworkPermission
	}
	if authErr == nil && scope.GroupID != "" {
		caller, authErr = threadCollaborationGuardTx(tx, reg, scope.GroupID, in.At)
	}
	if authErr == nil && scope.GroupID != "" {
		policy, authErr = threadCollaborationPolicyTx(tx, scope)
		if authErr == nil && (policy == nil || policy.State != "ENABLED") {
			authErr = errors.New(wire.ThreadCollaborationErrorPolicyRequired)
		}
	}

	if authErr == nil && request != nil {
		var original wire.ThreadCollaborationOriginal
		switch q := request.(type) {
		case wire.GroupLockAcquireRequest:
			original = q.Original
		case wire.GroupLockRenewRequest:
			original = q.Original
		case wire.GroupLockReleaseRequest:
			original = q.Original
		}
		if wire.ValidateGroupLockOriginalWindow(original, in.At) != nil {
			authErr = errors.New(wire.ThreadCollaborationErrorReceiptUnavailable)
		}
	}
	var savedID, savedOp, savedDigest string
	var savedSeq uint64
	var saved []byte
	err = tx.QueryRow(`SELECT operation_id,operation,sequence,request_digest,response_packet FROM thread_collaboration_node_originals_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND(operation_id=? OR sequence=?)`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.OperationID, rpc.Sequence).Scan(&savedID, &savedOp, &savedSeq, &savedDigest, &saved)
	if err == nil {
		if savedID != rpc.OperationID || savedOp != rpc.Operation || savedSeq != rpc.Sequence || savedDigest != rpc.RequestDigest {
			return nil, ErrNodeControlRPCConflict
		}
		if authErr != nil {
			// Current denial does not describe the historical operation's
			// outcome. Do not manufacture a signed original rejection: the
			// consumer must retain its packet until exact recovery is allowed.
			return nil, ErrHubEndpointGroupsOutcomeUncertain
		}
		return saved, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM thread_collaboration_node_originals_v1`).Scan(&count); err != nil {
		return nil, err
	}
	if count >= threadCollaborationOriginalCapacity {
		return nil, ErrHubOwnerDiagnosticsFull
	}
	if err = endpointGroupsNodeRateTx(tx, rpc, in.At); err != nil {
		return nil, err
	}
	if err = nativePairNodeAdmitTx(tx, rpc, in.At); err != nil {
		return nil, err
	}
	out := HubThreadCollaborationNodeOutput{}
	if authErr != nil {
		out.ErrorCode = threadCollaborationErrorCode(authErr)
	} else if scope.GroupID == "" {
		out.Result, err = threadCollaborationScopeTx(tx, reg, in.At)
	} else {

		if err == nil {
			var view wire.GroupSlotView
			view, err = threadCollaborationSlotsTx(tx, scope, *policy, in.At)
			if err == nil {
				if request == nil {
					out.Result = view
				} else {
					out.Result, err = threadCollaborationLockTx(tx, caller, rpc.Operation, request, view, in.At)
				}
			}
		}
	}
	if err != nil {
		code := threadCollaborationErrorCode(err)
		if code == wire.ThreadCollaborationErrorAuthorizationRequired && !errors.Is(err, ErrNetworkPermission) {
			return nil, err
		}
		out = HubThreadCollaborationNodeOutput{ErrorCode: code}
	}
	packet, err := seal(out)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO thread_collaboration_node_originals_v1 VALUES(?,?,?,?,?,?,?,?)`, rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, rpc.RequestDigest, packet, appNodeStamp(in.At)); err != nil {
		return nil, err
	}
	res, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='COMPLETE',response_packet=X'',updated_at=? WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=? AND operation=? AND request_digest=? AND state='PROCESSING'`, appNodeStamp(in.At), rpc.BindingID, rpc.NodeKeyEpoch, rpc.Sequence, rpc.OperationID, rpc.Operation, rpc.RequestDigest)
	if err != nil {
		return nil, err
	}
	if n, e := res.RowsAffected(); e != nil || n != 1 {
		return nil, ErrNodeControlRPCConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return packet, nil
}
func threadCollaborationErrorCode(err error) string {
	if err == nil {
		return ""
	}
	for _, code := range []string{wire.ThreadCollaborationErrorClassificationRequired, wire.ThreadCollaborationErrorWorkerGroupLimit, wire.ThreadCollaborationErrorPolicyRequired, wire.ThreadCollaborationErrorSlotInvalid, wire.ThreadCollaborationErrorSlotBusy, wire.ThreadCollaborationErrorVersionConflict, wire.ThreadCollaborationErrorHolderMismatch, wire.ThreadCollaborationErrorGenerationStale, wire.ThreadCollaborationErrorLeaseExpired, wire.ThreadCollaborationErrorOriginalConflict, wire.ThreadCollaborationErrorOriginalUncertain, wire.ThreadCollaborationErrorNetworkConflict, wire.ThreadCollaborationErrorNetworkUnresolved, wire.ThreadCollaborationErrorAtLimit, wire.ThreadCollaborationErrorReceiptUnavailable} {
		if err.Error() == code {
			return code
		}
	}
	return wire.ThreadCollaborationErrorAuthorizationRequired
}
