package store

import (
	"bytes"
	"database/sql"
	"errors"
	"reflect"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func endpointGroupsOwnerCurrentTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, r *wire.OwnerEndpointGroupsResult) error {
	r.CurrentRelation, r.CurrentGroup = nil, nil
	if r.Operation == nil || a.root != wire.RootActiveState || !appNodeScopeCurrent(a, request.claims.Scope) {
		return nil
	}
	if r.Operation.Target.OwnerID != request.c.OwnerID || r.Operation.Target.HubID != request.c.HubID {
		return ErrHubAccountRejected
	}
	relation, group, err := endpointGroupsCurrentTx(tx, in, a, r.Operation)
	if err != nil {
		return err
	}
	target := r.Operation.Target
	if relation != nil && (relation.GroupID != target.GroupID || relation.NetworkID != target.NetworkID) || group != nil && (group.GroupID != target.GroupID || group.NetworkID != target.NetworkID) {
		return ErrHubAccountRejected
	}
	r.CurrentRelation, r.CurrentGroup = relation, group
	return nil
}

func endpointGroupsOwnerStatusTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	q, ok := in.Body.(wire.OwnerEndpointGroupsStatusRequest)
	if !ok {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	original := endpointGroupsOwnerRequest{op: wire.OperationOwnerEndpointGroupsApply, c: request.c, claims: request.claims, digest: q.Body.OriginalPacketDigest}
	original.c.RequestID = q.Body.OperationID
	var f endpointGroupsOwnerFloor
	err := tx.QueryRow(`SELECT operation,request_digest,nonce_digest,account_id,account_epoch,device_epoch,owner_key_version FROM hub_endpoint_groups_owner_nonces_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, request.c.OwnerID, request.c.DeviceID, q.Body.OperationID).Scan(&f.op, &f.digest, &f.nonce, &f.account, &f.accountEpoch, &f.deviceEpoch, &f.ownerKeyVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return endpointGroupsOwnerReceipt{}, err
	}
	if err == nil {
		if f.op != original.op || f.digest != original.digest {
			return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "REJECTED_FENCED", "ORIGINAL_PACKET_CONFLICT", seal)
		}
		if f.account != request.c.AccountID {
			return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
		}
		original.nonce = f.nonce
		original.claims.Scope.AccountEpoch, original.claims.Scope.DeviceEpoch, original.claims.Scope.OwnerKeyVersion = f.accountEpoch, f.deviceEpoch, f.ownerKeyVersion
	}
	history, err := endpointGroupsOwnerHistoryTx(tx, original, in.At)
	if errors.Is(err, errEndpointGroupsOwnerUncertain) {
		return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "PREPARED", "OUTCOME_UNCERTAIN", seal)
	}
	if errors.Is(err, errEndpointGroupsOwnerPacketConflict) {
		return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "REJECTED_FENCED", "ORIGINAL_PACKET_CONFLICT", seal)
	}
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if !history.receipt.durable || len(history.receipt.packet) == 0 {
		return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "PREPARED", "OUTCOME_UNCERTAIN", seal)
	}
	return endpointGroupsOwnerStatusResultTx(tx, a, in, request, &history.receipt, "COMPLETED", "", seal)
}

func endpointGroupsOwnerStatusResultTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, original *endpointGroupsOwnerReceipt, state, code string, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	if original == nil && code == "OUTCOME_UNCERTAIN" {
		// The authenticated query finished. Its original mutation remains
		// unresolved; this wrapper contains no receipt that could settle it.
		state = "COMPLETED"
	}
	r := endpointGroupsOwnerResult(in, request, state, code)
	if original != nil {
		r.Operation = original.operation
		r.ReceiptPacket = append([]byte(nil), original.packet...)
		if r.Operation != nil {
			r.NodeID = r.Operation.Target.NodeID
		} else if request.op == wire.OperationOwnerEndpointGroupsReconcile && in.Original != nil {
			// Reconcile has already authenticated this exact retained original.
			// Its typed read/prepare scope survives without an apply operation.
			switch q := in.Original.Body.(type) {
			case wire.OwnerEndpointGroupsReadRequest:
				r.NodeID = q.Body.NodeID
			case wire.OwnerEndpointGroupsPrepareRequest:
				r.NodeID = q.Body.NodeID
			}
		}
		if err := endpointGroupsOwnerCurrentTx(tx, a, in, request, &r); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
	}
	packet, err := seal(r)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	return endpointGroupsOwnerSaveReadTx(tx, in, request, r, packet)
}

func endpointGroupsOwnerReconcileTx(tx *sql.Tx, a *hubAppNodeActor, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, seal HubEndpointGroupsSeal) (endpointGroupsOwnerReceipt, error) {
	q, ok := in.Body.(wire.OwnerEndpointGroupsReconcileRequest)
	if !ok || in.Original == nil || in.OriginalSeal == nil {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	original := *in.Original
	original.At, original.Now = in.At, nil
	originalRequest, err := endpointGroupsOwnerInput(tx, original)
	if err != nil || originalRequest.op == wire.OperationOwnerEndpointGroupsReconcile || originalRequest.c.RequestID == request.c.RequestID || originalRequest.c.OwnerID != request.c.OwnerID || originalRequest.c.AccountID != request.c.AccountID || originalRequest.c.DeviceID != request.c.DeviceID || originalRequest.c.Origin != request.c.Origin || originalRequest.c.HubID != request.c.HubID || !reflect.DeepEqual(original.Device, in.Device) || !bytes.Equal(original.Packet, q.Body.OriginalPacket) {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	// This path never calls a business helper. The writer decides between an
	// already committed original outcome and a permanent exact zero-effect fence.
	receipt, err := endpointGroupsOwnerProcessTx(tx, a, original, originalRequest, in.OriginalSeal, true)
	if errors.Is(err, ErrHubEndpointGroupsOutcomeUncertain) {
		return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "PREPARED", "OUTCOME_UNCERTAIN", seal)
	}
	if errors.Is(err, ErrHubEndpointGroupsPacketConflict) {
		return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "REJECTED_FENCED", "ORIGINAL_PACKET_CONFLICT", seal)
	}
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if !receipt.durable {
		return endpointGroupsOwnerStatusResultTx(tx, a, in, request, nil, "PREPARED", "OUTCOME_UNCERTAIN", seal)
	}
	return endpointGroupsOwnerStatusResultTx(tx, a, in, request, &receipt, "COMPLETED", "", seal)
}
