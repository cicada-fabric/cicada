package store

import (
	"bytes"
	"database/sql"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairNodeReadTx(tx *sql.Tx, in NodeControlRPCInput, pair string, at time.Time) (nativePairReceipt, error) {
	var r nativePairReceipt
	var operation, digest, created string
	var sequence uint64
	err := tx.QueryRow(`SELECT operation,sequence,pair_id,request_digest,outcome,response_packet,created_at FROM hub_native_pair_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, in.BindingID, in.NodeKeyEpoch, in.OperationID).Scan(&operation, &sequence, &r.pair, &digest, &r.state, &r.packet, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nativePairReceipt{}, nil
	}
	if err != nil {
		return nativePairReceipt{}, err
	}
	if operation != in.Operation || sequence != in.Sequence || r.pair != pair || digest != in.RequestDigest {
		return nativePairReceipt{}, ErrNodeControlRPCConflict
	}
	start, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	if !at.Before(start.Add(5 * time.Minute)) {
		return nativePairReceipt{}, nil
	}
	return r, nil
}

func nativePairNodeSaveReadTx(tx *sql.Tx, in NodeControlRPCInput, pair, state, nonce string, packet []byte, at time.Time) error {
	if len(packet) == 0 || len(packet) > wire.MaxNativePairNodeReconcilePacketBytes {
		return ErrHubAccountRejected
	}
	rows, err := tx.Query(`SELECT operation_id,created_at FROM hub_native_pair_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, in.BindingID, in.NodeKeyEpoch)
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
		start, e := time.Parse(time.RFC3339Nano, stamp)
		if e != nil {
			err = ErrHubAccountRejected
			break
		}
		if !at.Before(start.Add(5 * time.Minute)) {
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
	// Detached Node diagnostics never evict another still-cached original.
	// Their ephemeral outcome is a projection, not a permanent business ledger.
	if kept >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	for _, id := range drop {
		if _, err = tx.Exec(`DELETE FROM hub_native_pair_node_reads_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, in.BindingID, in.NodeKeyEpoch, id); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO hub_native_pair_node_reads_v1(owner_binding_id,node_key_epoch,operation_id,operation,sequence,pair_id,outcome,request_digest,nonce_digest,response_packet,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, in.BindingID, in.NodeKeyEpoch, in.OperationID, in.Operation, in.Sequence, pair, state, in.RequestDigest, nonce, packet, appNodeStamp(at))
	if isSQLiteConstraint(err) {
		return ErrNodeControlRPCConflict
	}
	return err
}

func nativePairNodeReconcileTx(tx *sql.Tx, in HubNativePairNodeInput, input NodeControlRPCInput, pair string, seal HubNativePairNodeSeal) ([]byte, error) {
	old, err := nativePairNodeReadTx(tx, input, pair, in.At)
	if err != nil || len(old.packet) > 0 {
		return old.packet, err
	}
	q, ok := in.Body.(wire.NativePairNodeReconcile)
	if !ok || in.Original == nil || in.OriginalSeal == nil {
		return nil, ErrHubAccountRejected
	}
	issued, err := time.Parse(time.RFC3339Nano, q.IssuedAt)
	if err != nil || issued.After(in.At.Add(30*time.Second)) || !in.At.Before(issued.Add(time.Minute)) {
		return nil, ErrHubAccountRejected
	}
	original := *in.Original
	original.At = in.At
	original.Now = nil
	op, originalPair, err := nativePairNodeInput(original)
	if err != nil || originalPair != pair || op.Operation == wire.OperationNativePairNodeReconcile || original.CredentialDigest != in.CredentialDigest || !bytes.Equal(q.OriginalPacket, original.Packet) {
		return nil, ErrHubAccountRejected
	}
	qp, err := wire.DecodeNativePairNodePacket(in.Packet)
	if err != nil {
		return nil, err
	}
	p, err := wire.DecodeNativePairNodePacket(original.Packet)
	if err != nil {
		return nil, err
	}
	want := p.Route
	want.Operation = wire.OperationNativePairNodeReconcile
	want.OperationID = qp.Route.OperationID
	if want != qp.Route || want.OperationID == p.Route.OperationID {
		return nil, ErrNodeControlRPCConflict
	}
	if _, err = nativePairRetainedNodeKeyTx(tx, in.CredentialDigest, p.Route, in.Hub, in.NodeControlPublic); err != nil {
		return nil, err
	}
	if err = nativePairNodeRateTx(tx, input, in.At); err != nil {
		return nil, err
	}
	r, err := nativePairNodeBusinessTx(tx, original, op, pair, in.OriginalSeal, true)
	if err != nil {
		return nil, err
	}
	// A v64 opaque receipt without an outcome is unresolved, never guessed from
	// an occupied slot or from the inbox's generic COMPLETE processing state.
	if r.state != "COMPLETED" && r.state != "REJECTED_FENCED" && r.state != "READ_EXPIRED" {
		return nil, ErrNodeControlRPCConflict
	}
	result := wire.NativePairNodeReconciled{ContractRevision: wire.NativePairContractRevision, PairID: pair, OriginalOperation: op.Operation, OriginalOperationID: op.OperationID, OriginalSequence: op.Sequence, OriginalPacketDigest: op.RequestDigest, State: r.state, ReceiptPacket: r.packet, ObservedAt: appNodeStamp(in.At)}
	if r.state == "READ_EXPIRED" {
		result.ReceiptPacket = nil
	}
	if wire.ValidateNativePairNodeReconcileTarget(result, pair, original.Packet) != nil {
		return nil, ErrHubAccountRejected
	}
	packet, err := seal(HubNativePairNodeOutput{Reconciled: &result})
	if err != nil {
		return nil, err
	}
	if err = nativePairNodeSaveReadTx(tx, input, pair, r.state, AccountDigest("native-pair-node-query-nonce", q.Nonce), packet, in.At); err != nil {
		return nil, err
	}
	return packet, nil
}
