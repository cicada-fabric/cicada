package store

import (
	"database/sql"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nativePairStatusTx(tx *sql.Tx, a *hubAppNodeActor, in HubNativePairInput, seal HubNativePairSeal, expired bool) (nativePairReceipt, error) {
	c, _, _, op, pair, err := nativePairInput(in)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairReadRate(tx, c, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	p, err := nativePairOwned(tx, a, pair, in.At)
	if err != nil {
		return nativePairReceipt{}, err
	}
	administrative := false
	if !expired && nativePairFresh(c, in.At) && c.AccountSessionID == a.scope.AccountSessionID &&
		c.AccountEpoch == a.scope.AccountEpoch && c.DeviceEpoch == a.scope.DeviceEpoch && c.ClientSessionEpoch == a.scope.ClientSessionEpoch {
		current, e := nativePairCurrentScope(tx, a, p.scope.Node, in.Hub, in.NodeControlPublic)
		administrative = e == nil && current.NodeTupleDigest == p.scope.NodeTupleDigest && appNodeSameSecurity(current.Actor, p.scope.Actor) && p.state != wire.NativePairExpired && p.state != wire.NativePairRevoked
	}
	state, code := "COMPLETED", ""
	if expired || !nativePairFresh(c, in.At) {
		state = "READ_EXPIRED"
		code = "READ_EXPIRED"
	}
	digest := wire.NativePairPacketDigest(in.Packet)
	body, err := nativePairResultTx(tx, p, c, op, digest, state, code, administrative, in.At)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if state == "READ_EXPIRED" {
		body.SlotA = nil
		body.SlotB = nil
		body.AdministrativePermission = false
	}
	packet, err := seal(body)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairSaveRead(tx, c, op, pair, digest, state, packet, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	return nativePairReceipt{packet: packet, state: state, pair: pair}, nil
}

// Reconciliation never admits an original mutation. It returns its permanent
// exact receipt, or commits its rejection fence before the original can arrive.
// Neither an expired login nor a revoked current Root supplies fresh authority.
func nativePairReconcileTx(tx *sql.Tx, a *hubAppNodeActor, in HubNativePairInput, seal HubNativePairSeal) (nativePairReceipt, error) {
	q, ok := in.Body.(wire.NativePairReconcileRequest)
	if !ok || in.Original == nil || in.OriginalSeal == nil || !nativePairFresh(q.Context, in.At) {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	if err := nativePairReadRate(tx, q.Context, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	original := *in.Original
	original.At = in.At
	original.Now = nil
	c, _, _, op, pair, err := nativePairInput(original)
	if err != nil || op == wire.OperationNativePairReconcile || !nativePairSameActor(c, a) || wire.NativePairPacketDigest(q.OriginalPacket) != wire.NativePairPacketDigest(original.Packet) {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	if op != wire.OperationNativePairBootstrapPrepare && q.PairID != pair {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	r, err := nativePairProcessTx(tx, a, original, in.OriginalSeal, true)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if q.PairID != "" && q.PairID != r.pair {
		return nativePairReceipt{}, ErrHubAccountRejected
	}
	body := wire.NativePairReconciled{Format: wire.NativePairFormat, RequestID: q.Context.RequestID, RequestPacketDigest: wire.NativePairPacketDigest(in.Packet), PairID: r.pair, OriginalOperation: op, OriginalRequestID: c.RequestID, OriginalPacketDigest: wire.NativePairPacketDigest(original.Packet), State: r.state, ReceiptPacket: r.packet, ObservedAt: appNodeStamp(in.At)}
	if r.state == "READ_EXPIRED" {
		body.ReceiptPacket = nil
	}
	packet, err := seal(body)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairSaveRead(tx, q.Context, wire.OperationNativePairReconcile, r.pair, body.RequestPacketDigest, r.state, packet, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	return nativePairReceipt{packet: packet, state: r.state, pair: r.pair}, nil
}
