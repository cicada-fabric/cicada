package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// All new Node business effects and sequence/receipt projection commit together.
// Detached diagnostics use retained Node authentication and never admit their
// own route sequence as a business operation.
func (s *Store) ProcessHubNativePairNode(in HubNativePairNodeInput, seal HubNativePairNodeSeal) ([]byte, error) {
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
	guard, err := tx.Exec(`UPDATE hub_native_pair_guard_v1 SET touched_at=touched_at WHERE id=1`)
	if err != nil {
		return nil, err
	}
	if count, e := guard.RowsAffected(); e != nil || count != 1 {
		return nil, ErrHubAccountRejected
	}
	if in.Now != nil {
		in.At = in.Now().UTC()
	}
	input, pair, err := nativePairNodeInput(in)
	if err != nil {
		return nil, err
	}
	packet, err := wire.DecodeNativePairNodePacket(in.Packet)
	if err != nil {
		return nil, err
	}
	if _, err = nativePairRetainedNodeKeyTx(tx, in.CredentialDigest, packet.Route, in.Hub, in.NodeControlPublic); err != nil {
		return nil, err
	}
	var out []byte
	if input.Operation == wire.OperationNativePairNodeReconcile {
		out, err = nativePairNodeReconcileTx(tx, in, input, pair, seal)
	} else {
		var receipt nativePairReceipt
		receipt, err = nativePairNodeBusinessTx(tx, in, input, pair, seal, false)
		out = receipt.packet
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func nativePairNodeRateTx(tx *sql.Tx, in NodeControlRPCInput, at time.Time) error {
	var stamp string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_native_pair_node_rates_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, in.BindingID, in.NodeKeyEpoch).Scan(&stamp, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	start, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || !at.Before(start.Add(time.Minute)) {
		stamp = appNodeStamp(at)
		count = 0
	}
	if count >= 128 {
		return ErrHubOwnerDiagnosticsFull
	}
	_, err = tx.Exec(`INSERT INTO hub_native_pair_node_rates_v1 VALUES(?,?,?,?) ON CONFLICT(owner_binding_id,node_key_epoch) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests`, in.BindingID, in.NodeKeyEpoch, stamp, count+1)
	return err
}

func nativePairNodeInboxTx(tx *sql.Tx, in NodeControlRPCInput) (*NodeControlRPCRecord, error) {
	var r NodeControlRPCRecord
	err := tx.QueryRow(`SELECT operation_id,operation,request_digest,state,response_packet FROM node_control_rpc_inbox_v1 WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=?`, in.BindingID, in.NodeKeyEpoch, in.Sequence).Scan(&r.OperationID, &r.Operation, &r.RequestDigest, &r.State, &r.ResponsePacket)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if r.OperationID != in.OperationID || r.Operation != in.Operation || r.RequestDigest != in.RequestDigest {
		return nil, ErrNodeControlRPCConflict
	}
	return &r, nil
}

func nativePairNodeAdmitTx(tx *sql.Tx, in NodeControlRPCInput, at time.Time) error {
	var used int
	for _, table := range []string{"node_control_rpc_inbox_v1", "hub_native_pair_node_operations_v1"} {
		if err := tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE owner_binding_id=? AND node_key_epoch=? AND operation_id=?`, in.BindingID, in.NodeKeyEpoch, in.OperationID).Scan(&used); err != nil {
			return err
		}
		if used != 0 {
			return ErrNodeControlRPCConflict
		}
	}
	var high int64
	err := tx.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, in.BindingID, in.NodeKeyEpoch).Scan(&high)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Gaps, old/occupied sequences and unknown conflicting originals are not a
	// proof that this particular original had no effect. Do not skip a sequence.
	if high < 0 || in.Sequence != uint64(high)+1 || in.Sequence > uint64(^uint64(0)>>1) {
		return ErrNodeControlRPCConflict
	}
	stamp := appNodeStamp(at)
	if _, err = tx.Exec(`INSERT INTO node_control_rpc_sequences_v1(owner_binding_id,node_key_epoch,last_sequence) VALUES(?,?,?) ON CONFLICT(owner_binding_id,node_key_epoch) DO UPDATE SET last_sequence=excluded.last_sequence`, in.BindingID, in.NodeKeyEpoch, in.Sequence); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO node_control_rpc_inbox_v1(owner_binding_id,node_key_epoch,sequence,operation_id,operation,request_digest,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'PROCESSING',?,?)`, in.BindingID, in.NodeKeyEpoch, in.Sequence, in.OperationID, in.Operation, in.RequestDigest, stamp, stamp)
	return err
}

func nativePairNodeSaveTx(tx *sql.Tx, in NodeControlRPCInput, pair, state string, packet []byte, at time.Time) error {
	if len(packet) == 0 || len(packet) > wire.MaxNativePairNodeReceiptBytes {
		return ErrHubAccountRejected
	}
	if in.Operation == wire.OperationNativePairNodeDescribe {
		if state != "COMPLETED" && state != "READ_EXPIRED" {
			return ErrHubAccountRejected
		}
		if err := nativePairNodeSaveReadTx(tx, in, pair, state, AccountDigest("native-pair-node-read-nonce", []byte(in.OperationID)), packet, at); err != nil {
			return err
		}
	}
	if in.Operation == wire.OperationNativePairNodeJoin {
		if state != "COMPLETED" && state != "REJECTED_FENCED" {
			return ErrHubAccountRejected
		}
		if _, err := tx.Exec(`INSERT INTO hub_native_pair_node_operations_v1(owner_binding_id,node_key_epoch,sequence,operation_id,operation,pair_id,request_digest,response_packet,created_at,outcome) VALUES(?,?,?,?,?,?,?,?,?,?)`, in.BindingID, in.NodeKeyEpoch, in.Sequence, in.OperationID, in.Operation, pair, in.RequestDigest, packet, appNodeStamp(at), state); err != nil {
			return err
		}
	}
	result, err := tx.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='COMPLETE',response_packet=?,updated_at=? WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=? AND operation=? AND request_digest=? AND state='PROCESSING'`, packet, appNodeStamp(at), in.BindingID, in.NodeKeyEpoch, in.Sequence, in.OperationID, in.Operation, in.RequestDigest)
	if err != nil {
		return err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrNodeControlRPCConflict
	}
	return nil
}

func nativePairNodeBusinessTx(tx *sql.Tx, in HubNativePairNodeInput, input NodeControlRPCInput, pair string, seal HubNativePairNodeSeal, fence bool) (nativePairReceipt, error) {
	old, err := nativePairNodeHistoryTx(tx, input, pair)
	if err != nil {
		return old, err
	}
	if len(old.packet) > 0 {
		if old.state != "COMPLETED" && old.state != "REJECTED_FENCED" {
			return nativePairReceipt{}, ErrNodeControlRPCConflict
		}
		return old, nil
	}
	if input.Operation == wire.OperationNativePairNodeDescribe {
		cached, e := nativePairNodeReadTx(tx, input, pair, in.At)
		if e != nil || len(cached.packet) > 0 {
			return cached, e
		}
	}
	cached, err := nativePairNodeInboxTx(tx, input)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if cached != nil {
		if input.Operation != wire.OperationNativePairNodeDescribe || cached.State != NodeControlRPCComplete {
			return nativePairReceipt{}, ErrNodeControlRPCConflict
		}
		return nativePairNodeExpiredReadTx(tx, input, pair, seal, in.At, !fence)
	}
	// Old Describe reads can expire without publishing a new observation.
	if input.Operation == wire.OperationNativePairNodeDescribe {
		var high int64
		err = tx.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, input.BindingID, input.NodeKeyEpoch).Scan(&high)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nativePairReceipt{}, err
		}
		if high < 0 {
			return nativePairReceipt{}, ErrNodeControlRPCConflict
		}
		if input.Sequence <= uint64(high) {
			return nativePairNodeExpiredReadTx(tx, input, pair, seal, in.At, !fence)
		}
	}
	if !fence {
		if err = nativePairNodeRateTx(tx, input, in.At); err != nil {
			return nativePairReceipt{}, err
		}
	}
	if err = nativePairNodeAdmitTx(tx, input, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	state := "COMPLETED"
	var output HubNativePairNodeOutput
	if fence {
		if input.Operation == wire.OperationNativePairNodeDescribe {
			output.ErrorCode = "RESULT_EXPIRED"
			state = "READ_EXPIRED"
		} else {
			output.ErrorCode = wire.NativePairNodeJoinFenceCode
			state = "REJECTED_FENCED"
		}
	} else {
		if _, err = tx.Exec(`SAVEPOINT native_pair_node_effect`); err != nil {
			return nativePairReceipt{}, err
		}
		output, err = nativePairNodeEffectTx(tx, in, input, pair)
		if err != nil {
			if _, e := tx.Exec(`ROLLBACK TO native_pair_node_effect`); e != nil {
				return nativePairReceipt{}, e
			}
			if input.Operation != wire.OperationNativePairNodeJoin {
				return nativePairReceipt{}, err
			}
			output = HubNativePairNodeOutput{ErrorCode: wire.NativePairNodeJoinFenceCode}
			state = "REJECTED_FENCED"
		}
		if _, err = tx.Exec(`RELEASE native_pair_node_effect`); err != nil {
			return nativePairReceipt{}, err
		}
	}
	packet, err := seal(output)
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairNodeSaveTx(tx, input, pair, state, packet, in.At); err != nil {
		return nativePairReceipt{}, err
	}
	return nativePairReceipt{packet: packet, pair: pair, state: state}, nil
}

func nativePairNodeEffectTx(tx *sql.Tx, in HubNativePairNodeInput, input NodeControlRPCInput, pair string) (HubNativePairNodeOutput, error) {
	p, err := readNativePair(tx, pair)
	if err != nil || p == nil || len(p.bootstrapProof) == 0 {
		return HubNativePairNodeOutput{}, ErrHubAccountRejected
	}
	if err = nativePairExpireTx(tx, p, in.At); err != nil {
		return HubNativePairNodeOutput{}, err
	}
	if p.state != wire.NativePairWaitingJoin && p.state != wire.NativePairWaitingConsent {
		return HubNativePairNodeOutput{}, ErrHubAccountRejected
	}
	if !appNodeBefore(in.At, p.joinUntil) || nativePairNodeCurrentTx(tx, p, in, input) != nil {
		return HubNativePairNodeOutput{}, ErrHubAccountRejected
	}
	if p.accountHub.HubID == "" {
		public, e := json.Marshal(in.Hub)
		if e != nil {
			return HubNativePairNodeOutput{}, e
		}
		if _, e = tx.Exec(`UPDATE hub_native_pairs_v1 SET account_hub_identity_json=? WHERE pair_id=? AND account_hub_identity_json=''`, string(public), p.id); e != nil {
			return HubNativePairNodeOutput{}, e
		}
		p.accountHub = in.Hub
	}
	if input.Operation == wire.OperationNativePairNodeDescribe {
		d := wire.NativePairNodeDescription{ContractRevision: wire.NativePairContractRevision, PairID: p.id, HubIdentity: in.Hub, BootstrapOwnerProof: p.bootstrapProof}
		for _, slot := range []string{"A", "B"} {
			var generation uint64
			if err = tx.QueryRow(`SELECT generation FROM hub_native_pair_slots_v1 WHERE pair_id=? AND slot=? AND state!='REJECTED'`, p.id, slot).Scan(&generation); err != nil {
				return HubNativePairNodeOutput{}, err
			}
			if slot == "A" {
				d.SlotAGeneration = generation
			} else {
				d.SlotBGeneration = generation
			}
		}
		return HubNativePairNodeOutput{Description: &d}, nil
	}
	q, ok := in.Body.(wire.NativePairNodeJoin)
	if !ok || q.BootstrapProofDigest != wire.NativePairProofDigest(p.bootstrapProof) {
		return HubNativePairNodeOutput{}, ErrHubAccountRejected
	}
	result, err := nativePairZeroJoinTx(tx, p, q, in.SessionToken, in.At)
	return HubNativePairNodeOutput{Join: result}, err
}

func nativePairNodeExpiredReadTx(tx *sql.Tx, input NodeControlRPCInput, pair string, seal HubNativePairNodeSeal, at time.Time, rate bool) (nativePairReceipt, error) {
	if rate {
		if err := nativePairNodeRateTx(tx, input, at); err != nil {
			return nativePairReceipt{}, err
		}
	}
	packet, err := seal(HubNativePairNodeOutput{ErrorCode: "RESULT_EXPIRED"})
	if err != nil {
		return nativePairReceipt{}, err
	}
	if err = nativePairNodeSaveReadTx(tx, input, pair, "READ_EXPIRED", AccountDigest("native-pair-node-read-nonce", []byte(input.OperationID)), packet, at); err != nil {
		return nativePairReceipt{}, err
	}
	return nativePairReceipt{packet: packet, pair: pair, state: "READ_EXPIRED"}, nil
}
