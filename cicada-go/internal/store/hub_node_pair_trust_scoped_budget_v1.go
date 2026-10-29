package store

import (
	"database/sql"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func nodePairScopedReadRate(tx *sql.Tx, h wire.NodePairTrustScopedPacket, at time.Time) error {
	var start string
	var count int
	err := tx.QueryRow(`SELECT window_start,requests FROM hub_node_pair_trust_rates_v1 WHERE attempt_id=? AND sender_key_id=?`, h.AttemptID, h.SenderPublic.ID).Scan(&start, &count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	window, e := time.Parse(time.RFC3339Nano, start)
	if e != nil || !at.Before(window.Add(time.Minute)) {
		start = appNodeStamp(at)
		count = 0
	}
	if count >= 60 {
		return ErrNodePairTrustCapacity
	}
	_, err = tx.Exec(`INSERT INTO hub_node_pair_trust_rates_v1(attempt_id,sender_key_id,window_start,requests,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(attempt_id,sender_key_id) DO UPDATE SET window_start=excluded.window_start,requests=excluded.requests,expires_at=excluded.expires_at`, h.AttemptID, h.SenderPublic.ID, start, count+1, appNodeStamp(at.Add(2*time.Minute)))
	return err
}

func nodePairScopedCritical(tx *sql.Tx, in HubNodePairTrustScopedInput, result wire.NodePairTrustScopedResult) bool {
	op := in.Header.Operation
	if result.ErrorCode != "" || op == wire.OperationNodePairTrustScopedReconcile || op == wire.OperationOwnerNodePairTrustScopedLookup || op == wire.OperationOwnerNodePairTrustScopedStatus {
		return false
	}
	r, err := nodePairScopedLoad(tx, in.Header.AttemptID)
	if err != nil || r.Approval == nil {
		return false
	}
	if op == wire.OperationNodePairTrustScopedPoll {
		return result.State == wire.NodePairTrustScopedOwnerApproved
	}
	if op == wire.OperationNodePairTrustScopedCancel || op == wire.OperationOwnerNodePairTrustScopedCancel {
		if result.State != wire.NodePairTrustScopedCancelled {
			return false
		}
		var prior bool
		if tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hub_node_pair_trust_receipts_v1 WHERE attempt_id=? AND operation IN(?,?))`, in.Header.AttemptID, wire.OperationNodePairTrustScopedCancel, wire.OperationOwnerNodePairTrustScopedCancel).Scan(&prior) != nil {
			return false
		}
		return !prior
	}
	return op == wire.OperationOwnerNodePairTrustScopedPrepare || op == wire.OperationOwnerNodePairTrustScopedComplete || op == wire.OperationNodePairTrustScopedACK
}

func nodePairScopedReadExpiry(tx *sql.Tx, in HubNodePairTrustScopedInput) string {
	end := in.At.Add(2 * time.Minute)
	if in.Header.Operation == wire.OperationNodePairTrustScopedStart || in.Header.Operation == wire.OperationNodePairTrustScopedExisting || in.Header.Operation == wire.OperationNodePairTrustScopedCommit {
		if r, e := nodePairScopedLoad(tx, in.Header.AttemptID); e == nil {
			if expiry, e := time.Parse(time.RFC3339Nano, r.Context.ExpiresAt); e == nil {
				end = expiry.Add(10 * time.Minute)
			}
		}
	}
	return appNodeStamp(end)
}

func nodePairScopedSaveRecordBudget(tx *sql.Tx, r *nodePairTrustScopedRecord, raw []byte, at time.Time) error {
	authorized := 0
	if r.Approval != nil {
		authorized = 1
	}
	terminal := r.State != wire.NodePairTrustScopedPending && r.State != wire.NodePairTrustScopedOwnerApproved && r.State != "ACKING"
	_, err := tx.Exec(`UPDATE hub_node_pair_trust_v1 SET state=?,oob_commitment=?,authorized=?,reserved_bytes=CASE WHEN ? THEN 0 WHEN authorized=1 THEN max(0,reserved_bytes-max(0,?-length(CAST(record_json AS BLOB)))) ELSE reserved_bytes END,record_json=?,updated_at=? WHERE attempt_id=?`, r.State, r.OOB, authorized, terminal, len(raw), string(raw), appNodeStamp(at), r.Context.AttemptID)
	return err
}

func nodePairScopedContextExpiry(c wire.NodePairTrustScopedContext) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	return t
}
