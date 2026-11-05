package store

import (
	"database/sql"
	"encoding/json"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"time"
)

// Bounded maintenance runs under the existing Store writer. Unknown originals
// and current effects are preserved. No daemon or lease-renewal work is added.
func threadCollaborationGCTx(tx *sql.Tx, at time.Time) error {
	stamp := appNodeStamp(at.Add(-5*time.Minute - 30*time.Second))
	_, err := tx.Exec(`DELETE FROM thread_collaboration_owner_originals_v1 WHERE rowid IN(SELECT rowid FROM thread_collaboration_owner_originals_v1 WHERE operation IN('owner.thread_collaboration.read','owner.thread_collaboration.prepare','owner.thread_collaboration.status','owner.thread_collaboration.reconcile') AND julianday(created_at)<julianday(?) ORDER BY created_at LIMIT 256)`, stamp)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM node_control_rpc_inbox_v1 WHERE rowid IN(SELECT o.rowid FROM node_control_rpc_inbox_v1 o JOIN node_control_rpc_sequences_v1 h ON h.owner_binding_id=o.owner_binding_id AND h.node_key_epoch=o.node_key_epoch WHERE o.state='COMPLETE' AND h.last_sequence>o.sequence AND((o.operation IN('thread_scope.read','group_locks.read') AND julianday(o.created_at)<julianday(?)) OR(o.operation IN('group_locks.acquire','group_locks.renew','group_locks.release') AND julianday(o.created_at)<julianday(?))) ORDER BY o.created_at LIMIT 256)`, stamp, appNodeStamp(at.Add(-wire.GroupLockOriginalRecoverySeconds*time.Second-30*time.Second)))
	if err != nil {
		return err
	}
	// Shared monotonic sequence state survives receipt removal. An old carrier
	// can never be admitted as a fresh next-sequence business operation.
	_, err = tx.Exec(`DELETE FROM thread_collaboration_node_originals_v1 WHERE rowid IN(SELECT o.rowid FROM thread_collaboration_node_originals_v1 o JOIN node_control_rpc_sequences_v1 h ON h.owner_binding_id=o.owner_binding_id AND h.node_key_epoch=o.node_key_epoch WHERE h.last_sequence>o.sequence AND((o.operation IN('thread_scope.read','group_locks.read') AND julianday(o.created_at)<julianday(?)) OR julianday(o.created_at)<julianday(?)) ORDER BY o.created_at LIMIT 256)`, stamp, appNodeStamp(at.Add(-wire.GroupLockOriginalRecoverySeconds*time.Second-30*time.Second)))
	if err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT group_id,registration_id,source_epoch,operation_id,receipt_json,error_code FROM group_lock_originals_v1 WHERE julianday(created_at)<julianday(?) ORDER BY created_at LIMIT 256`, appNodeStamp(at.Add(-wire.GroupLockOriginalRecoverySeconds*time.Second-30*time.Second)))
	if err != nil {
		return err
	}
	type original struct {
		group, registration, id, receipt, code string
		epoch                                  uint64
	}
	var candidates []original
	for rows.Next() {
		var o original
		if err = rows.Scan(&o.group, &o.registration, &o.epoch, &o.id, &o.receipt, &o.code); err != nil {
			break
		}
		candidates = append(candidates, o)
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if re != nil {
		return re
	}
	for _, o := range candidates {
		created, e := wire.GroupLockOriginalTime(o.id)
		if e != nil || at.Before(created.Add(wire.GroupLockOriginalRecoverySeconds*time.Second)) {
			continue
		}
		if o.code == "" {
			var receipt wire.GroupLockReceipt
			if json.Unmarshal([]byte(o.receipt), &receipt) != nil || wire.ValidateGroupLockReceipt(receipt) != nil {
				continue
			}
			var version uint64
			if tx.QueryRow(`SELECT version FROM group_lock_slots_v1 WHERE group_id=? AND slot=?`, o.group, receipt.Slot).Scan(&version) != nil || version <= receipt.AppliedVersion {
				continue
			}
		}
		// Rejected effects have no live CAS to preserve. Their time-prefixed IDs
		// are permanently outside the execution window, even with a new body.
		if _, err = tx.Exec(`DELETE FROM group_lock_originals_v1 WHERE group_id=? AND registration_id=? AND source_epoch=? AND operation_id=?`, o.group, o.registration, o.epoch, o.id); err != nil {
			return err
		}
	}
	// Expired unconsumed reviews cannot authorize Apply; consumed reviews remain
	// linked to their retained low-frequency mutation receipts.
	_, err = tx.Exec(`DELETE FROM thread_collaboration_owner_reviews_v1 WHERE review_id IN(SELECT review_id FROM thread_collaboration_owner_reviews_v1 WHERE state='PREPARED' AND julianday(expires_at)<julianday(?) LIMIT 256)`, appNodeStamp(at.Add(-24*time.Hour)))
	return err
}
