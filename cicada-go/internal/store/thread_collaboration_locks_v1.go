package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"reflect"
	"time"
)

const threadCollaborationOriginalCapacity = 65536

// Called only after the current native registration, classification, exact
// Endpoint Group source and independently approved policy all pass Guard.
func threadCollaborationLockTx(tx *sql.Tx, caller wire.GroupLockHolder, operation string, request any, view wire.GroupSlotView, at time.Time) (wire.GroupLockReceipt, error) {
	var empty wire.GroupLockReceipt
	if wire.VerifyGroupLockRequestDigest(operation, caller, request) != nil {
		return empty, errors.New(wire.ThreadCollaborationErrorOriginalConflict)
	}
	var original wire.ThreadCollaborationOriginal
	var slot uint8
	var version, generation uint64
	var note string
	var ttl *uint32
	switch q := request.(type) {
	case wire.GroupLockAcquireRequest:
		original = q.Original
		slot = q.Slot
		version = q.ExpectedVersion
		note = q.Note
		ttl = q.TTLSeconds
	case wire.GroupLockRenewRequest:
		original = q.Original
		slot = q.Slot
		version = q.ExpectedVersion
		generation = q.Generation
		ttl = q.TTLSeconds
	case wire.GroupLockReleaseRequest:
		original = q.Original
		slot = q.Slot
		version = q.ExpectedVersion
		generation = q.Generation
	default:
		return empty, ErrNetworkPermission
	}
	if err := wire.ValidateGroupLockOriginalWindow(original, at); err != nil {
		return empty, errors.New(wire.ThreadCollaborationErrorReceiptUnavailable)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return empty, err
	}
	actor, err := json.Marshal(caller)
	if err != nil {
		return empty, err
	}
	rows, err := tx.Query(`SELECT operation_id,idempotency_key,operation,request_digest,request_json,caller_json,receipt_json,error_code FROM group_lock_originals_v1 WHERE group_id=? AND registration_id=? AND source_epoch=? AND(operation_id=? OR idempotency_key=?)`, view.Scope.GroupID, caller.Source.RegistrationID, caller.Source.SourceEpoch, original.OperationID, original.IdempotencyKey)
	if err != nil {
		return empty, err
	}
	var saved *wire.GroupLockReceipt
	for rows.Next() {
		var id, key, op, digest, raw, who, receipt, code string
		if err = rows.Scan(&id, &key, &op, &digest, &raw, &who, &receipt, &code); err != nil {
			break
		}
		if id != original.OperationID || key != original.IdempotencyKey || op != operation || digest != original.RequestDigest || raw != string(body) || who != string(actor) {
			err = errors.New(wire.ThreadCollaborationErrorOriginalConflict)
			break
		}
		if code != "" {
			err = errors.New(code)
			break
		}
		var r wire.GroupLockReceipt
		if json.Unmarshal([]byte(receipt), &r) != nil || wire.ValidateGroupLockReceipt(r) != nil {
			err = errors.New(wire.ThreadCollaborationErrorOriginalUncertain)
			break
		}
		saved = &r
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return empty, err
	}
	if re != nil {
		return empty, re
	}
	if saved != nil {
		return *saved, nil
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM group_lock_originals_v1`).Scan(&count); err != nil {
		return empty, err
	}
	if count >= threadCollaborationOriginalCapacity {
		return empty, errors.New(wire.ThreadCollaborationErrorAtLimit)
	}
	reject := func(code string) (wire.GroupLockReceipt, error) {
		_, e := tx.Exec(`INSERT INTO group_lock_originals_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, view.Scope.GroupID, caller.Source.RegistrationID, caller.Source.SourceEpoch, original.OperationID, original.IdempotencyKey, operation, original.RequestDigest, string(body), string(actor), "", code, appNodeStamp(at))
		if e != nil {
			return empty, e
		}
		return empty, errors.New(code)
	}
	if slot < 1 || int(slot) > len(view.Slots) {
		return reject(wire.ThreadCollaborationErrorSlotInvalid)
	}
	s := view.Slots[int(slot)-1]
	if operation != wire.OperationGroupLocksAcquire && s.State != "HELD" {
		return reject(wire.ThreadCollaborationErrorLeaseExpired)
	}
	if operation != wire.OperationGroupLocksAcquire && s.Generation != generation {
		return reject(wire.ThreadCollaborationErrorGenerationStale)
	}
	if s.Version != version {
		return reject(wire.ThreadCollaborationErrorVersionConflict)
	}
	if s.Version >= 1<<63-1 || s.Generation >= 1<<63-1 {
		return reject(wire.ThreadCollaborationErrorAtLimit)
	}
	out := wire.GroupLockReceipt{Format: wire.GroupLockReceiptFormat, Scope: view.Scope, OperationID: original.OperationID, RequestDigest: original.RequestDigest, Slot: slot, AppliedVersion: s.Version + 1, Generation: s.Generation, ObservedAt: appNodeStamp(at)}
	switch operation {
	case wire.OperationGroupLocksAcquire:
		if s.State != "FREE" {
			return reject(wire.ThreadCollaborationErrorSlotBusy)
		}
		out.Generation++
		out.Outcome = "ACQUIRED"
		out.ExpiresAt, err = wire.GroupLockLeaseExpiry(ttl, at)
		if err != nil {
			return empty, err
		}
		_, err = tx.Exec(`UPDATE group_lock_slots_v1 SET state='HELD',version=?,generation=?,holder_json=?,note=?,expires_at=? WHERE group_id=? AND slot=? AND version=?`, out.AppliedVersion, out.Generation, string(actor), note, out.ExpiresAt, view.Scope.GroupID, slot, version)
	case wire.OperationGroupLocksRenew, wire.OperationGroupLocksRelease:
		if s.State != "HELD" {
			return reject(wire.ThreadCollaborationErrorLeaseExpired)
		}
		if s.Generation != generation {
			return reject(wire.ThreadCollaborationErrorGenerationStale)
		}
		if s.Holder == nil || !reflect.DeepEqual(*s.Holder, caller) {
			return reject(wire.ThreadCollaborationErrorHolderMismatch)
		}
		if operation == wire.OperationGroupLocksRenew {
			out.Outcome = "RENEWED"
			out.ExpiresAt, err = wire.GroupLockLeaseExpiry(ttl, at)
			if err != nil {
				return empty, err
			}
			_, err = tx.Exec(`UPDATE group_lock_slots_v1 SET version=?,expires_at=? WHERE group_id=? AND slot=? AND version=? AND generation=?`, out.AppliedVersion, out.ExpiresAt, view.Scope.GroupID, slot, version, generation)
		} else {
			out.Outcome = "RELEASED"
			_, err = tx.Exec(`UPDATE group_lock_slots_v1 SET state='FREE',version=?,holder_json='',note='',expires_at='' WHERE group_id=? AND slot=? AND version=? AND generation=?`, out.AppliedVersion, view.Scope.GroupID, slot, version, generation)
		}
	default:
		return empty, ErrNetworkPermission
	}
	if err != nil {
		return empty, err
	}
	if wire.ValidateGroupLockReceipt(out) != nil {
		return empty, ErrNetworkPermission
	}
	receipt, err := json.Marshal(out)
	if err != nil {
		return empty, err
	}
	_, err = tx.Exec(`INSERT INTO group_lock_originals_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, view.Scope.GroupID, caller.Source.RegistrationID, caller.Source.SourceEpoch, original.OperationID, original.IdempotencyKey, operation, original.RequestDigest, string(body), string(actor), string(receipt), "", appNodeStamp(at))
	return out, err
}
