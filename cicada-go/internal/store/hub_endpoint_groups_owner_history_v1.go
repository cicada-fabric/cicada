package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// A packet conflict never overwrites the original immutable response and is
// not a terminal receipt for another ciphertext sharing its request ID.
var ErrHubEndpointGroupsPacketConflict = errors.New("ORIGINAL_PACKET_CONFLICT")

var errEndpointGroupsOwnerPacketConflict = ErrHubEndpointGroupsPacketConflict

type endpointGroupsOwnerFloor struct {
	op, digest, nonce, account                 string
	accountEpoch, deviceEpoch, ownerKeyVersion uint64
}

type endpointGroupsOwnerHistory struct {
	floor   bool
	receipt endpointGroupsOwnerReceipt
}

func endpointGroupsOwnerFloorTx(tx *sql.Tx, request endpointGroupsOwnerRequest) (*endpointGroupsOwnerFloor, error) {
	var f endpointGroupsOwnerFloor
	err := tx.QueryRow(`SELECT operation,request_digest,nonce_digest,account_id,account_epoch,device_epoch,owner_key_version FROM hub_endpoint_groups_owner_nonces_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, request.c.OwnerID, request.c.DeviceID, request.c.RequestID).Scan(&f.op, &f.digest, &f.nonce, &f.account, &f.accountEpoch, &f.deviceEpoch, &f.ownerKeyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if f.op != request.op || f.digest != request.digest {
		return nil, errEndpointGroupsOwnerPacketConflict
	}
	s := request.claims.Scope
	if f.account != request.c.AccountID || f.accountEpoch != s.AccountEpoch || f.deviceEpoch != s.DeviceEpoch || f.ownerKeyVersion != s.OwnerKeyVersion || f.nonce != "" && f.nonce != request.nonce {
		return nil, errEndpointGroupsOwnerUncertain
	}
	return &f, nil
}

func endpointGroupsOwnerHistoryTx(tx *sql.Tx, request endpointGroupsOwnerRequest, at time.Time) (endpointGroupsOwnerHistory, error) {
	f, err := endpointGroupsOwnerFloorTx(tx, request)
	if err != nil {
		return endpointGroupsOwnerHistory{}, err
	}
	for _, table := range []string{"hub_endpoint_groups_owner_operations_v1", "hub_endpoint_groups_owner_reads_v1"} {
		var op, digest, nonce, account, state, created, operationJSON string
		var accountEpoch, deviceEpoch, ownerKeyVersion uint64
		var packet []byte
		query := `SELECT operation,request_digest,nonce_digest,account_id,account_epoch,device_epoch,owner_key_version,state,response_packet,created_at`
		if table == "hub_endpoint_groups_owner_operations_v1" {
			query += `,operation_json`
		}
		query += ` FROM ` + table + ` WHERE owner_id=? AND device_id=? AND operation_id=?`
		values := []any{&op, &digest, &nonce, &account, &accountEpoch, &deviceEpoch, &ownerKeyVersion, &state, &packet, &created}
		if table == "hub_endpoint_groups_owner_operations_v1" {
			values = append(values, &operationJSON)
		}
		err = tx.QueryRow(query, request.c.OwnerID, request.c.DeviceID, request.c.RequestID).Scan(values...)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return endpointGroupsOwnerHistory{}, err
		}
		if table == "hub_endpoint_groups_owner_reads_v1" && (request.op == wire.OperationOwnerEndpointGroupsPrepare || request.op == wire.OperationOwnerEndpointGroupsApply) {
			return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
		}
		if f == nil {
			return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
		}
		if op != f.op || digest != f.digest || nonce != f.nonce || account != f.account || accountEpoch != f.accountEpoch || deviceEpoch != f.deviceEpoch || ownerKeyVersion != f.ownerKeyVersion {
			return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
		}
		stamp, e := time.Parse(time.RFC3339Nano, created)
		if e != nil || len(packet) == 0 {
			return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
		}
		if table == "hub_endpoint_groups_owner_reads_v1" && !at.Before(stamp.Add(endpointGroupsOwnerReadLifetime)) {
			continue
		}
		r := endpointGroupsOwnerReceipt{packet: append([]byte(nil), packet...), state: state, durable: true}
		if operationJSON != "" {
			var operation wire.OwnerEndpointGroupsOperation
			if json.Unmarshal([]byte(operationJSON), &operation) != nil {
				return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
			}
			canonical, e := json.Marshal(operation)
			if e != nil || !bytes.Equal(canonical, []byte(operationJSON)) || request.op != wire.OperationOwnerEndpointGroupsApply || operation.OperationID != request.c.RequestID || operation.OriginalPacketDigest != request.digest || operation.State != state {
				return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
			}
			r.operation = &operation
		}
		if request.op == wire.OperationOwnerEndpointGroupsApply && ((state != "COMPLETED" && state != "REJECTED_FENCED") || state == "COMPLETED" && r.operation == nil) {
			return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
		}
		return endpointGroupsOwnerHistory{floor: true, receipt: r}, nil
	}
	if f != nil && (request.op == wire.OperationOwnerEndpointGroupsPrepare || request.op == wire.OperationOwnerEndpointGroupsApply) {
		return endpointGroupsOwnerHistory{}, errEndpointGroupsOwnerUncertain
	}
	return endpointGroupsOwnerHistory{floor: f != nil}, nil
}

func endpointGroupsOwnerNonceUsedTx(tx *sql.Tx, request endpointGroupsOwnerRequest) (bool, error) {
	if request.nonce == "" {
		return false, nil
	}
	s := request.claims.Scope
	var used int
	err := tx.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1 WHERE owner_id=? AND device_id=? AND account_epoch=? AND device_epoch=? AND owner_key_version=? AND nonce_digest=? AND operation_id!=?`, request.c.OwnerID, request.c.DeviceID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, request.nonce, request.c.RequestID).Scan(&used)
	return used != 0, err
}

func endpointGroupsOwnerClaimTx(tx *sql.Tx, request endpointGroupsOwnerRequest, at time.Time, fence bool) (string, error) {
	f, err := endpointGroupsOwnerFloorTx(tx, request)
	if err != nil {
		return "", err
	}
	if f != nil {
		return f.nonce, nil
	}
	used, err := endpointGroupsOwnerNonceUsedTx(tx, request)
	if err != nil {
		return "", err
	}
	if used {
		if !fence {
			return "", ErrHubAccountRejected
		}
		request.nonce = ""
	}
	s := request.claims.Scope
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_owner_nonces_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)`, request.c.OwnerID, request.c.DeviceID, request.c.RequestID, request.op, request.c.AccountID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, request.digest, request.nonce, appNodeStamp(at))
	return request.nonce, err
}

func endpointGroupsOwnerSavePermanentTx(tx *sql.Tx, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, r wire.OwnerEndpointGroupsResult, packet []byte, fence bool) (endpointGroupsOwnerReceipt, error) {
	if len(packet) == 0 || len(packet) > wire.MaxOwnerEndpointGroupsPacketBytes {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	nonce, err := endpointGroupsOwnerClaimTx(tx, request, in.At, fence)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	operationJSON := ""
	if r.Operation != nil {
		raw, e := json.Marshal(r.Operation)
		if e != nil {
			return endpointGroupsOwnerReceipt{}, e
		}
		operationJSON = string(raw)
	}
	s := request.claims.Scope
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_owner_operations_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, request.c.OwnerID, request.c.DeviceID, request.c.RequestID, request.op, request.c.AccountID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, request.digest, nonce, r.State, operationJSON, packet, appNodeStamp(in.At))
	return endpointGroupsOwnerReceipt{packet: packet, state: r.State, operation: r.Operation, durable: err == nil}, err
}

func endpointGroupsOwnerSaveReadTx(tx *sql.Tx, in HubEndpointGroupsInput, request endpointGroupsOwnerRequest, r wire.OwnerEndpointGroupsResult, packet []byte) (endpointGroupsOwnerReceipt, error) {
	if len(packet) == 0 || len(packet) > wire.MaxOwnerEndpointGroupsReconcilePacketBytes {
		return endpointGroupsOwnerReceipt{}, ErrHubAccountRejected
	}
	rows, err := tx.Query(`SELECT operation_id,account_epoch,device_epoch,owner_key_version,created_at FROM hub_endpoint_groups_owner_reads_v1 WHERE owner_id=? AND device_id=?`, request.c.OwnerID, request.c.DeviceID)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	var drop []string
	live := 0
	s := request.claims.Scope
	for rows.Next() {
		var id, created string
		var ae, de, ov uint64
		if err = rows.Scan(&id, &ae, &de, &ov, &created); err != nil {
			break
		}
		stamp, e := time.Parse(time.RFC3339Nano, created)
		if e != nil {
			err = errEndpointGroupsOwnerUncertain
			break
		}
		if !in.At.Before(stamp.Add(endpointGroupsOwnerReadLifetime)) {
			drop = append(drop, id)
		} else if ae == s.AccountEpoch && de == s.DeviceEpoch && ov == s.OwnerKeyVersion {
			live++
		}
	}
	re := rows.Err()
	rows.Close()
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	if re != nil {
		return endpointGroupsOwnerReceipt{}, re
	}
	if live >= 128 {
		return endpointGroupsOwnerReceipt{}, ErrHubOwnerDiagnosticsFull
	}
	for _, id := range drop {
		if _, err = tx.Exec(`DELETE FROM hub_endpoint_groups_owner_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, request.c.OwnerID, request.c.DeviceID, id); err != nil {
			return endpointGroupsOwnerReceipt{}, err
		}
	}
	nonce, err := endpointGroupsOwnerClaimTx(tx, request, in.At, false)
	if err != nil {
		return endpointGroupsOwnerReceipt{}, err
	}
	_, err = tx.Exec(`INSERT INTO hub_endpoint_groups_owner_reads_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, request.c.OwnerID, request.c.DeviceID, request.c.RequestID, request.op, request.c.AccountID, s.AccountEpoch, s.DeviceEpoch, s.OwnerKeyVersion, request.digest, nonce, r.State, packet, appNodeStamp(in.At))
	return endpointGroupsOwnerReceipt{packet: packet, state: r.State, operation: r.Operation, durable: err == nil}, err
}
