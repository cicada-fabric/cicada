package main

import (
	"database/sql"
	"encoding/json"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Runs inside the same SQLite transaction as insertion. A repeated prompt with
// another key cannot create a second acquire while this slot's outcome is unknown.
func pendingGroupLockAcquire(tx *sql.Tx, scope mcpOutboxScope, slot uint8) (*mcpOutboxOperation, error) {
	rows, err := tx.Query(`SELECT operation_id,kind,status,api_origin,scope,harness,native_session_id,
node_id,workspace,endpoint_id,group_id,network_id,idempotency_key,input_json,input_digest,
attempt_count,last_error,result_json,created_at,updated_at,codex_domain_binding
FROM mcp_outbox_operations WHERE api_origin=? AND scope=? AND harness=? AND native_session_id=?
AND node_id=? AND workspace=? AND endpoint_id=? AND group_id=? AND network_id=?
AND kind=? AND status IN (?,?) LIMIT 9`, scope.APIOrigin, scope.Scope, scope.Harness, scope.NativeSessionID, scope.NodeID, scope.Workspace, scope.EndpointID, scope.GroupID, scope.NetworkID, wire.OperationGroupLocksAcquire, mcpOutboxStatusPending, mcpOutboxStatusUnknown)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var op mcpOutboxOperation
		if err := scanMCPOutboxOperation(rows, &op); err != nil {
			return nil, err
		}
		var input mcpOutboxInput
		if json.Unmarshal([]byte(op.InputJSON), &input) != nil || input.GroupLock == nil {
			return nil, errMCPOutboxConflict
		}
		if input.GroupLock.Slot == slot {
			if !mcpOutboxScopeMatches(op, scope) {
				return nil, errMCPOutboxContext
			}
			return &op, nil
		}
	}
	return nil, rows.Err()
}

func validGroupLockOutboxInput(scope mcpOutboxScope, kind string, input mcpOutboxInput) error {
	l := input.GroupLock
	if l == nil {
		return errMCPOutboxConflict
	}
	relation := scope.EndpointGroupAuthority.Relation
	if l.Scope.GroupID != scope.GroupID || l.Scope.HubID != relation.HubID || l.Scope.NetworkID != relation.NetworkID {
		return errMCPOutboxContext
	}
	switch kind {
	case wire.OperationGroupLocksAcquire:
		return wire.ValidateGroupLockAcquireRequest(wire.GroupLockAcquireRequest{Scope: l.Scope, Slot: l.Slot, ExpectedVersion: l.ExpectedVersion, TTLSeconds: l.TTLSeconds, Note: l.Note, Original: l.Original})
	case wire.OperationGroupLocksRenew:
		return wire.ValidateGroupLockRenewRequest(wire.GroupLockRenewRequest{Scope: l.Scope, Slot: l.Slot, ExpectedVersion: l.ExpectedVersion, Generation: l.Generation, TTLSeconds: l.TTLSeconds, Original: l.Original})
	case wire.OperationGroupLocksRelease:
		return wire.ValidateGroupLockReleaseRequest(wire.GroupLockReleaseRequest{Scope: l.Scope, Slot: l.Slot, ExpectedVersion: l.ExpectedVersion, Generation: l.Generation, Original: l.Original})
	}
	return errMCPOutboxConflict
}

// Original coordinates are data, never new authorization. Terminal operators
// load these before a recovery RPC so a pending Node mutation is not replaced
// by a metadata/describe request. The caller still obtains fresh native proof.
func (s *mcpOutboxStore) findGroupLockOperatorOriginal(scope mcpOutboxScope, kind, key string, slot uint8, recover bool) (*mcpOutboxOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.withDBLocked()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT operation_id,kind,status,api_origin,scope,harness,native_session_id,
node_id,workspace,endpoint_id,group_id,network_id,idempotency_key,input_json,input_digest,
attempt_count,last_error,result_json,created_at,updated_at,codex_domain_binding
FROM mcp_outbox_operations WHERE api_origin=? AND scope=? AND harness=? AND native_session_id=?
AND node_id=? AND workspace=? AND group_id=? AND network_id=''
AND (idempotency_key=? OR (kind=? AND status IN (?,?)))
ORDER BY CASE WHEN idempotency_key=? THEN 0 ELSE 1 END LIMIT 10`,
		scope.APIOrigin, scope.Scope, scope.Harness, scope.NativeSessionID, scope.NodeID, scope.Workspace, scope.GroupID,
		key, kind, mcpOutboxStatusPending, mcpOutboxStatusUnknown, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var op mcpOutboxOperation
		if err := scanMCPOutboxOperation(rows, &op); err != nil {
			return nil, err
		}
		if op.IdempotencyKey == key {
			if op.Kind != kind {
				return nil, errMCPOutboxConflict
			}
			return &op, nil
		}
		if !recover && kind == wire.OperationGroupLocksAcquire {
			var input mcpOutboxInput
			if json.Unmarshal([]byte(op.InputJSON), &input) != nil || input.GroupLock == nil {
				return nil, errMCPOutboxConflict
			}
			if input.GroupLock.Slot == slot {
				return &op, nil
			}
		}
	}
	return nil, rows.Err()
}

func groupLockOriginalOutboxScope(op mcpOutboxOperation) mcpOutboxScope {
	return mcpOutboxScope{APIOrigin: op.APIOrigin, Scope: op.Scope, Harness: op.Harness,
		NativeSessionID: op.NativeSessionID, NodeID: op.NodeID, Workspace: op.Workspace,
		EndpointID: op.EndpointID, GroupID: op.GroupID, NetworkID: op.NetworkID,
		codexOutboxBinding: op.codexOutboxBinding}
}
