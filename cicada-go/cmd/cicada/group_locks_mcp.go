package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The final trusted-caller digest and sealed original live in the existing Node
// outbox. This credential-free intent preserves its IDs before the private RPC.
type mcpGroupLockIntent struct {
	Scope           wire.GroupLockScope              `json:"scope"`
	Slot            uint8                            `json:"slot"`
	ExpectedVersion uint64                           `json:"expected_version"`
	Generation      uint64                           `json:"generation,omitempty"`
	TTLSeconds      *uint32                          `json:"ttl_seconds,omitempty"`
	Note            string                           `json:"note,omitempty"`
	Original        wire.ThreadCollaborationOriginal `json:"original"`
}

func groupLockOperation(name string) string {
	switch name {
	case "cicada_thread_scope":
		return wire.OperationThreadScopeRead
	case "cicada_group_locks":
		return wire.OperationGroupLocksRead
	case "cicada_group_lock_acquire":
		return wire.OperationGroupLocksAcquire
	case "cicada_group_lock_renew":
		return wire.OperationGroupLocksRenew
	case "cicada_group_lock_release":
		return wire.OperationGroupLocksRelease
	}
	return ""
}

func groupLockTool(operation string) string {
	switch operation {
	case wire.OperationGroupLocksAcquire:
		return "cicada_group_lock_acquire"
	case wire.OperationGroupLocksRenew:
		return "cicada_group_lock_renew"
	case wire.OperationGroupLocksRelease:
		return "cicada_group_lock_release"
	}
	return ""
}
func isGroupLockOutboxKind(kind string) bool { return groupLockTool(kind) != "" }

func parseGroupLockMCPArguments(name string, args map[string]any) (mcpGroupLockIntent, string, bool, error) {
	var result mcpGroupLockIntent
	invalid := errors.New("invalid Group lock arguments; preserve the exact observed slot/version/generation")
	op := groupLockOperation(name)
	if op == "" {
		return result, "", false, invalid
	}
	if op == wire.OperationThreadScopeRead || op == wire.OperationGroupLocksRead {
		if len(args) != 0 {
			return result, "", false, invalid
		}
		return result, "", false, nil
	}
	allowed := map[string]bool{"slot": true, "expected_version": true, "idempotency_key": true, "recover": true}
	if op != wire.OperationGroupLocksAcquire {
		allowed["generation"] = true
	}
	if op != wire.OperationGroupLocksRelease {
		allowed["ttl_seconds"] = true
	}
	if op == wire.OperationGroupLocksAcquire {
		allowed["note"] = true
	}
	for key := range args {
		if !allowed[key] {
			return result, "", false, invalid
		}
	}
	slot, ok := strictMCPInteger(args["slot"])
	if !ok || slot < 1 || slot > 8 {
		return result, "", false, invalid
	}
	result.Slot = uint8(slot)
	version, ok := strictMCPInteger(args["expected_version"])
	if !ok || version < 1 {
		return result, "", false, invalid
	}
	result.ExpectedVersion = uint64(version)
	if op != wire.OperationGroupLocksAcquire {
		generation, ok := strictMCPInteger(args["generation"])
		if !ok || generation < 1 {
			return result, "", false, invalid
		}
		result.Generation = uint64(generation)
	}
	if value, present := args["ttl_seconds"]; present {
		ttl, ok := strictMCPInteger(value)
		if !ok || ttl < 1 || ttl > 3600 {
			return result, "", false, invalid
		}
		seconds := uint32(ttl)
		result.TTLSeconds = &seconds
	}
	if value, present := args["note"]; present {
		note, ok := value.(string)
		if !ok || !utf8.ValidString(note) || len(note) > wire.MaxGroupLockNoteBytes || strings.ContainsRune(note, 0) {
			return result, "", false, invalid
		}
		result.Note = note
	}
	key, ok := args["idempotency_key"].(string)
	if !ok {
		return result, "", false, invalid
	}
	key, err := normalizeMCPOutboxKey(key)
	if err != nil || key == "" {
		return result, "", false, invalid
	}
	recover := false
	if value, present := args["recover"]; present {
		var ok bool
		recover, ok = value.(bool)
		if !ok {
			return result, "", false, invalid
		}
	}
	return result, key, recover, nil
}

func groupLockInputsEqual(a, b mcpOutboxInput) bool {
	if a.GroupLock == nil || b.GroupLock == nil {
		return false
	}
	x, y := *a.GroupLock, *b.GroupLock
	x.Original, y.Original = wire.ThreadCollaborationOriginal{}, wire.ThreadCollaborationOriginal{}
	a.GroupLock, b.GroupLock = &x, &y
	return reflect.DeepEqual(a, b)
}

func stampGroupLockMCPInput(input mcpOutboxInput) (mcpOutboxInput, string, error) {
	if input.GroupLock == nil {
		return input, "", errMCPOutboxConflict
	}
	lock := *input.GroupLock
	if lock.Original != (wire.ThreadCollaborationOriginal{}) {
		return input, "", errMCPOutboxConflict
	}
	original, err := wire.NewGroupLockOriginal(time.Now().UTC())
	if err != nil {
		return input, "", err
	}
	lock.Original = original
	input.GroupLock = &lock
	return input, original.OperationID, nil
}

func (m *mcpServer) currentGroupLockScope() (wire.GroupLockScope, error) {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()
	relation := m.sessionEndpointGroupAuthority.Relation
	if m.sessionDomain.EndpointGroupsVersion != 1 || m.sessionGroupID == "" || relation.GroupID != m.sessionGroupID || relation.EndpointID != m.endpointID || relation.HubID == "" || relation.NetworkID == "" {
		return wire.GroupLockScope{}, errEndpointGroupsSelection
	}
	return wire.GroupLockScope{HubID: relation.HubID, NetworkID: relation.NetworkID, GroupID: relation.GroupID}, nil
}

func (m *mcpServer) threadCollaborationRequest(operation string) (localThreadCollaborationRequest, error) {
	base, err := m.endpointGroupsRequest(operation, "")
	if err != nil {
		return localThreadCollaborationRequest{}, err
	}
	base.Cursor, base.Limit = "", 0
	if operation != wire.OperationThreadScopeRead {
		scope, err := m.currentGroupLockScope()
		if err != nil {
			return localThreadCollaborationRequest{}, err
		}
		base.GroupID = scope.GroupID
	}
	return localThreadCollaborationRequest{localEndpointGroupsRequest: base}, nil
}

func (m *mcpServer) threadCollaborationTool(name string, args map[string]any) (any, error) {
	intent, key, recover, err := parseGroupLockMCPArguments(name, args)
	if err != nil {
		return nil, err
	}
	operation := groupLockOperation(name)
	if operation == wire.OperationThreadScopeRead || operation == wire.OperationGroupLocksRead {
		q, err := m.threadCollaborationRequest(operation)
		if err != nil {
			return nil, err
		}
		if operation == wire.OperationGroupLocksRead {
			scope, err := m.currentGroupLockScope()
			if err != nil {
				return nil, err
			}
			q.Scope = &scope
		}
		result, err := requestMachineAgentThreadCollaboration(context.Background(), m.joinSocketPath(harness.SessionContext{MachineID: m.codexContext.nodeID}), q)
		if err != nil {
			return nil, err
		}
		if result == nil || result.Operation != operation || result.Receipt != nil {
			return nil, errCodexMCPContext
		}
		if operation == wire.OperationThreadScopeRead {
			if result.Scope == nil || wire.ValidateThreadScopeView(*result.Scope) != nil || result.Scope.NodeID != m.codexContext.nodeID {
				return nil, errCodexMCPContext
			}
			return result.Scope, nil
		}
		if result.Locks == nil || wire.ValidateGroupSlotView(*result.Locks) != nil || result.Locks.Scope != *q.Scope {
			return nil, errCodexMCPContext
		}
		return result.Locks, nil
	}
	scope, err := m.currentMCPOutboxScope()
	if err != nil {
		return nil, err
	}
	intent.Scope, err = m.currentGroupLockScope()
	if err != nil {
		return nil, err
	}
	store, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, err
	}
	input := mcpOutboxInput{GroupLock: &intent}
	if recover {
		prior, err := store.findByIdempotencyKey(scope, key)
		if err != nil {
			return nil, err
		}
		if prior == nil || prior.Kind != operation {
			return nil, errMCPOutboxNotFound
		}
		var original mcpOutboxInput
		if json.Unmarshal([]byte(prior.InputJSON), &original) != nil || !groupLockInputsEqual(original, input) {
			return nil, errMCPOutboxConflict
		}
		if prior.Status == mcpOutboxStatusSent || prior.Status == mcpOutboxStatusFailed {
			return mcpOutboxPublicResult(*prior), nil
		}
		return m.dispatchMCPOutbox(store, scope, *prior)
	}
	op, created, err := store.prepare(scope, operation, key, input)
	if err != nil {
		return nil, err
	}
	if !created {
		return mcpOutboxPublicResult(op), nil
	}
	return m.dispatchMCPOutbox(store, scope, op)
}

func (m *mcpServer) dispatchGroupLockMCPOutbox(store *mcpOutboxStore, scope mcpOutboxScope, op mcpOutboxOperation) (any, error) {
	var input mcpOutboxInput
	unknown := func() (any, error) { return groupLockOutboxUnknown(store, scope, op) }
	if json.Unmarshal([]byte(op.InputJSON), &input) != nil || input.GroupLock == nil {
		return unknown()
	}
	lock := input.GroupLock
	current, err := m.currentGroupLockScope()
	if err != nil || current != lock.Scope || lock.Original.OperationID != op.OperationID {
		return unknown()
	}
	q, err := m.threadCollaborationRequest(op.Kind)
	if err != nil {
		return unknown()
	}
	// Only the original tool with explicit recover may retry a lock. Generic
	// outbox status remains readable, but cannot turn another purpose into it.
	if q.ToolName != groupLockTool(op.Kind) {
		return unknown()
	}
	return sendGroupLockOutbox(context.Background(), m.joinSocketPath(harness.SessionContext{MachineID: m.codexContext.nodeID}), store, scope, op, q)
}

func groupLockOutboxUnknown(store *mcpOutboxStore, scope mcpOutboxScope, op mcpOutboxOperation) (any, error) {
	saved, err := store.markError(scope, op.OperationID, mcpOutboxStatusUnknown, errors.New("Group lock outcome is unknown; original request retained"))
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(saved), nil
}

// Both native producers use the same persisted original and authenticated
// evidence settlement. No HTTP error or current Guard denial is a no-effect fence.
func sendGroupLockOutbox(ctx context.Context, socket string, store *mcpOutboxStore, scope mcpOutboxScope, op mcpOutboxOperation, q localThreadCollaborationRequest) (any, error) {
	unknown := func() (any, error) { return groupLockOutboxUnknown(store, scope, op) }
	var input mcpOutboxInput
	if json.Unmarshal([]byte(op.InputJSON), &input) != nil || input.GroupLock == nil || !mcpOutboxScopeMatches(op, scope) {
		return unknown()
	}
	lock := input.GroupLock
	if lock.Original.OperationID != op.OperationID || q.Operation != op.Kind || q.APIOrigin != scope.APIOrigin || q.Harness != scope.Harness || q.NativeSessionID != scope.NativeSessionID || q.Workspace != scope.Workspace || q.GroupID != scope.GroupID || q.codexEndpointGroupsBinding != scope.codexEndpointGroupsBinding {
		return unknown()
	}
	switch op.Kind {
	case wire.OperationGroupLocksAcquire:
		q.Acquire = &wire.GroupLockAcquireRequest{Scope: lock.Scope, Slot: lock.Slot, ExpectedVersion: lock.ExpectedVersion, Note: lock.Note, TTLSeconds: lock.TTLSeconds, Original: lock.Original}
	case wire.OperationGroupLocksRenew:
		q.Renew = &wire.GroupLockRenewRequest{Scope: lock.Scope, Slot: lock.Slot, ExpectedVersion: lock.ExpectedVersion, Generation: lock.Generation, TTLSeconds: lock.TTLSeconds, Original: lock.Original}
	case wire.OperationGroupLocksRelease:
		q.Release = &wire.GroupLockReleaseRequest{Scope: lock.Scope, Slot: lock.Slot, ExpectedVersion: lock.ExpectedVersion, Generation: lock.Generation, Original: lock.Original}
	default:
		return unknown()
	}
	result, err := requestMachineAgentThreadCollaboration(ctx, socket, q)
	if err != nil || result == nil || result.Operation != op.Kind || result.Evidence == nil {
		return unknown()
	}
	e := result.Evidence
	if e.Operation != op.Kind || e.Original.OperationID != lock.Original.OperationID || e.Original.IdempotencyKey != lock.Original.IdempotencyKey || !localContextHex(e.Original.RequestDigest, 64) || e.Original.RequestDigest == strings.Repeat("0", 64) || !localContextHex(e.RequestPacketDigest, 64) || !localContextHex(e.ResponsePacketDigest, 64) {
		return unknown()
	}
	status := mcpOutboxStatusUnknown
	if e.Outcome == localThreadCollaborationRejectedFenced && result.Receipt == nil && e.ErrorCode != "" {
		status = mcpOutboxStatusFailed
	}
	if e.Outcome == localThreadCollaborationApplied && result.Receipt != nil {
		r := result.Receipt
		outcome := map[string]string{wire.OperationGroupLocksAcquire: "ACQUIRED", wire.OperationGroupLocksRenew: "RENEWED", wire.OperationGroupLocksRelease: "RELEASED"}[op.Kind]
		if wire.ValidateGroupLockReceipt(*r) != nil || r.Scope != lock.Scope || r.Slot != lock.Slot || r.OperationID != lock.Original.OperationID || r.RequestDigest != e.Original.RequestDigest || r.Outcome != outcome || r.AppliedVersion != lock.ExpectedVersion+1 || op.Kind != wire.OperationGroupLocksAcquire && r.Generation != lock.Generation {
			return unknown()
		}
		status = mcpOutboxStatusSent
	}
	if status == mcpOutboxStatusUnknown {
		return unknown()
	}
	raw, err := json.Marshal(map[string]any{"receipt": result.Receipt, "evidence": e, "current_state_requires_read": true})
	if err != nil {
		return unknown()
	}
	saved, err := store.markResult(scope, op.OperationID, status, e.ErrorCode, string(raw))
	if err != nil {
		return nil, err
	}
	return mcpOutboxPublicResult(saved), nil
}
