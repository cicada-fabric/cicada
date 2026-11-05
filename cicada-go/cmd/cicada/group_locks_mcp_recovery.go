package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var errGroupLockNeedsCurrentRead = errors.New("Group lock has no original to recover before current self-view")

// A Node's pending semantic mutation must be recovered before issuing another
// sealed describe RPC. This runs only after fresh Host consumption. Cached
// selection locates the original; neither the cache nor its old authority can
// authorize a new operation. The Node still verifies the original and Guard.
func (m *mcpServer) groupLockOriginalBeforeRefresh(ctx context.Context, name string, args map[string]any, native harness.SessionContext, binding codexDomainBinding, route *mcpGroupRoute) (any, bool, error) {
	intent, key, recover, err := parseGroupLockMCPArguments(name, args)
	if err != nil {
		return nil, true, err
	}
	if m.localNode == nil {
		if recover {
			return nil, true, errMCPOutboxContext
		}
		return nil, false, nil
	}
	scopeID, trusted, err := mcpSessionScope(m.baseURL, native)
	if err != nil {
		return nil, true, err
	}
	selected := ""
	if route != nil {
		if !validMCPGroupRoute(*route) || !sameMCPRouteThread(route.Native, trusted) || route.Native.NodeID != trusted.NodeID || !sameMCPFacadeHistoricalStore(route.Pin, m.localNode.Pin) {
			return nil, true, errMCPOriginalGroupRoute
		}
		selected = route.GroupID
	} else {
		m.sessionMu.RLock()
		if m.sessionContextSet && m.sessionContext == trusted && m.sessionDomain == binding {
			selected = m.sessionGroupID
		}
		m.sessionMu.RUnlock()
	}
	if selected == "" {
		state := m.sessionStateStore()
		if state == nil {
			if recover {
				return nil, true, errMCPOutboxContext
			}
			return nil, false, nil
		}
		cached, err := state.load(m.baseURL, native)
		if err != nil {
			return nil, true, err
		}
		if cached != nil {
			if m.validateCachedConnection(cached) != nil || cached.codexDomainBinding != binding {
				return nil, true, errMCPOutboxContext
			}
			selected = cached.GroupID
		}
	}
	if selected == "" {
		if recover {
			return nil, true, errEndpointGroupsSelection
		}
		return nil, false, nil
	}
	store, err := m.ensureMCPOutbox()
	if err != nil {
		return nil, true, err
	}
	selector := mcpOutboxScope{APIOrigin: m.baseURL, Scope: scopeID, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace, GroupID: selected}
	prior, err := store.findGroupLockOperatorOriginal(selector, groupLockOperation(name), key, intent.Slot, recover)
	if err != nil {
		return nil, true, err
	}
	if prior == nil {
		if recover {
			return nil, true, errMCPOutboxNotFound
		}
		return nil, false, nil
	}
	// Reuse the existing bounded, original-sender/Hub-key-checked reader. It
	// sees the live WAL and never derives a replacement Group or registration.
	op, _, err := readMCPFacadeOperation(m.localNode.Pin, trusted, prior.OperationID)
	if err != nil || op != *prior || op.codexDomainBinding != binding {
		return nil, true, errMCPOutboxContext
	}
	scope := groupLockOriginalOutboxScope(op)
	r := scope.EndpointGroupAuthority.Relation
	if route != nil && (route.RegistrationDigest != op.RegistrationDigest || route.RegistrationRevision != op.RegistrationRevision || route.NetworkID != r.NetworkID || route.EndpointID != op.EndpointID || route.OwnerID != r.OwnerID || route.PrincipalID != r.PrincipalID) {
		return nil, true, errMCPOriginalGroupRoute
	}
	intent.Scope = wire.GroupLockScope{HubID: r.HubID, NetworkID: r.NetworkID, GroupID: r.GroupID}
	if op.IdempotencyKey == key {
		var saved mcpOutboxInput
		if json.Unmarshal([]byte(op.InputJSON), &saved) != nil || !groupLockInputsEqual(saved, mcpOutboxInput{GroupLock: &intent}) {
			return nil, true, errMCPOutboxConflict
		}
	}
	if !recover || op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
		return mcpOutboxPublicResult(op), true, nil
	}
	base, err := m.endpointGroupsRequest(op.Kind, op.GroupID)
	if err != nil {
		return nil, true, err
	}
	base.Cursor, base.Limit = "", 0
	op, err = store.markAttempt(scope, op.OperationID)
	if err != nil {
		if errors.Is(err, errMCPOutboxTerminal) {
			return mcpOutboxPublicResult(op), true, nil
		}
		return nil, true, err
	}
	value, err := sendGroupLockOutbox(ctx, m.joinSocketPath(native), store, scope, op, localThreadCollaborationRequest{localEndpointGroupsRequest: base})
	return value, true, err
}

func (f *codexMCPFacade) groupLockOriginalBeforeRefresh(child *mcpServer, name string, business map[string]any, native harness.SessionContext, verified localCodexContext) (any, error) {
	_, _, recover, err := parseGroupLockMCPArguments(name, business)
	if err != nil {
		return nil, err
	}
	trusted := mcpTrustedContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace}
	cache, err := loadCodexRouteCache(f.userRoot, f.nonce, trusted)
	if err != nil {
		return nil, err
	}
	var route *mcpGroupRoute
	if cache.Selected != nil {
		copy := *cache.Selected
		route = &copy
	} else if len(f.children) == 1 {
		// Retain the existing single-Hub authenticated selection rule. A hint
		// locates history only; the Node must still authenticate the replay.
		hint, err := codexOriginalSingleHubHint(*child.localNode, trusted, child.adoptConnection, child.retainedArtifacts)
		if err == nil && hint.EndpointGroupsVersion == 1 && hint.GroupID != "" {
			r := hint.EndpointGroupAuthority.Relation
			route = &mcpGroupRoute{Pin: child.localNode.Pin, Native: trusted, NetworkID: r.NetworkID, GroupID: hint.GroupID, EndpointID: hint.EndpointID, OwnerID: r.OwnerID, PrincipalID: r.PrincipalID, RegistrationDigest: hint.RegistrationDigest, RegistrationRevision: hint.RegistrationRevision}
		}
	}
	if route == nil {
		if recover {
			return nil, errMCPGroupRouteRequired
		}
		return nil, errGroupLockNeedsCurrentRead
	}
	binding, err := codexContextBinding(verified)
	if err != nil {
		return nil, err
	}
	value, handled, err := child.groupLockOriginalBeforeRefresh(context.Background(), name, business, native, binding, route)
	if handled || err != nil {
		return value, err
	}
	return nil, errGroupLockNeedsCurrentRead
}
