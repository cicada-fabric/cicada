package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/apppaths"
	"github.com/cicada-ai/cicada/internal/harness"
)

// A facade owns one schema and independent original children. It never changes
// a child's origin, Node, session/outbox path, credential, pin or HTTP pool.
// The injected enumerator is the reviewed Manager boundary, never raw registry
// interpretation. Both enumeration and the selected child revalidate per call.
type codexMCPFacade struct {
	mu                sync.Mutex
	userRoot          string
	nonce             string
	list              ListVerifiedLocalNodeConnectionsFunc
	children          map[string]*mcpServer
	front             *mcpServer
	adoptConnection   codexAdoptionResolver
	retainedArtifacts codexArtifactValidator
}

func newRoutedLocalNodeMCPServer(userRoot string, list ListVerifiedLocalNodeConnectionsFunc) (*mcpServer, error) {
	f, err := newCodexMCPFacade(userRoot, list)
	if err != nil {
		return nil, err
	}
	f.adoptConnection = ResolveAdoptedLocalNodeConnection
	f.retainedArtifacts = ValidateRetainedLocalNodeArtifacts
	if err := f.refresh(context.Background()); err != nil {
		f.close()
		return nil, err
	}
	if len(f.children) == 0 {
		f.close()
		return nil, codexLocalNodeError(ErrLocalNodeNotRunning)
	}
	server := newMCPServerWithPaths("", "", "", "")
	server.codexFacade, f.front = f, server
	return server, nil
}

func newCodexMCPFacade(userRoot string, list ListVerifiedLocalNodeConnectionsFunc) (*codexMCPFacade, error) {
	if _, err := apppaths.ResolveUserRoot(userRoot); err != nil || list == nil {
		return nil, errMCPGroupRouteUnavailable
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &codexMCPFacade{userRoot: userRoot, nonce: hex.EncodeToString(nonce[:]), list: list, children: map[string]*mcpServer{}}, nil
}

func closeCodexMCPChild(child *mcpServer) {
	child.stopCodexHeartbeat()
	close(child.stop)
	child.selectedNodeHTTPPool().close()
	if child.outbox != nil {
		_ = child.outbox.close()
	}
}

func (f *codexMCPFacade) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, child := range f.children {
		closeCodexMCPChild(child)
		delete(f.children, id)
	}
}

func (f *codexMCPFacade) refresh(ctx context.Context) error {
	connections, err := f.list(ctx, f.userRoot)
	if err != nil {
		return codexLocalNodeError(err)
	}
	if len(connections) > MaxLocalNodeHubConnections {
		return ErrLocalNodeDiscoveryLimit
	}
	current := map[string]bool{}
	paths := map[string]bool{}
	writerRoot := ""
	for _, connection := range connections {
		if connection.Pin.UserRoot != f.userRoot || validateLocalNodePin(connection.Pin) != nil {
			return ErrLocalNodeDiscoveryInvalid
		}
		id, err := codexChildRouteID(connection.Pin)
		if err != nil || current[id] {
			return ErrLocalNodeDiscoveryInvalid
		}
		current[id] = true
		if writerRoot != "" && connection.Pin.WriterRoot != writerRoot {
			return ErrLocalNodeDiscoveryInvalid
		}
		writerRoot = connection.Pin.WriterRoot
		for _, path := range []string{connection.Pin.StateDir, connection.Pin.SocketPath, connection.Pin.MCPSessionStateFile, connection.Pin.MCPOutboxStateFile} {
			if paths[path] {
				return ErrLocalNodeDiscoveryInvalid
			}
			paths[path] = true
		}
	}
	for _, connection := range connections {
		id, _ := codexChildRouteID(connection.Pin)
		if f.children[id] != nil {
			continue
		}
		child, err := newLocalNodeChildMCPServer(connection)
		if err != nil {
			return err
		}
		child.codexContext.nonce, err = codexChildConnectionNonce(f.nonce, id)
		if err != nil {
			closeCodexMCPChild(child)
			return err
		}
		f.children[id] = child
		child.adoptConnection = f.adoptConnection
		child.retainedArtifacts = f.retainedArtifacts
	}
	for id, child := range f.children {
		if !current[id] {
			closeCodexMCPChild(child)
			delete(f.children, id)
		}
	}
	return nil
}

func (f *codexMCPFacade) envelope(name string, arguments map[string]any) (codexRoutedContext, error) {
	var zero, preliminary codexRoutedContext
	raw, err := json.Marshal(arguments[codexMCPContextArgument])
	if err != nil || len(raw) > maxCodexRoutedContext || decodeLocalNodeJSON(raw, &preliminary) != nil ||
		len(preliminary.Children) == 0 || len(preliminary.Children) > MaxLocalNodeHubConnections || name != "cicada_groups" && len(preliminary.Children) != 1 {
		return zero, errCodexMCPContext
	}
	expected := map[string]string{}
	business, err := codexBusinessArguments(arguments)
	if err != nil || validateMCPArguments(name, business) != nil {
		return zero, errCodexMCPContext
	}
	if isMCPFacadeOperationTool(name) && validateMCPFacadeOperationArguments(business) != nil {
		return zero, errMCPOutboxContext
	}
	if name == "cicada_groups" {
		qualified := stringArgument(business, "hub_id") != "" || stringArgument(business, "network_id") != ""
		if qualified && len(preliminary.Children) != 1 || !qualified && stringArgument(business, "cursor") != "" && len(f.children) > 1 {
			return zero, errMCPGroupRouteAmbiguous
		}
	}
	for _, ticket := range preliminary.Children {
		child := f.children[ticket.RouteID]
		if child == nil {
			return zero, errMCPGroupRouteUnavailable
		}
		if name == "cicada_groups" && stringArgument(business, "hub_id") != "" && child.localNode.Pin.HubID != stringArgument(business, "hub_id") {
			return zero, errMCPGroupRouteUnavailable
		}
		expected[ticket.RouteID] = child.codexContext.nonce
	}
	return decodeCodexRoutedContext(raw, f.nonce, expected)
}

func codexFreshSender(child *mcpServer, native harness.SessionContext, fresh *localEndpointGroupsResult) (mcpGroupRoute, error) {
	var zero mcpGroupRoute
	if fresh == nil || child.localNode == nil {
		return zero, errEndpointGroupsUnsupported
	}
	a := fresh.Description.Registration
	route := mcpGroupRoute{Pin: child.localNode.Pin, Native: mcpTrustedContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace},
		NetworkID: a.NetworkID, EndpointID: a.Registration.EndpointID, OwnerID: a.Registration.OwnerID, PrincipalID: a.Registration.PrincipalID,
		RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision}
	if !validMCPSenderRoute(route) || a.Registration.HubID != route.Pin.HubID || a.Registration.NodeID != route.Pin.NodeID ||
		a.Registration.Harness != native.Harness || a.Registration.NativeSessionID != native.NativeSessionID || a.Registration.Workspace != native.Workspace {
		return zero, errEndpointGroupsRegistration
	}
	return route, nil
}

func codexFreshGroupRoutes(sender mcpGroupRoute, groups endpointGroupsMCPResult) []mcpGroupRoute {
	routes := make([]mcpGroupRoute, 0, len(groups.Groups))
	for _, card := range groups.Groups {
		if card.NetworkID != sender.NetworkID {
			continue
		}
		route := sender
		route.GroupID = card.GroupID
		routes = append(routes, route)
	}
	return routes
}

func (f *codexMCPFacade) call(name string, arguments map[string]any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !isCicadaMCPTool(name) {
		return nil, errCodexMCPContext
	}
	if err := f.refresh(context.Background()); err != nil {
		return nil, err
	}
	if f.front != nil {
		for _, child := range f.children {
			child.stdio = f.front.stdio
		}
	}
	envelope, err := f.envelope(name, arguments)
	if err != nil {
		return nil, err
	}
	if name == "cicada_groups" {
		return f.groups(arguments, envelope)
	}
	ticket := envelope.Children[0]
	child := f.children[ticket.RouteID]
	childArgs, err := codexRoutedChildArguments(arguments, ticket)
	if err != nil {
		return nil, err
	}
	return child.callContextualToolVerified(name, childArgs, func(native harness.SessionContext, verified localCodexContext, fresh *localEndpointGroupsResult, business map[string]any) (any, error) {
		if isGroupLockOutboxKind(groupLockOperation(name)) && verified.EndpointGroupsVersion == 1 && fresh == nil {
			return f.groupLockOriginalBeforeRefresh(child, name, business, native, verified)
		}
		if isMCPFacadeOperationTool(name) {
			connections := make([]LocalNodeConnection, 0, len(f.children))
			for _, candidate := range f.children {
				connections = append(connections, *candidate.localNode)
			}
			located, err := locateMCPFacadeOperation(connections, mcpTrustedContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace}, stringArgument(business, "operation_id"))
			if err != nil {
				return nil, err
			}
			id, _ := codexChildRouteID(located[0].Pin)
			if id != ticket.RouteID {
				return nil, errMCPOriginalGroupRoute
			}
		}
		if isMCPFacadeOperationStatus(name) {
			// Repeat original-sender lookup after authenticating the actual
			// native context; never report another selected Hub's operation.
			return child.facadeOperationStatus(native, verified, business)
		}
		if isMCPFacadeOperationTool(name) {
			return child.facadeOperationRetry(native, verified, fresh, business)
		}
		if verified.EndpointGroupsVersion == 0 {
			trusted := mcpTrustedContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace}
			cache, err := loadCodexRouteCache(f.userRoot, f.nonce, trusted)
			if err != nil {
				return nil, err
			}
			if len(f.children) != 1 || cache.Selected != nil || !child.isJoined() {
				return nil, errMCPGroupRouteRequired
			}
			original, err := codexOriginalSingleHubHint(*child.localNode, trusted, child.adoptConnection, child.retainedArtifacts)
			if err != nil {
				return nil, err
			}
			binding, err := codexContextBinding(verified)
			child.sessionMu.RLock()
			same := original.codexDomainBinding == binding && child.sessionContext == trusted && child.sessionGroupID == original.GroupID && child.endpointID == original.EndpointID
			child.sessionMu.RUnlock()
			if err != nil || !same {
				return nil, errCodexMCPContext
			}
			return child.callToolWithContext(name, business)
		}
		sender, err := codexFreshSender(child, native, fresh)
		if err != nil {
			return nil, err
		}
		cache, err := loadCodexRouteCache(f.userRoot, f.nonce, sender.Native)
		if err != nil {
			return nil, err
		}
		if name == "cicada_use_group" {
			choice, err := parseMCPGroupRouteChoice(business)
			if err != nil {
				return nil, err
			}
			if choice.HubID != "" && choice.HubID != sender.Pin.HubID || choice.NetworkID != "" && choice.NetworkID != sender.NetworkID {
				return nil, errMCPGroupRouteUnavailable
			}
			// Recheck known cross-Hub ambiguity before any child selection.
			if choice.HubID == "" {
				if !cache.Complete {
					return nil, errMCPGroupRouteUnavailable
				}
				if _, err := resolveMCPGroupRoute(cache.Routes, sender.Native, choice); err != nil {
					return nil, err
				}
			}
			result, err := child.callToolWithContext(name, business)
			if err != nil {
				return nil, err
			}
			// The child's existing exact select follows only this Group's
			// bounded authenticated pages under the original call deadline.
			// Absence from the first self page was never a refusal or a grant.
			selected := sender
			selected.GroupID = choice.GroupID
			cache.Selected = &selected
			if err := saveCodexRouteSelection(f.userRoot, *cache); err != nil {
				return nil, err
			}
			return result, nil
		}
		if cache.Selected == nil {
			if len(f.children) == 1 {
				original, hintErr := codexOriginalSingleHubHint(*child.localNode, sender.Native, child.adoptConnection, child.retainedArtifacts)
				child.sessionMu.RLock()
				group, authority := child.sessionGroupID, child.sessionEndpointGroupAuthority
				child.sessionMu.RUnlock()
				if hintErr == nil && original.EndpointGroupsVersion == 1 && original.RegistrationDigest == sender.RegistrationDigest && original.EndpointID == sender.EndpointID && original.GroupID == group && original.EndpointGroupAuthority == authority {
					result, err := child.callToolWithContext(name, business)
					if err != nil {
						return nil, err
					}
					selected := sender
					selected.GroupID = original.GroupID
					cache.Selected = &selected
					if err := saveCodexRouteSelection(f.userRoot, *cache); err != nil {
						return nil, err
					}
					return result, nil
				}
				if name == "cicada_whoami" && len(business) == 0 {
					return map[string]any{"hub_id": sender.Pin.HubID, "network_id": sender.NetworkID, "endpoint_id": sender.EndpointID, "principal_id": sender.PrincipalID, "owner_id": sender.OwnerID, "harness": sender.Native.Harness, "native_session_id": sender.Native.NativeSessionID, "node_id": sender.Native.NodeID, "workspace": sender.Native.Workspace, "group_id": "", "selection_required": true, "freshness": "VERIFIED_SELF_SNAPSHOT"}, nil
				}
			}
			return nil, errMCPGroupRouteRequired
		}
		selected := *cache.Selected
		if selected.originalSender() != sender.originalSender() {
			return nil, errMCPOriginalGroupRoute
		}
		child.sessionMu.RLock()
		selectedGroup := child.sessionGroupID
		child.sessionMu.RUnlock()
		if selectedGroup != selected.GroupID {
			return nil, errMCPGroupRouteRequired
		}
		// Partial self pages cannot prove the selected Group absent. Preserve
		// the original child's exact selected scope and final Node/Hub Guard.
		return child.callToolWithContext(name, business)
	})
}

type codexFacadeGroupsHub struct {
	HubID     string                   `json:"hub_id"`
	NodeID    string                   `json:"node_id"`
	NetworkID string                   `json:"network_id,omitempty"`
	Status    string                   `json:"status"`
	Groups    *endpointGroupsMCPResult `json:"groups,omitempty"`
}

type codexFacadeGroupsResult struct {
	Groups            []codexFacadeGroupCard `json:"groups"`
	Hubs              []codexFacadeGroupsHub `json:"hubs"`
	Complete          bool                   `json:"complete"`
	CurrentHubID      string                 `json:"current_hub_id,omitempty"`
	CurrentNetworkID  string                 `json:"current_network_id,omitempty"`
	CurrentGroupID    string                 `json:"current_group_id,omitempty"`
	SelectionRequired bool                   `json:"selection_required"`
	Freshness         string                 `json:"freshness"`
	SelectionStatus   string                 `json:"selection_status"`
	RetainedHubID     string                 `json:"retained_hub_id,omitempty"`
	RetainedNetworkID string                 `json:"retained_network_id,omitempty"`
	RetainedGroupID   string                 `json:"retained_group_id,omitempty"`
}

type codexFacadeGroupCard struct {
	HubID  string `json:"hub_id"`
	NodeID string `json:"node_id"`
	endpointGroupsMCPCard
}

func (f *codexMCPFacade) groups(arguments map[string]any, envelope codexRoutedContext) (any, error) {
	business, err := codexBusinessArguments(arguments)
	if err != nil {
		return nil, err
	}
	qualified := stringArgument(business, "hub_id") != "" || stringArgument(business, "network_id") != ""
	result := codexFacadeGroupsResult{Groups: []codexFacadeGroupCard{}, Hubs: []codexFacadeGroupsHub{}, Complete: qualified || len(envelope.Children) == len(f.children), SelectionRequired: true, Freshness: "SNAPSHOT_ONLY", SelectionStatus: "UNVERIFIED"}
	var cache *codexRouteCache
	seen := map[string]bool{}
	callCtx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	var wait sync.WaitGroup
	var aggregate sync.Mutex
	type outcome struct {
		public codexFacadeGroupsHub
		err    error
	}
	outcomes := make([]outcome, len(envelope.Children))
	for i, ticket := range envelope.Children {
		child := f.children[ticket.RouteID]
		seen[ticket.RouteID] = true
		wait.Add(1)
		go func(i int, ticket codexRoutedChildTicket, child *mcpServer) {
			defer wait.Done()
			public := codexFacadeGroupsHub{HubID: child.localNode.Pin.HubID, NodeID: child.localNode.Pin.NodeID, Status: "UNAVAILABLE"}
			childArgs, err := codexRoutedChildArguments(arguments, ticket)
			if err != nil {
				outcomes[i] = outcome{public, err}
				return
			}
			_, err = child.callContextualToolVerifiedContext(callCtx, "cicada_groups", childArgs, func(native harness.SessionContext, verified localCodexContext, fresh *localEndpointGroupsResult, business map[string]any) (any, error) {
				aggregate.Lock()
				defer aggregate.Unlock()
				sender, err := codexFreshSender(child, native, fresh)
				if err != nil {
					return nil, err
				}
				if cache == nil {
					cache, err = loadCodexRouteCache(f.userRoot, f.nonce, sender.Native)
					if err != nil {
						return nil, err
					}
				} else if !sameMCPRouteThread(cache.Native, sender.Native) {
					return nil, errCodexMCPContext
				}
				listed, err := child.callToolWithContext("cicada_groups", business)
				if err != nil {
					return nil, err
				}
				groups := listed.(endpointGroupsMCPResult)
				freshRoutes := codexFreshGroupRoutes(sender, groups)
				mergeCodexRouteCacheView(cache, sender, freshRoutes, stringArgument(business, "cursor") == "")
				public.NetworkID, public.Status, public.Groups = sender.NetworkID, "VERIFIED_SNAPSHOT", &groups
				result.Complete = result.Complete && groups.Complete
				if cache.Selected != nil && cache.Selected.originalSender() == sender.originalSender() && groups.CurrentGroupID == cache.Selected.GroupID {
					for _, route := range freshRoutes {
						if route.GroupID == cache.Selected.GroupID {
							result.CurrentHubID, result.CurrentNetworkID, result.CurrentGroupID = sender.Pin.HubID, sender.NetworkID, route.GroupID
							result.SelectionRequired, result.SelectionStatus = false, "VERIFIED_SNAPSHOT"
						}
					}
				}
				for _, card := range groups.Groups {
					card.Current = result.CurrentHubID == sender.Pin.HubID && result.CurrentNetworkID == sender.NetworkID && result.CurrentGroupID == card.GroupID
					result.Groups = append(result.Groups, codexFacadeGroupCard{HubID: sender.Pin.HubID, NodeID: sender.Pin.NodeID, endpointGroupsMCPCard: card})
				}
				// Each child may retain its last local selection. Presentation
				// shows only this facade Thread's one verified current choice.
				groups.CurrentGroupID, groups.SelectionRequired = "", true
				if result.CurrentHubID == sender.Pin.HubID && result.CurrentNetworkID == sender.NetworkID {
					groups.CurrentGroupID, groups.SelectionRequired = result.CurrentGroupID, false
				}
				for i := range groups.Groups {
					groups.Groups[i].Current = groups.Groups[i].GroupID == groups.CurrentGroupID
				}
				return nil, nil
			})
			outcomes[i] = outcome{public, err}
		}(i, ticket, child)
	}
	wait.Wait()
	for _, out := range outcomes {
		if errors.Is(out.err, errCodexMCPContext) {
			return nil, out.err
		}
		if out.err != nil {
			result.Complete = false
		}
		result.Hubs = append(result.Hubs, out.public)
	}
	for id, child := range f.children {
		if !seen[id] && !qualified {
			result.Hubs = append(result.Hubs, codexFacadeGroupsHub{HubID: child.localNode.Pin.HubID, NodeID: child.localNode.Pin.NodeID, Status: "UNAVAILABLE"})
		}
	}
	if cache == nil {
		return nil, errMCPGroupRouteUnavailable
	}
	if cache.Selected != nil {
		// Presentation does not claim the retained cold hint is authorized.
		result.RetainedHubID, result.RetainedNetworkID, result.RetainedGroupID = cache.Selected.Pin.HubID, cache.Selected.NetworkID, cache.Selected.GroupID
	}
	if !qualified {
		pruneCodexRouteCacheChildren(cache, f.children)
		cache.Complete = result.Complete && stringArgument(business, "cursor") == ""
	}
	if err := writeCodexRouteCache(f.userRoot, *cache); err != nil {
		return nil, err
	}
	sort.Slice(result.Hubs, func(i, j int) bool {
		if result.Hubs[i].HubID == result.Hubs[j].HubID {
			return result.Hubs[i].NodeID < result.Hubs[j].NodeID
		}
		return result.Hubs[i].HubID < result.Hubs[j].HubID
	})
	sort.Slice(result.Groups, func(i, j int) bool {
		a, b := result.Groups[i], result.Groups[j]
		if a.HubID != b.HubID {
			return a.HubID < b.HubID
		}
		if a.NetworkID != b.NetworkID {
			return a.NetworkID < b.NetworkID
		}
		return a.GroupID < b.GroupID
	})
	return result, nil
}

func pruneCodexRouteCacheChildren(cache *codexRouteCache, children map[string]*mcpServer) {
	live := func(r mcpGroupRoute) bool {
		id, err := codexChildRouteID(r.Pin)
		return err == nil && children[id] != nil
	}
	routes := cache.Routes[:0]
	for _, r := range cache.Routes {
		if live(r) {
			routes = append(routes, r)
		}
	}
	cache.Routes = routes
	senders := cache.Senders[:0]
	for _, r := range cache.Senders {
		if live(r) {
			senders = append(senders, r)
		}
	}
	cache.Senders = senders
}

func mergeCodexRouteCacheView(cache *codexRouteCache, sender mcpGroupRoute, routes []mcpGroupRoute, firstPage bool) {
	sameChild := func(r mcpGroupRoute) bool {
		return r.Pin.HubID == sender.Pin.HubID && r.Pin.NodeID == sender.Pin.NodeID
	}
	for _, old := range cache.Senders {
		if sameChild(old) && (old.originalSender() != sender.originalSender() || old.RegistrationRevision != sender.RegistrationRevision || !sameLocalNodeAuthority(old.Pin, sender.Pin)) {
			firstPage = true
			cache.Complete = false
		}
	}
	keptSenders := cache.Senders[:0]
	for _, old := range cache.Senders {
		if !sameChild(old) {
			keptSenders = append(keptSenders, old)
		}
	}
	cache.Senders = append(keptSenders, sender)
	keptRoutes := cache.Routes[:0]
	for _, old := range cache.Routes {
		if sameChild(old) {
			if firstPage {
				continue
			}
			replaced := false
			for _, fresh := range routes {
				if fresh.GroupID == old.GroupID {
					replaced = true
					break
				}
			}
			if replaced {
				continue
			}
		}
		keptRoutes = append(keptRoutes, old)
	}
	cache.Routes = append(keptRoutes, routes...)
}

func parseMCPGroupRouteChoice(arguments map[string]any) (mcpGroupRouteChoice, error) {
	choice := mcpGroupRouteChoice{}
	for key, raw := range arguments {
		value, ok := raw.(string)
		if !ok || !localContextText(value, 256) {
			return choice, errMCPGroupRouteUnavailable
		}
		switch key {
		case "group_id":
			choice.GroupID = value
		case "hub_id":
			choice.HubID = value
		case "network_id":
			choice.NetworkID = value
		default:
			return choice, errMCPGroupRouteUnavailable
		}
	}
	if choice.GroupID == "" {
		return choice, errMCPGroupRouteRequired
	}
	return choice, nil
}
