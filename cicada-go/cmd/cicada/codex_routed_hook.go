package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
)

const codexRoutedGroupsHookBudget = 8 * time.Second

// All identity coordinates below come from the actual Host event. Cache rows
// only choose an issuer; that original Node independently verifies transcript,
// registration, full tool arguments and the nonce before issuing its ticket.
func codexPreToolUseRouted(event codexHookInput, output io.Writer, userRoot string, list ListVerifiedLocalNodeConnectionsFunc, adoptions ...codexAdoptionResolver) error {
	name, matched := codexCicadaToolName(event.ToolName)
	if !matched {
		return codexHookOutput(output, map[string]any{})
	}
	budget := 30 * time.Second
	if name == "cicada_groups" {
		budget = codexRoutedGroupsHookBudget
	}
	callCtx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if !localContextText(event.SessionID, 128) || !filepath.IsAbs(event.CWD) || filepath.Clean(event.CWD) != event.CWD || list == nil {
		return codexHookDenyFor(output, codexHookCoordinatesInvalid)
	}
	input, ok := event.ToolInput[codexMCPContextArgument].(map[string]any)
	if !ok {
		return codexHookDenyFor(output, codexHookContextMissing)
	}
	for key := range input {
		if key != "connection_nonce" && key != "routing_version" && key != "children" {
			return codexHookDenyFor(output, codexHookContextMissing)
		}
	}
	parent, ok := input["connection_nonce"].(string)
	version, versionOK := strictMCPInteger(input["routing_version"])
	if !ok || !localContextHex(parent, 64) || !versionOK || version != codexRoutingVersion {
		return codexHookDenyFor(output, codexHookNonceInvalid)
	}
	business, err := codexBusinessArguments(event.ToolInput)
	if err != nil || validateMCPArguments(name, business) != nil {
		return codexHookDenyFor(output, codexHookArgumentsInvalid)
	}
	digest, err := codexArgumentsDigest(business)
	if err != nil {
		return codexHookDenyFor(output, codexHookDigestInvalid)
	}
	connections, err := list(callCtx, userRoot)
	if err != nil || len(connections) == 0 || len(connections) > MaxLocalNodeHubConnections {
		return codexHookDenyFor(output, codexHookTicketUnavailable)
	}
	native := mcpTrustedContext{Harness: "codex", NativeSessionID: event.SessionID, Workspace: event.CWD}
	adopt := codexAdoptionResolver(ResolveAdoptedLocalNodeConnection)
	if len(adoptions) > 0 {
		adopt = adoptions[0]
	}
	chosen, err := codexRoutedHookConnections(name, business, connections, userRoot, parent, native, adopt)
	if err != nil {
		return codexRoutedHookDeny(output, err)
	}
	envelope := codexRoutedContext{ConnectionNonce: parent, RoutingVersion: codexRoutingVersion}
	seen := map[string]bool{}
	children := make([]codexRoutedChildTicket, len(chosen))
	for i, connection := range chosen {
		p := connection.Pin
		if p.UserRoot != userRoot || validateLocalNodePin(p) != nil {
			return codexHookDenyFor(output, codexHookTicketUnavailable)
		}
		id, err := codexChildRouteID(p)
		if err != nil || seen[id] {
			return codexHookDenyFor(output, codexHookTicketUnavailable)
		}
		seen[id] = true
		nonce, err := codexChildConnectionNonce(parent, id)
		if err != nil {
			return codexHookDenyFor(output, codexHookNonceInvalid)
		}
		children[i] = codexRoutedChildTicket{RouteID: id, ConnectionNonce: nonce}
	}
	var wait sync.WaitGroup
	issue := func(i int) {
		p, child := chosen[i].Pin, children[i]
		issued, err := requestMachineAgentCodexContextIssueContext(callCtx, p.SocketPath, localCodexContextIssue{Version: localJoinProtocolVersion, Operation: "codex_context_issue", APIOrigin: p.APIOrigin, Harness: "codex", NativeSessionID: event.SessionID, Workspace: event.CWD, TranscriptPath: event.TranscriptPath, ConnectionNonce: child.ConnectionNonce, ToolName: name, ArgumentsDigest: digest, TurnID: event.TurnID, ToolUseID: event.ToolUseID})
		if err == nil && issued != nil && issued.Ticket != "" && len(issued.Ticket) <= 256 {
			children[i].Ticket = issued.Ticket
		}
	}
	for i := range chosen {
		if name == "cicada_groups" {
			wait.Add(1)
			go func(i int) { defer wait.Done(); issue(i) }(i)
		} else {
			issue(i)
		}
	}
	wait.Wait()
	for _, child := range children {
		if child.Ticket != "" {
			envelope.Children = append(envelope.Children, child)
		}
	}
	if name != "cicada_groups" && len(envelope.Children) != 1 {
		return codexHookDenyFor(output, codexHookTicketUnavailable)
	}
	if len(envelope.Children) == 0 {
		return codexHookDenyFor(output, codexHookTicketUnavailable)
	}
	// Ignore all provider-supplied child tickets and replace the whole reserved
	// envelope. The original business digest and opaque cursor remain exact.
	business[codexMCPContextArgument] = envelope
	return codexHookOutput(output, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": business}})
}

func codexRoutedHookConnections(name string, business map[string]any, connections []LocalNodeConnection, userRoot, parent string, native mcpTrustedContext, adoptions ...codexAdoptionResolver) ([]LocalNodeConnection, error) {
	if name == "cicada_groups" && stringArgument(business, "hub_id") == "" && stringArgument(business, "network_id") == "" {
		if stringArgument(business, "cursor") != "" && len(connections) != 1 {
			return nil, errMCPGroupRouteAmbiguous
		}
		return connections, nil
	}
	cache, err := loadCodexRouteCache(userRoot, parent, native)
	if err != nil {
		return nil, err
	}
	var route *mcpGroupRoute
	hub, network := stringArgument(business, "hub_id"), stringArgument(business, "network_id")
	if name == "cicada_groups" || name == "cicada_use_group" {
		if hub == "" {
			if name == "cicada_use_group" {
				if !cache.Complete {
					return nil, errMCPGroupRouteUnavailable
				}
				choice, err := parseMCPGroupRouteChoice(business)
				if err != nil {
					return nil, err
				}
				selected, err := resolveMCPGroupRoute(cache.Routes, native, choice)
				if err != nil {
					return nil, err
				}
				route, hub, network = &selected, selected.Pin.HubID, selected.NetworkID
			} else {
				for _, sender := range cache.Senders {
					if sender.NetworkID != network {
						continue
					}
					if route != nil {
						return nil, errMCPGroupRouteAmbiguous
					}
					copy := sender
					route, hub = &copy, sender.Pin.HubID
				}
				if route == nil {
					return nil, errMCPGroupRouteUnavailable
				}
			}
		}
	} else {
		if isMCPFacadeOperationTool(name) {
			if err := validateMCPFacadeOperationArguments(business); err != nil {
				return nil, err
			}
			return locateMCPFacadeOperation(connections, native, stringArgument(business, "operation_id"))
		}
		if cache.Selected == nil {
			if len(connections) == 1 {
				if name == "cicada_whoami" && len(business) == 0 {
					return connections, nil
				}
				var adopt codexAdoptionResolver
				if len(adoptions) > 0 {
					adopt = adoptions[0]
				}
				if _, err := codexOriginalSingleHubHint(connections[0], native, adopt, ValidateRetainedLocalNodeArtifacts); err == nil {
					return connections, nil
				}
			}
			return nil, errMCPGroupRouteRequired
		}
		route, hub, network = cache.Selected, cache.Selected.Pin.HubID, cache.Selected.NetworkID
	}
	var chosen []LocalNodeConnection
	for _, connection := range connections {
		p := connection.Pin
		if p.HubID != hub {
			continue
		}
		if route != nil && (p.APIOrigin != route.Pin.APIOrigin || p.NodeID != route.Pin.NodeID ||
			p.Binding.HubKeyID != route.Pin.Binding.HubKeyID || p.Binding.HubKeyVersion != route.Pin.Binding.HubKeyVersion || p.Binding.HubFingerprint != route.Pin.Binding.HubFingerprint) {
			continue
		}
		chosen = append(chosen, connection)
	}
	if len(chosen) == 0 {
		return nil, errMCPGroupRouteUnavailable
	}
	if len(chosen) != 1 {
		return nil, errMCPGroupRouteAmbiguous
	}
	return chosen, nil
}

func codexOriginalSingleHubHint(connection LocalNodeConnection, native mcpTrustedContext, adopt codexAdoptionResolver, validators ...codexArtifactValidator) (*mcpCachedSession, error) {
	context := harness.SessionContext{Harness: native.Harness, NativeSessionID: native.NativeSessionID, MachineID: connection.Pin.NodeID, Workspace: native.Workspace}
	cached, err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).load(connection.Pin.APIOrigin, context)
	if err != nil || cached == nil || cached.GroupID == "" {
		return nil, errMCPGroupRouteRequired
	}
	var retained codexArtifactValidator
	if len(validators) > 0 {
		retained = validators[0]
	}
	if err := validateCodexCachedArtifact(cached, &connection, adopt, retained); err != nil {
		return nil, err
	}
	return cached, nil
}

func codexRoutedHookDeny(output io.Writer, err error) error {
	message := "当前 Thread 的 Group 路由未验证；请刷新 Group 并明确选择原范围。 / This Thread's Group route is unverified; refresh Groups and select the original scope."
	switch {
	case errors.Is(err, errMCPGroupRouteAmbiguous):
		message = "Group 或原请求匹配多个 Hub；请明确 Hub 和 Network，未猜选连接。 / The Group or original request matches multiple Hubs; qualify Hub and Network. No connection was guessed."
	case errors.Is(err, errMCPGroupRouteRequired):
		message = "请先通过 cicada_groups 和 cicada_use_group 选择当前 Thread 已获授权的 Group。 / Select an authorized Group for this Thread with cicada_groups and cicada_use_group."
	case errors.Is(err, errMCPOutboxNotFound):
		message = "未找到当前原生 Thread 的原请求，未创建替代请求。 / The original operation was not found for this native Thread; no replacement was created."
	}
	return codexHookOutput(output, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": message}})
}
