package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This component fixture executes the production Hook, parent, children and
// actual Unix ticket issue/consume clients. Its two private Node/HTTP peers are
// synthetic, not production Hub Guard, Manager lifecycle or native Runtime
// acceptance. The independent current-NPT lane owns those additional proofs.
type codexFacadeProducerNode struct {
	mu                                   sync.Mutex
	connection                           LocalNodeConnection
	profile                              localCodexContext
	pages                                [2]wire.EndpointGroupsNodeDescribeResult
	last                                 wire.EndpointGroupCurrentEndpoint
	token                                string
	issues, consumes, selects, httpCalls int
	deny                                 bool
	stallIssue, stallConsume             <-chan struct{}
	issueAt, consumeAt                   time.Time
}

func newCodexFacadeProducerNode(t *testing.T, root, node, sid, workspace string) *codexFacadeProducerNode {
	t.Helper()
	f := &codexFacadeProducerNode{token: "SYNTHETIC_PRIVATE_TOKEN_" + node}
	pin := syntheticLocalNodePin(t, root, node)
	pin.WriterRoot = filepath.Join(root, "original-shared-writer")
	pin.MCPSessionStateFile = filepath.Join(pin.StateDir, "mcp", "sessions.json")
	pin.MCPOutboxStateFile = filepath.Join(pin.StateDir, "mcp", "outbox.sqlite3")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.httpCalls++
		if f.deny || r.Method != http.MethodGet || r.URL.Path != "/v2/fabric/whoami" || r.Header.Get("Authorization") != "CicadaSession "+f.token || r.Header.Get("Cicada-Group-Scope") != f.last.Relation.GroupID {
			http.Error(w, "SYNTHETIC current Group refused", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"endpoint_id": f.last.Relation.EndpointID, "principal_id": f.last.Relation.PrincipalID, "group_id": f.last.Relation.GroupID, "node_id": node, "native_session_id": sid, "workspace": workspace})
	}))
	t.Cleanup(server.Close)
	pin.APIOrigin = server.URL
	f.connection = LocalNodeConnection{Pin: pin, InstanceID: strings.Repeat("a", 32)}
	registration := e2ee.EndpointGroupRegistration{HubID: pin.HubID, OwnerID: "synthetic-owner", NodeID: node, Harness: "codex", NativeSessionID: sid, Workspace: workspace, EndpointID: "synthetic-" + node + "-endpoint", PrincipalID: "synthetic-" + node + "-principal"}
	digest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	if err != nil {
		t.Fatal(err)
	}
	f.profile = syntheticEndpointGroupsContext()
	f.profile.RegistrationDigest = digest
	f.profile.Harness, f.profile.NativeSessionID, f.profile.Workspace = "codex", sid, workspace
	binding, err := codexContextBinding(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	anchor := wire.EndpointGroupsRegistrationAnchor{Profile: wire.EndpointGroupsNativeProfile, RegistrationSource: wire.EndpointGroupsRegistrationSource, Registration: registration, RegistrationDigest: digest, RegistrationRevision: f.profile.RegistrationRevision, NetworkID: "synthetic-" + node + "-network", BindingID: f.profile.BindingID, BindingEpoch: f.profile.BindingEpoch, NodeKeyEpoch: f.profile.NodeKeyEpoch, State: "REGISTERED", LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	for page := range f.pages {
		f.pages[page] = wire.EndpointGroupsNodeDescribeResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: anchor, RelationsRevision: 1, Complete: page == 1, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	f.pages[0].NextCursor = "SYNTHETIC-original-opaque-page-2"
	for i := 0; i < 65; i++ {
		a := syntheticEndpointGroupsAuthority(binding)
		a.Relation.HubID, a.Relation.OwnerID, a.Relation.NodeID = pin.HubID, registration.OwnerID, node
		a.Relation.EndpointID, a.Relation.PrincipalID, a.Relation.NetworkID = registration.EndpointID, registration.PrincipalID, anchor.NetworkID
		a.Relation.GroupID = fmt.Sprintf("synthetic-shared-group-%02d", i)
		card := wire.OwnerEndpointGroupsRelationCard{GroupID: a.Relation.GroupID, GroupName: "Synthetic Group", NetworkID: anchor.NetworkID, State: "ACTIVE", RelationRevision: 1, OwnerControl: a.OwnerControl, KeyState: "CURRENT", SelectedSource: &wire.EndpointGroupSourceReference{Source: a.Relation.Source, AuthorityID: a.Relation.AuthorityID, AuthorityEpoch: a.Relation.AuthorityEpoch, ContributionRevision: a.Relation.ContributionRevision}}
		page := 0
		if i == 64 {
			page = 1
			f.last = a
		}
		f.pages[page].Relations = append(f.pages[page].Relations, card)
		f.pages[page].Authorities = append(f.pages[page].Authorities, a)
	}
	locator := localNodeLocator{Format: localNodeLocatorFormat, InstanceID: f.connection.InstanceID, SocketPath: pin.SocketPath}
	locatorRaw, _ := json.Marshal(locator)
	locatorRaw = append(locatorRaw, '\n')
	f.connection.LocatorDigest = localNodeDigest(locatorRaw)
	dir := filepath.Join(root, "run", "nodes")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, localNodeLocatorName(pin.StateDir, node)), locatorRaw, 0600); err != nil {
		t.Fatal(err)
	}
	var tickets localCodexContextAuthority
	codexConsumerNode(t, pin.StateDir, node, func(c net.Conn, raw json.RawMessage) {
		var header struct {
			Operation string `json:"operation"`
		}
		_ = json.Unmarshal(raw, &header)
		switch header.Operation {
		case "local_node_describe":
			var q localNodeDescribeRequest
			_ = json.Unmarshal(raw, &q)
			_ = json.NewEncoder(c).Encode(localNodeDescribeResponse{Version: 1, Description: &localNodeDescription{Nonce: q.Nonce, InstanceID: f.connection.InstanceID, LocatorDigest: f.connection.LocatorDigest, Connection: pin}})
		case "codex_context_issue":
			f.mu.Lock()
			stall := f.stallIssue
			f.mu.Unlock()
			if stall != nil {
				<-stall
				return
			}
			var q localCodexContextIssue
			if decodeLocalBridgeRequest(raw, &q) != nil || q.NativeSessionID != sid || q.Workspace != workspace || q.APIOrigin != pin.APIOrigin {
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "SYNTHETIC issuer refused"})
				return
			}
			profile := f.profile
			profile.TurnID, profile.ToolUseID = q.TurnID, q.ToolUseID
			issued, err := tickets.issueVerified(q, "SYNTHETIC-node-binding-"+node, time.Now(), profile)
			if err != nil {
				t.Errorf("synthetic issue: %v", err)
			}
			f.mu.Lock()
			f.issues++
			f.issueAt = time.Now()
			f.mu.Unlock()
			_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, CodexContextIssue: issued})
		case "codex_context_consume":
			f.mu.Lock()
			stall := f.stallConsume
			f.mu.Unlock()
			if stall != nil {
				<-stall
				return
			}
			var q localCodexContextConsume
			_ = json.Unmarshal(raw, &q)
			consumed, err := tickets.consume(q, "SYNTHETIC-node-binding-"+node, time.Now())
			response := localJoinResponse{Version: 1, CodexContextConsume: consumed}
			if err != nil {
				response.Error = "SYNTHETIC ticket refused"
			}
			f.mu.Lock()
			f.consumes++
			f.consumeAt = time.Now()
			f.mu.Unlock()
			_ = json.NewEncoder(c).Encode(response)
		case "endpoint_groups_self", "endpoint_groups_select":
			var q localEndpointGroupsRequest
			if decodeLocalBridgeRequest(raw, &q) != nil {
				t.Error("self request not closed")
				return
			}
			record, err := tickets.consumedEndpointGroups(q.ContextTicketID, q.APIOrigin, q.NativeSessionID, q.Workspace, time.Now())
			if err != nil || record.Nonce != q.ConnectionNonce || record.Tool != q.ToolName || record.Arguments != q.ArgumentsDigest || q.codexEndpointGroupsBinding != binding.codexEndpointGroupsBinding {
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "SYNTHETIC self guard refused"})
				return
			}
			args, err := endpointGroupsBusinessArguments(q.Arguments)
			if err != nil {
				t.Error(err)
				return
			}
			if hub := stringArgument(args, "hub_id"); hub != "" && hub != pin.HubID {
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "SYNTHETIC wrong Hub"})
				return
			}
			if network := stringArgument(args, "network_id"); network != "" && network != anchor.NetworkID {
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "SYNTHETIC wrong Network"})
				return
			}
			page := 0
			if q.Cursor != "" {
				if q.Cursor != f.pages[0].NextCursor {
					t.Error("opaque cursor changed")
					return
				}
				page = 1
			}
			result := &localEndpointGroupsResult{Description: f.pages[page], SessionToken: f.token, LocalAccessRevision: 1}
			if header.Operation == "endpoint_groups_select" {
				choice, err := parseMCPGroupRouteChoice(args)
				if err != nil || q.ToolName != "cicada_use_group" || choice.GroupID != q.GroupID {
					t.Error("exact select lost signed business")
					return
				}
				for _, p := range f.pages {
					for _, a := range p.Authorities {
						if a.Relation.GroupID == q.GroupID {
							result.Authority = a
						}
					}
				}
				if result.Authority.Relation.GroupID == "" {
					_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "SYNTHETIC Group refused"})
					return
				}
				result.Card = &fabric.NetworkCard{EndpointID: registration.EndpointID, PrincipalID: registration.PrincipalID, GroupID: q.GroupID, NodeID: node, Harness: "codex", NativeSessionID: sid, Workspace: workspace, BindingID: anchor.BindingID, BindingEpoch: anchor.BindingEpoch}
				f.mu.Lock()
				f.selects++
				f.mu.Unlock()
			}
			_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, EndpointGroups: result})
		default:
			t.Errorf("unexpected synthetic peer operation %s", header.Operation)
		}
	})
	return f
}

func codexFacadeProducerInput(t *testing.T, front *mcpServer, list ListVerifiedLocalNodeConnectionsFunc, sid, workspace, name string, args map[string]any) map[string]any {
	t.Helper()
	input := map[string]any{}
	for k, v := range args {
		input[k] = v
	}
	input[codexMCPContextArgument] = map[string]any{"connection_nonce": front.codexFacade.nonce, "routing_version": 1}
	event := codexHookInput{SessionID: sid, CWD: workspace, TranscriptPath: filepath.Join(workspace, "SYNTHETIC-owned-transcript.jsonl"), Event: "PreToolUse", TurnID: "SYNTHETIC-turn", ToolUseID: "SYNTHETIC-tool-use", ToolName: "mcp__cicada__" + name, ToolInput: input}
	var output bytes.Buffer
	if err := codexPreToolUseRouted(event, &output, front.codexFacade.userRoot, list); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Hook struct {
			Decision string         `json:"permissionDecision"`
			Updated  map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(output.Bytes(), &response) != nil || response.Hook.Decision != "allow" {
		t.Fatal("actual Hook did not issue expected synthetic child context")
	}
	return response.Hook.Updated
}

func TestCodexFacadeProducerRoutesPageTwoAndColdSelectionThroughActualHook(t *testing.T) {
	root := privateLocalNodeRoot(t)
	workspace := privateLocalNodeRoot(t)
	const sid = "synthetic-original-facade-thread"
	a := newCodexFacadeProducerNode(t, root, "synthetic-a", sid, workspace)
	b := newCodexFacadeProducerNode(t, root, "synthetic-b", sid, workspace)
	connections := []LocalNodeConnection{a.connection, b.connection}
	list := func(context.Context, string) ([]LocalNodeConnection, error) { return connections, nil }
	front, err := newRoutedLocalNodeMCPServer(root, list)
	if err != nil {
		t.Fatal(err)
	}
	defer front.codexFacade.close()
	groups := codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_groups", map[string]any{})
	value, err := front.callTool("cicada_groups", groups)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(codexFacadeGroupsResult)
	if len(result.Groups) != 128 || result.Complete || !result.SelectionRequired {
		t.Fatal("aggregate silently selected or lost partial page")
	}
	pageArgs := map[string]any{"hub_id": b.connection.Pin.HubID, "network_id": b.pages[0].Registration.NetworkID, "cursor": b.pages[0].NextCursor}
	value, err = front.callTool("cicada_groups", codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_groups", pageArgs))
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(codexFacadeGroupsResult); len(got.Groups) != 1 || got.Groups[0].GroupID != b.last.Relation.GroupID {
		t.Fatal("qualified original second-page cursor changed")
	}
	selectArgs := map[string]any{"hub_id": b.connection.Pin.HubID, "network_id": b.pages[0].Registration.NetworkID, "group_id": b.last.Relation.GroupID}
	if _, err := front.callTool("cicada_use_group", codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_use_group", selectArgs)); err != nil {
		t.Fatal("second-page exact Group refused", err)
	}
	if _, err := front.callTool("cicada_whoami", codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_whoami", map[string]any{})); err != nil {
		t.Fatal("selected second-page Group could not make ordinary call", err)
	}
	a.mu.Lock()
	aHTTP, aIssues := a.httpCalls, a.issues
	a.mu.Unlock()
	b.mu.Lock()
	bHTTP, bSelect := b.httpCalls, b.selects
	b.mu.Unlock()
	if aHTTP != 0 || aIssues != 1 || bHTTP != 1 || bSelect != 1 {
		t.Fatal("ordinary call issued another Hub's ticket or request")
	}
	cold, err := newRoutedLocalNodeMCPServer(root, list)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.codexFacade.close()
	if _, err := cold.callTool("cicada_whoami", codexFacadeProducerInput(t, cold, list, sid, workspace, "cicada_whoami", map[string]any{})); err != nil {
		t.Fatal("cold parent lost original selected scope", err)
	}
	tampered := codexFacadeProducerInput(t, cold, list, sid, workspace, "cicada_use_group", selectArgs)
	tampered["hub_id"] = a.connection.Pin.HubID
	if _, err := cold.callTool("cicada_use_group", tampered); err == nil {
		t.Fatal("child ticket authorized rewritten Hub arguments")
	}
	b.mu.Lock()
	selectsAfter := b.selects
	b.mu.Unlock()
	if selectsAfter != 1 {
		t.Fatal("changed digest reached Group selection")
	}
	connections = []LocalNodeConnection{a.connection}
	cache, err := loadCodexRouteCache(root, cold.codexFacade.nonce, mcpTrustedContext{Harness: "codex", NativeSessionID: sid, Workspace: workspace})
	if err != nil || cache.Selected == nil {
		t.Fatal(err)
	}
	if _, err := codexRoutedHookConnections("cicada_whoami", map[string]any{}, connections, root, cold.codexFacade.nonce, cache.Native); err == nil {
		t.Fatal("removed selected B fell back to sole A")
	}
}

func TestCodexFacadeProducerSingleHubSelfReadAndVerifiedOldChoice(t *testing.T) {
	root := privateLocalNodeRoot(t)
	workspace := privateLocalNodeRoot(t)
	const sid = "synthetic-original-single-thread"
	a := newCodexFacadeProducerNode(t, root, "synthetic-a", sid, workspace)
	list := func(context.Context, string) ([]LocalNodeConnection, error) {
		return []LocalNodeConnection{a.connection}, nil
	}
	front, err := newRoutedLocalNodeMCPServer(root, list)
	if err != nil {
		t.Fatal(err)
	}
	defer front.codexFacade.close()
	value, err := front.callTool("cicada_whoami", codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_whoami", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	self := value.(map[string]any)
	if self["selection_required"] != true || self["group_id"] != "" {
		t.Fatal("self read inferred a Group grant or selection")
	}
	a.mu.Lock()
	calls := a.httpCalls
	a.mu.Unlock()
	if calls != 0 {
		t.Fatal("unselected self read made Group HTTP request")
	}
	choice := map[string]any{"hub_id": a.connection.Pin.HubID, "network_id": a.pages[0].Registration.NetworkID, "group_id": a.last.Relation.GroupID}
	if _, err := front.callTool("cicada_use_group", codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_use_group", choice)); err != nil {
		t.Fatal(err)
	}
	// Simulate the first facade upgrade: the original authenticated child
	// session remains, while no new-format parent choice has existed yet.
	native := mcpTrustedContext{Harness: "codex", NativeSessionID: sid, Workspace: workspace}
	path, err := codexRouteCachePath(root, "", native)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	} // Exact task-owned fixture hint.
	cold, err := newRoutedLocalNodeMCPServer(root, list)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.codexFacade.close()
	if _, err := cold.callTool("cicada_whoami", codexFacadeProducerInput(t, cold, list, sid, workspace, "cicada_whoami", map[string]any{})); err != nil {
		t.Fatal("existing single-Hub choice could not continue", err)
	}
	cache, err := loadCodexRouteCache(root, cold.codexFacade.nonce, native)
	if err != nil || cache.Selected == nil || cache.Selected.GroupID != a.last.Relation.GroupID || cache.Selected.EndpointID != a.last.Relation.EndpointID {
		t.Fatal("old choice migration replaced sender or selected from roster", err)
	}
}

func TestCodexFacadeProducerStalledAStillReturnsHealthyBWithinSharedBudget(t *testing.T) {
	for _, stage := range []string{"issue", "consume"} {
		t.Run(stage, func(t *testing.T) {
			root, workspace := privateLocalNodeRoot(t), privateLocalNodeRoot(t)
			const sid = "synthetic-budget-original-thread"
			a := newCodexFacadeProducerNode(t, root, "synthetic-stall-a", sid, workspace)
			b := newCodexFacadeProducerNode(t, root, "synthetic-healthy-b", sid, workspace)
			release := make(chan struct{})
			defer close(release)
			a.mu.Lock()
			if stage == "issue" {
				a.stallIssue = release
			} else {
				a.stallConsume = release
			}
			a.mu.Unlock()
			list := func(context.Context, string) ([]LocalNodeConnection, error) {
				return []LocalNodeConnection{a.connection, b.connection}, nil
			}
			front, err := newRoutedLocalNodeMCPServer(root, list)
			if err != nil {
				t.Fatal(err)
			}
			defer front.codexFacade.close()
			started := time.Now()
			input := codexFacadeProducerInput(t, front, list, sid, workspace, "cicada_groups", map[string]any{})
			value, err := front.callTool("cicada_groups", input)
			if err != nil {
				t.Fatal("unavailable A suppressed authenticated B", err)
			}
			limit := codexRoutedGroupsHookBudget + 3*time.Second
			if stage == "consume" {
				limit = 21 * time.Second
			}
			if time.Since(started) > limit {
				t.Fatal("aggregation multiplied the per-child deadline")
			}
			result := value.(codexFacadeGroupsResult)
			if result.Complete || len(result.Groups) != 64 || len(result.Hubs) != 2 {
				t.Fatal("unavailable child became complete or hid healthy Groups")
			}
			for _, view := range result.Hubs {
				if view.HubID == a.connection.Pin.HubID && view.Status != "UNAVAILABLE" {
					t.Fatal("stalled child claimed verified status")
				}
			}
			b.mu.Lock()
			issued, consumed := b.issueAt, b.consumeAt
			b.mu.Unlock()
			if issued.IsZero() || consumed.IsZero() {
				t.Fatal("healthy child never issued/consumed its own ticket")
			}
			if stage == "issue" && !issued.Before(started.Add(5*time.Second)) {
				t.Fatal("healthy issuer waited behind stalled A")
			}
			if stage == "consume" && !consumed.Before(started.Add(5*time.Second)) {
				t.Fatal("healthy consumer waited behind stalled A")
			}
		})
	}
}

func TestCodexFacadeProducerDefaultVerifiedListAndHookEntry(t *testing.T) {
	root, workspace := privateLocalNodeRoot(t), privateLocalNodeRoot(t)
	const sid = "synthetic-default-entry-original-thread"
	a := newCodexFacadeProducerNode(t, root, "synthetic-default-a", sid, workspace)
	b := newCodexFacadeProducerNode(t, root, "synthetic-default-b", sid, workspace)
	front, err := newRoutedLocalNodeMCPServer(root, ListVerifiedLocalNodeConnections)
	if err != nil {
		t.Fatal("actual verified List factory failed", err)
	}
	defer front.codexFacade.close()
	if front.codexFacade.adoptConnection == nil || len(front.contextualMCPTools()) != 73 {
		t.Fatal("default factory omitted adoption resolver or duplicated tools")
	}
	input := map[string]any{codexMCPContextArgument: map[string]any{"connection_nonce": front.codexFacade.nonce, "routing_version": 1}}
	event := codexHookInput{SessionID: sid, CWD: workspace, TranscriptPath: filepath.Join(workspace, "SYNTHETIC-owned-transcript.jsonl"), Event: "PreToolUse", TurnID: "SYNTHETIC-turn", ToolUseID: "SYNTHETIC-default-tool", ToolName: "mcp__cicada__cicada_groups", ToolInput: input}
	raw, _ := json.Marshal(event)
	var output bytes.Buffer
	if err := runCodexHook([]string{"--user-root", root}, bytes.NewReader(raw), &output); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Hook struct {
			Decision string         `json:"permissionDecision"`
			Updated  map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(output.Bytes(), &response) != nil || response.Hook.Decision != "allow" {
		t.Fatal("default Hook failed actual verified enumeration")
	}
	value, err := front.callTool("cicada_groups", response.Hook.Updated)
	if err != nil {
		t.Fatal(err)
	}
	if result := value.(codexFacadeGroupsResult); len(result.Hubs) != 2 || len(result.Groups) != 128 || !result.SelectionRequired {
		t.Fatal("default front guessed a Hub or lost a child")
	}
	a.mu.Lock()
	aIssued := a.issues
	a.mu.Unlock()
	b.mu.Lock()
	bIssued := b.issues
	b.mu.Unlock()
	if aIssued != 1 || bIssued != 1 {
		t.Fatal("default Hook failed independent original issuers")
	}
}
