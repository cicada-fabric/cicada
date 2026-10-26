package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Scripted trusted Node boundary: these tests cover actual MCP one-use
// consumption/private IPC/cache/outbox, not Hub cryptography or native Runtime.
func TestEndpointGroupsMCPRegisteredUnselectedAndExactAuthority(t *testing.T) {
	var httpCalls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		http.Error(w, "unexpected direct business request", 403)
	}))
	defer hub.Close()
	base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	m := newMCPServer(hub.URL, "", base)
	m.hubStateDir = shortLocalJoinStateDir(t)
	if err := m.enableCodexContext("synthetic-node"); err != nil {
		t.Fatal(err)
	}
	defer m.stopCodexHeartbeat()
	native := harness.SessionContext{Harness: "codex", MachineID: "synthetic-node", NativeSessionID: "synthetic-original-thread", Workspace: t.TempDir()}
	profile := syntheticEndpointGroupsContext()
	profile.Harness = native.Harness
	profile.NativeSessionID = native.NativeSessionID
	profile.Workspace = native.Workspace
	binding, err := codexContextBinding(profile)
	if err != nil {
		t.Fatal(err)
	}
	first := syntheticEndpointGroupsAuthority(binding)
	second := first
	second.Relation.GroupID = "synthetic-group-2"
	second.Relation.Source = "OWNER_EXPLICIT"
	second.Relation.AuthorityID = strings.Repeat("c", 32)
	second.Relation.PolicyID = second.Relation.AuthorityID
	second.Relation.PolicyEpoch = 1
	second.Relation.DecisionRevision = 1
	second.OwnerControl = e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "NONE", PolicyID: second.Relation.AuthorityID, PolicyEpoch: 1}
	anchor := wire.EndpointGroupsRegistrationAnchor{Profile: wire.EndpointGroupsNativeProfile, RegistrationSource: wire.EndpointGroupsRegistrationSource, Registration: e2ee.EndpointGroupRegistration{HubID: "synthetic-hub", OwnerID: "synthetic-owner", NodeID: native.MachineID, Harness: native.Harness, NativeSessionID: native.NativeSessionID, Workspace: native.Workspace, EndpointID: first.Relation.EndpointID, PrincipalID: first.Relation.PrincipalID}, RegistrationDigest: profile.RegistrationDigest, RegistrationRevision: profile.RegistrationRevision, BindingID: profile.BindingID, BindingEpoch: profile.BindingEpoch, NodeKeyEpoch: profile.NodeKeyEpoch, State: "REGISTERED", LeaseExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	card := func(a wire.EndpointGroupCurrentEndpoint) wire.OwnerEndpointGroupsRelationCard {
		return wire.OwnerEndpointGroupsRelationCard{GroupID: a.Relation.GroupID, GroupName: "Synthetic Group", NetworkID: "synthetic-network", State: "ACTIVE", RelationRevision: 1, OwnerControl: a.OwnerControl, KeyState: "CURRENT", SelectedSource: &wire.EndpointGroupSourceReference{Source: a.Relation.Source, AuthorityID: a.Relation.AuthorityID, AuthorityEpoch: a.Relation.AuthorityEpoch, ContributionRevision: a.Relation.ContributionRevision}}
	}
	description := wire.EndpointGroupsNodeDescribeResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: anchor, Relations: []wire.OwnerEndpointGroupsRelationCard{card(first), card(second)}, Authorities: []wire.EndpointGroupCurrentEndpoint{first, second}, RelationsRevision: 1, Complete: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var mu sync.Mutex
	localAccessRevision := uint64(1)
	var tickets localCodexContextAuthority
	const token = "synthetic-original-private-token"
	codexConsumerNode(t, m.hubStateDir, native.MachineID, func(c net.Conn, raw json.RawMessage) {
		var header struct {
			Operation string `json:"operation"`
		}
		_ = json.Unmarshal(raw, &header)
		switch header.Operation {
		case "codex_context_consume":
			var q localCodexContextConsume
			_ = json.Unmarshal(raw, &q)
			consumed, err := tickets.consume(q, "synthetic-node-binding", time.Now())
			r := localJoinResponse{Version: 1, CodexContextConsume: consumed}
			if err != nil {
				r.Error = "synthetic consumed ticket rejected"
			}
			_ = json.NewEncoder(c).Encode(r)
		case "endpoint_groups_self", "endpoint_groups_select":
			var q localEndpointGroupsRequest
			if decodeLocalBridgeRequest(raw, &q) != nil {
				t.Error("private self request was not closed")
				return
			}
			record, err := tickets.consumedEndpointGroups(q.ContextTicketID, q.APIOrigin, q.NativeSessionID, q.Workspace, time.Now())
			if err != nil || record.Nonce != q.ConnectionNonce || record.Tool != q.ToolName || record.Arguments != q.ArgumentsDigest || q.codexEndpointGroupsBinding != binding.codexEndpointGroupsBinding {
				t.Error("private self call lost its consumed original tool/context")
				return
			}
			mu.Lock()
			rawDescription, _ := json.Marshal(description)
			accessRevision := localAccessRevision
			mu.Unlock()
			var d wire.EndpointGroupsNodeDescribeResult
			_ = json.Unmarshal(rawDescription, &d)
			result := &localEndpointGroupsResult{Description: d, SessionToken: token, LocalAccessRevision: accessRevision}
			if header.Operation == "endpoint_groups_select" {
				if q.ToolName != "cicada_use_group" {
					t.Error("selection borrowed another tool call")
					return
				}
				for _, a := range d.Authorities {
					if a.Relation.GroupID == q.GroupID {
						result.Authority = a
						break
					}
				}
				result.Card = &fabric.NetworkCard{EndpointID: anchor.Registration.EndpointID, PrincipalID: anchor.Registration.PrincipalID, GroupID: q.GroupID, NodeID: native.MachineID, Harness: native.Harness, NativeSessionID: native.NativeSessionID, Workspace: native.Workspace, BindingID: anchor.BindingID, BindingEpoch: anchor.BindingEpoch}
			}
			_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, EndpointGroups: result})
		default:
			t.Errorf("unexpected Node operation %s", header.Operation)
		}
	})
	call := func(tool string, args map[string]any) (any, error) {
		q := syntheticCodexContextIssue()
		q.APIOrigin = hub.URL
		q.Harness = native.Harness
		q.NativeSessionID = native.NativeSessionID
		q.Workspace = native.Workspace
		q.ConnectionNonce = m.codexContext.nonce
		q.ToolName = tool
		q.ArgumentsDigest, _ = codexArgumentsDigest(args)
		p := profile
		p.TurnID = q.TurnID
		p.ToolUseID = q.ToolUseID
		issued, err := tickets.issueVerified(q, "synthetic-node-binding", time.Now(), p)
		if err != nil {
			t.Fatal(err)
		}
		business := map[string]any{}
		for k, v := range args {
			business[k] = v
		}
		business[codexMCPContextArgument] = map[string]any{"connection_nonce": m.codexContext.nonce, "ticket": issued.Ticket}
		return m.callTool(tool, business)
	}
	value, err := call("cicada_groups", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	list := value.(endpointGroupsMCPResult)
	if !list.SelectionRequired || list.CurrentGroupID != "" || len(list.Groups) != 2 || m.sessionToken != token || m.sessionGroupID != "" {
		t.Fatal("self list required Join or silently selected a Group")
	}
	encoded, _ := json.Marshal(value)
	for _, private := range []string{token, native.NativeSessionID, native.Workspace, "principal_id", "owner_control"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("self list exposed private registration evidence")
		}
	}
	if _, err = call("cicada_use_group", map[string]any{"group_id": first.Relation.GroupID}); err != nil {
		t.Fatal("registered unselected caller could not explicitly select", err)
	}
	scope, err := m.currentMCPOutboxScope()
	if err != nil || scope.EndpointGroupAuthority != first {
		t.Fatal("selected source was not frozen", err)
	}
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := outbox.prepare(scope, "send", "synthetic-original-op", mcpOutboxInput{Target: "synthetic-peer", Body: "synthetic-private-message"})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	description.Authorities[0].Relation.ContributionRevision++
	description.Relations[0].SelectedSource.ContributionRevision++
	mu.Unlock()
	value, err = call("cicada_groups", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	list = value.(endpointGroupsMCPResult)
	if !list.SelectionRequired || list.CurrentGroupID != "" || m.sessionToken != token {
		t.Fatal("source change lent a new generation to the old selection or deleted registration")
	}
	retained, err := outbox.load(scope, original.OperationID)
	if err != nil || retained.codexOutboxBinding != original.codexOutboxBinding {
		t.Fatal("source change rewrote the retained original operation", err)
	}
	if _, err = call("cicada_use_group", map[string]any{"group_id": first.Relation.GroupID}); err != nil {
		t.Fatal(err)
	}
	freshScope, err := m.currentMCPOutboxScope()
	if err != nil || mcpOutboxScopeMatches(original, freshScope) {
		t.Fatal("new selection borrowed the original outbox source generation", err)
	}
	mu.Lock()
	localAccessRevision++
	mu.Unlock()
	value, err = call("cicada_groups", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !value.(endpointGroupsMCPResult).SelectionRequired || m.sessionToken != token {
		t.Fatal("local Leave/Join generation resurrected an in-memory Group selection")
	}
	if _, err = call("cicada_task_list", map[string]any{}); err == nil {
		t.Fatal("finite Group rights reached Task path")
	}
	saved, err := newMCPSessionStateStore(base).load(hub.URL, native)
	if err != nil || saved == nil || saved.SessionToken != token || saved.EndpointGroupsVersion != 1 {
		t.Fatal("private restart cache lost original registered identity", err)
	}
	if httpCalls.Load() != 0 {
		t.Fatal("managed self/list/select/deny bypassed the trusted Node boundary")
	}
}

func TestEndpointGroupsClosedBusinessArgumentsAndHistoricalTime(t *testing.T) {
	for _, args := range []map[string]any{{"endpoint_id": "synthetic-other"}, {"group_id": "synthetic-group"}, {"limit": 1.5}, {"limit": 0}, {"limit": 65}, {"limit": "1"}, {"cursor": " padded "}, {"cursor": true}} {
		if _, _, err := parseEndpointGroupsMCPArguments(args); err == nil {
			t.Fatal("self list accepted foreign identity or invalid pagination")
		}
	}
	for _, raw := range []string{"", "2026-10-26T00:00:00+00:00", "2026-10-26T00:00:00.000Z", "0001-01-01T00:00:00Z"} {
		if _, err := endpointGroupsHistoricalObservedAt(raw); err == nil {
			t.Fatal("noncanonical or zero historical observation accepted")
		}
	}
	if _, err := endpointGroupsHistoricalObservedAt("2026-10-26T00:00:00.000000001Z"); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"cicada_task_claim", "cicada_task_submit", "cicada_artifact_read", "cicada_journal_append", "cicada_space_sync", "cicada_broadcast", "cicada_leave", "cicada_network_directory"} {
		if endpointGroupsMCPToolAllowed(tool, map[string]any{}) {
			t.Fatal("finite source expanded beyond its five rights")
		}
	}
}
