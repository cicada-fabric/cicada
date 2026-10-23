package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func localDomainContextualTool(t *testing.T, f *nativePairTCPConsumerFixture, m *mcpServer, index int, tool string, args map[string]any) (any, error) {
	t.Helper()
	issue := localDomainConsumerIssue(t, f, index)
	input := make(map[string]any, len(args)+1)
	for key, value := range args {
		input[key] = value
	}
	input[codexMCPContextArgument] = map[string]any{"connection_nonce": m.codexContext.nonce}
	event := codexHookInput{Event: "PreToolUse", SessionID: f.native[index], CWD: f.workspace, TranscriptPath: issue.TranscriptPath, ToolName: "mcp__cicada__" + tool, ToolInput: input, TurnID: "synthetic-current-turn", ToolUseID: "synthetic-current-tool"}
	var output bytes.Buffer
	if err := codexPreToolUse(event, &output); err != nil {
		return nil, err
	}
	var hook struct {
		Specific struct {
			Decision string         `json:"permissionDecision"`
			Updated  map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(output.Bytes(), &hook) != nil || hook.Specific.Decision != "allow" {
		t.Fatal("actual pre-tool Hook did not issue a Node-bound ticket", output.String())
	}
	return m.callTool(tool, hook.Specific.Updated)
}

func TestLocalDomainHookMCPRelayAndNativeCallbackRealTCP(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	activateLocalDomainConsumer(t, f)
	base := filepath.Join(f.root, "formal-domain-consumer", "sessions.json")
	t.Setenv("CICADA_API_URL", f.server.URL)
	t.Setenv("CICADA_MCP_SESSION_STATE_FILE", base)
	names := [2]string{"Synthetic UX-A", "Synthetic UX-B"}
	for i := 0; i < 2; i++ {
		issue := localDomainConsumerIssue(t, f, i)
		event := codexHookInput{Event: "UserPromptSubmit", SessionID: f.native[i], CWD: f.workspace, TranscriptPath: issue.TranscriptPath, TurnID: "synthetic-original-prompt-turn-" + f.native[i], Prompt: "cicada join '" + names[i] + "'"}
		var output bytes.Buffer
		if err := codexUserPrompt(event, &output); err != nil {
			t.Fatal(err)
		}
		cached, err := newMCPSessionStateStore(base).load(f.server.URL, harness.SessionContext{Harness: "codex", NativeSessionID: f.native[i], MachineID: f.nodeID, Workspace: f.workspace})
		if err != nil || cached == nil || cached.LocalDomainVersion != 1 || cached.SessionToken == "" {
			t.Fatal("normal literal Hook did not persist its current v2 domain admission", err, output.String())
		}
	}
	// One long-lived MCP connection alternates both native Threads. Identity
	// always comes from a fresh consumed Node ticket, never process SID env.
	close(f.mcp[0].stop)
	f.mcp[0] = newMCPServer(f.server.URL, "", base)
	m := f.mcp[0]
	m.hubStateDir = f.nodeRoot
	if err := m.enableCodexContext(f.nodeID); err != nil {
		t.Fatal(err)
	}
	var endpoints [2]string
	for i := range endpoints {
		result, err := localDomainContextualTool(t, f, m, i, "cicada_whoami", map[string]any{})
		if err != nil {
			t.Fatal("actual contextual whoami", err)
		}
		raw, _ := json.Marshal(result)
		var self struct {
			EndpointID string `json:"endpoint_id"`
			NativeID   string `json:"native_session_id"`
		}
		if json.Unmarshal(raw, &self) != nil || self.EndpointID == "" || self.NativeID != f.native[i] {
			t.Fatal("shared MCP connection borrowed another Thread's identity")
		}
		endpoints[i] = self.EndpointID
	}
	for _, tool := range []string{"cicada_resolve", "cicada_find", "cicada_inspect"} {
		result, err := localDomainContextualTool(t, f, m, 0, tool, map[string]any{"query": names[1], "workspace": f.workspace, "node_id": f.nodeID})
		raw, _ := json.Marshal(result)
		var card struct {
			EndpointID string `json:"endpoint_id"`
			NativeID   string `json:"native_session_id"`
			Workspace  string `json:"workspace"`
		}
		if err != nil || json.Unmarshal(raw, &card) != nil || card.EndpointID != endpoints[1] || card.Workspace != f.workspace || card.NativeID != "" {
			t.Fatal("directory filters lost the authorized peer or its redaction", tool, err)
		}
		if _, err = localDomainContextualTool(t, f, m, 0, tool, map[string]any{"query": endpoints[1], "workspace": "/synthetic-wrong-workspace"}); err == nil {
			t.Fatal("directory workspace filter selected an unrelated peer")
		}
		if _, err = localDomainContextualTool(t, f, m, 0, tool, map[string]any{"query": endpoints[1], "node_id": "synthetic-other-node"}); err == nil {
			t.Fatal("directory node filter selected an unrelated peer")
		}
	}
	for _, tool := range []string{"cicada_members", "cicada_list"} {
		result, err := localDomainContextualTool(t, f, m, 0, tool, map[string]any{"node_id": f.nodeID, "harness": "codex", "limit": float64(8)})
		raw, _ := json.Marshal(result)
		var page struct {
			Endpoints []map[string]any `json:"endpoints"`
		}
		if err != nil || json.Unmarshal(raw, &page) != nil || len(page.Endpoints) != 2 {
			t.Fatal("directory target filters changed the current Group", tool, err)
		}
		result, err = localDomainContextualTool(t, f, m, 0, tool, map[string]any{"node_id": "synthetic-other-node"})
		raw, _ = json.Marshal(result)
		if err != nil || json.Unmarshal(raw, &page) != nil || len(page.Endpoints) != 0 {
			t.Fatal("unmatched directory node filter escaped its current Group", tool, err)
		}
	}
	self, err := localDomainContextualTool(t, f, m, 0, "cicada_whoami", map[string]any{})
	selfJSON, _ := json.Marshal(self)
	var original struct {
		EndpointID string `json:"endpoint_id"`
		NativeID   string `json:"native_session_id"`
		Workspace  string `json:"workspace"`
		NodeID     string `json:"node_id"`
	}
	if err != nil || json.Unmarshal(selfJSON, &original) != nil || original.EndpointID != endpoints[0] || original.NativeID != f.native[0] || original.Workspace != f.workspace || original.NodeID != f.nodeID {
		t.Fatal("target filters replaced the authenticated current caller")
	}
	message := func(index int, tool string, args map[string]any) (string, string) {
		result, err := localDomainContextualTool(t, f, m, index, tool, args)
		if err != nil {
			t.Fatal("actual contextual sealed message", err)
		}
		raw, _ := json.Marshal(result)
		var public struct {
			Message  string `json:"message_id"`
			Request  string `json:"request_id"`
			Delivery string `json:"delivery"`
			Status   string `json:"status"`
			Error    string `json:"error"`
		}
		if json.Unmarshal(raw, &public) != nil || public.Message == "" || public.Delivery != "RELAY_PERSISTED" {
			t.Fatal("domain message did not enter the actual bounded Relay", public.Status, public.Error)
		}
		return public.Message, public.Request
	}
	inbox, journal := f.inbox(t)
	ask, request := message(0, "cicada_ask", map[string]any{"target": endpoints[1], "question": "SYNTHETIC_DOMAIN_ASK /resume 'literal'", "idempotency_key": "synthetic-domain-ask"})
	_, claim, entry := f.acceptOne(t, inbox, journal)
	ctx, process := f.queue(t, 1)
	if err := drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal("domain ASK native callback", err)
	}
	stored, err := inbox.Get(f.ctx, ask)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, process.CounterPath) != 1 {
		t.Fatal("domain ASK lost its exact synthetic native outcome")
	}
	reply, root := message(1, "cicada_reply", map[string]any{"request_id": request, "body": "SYNTHETIC_DOMAIN_REPLY", "idempotency_key": "synthetic-domain-reply"})
	if root != request {
		t.Fatal("domain REPLY replaced its original ASK root")
	}
	_, claim, entry = f.acceptOne(t, inbox, journal)
	ctx, process = f.queue(t, 0)
	if err := drainMachineCrossNodeGroupRelayClaim(ctx, f.server.URL, f.nodeID, f.nodeRoot, inbox, journal, claim, entry); err != nil {
		t.Fatal("domain REPLY native callback", err)
	}
	stored, err = inbox.Get(f.ctx, reply)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, process.CounterPath) != 1 {
		t.Fatal("domain REPLY lost its exact synthetic native outcome")
	}
	if os.Getenv("CODEX_THREAD_ID") != "" {
		t.Fatal("contextual admission/message flow rewrote process native identity")
	}
	t.Log("real Hook/private IPC/cache v2/contextual MCP/Hub/Relay/crypto/inbox/writer with two synthetic queue subprocesses; real Runtime consumption NOT_RUN")
}
