package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This is a consumer recovery test with a scripted private Node. The Node's
// actual sealed-packet recovery and revocation guards have a separate gate.
func TestCodexPendingDomainJoinRecoversBeforeUnavailableCurrentContext(t *testing.T) {
	root, state := privateLocalNodeRoot(t), shortLocalJoinStateDir(t)
	workspace := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	q := syntheticLocalEndpointRequest("endpoint_register")
	q.Workspace = workspace
	q, result := syntheticCodexDomainAdmission(t, q)
	node := result.LocalDomain.Description.Policy.Node
	base := filepath.Join(root, "cache", "sessions.json")
	pin := LocalNodeConnectionPin{UserRoot: root, HubID: result.HubID, APIOrigin: q.APIOrigin, NodeID: result.NodeID,
		StateDir: state, WriterRoot: state, SocketPath: machineAgentJoinSocketPath(state, result.NodeID),
		MCPSessionStateFile: base, MCPOutboxStateFile: filepath.Join(root, "outbox", "outbox.sqlite3"),
		Binding: LocalNodeBinding{BindingID: node.OwnerBindingID, BindingVersion: node.BindingVersion, NodeKeyEpoch: node.NodeKeyEpoch,
			NodeKeyVersion: node.NodeKeyVersion, NodeKeyID: node.NodePublic.ID, NodeKeyFingerprint: node.NodeKeyFingerprint,
			HubKeyVersion: node.HubNodeControlKeyVersion, HubKeyID: node.HubNodeControlPublic.ID, HubFingerprint: node.HubNodeControlFingerprint}}
	locator := localNodeLocator{localNodeLocatorFormat, strings.Repeat("a", 32), pin.SocketPath}
	locatorData, _ := json.Marshal(locator)
	locatorData = append(locatorData, '\n')
	locatorDir := filepath.Join(root, "run", "nodes")
	if err := os.MkdirAll(locatorDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locatorDir, localNodeLocatorName(state, pin.NodeID)), locatorData, 0600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "codex")
	t.Setenv("CODEX_HOME", home)
	transcript := filepath.Join(home, "sessions", "synthetic-rollout.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0700); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": q.NativeSessionID, "cwd": workspace, "source": "exec", "originator": "codex_exec"}})
	if err := os.WriteFile(transcript, append(metadata, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	coordinates := mcpTestContext("codex", q.NativeSessionID, result.NodeID, workspace)
	scope, _, _ := mcpSessionScope(q.APIOrigin, coordinates)
	intentPath := filepath.Join(filepath.Dir(base), "scopes", scope, "operator-intent.json")
	var authority localCodexContextAuthority
	var revoked atomic.Bool
	var issues, calls, issuesBeforeHistory atomic.Int32
	var original atomic.Pointer[localEndpointRequest]
	var currentPin atomic.Pointer[LocalNodeConnectionPin]
	currentPin.Store(&pin)
	codexConsumerNode(t, state, result.NodeID, func(c net.Conn, raw json.RawMessage) {
		var header struct{ Operation string }
		_ = json.Unmarshal(raw, &header)
		switch header.Operation {
		case "local_node_describe":
			var describe localNodeDescribeRequest
			_ = json.Unmarshal(raw, &describe)
			_ = json.NewEncoder(c).Encode(localNodeDescribeResponse{Version: 1, Description: &localNodeDescription{
				Nonce: describe.Nonce, InstanceID: locator.InstanceID, LocatorDigest: localNodeDigest(locatorData), Connection: *currentPin.Load()}})
		case "codex_context_issue":
			issues.Add(1)
			var issue localCodexContextIssue
			response := localJoinResponse{Version: 1, Error: "synthetic no current policy: strict native record refused"}
			if !revoked.Load() && json.Unmarshal(raw, &issue) == nil && verifyCodexContextTranscript(issue.TranscriptPath, issue.NativeSessionID, issue.Workspace) == nil {
				response.Error = ""
				response.CodexContextIssue = codexConsumerIssueProfile(t, &authority, issue, localCodexContext{
					VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1, LocalDomain: q.LocalDomain})
			}
			_ = json.NewEncoder(c).Encode(response)
		case "codex_context_consume":
			var consume localCodexContextConsume
			_ = json.Unmarshal(raw, &consume)
			value, err := authority.consume(consume, "synthetic-node-binding", time.Now())
			response := localJoinResponse{Version: 1, CodexContextConsume: value}
			if err != nil {
				response.Error = "synthetic context refused"
			}
			_ = json.NewEncoder(c).Encode(response)
		case "endpoint_register":
			var actual localEndpointRequest
			_ = json.Unmarshal(raw, &actual)
			saved, err := os.ReadFile(intentPath)
			var disk codexOperatorIntentDisk
			if err != nil || json.Unmarshal(saved, &disk) != nil || disk.Pending == nil || disk.Pending.Request != actual ||
				!sameCodexOperatorConnectionPin(&pin, disk.Pending.ConnectionPin) {
				t.Error("private IPC preceded exact pinned intent persistence")
				return
			}
			n := calls.Add(1)
			if n == 1 {
				original.Store(&actual)
				return // Accepted, then the IPC response is lost.
			}
			if first := original.Load(); first == nil || actual != *first {
				t.Error("historical recovery changed original request or selector")
				return
			}
			if n == 2 {
				if issues.Load() != issuesBeforeHistory.Load() {
					t.Error("historical IPC was preceded by a fresh issuer gate")
				}
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "synthetic original remains uncertain", EndpointOperation: &localEndpointResult{
					RequestID: actual.RequestID, IntentDigest: codexOperatorDigest(actual, false), HubID: result.HubID, NodeID: result.NodeID, Operation: actual.Operation, State: "UNKNOWN"}})
				return
			}
			copy := *result
			copy.RequestID, copy.IntentDigest = actual.RequestID, codexOperatorDigest(actual, false)
			_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, EndpointOperation: &copy})
		default:
			t.Error("recovery issued an unexpected private operation")
		}
	})
	selection := &LocalNodeSelection{UserRoot: root}
	event := codexHookInput{Event: "UserPromptSubmit", SessionID: q.NativeSessionID, CWD: workspace, TranscriptPath: transcript, Prompt: "cicada join " + q.Name}
	var output bytes.Buffer
	if err := codexUserPromptWithSelection(event, &output, selection); err != nil || calls.Load() != 1 || !strings.Contains(output.String(), "unconfirmed") {
		t.Fatal("lost original response was not retained", err)
	}
	before, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	if err := os.Chmod(transcript, 0622); err != nil {
		t.Fatal(err)
	}
	if verifyCodexContextTranscript(transcript, event.SessionID, event.CWD) == nil {
		t.Fatal("synthetic record no longer reproduces the strict-verifier refusal")
	}
	for _, change := range []string{"name", "cwd", "pin", "sid"} {
		t.Run(change, func(t *testing.T) {
			changed := event
			beforeIssues := issues.Load()
			wantIssues := beforeIssues
			switch change {
			case "name":
				changed.Prompt = "cicada join Another"
			case "cwd":
				changed.CWD = root
			case "pin":
				other := pin
				other.Binding.NodeKeyEpoch++
				currentPin.Store(&other)
				defer currentPin.Store(&pin)
			case "sid":
				changed.SessionID = "synthetic-different-thread"
				wantIssues++ // No matching local original: the new request needs a ticket.
			}
			output.Reset()
			if err := codexUserPromptWithSelection(changed, &output, selection); err != nil || calls.Load() != 1 || issues.Load() != wantIssues {
				t.Fatal("changed original scope reached issuer or endpoint IPC", err)
			}
			if change == "sid" {
				otherScope, _, err := mcpSessionScope(q.APIOrigin, mcpTestContext("codex", changed.SessionID, result.NodeID, workspace))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(filepath.Dir(base), "scopes", otherScope)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected new scope created replacement intent state", err)
				}
			}
			after, err := os.ReadFile(intentPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("scope refusal rewrote original uncertainty", err)
			}
		})
	}
	issuesBeforeHistory.Store(issues.Load())
	output.Reset()
	if err := codexUserPromptWithSelection(event, &output, selection); err != nil || calls.Load() != 2 || issues.Load() != issuesBeforeHistory.Load() || !strings.Contains(output.String(), "unconfirmed") {
		t.Fatal("no-current issuer blocked the exact historical UNKNOWN query", err)
	}
	after, err := os.ReadFile(intentPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("UNKNOWN replaced or acknowledged the original intent", err)
	}
	writer := codexConsumerWriter(func([]byte) (int, error) { return 0, errors.New("synthetic output loss") })
	if err := codexUserPromptWithSelection(event, writer, selection); err == nil || calls.Load() != 3 {
		t.Fatal("historical completion did not retain its result after output loss")
	}
	output.Reset()
	if err := codexUserPromptWithSelection(event, &output, selection); err != nil || calls.Load() != 3 ||
		!strings.Contains(output.String(), "no historical communication permission was restored") || strings.Contains(output.String(), result.Join.SessionToken) {
		t.Fatal("historical completion was blocked, leaked a token or claimed current admission", err)
	}
	if cached, err := newMCPSessionStateStore(base).load(q.APIOrigin, coordinates); err != nil || cached != nil {
		t.Fatal("historical token was stored as a current session", err)
	}
	saved, err := os.ReadFile(intentPath)
	var disk codexOperatorIntentDisk
	if err != nil || json.Unmarshal(saved, &disk) != nil || disk.Pending != nil || disk.LastAck == nil || disk.LastAck.RequestID != original.Load().RequestID {
		t.Fatal("confirmed historical output did not acknowledge its original intent")
	}
	output.Reset()
	if err := codexUserPromptWithSelection(event, &output, selection); err != nil || calls.Load() != 3 ||
		!strings.Contains(output.String(), string(codexHookTicketUnavailable)) {
		t.Fatal("a new Join without current context bypassed the ticket guard", err)
	}
	if after, err := os.ReadFile(intentPath); err != nil || !bytes.Equal(saved, after) {
		t.Fatal("rejected new Join created a replacement intent", err)
	}
}
