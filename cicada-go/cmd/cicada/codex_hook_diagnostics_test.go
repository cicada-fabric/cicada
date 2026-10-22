package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCodexHookInvocationDiagnosticsRemainClosedAndPrivate(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_NODE_STATE_DIR", root)
	t.Setenv("CICADA_MACHINE_ID", "synthetic-node")
	t.Setenv("CICADA_API_URL", "https://synthetic.invalid")
	var issues atomic.Int32
	codexConsumerNode(t, root, "synthetic-node", func(c net.Conn, _ json.RawMessage) {
		issues.Add(1)
		_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, Error: "SYNTHETIC_PRIVATE_NODE_RESPONSE_MUST_NOT_LEAK"})
	})
	context := func(nonce string) map[string]any {
		return map[string]any{codexMCPContextArgument: map[string]any{"connection_nonce": nonce, "ticket": "SYNTHETIC_PRIVATE_TICKET"}}
	}
	for _, test := range []struct {
		name           string
		stage          codexHookFailure
		input          map[string]any
		badCoordinates bool
		issue          bool
	}{
		{name: "coordinates", stage: codexHookCoordinatesInvalid, input: context(strings.Repeat("a", 64)), badCoordinates: true},
		{name: "tool-input", stage: codexHookToolInputMissing},
		{name: "context", stage: codexHookContextMissing, input: map[string]any{"body": "SYNTHETIC_PRIVATE_BODY"}},
		{name: "nonce", stage: codexHookNonceInvalid, input: context("SYNTHETIC_PRIVATE_INVALID_NONCE")},
		{name: "node-ticket", stage: codexHookTicketUnavailable, input: context(strings.Repeat("a", 64)), issue: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := codexHookInput{Event: "PreToolUse", SessionID: "synthetic-original-thread", CWD: root, ToolName: "mcp__plugin_cicada_cicada__cicada_whoami", ToolInput: test.input}
			if test.badCoordinates {
				event.CWD = "relative-workspace"
			}
			before := issues.Load()
			var output bytes.Buffer
			if err := codexPreToolUse(event, &output); err != nil {
				t.Fatal(err)
			}
			var response struct {
				Hook struct {
					Event      string `json:"hookEventName"`
					Permission string `json:"permissionDecision"`
					Message    string `json:"permissionDecisionReason"`
				} `json:"hookSpecificOutput"`
			}
			if json.Unmarshal(output.Bytes(), &response) != nil || response.Hook.Event != "PreToolUse" || response.Hook.Permission != "deny" || !strings.HasPrefix(response.Hook.Message, string(test.stage)+":") {
				t.Fatal("diagnostic lost refusal or stage", output.String())
			}
			for _, private := range []string{"SYNTHETIC_PRIVATE_", root, "synthetic-original-thread", strings.Repeat("a", 64)} {
				if strings.Contains(response.Hook.Message, private) {
					t.Fatal("diagnostic leaked private context")
				}
			}
			want := before
			if test.issue {
				want++
			}
			if issues.Load() != want {
				t.Fatal("invalid invocation reached Node issue")
			}
		})
	}
	input := context(strings.Repeat("a", 64))
	input["native_session_id"] = "SYNTHETIC_PRIVATE_FORGED_ID"
	var output bytes.Buffer
	before := issues.Load()
	if err := codexPreToolUse(codexHookInput{SessionID: "synthetic-thread", CWD: root, ToolName: "mcp__cicada__cicada_whoami", ToolInput: input}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), string(codexHookArgumentsInvalid)) || strings.Contains(output.String(), "SYNTHETIC_PRIVATE_") || issues.Load() != before {
		t.Fatal("invalid business arguments lost stage or reached Node")
	}
}

func TestCodexHookRecordDiagnosticBlocksWithoutChangingOriginal(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	t.Setenv("CICADA_MACHINE_ID", "synthetic-node")
	t.Setenv("CICADA_API_URL", "https://synthetic.invalid")
	stateDir := filepath.Join(t.TempDir(), "node")
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	codexConsumerOperatorNode(t, stateDir, "synthetic-node", localCodexContext{}, func(net.Conn, json.RawMessage) { t.Error("unverified native record reached endpoint operation") })
	path := filepath.Join(root, "sessions", "synthetic-rollout.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": "synthetic-thread", "cwd": workspace, "source": "cli"}})
	if err := os.WriteFile(path, append(metadata, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	event := codexHookInput{Event: "UserPromptSubmit", SessionID: "synthetic-thread", CWD: workspace, TranscriptPath: path, Prompt: "cicada join Synthetic"}
	raw, _ := json.Marshal(event)
	var output bytes.Buffer
	if err := runCodexHook(nil, bytes.NewReader(raw), &output); err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if json.Unmarshal(output.Bytes(), &response) != nil || response["decision"] != "block" || response["reason"] != codexHookLocalHandlingReason || !strings.HasPrefix(response["systemMessage"].(string), "CODEX_NODE_TICKET_UNAVAILABLE:") {
		t.Fatal("record failure passed to model or lost its phase", output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0664 || !bytes.Equal(before, after) {
		t.Fatal("diagnostic repaired or replaced the original record", err)
	}
	if strings.Contains(output.String(), path) || strings.Contains(output.String(), "synthetic-thread") {
		t.Fatal("diagnostic exposed native identity")
	}
}

func TestCodexHookRecordDiagnosticUsesOnlyTypedSafeStage(t *testing.T) {
	for _, stage := range []string{"ROOT", "PATH", "OWNERSHIP", "PERMISSION", "INODE", "METADATA", "SOURCE", "SESSION", "WORKSPACE"} {
		wrapped := fmt.Errorf("SYNTHETIC_PRIVATE_WRAPPER: %w", &LocalCodexContextError{Stage: stage})
		message := codexHookRecordFailure(wrapped)
		if !strings.HasPrefix(message, "CODEX_NATIVE_RECORD_"+stage+":") || strings.Contains(message, "SYNTHETIC_PRIVATE_") {
			t.Fatal("typed diagnostic lost its safe stage or exposed wrapper")
		}
	}
	for _, err := range []error{errors.New("SYNTHETIC_PRIVATE_PATH_AND_ID"), &LocalCodexContextError{Stage: "SYNTHETIC_PRIVATE_UNRECOGNIZED_STAGE"}} {
		message := codexHookRecordFailure(err)
		if !strings.HasPrefix(message, string(codexHookRecordUnverified)+":") || strings.Contains(message, "SYNTHETIC_PRIVATE_") {
			t.Fatal("untyped error or unknown stage was echoed")
		}
	}
}
