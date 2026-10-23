package main

import (
	"bytes"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMCPDirectoryAdvertisedFiltersAndCallerClaims(t *testing.T) {
	filters := map[string]map[string]any{
		"cicada_members": {"status": "online", "node_id": "synthetic-target-node", "harness": "codex", "limit": float64(8)},
		"cicada_list":    {"status": "online", "node_id": "synthetic-target-node", "machine_id": "synthetic-target-node", "harness": "codex", "limit": float64(8)},
		"cicada_find":    {"query": "Synthetic UX-B", "node_id": "synthetic-target-node", "workspace": "/synthetic/target-B"},
		"cicada_resolve": {"query": "Synthetic UX-B", "node_id": "synthetic-target-node", "workspace": "/synthetic/target-B"},
		"cicada_inspect": {"query": "Synthetic UX-B", "node_id": "synthetic-target-node", "workspace": "/synthetic/target-B"},
	}
	for _, tool := range cicadaMCPTools() {
		name := tool["name"].(string)
		args, ok := filters[name]
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			schema := tool["inputSchema"].(map[string]any)
			properties := schema["properties"].(map[string]any)
			if schema["additionalProperties"] != false || len(properties) != len(args) {
				t.Fatal("directory test does not match the advertised closed property set")
			}
			for key := range args {
				if _, ok := properties[key]; !ok {
					t.Fatal("directory test invented an undeclared filter")
				}
			}
			if err := validateMCPArguments(name, args); err != nil {
				t.Fatal("advertised target filters were rejected", err)
			}
			for key, value := range args {
				if _, stringFilter := value.(string); !stringFilter {
					continue
				}
				if err := validateMCPArguments(name, map[string]any{key: ""}); err != nil {
					t.Fatal("optional empty string filter was rejected", key)
				}
				for _, invalid := range []any{nil, false, float64(1), map[string]any{}, []any{}} {
					if err := validateMCPArguments(name, map[string]any{key: invalid}); err == nil {
						t.Fatal("non-string directory property was silently ignored", key)
					}
				}
			}
			for _, key := range []string{"native_session_id", "native_thread_id", "endpoint_id", "principal_id", "owner_id", "sender_endpoint_id", "session_token", "credential", "role", "group_id", "network_id", "unknown_filter", "Workspace", " workspace "} {
				for _, value := range []any{nil, "", "synthetic-forged-value"} {
					if err := validateMCPArguments(name, map[string]any{key: value}); err == nil {
						t.Fatal("directory input supplied caller identity or an undeclared property", key)
					}
				}
			}
			if name == "cicada_members" || name == "cicada_list" {
				for _, value := range []any{nil, false, "8", float64(1.5), map[string]any{}} {
					if err := validateMCPArguments(name, map[string]any{"limit": value}); err == nil {
						t.Fatal("non-integer directory limit was accepted")
					}
				}
			}
			for _, key := range []string{"node_id", "machine_id", "workspace", "harness"} {
				if _, declared := properties[key]; !declared && validateMCPArguments(name, map[string]any{key: "synthetic"}) == nil {
					t.Fatal("filter exception escaped the exact tool property", key)
				}
			}
		})
	}
	for _, name := range []string{"cicada_whoami", "cicada_join", "cicada_send", "cicada_ask", "cicada_reply"} {
		for _, key := range []string{"node_id", "machine_id", "workspace", "harness"} {
			if validateMCPArguments(name, map[string]any{key: "synthetic-forged-caller"}) == nil {
				t.Fatal("directory exception changed another tool's caller identity guard", name, key)
			}
		}
	}
}

func TestCodexDirectoryHookBindsUnmodifiedTargetFilters(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_NODE_STATE_DIR", root)
	t.Setenv("CICADA_MACHINE_ID", "synthetic-original-caller-node")
	t.Setenv("CICADA_API_URL", "https://synthetic.invalid")
	var calls atomic.Int32
	businessFor := func(name string) map[string]any {
		if name == "cicada_members" || name == "cicada_list" {
			return map[string]any{"node_id": "synthetic-target-node", "status": "online", "harness": "codex", "limit": float64(8)}
		}
		return map[string]any{"node_id": "synthetic-target-node", "workspace": "/synthetic/target-B", "query": "Synthetic UX-B"}
	}
	codexConsumerNode(t, root, "synthetic-original-caller-node", func(c net.Conn, raw json.RawMessage) {
		var q localCodexContextIssue
		if json.Unmarshal(raw, &q) != nil {
			t.Error("invalid synthetic context issue")
			return
		}
		expectedDigest, _ := codexArgumentsDigest(businessFor(q.ToolName))
		if q.ArgumentsDigest != expectedDigest || q.NativeSessionID != "synthetic-original-caller-thread" || q.Workspace != root {
			t.Error("target filters changed the caller or the HMAC argument binding")
		}
		calls.Add(1)
		_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, CodexContextIssue: &localCodexContextIssueResult{Ticket: "synthetic-issued-ticket", ExpiresAt: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)}})
	})
	for _, name := range []string{"cicada_find", "cicada_resolve", "cicada_inspect", "cicada_members", "cicada_list"} {
		t.Run(name, func(t *testing.T) {
			business := businessFor(name)
			input := make(map[string]any, len(business)+1)
			for key, value := range business {
				input[key] = value
			}
			input[codexMCPContextArgument] = map[string]any{"connection_nonce": strings.Repeat("a", 64)}
			event := codexHookInput{Event: "PreToolUse", SessionID: "synthetic-original-caller-thread", CWD: root, ToolName: "mcp__cicada__" + name, TurnID: "synthetic-turn", ToolUseID: "synthetic-call", ToolInput: input}
			before := calls.Load()
			var output bytes.Buffer
			if err := codexPreToolUse(event, &output); err != nil {
				t.Fatal(err)
			}
			var response struct {
				Specific struct {
					Decision string         `json:"permissionDecision"`
					Updated  map[string]any `json:"updatedInput"`
				} `json:"hookSpecificOutput"`
			}
			if json.Unmarshal(output.Bytes(), &response) != nil || response.Specific.Decision != "allow" || calls.Load() != before+1 {
				t.Fatal("declared target filter was denied before a Node ticket")
			}
			got, err := codexBusinessArguments(response.Specific.Updated)
			if err != nil || !reflect.DeepEqual(got, business) {
				t.Fatal("Hook dropped or rewrote target filters before dispatch")
			}
			input["native_session_id"] = "synthetic-forged-caller"
			output.Reset()
			if err := codexPreToolUse(event, &output); err != nil || calls.Load() != before+1 || !strings.Contains(output.String(), string(codexHookArgumentsInvalid)) {
				t.Fatal("directory filter exception let a forged caller reach the Node")
			}
		})
	}
}
