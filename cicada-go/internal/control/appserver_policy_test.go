package control

import (
	"bytes"
	"context"
	"encoding/json"

	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// Actual adapter requests, fake process only; no native permission enforcement claim.
func TestControlAppServerSandboxPolicyWire(t *testing.T) {
	for _, mode := range []string{"fresh", "resumed-read-only", "resumed-named-profile"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			workspaceRoot := filepath.Join(root, "workspace")
			workspace := filepath.Join(workspaceRoot, "goal")
			if err := os.MkdirAll(workspace, 0700); err != nil {
				t.Fatal("create owned workspace")
			}
			binary := fakeCodex(t, "normal")
			data, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal("read fake process")
			}
			wire := filepath.Join(root, "wire.jsonl")
			t.Setenv("CICADA_TEST_POLICY_WIRE", wire)
			t.Setenv("CICADA_CODEX_MODEL", "synthetic-wire-model")
			script := strings.Replace(string(data), "  case \"$line\" in", "  printf '%s\\n' \"$line\" >> \"$CICADA_TEST_POLICY_WIRE\"\n  case \"$line\" in", 1)
			if script == string(data) {
				t.Fatal("fake protocol shape changed")
			}
			if mode == "resumed-read-only" {
				script = strings.ReplaceAll(script, `"result":{"thread":{"id":"fake-thread"}}`, `"result":{"thread":{"id":"fake-thread"},"sandbox":{"type":"readOnly"}}`)
			}
			if mode == "resumed-named-profile" {
				script = strings.ReplaceAll(script, `"result":{"thread":{"id":"fake-thread"}}`, `"result":{"thread":{"id":"fake-thread"},"activePermissionProfile":{"id":"synthetic-restricted-profile"}}`)
			}
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal("write fake process")
			}
			c, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: workspaceRoot, CodexBinary: binary, WorkerTimeout: 5 * time.Second})
			if err != nil {
				t.Fatal("create synthetic Control")
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if c.Shutdown(ctx) != nil {
					t.Error("shutdown synthetic Control")
				}
			})
			machine, err := c.store.UpsertMachine("synthetic-policy-machine", "synthetic", nil, "available")
			if err != nil {
				t.Fatal("seed machine")
			}
			goal, err := c.store.CreateGoal("synthetic-policy-goal", "synthetic", "done", "", 50, machine.ID, "", workspace)
			if err != nil {
				t.Fatal("seed Goal")
			}
			worker, err := c.store.CreateWorkerAtHarness("synthetic-policy-worker", goal.ID, machine.ID, "codex", filepath.Join(root, "result"), workspace)
			if err != nil {
				t.Fatal("seed Worker")
			}
			if mode != "fresh" {
				sid := "fake-thread"
				if _, err := c.store.UpdateWorker(worker.ID, store.WorkerUpdate{ThreadID: &sid}); err != nil {
					t.Fatal("seed exact original Thread")
				}
			}
			result := c.runAppServer(context.Background(), *goal, worker.ID, "PUBLIC_SYNTHETIC_PROTOCOL")
			if result.ExitCode != 0 || result.ThreadID != "fake-thread" {
				t.Fatal("adapter protocol fixture failed")
			}
			data, err = os.ReadFile(wire)
			if err != nil || len(data) > 65536 {
				t.Fatal("wire capture unavailable")
			}
			seenThread, seenTurn := false, false
			for _, line := range bytes.Split(data, []byte("\n")) {
				if len(line) == 0 {
					continue
				}
				var request struct {
					Method string         `json:"method"`
					Params map[string]any `json:"params"`
				}
				if json.Unmarshal(line, &request) != nil {
					t.Fatal("malformed captured request")
				}
				p := request.Params
				switch request.Method {
				case "thread/start", "thread/resume":
					seenThread = true
					if p["approvalPolicy"] != "on-request" || p["cwd"] != workspace || p["model"] != "synthetic-wire-model" {
						t.Fatal("management fields changed")
					}
					if mode == "fresh" {
						if request.Method != "thread/start" || p["sandbox"] != "workspace-write" {
							t.Fatal("new Worker default changed")
						}
					} else {
						if request.Method != "thread/resume" || p["threadId"] != "fake-thread" {
							t.Fatal("original Thread changed")
						}
						if _, ok := p["permissions"]; ok {
							t.Fatal("resume overwrote named permissions")
						}
						if _, ok := p["sandbox"]; ok {
							t.Fatal("resume overwrote sandbox")
						}
					}
				case "turn/start":
					seenTurn = true
					if p["threadId"] != "fake-thread" || p["approvalPolicy"] != "on-request" || p["cwd"] != workspace || p["model"] != "synthetic-wire-model" {
						t.Fatal("turn fields changed")
					}
					if _, ok := p["permissions"]; ok {
						t.Fatal("turn overwrote named permissions")
					}
					if _, ok := p["sandboxPolicy"]; ok {
						t.Fatal("turn overwrote sandbox")
					}
				}
			}
			if !seenThread || !seenTurn {
				t.Fatal("required wire requests absent")
			}
		})
	}
}
