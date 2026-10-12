package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func syntheticFailedTurn(info string, thread, turn string) string {
	return "{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"" + thread +
		"\",\"turn\":{\"id\":\"" + turn + "\",\"status\":\"failed\",\"items\":[],\"error\":{\"message\":\"synthetic fixture only\",\"codexErrorInfo\":" + info + "}}}}"
}

func TestMachineProviderCooldownConfirmedStdio(t *testing.T) {
	for _, item := range []struct {
		name, info, prelude string
		want                bool
	}{
		{"http429", "{\"httpConnectionFailed\":{\"httpStatusCode\":429}}", "", true},
		{"rate-enum", "\"rateLimitExceeded\"", "", true},
		{"http500", "{\"httpConnectionFailed\":{\"httpStatusCode\":500}}", "", false},
		{"message-is-not-authority", "\"other\"", "", false},
		{"foreign-thread", "\"other\"", syntheticFailedTurn("\"rateLimitExceeded\"", "foreign-thread", "native-turn-a"), false},
		{"foreign-turn", "\"other\"", syntheticFailedTurn("\"rateLimitExceeded\"", "native-thread-a", "foreign-turn"), false},
		{"early-completion", "\"other\"", syntheticFailedTurn("\"rateLimitExceeded\"", "native-thread-a", "native-turn-a"), false},
	} {
		t.Run(item.name, func(t *testing.T) {
			_, ctx, _ := machineApprovalDecisionFixture(t)
			root := t.TempDir()
			path := filepath.Join(root, "synthetic-codex")
			before, after := "", ""
			if item.prelude != "" {
				frame := "printf '%s\\n' '" + item.prelude + "'\n"
				if item.name == "early-completion" {
					before = frame
				} else {
					after = frame
				}
			}
			terminal := syntheticFailedTurn(item.info, "native-thread-a", "native-turn-a")
			// A real local child speaks the official JSON-RPC envelope. It does
			// not execute Codex, contact a provider, or emit a mocked PASS marker.
			script := "#!/bin/sh\nset -eu\ntest \"$1\" = app-server\n" +
				"while IFS= read -r line; do\ncase \"$line\" in\n" +
				"*'\"method\":\"initialize\"'*) printf '%s\\n' '{\"id\":1,\"result\":{}}' ;;\n" +
				"*'\"method\":\"thread/resume\"'*) printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"native-thread-a\"}}}' ;;\n" +
				"*'\"method\":\"turn/start\"'*)\n" + before +
				"printf '%s\\n' '{\"id\":3,\"result\":{\"turn\":{\"id\":\"native-turn-a\",\"items\":[],\"status\":\"inProgress\"}}}'\n" +
				after + "printf '%s\\n' '" + terminal + "' ;;\nesac\ndone\n"
			if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CICADA_CODEX_BIN", path)
			t.Setenv("CICADA_WORKSPACE_ROOT", root)
			job := machineJob{GoalID: "synthetic-goal", WorkerID: "synthetic-worker",
				MachineID: "node-recovery-test", Harness: "codex", Attempt: 1,
				ThreadID: "native-thread-a", Prompt: "synthetic protocol fixture only",
				Workspace:   filepath.Join(root, "synthetic-goal"),
				executionID: "synthetic-execution", providerID: "codex", leaseID: "synthetic-lease"}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			result := executeMachineJobWithApproval(ctx, job, &machineApprovalBridge{})
			if result.Status != "failed" || result.ThreadID != job.ThreadID || !result.providerStarted ||
				result.providerRateLimited != item.want || result.Error != "turn status: failed" {
				t.Fatalf("genuine child completion had wrong closed result: status=%s started=%t rateLimited=%t err=%s",
					result.Status, result.providerStarted, result.providerRateLimited, result.Error)
			}
			if item.want && result.providerTurnID != "native-turn-a" {
				t.Fatal("cooldown lost the confirmed turn identity")
			}
			public, err := json.Marshal(result)
			if err != nil || strings.Contains(string(public), "rateLimitExceeded") ||
				strings.Contains(string(public), "providerRateLimited") || strings.Contains(string(public), "providerTurnID") {
				t.Fatal("private scheduling metadata became a Hub result field")
			}
		})
	}
}

func TestMachineProviderCooldownClosedCompletionRejectsClaims(t *testing.T) {
	for _, item := range []struct {
		name, frame string
	}{
		{"unconfirmed", syntheticFailedTurn("\"rateLimitExceeded\"", "native-thread-a", "native-turn-a")},
		{"numeric-string", syntheticFailedTurn("{\"httpConnectionFailed\":{\"httpStatusCode\":\"429\"}}", "native-thread-a", "native-turn-a")},
		{"fractional", syntheticFailedTurn("{\"httpConnectionFailed\":{\"httpStatusCode\":429.5}}", "native-thread-a", "native-turn-a")},
		{"unknown-variant", syntheticFailedTurn("{\"modelClaim\":{\"httpStatusCode\":429}}", "native-thread-a", "native-turn-a")},
		{"extra-variant", syntheticFailedTurn("{\"httpConnectionFailed\":{\"httpStatusCode\":429},\"other\":{}}", "native-thread-a", "native-turn-a")},
		{"extra-status-field", syntheticFailedTurn("{\"httpConnectionFailed\":{\"httpStatusCode\":429,\"retryAfter\":1}}", "native-thread-a", "native-turn-a")},
	} {
		t.Run(item.name, func(t *testing.T) {
			decoder := json.NewDecoder(strings.NewReader(item.frame))
			decoder.UseNumber()
			var event map[string]any
			if err := decoder.Decode(&event); err != nil {
				t.Fatal(err)
			}
			thread := "native-thread-a"
			if item.name == "unconfirmed" {
				thread = ""
			}
			if machineCodexFailedTurnRateLimited("turn/completed", event["params"].(map[string]any), thread, "native-turn-a") {
				t.Fatal("unsupported or unconfirmed input became scheduling authority")
			}
		})
	}
}

func TestMachineProviderCooldownRequiresCurrentClaimBinding(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*machineNodeControlClient, *machineJob, *machineJobResult)
	}{
		{"current", nil},
		{"binding-version", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) { c.state.BindingVersion++ }},
		{"node-epoch", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) { c.state.NodeKeyEpoch++ }},
		{"foreign-hub", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) { c.state.HubID = "foreign-hub" }},
		{"foreign-node", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) { c.state.NodeID = "foreign-node" }},
		{"wrong-claim-phase", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) {
			c.state.ClaimTicket.Phase = "READY"
		}},
		{"wrong-worker-attempt", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) { c.state.ClaimTicket.Attempt++ }},
		{"wrong-lease", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) {
			c.state.ClaimTicket.LeaseID = "foreign-lease"
		}},
		{"wrong-fence", func(c *machineNodeControlClient, _ *machineJob, _ *machineJobResult) {
			c.state.ClaimTicket.FencingEpoch++
		}},
		{"wrong-native-thread", func(_ *machineNodeControlClient, _ *machineJob, r *machineJobResult) {
			r.ThreadID = "foreign-native-thread"
		}},
		{"missing-turn", func(_ *machineNodeControlClient, _ *machineJob, r *machineJobResult) { r.providerTurnID = "" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			server := httptest.NewServer(http.NotFoundHandler())
			defer server.Close()
			client, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
			ledgerRoot := t.TempDir()
			if err := os.Chmod(ledgerRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(ledgerRoot, "provider.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			hub, _ := machineHubFrom(ctx)
			hub.ProviderAdmissions = ledger
			ctx = withMachineHubContext(ctx, hub)
			job := machineJob{WorkerID: "synthetic-worker", Attempt: 1, MachineID: hub.NodeID,
				Harness: "codex", ThreadID: "native-thread-a", executionID: "synthetic-execution",
				providerID: "codex", leaseID: "synthetic-lease"}
			if err := installMachineNodeRecoveryClaimTicket(client, job); err != nil {
				t.Fatal(err)
			}
			job, _, err = prepareMachineNodeClaimExecution(ctx, client, job)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.beginClaimExecution(job); err != nil {
				t.Fatal(err)
			}
			result := machineJobResult{Status: "failed", ThreadID: job.ThreadID,
				providerStarted: true, providerRateLimited: true, providerTurnID: "native-turn-a"}
			if item.change != nil {
				client.mu.Lock()
				item.change(client, &job, &result)
				client.mu.Unlock()
			}
			err = recordMachineNodeProviderOutcome(ctx, job, result, client)
			if (err == nil) != (item.change == nil) {
				t.Fatalf("current authority guard mismatch: %v", err)
			}
			original, err := ledger.InspectProviderAttempt(ctx, nodeinbox.ProviderAdmissionRequest{
				ExecutionID: job.executionID, ProviderID: job.providerID})
			if err != nil || original.State != nodeinbox.ProviderAdmissionInjectionUncertain || original.Admitted || original.Retryable {
				t.Fatalf("rejected/accepted cooldown changed original uncertainty: %#v %v", original, err)
			}
			newRequest := nodeinbox.ProviderAdmissionRequest{ExecutionID: "synthetic-new", ProviderID: job.providerID,
				AdmissionIntent: strings.Repeat("b", 64)}
			next, err := ledger.AdmitProviderAttempt(ctx, newRequest)
			if err != nil || next.CoolingDown != (item.change == nil) || next.Admitted != (item.change != nil) {
				t.Fatalf("stale/foreign authority scheduled a cooldown: %#v %v", next, err)
			}
		})
	}
}
