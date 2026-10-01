package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func fakeCompletionVerifier(t *testing.T, mode string) (string, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "verifier")
	state := filepath.Join(root, "count")
	script := `#!/bin/sh
set -eu
output=''
for argument in "$@"; do
  if [ "${previous:-}" = '--output-last-message' ]; then output="$argument"; fi
  previous="$argument"
done
printf 'call\n' >> "$CICADA_TEST_VERIFIER_STATE.calls"
count=$(wc -l < "$CICADA_TEST_VERIFIER_STATE.calls")
printf '%s' "$count" > "$CICADA_TEST_VERIFIER_STATE"
printf '%s\n' "$@" > "$CICADA_TEST_VERIFIER_STATE.args"
case "$CICADA_TEST_VERIFIER_MODE" in
  revise_once)
    if [ "$count" -eq 1 ]; then
      result='{"decision":"revise","confidence":0.95,"rationale":"missing verification evidence","correction":"run the verification and report its output"}'
    else
      result='{"decision":"accept","confidence":0.98,"rationale":"evidence now satisfies the goal","correction":""}'
    fi
    ;;
  low_confidence)
    result='{"decision":"revise","confidence":0.4,"rationale":"uncertain concern","correction":"check again"}'
    ;;
  *)
    result='{"decision":"accept","confidence":0.99,"rationale":"verified","correction":""}'
    ;;
esac
printf '%s' "$result" > "$output"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_TEST_VERIFIER_STATE", state)
	t.Setenv("CICADA_TEST_VERIFIER_MODE", mode)
	return path, state
}

func TestCompletionVerifierUsesReadOnlyGPT55AndConfidenceThreshold(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	verifier, state := fakeCompletionVerifier(t, "low_confidence")
	controlPlane.config.CompletionVerifierBin = verifier
	controlPlane.config.CompletionVerifierTime = 2 * time.Second
	verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{
		ID: "goal-verifier", Objective: "verify the result", SuccessCriteria: "include evidence",
	}, store.Worker{ID: "worker-verifier", Harness: "codex", Prompt: "run an independent check"}, "candidate evidence")
	if !verdict.Accepted || verdict.Source != "gpt-5.5" || verdict.Confidence != 0.4 {
		t.Fatalf("low-confidence verdict should not block completion: %#v", verdict)
	}
	data, err := os.ReadFile(state + ".args")
	arguments := string(data)
	if err != nil || !strings.Contains(arguments, "--sandbox\nread-only\n") ||
		!strings.Contains(arguments, "--model\ngpt-5.5\n") || !strings.Contains(arguments, "--ignore-rules\n") {
		t.Fatalf("unsafe completion verifier arguments:\n%s\nerr=%v", arguments, err)
	}
}

func TestCompletionVerifierRejectsEmptySummaryWithoutModel(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{}, store.Worker{}, "  ")
	if verdict.Accepted || verdict.Source != "deterministic" || verdict.Correction == "" {
		t.Fatalf("empty completion was accepted: %#v", verdict)
	}
}

func TestCompletionVerifierFailureDegradesWithoutBlocking(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	controlPlane.config.CompletionVerifierBin = filepath.Join(t.TempDir(), "missing-verifier")
	verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{}, store.Worker{Harness: "codex"}, "bounded evidence")
	if !verdict.Accepted || verdict.Source != "unavailable" || !strings.Contains(verdict.Rationale, "unavailable") {
		t.Fatalf("verifier outage blocked completion: %#v", verdict)
	}
}

func TestExplicitModelCompletionVerifierFailsClosedWhenUnavailable(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{
		Resources: map[string]any{"completion_verifier": "model"},
	}, store.Worker{Harness: "shell"}, "bounded evidence")
	if verdict.Accepted || !verdict.RequiresAttention || verdict.Source != "unavailable" ||
		!strings.Contains(verdict.Rationale, "not configured") {
		t.Fatalf("explicit model requirement silently degraded: %#v", verdict)
	}
}

func TestUnknownCompletionVerifierModeFailsClosed(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{
		Resources: map[string]any{"completion_verifier": "future-mode"},
	}, store.Worker{Harness: "shell"}, "bounded evidence")
	if verdict.Accepted || !verdict.RequiresAttention || verdict.Source != "unavailable" ||
		!strings.Contains(verdict.Rationale, "Unsupported completion verifier mode") {
		t.Fatalf("unknown verifier mode silently passed: %#v", verdict)
	}
}

func TestInvalidCompletionVerifierConfigurationFailsClosed(t *testing.T) {
	for name, configuredValue := range map[string]any{
		"null":       nil,
		"boolean":    true,
		"number":     1,
		"empty mode": "  ",
	} {
		t.Run(name, func(t *testing.T) {
			controlPlane := newTestControl(t, "success")
			verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{
				Resources: map[string]any{"completion_verifier": configuredValue},
			}, store.Worker{Harness: "shell"}, "bounded evidence")
			if verdict.Accepted || !verdict.RequiresAttention || verdict.Source != "unavailable" {
				t.Fatalf("invalid verifier configuration silently passed: %#v", verdict)
			}
		})
	}
}

func TestCompletionVerdictDecoderRequiresExactSchemaObject(t *testing.T) {
	valid := []byte(`{"decision":"accept","confidence":0.99,"rationale":"checked","correction":""}`)
	verdict, err := decodeModelCompletionVerdict(valid)
	if err != nil || verdict.Decision != "accept" || verdict.Rationale != "checked" {
		t.Fatalf("valid verdict failed decode: %#v err=%v", verdict, err)
	}
	for name, data := range map[string][]byte{
		"missing required field": []byte(`{"decision":"accept","confidence":0.99,"rationale":"checked"}`),
		"unknown field":          []byte(`{"decision":"accept","confidence":0.99,"rationale":"checked","correction":"","extra":true}`),
		"trailing value":         []byte(`{"decision":"accept","confidence":0.99,"rationale":"checked","correction":""} {}`),
		"wrong top-level type":   []byte(`[]`),
		"case-variant key":       []byte(`{"Decision":"accept","confidence":0.99,"rationale":"checked","correction":""}`),
		"duplicate key":          []byte(`{"decision":"accept","decision":"revise","confidence":0.99,"rationale":"checked","correction":""}`),
		"null string":            []byte(`{"decision":null,"confidence":0.99,"rationale":"checked","correction":""}`),
		"string confidence":      []byte(`{"decision":"accept","confidence":"0.99","rationale":"checked","correction":""}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeModelCompletionVerdict(data); err == nil {
				t.Fatalf("invalid verdict was accepted: %s", data)
			}
		})
	}
}

func TestShellCompletionUsesLocalCheckUnlessModelIsExplicit(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	controlPlane.config.CompletionVerifierBin = filepath.Join(t.TempDir(), "must-not-run")
	verdict := controlPlane.verifyCompletion(context.Background(), store.Goal{}, store.Worker{Harness: "shell"}, "local output")
	if !verdict.Accepted || verdict.Source != "deterministic" {
		t.Fatalf("Shell evidence was sent to the model by default: %#v", verdict)
	}
}

func TestLocalCompletionVerifierCorrectsThenAccepts(t *testing.T) {
	controlPlane := newTestControl(t, "correction")
	verifier, state := fakeCompletionVerifier(t, "revise_once")
	controlPlane.config.CompletionVerifierBin = verifier
	controlPlane.config.CompletionVerifierTime = 2 * time.Second
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "produce and verify the result", SuccessCriteria: "include verified evidence",
	})
	if err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || final.Summary != "FAKE_CORRECTED_READY" {
		t.Fatalf("verifier correction did not complete: %#v", final)
	}
	count, err := os.ReadFile(state)
	if err != nil || string(count) != "2" {
		t.Fatalf("verifier invocation count=%q err=%v", count, err)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	types := eventTypes(events)
	if !types["WorkerCompletionRejected"] || !types["WorkerCompletionVerified"] {
		t.Fatalf("completion verdict events missing: %v", types)
	}
}
