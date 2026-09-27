package harness

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestCanonicalAndResult(t *testing.T) {
	if Canonical("Claude") != "claude-code" || Canonical("happy_agent") != "happy-agent" {
		t.Fatal("harness aliases were not canonicalized")
	}
	summary, session := Result([]byte(`{"session_id":"s1","message":"done"}`), "fallback")
	if summary != "done" || session != "s1" {
		t.Fatalf("unexpected result summary=%q session=%q", summary, session)
	}
}

func TestArgsRejectsInvalidJSON(t *testing.T) {
	t.Setenv("CICADA_OPENCODE_ARGS_JSON", `{"bad":true}`)
	if _, err := Args("opencode"); err == nil || !strings.Contains(err.Error(), "JSON string array") {
		t.Fatalf("invalid optional harness args were accepted: %v", err)
	}
}

func TestCommandDoesNotUseShell(t *testing.T) {
	t.Setenv("CICADA_HAPPY_AGENT_BIN", "echo")
	t.Setenv("CICADA_HAPPY_AGENT_ARGS_JSON", `["hello"]`)
	command, err := Command(context.Background(), "happy-agent", "prompt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != exec.Command("echo").Path || command.Args[1] != "hello" {
		t.Fatalf("unexpected command: %#v", command.Args)
	}
}
