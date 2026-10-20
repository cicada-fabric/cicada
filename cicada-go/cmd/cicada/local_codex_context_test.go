package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func syntheticCodexContextIssue() localCodexContextIssue {
	return localCodexContextIssue{Version: 1, Operation: "codex_context_issue", APIOrigin: "https://synthetic.invalid", Harness: "codex", NativeSessionID: "synthetic-thread", Workspace: "/synthetic/work", ConnectionNonce: strings.Repeat("a", 64), ToolName: "cicada_endpoint_register", ArgumentsDigest: strings.Repeat("b", 64), TurnID: "synthetic-turn", ToolUseID: "synthetic-tool-call"}
}

func syntheticCodexContextConsume(q localCodexContextIssue, ticket string) localCodexContextConsume {
	return localCodexContextConsume{Version: 1, Operation: "codex_context_consume", APIOrigin: q.APIOrigin, ConnectionNonce: q.ConnectionNonce, ToolName: q.ToolName, ArgumentsDigest: q.ArgumentsDigest, Ticket: ticket}
}

func TestLocalCodexContextAtomicConsumptionAndBinding(t *testing.T) {
	var authority localCodexContextAuthority
	q := syntheticCodexContextIssue()
	now := time.Now().UTC()
	ticket, err := authority.issue(q, "synthetic-original-binding", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*localCodexContextConsume){func(c *localCodexContextConsume) { c.APIOrigin = "https://other.invalid" }, func(c *localCodexContextConsume) { c.ConnectionNonce = strings.Repeat("c", 64) }, func(c *localCodexContextConsume) { c.ToolName = "cicada_endpoint_leave" }, func(c *localCodexContextConsume) { c.ArgumentsDigest = strings.Repeat("d", 64) }, func(c *localCodexContextConsume) { c.Ticket = c.Ticket[:len(c.Ticket)-1] + "z" }} {
		c := syntheticCodexContextConsume(q, ticket.Ticket)
		change(&c)
		if _, err := authority.consume(c, "synthetic-original-binding", now); err == nil {
			t.Fatal("changed call consumed a context ticket")
		}
	}
	if _, err := authority.consume(syntheticCodexContextConsume(q, ticket.Ticket), "synthetic-new-epoch", now); err == nil {
		t.Fatal("binding replacement accepted old ticket")
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := authority.consume(syntheticCodexContextConsume(q, ticket.Ticket), "synthetic-original-binding", now)
			if err == nil {
				if r.Context.NativeSessionID != q.NativeSessionID || r.Context.ToolUseID != q.ToolUseID {
					t.Error("ticket changed its original context")
				}
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("concurrent consumers succeeded %d times", success.Load())
	}
	if strings.Contains(ticket.Ticket, q.NativeSessionID) || strings.Contains(ticket.Ticket, q.Workspace) {
		t.Fatal("opaque ticket leaked context")
	}
}

func TestLocalCodexContextExpiryCapacityAndRestart(t *testing.T) {
	var authority localCodexContextAuthority
	q := syntheticCodexContextIssue()
	now := time.Now().UTC()
	first, err := authority.issue(q, "binding", now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxLocalCodexContexts; i++ {
		if _, err := authority.issue(q, "binding", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authority.issue(q, "binding", now); err == nil {
		t.Fatal("capacity silently evicted a live ticket")
	}
	if _, err := authority.consume(syntheticCodexContextConsume(q, first.Ticket), "binding", now); err != nil {
		t.Fatal("oldest live ticket was evicted")
	}
	expiring, err := authority.issue(q, "binding", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.consume(syntheticCodexContextConsume(q, expiring.Ticket), "binding", now.Add(localCodexContextTTL)); err == nil {
		t.Fatal("expired ticket accepted")
	}
	if _, err := authority.issue(q, "binding", now.Add(localCodexContextTTL)); err != nil {
		t.Fatal("expired live set could not be reclaimed")
	}
	var restarted localCodexContextAuthority
	if _, err := restarted.consume(syntheticCodexContextConsume(q, first.Ticket), "binding", now); err == nil {
		t.Fatal("restart retained a context key")
	}
}

func TestLocalCodexContextTranscriptMetadataAndPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	workspace := t.TempDir()
	path := filepath.Join(root, "sessions", "2026", "10", "20", "rollout-synthetic.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(source any, originator, sid, cwd string) {
		data, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": sid, "cwd": cwd, "source": source, "originator": originator, "forked_from_id": "synthetic-parent"}})
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("exec", "codex_exec", "synthetic-fork", workspace)
	if err := verifyCodexContextTranscript(path, "synthetic-fork", workspace); err != nil {
		t.Fatal(err)
	}
	if err := verifyCodexContextTranscript(path, "synthetic-parent", workspace); err == nil {
		t.Fatal("fork inherited parent identity")
	}
	write(map[string]any{"subagent": map[string]any{"thread_spawn": true}}, "codex_exec", "synthetic-fork", workspace)
	if err := verifyCodexContextTranscript(path, "synthetic-fork", workspace); err == nil {
		t.Fatal("subagent record accepted")
	}
	for _, source := range []any{nil, "unknown"} {
		write(source, "codex_exec", "synthetic-fork", workspace)
		if verifyCodexContextTranscript(path, "synthetic-fork", workspace) == nil {
			t.Fatal("unknown ancestry accepted")
		}
	}
	write("exec", "codex_exec", "synthetic-fork", workspace)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if verifyCodexContextTranscript(path, "synthetic-fork", workspace) == nil {
		t.Fatal("writable record accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "rollout-link.jsonl")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if verifyCodexContextTranscript(link, "synthetic-fork", workspace) == nil {
		t.Fatal("symlink record accepted")
	}
	if verifyCodexContextTranscript(path, "synthetic-fork", root) == nil {
		t.Fatal("workspace mismatch accepted")
	}
}
