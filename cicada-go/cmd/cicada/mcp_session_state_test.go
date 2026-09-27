package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/harness"
)

func mcpTestContext(harnessName, nativeSessionID, nodeID, workspace string) harness.SessionContext {
	return harness.SessionContext{Harness: harnessName, NativeSessionID: nativeSessionID, MachineID: nodeID, Workspace: workspace}
}

func mcpTestCachedSession(t *testing.T, origin string, context harness.SessionContext, token, group, endpoint string) mcpCachedSession {
	t.Helper()
	scope, trusted, err := mcpSessionScope(origin, context)
	if err != nil {
		t.Fatal(err)
	}
	return mcpCachedSession{
		Scope: scope, APIOrigin: origin, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		NodeID: trusted.NodeID, Workspace: trusted.Workspace, GroupID: group, EndpointID: endpoint,
		SessionToken: token,
	}
}

func TestMCPSessionStateIsPrivateAndIsolatedByTrustedScope(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	state := newMCPSessionStateStore(statePath)
	origin := "HTTP://Example.COM:80/"
	contextA := mcpTestContext("codex", "thread-a", "node-a", "/work/a")
	contextB := mcpTestContext("codex", "thread-b", "node-a", "/work/b")
	entryA := mcpTestCachedSession(t, origin, contextA, "cicada_session_a", "group-a", "endpoint-a")
	entryB := mcpTestCachedSession(t, origin, contextB, "cicada_session_b", "group-b", "endpoint-b")
	if err := state.save(entryA); err != nil {
		t.Fatal(err)
	}
	if err := state.save(entryB); err != nil {
		t.Fatal(err)
	}
	if got, err := state.load("http://example.com", contextA); err != nil || got == nil || got.SessionToken != "cicada_session_a" {
		t.Fatalf("session A was not isolated/restored: %#v err=%v", got, err)
	}
	if got, err := state.load("http://example.com", contextB); err != nil || got == nil || got.SessionToken != "cicada_session_b" {
		t.Fatalf("session B was not isolated/restored: %#v err=%v", got, err)
	}
	if got, err := state.load("http://example.com", mcpTestContext("codex", "thread-a", "node-b", "/work/a")); err != nil || got != nil {
		t.Fatalf("different trusted node reached another session: %#v err=%v", got, err)
	}

	parentInfo, err := os.Stat(filepath.Dir(statePath))
	if err != nil {
		t.Fatal(err)
	}
	if mode := parentInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("MCP state directory mode = %o, want 700", mode)
	}
	scopesInfo, err := os.Stat(filepath.Join(filepath.Dir(statePath), "scopes"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := scopesInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("MCP scope directory mode = %o, want 700", mode)
	}
	scopeInfo, err := os.Stat(filepath.Join(filepath.Dir(statePath), "scopes", entryA.Scope+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := scopeInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("MCP session state mode = %o, want 600", mode)
	}
	if err := state.remove(entryA.Scope); err != nil {
		t.Fatal(err)
	}
	if got, err := state.load(origin, contextA); err != nil || got != nil {
		t.Fatalf("leave/removal did not clear only session A: %#v err=%v", got, err)
	}
	if got, err := state.load(origin, contextB); err != nil || got == nil {
		t.Fatalf("removing session A cleared session B: %#v err=%v", got, err)
	}
}

func TestMCPSessionStateIndependentStoresDoNotOverwriteScopes(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "mcp", "sessions.json")
	origin := "https://fabric.example"
	contextA := mcpTestContext("codex", "thread-concurrent-a", "node-a", "/work/a")
	contextB := mcpTestContext("codex", "thread-concurrent-b", "node-b", "/work/b")
	entryA := mcpTestCachedSession(t, origin, contextA, "cicada_session_concurrent_a", "group-a", "endpoint-a")
	entryB := mcpTestCachedSession(t, origin, contextB, "cicada_session_concurrent_b", "group-b", "endpoint-b")
	stores := []*mcpSessionStateStore{newMCPSessionStateStore(statePath), newMCPSessionStateStore(statePath)}
	entries := []mcpCachedSession{entryA, entryB}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, len(stores))
	for index := range stores {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsSeen <- stores[index].save(entries[index])
		}(index)
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	state := newMCPSessionStateStore(statePath)
	if got, err := state.load(origin, contextA); err != nil || got == nil || got.SessionToken != entryA.SessionToken {
		t.Fatalf("concurrent state A lost: %#v err=%v", got, err)
	}
	if got, err := state.load(origin, contextB); err != nil || got == nil || got.SessionToken != entryB.SessionToken {
		t.Fatalf("concurrent state B lost: %#v err=%v", got, err)
	}
}

func TestNormalizeMCPAPIOriginRejectsBasePathsAndHandlesIPv6(t *testing.T) {
	if got, err := normalizeMCPAPIOrigin("HTTP://Example.COM:80/"); err != nil || got != "http://example.com" {
		t.Fatalf("normalized origin = %q err=%v", got, err)
	}
	if got, err := normalizeMCPAPIOrigin("https://[::1]"); err != nil || got != "https://[::1]" {
		t.Fatalf("normalized IPv6 origin = %q err=%v", got, err)
	}
	if _, err := normalizeMCPAPIOrigin("https://example.com/control"); err == nil {
		t.Fatal("API base path was accepted into an origin-scoped credential cache")
	}
}
