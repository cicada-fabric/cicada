//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTerminalThreadSelectorUsesOnlyExactOwnedRecord(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	workspace := t.TempDir()
	directory := filepath.Join(root, "sessions", "2026", "10", "26")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	const sid = "synthetic-terminal-original-thread"
	path := filepath.Join(directory, "rollout-2026-10-26T00-00-00-"+sid+".jsonl")
	write := func(id, source string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": id, "cwd": workspace, "source": source, "originator": "codex-tui"}})
		if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(sid, "vscode")
	actual, cwd, err := nativeThreadOperatorRecord(sid)
	if err != nil || actual != path || cwd != workspace {
		t.Fatal("exact owned record selector rejected", err)
	}
	for _, bad := range []string{"../" + sid, sid + "*", sid + "?", "[" + sid + "]", "synthetic-ancestor-thread"} {
		if _, _, err := nativeThreadOperatorRecord(bad); err == nil {
			t.Fatal("selector accepted glob/path/ancestor identity")
		}
	}
	write("synthetic-other-thread", "vscode")
	if _, _, err := nativeThreadOperatorRecord(sid); err == nil {
		t.Fatal("filename substituted for actual record identity")
	}
	write(sid, "unknown-source")
	if _, _, err := nativeThreadOperatorRecord(sid); err == nil {
		t.Fatal("unknown record source entered terminal operator")
	}
	write(sid, "vscode")
	duplicate := filepath.Join(directory, "rollout-2026-10-26T00-00-01-"+sid+".jsonl")
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(duplicate, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := nativeThreadOperatorRecord(sid); err == nil {
		t.Fatal("ambiguous records were first-match selected")
	}
}
