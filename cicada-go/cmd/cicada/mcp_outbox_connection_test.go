package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func connectionOutbox(t *testing.T, pin LocalNodeConnectionPin) *mcpOutboxStore {
	t.Helper()
	s := newMCPOutbox(pin.MCPOutboxStateFile)
	s.connectionPin = &pin
	t.Cleanup(func() { _ = s.close() })
	return s
}

func connectionOutboxScope(pin LocalNodeConnectionPin) mcpOutboxScope {
	return mcpOutboxScope{APIOrigin: pin.APIOrigin, Scope: "synthetic-original-scope", Harness: "codex", NativeSessionID: "synthetic-thread", NodeID: pin.NodeID, Workspace: pin.UserRoot, EndpointID: "synthetic-endpoint", GroupID: "synthetic-group"}
}

func outboxFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		data, err := os.ReadFile(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[suffix] = data
	}
	return files
}

func requireOutboxFilesUnchanged(t *testing.T, path string, before map[string][]byte) {
	t.Helper()
	after := outboxFiles(t, path)
	if len(before) != len(after) {
		t.Fatal("refusal changed original DB side files")
	}
	for suffix, data := range before {
		if !bytes.Equal(data, after[suffix]) {
			t.Fatal("refusal changed original DB bytes", suffix)
		}
	}
}

func TestMCPOutboxConnectionPinNewDBRestartAndLegacyRefusal(t *testing.T) {
	root := privateLocalNodeRoot(t)
	pin := syntheticLocalNodePin(t, root, "synthetic-node")
	pin.MCPOutboxStateFile = filepath.Join(root, "original root's $(literal) outbox.sqlite3")
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	scope := connectionOutboxScope(pin)
	s := connectionOutbox(t, pin)
	input := mcpOutboxInput{Target: "synthetic-peer", Body: "SYNTHETIC_UNCERTAIN_ORIGINAL_BODY"}
	op, created, err := s.prepare(scope, "send", "synthetic-idempotency-key", input)
	if err != nil || !created {
		t.Fatal("new pinned DB", err)
	}
	if _, err := s.markAttempt(scope, op.OperationID); err != nil {
		t.Fatal(err)
	}
	original, err := s.markError(scope, op.OperationID, mcpOutboxStatusUnknown, errors.New("synthetic lost response"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("outbox changed installation-root permissions", err)
	}
	before := outboxFiles(t, pin.MCPOutboxStateFile)
	legacy := newMCPOutbox(pin.MCPOutboxStateFile)
	defer legacy.close()
	if _, err := legacy.load(scope, op.OperationID); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("legacy consumer bypassed persisted pin", err)
	}
	other := pin
	other.Binding.NodeKeyEpoch++
	if _, err := connectionOutbox(t, other).load(scope, op.OperationID); !errors.Is(err, ErrLocalNodeBindingChanged) {
		t.Fatal("other binding adopted old outbox", err)
	}
	requireOutboxFilesUnchanged(t, pin.MCPOutboxStateFile, before)
	resumed := connectionOutbox(t, pin)
	recovered, created, err := resumed.prepare(scope, "send", "synthetic-idempotency-key", input)
	if err != nil || created || recovered != original {
		t.Fatal("restart did not recover the original uncertain operation", err)
	}
	if _, _, err := resumed.prepare(scope, "send", "synthetic-idempotency-key", mcpOutboxInput{Target: input.Target, Body: "REPLACEMENT"}); !errors.Is(err, errMCPOutboxConflict) {
		t.Fatal("retry replaced original package", err)
	}
}

func TestMCPOutboxConnectionPinRefusesOldOutboxWithoutCache(t *testing.T) {
	root := privateLocalNodeRoot(t)
	pin := syntheticLocalNodePin(t, root, "synthetic-node")
	scope := connectionOutboxScope(pin)
	legacy := newMCPOutbox(pin.MCPOutboxStateFile)
	defer legacy.close()
	op, _, err := legacy.prepare(scope, "send", "synthetic-old-key", mcpOutboxInput{Target: "synthetic-peer", Body: "SYNTHETIC_OLD_ORIGINAL"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.markAttempt(scope, op.OperationID); err != nil {
		t.Fatal(err)
	}
	original, err := legacy.markError(scope, op.OperationID, mcpOutboxStatusUnknown, errors.New("synthetic lost reply"))
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.close(); err != nil {
		t.Fatal(err)
	}
	before := outboxFiles(t, pin.MCPOutboxStateFile)
	if _, err := connectionOutbox(t, pin).load(scope, op.OperationID); !errors.Is(err, ErrLocalNodeConfigRequired) {
		t.Fatal("root consumer stamped an old outbox", err)
	}
	requireOutboxFilesUnchanged(t, pin.MCPOutboxStateFile, before)
	recovered, err := legacy.load(scope, op.OperationID)
	if err != nil || recovered != original {
		t.Fatal("legacy original operation was lost", err)
	}
	if _, err := os.Lstat(pin.MCPSessionStateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("outbox-only recovery fabricated a cache")
	}
}

func TestMCPOutboxConnectionPinRefusesCrashArtifacts(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal", ""} {
		t.Run("artifact"+suffix, func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			pin := syntheticLocalNodePin(t, root, "synthetic-node")
			if err := os.MkdirAll(filepath.Dir(pin.MCPOutboxStateFile), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("SYNTHETIC_ORIGINAL_RECOVERY_ARTIFACT")
			if suffix == "" {
				data = nil
			}
			if err := os.WriteFile(pin.MCPOutboxStateFile+suffix, data, 0600); err != nil {
				t.Fatal(err)
			}
			before := outboxFiles(t, pin.MCPOutboxStateFile)
			s := connectionOutbox(t, pin)
			if _, err := s.load(connectionOutboxScope(pin), "synthetic-operation"); !errors.Is(err, ErrLocalNodeConfigRequired) {
				t.Fatal("adopted incomplete original DB artifacts", err)
			}
			requireOutboxFilesUnchanged(t, pin.MCPOutboxStateFile, before)
		})
	}
}
