package nodebackup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	_ "modernc.org/sqlite"
)

const backupTestNodeID = "node-backup-test"

func TestNodeBackupWALRestoreQuarantineAndManifestPrivacy(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	nodeDir := nodeStatePath(stateDir, backupTestNodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privateSentinel := "synthetic-private-node-token-do-not-manifest"
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte(privateSentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(nodeDir, "endpoint-keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "endpoint-keys", "identity-key.json"),
		[]byte("synthetic-private-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "outbox.sqlite3"), []byte("synthetic external MCP outbox"), 0o600); err != nil {
		t.Fatal(err)
	}

	databaseNames := []string{"inbox.sqlite", "local-inbox.sqlite3", "local-messages.sqlite3", "node-crypto-state.sqlite"}
	const databaseSecret = "synthetic-encrypted-envelope-do-not-manifest"
	openDatabases := make([]*sql.DB, 0, len(databaseNames))
	for _, name := range databaseNames {
		database := openWALTestDatabase(t, filepath.Join(nodeDir, name), databaseSecret+":"+name)
		openDatabases = append(openDatabases, database)
	}
	defer func() {
		for _, database := range openDatabases {
			_ = database.Close()
		}
	}()
	for _, name := range databaseNames {
		info, err := os.Stat(filepath.Join(nodeDir, name+"-wal"))
		if err != nil || info.Size() == 0 {
			t.Fatalf("test fixture did not leave committed WAL frames for %s: info=%v err=%v", name, info, err)
		}
	}

	backupDir := filepath.Join(root, "node-backup")
	report, err := Backup(stateDir, backupTestNodeID, backupDir)
	if err != nil {
		t.Fatalf("backup Node subtree: %v", err)
	}
	if report.Manifest.NodeID != backupTestNodeID || len(report.Manifest.Databases) != len(databaseNames) {
		t.Fatalf("manifest does not describe all Node databases: %#v", report.Manifest)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(backupDir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{privateSentinel, "synthetic-private-key-material", databaseSecret, "synthetic external MCP outbox"} {
		if bytes.Contains(manifestBytes, []byte(secret)) {
			t.Fatalf("manifest exposed private payload %q", secret)
		}
	}
	var decoded Manifest
	if err := json.Unmarshal(manifestBytes, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, entry := range decoded.Files {
		if strings.Contains(entry.Path, "outbox") {
			t.Fatalf("external MCP outbox leaked into Node subtree backup: %s", entry.Path)
		}
		info, err := os.Stat(filepath.Join(backupDir, payloadName, filepath.FromSlash(entry.Path)))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("backup file %s mode=%v err=%v, want 0600", entry.Path, info, err)
		}
	}
	for _, path := range []string{backupDir, filepath.Join(backupDir, payloadName)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("private directory %s mode=%v err=%v, want 0700", path, info, err)
		}
	}
	manifestInfo, err := os.Stat(filepath.Join(backupDir, manifestName))
	if err != nil || manifestInfo.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode=%v err=%v, want 0600", manifestInfo, err)
	}

	payloadBefore, err := snapshotBackupPayload(t, backupDir)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(backupDir)
	if err != nil {
		t.Fatalf("verify Node backup: %v", err)
	}
	if len(verified.Databases) != len(databaseNames) {
		t.Fatalf("verify saw %d Node databases, want %d", len(verified.Databases), len(databaseNames))
	}
	payloadAfter, err := snapshotBackupPayload(t, backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if !equalFileSnapshots(payloadBefore, payloadAfter) {
		t.Fatal("Verify changed the backup payload or created SQLite sidecars")
	}

	targetStateDir := filepath.Join(root, "restored-state")
	restored, err := Restore(backupDir, targetStateDir)
	if err != nil {
		t.Fatalf("restore Node subtree: %v", err)
	}
	if !restored.Quarantined || restored.NodeID != backupTestNodeID {
		t.Fatalf("restore was not marked quarantined: %#v", restored)
	}
	markerBytes, err := os.ReadFile(filepath.Join(restored.NodeState, recoveryMarker))
	if err != nil {
		t.Fatalf("recovery marker missing: %v", err)
	}
	var marker recoveryPendingManifest
	if err := json.Unmarshal(markerBytes, &marker); err != nil || marker.NodeID != backupTestNodeID || marker.Status != "pending" {
		t.Fatalf("invalid recovery marker %#v err=%v", marker, err)
	}
	for _, name := range databaseNames {
		path := filepath.Join(restored.NodeState, name)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("restored database %s mode=%v err=%v, want 0600", name, info, err)
		}
		value, err := readSQLiteFixtureValue(path)
		if err != nil || value != databaseSecret+":"+name {
			t.Fatalf("restored database %s value=%q err=%v", name, value, err)
		}
	}
}

func TestNodeBackupPreservesEndpointIdentityAndReplayState(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	nodeDir := nodeStatePath(stateDir, backupTestNodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}

	identity, err := nodekeys.LoadOrCreate(nodeDir, "ep_backup")
	if err != nil {
		t.Fatal(err)
	}
	identityBytes, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	identityID := identity.Public().ID

	ctx := context.Background()
	cryptoState, err := nodekeys.OpenCryptoState(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	for want := uint64(1); want <= 2; want++ {
		sequence, reserveErr := cryptoState.ReserveOutboundSequence(ctx, "ep_backup", identityID)
		if reserveErr != nil || sequence != want {
			t.Fatalf("reserve outbound sequence = %d, err=%v; want %d", sequence, reserveErr, want)
		}
	}
	outboundEnvelope := []byte("opaque outbound envelope retained byte-for-byte")
	outbound, created, err := cryptoState.StoreOutbound(ctx, "op_backup", "ep_backup", identityID, outboundEnvelope)
	if err != nil || !created || !bytes.Equal(outbound.Envelope, outboundEnvelope) {
		t.Fatalf("store outbound envelope: record=%+v created=%v err=%v", outbound, created, err)
	}
	inboundEnvelope := []byte("opaque inbound ciphertext retained byte-for-byte")
	duplicate, err := cryptoState.AcceptInbound(ctx, "ep_backup", "sender_key_backup", "msg_backup", 17, inboundEnvelope)
	if err != nil || duplicate {
		t.Fatalf("store inbound replay record: duplicate=%v err=%v", duplicate, err)
	}

	backupDir := filepath.Join(root, "backup")
	if _, err := Backup(stateDir, backupTestNodeID, backupDir); err != nil {
		t.Fatalf("backup Node subtree: %v", err)
	}
	if err := cryptoState.Close(); err != nil {
		t.Fatal(err)
	}

	targetStateDir := filepath.Join(root, "restored-state")
	restored, err := Restore(backupDir, targetStateDir)
	if err != nil {
		t.Fatalf("restore Node subtree: %v", err)
	}
	if !restored.Quarantined {
		t.Fatal("restored Node subtree was not quarantined")
	}

	restoredIdentity, err := nodekeys.LoadOrCreate(restored.NodeState, "ep_backup")
	if err != nil {
		t.Fatal(err)
	}
	restoredIdentityBytes, err := restoredIdentity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if restoredIdentity.Public().ID != identityID || !bytes.Equal(restoredIdentityBytes, identityBytes) {
		t.Fatal("restore changed the Endpoint identity")
	}

	restoredCrypto, err := nodekeys.OpenCryptoState(restored.NodeState)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredCrypto.Close()
	restoredOutbound, err := restoredCrypto.GetOutbound(ctx, "op_backup", identityID)
	if err != nil || restoredOutbound.SourceEndpointID != "ep_backup" ||
		restoredOutbound.Digest != outbound.Digest || !bytes.Equal(restoredOutbound.Envelope, outboundEnvelope) {
		t.Fatalf("restored outbound record=%+v err=%v", restoredOutbound, err)
	}
	restoredInbound, err := restoredCrypto.GetInbound(ctx, "ep_backup", "sender_key_backup", "msg_backup")
	if err != nil || restoredInbound.Sequence != 17 || restoredInbound.Digest == "" ||
		!bytes.Equal(restoredInbound.Envelope, inboundEnvelope) {
		t.Fatalf("restored inbound record=%+v err=%v", restoredInbound, err)
	}
	duplicate, err = restoredCrypto.AcceptInbound(ctx, "ep_backup", "sender_key_backup", "msg_backup", 17, inboundEnvelope)
	if err != nil || !duplicate {
		t.Fatalf("restored replay identity was not retained: duplicate=%v err=%v", duplicate, err)
	}
	nextSequence, err := restoredCrypto.ReserveOutboundSequence(ctx, "ep_backup", identityID)
	if err != nil || nextSequence != 3 {
		t.Fatalf("post-restore outbound sequence=%d err=%v, want 3", nextSequence, err)
	}
}

func TestNodeBackupRejectsLiveAgentAndDirectWriter(t *testing.T) {
	for _, acquire := range []struct {
		name string
		lock func(string, string) (func() error, error)
	}{
		{name: "Agent", lock: func(stateDir, nodeID string) (func() error, error) {
			agent, err := nodelock.AcquireAgent(stateDir, nodeID)
			if err != nil {
				return nil, err
			}
			return agent.Close, nil
		}},
		{name: "direct writer", lock: func(stateDir, nodeID string) (func() error, error) {
			writer, err := nodelock.AcquireMaintenance(stateDir, nodeID)
			if err != nil {
				return nil, err
			}
			return writer.Close, nil
		}},
	} {
		t.Run(acquire.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			nodeDir := nodeStatePath(stateDir, backupTestNodeID)
			if err := os.MkdirAll(nodeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			closeLock, err := acquire.lock(stateDir, backupTestNodeID)
			if err != nil {
				t.Fatal(err)
			}
			defer closeLock()
			output := filepath.Join(t.TempDir(), "must-not-publish")
			_, err = Backup(stateDir, backupTestNodeID, output)
			if !errors.Is(err, ErrBusy) {
				t.Fatalf("backup error=%v, want ErrBusy", err)
			}
			if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("busy backup published output or left a partial directory: %v", statErr)
			}
		})
	}
}

func TestNodeBackupCorruptionAndExtraWALRefuseRestore(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(t *testing.T, backupDir string)
	}{
		{name: "payload checksum", fn: func(t *testing.T, backupDir string) {
			if err := os.WriteFile(filepath.Join(backupDir, payloadName, "identity.json"), []byte("tampered"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unmanifested WAL", fn: func(t *testing.T, backupDir string) {
			if err := os.WriteFile(filepath.Join(backupDir, payloadName, "node-crypto-state.sqlite-wal"), []byte("unverified wal"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			backupDir := createSmallNodeBackup(t)
			mutate.fn(t, backupDir)
			if _, err := Verify(backupDir); err == nil {
				t.Fatal("Verify accepted a corrupted or extended backup")
			}
			targetStateDir := filepath.Join(t.TempDir(), "fresh-state")
			if _, err := Restore(backupDir, targetStateDir); err == nil {
				t.Fatal("Restore accepted a corrupted or extended backup")
			}
			if _, err := os.Lstat(nodeStatePath(targetStateDir, backupTestNodeID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed restore published a Node subtree: %v", err)
			}
		})
	}
}

func TestNodeRestoreAcceptsExistingEmptyTargetAndPreservesNonemptyTarget(t *testing.T) {
	t.Run("empty target", func(t *testing.T) {
		backupDir := createSmallNodeBackup(t)
		targetStateDir := filepath.Join(t.TempDir(), "state")
		targetNodeDir := nodeStatePath(targetStateDir, backupTestNodeID)
		if err := os.MkdirAll(filepath.Dir(targetNodeDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(targetNodeDir, 0o700); err != nil {
			t.Fatal(err)
		}

		restored, err := Restore(backupDir, targetStateDir)
		if err != nil {
			t.Fatalf("restore into existing empty Node directory: %v", err)
		}
		if !restored.Quarantined {
			t.Fatal("restore into empty target was not quarantined")
		}
		if _, err := os.Stat(filepath.Join(targetNodeDir, recoveryMarker)); err != nil {
			t.Fatalf("restored quarantine marker missing: %v", err)
		}
		payload, err := os.ReadFile(filepath.Join(targetNodeDir, "identity.json"))
		if err != nil || string(payload) != "synthetic fixture" {
			t.Fatalf("restored payload=%q err=%v", payload, err)
		}
	})

	t.Run("nonempty target", func(t *testing.T) {
		backupDir := createSmallNodeBackup(t)
		targetStateDir := filepath.Join(t.TempDir(), "state")
		targetNodeDir := nodeStatePath(targetStateDir, backupTestNodeID)
		if err := os.MkdirAll(targetNodeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		sentinelPath := filepath.Join(targetNodeDir, "existing.txt")
		const sentinel = "existing target must remain untouched"
		if err := os.WriteFile(sentinelPath, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := Restore(backupDir, targetStateDir); !errors.Is(err, ErrRestoreTargetBusy) {
			t.Fatalf("restore error=%v, want ErrRestoreTargetBusy", err)
		}
		payload, err := os.ReadFile(sentinelPath)
		if err != nil || string(payload) != sentinel {
			t.Fatalf("existing target file changed: payload=%q err=%v", payload, err)
		}
		if _, err := os.Lstat(filepath.Join(targetNodeDir, recoveryMarker)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed restore published quarantine marker: %v", err)
		}
	})
}

func TestNodeBackupRejectsSymlinkedOutputPath(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	nodeDir := nodeStatePath(stateDir, backupTestNodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(stateDir, "nodes"), alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Backup(stateDir, backupTestNodeID, filepath.Join(alias, "node-backup")); err == nil {
		t.Fatal("backup accepted a destination path which aliases the Node subtree")
	}
	if _, err := os.Stat(filepath.Join(nodeDir, "node-backup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked output changed the Node subtree: %v", err)
	}
}

func TestNodeBackupOnlyOmitsStaleRootJoinSocket(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	nodeDir := nodeStatePath(stateDir, backupTestNodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(nodeDir, "join.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, "backup")
	report, err := Backup(stateDir, backupTestNodeID, backupDir)
	if err != nil {
		t.Fatalf("backup with stale root join socket: %v", err)
	}
	if len(report.Manifest.RuntimeOmissions) != 1 || report.Manifest.RuntimeOmissions[0].Path != "join.sock" {
		t.Fatalf("stale join socket omission was not recorded: %#v", report.Manifest.RuntimeOmissions)
	}
	if _, err := os.Lstat(filepath.Join(backupDir, payloadName, "join.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup contains runtime socket: %v", err)
	}

	otherPath := filepath.Join(nodeDir, "other.sock")
	otherListener, err := net.Listen("unix", otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if unixListener, ok := otherListener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	if err := otherListener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Backup(stateDir, backupTestNodeID, filepath.Join(root, "second-backup")); err == nil {
		t.Fatal("backup silently accepted an unexpected Node socket")
	}
}

func TestSQLiteExclusiveSnapshotBlocksWALWriter(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "snapshot.sqlite3")
	database := openWALTestDatabase(t, path, "before")
	defer database.Close()
	snapshot, err := checkpointSQLite(path)
	if err != nil {
		t.Fatalf("checkpoint and lock SQLite: %v", err)
	}
	defer snapshot.Close()
	started := time.Now()
	if _, err := database.Exec(`INSERT INTO backup_values(value) VALUES ('blocked')`); err == nil {
		t.Fatal("BEGIN EXCLUSIVE did not block a WAL writer")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked writer exceeded fail-fast SQLite timeout: %s", elapsed)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO backup_values(value) VALUES ('after')`); err != nil {
		t.Fatalf("writer remained blocked after snapshot release: %v", err)
	}
}

func createSmallNodeBackup(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	nodeDir := nodeStatePath(stateDir, backupTestNodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("synthetic fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, "backup")
	if _, err := Backup(stateDir, backupTestNodeID, backupDir); err != nil {
		t.Fatal(err)
	}
	return backupDir
}

func openWALTestDatabase(t *testing.T, path, value string) *sql.DB {
	t.Helper()
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rwc"}).String()
	database, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = database.Close() })
	for _, statement := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`,
		`CREATE TABLE backup_values (value TEXT NOT NULL)`} {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("initialize WAL test database: %v", err)
		}
	}
	if _, err := database.Exec(`INSERT INTO backup_values(value) VALUES (?)`, value); err != nil {
		t.Fatalf("write WAL test row: %v", err)
	}
	return database
}

func readSQLiteFixtureValue(path string) (string, error) {
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro&immutable=1"}).String()
	database, err := sql.Open("sqlite", uri)
	if err != nil {
		return "", err
	}
	defer database.Close()
	var value string
	if err := database.QueryRow(`SELECT value FROM backup_values LIMIT 1`).Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}

type fileSnapshot struct {
	size int64
	mode os.FileMode
	mod  time.Time
	data string
}

func snapshotBackupPayload(t *testing.T, backupDir string) (map[string]fileSnapshot, error) {
	t.Helper()
	result := make(map[string]fileSnapshot)
	err := filepath.WalkDir(filepath.Join(backupDir, payloadName), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Join(backupDir, payloadName), path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = fileSnapshot{size: info.Size(), mode: info.Mode().Perm(), mod: info.ModTime(), data: fmt.Sprintf("%x", data)}
		return nil
	})
	return result, err
}

func equalFileSnapshots(a, b map[string]fileSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for path, first := range a {
		second, ok := b[path]
		if !ok || first != second {
			return false
		}
	}
	return true
}
