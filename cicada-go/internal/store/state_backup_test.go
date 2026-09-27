package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	_ "modernc.org/sqlite"
)

func TestStateBackupRestorePreservesSQLiteIdentityAndReplayState(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source-state")
	databasePath := filepath.Join(source, stateDatabaseName)
	persistence, err := New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := e2ee.NewIdentity()
	if err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	contact, err := persistence.CreateContact(Contact{ID: "contact-backup", Label: "fixture peer", Identity: remote.Public()})
	if err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	if _, err := persistence.AllocateContactSequence(contact.ID); err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	if _, err := persistence.AllocateContactSequence(contact.ID); err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	if err := persistence.SavePeerSession(PeerSession{
		ContactID:       contact.ID,
		Epoch:           4,
		RootKey:         bytesForBackupTest(32, 0x11),
		SendChainKey:    bytesForBackupTest(32, 0x22),
		ReceiveChainKey: bytesForBackupTest(32, 0x33),
		SendCount:       8,
		ReceiveCount:    13,
		PendingOffer:    []byte("pending-offer-secret"),
	}); err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	if _, _, err := persistence.AcceptInboundPeerMessage(PeerMessage{
		TransportID: "transport-backup",
		ContactID:   contact.ID,
		SenderID:    remote.Public().ID,
		RecipientID: "local-backup",
		Sequence:    77,
		Envelope:    json.RawMessage(`{"ciphertext":"opaque-fixture-envelope"}`),
		AAD:         "aad-fixture",
	}); err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	identityBytes, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(source, "e2ee", "identity.json")
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, identityBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientIdentityBytes, err := clientIdentity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	clientIdentityPath := filepath.Join(source, "e2ee", "client-control-identity.json")
	if err := os.WriteFile(clientIdentityPath, clientIdentityBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	keyBytes := []byte("contact-key-file-secret")
	keyPath := filepath.Join(source, "e2ee", "contacts", "peer.key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	backup := filepath.Join(root, "backup")
	manifest, err := BackupStateDir(source, backup)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Complete || manifest.Database.IntegrityCheck != "ok" || manifest.Database.ForeignKeyCheck != "ok" {
		t.Fatalf("backup was not complete and clean: %#v", manifest)
	}
	if manifest.Contacts.Contacts != 1 || manifest.Contacts.PeerSessions != 1 || manifest.Contacts.PeerMessages != 1 || manifest.Contacts.ReplaySequences != 1 {
		t.Fatalf("contact continuity summary lost rows: %#v", manifest.Contacts)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(backup, stateBackupManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pending-offer-secret", "contact-key-file-secret", "opaque-fixture-envelope", "ciphertext"} {
		if strings.Contains(string(manifestBytes), forbidden) {
			t.Fatalf("manifest exposed private/key/body value %q: %s", forbidden, manifestBytes)
		}
	}
	assertPrivateMode(t, backup, 0o700)
	assertPrivateMode(t, filepath.Join(backup, stateBackupManifestName), 0o600)
	assertPrivateMode(t, filepath.Join(backup, stateBackupPayloadName, "e2ee", "identity.json"), 0o600)
	assertPrivateMode(t, filepath.Join(backup, stateBackupPayloadName, "e2ee", "client-control-identity.json"), 0o600)
	assertPrivateMode(t, filepath.Join(backup, stateBackupPayloadName, stateDatabaseName), 0o600)
	if _, err := VerifyStateBackup(backup); err != nil {
		t.Fatalf("fresh backup failed independent verification: %v", err)
	}

	target := filepath.Join(root, "restored-state")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := RestoreStateDir(backup, target)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified || report.Manifest.Contacts != manifest.Contacts {
		t.Fatalf("unexpected restore report: %#v", report)
	}
	restoredIdentity, err := os.ReadFile(filepath.Join(target, "e2ee", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredIdentity) != string(identityBytes) {
		t.Fatal("restore changed E2EE identity bytes")
	}
	restoredClientIdentity, err := os.ReadFile(filepath.Join(target, "e2ee", "client-control-identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredClientIdentity) != string(clientIdentityBytes) {
		t.Fatal("restore changed Client-Control PQ identity bytes")
	}
	restoredKey, err := os.ReadFile(filepath.Join(target, "e2ee", "contacts", "peer.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredKey) != string(keyBytes) {
		t.Fatal("restore changed contact key file bytes")
	}

	restored, err := New(filepath.Join(target, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	restoredContact, err := restored.GetContact(contact.ID)
	if err != nil {
		restored.Close()
		t.Fatal(err)
	}
	if restoredContact == nil || restoredContact.SendSequence != 2 || len(restoredContact.ReceivedSequences) != 1 || restoredContact.ReceivedSequences[0] != 77 {
		restored.Close()
		t.Fatalf("contact replay/send counters were not restored: %#v", restoredContact)
	}
	restoredSession, err := restored.GetPeerSession(contact.ID)
	if err != nil {
		restored.Close()
		t.Fatal(err)
	}
	if restoredSession == nil || restoredSession.Epoch != 4 || restoredSession.SendCount != 8 || restoredSession.ReceiveCount != 13 || string(restoredSession.RootKey) != string(bytesForBackupTest(32, 0x11)) {
		restored.Close()
		t.Fatalf("peer session counters/key continuity was not restored: %#v", restoredSession)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	checkSQLiteIntegrityAndForeignKeys(t, filepath.Join(target, stateDatabaseName))

	if err := os.WriteFile(filepath.Join(root, "non-empty"), []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	nonEmptyTarget := filepath.Join(root, "non-empty-target")
	if err := os.Mkdir(nonEmptyTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyTarget, "keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreStateDir(backup, nonEmptyTarget); !errors.Is(err, ErrStateRestoreTargetNotEmpty) {
		t.Fatalf("restore overwrote non-empty target: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nonEmptyTarget, "keep")); err != nil {
		t.Fatalf("failed restore did not leave target untouched: %v", err)
	}
}

func TestStateBackupRejectsExistingBackupAndIncompleteTarget(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	persistence, err := New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup")
	if _, err := BackupStateDir(source, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupStateDir(source, backup); !errors.Is(err, ErrStateBackupDestinationExists) {
		t.Fatalf("existing backup was overwritten: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "partial"), []byte("half-complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreStateDir(backup, target); !errors.Is(err, ErrStateRestoreTargetNotEmpty) {
		t.Fatalf("half-complete restore target was accepted: %v", err)
	}
}

func TestHubBackupDoesNotCaptureOrRestoreColocatedNodeState(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	persistence, err := New(filepath.Join(source, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	nodeKey := filepath.Join(source, "nodes", "node-a", "endpoint-keys", "private.json")
	if err := os.MkdirAll(filepath.Dir(nodeKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodeKey, []byte("synthetic-node-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	backup := filepath.Join(root, "hub-backup")
	manifest, err := BackupStateDir(source, backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		if file.Path == "nodes" || strings.HasPrefix(file.Path, "nodes/") {
			t.Fatalf("Hub backup captured independent Node state: %s", file.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(backup, stateBackupPayloadName, "nodes")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Hub backup payload contains Node state: %v", err)
	}
	if _, err := VerifyStateBackup(backup); err != nil {
		t.Fatalf("Hub backup without Node subtree failed verification: %v", err)
	}
	target := filepath.Join(root, "restored-hub")
	if _, err := RestoreStateDir(backup, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "nodes")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Hub restore reintroduced Node state: %v", err)
	}
	// Older archives might contain Node files. Their bytes remain on disk for
	// manual recovery, but the Hub-only restore must refuse them before copy.
	manifest.Files = append(manifest.Files, StateBackupFile{Path: "nodes/node-a/relay.token", Mode: 0o600})
	if err := validateManifestFiles(manifest.Files); !errors.Is(err, ErrStateBackupPathUnsafe) {
		t.Fatalf("legacy manifest with Node secrets was accepted: %v", err)
	}
}

func checkSQLiteIntegrityAndForeignKeys(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteFileURI(path, "mode=ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("restored database integrity=%q err=%v", integrity, err)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("restored database has foreign-key violations")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode=%o want %o", path, info.Mode().Perm(), want)
	}
}

func bytesForBackupTest(size int, value byte) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = value
	}
	return result
}
