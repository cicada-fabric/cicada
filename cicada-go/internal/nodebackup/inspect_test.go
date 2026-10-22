package nodebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func TestRecoveryInspectIsReadOnlyAndReportsUncertainty(t *testing.T) {
	backupDir, stateDir, nodeDir := createRecoveryInspectFixture(t)
	before := snapshotNodeTree(t, nodeDir)
	markerBefore, err := os.ReadFile(filepath.Join(nodeDir, recoveryMarker))
	if err != nil {
		t.Fatal(err)
	}

	report, err := Inspect(backupDir, stateDir)
	if err != nil {
		t.Fatalf("inspect restored Node: %v", err)
	}
	after := snapshotNodeTree(t, nodeDir)
	markerAfter, err := os.ReadFile(filepath.Join(nodeDir, recoveryMarker))
	if err != nil {
		t.Fatal(err)
	}
	if !equalFileSnapshots(before, after) || !bytes.Equal(markerBefore, markerAfter) {
		t.Fatal("recovery inspection modified Node files or its quarantine marker")
	}
	if report.AgentMayStart || report.QuarantineStatus != "pending" || report.HubBindingCheck != "not_checked_offline" ||
		report.CryptoCounterWatermark != "local_only_not_reconciled" || report.NativeRuntimeCheck != "not_checked" {
		t.Fatalf("inspection implied reconciliation or startup is safe: %+v", report)
	}
	if report.CryptoState.SequenceStreams != 1 || report.CryptoState.HighestLocalSequence != 1 ||
		report.CryptoState.OutboxRecords != 1 || report.CryptoState.ReplayRecords != 1 || report.CryptoState.InboxRecords != 1 {
		t.Fatalf("unexpected local crypto metadata: %+v", report.CryptoState)
	}
	if report.RelayInbox.Present || !report.LocalInbox.Present || report.LocalMessages.Present {
		t.Fatalf("optional databases were not reported accurately: relay=%+v local=%+v messages=%+v",
			report.RelayInbox, report.LocalInbox, report.LocalMessages)
	}
	if report.LocalInbox.PendingInjectionDeliveries != 1 ||
		report.LocalInbox.DeliveriesByState[string(nodeinbox.INJECTION_UNCERTAIN)] != 1 ||
		report.LocalInbox.AttemptsByState[string(nodeinbox.INJECTION_UNCERTAIN)] != 1 {
		t.Fatalf("pending or uncertain native injection state missing: %+v", report.LocalInbox)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SYNTHETIC-PRIVATE-KEY", "SYNTHETIC-OPAQUE-CIPHERTEXT", "SYNTHETIC-DELIVERY-BODY"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("inspection report exposed sensitive fixture data %q", secret)
		}
	}
}

func TestRecoveryInspectRejectsRestoredTreeCorruption(t *testing.T) {
	backupDir, stateDir, nodeDir := createRecoveryInspectFixture(t)
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(backupDir, stateDir); err == nil {
		t.Fatal("inspection accepted a restored Node file that differs from its manifest")
	}
}

func TestRecoveryInspectRejectsMissingMarker(t *testing.T) {
	backupDir, stateDir, nodeDir := createRecoveryInspectFixture(t)
	if err := os.Remove(filepath.Join(nodeDir, recoveryMarker)); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(backupDir, stateDir); err == nil {
		t.Fatal("inspection accepted a restored Node without its quarantine marker")
	}
}

func TestRecoveryRegistryKeepsRestoredNodeQuarantinedAfterMarkerLoss(t *testing.T) {
	_, stateDir, nodeDir := createRecoveryInspectFixture(t)
	if err := os.Remove(filepath.Join(nodeDir, recoveryMarker)); err != nil {
		t.Fatal(err)
	}
	active, err := RecoveryQuarantineActive(stateDir, backupTestNodeID)
	if err != nil || !active {
		t.Fatalf("restored Node escaped quarantine after marker loss: active=%t err=%v", active, err)
	}
}

func TestRecoveryInspectRejectsMarkerDigestMismatch(t *testing.T) {
	backupDir, stateDir, nodeDir := createRecoveryInspectFixture(t)
	markerPath := filepath.Join(nodeDir, recoveryMarker)
	markerBytes, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker recoveryPendingManifest
	if err := json.Unmarshal(markerBytes, &marker); err != nil {
		t.Fatal(err)
	}
	marker.BackupManifestSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	markerBytes, err = json.MarshalIndent(marker, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	markerBytes = append(markerBytes, '\n')
	if err := os.WriteFile(markerPath, markerBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(backupDir, stateDir); err == nil {
		t.Fatal("inspection accepted a marker with a different manifest digest")
	}
}

func TestRecoveryInspectRejectsMissingDatabase(t *testing.T) {
	backupDir, stateDir, nodeDir := createRecoveryInspectFixture(t)
	if err := os.Remove(filepath.Join(nodeDir, "local-inbox.sqlite3")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(backupDir, stateDir); err == nil {
		t.Fatal("inspection accepted a restored Node missing a manifest database")
	}
}

func TestRecoveryInspectRequiresExclusiveMaintenanceLock(t *testing.T) {
	backupDir, stateDir, _ := createRecoveryInspectFixture(t)
	writer, err := nodelock.AcquireMaintenance(stateDir, backupTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := Inspect(backupDir, stateDir); !errors.Is(err, nodelock.ErrBusy) {
		t.Fatalf("inspection with an active Node writer returned %v, want busy", err)
	}
}

func TestLocalDomainCryptoSchemaInspectionRequiresAllTrustTablesReadOnly(t *testing.T) {
	for _, missing := range []string{"", "node_crypto_owner_key_trust", "node_native_pair_attestations", "node_local_domain_policies_v1", "node_local_domain_members_v1", "node_local_domain_local_keys_v1", "node_local_domain_attestations_v1", "future-schema"} {
		t.Run(missing, func(t *testing.T) {
			dir := t.TempDir()
			state, err := nodekeys.OpenCryptoState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "node-crypto-state.sqlite")
			if missing != "" {
				db, err := openSQLite(path, "mode=rw")
				if err != nil {
					t.Fatal(err)
				}
				statement := "DROP TABLE " + missing
				if missing == "future-schema" {
					statement = "UPDATE node_crypto_schema SET version=8 WHERE singleton=1"
				}
				_, err = db.Exec(statement)
				closeErr := db.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			before := snapshotNodeTree(t, dir)
			report, err := inspectCryptoState(path)
			if missing == "" {
				if err != nil || report.SchemaVersion != 7 {
					t.Fatal("current crypto schema was not inspected", err)
				}
			} else if !errors.Is(err, ErrBackupInvalid) {
				t.Fatal("unsupported or incomplete crypto schema accepted", err)
			}
			if !equalFileSnapshots(before, snapshotNodeTree(t, dir)) {
				t.Fatal("offline inspection changed crypto state")
			}
		})
	}
}

func createRecoveryInspectFixture(t *testing.T) (backupDir, stateDir, nodeDir string) {
	t.Helper()
	root := t.TempDir()
	stateDir = filepath.Join(root, "restored-state")
	sourceStateDir := filepath.Join(root, "source-state")
	nodeDir = nodeStatePath(sourceStateDir, backupTestNodeID)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "identity.json"), []byte("synthetic Node identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	cryptoState, err := nodekeys.OpenCryptoState(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	if sequence, err := cryptoState.ReserveOutboundSequence(ctx, "ep_recovery", "key_recovery"); err != nil || sequence != 1 {
		t.Fatalf("reserve local sequence: sequence=%d err=%v", sequence, err)
	}
	if _, created, err := cryptoState.StoreOutbound(ctx, "op_recovery", "ep_recovery", "key_recovery",
		[]byte("SYNTHETIC-OPAQUE-CIPHERTEXT")); err != nil || !created {
		t.Fatalf("store synthetic outbound ciphertext: created=%t err=%v", created, err)
	}
	if duplicate, err := cryptoState.AcceptInbound(ctx, "ep_recovery", "sender_key_recovery", "message_recovery", 7,
		[]byte("SYNTHETIC-INBOUND-CIPHERTEXT")); err != nil || duplicate {
		t.Fatalf("record replay identity: duplicate=%t err=%v", duplicate, err)
	}
	if err := cryptoState.Close(); err != nil {
		t.Fatal(err)
	}

	inbox, err := nodeinbox.Open(filepath.Join(nodeDir, "local-inbox.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	uncertain, _, err := inbox.Save(ctx, nodeinbox.Message{MessageID: "message_uncertain", Digest: "synthetic-digest-a",
		EndpointID: "ep_recovery", SessionID: "native-session-a", BindingEpoch: 4,
		Payload: []byte("SYNTHETIC-DELIVERY-BODY")})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := inbox.Claim(ctx, "inspect-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Acknowledge(ctx, nodeinbox.Receipt{MessageID: uncertain.MessageID, Digest: uncertain.Digest,
		EndpointID: uncertain.EndpointID, SessionID: uncertain.SessionID, BindingEpoch: uncertain.BindingEpoch,
		AttemptID: claim.AttemptID, State: nodeinbox.INJECTION_UNCERTAIN}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inbox.Save(ctx, nodeinbox.Message{MessageID: "message_pending", Digest: "synthetic-digest-b",
		EndpointID: "ep_recovery", SessionID: "native-session-a", BindingEpoch: 4,
		Payload: []byte("SYNTHETIC-PENDING-BODY")}); err != nil {
		t.Fatal(err)
	}
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}

	backupDir = filepath.Join(root, "backup")
	if _, err := Backup(sourceStateDir, backupTestNodeID, backupDir); err != nil {
		t.Fatal(err)
	}
	restored, err := Restore(backupDir, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	return backupDir, stateDir, restored.NodeState
}

func snapshotNodeTree(t *testing.T, root string) map[string]fileSnapshot {
	t.Helper()
	result := make(map[string]fileSnapshot)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
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
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = fileSnapshot{size: info.Size(), mode: info.Mode().Perm(), mod: info.ModTime(), data: string(data)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type recoveryInspectionSnapshot struct {
	info os.FileInfo
	data string
}

func snapshotRecoveryInspection(t *testing.T, root string) map[string]recoveryInspectionSnapshot {
	t.Helper()
	result := map[string]recoveryInspectionSnapshot{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = os.ReadFile(path)
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = os.Readlink(path)
			data = []byte(target)
		}
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[rel] = recoveryInspectionSnapshot{info: info, data: string(data)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertRecoveryInspectionUnchanged(t *testing.T, root string, before map[string]recoveryInspectionSnapshot) {
	t.Helper()
	after := snapshotRecoveryInspection(t, root)
	if len(before) != len(after) {
		t.Fatalf("inspection changed entries: %d -> %d", len(before), len(after))
	}
	for path, b := range before {
		a, ok := after[path]
		if !ok || b.data != a.data || b.info.Mode() != a.info.Mode() || !os.SameFile(b.info, a.info) || !b.info.ModTime().Equal(a.info.ModTime()) {
			t.Fatalf("inspection changed file/directory %s", path)
		}
	}
}

func TestRecoveryInspectPreservesEntireStateIncludingLockMetadata(t *testing.T) {
	backup, state, _ := createRecoveryInspectFixture(t)
	before := snapshotRecoveryInspection(t, filepath.Dir(state))
	report, err := Inspect(backup, state)
	if err != nil {
		t.Fatal(err)
	}
	if report.AgentMayStart || report.QuarantineStatus != "pending" || report.CryptoCounterWatermark != "local_only_not_reconciled" {
		t.Fatalf("unsafe report: %+v", report)
	}
	assertRecoveryInspectionUnchanged(t, filepath.Dir(state), before)
}

func TestRecoveryInspectMissingAndUnsafeNodeLocksDoNotMutate(t *testing.T) {
	for _, kind := range []string{"missing directory", "missing file", "public directory", "public file", "symlink file"} {
		t.Run(kind, func(t *testing.T) {
			backup, state, _ := createRecoveryInspectFixture(t)
			dir := filepath.Join(state, "nodes", ".locks")
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var path string
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".maintenance.lock") {
					path = filepath.Join(dir, entry.Name())
				}
			}
			if path == "" {
				t.Fatal("restore did not establish lock")
			}
			switch kind {
			case "missing directory":
				err = os.RemoveAll(dir)
			case "missing file":
				err = os.Remove(path)
			case "public directory":
				err = os.Chmod(dir, 0o755)
			case "public file":
				err = os.Chmod(path, 0o644)
			case "symlink file":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.Symlink(path+".old", path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotRecoveryInspection(t, filepath.Dir(state))
			if report, err := Inspect(backup, state); err == nil || report != nil {
				t.Fatal("inspection accepted missing/unsafe Node lock")
			}
			assertRecoveryInspectionUnchanged(t, filepath.Dir(state), before)
		})
	}
}

func createSharedRecoveryInspectionFixture(t *testing.T) (base, backup, state, writer string) {
	t.Helper()
	base = t.TempDir()
	source := filepath.Join(base, "source")
	sourceWriter := filepath.Join(base, "source-writer")
	makePrivateDir(t, source)
	makePrivateDir(t, sourceWriter)
	makeNodeSubtree(t, source, backupTestNodeID)
	populateSharedWriterRoot(t, sourceWriter)
	backup = filepath.Join(base, "backup")
	if _, err := BackupWithWriterRoot(source, backupTestNodeID, sourceWriter, backup); err != nil {
		t.Fatal(err)
	}
	state = filepath.Join(base, "target")
	writer = filepath.Join(base, "target-writer")
	makePrivateDir(t, writer)
	if _, err := RestoreWithWriterRoot(backup, state, writer); err != nil {
		t.Fatal(err)
	}
	return
}

func TestRecoveryInspectWriterRootPreservesFencesDatabasesAndBothHolds(t *testing.T) {
	base, backup, state, writer := createSharedRecoveryInspectionFixture(t)
	before := snapshotRecoveryInspection(t, base)
	report, err := InspectWithWriterRoot(backup, state, writer)
	if err != nil {
		t.Fatal(err)
	}
	if report.AgentMayStart || report.QuarantineStatus != "pending" || report.CryptoCounterWatermark != "local_only_not_reconciled" ||
		!report.SharedWriterRootHeld || report.SharedWriterRootCheck != "matches_archive_bundle_but_reconciliation_required" {
		t.Fatalf("unsafe report: %+v", report)
	}
	assertRecoveryInspectionUnchanged(t, base, before)
}

func TestRecoveryInspectWriterRootMissingUnsafeAndBusyDoNotMutate(t *testing.T) {
	for _, kind := range []string{"missing root", "missing file", "public file", "public root", "peer writer", "Node writer"} {
		t.Run(kind, func(t *testing.T) {
			base, backup, state, writer := createSharedRecoveryInspectionFixture(t)
			var err error
			var held *nodelock.Lock
			switch kind {
			case "missing root":
				writer = filepath.Join(base, "absent")
			case "missing file":
				err = os.Remove(filepath.Join(writer, ".writer-root.maintenance.lock"))
			case "public file":
				err = os.Chmod(filepath.Join(writer, ".writer-root.maintenance.lock"), 0o644)
			case "public root":
				err = os.Chmod(writer, 0o755)
			case "peer writer":
				held, err = nodelock.AcquireWriterRoot(writer)
			case "Node writer":
				held, err = nodelock.AcquireMaintenance(state, backupTestNodeID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if held != nil {
				defer held.Close()
			}
			before := snapshotRecoveryInspection(t, base)
			result := make(chan error, 1)
			go func() {
				report, err := InspectWithWriterRoot(backup, state, writer)
				if report != nil && err == nil {
					err = errors.New("accepted unsafe/busy state")
				}
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("inspection accepted unsafe state")
				}
				if held != nil && !errors.Is(err, nodelock.ErrBusy) {
					t.Fatalf("want busy, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("inspection blocked on a held lock")
			}
			assertRecoveryInspectionUnchanged(t, base, before)
			if held != nil {
				_ = held.Close()
				// Failed acquisition of the second lock releases the first.
				if _, err := InspectWithWriterRoot(backup, state, writer); err != nil {
					t.Fatalf("failed inspection leaked a lock: %v", err)
				}
			}
		})
	}
}

func TestRecoveryInspectionAndRestoreOppositeLockOrderReturnsBusy(t *testing.T) {
	base, _, state, writer := createSharedRecoveryInspectionFixture(t)
	before := snapshotRecoveryInspection(t, base)
	ready := make(chan error, 2)
	start := make(chan struct{})
	release := make(chan struct{})
	results := make(chan error, 2)
	done := make(chan struct{}, 2)
	defer func() {
		select {
		case <-start:
		default:
			close(start)
		}
		close(release)
		<-done
		<-done
	}()
	// Force the actual first-lock collision deterministically: inspection is
	// WriterRoot-first and restore is Node-first. Keep both first locks held
	// until both second acquisitions return, rather than relying on scheduling.
	go func() {
		defer func() { done <- struct{}{} }()
		first, err := nodelock.AcquireWriterRootExclusiveExisting(writer)
		ready <- err
		if err != nil {
			return
		}
		defer first.Close()
		<-start
		second, err := nodelock.AcquireMaintenanceExclusiveExisting(state, backupTestNodeID)
		if second != nil {
			_ = second.Close()
		}
		results <- err
		<-release
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		first, err := nodelock.AcquireMaintenanceExclusive(state, backupTestNodeID)
		ready <- err
		if err != nil {
			return
		}
		defer first.Close()
		<-start
		second, err := nodelock.AcquireWriterRootExclusive(writer)
		if second != nil {
			_ = second.Close()
		}
		results <- err
		<-release
	}()
	for i := 0; i < 2; i++ {
		if err := <-ready; err != nil {
			t.Fatal(err)
		}
	}
	close(start)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, nodelock.ErrBusy) {
				t.Fatalf("opposite-order acquisition error=%v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("opposite-order locks deadlocked")
		}
	}
	assertRecoveryInspectionUnchanged(t, base, before)

}
