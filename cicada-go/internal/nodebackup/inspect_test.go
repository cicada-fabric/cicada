package nodebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
