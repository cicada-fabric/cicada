package nodebackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func TestSharedWriterRootBackupRestorePreservesFencesAndQuarantines(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "source-state")
	writerRoot := filepath.Join(base, "source-writer-root")
	makePrivateDir(t, stateDir)
	makePrivateDir(t, writerRoot)
	makeNodeSubtree(t, stateDir, "node-shared-backup")
	populateSharedWriterRoot(t, writerRoot)

	backupDir := filepath.Join(base, "archive")
	report, err := BackupWithWriterRoot(stateDir, "node-shared-backup", writerRoot, backupDir)
	if err != nil {
		t.Fatalf("backup shared WriterRoot: %v", err)
	}
	if report.Manifest.FormatVersion != CurrentFormatVersion || report.Manifest.SharedWriterRoot == nil {
		t.Fatalf("backup omitted v2 shared fence manifest: %#v", report.Manifest)
	}
	var nativeEpoch, nativeOperation, resourceRecord, flockFile bool
	for _, entry := range report.Manifest.SharedWriterRoot.Files {
		nativeEpoch = nativeEpoch || strings.HasPrefix(entry.Path, ".native-writers/") && strings.HasSuffix(entry.Path, ".lock.epoch")
		nativeOperation = nativeOperation || strings.Contains(entry.Path, ".lock.operations/")
		resourceRecord = resourceRecord || strings.HasPrefix(entry.Path, "nodes/.locks/resource-") && strings.HasSuffix(entry.Path, ".execution.json")
		flockFile = flockFile || strings.HasSuffix(entry.Path, ".lock")
	}
	if !nativeEpoch || !nativeOperation || !resourceRecord || flockFile {
		t.Fatalf("shared archive durable marker selection epoch=%t operation=%t resource=%t flock=%t files=%v",
			nativeEpoch, nativeOperation, resourceRecord, flockFile, report.Manifest.SharedWriterRoot.Files)
	}
	if _, err := Verify(backupDir); err != nil {
		t.Fatalf("verify shared WriterRoot archive: %v", err)
	}
	for _, prohibited := range []string{"outside-node-scope.json", "nodes/node-other/private.json"} {
		for _, entry := range report.Manifest.SharedWriterRoot.Files {
			if entry.Path == prohibited {
				t.Fatalf("archive included out-of-scope WriterRoot path %q", prohibited)
			}
		}
	}

	targetState := filepath.Join(base, "target-state")
	targetWriterRoot := filepath.Join(base, "target-writer-root")
	makePrivateDir(t, targetWriterRoot)
	restored, err := RestoreWithWriterRoot(backupDir, targetState, targetWriterRoot)
	if err != nil {
		t.Fatalf("restore shared WriterRoot archive: %v", err)
	}
	if !restored.Quarantined || restored.Manifest.SharedWriterRoot == nil {
		t.Fatalf("restore did not remain quarantined with shared manifest: %#v", restored)
	}
	if active, err := WriterRootRecoveryQuarantineActive(targetWriterRoot); err != nil || !active {
		t.Fatalf("WriterRoot recovery hold active=%t err=%v", active, err)
	}
	if err := sharedRootMatchesManifest(targetWriterRoot, report.Manifest.SharedWriterRoot); err != nil {
		t.Fatalf("restored four shared fence areas differ from archive: %v", err)
	}

	// A second Hub's per-Node subtree can be restored only when it carries the
	// exact same shared bundle. The shared databases and epochs are verified in
	// place and never replaced.
	secondNodeState := filepath.Join(base, "second-hub-state")
	makePrivateDir(t, secondNodeState)
	if _, err := RestoreWithWriterRoot(backupDir, secondNodeState, targetWriterRoot); err != nil {
		t.Fatalf("idempotent exact shared bundle restore: %v", err)
	}
	assertSharedFenceStateReadable(t, targetWriterRoot)
}

func TestSharedWriterRootRestoreRejectsMissingLegacyAndConflictingBundles(t *testing.T) {
	t.Run("legacy archive establishes permanent shared hold", func(t *testing.T) {
		backupDir := createMinimalNodeBackup(t, "node-legacy-shared-hold")
		writerRoot := filepath.Join(t.TempDir(), "writer-root")
		makePrivateDir(t, writerRoot)
		targetState := filepath.Join(t.TempDir(), "state")
		if _, err := RestoreWithWriterRoot(backupDir, targetState, writerRoot); err != nil {
			t.Fatalf("restore legacy Node subtree into held root: %v", err)
		}
		active, err := WriterRootRecoveryQuarantineActive(writerRoot)
		if err != nil || !active {
			t.Fatalf("legacy restore did not hold WriterRoot active=%t err=%v", active, err)
		}
		v2Base := t.TempDir()
		v2State := filepath.Join(v2Base, "state")
		v2Root := filepath.Join(v2Base, "writer-root")
		makePrivateDir(t, v2State)
		makePrivateDir(t, v2Root)
		makeNodeSubtree(t, v2State, "node-v2-after-legacy")
		populateSharedWriterRoot(t, v2Root)
		v2Archive := filepath.Join(v2Base, "archive")
		if _, err := BackupWithWriterRoot(v2State, "node-v2-after-legacy", v2Root, v2Archive); err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreWithWriterRoot(v2Archive, filepath.Join(v2Base, "target-state"), writerRoot); !errors.Is(err, ErrRestoreTargetBusy) {
			t.Fatalf("v2 archive unexpectedly replaced permanent legacy hold: %v", err)
		}
	})

	t.Run("preexisting shared path without restore marker is never overwritten", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		writerRoot := filepath.Join(base, "source-root")
		makePrivateDir(t, stateDir)
		makePrivateDir(t, writerRoot)
		makeNodeSubtree(t, stateDir, "node-conflict")
		populateSharedWriterRoot(t, writerRoot)
		backupDir := filepath.Join(base, "archive")
		if _, err := BackupWithWriterRoot(stateDir, "node-conflict", writerRoot, backupDir); err != nil {
			t.Fatal(err)
		}
		targetRoot := filepath.Join(base, "target-root")
		makePrivateDir(t, targetRoot)
		if err := os.Mkdir(filepath.Join(targetRoot, ".native-writers"), 0o700); err != nil {
			t.Fatal(err)
		}
		preexisting := filepath.Join(targetRoot, ".native-writers", "unrelated.lock")
		if err := os.WriteFile(preexisting, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := RestoreWithWriterRoot(backupDir, filepath.Join(base, "target-state"), targetRoot)
		if !errors.Is(err, ErrRestoreTargetBusy) {
			t.Fatalf("restore error=%v, want conflict", err)
		}
		got, readErr := os.ReadFile(preexisting)
		if readErr != nil || string(got) != "preserve" {
			t.Fatalf("restore modified preexisting shared state: %q err=%v", got, readErr)
		}
		if active, _ := WriterRootRecoveryQuarantineActive(targetRoot); active {
			t.Fatal("conflict installed a misleading recovery marker")
		}
	})
}

func TestSharedWriterRootRestorePreservesForeignNodesAndRejectsFenceRollback(t *testing.T) {
	base := t.TempDir()
	sourceState := filepath.Join(base, "source-state")
	sourceRoot := filepath.Join(base, "source-root")
	makePrivateDir(t, sourceState)
	makePrivateDir(t, sourceRoot)
	makeNodeSubtree(t, sourceState, "node-backup-source")
	populateSharedWriterRoot(t, sourceRoot)
	archive := filepath.Join(base, "archive")
	if _, err := BackupWithWriterRoot(sourceState, "node-backup-source", sourceRoot, archive); err != nil {
		t.Fatal(err)
	}

	targetState := filepath.Join(base, "target-state")
	targetRoot := filepath.Join(base, "target-root")
	makePrivateDir(t, targetState)
	makePrivateDir(t, targetRoot)
	foreignNode := filepath.Join(targetRoot, "nodes", "node-foreign")
	makePrivateDir(t, foreignNode)
	foreignIdentity := filepath.Join(foreignNode, "identity.json")
	if err := os.WriteFile(foreignIdentity, []byte("foreign synthetic node state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreWithWriterRoot(archive, targetState, targetRoot); err != nil {
		t.Fatalf("restore alongside a foreign Node subtree: %v", err)
	}
	if got, err := os.ReadFile(foreignIdentity); err != nil || string(got) != "foreign synthetic node state" {
		t.Fatalf("restore changed foreign Node state: %q err=%v", got, err)
	}

	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(targetRoot, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.RecordProviderAdmissionOutcome(context.Background(), nodeinbox.ProviderAdmissionOutcome{
		ExecutionID: "synthetic-execution", ProviderID: "synthetic-provider", Attempt: 1,
		Class: nodeinbox.ProviderOutcomeRetryableNotInjected}); err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	// The bounded provider backoff is one second for the first attempt.
	time.Sleep(1100 * time.Millisecond)
	decision, err := ledger.AdmitProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: "synthetic-execution", ProviderID: "synthetic-provider", AdmissionIntent: strings.Repeat("c", 64)})
	if err != nil || decision.Attempt != 2 || !decision.Admitted {
		_ = ledger.Close()
		t.Fatalf("advance restored provider generation decision=%#v err=%v", decision, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	resources, err := nodelock.OpenResourceExecutionManager(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	original := nodelock.ResourceExecutionRequest{ResourceID: "gpu/0", LeaseID: "synthetic-lease",
		FencingEpoch: 1, ExecutionID: "synthetic-resource-execution"}
	if err := resources.ReconcileStopped(original, func(record nodelock.ResourceExecutionRecord) (nodelock.ResourceStopReceipt, error) {
		return nodelock.ResourceStopReceipt{ResourceID: record.ResourceID, LeaseID: record.LeaseID,
			FencingEpoch: record.FencingEpoch, ExecutionID: record.ExecutionID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	advanced, err := resources.Begin(nodelock.ResourceExecutionRequest{ResourceID: "gpu/0", LeaseID: "synthetic-lease-next",
		FencingEpoch: 2, ExecutionID: "synthetic-resource-execution-next"})
	if err != nil {
		t.Fatal(err)
	}
	if err := advanced.Quarantine(); err != nil {
		t.Fatal(err)
	}

	secondHubState := filepath.Join(base, "second-hub-state")
	makePrivateDir(t, secondHubState)
	if _, err := RestoreWithWriterRoot(archive, secondHubState, targetRoot); !errors.Is(err, ErrRestoreTargetBusy) {
		t.Fatalf("restore overwrote advanced shared fences: %v", err)
	}
	ledger, err = nodeinbox.OpenProviderAdmissionLedger(filepath.Join(targetRoot, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	decision, err = ledger.InspectProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: "synthetic-execution", ProviderID: "synthetic-provider", AdmissionIntent: strings.Repeat("c", 64)})
	_ = ledger.Close()
	if err != nil || decision.Attempt != 2 || decision.State != nodeinbox.ProviderAdmissionInProgress {
		t.Fatalf("restore rolled provider attempt back decision=%#v err=%v", decision, err)
	}
	resource, err := resources.Inspect("gpu/0")
	if err != nil || resource == nil || resource.FencingEpoch != 2 || resource.ExecutionID != "synthetic-resource-execution-next" {
		t.Fatalf("restore rolled resource epoch back record=%#v err=%v", resource, err)
	}
	if got, err := os.ReadFile(foreignIdentity); err != nil || string(got) != "foreign synthetic node state" {
		t.Fatalf("failed restore changed foreign Node state: %q err=%v", got, err)
	}
}

func TestSharedWriterRootBackupRequiresBoundedOfflineWindowAndCompleteFences(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	writerRoot := filepath.Join(base, "writer-root")
	makePrivateDir(t, stateDir)
	makePrivateDir(t, writerRoot)
	makeNodeSubtree(t, stateDir, "node-busy")
	populateSharedWriterRoot(t, writerRoot)

	shared, err := nodelock.AcquireWriterRoot(writerRoot)
	if err != nil {
		t.Fatal(err)
	}
	_, err = BackupWithWriterRoot(stateDir, "node-busy", writerRoot, filepath.Join(base, "busy-archive"))
	_ = shared.Close()
	if !errors.Is(err, nodelock.ErrBusy) {
		t.Fatalf("backup with live WriterRoot reader error=%v, want immediate ErrBusy", err)
	}

	missingRoot := filepath.Join(base, "missing-root")
	makePrivateDir(t, missingRoot)
	if _, err := BackupWithWriterRoot(stateDir, "node-busy", missingRoot, filepath.Join(base, "missing-archive")); !errors.Is(err, ErrSharedFencesUnavailable) {
		t.Fatalf("backup missing required shared sidecars error=%v", err)
	}
}

func makePrivateDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func makeNodeSubtree(t *testing.T, stateDir, nodeID string) {
	t.Helper()
	path := nodeStatePath(stateDir, nodeID)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "identity.json"), []byte("synthetic-node-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func populateSharedWriterRoot(t *testing.T, root string) {
	t.Helper()
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(root, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AdmitProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: "synthetic-execution", ProviderID: "synthetic-provider", AdmissionIntent: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(root, "node-native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CheckAndRecordNativeContext(context.Background(), nodeinbox.NativeContextScopeInput{
		AccountID: "synthetic-account", Harness: "codex", NativeSessionID: "synthetic-thread",
		HubID: "synthetic-hub", GroupID: "synthetic-group", ContextPolicy: nodeinbox.NativeContextPolicyGroupScoped,
		EndpointID: "synthetic-endpoint", BindingID: "synthetic-binding", BindingEpoch: 1}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := nodelock.AcquireNativeWriter(context.Background(), root, "synthetic-account", "codex", "synthetic-thread")
	if err != nil {
		t.Fatal(err)
	}
	operation := nodelock.NativeOperation{HubID: "synthetic-hub", NodeID: "synthetic-node", EndpointID: "synthetic-endpoint",
		BindingID: "synthetic-binding", BindingEpoch: 1, MessageID: "synthetic-message", Digest: strings.Repeat("b", 64), AttemptID: "synthetic-attempt"}
	if _, err := writer.BeginNativeOperation(operation); err != nil {
		t.Fatal(err)
	}
	if err := writer.FinishNativeOperation(operation, nodelock.NativeQueueAccepted); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	resources, err := nodelock.OpenResourceExecutionManager(root)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := resources.Begin(nodelock.ResourceExecutionRequest{ResourceID: "gpu/0", LeaseID: "synthetic-lease",
		FencingEpoch: 1, ExecutionID: "synthetic-resource-execution"})
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Quarantine(); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "unrelated-hub-data")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "outside-node-scope.json"), []byte("synthetic-unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes := filepath.Join(root, "nodes")
	if err := os.MkdirAll(filepath.Join(nodes, "node-other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodes, "node-other", "private.json"), []byte("synthetic-other-node"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertSharedFenceStateReadable(t *testing.T, root string) {
	t.Helper()
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(root, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := ledger.InspectProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{
		ExecutionID: "synthetic-execution", ProviderID: "synthetic-provider", AdmissionIntent: strings.Repeat("a", 64)})
	if err != nil || decision.Attempt != 1 || decision.State != nodeinbox.ProviderAdmissionInProgress {
		t.Fatalf("restored provider attempt=%#v err=%v", decision, err)
	}
	_ = ledger.Close()
	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(root, "node-native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	decisionScope, err := registry.CheckAndRecordNativeContext(context.Background(), nodeinbox.NativeContextScopeInput{
		AccountID: "synthetic-account", Harness: "codex", NativeSessionID: "synthetic-thread",
		HubID: "synthetic-hub", GroupID: "synthetic-group", ContextPolicy: nodeinbox.NativeContextPolicyGroupScoped,
		EndpointID: "synthetic-endpoint", BindingID: "synthetic-binding", BindingEpoch: 1})
	if err != nil || decisionScope.KnownScopeCount != 1 {
		t.Fatalf("restored native context scope=%#v err=%v", decisionScope, err)
	}
	_ = registry.Close()
	resources, err := nodelock.OpenResourceExecutionManager(root)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := resources.Inspect("gpu/0")
	if err != nil || resource == nil || resource.ExecutionID != "synthetic-resource-execution" || resource.State != nodelock.ResourceExecutionQuarantined {
		t.Fatalf("restored resource fence=%#v err=%v", resource, err)
	}
}
