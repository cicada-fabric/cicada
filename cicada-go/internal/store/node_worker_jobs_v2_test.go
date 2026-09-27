package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type boundNodeFixture struct {
	ownerID string
	device  *ClientDevice
	nodeID  string
	digest  string
	binding *NodeDeviceBinding
}

func newBoundNodeFixture(t *testing.T, s *Store, ownerID string, device *ClientDevice, label string) boundNodeFixture {
	t.Helper()
	nodeID := "node-" + label
	digest := nodeBindingTestCredentialDigest("worker-job-token-" + label)
	codeDigest := nodeBindingTestCodeDigest("worker-job-code-" + label)
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, label, digest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	binding, err := s.ConfirmPendingNodeDeviceBinding(ownerID, device.DeviceID, codeDigest)
	if err != nil {
		t.Fatal(err)
	}
	return boundNodeFixture{ownerID: ownerID, device: device, nodeID: nodeID, digest: digest, binding: binding}
}

func addSecondOwnerDevice(t *testing.T, s *Store) *ClientDevice {
	t.Helper()
	if _, err := s.CreatePrincipal(Principal{ID: "owner_b", Kind: PrincipalKindHuman, OwnerID: "owner_b", Name: "owner_b", Status: PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterOwnerApprovalKeyLocal("owner_b", ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant, err := ownerKey.SignOwnerDeviceGrant("owner_b", "phone_b", deviceKey.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_b", OwnerKeyID: ownerKey.Public().ID, DeviceID: "phone_b",
		DevicePublic: deviceKey.Public(), OwnerDeviceGrant: grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func createOwnerWorker(t *testing.T, s *Store, owner boundNodeFixture, id string) *Worker {
	t.Helper()
	goal, err := s.CreateOwnedGoal(owner.ownerID, Goal{
		ID: "goal-" + id, Objective: "owner-scoped work", SuccessCriteria: "finish",
		MachineID: owner.nodeID, Resources: map[string]any{}, Budget: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := s.CreateWorkerAtHarness("worker-"+id, goal.ID, owner.nodeID, "codex", "/tmp/response-"+id, "/tmp/work-"+id)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestBoundNodeWorkerReadsAndClaimsAreOwnerMachineAndGoalScoped(t *testing.T) {
	s, _, _, deviceA := newClientDeviceFixture(t)
	ownerA := newBoundNodeFixture(t, s, "owner_a", deviceA, "a")
	ownerASecondNode := newBoundNodeFixture(t, s, "owner_a", deviceA, "a-second")
	deviceB := addSecondOwnerDevice(t, s)
	ownerB := newBoundNodeFixture(t, s, "owner_b", deviceB, "b")
	workerA := createOwnerWorker(t, s, ownerA, "a")
	workerASecondNode := createOwnerWorker(t, s, ownerASecondNode, "a-second")
	workerB := createOwnerWorker(t, s, ownerB, "b")

	legacyGoal, err := s.CreateGoal("goal-legacy-node-worker", "legacy", "", "", 50, ownerA.nodeID, "", "/tmp/legacy")
	if err != nil {
		t.Fatal(err)
	}
	legacyWorker, err := s.CreateWorkerAtHarness("worker-legacy-node-worker", legacyGoal.ID, ownerA.nodeID, "codex", "/tmp/legacy-response", "/tmp/legacy")
	if err != nil {
		t.Fatal(err)
	}
	if legacyGoal.OwnerID != "" || legacyWorker.MachineID != ownerA.nodeID {
		t.Fatalf("legacy fixture was unexpectedly owner-attributed: goal=%#v worker=%#v", legacyGoal, legacyWorker)
	}

	// A forged Worker that points at another owner's Goal cannot pass even if
	// its machine_id is changed to the caller's Node.
	stamp := now()
	if _, err := s.db.Exec(`INSERT INTO workers
(id, goal_id, machine_id, harness, status, response_file, workspace, created_at, updated_at)
VALUES ('worker-owner-mismatch', ?, ?, 'codex', 'queued', '/tmp/x', '/tmp/x', ?, ?)`, workerB.GoalID, ownerA.nodeID, stamp, stamp); err != nil {
		t.Fatal(err)
	}

	ids, err := s.ListBoundNodeWorkerIDs(ownerA.digest, ownerA.nodeID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != workerA.ID {
		t.Fatalf("Node A saw a Worker assigned to another same-owner Node: %#v", ids)
	}
	if _, err := s.GetBoundNodeWorker(ownerA.digest, ownerB.nodeID, workerA.ID); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("wrong Node path accepted A's token: %v", err)
	}
	for _, workerID := range []string{workerASecondNode.ID, workerB.ID, legacyWorker.ID, "worker-owner-mismatch"} {
		if _, err := s.GetBoundNodeWorker(ownerA.digest, ownerA.nodeID, workerID); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
			t.Fatalf("Node A read unauthorized Worker %q: %v", workerID, err)
		}
		if _, err := s.ClaimBoundNodeWorker(ownerA.digest, ownerA.nodeID, workerID); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
			t.Fatalf("Node A claimed unauthorized Worker %q: %v", workerID, err)
		}
	}
	if _, err := s.ClaimBoundNodeWorker(ownerA.digest, ownerA.nodeID, workerA.ID); err != nil {
		t.Fatalf("owner-bound Node could not claim its Worker: %v", err)
	}
}

func TestBoundNodeWorkerConcurrentClaimsAndResultsAreAttemptFenced(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	owner := newBoundNodeFixture(t, s, "owner_a", device, "race")
	worker := createOwnerWorker(t, s, owner, "race")

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := 0
	var claimErrors []error
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				claimed++
			} else if !errors.Is(err, ErrNodeWorkerUnavailable) {
				claimErrors = append(claimErrors, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if claimed != 1 || len(claimErrors) != 0 {
		t.Fatalf("concurrent claims=%d unexpected errors=%v", claimed, claimErrors)
	}

	start = make(chan struct{})
	var began int
	var beginErrors []error
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.BeginBoundNodeWorkerResult(owner.digest, owner.nodeID, worker.ID, 1)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				began++
			} else if !errors.Is(err, ErrNodeWorkerUnavailable) {
				beginErrors = append(beginErrors, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if began != 1 || len(beginErrors) != 0 {
		t.Fatalf("concurrent result admissions=%d unexpected errors=%v", began, beginErrors)
	}

	updated, err := s.UpdateBoundNodeWorkerAtAttempt(owner.digest, owner.nodeID, worker.ID,
		"verifying", "completed", 1, WorkerUpdate{Summary: stringPtrForStore("first result")})
	if err != nil || updated == nil || updated.Status != "completed" || updated.Summary != "first result" {
		t.Fatalf("guarded final result=%#v err=%v", updated, err)
	}
	if _, err := s.UpdateBoundNodeWorkerAtAttempt(owner.digest, owner.nodeID, worker.ID,
		"verifying", "completed", 1, WorkerUpdate{Summary: stringPtrForStore("late result")}); !errors.Is(err, ErrNodeWorkerUnavailable) {
		t.Fatalf("late duplicate result was accepted: %v", err)
	}
	stored, err := s.GetWorker(worker.ID)
	if err != nil || stored.Summary != "first result" || stored.Attempt != 1 {
		t.Fatalf("late result changed stored attempt: %#v err=%v", stored, err)
	}
}

func TestBoundNodeResultRevocationDiscardsResultAndLeavesRecoverableAttempt(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	owner := newBoundNodeFixture(t, s, "owner_a", device, "revoke-result")
	worker := createOwnerWorker(t, s, owner, "revoke-result")
	if _, err := s.ClaimBoundNodeWorker(owner.digest, owner.nodeID, worker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginBoundNodeWorkerResult(owner.digest, owner.nodeID, worker.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeNodeDeviceBinding(owner.ownerID, owner.binding.ID, owner.binding.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateBoundNodeWorkerAtAttempt(owner.digest, owner.nodeID, worker.ID,
		"verifying", "completed", 1, WorkerUpdate{Summary: stringPtrForStore("must not persist")}); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("revoked Node result passed final guard: %v", err)
	}
	recovered, err := s.RecoverBoundNodeWorkerAfterRevocation(worker.ID, owner.nodeID, 1)
	if err != nil || recovered == nil || recovered.Status != "recovering" || recovered.Summary != "" || recovered.Attempt != 1 {
		t.Fatalf("revoked attempt was not safely recoverable: %#v err=%v", recovered, err)
	}
}

func TestBoundNodeCredentialRotationAndLegacyMigrationStayOwnerless(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	var machineOwner, goalOwner string
	if err := s.db.QueryRow(`SELECT owner_id FROM machines WHERE id='machine_legacy'`).Scan(&machineOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT owner_id FROM goals WHERE id='goal_legacy'`).Scan(&goalOwner); err != nil {
		t.Fatal(err)
	}
	if machineOwner != "" || goalOwner != "" {
		t.Fatalf("migration inferred owner attribution for legacy rows: machine=%q goal=%q", machineOwner, goalOwner)
	}
	_ = s.Close()

	s, _, _, device := newClientDeviceFixture(t)
	defer s.Close()
	owner := newBoundNodeFixture(t, s, "owner_a", device, "rotate")
	worker := createOwnerWorker(t, s, owner, "rotate")
	if _, err := s.RevokeNodeDeviceBinding(owner.ownerID, owner.binding.ID, owner.binding.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_device_binding_requests_v2 SET created_at=? WHERE node_id=?`,
		time.Now().UTC().Add(-10*time.Second).Format(time.RFC3339Nano), owner.nodeID); err != nil {
		t.Fatal(err)
	}
	newDigest := nodeBindingTestCredentialDigest("worker-job-token-rotate-2")
	newCode := nodeBindingTestCodeDigest("worker-job-code-rotate-2")
	if _, err := s.CreatePendingNodeDeviceBinding(owner.nodeID, "rotate", newDigest, newCode, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding(owner.ownerID, device.DeviceID, newCode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListBoundNodeWorkerIDs(owner.digest, owner.nodeID, 100); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("rotated credential remained active: %v", err)
	}
	ids, err := s.ListBoundNodeWorkerIDs(newDigest, owner.nodeID, 100)
	if err != nil || len(ids) != 1 || ids[0] != worker.ID {
		t.Fatalf("rotated owner-bound credential lost its Worker: ids=%v err=%v", ids, err)
	}
}

func TestBoundNodeHeartbeatPreservesStatusUnlessExplicit(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	owner := newBoundNodeFixture(t, s, "owner_a", device, "heartbeat")
	machine, err := s.GetMachine(owner.nodeID)
	if err != nil || machine == nil || machine.Status != "offline" || machine.LastSeen != "" {
		t.Fatalf("confirmed-but-disconnected Node appears online: machine=%#v err=%v", machine, err)
	}
	if err := s.RecordBoundNodeMachineHeartbeat(owner.digest, "", nil); err != nil {
		t.Fatal(err)
	}
	machine, err = s.GetMachine(owner.nodeID)
	if err != nil || machine == nil || machine.Status != "offline" || machine.LastSeen == "" {
		t.Fatalf("transport heartbeat changed worker status or missed liveness: machine=%#v err=%v", machine, err)
	}
	if err := s.RecordBoundNodeMachineHeartbeat(owner.digest, "busy", nil); err != nil {
		t.Fatal(err)
	}
	machine, err = s.GetMachine(owner.nodeID)
	if err != nil || machine == nil || machine.Status != "busy" {
		t.Fatalf("explicit Node status was not applied: machine=%#v err=%v", machine, err)
	}
	if _, err := s.db.Exec(`UPDATE machines SET owner_id='' WHERE id=?`, owner.nodeID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBoundNodeMachineHeartbeat(owner.digest, "available", nil); !errors.Is(err, ErrNodeMachineOwnershipConflict) {
		t.Fatalf("Node heartbeat took over an ownerless machine: %v", err)
	}
}

func stringPtrForStore(value string) *string { return &value }
