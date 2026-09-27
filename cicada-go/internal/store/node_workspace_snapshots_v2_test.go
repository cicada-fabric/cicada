package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type nodeWorkspaceSnapshotFixture struct {
	store          *Store
	credentialHash string
	nodeID         string
	goalID         string
	workerID       string
	workspaceID    string
}

func newNodeWorkspaceSnapshotFixture(t *testing.T) nodeWorkspaceSnapshotFixture {
	t.Helper()
	s, _, _, device := newClientDeviceFixture(t)
	credentialHash := nodeBindingTestCredentialDigest(t.Name() + " node token")
	codeDigest := nodeBindingTestCodeDigest(t.Name() + " node code")
	const nodeID = "snapshot-node"
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, "snapshot node", credentialHash,
		codeDigest, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	const goalID, workerID, workspaceID = "snapshot-goal", "snapshot-worker", "snapshot-workspace"
	const workspacePath = "/workspace/snapshot-goal"
	if _, err := s.CreateGoal(goalID, "run task", "finish", "", 50, nodeID, "", workspacePath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE goals SET owner_id='owner_a' WHERE id=?`, goalID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWorkspace(workspaceID, goalID, workspacePath, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWorkerAtHarness(workerID, goalID, nodeID, "codex", filepath.Join(workspacePath, ".last-message"), workspacePath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE workers SET status='running', attempt=1 WHERE id=?`, workerID); err != nil {
		t.Fatal(err)
	}
	return nodeWorkspaceSnapshotFixture{
		store: s, credentialHash: credentialHash, nodeID: nodeID,
		goalID: goalID, workerID: workerID, workspaceID: workspaceID,
	}
}

func addSnapshotTestOwner(t *testing.T, s *Store, ownerID string) string {
	t.Helper()
	if _, err := s.CreatePrincipal(Principal{
		ID: ownerID, Kind: PrincipalKindHuman, OwnerID: ownerID,
		Name: ownerID, Status: PrincipalStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	registeredKey, err := s.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "device-" + ownerID
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: registeredKey.KeyID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	return deviceID
}

func TestBoundNodeWorkspaceSnapshotRequiresExactOwnerWorkerAttemptAndWorkspace(t *testing.T) {
	f := newNodeWorkspaceSnapshotFixture(t)
	otherHash := nodeBindingTestCredentialDigest("wrong node token")
	if _, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(otherHash, f.nodeID, f.workerID, 1, f.workspaceID); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("wrong token authorized snapshot: %v", err)
	}
	if _, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(f.credentialHash, f.nodeID, f.workerID, 1, "different-workspace"); !errors.Is(err, ErrNodeWorkerUnavailable) {
		t.Fatalf("wrong Workspace authorized snapshot: %v", err)
	}
	if _, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(f.credentialHash, f.nodeID, f.workerID, 2, f.workspaceID); !errors.Is(err, ErrNodeWorkerUnavailable) {
		t.Fatalf("stale attempt authorized snapshot: %v", err)
	}

	otherDeviceID := addSnapshotTestOwner(t, f.store, "owner_b")
	differentOwnerHash := nodeBindingTestCredentialDigest("other owner's node token")
	codeDigest := nodeBindingTestCodeDigest("other owner's pairing code")
	if _, err := f.store.CreatePendingNodeDeviceBinding("other-owner-node", "other owner node", differentOwnerHash,
		codeDigest, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ConfirmPendingNodeDeviceBinding("owner_b", otherDeviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(differentOwnerHash, "other-owner-node", f.workerID, 1, f.workspaceID); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("different active owner authorized the Goal Workspace: %v", err)
	}
}

func TestBoundNodeWorkspaceSnapshotAttachRechecksRevocationAndAttemptAtomically(t *testing.T) {
	f := newNodeWorkspaceSnapshotFixture(t)
	digest := nodeBindingTestCodeDigest("synthetic archive digest")
	if _, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(f.credentialHash, f.nodeID, f.workerID, 1, f.workspaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED' WHERE node_id=?`, f.nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AttachBoundNodeWorkerWorkspaceSnapshot(f.credentialHash, f.nodeID, f.workerID, 1, f.workspaceID, "", digest); !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("revoked Node attached a snapshot after preflight: %v", err)
	}
	workspace, err := f.store.GetWorkspace(f.workspaceID)
	if err != nil || workspace == nil || workspace.SnapshotDigest != "" {
		t.Fatalf("revoked upload published snapshot pointer: %#v err=%v", workspace, err)
	}
}

func TestBoundNodeWorkspaceSnapshotConcurrentRevocationCannotAttach(t *testing.T) {
	f := newNodeWorkspaceSnapshotFixture(t)
	digest := nodeBindingTestCodeDigest("concurrent archive digest")
	if _, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(f.credentialHash, f.nodeID, f.workerID, 1, f.workspaceID); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	start := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(ready)
		<-start
		_, err := f.store.AttachBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
			f.nodeID, f.workerID, 1, f.workspaceID, "", digest)
		result <- err
	}()
	<-ready
	if _, err := f.store.db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED' WHERE node_id=?`, f.nodeID); err != nil {
		t.Fatal(err)
	}
	close(start)
	err := <-result
	if !errors.Is(err, ErrNodeWorkerNotAuthorized) {
		t.Fatalf("concurrent revoke did not fence attachment: %v", err)
	}
	workspace, err := f.store.GetWorkspace(f.workspaceID)
	if err != nil || workspace == nil || workspace.SnapshotDigest != "" {
		t.Fatalf("concurrent revoked upload published snapshot pointer: %#v err=%v", workspace, err)
	}
}

func TestBoundNodeWorkspaceSnapshotGetRequiresCurrentDigest(t *testing.T) {
	f := newNodeWorkspaceSnapshotFixture(t)
	digest := nodeBindingTestCodeDigest("valid archive digest")
	if _, err := f.store.AttachBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, "", digest); err != nil {
		t.Fatal(err)
	}
	workspace, err := f.store.GetBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, digest)
	if err != nil || workspace.SnapshotDigest != digest {
		t.Fatalf("current Workspace snapshot was not returned: %#v err=%v", workspace, err)
	}
	if _, err := f.store.GetBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, fmt.Sprintf("%064x", 7)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-current digest was returned: %v", err)
	}
	if _, err := f.store.db.Exec(`UPDATE workers SET attempt=2, status='queued' WHERE id=?`, f.workerID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, digest); !errors.Is(err, ErrNodeWorkerUnavailable) {
		t.Fatalf("stale attempt downloaded a snapshot: %v", err)
	}
}

func TestBoundNodeWorkspaceSnapshotAttachmentCASAllowsRetryButRejectsDivergentUpload(t *testing.T) {
	f := newNodeWorkspaceSnapshotFixture(t)
	firstDigest := nodeBindingTestCodeDigest("first archive bytes")
	secondDigest := nodeBindingTestCodeDigest("different concurrent archive")
	previousDigest, err := f.store.CheckBoundNodeWorkerWorkspaceSnapshot(
		f.credentialHash, f.nodeID, f.workerID, 1, f.workspaceID)
	if err != nil || previousDigest != "" {
		t.Fatalf("unexpected baseline snapshot pointer: %q err=%v", previousDigest, err)
	}
	if _, err := f.store.AttachBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, previousDigest, firstDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AttachBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, previousDigest, secondDigest); !errors.Is(err, ErrNodeWorkerUnavailable) {
		t.Fatalf("concurrent divergent archive replaced the first snapshot: %v", err)
	}
	if _, err := f.store.AttachBoundNodeWorkerWorkspaceSnapshot(f.credentialHash,
		f.nodeID, f.workerID, 1, f.workspaceID, previousDigest, firstDigest); err != nil {
		t.Fatalf("same-digest retry was not idempotent: %v", err)
	}
	workspace, err := f.store.GetWorkspace(f.workspaceID)
	if err != nil || workspace == nil || workspace.SnapshotDigest != firstDigest {
		t.Fatalf("snapshot CAS did not retain the first digest: %#v err=%v", workspace, err)
	}
}
