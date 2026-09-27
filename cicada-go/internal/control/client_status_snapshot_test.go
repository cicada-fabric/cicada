package control

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func newClientStatusControl(t *testing.T, staleAfter time.Duration) *Control {
	t.Helper()
	root := t.TempDir()
	controlPlane, err := New(Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
		MachineStaleAfter: staleAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controlPlane.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown Control: %v", err)
		}
	})
	return controlPlane
}

func createSnapshotMember(t *testing.T, c *Control, groupID, principalID string) *store.Principal {
	t.Helper()
	ownerID := c.Identity().ID
	principal, err := c.store.CreatePrincipal(store.Principal{
		ID: principalID, Kind: store.PrincipalKindAgent, OwnerID: ownerID,
		TrustDomainID: ownerID, Name: principalID, Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateMembership(store.Membership{
		PrincipalID: principal.ID, GroupID: groupID, Role: "member",
		Status: store.MembershipStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	return principal
}

func TestBuildClientStatusSnapshotUsesOwnerScopedTypedState(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "owned-group"})
	if err != nil {
		t.Fatal(err)
	}
	secondGroup, err := c.CreateGroup(GroupCreateInput{Name: "owned-child"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetGroupParent(secondGroup.ID, group.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	member := createSnapshotMember(t, c, group.ID, "snapshot-agent")
	if _, err := c.store.CreateMembership(store.Membership{
		PrincipalID: member.ID, GroupID: secondGroup.ID, Role: "member",
		Status: store.MembershipStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := c.RegisterMachine("snapshot-node", "snapshot-node", map[string]any{
		"public_capability": "codex", "must_not_escape": "machine-capability-secret",
	}, "available"); err != nil {
		t.Fatal(err)
	}
	endpoint, err := c.store.UpsertEndpoint(store.Endpoint{
		ID: "snapshot-endpoint", Name: "session", Harness: "codex", NativeSessionID: "native-session-1",
		MachineID: "snapshot-node", Status: "online", Capabilities: map[string]any{"opaque": "endpoint-capability-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.store.CreateSessionBinding(store.SessionBinding{
		ID: "snapshot-binding", EndpointID: endpoint.ID, PrincipalID: member.ID,
		GroupID: group.ID, NativeSessionID: endpoint.NativeSessionID, NodeID: endpoint.MachineID,
		Status: store.SessionBindingStatusActive, CredentialHash: "binding-credential-hash-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.JoinEndpointGroup(endpoint.ID, secondGroup.ID); err != nil {
		t.Fatal(err)
	}
	if binding.ID == "" {
		t.Fatal("test setup did not create a session binding")
	}

	goal, err := c.store.CreateGoal("snapshot-goal", "goal objective secret", "criteria", "", 1, "snapshot-node", "", "/work")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := c.store.CreateWorkerAtHarness("snapshot-worker", goal.ID, "snapshot-node", "codex", filepath.Join(t.TempDir(), "response.txt"), "/work")
	if err != nil {
		t.Fatal(err)
	}
	prompt := "worker-prompt-secret"
	summary := "worker-summary-secret"
	if _, err := c.store.UpdateWorker(worker.ID, store.WorkerUpdate{Prompt: &prompt, Summary: &summary}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateSharedTask(group.ID, store.SharedTask{
		Objective: "task-objective-secret", AcceptanceCriteria: "task-criteria-secret",
	}); err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := c.store.CreatePrincipal(store.Principal{
		ID: "foreign-owner", Kind: store.PrincipalKindHuman, OwnerID: "foreign-owner",
		Name: "foreign-owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignGroup, err := c.store.CreateGroup(store.Group{
		ID: "foreign-group", OwnerPrincipalID: foreignOwner.ID, Name: "foreign", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateSharedTask(store.SharedTask{
		ID: "foreign-task", GroupID: foreignGroup.ID, Objective: "foreign task", AcceptanceCriteria: "criteria",
	}); err != nil {
		t.Fatal(err)
	}

	snapshot, err := c.BuildClientStatusSnapshot(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ContractVersion != ClientStatusSnapshotContractVersion || snapshot.ScopeMode != ClientStatusSnapshotScopeSingleOwner || snapshot.ReadConsistency != "best_effort" {
		t.Fatalf("unexpected snapshot contract/scope: %#v", snapshot)
	}
	if len(snapshot.Groups) != 2 || len(snapshot.Tasks) != 1 || snapshot.Tasks[0].GroupID != group.ID {
		t.Fatalf("snapshot crossed owner Group scope: groups=%#v tasks=%#v", snapshot.Groups, snapshot.Tasks)
	}
	if len(snapshot.Endpoints) != 1 || snapshot.Endpoints[0].EndpointID != endpoint.ID || len(snapshot.Endpoints[0].GroupIDs) != 2 {
		t.Fatalf("endpoint Group membership missing or duplicated: %#v", snapshot.Endpoints)
	}
	if got := snapshot.Endpoints[0].NativeSession.State; got != ClientNativeSessionKnown || !snapshot.Endpoints[0].NativeSession.Known || !snapshot.Endpoints[0].NativeSession.Stale {
		t.Fatalf("native session identity or unverified binding status was not projected honestly: %#v", snapshot.Endpoints[0].NativeSession)
	}
	if len(snapshot.Goals) != 1 || snapshot.Goals[0].Lifecycle.State != ClientGoalQueued || !snapshot.Goals[0].Lifecycle.Known {
		t.Fatalf("Goal status was not read from the backend: %#v", snapshot.Goals)
	}
	if len(snapshot.Workers) != 1 || snapshot.Workers[0].Execution.State != ClientWorkerQueued || !snapshot.Workers[0].Execution.Known {
		t.Fatalf("Worker status was not read from the backend: %#v", snapshot.Workers)
	}
	var remoteNode *ClientNodeStatus
	for index := range snapshot.Nodes {
		if snapshot.Nodes[index].NodeID == "snapshot-node" {
			remoteNode = &snapshot.Nodes[index]
		}
	}
	if remoteNode == nil || remoteNode.Connectivity.State != ClientNodeConnected || remoteNode.Connectivity.Source != "store.machines.status+last_seen" {
		t.Fatalf("Node heartbeat status was not projected: %#v", remoteNode)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"machine-capability-secret", "endpoint-capability-secret", "binding-credential-hash-secret",
		"goal objective secret", "worker-prompt-secret", "worker-summary-secret",
		"task-objective-secret", "task-criteria-secret", "foreign-task",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("snapshot exposed omitted content %q: %s", forbidden, encoded)
		}
	}
}

func TestClientStatusSnapshotValidatesSingleOwnerPrincipal(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	ownerID := c.Identity().ID
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		t.Fatalf("fresh Hub did not bootstrap its local owner Principal: %v", err)
	}
	if _, err := c.CreateGroup(GroupCreateInput{Name: "owner-group"}); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateClientOwnerScope("another-owner"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("a different authenticated owner was accepted: %v", err)
	}
	if _, err := c.store.RevokePrincipal(ownerID, "test revoke"); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateClientOwnerScope(ownerID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked owner Principal was accepted: %v", err)
	}
	if _, err := c.BuildClientStatusSnapshot(ownerID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("snapshot was built for revoked owner: %v", err)
	}
}

func TestControlRestartDoesNotReactivateRevokedClientOwner(t *testing.T) {
	root := t.TempDir()
	config := Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")}
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := c.Identity().ID
	if _, err := c.store.RevokePrincipal(ownerID, "owner revoked"); err != nil {
		t.Fatal(err)
	}
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted, err := New(config); err == nil {
		restarted.Shutdown(context.Background())
		t.Fatal("restart silently reactivated a revoked owner Principal")
	}
}

func TestClientStatusMappingsKeepOfflineAndUnknownDistinct(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-time.Hour).Format(time.RFC3339Nano)

	staleNode := clientNodeConnectivity(store.Machine{ID: "node", Status: "available", LastSeen: old}, now, time.Minute)
	if staleNode.State != ClientNodeStale || !staleNode.Known || !staleNode.Stale {
		t.Fatalf("old heartbeat should be stale: %#v", staleNode)
	}
	offlineNode := clientNodeConnectivity(store.Machine{ID: "node", Status: "offline", LastSeen: old}, now, time.Minute)
	if offlineNode.State != ClientNodeOffline || !offlineNode.Known || !offlineNode.Stale {
		t.Fatalf("explicit offline should remain distinct while its timestamp is stale: %#v", offlineNode)
	}
	unknownNode := clientNodeConnectivity(store.Machine{ID: "node", Status: "connected-ish", LastSeen: now.Format(time.RFC3339Nano)}, now, time.Minute)
	if unknownNode.State != ClientNodeUnknown || unknownNode.Known {
		t.Fatalf("unrecognized backend Node status was guessed: %#v", unknownNode)
	}
	missingEndpoint := clientEndpointPresence("online", "", now, time.Minute)
	if missingEndpoint.State != ClientEndpointOnline || !missingEndpoint.Known || !missingEndpoint.Stale {
		t.Fatalf("known endpoint state with missing heartbeat was not marked stale: %#v", missingEndpoint)
	}
	unknownWorker := clientWorkerExecution("suspended", now.Format(time.RFC3339Nano))
	if unknownWorker.State != ClientWorkerUnknown || unknownWorker.Known {
		t.Fatalf("unrecognized Worker status was guessed: %#v", unknownWorker)
	}
	unknownGoal := clientGoalLifecycle("paused", now.Format(time.RFC3339Nano))
	if unknownGoal.State != ClientGoalUnknown || unknownGoal.Known {
		t.Fatalf("unsupported Goal pause state was represented as real: %#v", unknownGoal)
	}
	knownGroupPause := clientGroupLifecycle(store.GroupStatePaused, now.Format(time.RFC3339Nano))
	if knownGroupPause.State != ClientGroupPaused || !knownGroupPause.Known {
		t.Fatalf("persisted Group pause state was lost: %#v", knownGroupPause)
	}
	lostBinding := clientNativeSession(store.Endpoint{
		NativeSessionID: "known-native-session", MigrationState: store.EndpointMigrationReady,
		UpdatedAt: now.Format(time.RFC3339Nano),
	})
	if lostBinding.State != ClientNativeSessionBindingLost || !lostBinding.Known || !lostBinding.Stale {
		t.Fatalf("missing binding was not reported as lost: %#v", lostBinding)
	}
}

func TestClientStatusSnapshotDoesNotTurnOfflineNodeIntoCompletedWork(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	group, err := c.CreateGroup(GroupCreateInput{Name: "offline-group"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterMachine("offline-node", "offline-node", nil, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := c.store.CreateGoal("offline-goal", "objective", "criteria", "", 1, "offline-node", "", "/work")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.UpdateGoal(goal.ID, "running", ""); err != nil {
		t.Fatal(err)
	}
	worker, err := c.store.CreateWorkerAtHarness("offline-worker", goal.ID, "offline-node", "codex", filepath.Join(t.TempDir(), "response.txt"), "/work")
	if err != nil {
		t.Fatal(err)
	}
	running := "running"
	if _, err := c.store.UpdateWorker(worker.ID, store.WorkerUpdate{Status: &running}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.SetMachineStatus("offline-node", "offline"); err != nil {
		t.Fatal(err)
	}

	snapshot, err := c.BuildClientStatusSnapshot(c.Identity().ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Goals[0].Lifecycle.State != ClientGoalRunning || !snapshot.Goals[0].Lifecycle.Stale {
		t.Fatalf("Node status changed Goal lifecycle or failed to mark stale: %#v", snapshot.Goals[0])
	}
	if snapshot.Workers[0].Execution.State != ClientWorkerRunning || !snapshot.Workers[0].Execution.Stale {
		t.Fatalf("Node status changed Worker execution or failed to mark stale: %#v", snapshot.Workers[0])
	}
	if len(snapshot.Groups) != 1 || snapshot.Groups[0].GroupID != group.ID {
		t.Fatalf("unexpected owner Group scope: %#v", snapshot.Groups)
	}
}

func TestBuildClientStatusSnapshotMarksUnknownNodeStatusUnknown(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	if _, err := c.CreateGroup(GroupCreateInput{Name: "missing-node-group"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.UpsertMachine("unknown-node", "unknown-node", nil, "unexpected"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.BuildClientStatusSnapshot(c.Identity().ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range snapshot.Nodes {
		if node.NodeID == "unknown-node" {
			if node.Connectivity.State != ClientNodeUnknown || node.Connectivity.Known || !node.Connectivity.Stale {
				t.Fatalf("unrecognized Node status was guessed: %#v", node)
			}
			return
		}
	}
	t.Fatal("missing referenced Node was silently omitted from snapshot")
}

func TestBuildClientStatusSnapshotToleratesConcurrentStateUpdates(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	if _, err := c.CreateGroup(GroupCreateInput{Name: "concurrent-group"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterMachine("concurrent-node", "concurrent-node", nil, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := c.store.CreateGoal("concurrent-goal", "objective", "criteria", "", 1, "concurrent-node", "", "/work")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := c.store.CreateWorkerAtHarness("concurrent-worker", goal.ID, "concurrent-node", "codex", filepath.Join(t.TempDir(), "response.txt"), "/work")
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		<-start
		for index := 0; index < 80; index++ {
			status := "running"
			if index%2 == 0 {
				status = "queued"
			}
			_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{Status: &status})
			nodeStatus := "available"
			if index%2 == 0 {
				nodeStatus = "offline"
			}
			_ = c.store.SetMachineStatus("concurrent-node", nodeStatus)
		}
	}()
	close(start)
	for index := 0; index < 30; index++ {
		snapshot, err := c.BuildClientStatusSnapshot(c.Identity().ID)
		if err != nil {
			t.Fatalf("snapshot %d failed during concurrent updates: %v", index, err)
		}
		if snapshot.ReadConsistency != "best_effort" || len(snapshot.Goals) != 1 || len(snapshot.Workers) != 1 {
			t.Fatalf("snapshot %d lost stable records during concurrent updates: %#v", index, snapshot)
		}
		state := snapshot.Workers[0].Execution.State
		if state != ClientWorkerQueued && state != ClientWorkerRunning {
			t.Fatalf("snapshot %d invented a Worker state: %#v", index, snapshot.Workers[0])
		}
	}
	writers.Wait()
}
