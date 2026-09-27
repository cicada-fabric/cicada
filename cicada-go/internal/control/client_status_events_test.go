package control

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func newStatusEventsControl(t *testing.T, stateDir string) *Control {
	t.Helper()
	c, err := New(Config{StateDir: stateDir, WorkspaceRoot: filepath.Join(stateDir, "workspace"), MachineStaleAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown Control: %v", err)
		}
	})
	return c
}

func TestReadClientStatusChangesReturnsStableOwnerBoundSnapshotDeltas(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	c := newStatusEventsControl(t, stateDir)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "initial-name"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.ReadClientStatusChanges(ownerID, "", 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if first.Completeness != "partial" || first.Coverage != ClientStatusChangesCoverage || first.Limit != clientStatusChangesMaxLimit {
		t.Fatalf("feed completeness/limit contract=%#v", first)
	}
	if len(first.Events) == 0 || first.Cursor == "" {
		t.Fatalf("first observation did not create a durable baseline: %#v", first)
	}
	excluded := strings.Join(first.ExcludedChangeSources, ",")
	if strings.Contains(excluded, "approvals") || strings.Contains(excluded, "control_intents") ||
		!strings.Contains(excluded, "topology_memberships_and_links") || !strings.Contains(excluded, "transitions_between_snapshot_reads") {
		t.Fatalf("partial feed omissions were not explicit: %#v", first.ExcludedChangeSources)
	}
	foundGroup := false
	for _, event := range first.Events {
		if event.EntityType == "group" && event.EntityID == group.ID {
			foundGroup = true
		}
		state, err := json.Marshal(event.StateJSON)
		if err != nil {
			t.Fatal(err)
		}
		for _, volatile := range []string{"captured_at", "observed_at", "credential_hash", "prompt", "payload"} {
			if strings.Contains(string(state), volatile) {
				t.Fatalf("status event state contained volatile or sensitive field %q: %s", volatile, state)
			}
		}
	}
	if !foundGroup {
		t.Fatalf("baseline omitted real Group %q: %#v", group.ID, first.Events)
	}
	unchanged, err := c.ReadClientStatusChanges(ownerID, first.Cursor, 100)
	if err != nil || len(unchanged.Events) != 0 || unchanged.Cursor != first.Cursor {
		t.Fatalf("stable observation repeated deltas: page=%#v err=%v", unchanged, err)
	}

	group.Name = "updated-name"
	if _, err := c.store.UpsertGroup(*group); err != nil {
		t.Fatal(err)
	}
	updated, err := c.ReadClientStatusChanges(ownerID, first.Cursor, 100)
	if err != nil || len(updated.Events) != 1 || updated.Events[0].ChangeType != store.ClientStatusChangeUpdated ||
		updated.Events[0].EntityType != "group" || updated.Events[0].EntityID != group.ID {
		t.Fatalf("Group update delta=%#v err=%v", updated, err)
	}
	if !strings.Contains(string(updated.Events[0].StateJSON), "updated-name") {
		t.Fatalf("Group metadata update missing from event: %s", updated.Events[0].StateJSON)
	}
	if _, err := c.ReadClientStatusChanges(ownerID, encodeClientStatusCursor("another-owner", 1), 100); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-owner cursor was accepted: %v", err)
	}
	latest, err := c.store.LatestClientStatusChangeID(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadClientStatusChanges(ownerID, encodeClientStatusCursor(ownerID, latest+1), 100); !errors.Is(err, store.ErrClientStatusCursorRange) {
		t.Fatalf("future cursor was accepted: %v", err)
	}
}

func TestClientManagementStatusObservationsAreOwnerScopedAndMetadataOnly(t *testing.T) {
	c := newStatusEventsControl(t, filepath.Join(t.TempDir(), "state"))
	ownerID := c.Identity().ID
	otherOwnerID := "another-owner"

	ownedGoal, err := c.store.CreateOwnedGoal(ownerID, store.Goal{
		ID: "owned-approval-goal", Objective: "safe approval state", SuccessCriteria: "done", Priority: 1, MachineID: "control-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	ownedWorker, err := c.store.CreateWorker("owned-approval-worker", ownedGoal.ID, "control-local", filepath.Join(t.TempDir(), "owned-result"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateApproval("owned-approval", ownedGoal.ID, ownedWorker.ID, "review", map[string]string{"private_request": "approval-secret-body"}); err != nil {
		t.Fatal(err)
	}

	otherGoal, err := c.store.CreateOwnedGoal(otherOwnerID, store.Goal{
		ID: "other-approval-goal", Objective: "other goal", SuccessCriteria: "done", Priority: 1, MachineID: "control-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	otherWorker, err := c.store.CreateWorker("other-approval-worker", otherGoal.ID, "control-local", filepath.Join(t.TempDir(), "other-result"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateApproval("other-approval", otherGoal.ID, otherWorker.ID, "review", map[string]string{"private_request": "other-approval-secret"}); err != nil {
		t.Fatal(err)
	}
	legacyGoal, err := c.store.CreateGoal("legacy-approval-goal", "legacy", "done", "", 1, "control-local", "", "")
	if err != nil {
		t.Fatal(err)
	}
	legacyWorker, err := c.store.CreateWorker("legacy-approval-worker", legacyGoal.ID, "control-local", filepath.Join(t.TempDir(), "legacy-result"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateApproval("legacy-approval", legacyGoal.ID, legacyWorker.ID, "review", map[string]string{"private_request": "legacy-approval-secret"}); err != nil {
		t.Fatal(err)
	}

	ownedIntent, err := c.AcceptClientIntentForOwner(ownerID, "owned-client-request", IntentInput{Text: "owned-intent-secret-body", Kind: "idea"})
	if err != nil {
		t.Fatal(err)
	}
	otherInput := []byte(`{"text":"other-intent-secret-body","kind":"idea"}`)
	if _, _, err := c.store.AcceptClientIntentForOwner(otherOwnerID, "other-client-request", "other-intent-secret-body", "idea", "", nil, otherInput); err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateIntent("legacy-intent-secret-body", "idea", "", nil); err != nil {
		t.Fatal(err)
	}

	observations, err := c.clientManagementStatusObservations(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	foundApproval, foundIntent := false, false
	for _, observation := range observations {
		switch observation.EntityType {
		case "approval":
			if observation.EntityID != "owned-approval" {
				t.Fatalf("foreign or ownerless approval was projected: %#v", observation)
			}
			foundApproval = true
		case "intent":
			if observation.EntityID != ownedIntent.ID {
				t.Fatalf("foreign or ownerless Intent was projected: %#v", observation)
			}
			foundIntent = true
		default:
			t.Fatalf("unexpected management entity type %q", observation.EntityType)
		}
		for _, secret := range []string{"approval-secret-body", "other-approval-secret", "legacy-approval-secret", "owned-intent-secret-body", "other-intent-secret-body", "legacy-intent-secret-body", "private_request", "text", "result", "error"} {
			if strings.Contains(string(observation.StateJSON), secret) {
				t.Fatalf("status state leaked private input field %q: %s", secret, observation.StateJSON)
			}
		}
	}
	if !foundApproval || !foundIntent || len(observations) != 2 {
		t.Fatalf("owner-scoped Approval/Intent observations missing: %#v", observations)
	}
}

func TestReadClientStatusChangesTracksApprovalAndIntentLifecycleOnly(t *testing.T) {
	c := newStatusEventsControl(t, filepath.Join(t.TempDir(), "state"))
	ownerID := c.Identity().ID
	goal, err := c.store.CreateOwnedGoal(ownerID, store.Goal{
		ID: "status-goal", Objective: "status goal", SuccessCriteria: "done", Priority: 1, MachineID: "control-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := c.store.CreateWorker("status-worker", goal.ID, "control-local", filepath.Join(t.TempDir(), "status-result"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateApproval("status-approval", goal.ID, worker.ID, "review", map[string]string{"private_request": "do-not-emit"}); err != nil {
		t.Fatal(err)
	}
	intent, err := c.AcceptClientIntentForOwner(ownerID, "status-client-request", IntentInput{Text: "do-not-emit-intent-body", Kind: "idea"})
	if err != nil {
		t.Fatal(err)
	}

	initial, err := c.ReadClientStatusChanges(ownerID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	approvalInitial, intentInitial, goalInitial := false, false, false
	for _, event := range initial.Events {
		switch event.EntityType {
		case "approval":
			approvalInitial = event.EntityID == "status-approval" && strings.Contains(string(event.StateJSON), `"pending"`)
		case "intent":
			intentInitial = event.EntityID == intent.ID && strings.Contains(string(event.StateJSON), `"QUEUED"`)
		case "goal":
			if event.EntityID == goal.ID {
				var state map[string]any
				if err := json.Unmarshal(event.StateJSON, &state); err != nil {
					t.Fatal(err)
				}
				_, goalInitial = state["lifecycle_version"]
			}
		}
		for _, secret := range []string{"do-not-emit", "private_request", "request"} {
			if strings.Contains(string(event.StateJSON), secret) {
				t.Fatalf("status event exposed private management input %q: %s", secret, event.StateJSON)
			}
		}
	}
	if !approvalInitial || !intentInitial || !goalInitial {
		t.Fatalf("first status page missed safe lifecycle baseline: approval=%v intent=%v goal_version=%v events=%#v", approvalInitial, intentInitial, goalInitial, initial.Events)
	}

	if _, err := c.store.ResolveApproval("status-approval", "accept"); err != nil {
		t.Fatal(err)
	}
	if err := c.DispatchClientIntentAsync(intent.ID); err != nil {
		t.Fatal(err)
	}
	waitForClientIntent(t, c, intent.ID, store.ClientIntentDone)

	updated, err := c.ReadClientStatusChanges(ownerID, initial.Cursor, 100)
	if err != nil {
		t.Fatal(err)
	}
	approvalUpdated, intentUpdated := false, false
	for _, event := range updated.Events {
		if event.ChangeType != store.ClientStatusChangeUpdated {
			continue
		}
		switch event.EntityType {
		case "approval":
			approvalUpdated = event.EntityID == "status-approval" && strings.Contains(string(event.StateJSON), `"resolved"`) && strings.Contains(string(event.StateJSON), `"accept"`)
		case "intent":
			intentUpdated = event.EntityID == intent.ID && strings.Contains(string(event.StateJSON), `"resolved"`) && strings.Contains(string(event.StateJSON), `"DONE"`)
		}
	}
	if !approvalUpdated || !intentUpdated {
		t.Fatalf("terminal Approval/Intent deltas missing: approval=%v intent=%v events=%#v", approvalUpdated, intentUpdated, updated.Events)
	}
}

func TestReadClientStatusChangesResumesAfterControlRestart(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	c := newStatusEventsControl(t, stateDir)
	ownerID := c.Identity().ID
	group, err := c.CreateGroup(GroupCreateInput{Name: "before-restart"})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.ReadClientStatusChanges(ownerID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	restarted := newStatusEventsControl(t, stateDir)
	if restarted.Identity().ID != ownerID {
		t.Fatalf("Control owner identity changed on restart: %s != %s", restarted.Identity().ID, ownerID)
	}
	resumed, err := restarted.ReadClientStatusChanges(ownerID, initial.Cursor, 100)
	if err != nil || len(resumed.Events) != 0 || resumed.Cursor != initial.Cursor {
		t.Fatalf("unchanged state after restart did not resume cleanly: %#v err=%v", resumed, err)
	}
	group.Name = "after-restart"
	if _, err := restarted.store.UpsertGroup(*group); err != nil {
		t.Fatal(err)
	}
	changes, err := restarted.ReadClientStatusChanges(ownerID, initial.Cursor, 100)
	if err != nil || len(changes.Events) != 1 || changes.Events[0].EntityID != group.ID {
		t.Fatalf("state delta was not recoverable after restart: %#v err=%v", changes, err)
	}
}
