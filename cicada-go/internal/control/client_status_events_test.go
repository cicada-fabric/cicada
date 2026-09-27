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
	if !strings.Contains(strings.Join(first.ExcludedChangeSources, ","), "approvals") || !strings.Contains(strings.Join(first.ExcludedChangeSources, ","), "control_intents") {
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
