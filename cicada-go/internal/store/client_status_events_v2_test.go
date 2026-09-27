package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func openClientStatusEventsTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.initializeClientStatusEventsV2Schema(); err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close Client status Store: %v", err)
		}
	})
	return s
}

func TestClientStatusObservationFeedIsDurableOwnerFilteredAndSnapshotBased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.sqlite3")
	s := openClientStatusEventsTestStore(t, path)
	firstAt := "2026-09-23T10:00:00.000000001Z"
	connected := json.RawMessage(`{"connectivity":{"state":"connected","known":true,"stale":false}}`)
	if err := s.RecordClientStatusObservations("owner-a", firstAt, []string{"node"}, []ClientStatusObservation{{
		EntityType: "node", EntityID: "node-a", StateJSON: connected,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordClientStatusObservations("owner-b", firstAt, []string{"node"}, []ClientStatusObservation{{
		EntityType: "node", EntityID: "node-b", StateJSON: connected,
	}}); err != nil {
		t.Fatal(err)
	}
	if latest, err := s.LatestClientStatusChangeID("owner-a"); err != nil || latest != 1 {
		t.Fatalf("owner-a sequence=%d err=%v", latest, err)
	}
	if latest, err := s.LatestClientStatusChangeID("owner-b"); err != nil || latest != 1 {
		t.Fatalf("owner-b sequence leaked global event IDs: %d err=%v", latest, err)
	}

	unchangedAt := "2026-09-23T10:00:01.000000000Z"
	if err := s.RecordClientStatusObservations("owner-a", unchangedAt, []string{"node"}, []ClientStatusObservation{{
		EntityType: "node", EntityID: "node-a", StateJSON: connected,
	}}); err != nil {
		t.Fatal(err)
	}
	if latest, err := s.LatestClientStatusChangeID("owner-a"); err != nil || latest != 1 {
		t.Fatalf("unchanged snapshot generated a change: latest=%d err=%v", latest, err)
	}

	stale := json.RawMessage(`{"connectivity":{"state":"stale","known":true,"stale":true}}`)
	changedAt := "2026-09-23T10:00:02.000000000Z"
	if err := s.RecordClientStatusObservations("owner-a", changedAt, []string{"node"}, []ClientStatusObservation{{
		EntityType: "node", EntityID: "node-a", StateJSON: stale,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordClientStatusObservations("owner-a", "2026-09-23T10:00:01.500000000Z", []string{"node"}, []ClientStatusObservation{{
		EntityType: "node", EntityID: "node-a", StateJSON: connected,
	}}); err != nil {
		t.Fatal(err)
	}
	if latest, err := s.LatestClientStatusChangeID("owner-a"); err != nil || latest != 2 {
		t.Fatalf("stale snapshot reverted newer status: latest=%d err=%v", latest, err)
	}
	changes, err := s.ListClientStatusChanges("owner-a", 0, 10)
	if err != nil || len(changes) != 2 || changes[0].ID != 1 || changes[1].ID != 2 || string(changes[1].StateJSON) != string(stale) {
		t.Fatalf("owner filtered status changes=%#v err=%v", changes, err)
	}
	if foreign, err := s.ListClientStatusChanges("owner-b", 0, 10); err != nil || len(foreign) != 1 || foreign[0].EntityID != "node-b" {
		t.Fatalf("other owner's stream leaked: %#v err=%v", foreign, err)
	}

	removedAt := "2026-09-23T10:00:03.000000000Z"
	if err := s.RecordClientStatusObservations("owner-a", removedAt, []string{"node"}, nil); err != nil {
		t.Fatal(err)
	}
	removed, err := s.ListClientStatusChanges("owner-a", 2, 10)
	if err != nil || len(removed) != 1 || removed[0].ChangeType != ClientStatusChangeRemoved || string(removed[0].StateJSON) != `{}` {
		t.Fatalf("removed entity event=%#v err=%v", removed, err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.initializeClientStatusEventsV2Schema(); err != nil {
		t.Fatal(err)
	}
	if latest, err := reopened.LatestClientStatusChangeID("owner-a"); err != nil || latest != 3 {
		t.Fatalf("restart lost owner cursor: latest=%d err=%v", latest, err)
	}
	resumed, err := reopened.ListClientStatusChanges("owner-a", 2, 10)
	if err != nil || len(resumed) != 1 || resumed[0].ID != 3 || resumed[0].ChangeType != ClientStatusChangeRemoved {
		t.Fatalf("restart did not resume exact delta cursor: %#v err=%v", resumed, err)
	}
}

func TestClientStatusObservationFeedRejectsInvalidScopeAndBounds(t *testing.T) {
	s := openClientStatusEventsTestStore(t, filepath.Join(t.TempDir(), "status.sqlite3"))
	valid := ClientStatusObservation{EntityType: "node", EntityID: "node", StateJSON: json.RawMessage(`{"state":"connected"}`)}
	if err := s.RecordClientStatusObservations("", "2026-09-23T10:00:00Z", []string{"node"}, []ClientStatusObservation{valid}); !errors.Is(err, ErrClientStatusOwnerRequired) {
		t.Fatalf("empty owner error=%v", err)
	}
	if err := s.RecordClientStatusObservations("owner", "not-a-time", []string{"node"}, []ClientStatusObservation{valid}); err == nil {
		t.Fatal("invalid observation time was accepted")
	}
	if err := s.RecordClientStatusObservations("owner", "2026-09-23T10:00:00Z", []string{"approval"}, nil); err == nil {
		t.Fatal("unsupported entity type was accepted")
	}
	if err := s.RecordClientStatusObservations("owner", "2026-09-23T10:00:00Z", []string{"node"}, []ClientStatusObservation{{
		EntityType: "node", EntityID: "node", StateJSON: json.RawMessage(`not-json`),
	}}); err == nil {
		t.Fatal("invalid state JSON was accepted")
	}
	if err := s.RecordClientStatusObservations("owner", "2026-09-23T10:00:00Z", []string{"node"}, []ClientStatusObservation{valid, valid}); err == nil {
		t.Fatal("duplicate entity observation was accepted")
	}
	if _, err := s.ListClientStatusChanges("owner", 0, 0); err == nil {
		t.Fatal("unbounded list size was accepted")
	}
	if _, err := s.ListClientStatusChanges("", 0, 10); !errors.Is(err, ErrClientStatusOwnerRequired) {
		t.Fatalf("empty owner list error=%v", err)
	}
}
