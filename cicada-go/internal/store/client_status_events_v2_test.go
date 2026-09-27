package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
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
	if err := s.RecordClientStatusObservations("owner", "2026-09-23T10:00:00Z", []string{"unknown"}, nil); err == nil {
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

func TestExpandClientStatusEventsEntityTypesPreservesV24RowsAndOwnerCursors(t *testing.T) {
	s := openClientStatusEventsTestStore(t, filepath.Join(t.TempDir(), "status.sqlite3"))
	if _, err := s.db.Exec(`DROP TABLE client_status_state_v2;
DROP TABLE client_status_change_events_v2;
CREATE TABLE client_status_state_v2 (
  owner_principal_id TEXT NOT NULL,
  entity_type TEXT NOT NULL CHECK(entity_type IN ('node','endpoint','worker','goal','group','task')),
  entity_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  present INTEGER NOT NULL CHECK(present IN (0,1)),
  observed_at TEXT NOT NULL,
  PRIMARY KEY(owner_principal_id, entity_type, entity_id)
);
CREATE TABLE client_status_change_events_v2 (
  id INTEGER NOT NULL CHECK(id > 0),
  owner_principal_id TEXT NOT NULL,
  change_type TEXT NOT NULL CHECK(change_type IN ('present','updated','removed')),
  entity_type TEXT NOT NULL CHECK(entity_type IN ('node','endpoint','worker','goal','group','task')),
  entity_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(owner_principal_id,id)
);
INSERT INTO client_status_state_v2 VALUES('owner-a','node','node-a','{"state":"online"}',1,'2026-09-23T10:00:00Z');
INSERT INTO client_status_streams_v2(owner_principal_id,last_sequence) VALUES('owner-a',2),('owner-b',1);
INSERT INTO client_status_change_events_v2 VALUES
 (1,'owner-a','present','node','node-a','{"state":"online"}','2026-09-23T10:00:00Z','2026-09-23T10:00:00Z'),
 (2,'owner-a','updated','node','node-a','{"state":"busy"}','2026-09-23T10:00:01Z','2026-09-23T10:00:01Z'),
 (1,'owner-b','present','task','task-b','{"state":"ready"}','2026-09-23T10:00:00Z','2026-09-23T10:00:00Z');`); err != nil {
		t.Fatal(err)
	}

	// Simulate a failed v25 attempt after the table rebuild. The enclosing
	// migration savepoint restores the old schema and rows so it can retry.
	if _, err := s.db.Exec(`SAVEPOINT v25_rollback_test`); err != nil {
		t.Fatal(err)
	}
	if err := s.expandClientStatusEventsEntityTypes(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ROLLBACK TO SAVEPOINT v25_rollback_test;
RELEASE SAVEPOINT v25_rollback_test;`); err != nil {
		t.Fatal(err)
	}
	var oldSchema string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='client_status_state_v2'`).Scan(&oldSchema); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(oldSchema, "'approval'") || strings.Contains(oldSchema, "'intent'") {
		t.Fatalf("rolled-back v25 attempt left expanded schema: %s", oldSchema)
	}

	if _, err := s.db.Exec(`SAVEPOINT v25_retry_test`); err != nil {
		t.Fatal(err)
	}
	if err := s.expandClientStatusEventsEntityTypes(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`RELEASE SAVEPOINT v25_retry_test`); err != nil {
		t.Fatal(err)
	}
	if err := verifyClientStatusPrimaryKey(s.db, "client_status_state_v2"); err != nil {
		t.Fatal(err)
	}
	if err := verifyClientStatusPrimaryKey(s.db, "client_status_change_events_v2"); err != nil {
		t.Fatal(err)
	}
	if latest, err := s.LatestClientStatusChangeID("owner-a"); err != nil || latest != 2 {
		t.Fatalf("owner-a sequence changed during v25 migration: %d err=%v", latest, err)
	}
	if latest, err := s.LatestClientStatusChangeID("owner-b"); err != nil || latest != 1 {
		t.Fatalf("owner-b sequence changed during v25 migration: %d err=%v", latest, err)
	}
	legacyRows, err := s.ListClientStatusChanges("owner-a", 0, 10)
	if err != nil || len(legacyRows) != 2 || legacyRows[0].ID != 1 || legacyRows[1].ID != 2 || legacyRows[1].EntityID != "node-a" {
		t.Fatalf("v24 owner-a rows/cursor not preserved: %#v err=%v", legacyRows, err)
	}
	foreignRows, err := s.ListClientStatusChanges("owner-b", 0, 10)
	if err != nil || len(foreignRows) != 1 || foreignRows[0].ID != 1 || foreignRows[0].EntityID != "task-b" {
		t.Fatalf("v24 owner-b rows/cursor not preserved: %#v err=%v", foreignRows, err)
	}

	managementAt := "2026-09-23T10:00:02Z"
	if err := s.RecordClientStatusObservations("owner-a", managementAt, []string{"approval", "intent"}, []ClientStatusObservation{
		{EntityType: "approval", EntityID: "approval-a", StateJSON: json.RawMessage(`{"status":"pending"}`)},
		{EntityType: "intent", EntityID: "intent-a", StateJSON: json.RawMessage(`{"status":"resolved"}`)},
	}); err != nil {
		t.Fatalf("expanded status entity types rejected: %v", err)
	}
	updatedRows, err := s.ListClientStatusChanges("owner-a", 2, 10)
	if err != nil || len(updatedRows) != 2 || updatedRows[0].ID != 3 || updatedRows[0].EntityType != "approval" || updatedRows[1].ID != 4 || updatedRows[1].EntityType != "intent" {
		t.Fatalf("owner-local sequence did not continue through management deltas: %#v err=%v", updatedRows, err)
	}
	if foreignRows, err := s.ListClientStatusChanges("owner-b", 0, 10); err != nil || len(foreignRows) != 1 {
		t.Fatalf("management changes leaked into another owner stream: %#v err=%v", foreignRows, err)
	}
}
