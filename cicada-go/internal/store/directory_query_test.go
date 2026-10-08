package store

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestListDirectoryRecordsFieldsFiltersAndOrder(t *testing.T) {
	s := newDirectoryQueryTestStore(t)

	activeOld := putDirectoryQueryTestRecord(t, s, directoryQueryTestRecord("active-old", "active"), "2026-02-01T00:00:00Z")
	inactiveNewest := putDirectoryQueryTestRecord(t, s, directoryQueryTestRecord("inactive-newest", "revoked"), "2026-04-01T00:00:00Z")
	activeNewest := putDirectoryQueryTestRecord(t, s, directoryQueryTestRecord("active-newest", "active"), "2026-03-01T00:00:00Z")

	all, err := s.ListDirectoryRecords(false)
	if err != nil {
		t.Fatal(err)
	}
	wantAll := []DirectoryRecord{inactiveNewest, activeNewest, activeOld}
	if !reflect.DeepEqual(all, wantAll) {
		t.Fatalf("all directory records mismatch:\n got: %#v\nwant: %#v", all, wantAll)
	}

	active, err := s.ListDirectoryRecords(true)
	if err != nil {
		t.Fatal(err)
	}
	wantActive := []DirectoryRecord{activeNewest, activeOld}
	if !reflect.DeepEqual(active, wantActive) {
		t.Fatalf("active directory records mismatch:\n got: %#v\nwant: %#v", active, wantActive)
	}

	byID, err := s.GetDirectoryRecord(activeNewest.ID)
	if err != nil || !reflect.DeepEqual(byID, &activeNewest) {
		t.Fatalf("GetDirectoryRecord by id = %#v, want %#v, err=%v", byID, activeNewest, err)
	}
	byRemoteID, err := s.GetDirectoryRecord(activeNewest.RemoteID)
	if err != nil || !reflect.DeepEqual(byRemoteID, &activeNewest) {
		t.Fatalf("GetDirectoryRecord by remote id = %#v, want %#v, err=%v", byRemoteID, activeNewest, err)
	}
	byTrimmedRemoteID, err := s.GetDirectoryRecordByRemoteID("  " + activeNewest.RemoteID + "  ")
	if err != nil || !reflect.DeepEqual(byTrimmedRemoteID, &activeNewest) {
		t.Fatalf("GetDirectoryRecordByRemoteID = %#v, want %#v, err=%v", byTrimmedRemoteID, activeNewest, err)
	}
}

func TestListDirectoryRecordsEmptyResultIsNil(t *testing.T) {
	s := newDirectoryQueryTestStore(t)

	all, err := s.ListDirectoryRecords(false)
	if err != nil || all != nil {
		t.Fatalf("empty all-record list = %#v, want nil, err=%v", all, err)
	}
	active, err := s.ListDirectoryRecords(true)
	if err != nil || active != nil {
		t.Fatalf("empty active-record list = %#v, want nil, err=%v", active, err)
	}

	putDirectoryQueryTestRecord(t, s, directoryQueryTestRecord("only-inactive", "expired"), "2026-04-01T00:00:00Z")
	active, err = s.ListDirectoryRecords(true)
	if err != nil || active != nil {
		t.Fatalf("active list with only inactive rows = %#v, want nil, err=%v", active, err)
	}
}

func insertMalformedDirectoryQueryTestRecord(t *testing.T, s *Store, id, remoteID, identityJSON, endpointsJSON string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO directory_records
(id, remote_id, label, identity_json, endpoints_json, announcement_json, expires_at, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, remoteID, "Synthetic malformed peer", identityJSON, endpointsJSON, `{"version":1,"synthetic":true}`, "2030-01-01T00:00:00Z", "active",
		"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
}

func TestListDirectoryRecordsMalformedStoredJSONReturnsError(t *testing.T) {
	s := newDirectoryQueryTestStore(t)
	insertMalformedDirectoryQueryTestRecord(t, s, "directory-malformed-identity-synthetic", "synthetic-malformed-identity-peer", "{", "[]")
	insertMalformedDirectoryQueryTestRecord(t, s, "directory-malformed-endpoints-synthetic", "synthetic-malformed-endpoints-peer", "{}", "{")

	if records, err := s.ListDirectoryRecords(true); err == nil || records != nil {
		t.Fatalf("malformed stored identity returned records=%#v err=%v, want error and nil records", records, err)
	}
	for _, id := range []string{"directory-malformed-identity-synthetic", "directory-malformed-endpoints-synthetic"} {
		if record, err := s.GetDirectoryRecord(id); err == nil || record != nil {
			t.Fatalf("GetDirectoryRecord malformed stored JSON %q = %#v, err=%v; want error and nil record", id, record, err)
		}
	}
}

func newDirectoryQueryTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return s
}

// These storage-only PUBLIC_SYNTHETIC records are not deployment credentials.
func directoryQueryTestRecord(suffix, status string) DirectoryRecord {
	return DirectoryRecord{
		ID:       "directory-synthetic-" + suffix,
		RemoteID: "synthetic-peer-" + suffix,
		Label:    "Synthetic peer " + suffix,
		Identity: e2ee.PublicIdentity{
			ID:            "synthetic-identity-" + suffix,
			KEMPublic:     []byte("PUBLIC_SYNTHETIC_KEM_" + suffix),
			SigningPublic: []byte("PUBLIC_SYNTHETIC_SIGNING_" + suffix),
		},
		Endpoints:    []string{"https://" + suffix + ".peer.invalid/federation", "wss://" + suffix + ".peer.invalid/relay"},
		Announcement: json.RawMessage(`{"version":1,"synthetic":true,"peer":"` + suffix + `","capabilities":["federation","relay"]}`),
		ExpiresAt:    "2030-01-01T00:00:00Z",
		Status:       status,
	}
}

func putDirectoryQueryTestRecord(t *testing.T, s *Store, record DirectoryRecord, updatedAt string) DirectoryRecord {
	t.Helper()
	stored, err := s.UpsertDirectoryRecord(record)
	if err != nil {
		t.Fatalf("upsert synthetic directory record %q: %v", record.ID, err)
	}
	if _, err := s.db.Exec(`UPDATE directory_records SET updated_at = ? WHERE id = ?`, updatedAt, stored.ID); err != nil {
		t.Fatalf("set deterministic updated_at for %q: %v", stored.ID, err)
	}
	stored.UpdatedAt = updatedAt
	return *stored
}

func BenchmarkListDirectoryRecords(b *testing.B) {
	for _, count := range []int{100, 1000} {
		for _, activeOnly := range []bool{false, true} {
			name := fmt.Sprintf("records=%d/active_only=%t", count, activeOnly)
			b.Run(name, func(b *testing.B) {
				s, err := New(filepath.Join(b.TempDir(), "cicada.sqlite3"))
				if err != nil {
					b.Fatal(err)
				}
				defer func() {
					if err := s.Close(); err != nil {
						b.Errorf("close store: %v", err)
					}
				}()
				seedDirectoryQueryBenchmark(b, s, count)

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := s.ListDirectoryRecords(activeOnly); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func seedDirectoryQueryBenchmark(b *testing.B, s *Store, count int) {
	b.Helper()
	identityJSON, err := json.Marshal(e2ee.PublicIdentity{
		ID: "synthetic-benchmark-peer", KEMPublic: []byte("PUBLIC_SYNTHETIC_KEM"),
		SigningPublic: []byte("PUBLIC_SYNTHETIC_SIGNING"),
	})
	if err != nil {
		b.Fatal(err)
	}
	endpointsJSON, err := json.Marshal([]string{"https://benchmark.peer.invalid/federation", "wss://benchmark.peer.invalid/relay"})
	if err != nil {
		b.Fatal(err)
	}
	announcement := `{"version":1,"synthetic":true,"peer":"benchmark"}`

	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < count; i++ {
		status := "active"
		if i%10 == 0 {
			status = "expired"
		}
		updatedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		_, err := tx.Exec(`INSERT INTO directory_records
(id, remote_id, label, identity_json, endpoints_json, announcement_json, expires_at, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("directory-benchmark-%04d", i), fmt.Sprintf("synthetic-benchmark-peer-%04d", i), "Synthetic benchmark peer",
			string(identityJSON), string(endpointsJSON), announcement, "2030-01-01T00:00:00Z", status,
			"2026-01-01T00:00:00Z", updatedAt)
		if err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}
