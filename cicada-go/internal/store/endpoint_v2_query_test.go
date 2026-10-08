package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All fixtures in this file are PUBLIC_SYNTHETIC metadata in disposable Stores.
// Keep fixture SQL independent of production decoders so the same tests and
// benchmark can also run against the original endpoint query implementation.
const endpointV2QueryInsertSQL = `INSERT INTO fabric_endpoints
(id,name,role,harness,native_session_id,machine_id,workspace,goal_id,status,
capabilities_json,tags_json,owner,visibility,joined_at,last_seen,created_at,updated_at,
principal_id,group_id,binding_id,migration_state)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

func newEndpointV2QueryStore(tb testing.TB) *Store {
	tb.Helper()
	s, err := New(filepath.Join(tb.TempDir(), "PUBLIC_SYNTHETIC.sqlite3"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := s.Close(); err != nil {
			tb.Error(err)
		}
	})
	return s
}

func endpointV2QueryFixture(id, principalID, groupID string) Endpoint {
	return Endpoint{
		ID: id, Name: "PUBLIC_SYNTHETIC " + id, Role: "worker", Harness: "codex",
		NativeSessionID: "PUBLIC_SYNTHETIC_native_" + id, MachineID: "node_a",
		Workspace: "PUBLIC_SYNTHETIC_workspace", GoalID: "PUBLIC_SYNTHETIC_goal", Status: "online",
		Capabilities: map[string]any{"synthetic": true, "count": float64(3), "nested": map[string]any{"mode": "read"}},
		Tags:         []string{"PUBLIC_SYNTHETIC", "query-fixture"}, Owner: "legacy_owner",
		Visibility: "private", JoinedAt: "2025-01-01T01:00:00Z", LastSeen: "2025-01-02T01:00:00Z",
		CreatedAt: "2025-01-01T00:00:00Z", UpdatedAt: "2025-01-03T00:00:00Z",
		PrincipalID: principalID, GroupID: groupID, BindingID: "PUBLIC_SYNTHETIC_binding_" + id,
		MigrationState: EndpointMigrationReady, MigrationStatus: EndpointMigrationReady,
	}
}

func endpointV2QueryValues(tb testing.TB, endpoint Endpoint) []any {
	tb.Helper()
	capabilities, err := json.Marshal(endpoint.Capabilities)
	if err != nil {
		tb.Fatal(err)
	}
	tags, err := json.Marshal(endpoint.Tags)
	if err != nil {
		tb.Fatal(err)
	}
	return []any{endpoint.ID, endpoint.Name, endpoint.Role, endpoint.Harness, endpoint.NativeSessionID,
		endpoint.MachineID, endpoint.Workspace, endpoint.GoalID, endpoint.Status, string(capabilities), string(tags),
		endpoint.Owner, endpoint.Visibility, endpoint.JoinedAt, endpoint.LastSeen, endpoint.CreatedAt, endpoint.UpdatedAt,
		endpoint.PrincipalID, endpoint.GroupID, endpoint.BindingID, endpoint.MigrationState}
}

func execEndpointV2Query(tb testing.TB, s *Store, query string, args ...any) {
	tb.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		tb.Fatal(err)
	}
}

func assertEndpointV2QueryIDs(t *testing.T, s *Store, filter EndpointV2Filter, want ...string) {
	t.Helper()
	endpoints, err := s.ListEndpointsV2(filter)
	if err != nil {
		t.Fatal(err)
	}
	if endpoints == nil {
		t.Fatal("successful empty lists must be non-nil")
	}
	ids := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		ids = append(ids, endpoint.ID)
	}
	if len(ids) != len(want) {
		t.Fatalf("filter %+v: IDs %v, want %v", filter, ids, want)
	}
	for i := range ids {
		if ids[i] != want[i] {
			t.Fatalf("filter %+v: IDs %v, want %v", filter, ids, want)
		}
	}
}

func TestEndpointV2QueryFieldsAndMigration(t *testing.T) {
	s := newEndpointV2QueryStore(t)
	ready := endpointV2QueryFixture("ep_ready", "pr_a", "grp_a")
	pending := endpointV2QueryFixture("ep_pending", "", "")
	pending.BindingID = ""
	pending.MigrationState = EndpointMigrationPendingGroup
	pending.MigrationStatus = EndpointMigrationPendingGroup
	pending.Capabilities = nil
	pending.Tags = nil
	for _, want := range []Endpoint{ready, pending} {
		execEndpointV2Query(t, s, endpointV2QueryInsertSQL, endpointV2QueryValues(t, want)...)
		got, err := s.GetEndpointV2(want.ID)
		if err != nil || !reflect.DeepEqual(got, &want) {
			t.Fatalf("GetEndpointV2(%q) = %#v, %v; want %#v", want.ID, got, err, want)
		}
		listed, err := s.ListEndpointsV2(EndpointV2Filter{MigrationState: want.MigrationState})
		if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0], want) {
			t.Fatalf("list state %q = %#v, %v; want %#v", want.MigrationState, listed, err, want)
		}
	}
	assertEndpointV2QueryIDs(t, s, EndpointV2Filter{}, pending.ID, ready.ID)
	assertEndpointV2QueryIDs(t, s, EndpointV2Filter{PrincipalID: "absent"})
}

func TestEndpointV2QueryScopeAndFilters(t *testing.T) {
	s := newEndpointV2QueryStore(t)
	for _, groupID := range []string{"grp_a", "grp_b"} {
		if _, err := s.CreateGroup(Group{ID: groupID, Name: "PUBLIC_SYNTHETIC " + groupID, State: GroupStateActive}); err != nil {
			t.Fatal(err)
		}
	}
	for i, owner := range []string{"owner_a", "owner_a", "owner_b"} {
		principalID := fmt.Sprintf("pr_%d", i)
		if _, err := s.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent, OwnerID: owner, Name: "PUBLIC_SYNTHETIC " + principalID}); err != nil {
			t.Fatal(err)
		}
		for _, groupID := range []string{"grp_a", "grp_b"} {
			if _, err := s.CreateMembership(Membership{PrincipalID: principalID, GroupID: groupID}); err != nil {
				t.Fatal(err)
			}
		}
	}
	a := endpointV2QueryFixture("ep_a", "pr_0", "grp_a")
	b := endpointV2QueryFixture("ep_b", "pr_1", "grp_a")
	b.Status, b.MachineID, b.Harness = "offline", "node_b", "synthetic_harness"
	c := endpointV2QueryFixture("ep_c", "pr_2", "grp_b")
	for _, endpoint := range []Endpoint{a, b, c} {
		execEndpointV2Query(t, s, endpointV2QueryInsertSQL, endpointV2QueryValues(t, endpoint)...)
		execEndpointV2Query(t, s, `INSERT INTO endpoint_group_memberships
(endpoint_id,group_id,status,created_at,updated_at) VALUES(?,?,'active',?,?)`,
			endpoint.ID, endpoint.GroupID, endpoint.CreatedAt, endpoint.UpdatedAt)
	}
	// A second relation must select the same Endpoint without changing its
	// primary Group/Binding identity, and must never duplicate a list row.
	execEndpointV2Query(t, s, `INSERT INTO endpoint_group_memberships
(endpoint_id,group_id,status,created_at,updated_at) VALUES('ep_a','grp_b','active',?,?)`, a.CreatedAt, a.UpdatedAt)
	cases := []struct {
		name   string
		filter EndpointV2Filter
		want   []string
	}{
		{"group a", EndpointV2Filter{GroupID: "grp_a"}, []string{"ep_a", "ep_b"}},
		{"group b", EndpointV2Filter{GroupID: "grp_b"}, []string{"ep_a", "ep_c"}},
		{"owner a", EndpointV2Filter{OwnerID: "owner_a"}, []string{"ep_a", "ep_b"}},
		{"owner b", EndpointV2Filter{OwnerID: "owner_b"}, []string{"ep_c"}},
		{"principal", EndpointV2Filter{PrincipalID: "pr_1"}, []string{"ep_b"}},
		{"status", EndpointV2Filter{Status: "offline"}, []string{"ep_b"}},
		{"node", EndpointV2Filter{NodeID: "node_b"}, []string{"ep_b"}},
		{"harness", EndpointV2Filter{Harness: "synthetic_harness"}, []string{"ep_b"}},
		{"combined trimmed", EndpointV2Filter{GroupID: " grp_b ", OwnerID: " owner_a ", PrincipalID: " pr_0 ", Status: " online ", NodeID: " node_a ", Harness: " codex ", MigrationState: " READY "}, []string{"ep_a"}},
		{"scope mismatch", EndpointV2Filter{GroupID: "grp_a", OwnerID: "owner_b"}, nil},
		{"pending", EndpointV2Filter{MigrationState: EndpointMigrationPendingGroup}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertEndpointV2QueryIDs(t, s, tc.filter, tc.want...) })
	}
	listed, err := s.ListEndpointsV2(EndpointV2Filter{GroupID: "grp_b", PrincipalID: "pr_0"})
	if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0], a) {
		t.Fatalf("secondary Group changed Endpoint identity: %#v, %v", listed, err)
	}
	for _, tc := range []struct {
		name, change, restore string
	}{
		{"relation revoked", `UPDATE endpoint_group_memberships SET status='revoked' WHERE endpoint_id='ep_a' AND group_id='grp_b'`, `UPDATE endpoint_group_memberships SET status='active' WHERE endpoint_id='ep_a' AND group_id='grp_b'`},
		{"membership revoked", `UPDATE memberships SET status='revoked' WHERE principal_id='pr_0' AND group_id='grp_b'`, `UPDATE memberships SET status='active' WHERE principal_id='pr_0' AND group_id='grp_b'`},
		{"principal suspended", `UPDATE principals SET status='suspended' WHERE id='pr_0'`, `UPDATE principals SET status='active' WHERE id='pr_0'`},
		{"group paused", `UPDATE groups SET state='PAUSED' WHERE id='grp_b'`, `UPDATE groups SET state='ACTIVE' WHERE id='grp_b'`},
		{"expired", `UPDATE memberships SET expires_at='2000-01-01T00:00:00Z' WHERE principal_id='pr_0' AND group_id='grp_b'`, `UPDATE memberships SET expires_at='' WHERE principal_id='pr_0' AND group_id='grp_b'`},
		{"malformed expiry", `UPDATE memberships SET expires_at='PUBLIC_SYNTHETIC_invalid_time' WHERE principal_id='pr_0' AND group_id='grp_b'`, `UPDATE memberships SET expires_at='' WHERE principal_id='pr_0' AND group_id='grp_b'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			execEndpointV2Query(t, s, tc.change)
			assertEndpointV2QueryIDs(t, s, EndpointV2Filter{GroupID: "grp_b", PrincipalID: "pr_0"})
			if tc.name == "principal suspended" {
				assertEndpointV2QueryIDs(t, s, EndpointV2Filter{OwnerID: "owner_a"}, "ep_b")
			}
			execEndpointV2Query(t, s, tc.restore)
			assertEndpointV2QueryIDs(t, s, EndpointV2Filter{GroupID: "grp_b", PrincipalID: "pr_0"}, "ep_a")
		})
	}
	execEndpointV2Query(t, s, `UPDATE memberships SET expires_at=? WHERE principal_id='pr_0' AND group_id='grp_b'`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	assertEndpointV2QueryIDs(t, s, EndpointV2Filter{GroupID: "grp_b", PrincipalID: "pr_0"}, "ep_a")
}

func TestEndpointV2QueryOrderAndLimit(t *testing.T) {
	s := newEndpointV2QueryStore(t)
	assertEndpointV2QueryIDs(t, s, EndpointV2Filter{})
	for _, id := range []string{"ep_c", "ep_b", "ep_a"} {
		endpoint := endpointV2QueryFixture(id, "pr_a", "grp_a")
		if id == "ep_c" {
			endpoint.UpdatedAt = "2025-01-04T00:00:00Z"
		}
		execEndpointV2Query(t, s, endpointV2QueryInsertSQL, endpointV2QueryValues(t, endpoint)...)
	}
	assertEndpointV2QueryIDs(t, s, EndpointV2Filter{}, "ep_c", "ep_a", "ep_b")
	assertEndpointV2QueryIDs(t, s, EndpointV2Filter{Limit: 2}, "ep_c", "ep_a")
	for _, limit := range []int{-1, 0, 1001} {
		assertEndpointV2QueryIDs(t, s, EndpointV2Filter{Limit: limit}, "ep_c", "ep_a", "ep_b")
	}
	for i := 0; i < 202; i++ {
		endpoint := endpointV2QueryFixture(fmt.Sprintf("ep_older_%03d", i), "pr_a", "grp_a")
		endpoint.UpdatedAt = "2025-01-01T00:00:00Z"
		execEndpointV2Query(t, s, endpointV2QueryInsertSQL, endpointV2QueryValues(t, endpoint)...)
	}
	for _, limit := range []int{-1, 0, 1001, 1000} {
		wantCount := 200
		if limit == 1000 {
			wantCount = 205
		}
		listed, err := s.ListEndpointsV2(EndpointV2Filter{Limit: limit})
		if err != nil || len(listed) != wantCount {
			t.Fatalf("limit %d: count=%d err=%v; want %d", limit, len(listed), err, wantCount)
		}
	}
}

func TestEndpointV2QueryDecodeAndLookupErrors(t *testing.T) {
	s := newEndpointV2QueryStore(t)
	endpoint := endpointV2QueryFixture("ep_a", "pr_a", "grp_a")
	execEndpointV2Query(t, s, endpointV2QueryInsertSQL, endpointV2QueryValues(t, endpoint)...)
	for _, id := range []string{"absent", "", " ep_a "} {
		if got, err := s.GetEndpointV2(id); got != nil || !errors.Is(err, ErrEndpointNotFound) {
			t.Fatalf("GetEndpointV2(%q) = %#v, %v; want ErrEndpointNotFound", id, got, err)
		}
	}
	valid := endpointV2QueryFixture("ep_valid", "pr_valid", "grp_a")
	valid.UpdatedAt = "2025-01-04T00:00:00Z"
	execEndpointV2Query(t, s, endpointV2QueryInsertSQL, endpointV2QueryValues(t, valid)...)
	for _, tc := range []struct{ column, invalid, valid, prefix string }{
		{"capabilities_json", "{", `{}`, "decode endpoint capabilities:"},
		{"capabilities_json", `[]`, `{}`, "decode endpoint capabilities:"},
		{"tags_json", "[", `[]`, "decode endpoint tags:"},
		{"tags_json", `{}`, `[]`, "decode endpoint tags:"},
	} {
		t.Run(tc.column+tc.invalid, func(t *testing.T) {
			execEndpointV2Query(t, s, `UPDATE fabric_endpoints SET `+tc.column+`=? WHERE id='ep_a'`, tc.invalid)
			got, err := s.GetEndpointV2("ep_a")
			if got != nil || err == nil || !strings.HasPrefix(err.Error(), tc.prefix) {
				t.Fatalf("Get malformed JSON = %#v, %v; want %q error", got, err, tc.prefix)
			}
			listed, err := s.ListEndpointsV2(EndpointV2Filter{})
			if listed != nil || err == nil || !strings.HasPrefix(err.Error(), tc.prefix) {
				t.Fatalf("List malformed JSON = %#v, %v; want %q error", listed, err, tc.prefix)
			}
			// SQL filtering must happen before decoding unrelated corrupt rows.
			assertEndpointV2QueryIDs(t, s, EndpointV2Filter{PrincipalID: "absent"})
			execEndpointV2Query(t, s, `UPDATE fabric_endpoints SET `+tc.column+`=? WHERE id='ep_a'`, tc.valid)
		})
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetEndpointV2("ep_a"); got != nil || err == nil || errors.Is(err, ErrEndpointNotFound) {
		t.Fatalf("closed Store lookup = %#v, %v; want database error", got, err)
	}
	if listed, err := s.ListEndpointsV2(EndpointV2Filter{}); listed != nil || err == nil {
		t.Fatalf("closed Store list = %#v, %v; want database error", listed, err)
	}
}

func BenchmarkListEndpointsV2PublicSynthetic(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprintf("rows_%d", count), func(b *testing.B) {
			b.StopTimer()
			s := newEndpointV2QueryStore(b)
			tx, err := s.db.Begin()
			if err != nil {
				b.Fatal(err)
			}
			defer tx.Rollback()
			stmt, err := tx.Prepare(endpointV2QueryInsertSQL)
			if err != nil {
				b.Fatal(err)
			}
			defer stmt.Close()
			for i := 0; i < count; i++ {
				endpoint := endpointV2QueryFixture(fmt.Sprintf("PUBLIC_SYNTHETIC_ep_%04d", i), "PUBLIC_SYNTHETIC_pr", "PUBLIC_SYNTHETIC_grp")
				if _, err := stmt.Exec(endpointV2QueryValues(b, endpoint)...); err != nil {
					b.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}
			filter := EndpointV2Filter{PrincipalID: "PUBLIC_SYNTHETIC_pr", MigrationState: EndpointMigrationReady, Limit: count}
			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				endpoints, err := s.ListEndpointsV2(filter)
				if err != nil || len(endpoints) != count {
					b.Fatalf("list %d synthetic endpoints: count=%d err=%v", count, len(endpoints), err)
				}
			}
			b.StopTimer()
		})
	}
}
