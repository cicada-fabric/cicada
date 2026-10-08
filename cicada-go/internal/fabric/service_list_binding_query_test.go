package fabric

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

// All database rows, native IDs and credential labels here are PUBLIC_SYNTHETIC.
// Tests and benchmarks use Service.List so an old service.go overlay can run
// the same fixture without depending on the new Store batching method.
type directoryListQueryFixture struct {
	service *Service
	store   *store.Store
	db      *sql.DB
	actor   Actor
	groupID string
}

func newDirectoryListQueryFixture(tb testing.TB) *directoryListQueryFixture {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "PUBLIC_SYNTHETIC.sqlite3")
	persistence, err := store.New(path)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{ID: "PUBLIC_SYNTHETIC_owner",
		Kind: store.PrincipalKindHuman, OwnerID: "PUBLIC_SYNTHETIC_owner", TrustDomainID: "PUBLIC_SYNTHETIC_owner", Name: "PUBLIC_SYNTHETIC Owner"})
	if err != nil {
		tb.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{ID: "PUBLIC_SYNTHETIC_group", Name: "PUBLIC_SYNTHETIC Group",
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.ID, State: store.GroupStateActive})
	if err != nil {
		tb.Fatal(err)
	}
	service, err := NewService(persistence, owner.ID, owner.ID)
	if err != nil {
		tb.Fatal(err)
	}
	joined, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "PUBLIC_SYNTHETIC Actor",
		EndpointName: "PUBLIC_SYNTHETIC_actor", Harness: "codex", NativeSessionID: "PUBLIC_SYNTHETIC_actor_native",
		NodeID: "PUBLIC_SYNTHETIC_actor_node"})
	if err != nil {
		tb.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		tb.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		tb.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	tb.Cleanup(func() { _ = db.Close() })
	return &directoryListQueryFixture{service: service, store: persistence, db: db, actor: actor, groupID: group.ID}
}

func directoryListPeerID(index int) string {
	return fmt.Sprintf("PUBLIC_SYNTHETIC_ep_%04d", index)
}

func seedDirectoryListQueryPeers(tb testing.TB, f *directoryListQueryFixture, count int) {
	tb.Helper()
	tx, err := f.db.Begin()
	if err != nil {
		tb.Fatal(err)
	}
	defer tx.Rollback()
	queries := []string{
		`INSERT INTO principals(id,kind,owner_id,name,status,created_at,updated_at)
VALUES(?,'agent','PUBLIC_SYNTHETIC_owner',?,'active',?,?)`,
		`INSERT INTO memberships(id,principal_id,group_id,status,created_at,updated_at)
VALUES(?,?,?,'active',?,?)`,
		`INSERT INTO fabric_endpoints(id,name,harness,native_session_id,machine_id,workspace,status,
capabilities_json,tags_json,owner,principal_id,group_id,binding_id,migration_state,joined_at,last_seen,created_at,updated_at)
VALUES(?,?,'codex',?,'PUBLIC_SYNTHETIC_peer_node','PUBLIC_SYNTHETIC_workspace','online',
'{"synthetic":true}','["PUBLIC_SYNTHETIC"]','PUBLIC_SYNTHETIC_owner',?,?,?,'READY',?,?,?,?)`,
		`INSERT INTO endpoint_group_memberships(endpoint_id,group_id,status,created_at,updated_at)
VALUES(?,?,'active',?,?)`,
		`INSERT INTO session_bindings(id,endpoint_id,principal_id,group_id,native_session_id,node_id,epoch,
status,credential_hash,context_continuity,created_at,updated_at)
VALUES(?,?,?,?,?,'PUBLIC_SYNTHETIC_peer_node',?,'active',?,'PUBLIC_SYNTHETIC_continuity',?,?)`,
	}
	statements := make([]*sql.Stmt, len(queries))
	for i, query := range queries {
		statements[i], err = tx.Prepare(query)
		if err != nil {
			tb.Fatal(err)
		}
		defer statements[i].Close()
	}
	stamp := "2025-01-01T00:00:00Z"
	for i := 0; i < count; i++ {
		id := directoryListPeerID(i)
		principalID, bindingID := "pr_"+id, "bind_"+id
		name, nativeID := fmt.Sprintf("peer-%04d", i), "PUBLIC_SYNTHETIC_native_"+id
		values := [][]any{
			{principalID, name, stamp, stamp},
			{"mem_" + id, principalID, f.groupID, stamp, stamp},
			{id, name, nativeID, principalID, f.groupID, bindingID, stamp, stamp, stamp, stamp},
			{id, f.groupID, stamp, stamp},
			{bindingID, id, principalID, f.groupID, nativeID, i + 1, "PUBLIC_SYNTHETIC_credential_" + id, stamp, stamp},
		}
		for j, args := range values {
			if _, err := statements[j].Exec(args...); err != nil {
				tb.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
}

func execDirectoryListQuery(tb testing.TB, f *directoryListQueryFixture, query string, args ...any) {
	tb.Helper()
	if _, err := f.db.Exec(query, args...); err != nil {
		tb.Fatal(err)
	}
}

func assertDirectoryListPeerIDs(t *testing.T, f *directoryListQueryFixture, limit int, want ...int) []NetworkCard {
	t.Helper()
	cards, err := f.service.List(f.actor, "", "PUBLIC_SYNTHETIC_peer_node", "", limit)
	if err != nil || cards == nil || len(cards) != len(want) {
		t.Fatalf("List limit=%d: cards=%#v err=%v; want indices %v", limit, cards, err, want)
	}
	for i, index := range want {
		if cards[i].EndpointID != directoryListPeerID(index) {
			t.Fatalf("card %d = %s; want peer %d", i, cards[i].EndpointID, index)
		}
	}
	return cards
}

func TestServiceListBindingQuerySelectionScopeAndPrivacy(t *testing.T) {
	f := newDirectoryListQueryFixture(t)
	seedDirectoryListQueryPeers(t, f, 11)
	execDirectoryListQuery(t, f, `UPDATE session_bindings SET status='released' WHERE endpoint_id=?`, directoryListPeerID(0))
	execDirectoryListQuery(t, f, `UPDATE fabric_endpoints SET status='left' WHERE id=?`, directoryListPeerID(1))
	for i, status := range []string{"active", "leased", "online", "ready", "acquired"} {
		execDirectoryListQuery(t, f, `UPDATE session_bindings SET status=? WHERE endpoint_id=?`, status, directoryListPeerID(i+2))
	}
	// A higher inactive epoch and a stale Endpoint binding pointer must not
	// override the active selection; the production unique-active indexes stay.
	execDirectoryListQuery(t, f, `INSERT INTO session_bindings
(id,endpoint_id,principal_id,group_id,native_session_id,epoch,status,created_at,updated_at)
SELECT 'PUBLIC_SYNTHETIC_inactive_high',endpoint_id,principal_id,group_id,native_session_id,999,'revoked',created_at,updated_at
FROM session_bindings WHERE endpoint_id=?`, directoryListPeerID(2))
	execDirectoryListQuery(t, f, `UPDATE fabric_endpoints SET binding_id='PUBLIC_SYNTHETIC_inactive_high' WHERE id=?`, directoryListPeerID(2))
	// Binding selection historically checks status, not peer lease expiry.
	execDirectoryListQuery(t, f, `UPDATE session_bindings SET lease_expires_at='2000-01-01T00:00:00Z' WHERE endpoint_id=?`, directoryListPeerID(3))
	execDirectoryListQuery(t, f, `UPDATE session_bindings SET capabilities_json='{' WHERE endpoint_id=?`, directoryListPeerID(7))
	execDirectoryListQuery(t, f, `INSERT INTO session_bindings
(id,endpoint_id,principal_id,group_id,native_session_id,epoch,status,created_at,updated_at)
SELECT 'PUBLIC_SYNTHETIC_inactive_fallback',endpoint_id,principal_id,group_id,native_session_id,1,'released',created_at,updated_at
FROM session_bindings WHERE endpoint_id=?`, directoryListPeerID(7))
	execDirectoryListQuery(t, f, `UPDATE fabric_endpoints SET migration_state=? WHERE id=?`, store.EndpointMigrationPendingGroup, directoryListPeerID(8))
	foreign, err := f.store.CreateGroup(store.Group{ID: "PUBLIC_SYNTHETIC_foreign_group", Name: "PUBLIC_SYNTHETIC Foreign",
		OwnerPrincipalID: "PUBLIC_SYNTHETIC_owner", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"memberships", "endpoint_group_memberships", "session_bindings", "fabric_endpoints"} {
		column := "endpoint_id"
		if table == "memberships" {
			column = "principal_id"
		} else if table == "fabric_endpoints" {
			column = "id"
		}
		id := directoryListPeerID(9)
		if table == "memberships" {
			id = "pr_" + id
		}
		execDirectoryListQuery(t, f, `UPDATE `+table+` SET group_id=? WHERE `+column+`=?`, foreign.ID, id)
	}
	execDirectoryListQuery(t, f, `UPDATE fabric_endpoints SET name='peer-0002' WHERE id=?`, directoryListPeerID(9))
	execDirectoryListQuery(t, f, `UPDATE memberships SET expires_at='2000-01-01T00:00:00Z' WHERE principal_id=?`, "pr_"+directoryListPeerID(10))
	cards := assertDirectoryListPeerIDs(t, f, 100, 2, 3, 4, 5, 6)
	for i, card := range cards {
		index := i + 2
		if card.BindingID != "bind_"+directoryListPeerID(index) || card.BindingEpoch != uint64(index+1) ||
			card.GroupID != f.groupID || card.NativeSessionID != "" || card.ContextContinuity != "PUBLIC_SYNTHETIC_continuity" ||
			card.Workspace != "PUBLIC_SYNTHETIC_workspace" || card.Capabilities["synthetic"] != true ||
			len(card.Tags) != 1 || card.Tags[0] != "PUBLIC_SYNTHETIC" {
			t.Fatalf("wrong binding or card projection: %#v", card)
		}
	}
	encoded, err := json.Marshal(cards)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{"PUBLIC_SYNTHETIC_native_", "PUBLIC_SYNTHETIC_credential_", "lease_expires_at", foreign.ID} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("Directory exposed private value %q", privateValue)
		}
	}
	resolved, err := f.service.Resolve(f.actor, ResolveInput{Query: "peer-0002"})
	if err != nil || resolved.EndpointID != directoryListPeerID(2) || resolved.BindingEpoch != 3 || resolved.NativeSessionID != "" {
		t.Fatalf("alias selected an inactive or foreign binding: %#v, %v", resolved, err)
	}
	if _, err := f.service.Resolve(f.actor, ResolveInput{Query: directoryListPeerID(9)}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("foreign stable ID became visible: %v", err)
	}
	// The SQL endpoint limit precedes binding/left skipping; do not backfill.
	assertDirectoryListPeerIDs(t, f, 1)
	assertDirectoryListPeerIDs(t, f, 3, 2)
	filtered, err := f.service.List(f.actor, " online ", " PUBLIC_SYNTHETIC_peer_node ", " codex ", 100)
	if err != nil || len(filtered) != len(cards) {
		t.Fatalf("trimmed filters changed listing: %#v, %v", filtered, err)
	}
	assertDirectoryListPeerIDs(t, f, 0, 2, 3, 4, 5, 6)
	denied := f.actor
	denied.BindingEpoch++
	if cards, err := f.service.List(denied, "", "", "", 100); cards != nil || !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("stale actor obtained Directory cards: %#v, %v", cards, err)
	}
}

func TestServiceListBindingQueryOrderAndRevocation(t *testing.T) {
	f := newDirectoryListQueryFixture(t)
	assertDirectoryListPeerIDs(t, f, 100)
	seedDirectoryListQueryPeers(t, f, 3)
	execDirectoryListQuery(t, f, `UPDATE fabric_endpoints SET updated_at='2025-01-02T00:00:00Z' WHERE id=?`, directoryListPeerID(2))
	assertDirectoryListPeerIDs(t, f, 2, 2, 0)
	execDirectoryListQuery(t, f, `UPDATE endpoint_group_memberships SET status='revoked' WHERE endpoint_id=?`, directoryListPeerID(2))
	assertDirectoryListPeerIDs(t, f, 2, 0, 1)
	execDirectoryListQuery(t, f, `DELETE FROM session_bindings WHERE endpoint_id=?`, directoryListPeerID(0))
	assertDirectoryListPeerIDs(t, f, 2, 1)
	execDirectoryListQuery(t, f, `UPDATE fabric_endpoints SET status='left' WHERE id=?`, directoryListPeerID(1))
	assertDirectoryListPeerIDs(t, f, 100)
}

func BenchmarkServiceListBindingsPublicSynthetic(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprintf("rows_%d", count), func(b *testing.B) {
			b.StopTimer()
			f := newDirectoryListQueryFixture(b)
			seedDirectoryListQueryPeers(b, f, count)
			b.ReportAllocs()
			b.ResetTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				cards, err := f.service.List(f.actor, "", "PUBLIC_SYNTHETIC_peer_node", "", count)
				if err != nil || len(cards) != count {
					b.Fatalf("list %d synthetic peers: count=%d err=%v", count, len(cards), err)
				}
			}
			b.StopTimer()
		})
	}
}
