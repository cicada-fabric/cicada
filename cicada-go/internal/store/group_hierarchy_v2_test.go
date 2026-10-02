package store

import (
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGroupHierarchyVersionCycleAndOwnerBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.CreatePrincipal(Principal{ID: "owner-a", Kind: PrincipalKindHuman, Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreatePrincipal(Principal{ID: "owner-b", Kind: PrincipalKindHuman, Name: "B"})
	if err != nil {
		t.Fatal(err)
	}
	create := func(id string, principal *Principal) *Group {
		t.Helper()
		group, err := s.CreateGroup(Group{ID: id, Name: id, OwnerPrincipalID: principal.ID,
			TrustDomainID: principal.ID, State: GroupStateActive})
		if err != nil {
			t.Fatal(err)
		}
		return group
	}
	root := create("root", owner)
	child := create("child", owner)
	grandchild := create("grandchild", owner)
	external := create("external", other)
	if _, err := s.CreateGroup(Group{ID: "skipped-parent", Name: "skipped-parent", ParentGroupID: root.ID}); err == nil {
		t.Fatal("group creation silently ignored requested parent")
	}
	child, err = s.SetGroupParent(child.ID, root.ID, child.Version)
	if err != nil || child.ParentGroupID != root.ID || child.Revision != 2 {
		t.Fatalf("attach child: %#v err=%v", child, err)
	}
	unchanged, err := s.SetGroupParent(child.ID, root.ID, child.Version)
	if err != nil || unchanged.Version != child.Version || unchanged.Revision != child.Revision {
		t.Fatalf("repeating same placement changed revision: %#v err=%v", unchanged, err)
	}
	if _, err := s.SetGroupParent(child.ID, external.ID, child.Version); !errors.Is(err, ErrGroupParentOwnerScope) {
		t.Fatalf("cross-owner placement = %v", err)
	}
	if _, err := s.SetGroupParent(grandchild.ID, child.ID, grandchild.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetGroupParent(root.ID, grandchild.ID, root.Version); !errors.Is(err, ErrGroupHierarchyCycle) {
		t.Fatalf("cycle through grandchildren = %v", err)
	}
	if _, err := s.SetGroupParent(root.ID, root.ID, root.Version); !errors.Is(err, ErrGroupHierarchyCycle) {
		t.Fatalf("self-parent = %v", err)
	}
	if _, err := s.SetGroupParent(child.ID, "", child.Version-1); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale graph edit = %v", err)
	}
	cleared, err := s.SetGroupParent(child.ID, "", child.Version)
	if err != nil || cleared.ParentGroupID != "" || cleared.Version != child.Version+1 {
		t.Fatalf("remove parent: %#v err=%v", cleared, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetGroup(grandchild.ID)
	if err != nil || got.ParentGroupID != child.ID {
		t.Fatalf("restart lost hierarchy: %#v err=%v", got, err)
	}
}

func TestClientTopologyMutationGuardHierarchyCASAndScope(t *testing.T) {
	f := newClientTopologyStoreMutationFixture(t, true)
	child, parent := f.groups[0], f.groups[1]
	request := f.request(t, "topology.apply")
	attached, err := f.store.SetGroupParentForClientRequest(request, "owner_a", child.ID, parent.ID, child.Version)
	if err != nil || attached.ParentGroupID != parent.ID || attached.Version != child.Version+1 || attached.Revision != child.Revision+1 {
		t.Fatalf("current parent placement failed: %v", err)
	}
	repeated, err := f.store.SetGroupParentForClientRequest(f.request(t, "topology.apply"), "owner_a", child.ID, parent.ID, attached.Version)
	if err != nil || !reflect.DeepEqual(attached, repeated) {
		t.Fatalf("same placement changed the Group: %v", err)
	}
	for _, tc := range []struct {
		name, childID, parentID string
		version                 int64
		want                    error
	}{
		{"stale_CAS", child.ID, "", child.Version, ErrVersionConflict},
		{"exhausted_CAS", child.ID, "", math.MaxInt64, ErrVersionConflict},
		{"self_cycle", parent.ID, parent.ID, parent.Version, ErrGroupHierarchyCycle},
		{"ancestor_cycle", parent.ID, child.ID, parent.Version, ErrGroupHierarchyCycle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.snapshot(t)
			if _, err := f.store.SetGroupParentForClientRequest(f.request(t, "topology.apply"), "owner_a", tc.childID, tc.parentID, tc.version); !errors.Is(err, tc.want) {
				t.Fatalf("hierarchy/CAS guard = %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("hierarchy refusal changed persisted business state")
			}
		})
	}
	for _, tc := range []struct{ name, networkID, trustDomain string }{
		{"different_trust_domain", child.NetworkID, "other-domain"},
		{"different_network", "synthetic-other-network", "owner_a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.networkID != child.NetworkID {
				if _, err := f.store.CreateNetwork(Network{ID: tc.networkID, Name: tc.networkID, HubID: f.hubID, OwnerID: "owner_a", State: NetworkStateActive}); err != nil {
					t.Fatal(err)
				}
			}
			external, err := f.store.CreateGroup(Group{ID: "synthetic-" + tc.name, Name: tc.name, NetworkID: tc.networkID,
				OwnerPrincipalID: "owner_a", TrustDomainID: tc.trustDomain, State: GroupStateActive})
			if err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			if _, err := f.store.SetGroupParentForClientRequest(f.request(t, "topology.apply"), "owner_a", child.ID, external.ID, attached.Version); !errors.Is(err, ErrGroupParentOwnerScope) {
				t.Fatalf("hierarchy scope widened: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("scope refusal changed persisted business state")
			}
		})
	}
}

func TestGroupHierarchyMigrationRollsBackAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("stop after group hierarchy DDL")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.group.hierarchy" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("migration interruption = %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	columns, err := existingColumns(db, "groups", []string{"parent_group_id"})
	if err != nil {
		t.Fatal(err)
	}
	if len(columns) != 0 {
		t.Fatal("interrupted migration left parent column behind")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyStatePreserved(t, reopened)
	columns, err = existingColumns(reopened.db, "groups", []string{"parent_group_id"})
	if err != nil || len(columns) != 1 {
		t.Fatalf("resumed migration parent column = %#v err=%v", columns, err)
	}
	entry, err := reopened.readV2Migration(12)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("resumed migration ledger = %#v err=%v", entry, err)
	}
}
