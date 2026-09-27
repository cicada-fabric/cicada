package store

import (
	"database/sql"
	"errors"
	"path/filepath"
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
