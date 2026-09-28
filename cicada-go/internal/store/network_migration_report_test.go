package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newNetworkMigrationReportFixture(t *testing.T, path string) (*Store, Group) {
	t.Helper()
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.CreatePrincipal(Principal{ID: "inventory_owner", Kind: PrincipalKindHuman,
		OwnerID: "inventory_owner", TrustDomainID: "inventory_domain", Name: "synthetic owner", Status: PrincipalStatusActive})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	network, err := s.CreateNetwork(Network{ID: "inventory_network", HubID: hubID,
		Name: "synthetic inventory", OwnerID: owner.ID})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	group, err := s.CreateGroup(Group{ID: "inventory_group", OwnerPrincipalID: owner.ID,
		TrustDomainID: owner.TrustDomainID, Name: "synthetic group", State: GroupStateActive})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, err := s.CreateMembership(Membership{ID: "inventory_membership", PrincipalID: owner.ID,
		GroupID: group.ID, Role: "member", Grants: []string{"task.read"}, Status: MembershipStatusActive}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, err := s.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic sensitive reason marker", group.Version); err != nil {
		s.Close()
		t.Fatal(err)
	}
	return s, *group
}

func TestNetworkMigrationReportInventoriesSafeIdentifiersAndGroupRelations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.sqlite3")
	s, _ := newNetworkMigrationReportFixture(t, path)
	defer s.Close()
	report, err := s.DryRunNetworkMigration()
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != CurrentV2SchemaVersion || report.Phase != NetworkModePreparing ||
		report.GroupCount != 1 || report.PendingCount != 1 || report.GroupDetailsOmitted != 0 ||
		len(report.Groups) != 1 || report.Groups[0].GroupID != "inventory_group" {
		t.Fatalf("incomplete migration inventory summary: %#v", report)
	}
	foundMembershipRelation := false
	for _, relation := range report.Groups[0].Relations {
		if relation.Table == "memberships" && relation.Column == "group_id" && relation.Rows == 1 {
			foundMembershipRelation = true
		}
	}
	if !foundMembershipRelation {
		t.Fatalf("Group relation inventory omitted Membership row: %#v", report.Groups[0].Relations)
	}
	tables := make(map[string]NetworkMigrationTableInventory, len(report.Tables))
	for _, table := range report.Tables {
		tables[table.Table] = table
	}
	for _, required := range []string{"groups", "memberships", "network_group_mappings_v2", "relay_v2_inbox", "shared_tasks_v2", "artifact_v2_refs"} {
		if _, ok := tables[required]; !ok {
			t.Fatalf("migration report omitted table %q", required)
		}
	}
	if tables["groups"].Rows != 1 || tables["groups"].IdentifierDigest == "" ||
		!slices.Contains(tables["groups"].IdentifierColumns, "id") {
		t.Fatalf("Group identifier inventory is incomplete: %#v", tables["groups"])
	}
	if slices.Contains(tables["network_invitations_v2"].IdentifierColumns, "token_hash") ||
		slices.Contains(tables["network_join_consents_v2"].IdentifierColumns, "token_hash") {
		t.Fatal("migration report inventoried token hashes as identifiers")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("synthetic sensitive reason marker")) || bytes.Contains(encoded, []byte("reason")) {
		t.Fatalf("migration report exposed arbitrary mapping reason: %s", encoded)
	}
}

func TestNetworkMigrationReportUsesOneSQLiteSnapshotAcrossHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.sqlite3")
	seed, group := newNetworkMigrationReportFixture(t, path)
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	tx, err := reader.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var initialGroups int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM groups`).Scan(&initialGroups); err != nil || initialGroups != 1 {
		t.Fatalf("snapshot start group count=%d err=%v", initialGroups, err)
	}
	writer, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.CreateGroup(Group{ID: "snapshot_concurrent_group",
		OwnerPrincipalID: "inventory_owner", TrustDomainID: "inventory_domain",
		Name: "synthetic concurrent", State: GroupStateActive}); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := buildNetworkMigrationReportSnapshot(tx)
	if err != nil {
		t.Fatal(err)
	}
	if report.GroupCount != initialGroups || report.Tables[networkMigrationTableIndex(report.Tables, "groups")].Rows != initialGroups {
		t.Fatalf("report mixed concurrent commits into its snapshot: groups=%d table_rows=%d", report.GroupCount,
			report.Tables[networkMigrationTableIndex(report.Tables, "groups")].Rows)
	}
	if report.Groups[0].GroupID != group.ID {
		t.Fatalf("snapshot Group changed unexpectedly: %#v", report.Groups)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	after, err := InspectNetworkMigrationReadOnly(path)
	if err != nil || after.GroupCount != initialGroups+1 {
		t.Fatalf("new snapshot missed committed Group: %#v err=%v", after, err)
	}
}

func networkMigrationTableIndex(tables []NetworkMigrationTableInventory, name string) int {
	for i := range tables {
		if tables[i].Table == name {
			return i
		}
	}
	return -1
}

func TestNetworkMigrationBackupDryRunAndRestoreOnDisposableDatabase(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "hub.sqlite3")
	s, _ := newNetworkMigrationReportFixture(t, path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "hub.backup.sqlite3")
	copyNetworkMigrationFile(t, path, backup)
	before, err := InspectNetworkMigrationReadOnly(backup)
	if err != nil || before.GroupCount != 1 {
		t.Fatalf("backup dry-run failed: groups=%d err=%v", before.GroupCount, err)
	}
	backupDigest := networkMigrationFileDigest(t, backup)
	if _, err := InspectNetworkMigrationReadOnly(backup); err != nil {
		t.Fatal(err)
	}
	if got := networkMigrationFileDigest(t, backup); got != backupDigest {
		t.Fatal("read-only dry-run modified backup bytes")
	}
	mutable, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mutable.CreateGroup(Group{ID: "disposable_mutation",
		OwnerPrincipalID: "inventory_owner", TrustDomainID: "inventory_domain",
		Name: "synthetic mutation", State: GroupStateActive}); err != nil {
		mutable.Close()
		t.Fatal(err)
	}
	if err := mutable.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	copyNetworkMigrationFile(t, backup, path)
	restored, err := InspectNetworkMigrationReadOnly(path)
	if err != nil || restored.GroupCount != before.GroupCount || restored.GroupInventoryDigest != before.GroupInventoryDigest {
		t.Fatalf("disposable backup restore did not recover the pre-mutation snapshot: %#v err=%v", restored, err)
	}
}

func copyNetworkMigrationFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func networkMigrationFileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestNetworkMigrationReportBoundsGroupDetailsWithoutDroppingDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded.sqlite3")
	s, _ := newNetworkMigrationReportFixture(t, path)
	defer s.Close()
	for i := 0; i < networkMigrationMaxGroupDetail; i++ {
		if _, err := s.CreateGroup(Group{ID: fmt.Sprintf("bounded_group_%03d", i),
			OwnerPrincipalID: "inventory_owner", TrustDomainID: "inventory_domain",
			Name: "synthetic bounded", State: GroupStateActive}); err != nil {
			t.Fatal(err)
		}
	}
	report, err := s.DryRunNetworkMigration()
	if err != nil {
		t.Fatal(err)
	}
	if report.GroupCount != networkMigrationMaxGroupDetail+1 || len(report.Groups) != networkMigrationMaxGroupDetail ||
		report.GroupDetailsOmitted != 1 || len(report.GroupInventoryDigest) != 64 {
		t.Fatalf("bounded inventory omitted completeness markers: total=%d details=%d omitted=%d digest=%q",
			report.GroupCount, len(report.Groups), report.GroupDetailsOmitted, report.GroupInventoryDigest)
	}
	if strings.Contains(report.Groups[0].GroupID, "reason") {
		t.Fatal("unexpected Group reason in bounded output")
	}
}
