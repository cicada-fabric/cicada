package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestEndpointCanJoinSecondGroupWithoutReplacingNativeBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cicada.sqlite3")
	persistence, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	principal, err := persistence.CreatePrincipal(Principal{ID: "pr_multi", Kind: PrincipalKindAgent, Name: "multi"})
	if err != nil {
		t.Fatal(err)
	}
	for _, groupID := range []string{"grp_a", "grp_b"} {
		if _, err := persistence.CreateGroup(Group{ID: groupID, Name: groupID, State: GroupStateActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
			Grants: []string{"message.send"}}); err != nil {
			t.Fatal(err)
		}
	}
	endpoint, err := persistence.UpsertEndpoint(Endpoint{ID: "ep_multi", Name: "multi", Harness: "codex",
		NativeSessionID: "native-multi", MachineID: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.JoinEndpointGroup(endpoint.ID, "grp_b"); !errors.Is(err, ErrEndpointMigrationRequired) {
		t.Fatalf("unjoined endpoint acquired group membership: %v", err)
	}
	binding, err := persistence.CreateSessionBinding(SessionBinding{ID: "bind_multi", EndpointID: endpoint.ID,
		PrincipalID: principal.ID, GroupID: "grp_a", NativeSessionID: endpoint.NativeSessionID,
		NodeID: "node-1", CredentialHash: HashCredential([]byte("multi-credential"))})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := persistence.GetEndpointGroupMembership(endpoint.ID, "grp_a")
	if err != nil || primary.Status != MembershipStatusActive {
		t.Fatalf("primary group was not atomically enrolled with binding: %#v, %v", primary, err)
	}
	second, err := persistence.JoinEndpointGroup(endpoint.ID, "grp_b")
	if err != nil || second.Status != MembershipStatusActive {
		t.Fatalf("second group join failed: %#v, %v", second, err)
	}
	repeated, err := persistence.JoinEndpointGroup(endpoint.ID, "grp_b")
	if err != nil || repeated.Revision != second.Revision {
		t.Fatalf("idempotent join changed revision: %#v, %v", repeated, err)
	}
	groups, err := persistence.ListEndpointGroupMemberships(endpoint.ID)
	if err != nil || len(groups) != 2 {
		t.Fatalf("one endpoint should belong to two groups: %#v, %v", groups, err)
	}
	identity, err := persistence.GetEndpointV2(endpoint.ID)
	if err != nil || identity.ID != endpoint.ID || identity.NativeSessionID != "native-multi" || identity.BindingID != binding.ID || identity.GroupID != "grp_a" {
		t.Fatalf("second group changed stable identity/binding: %#v, %v", identity, err)
	}
	if _, err := persistence.RevokeMembershipForPrincipalGroup(principal.ID, "grp_b", "left group b"); err != nil {
		t.Fatal(err)
	}
	second, err = persistence.GetEndpointGroupMembership(endpoint.ID, "grp_b")
	if err != nil || second.Status != MembershipStatusRevoked {
		t.Fatalf("group b revocation did not fence endpoint relation: %#v, %v", second, err)
	}
	if _, err := persistence.JoinEndpointGroup(endpoint.ID, "grp_b"); !errors.Is(err, ErrMembershipNotActive) {
		t.Fatalf("revoked principal membership rejoined endpoint: %v", err)
	}
	currentBinding, err := persistence.GetSessionBinding(binding.ID)
	if err != nil || currentBinding.Status != SessionBindingStatusActive {
		t.Fatalf("revoking group b invalidated group a native binding: %#v, %v", currentBinding, err)
	}
}

func TestEndpointGroupMigrationBackfillsOnlyReadyExplicitlyJoinedEndpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cicada.sqlite3")
	persistence, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := persistence.CreatePrincipal(Principal{ID: "pr_existing", Kind: PrincipalKindAgent, Name: "existing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateGroup(Group{ID: "grp_existing", Name: "existing", State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: "grp_existing"}); err != nil {
		t.Fatal(err)
	}
	for _, endpointID := range []string{"ep_joined", "ep_unjoined"} {
		if _, err := persistence.UpsertEndpoint(Endpoint{ID: endpointID, Name: endpointID, Harness: "codex",
			NativeSessionID: "native-" + endpointID, MachineID: "node-1"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := persistence.CreateSessionBinding(SessionBinding{EndpointID: "ep_joined",
		PrincipalID: principal.ID, GroupID: "grp_existing", NativeSessionID: "native-ep_joined",
		CredentialHash: HashCredential([]byte("migration-credential"))}); err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	// Construct a v10 snapshot: the READY Endpoint and legacy tables remain,
	// while only the new relation and its ledger entry are absent.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE endpoint_group_memberships; DELETE FROM schema_migrations_v2 WHERE version = 11`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	joined, err := reopened.GetEndpointGroupMembership("ep_joined", "grp_existing")
	if err != nil || joined.Status != MembershipStatusActive {
		t.Fatalf("v10 READY endpoint was not backfilled: %#v, %v", joined, err)
	}
	if groups, err := reopened.ListEndpointGroupMemberships("ep_unjoined"); err != nil || len(groups) != 0 {
		t.Fatalf("unjoined endpoint gained membership: %#v, %v", groups, err)
	}
}
