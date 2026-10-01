package store

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type atomicTopologyGroupFixture struct {
	store *Store
	hubID string
	next  int
}

func newAtomicTopologyGroupFixture(t *testing.T) *atomicTopologyGroupFixture {
	t.Helper()
	s, _, _, _ := newClientDeviceFixture(t)
	if _, err := s.db.Exec(`UPDATE principals SET trust_domain_id='owner_a' WHERE id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"net_a", "net_b"} {
		if _, err := s.CreateNetwork(Network{ID: id, HubID: hubID, Name: id,
			OwnerID: "owner_a", State: NetworkStateActive}); err != nil {
			t.Fatal(err)
		}
	}
	return &atomicTopologyGroupFixture{store: s, hubID: hubID}
}

func (f *atomicTopologyGroupFixture) request(t *testing.T, operation string) string {
	t.Helper()
	f.next++
	id := "req_topology_" + NewID("synthetic")
	device, err := f.store.GetClientDevice("owner_a", "phone_a")
	if err != nil {
		t.Fatal(err)
	}
	timestamp := now()
	_, err = f.store.db.Exec(`INSERT INTO client_device_requests_v2
(id,owner_id,device_id,session_epoch,sequence,operation_id,route_operation,
 ciphertext_digest,status,created_at,updated_at)
VALUES (?,'owner_a','phone_a',?,?,?,? ,?,'PROCESSING',?,?)`,
		id, device.SessionEpoch, f.next, id, operation, strings.Repeat("a", 64), timestamp, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func atomicGroupInput(networkID, name string) Group {
	return Group{NetworkID: networkID, OwnerPrincipalID: "owner_a", TrustDomainID: "owner_a",
		Name: name, State: GroupStateActive, ContextPolicy: "group_scoped",
		IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated"}
}

func countAtomicGroups(t *testing.T, s *Store, name string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM groups WHERE name=?`, name).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countAtomicOwnerMemberships(t *testing.T, s *Store) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM memberships WHERE principal_id='owner_a'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestClientTopologyNestedGroupCreateAtomicRetryAndMembership(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	root, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "root"), "",
		f.request(t, "topology.apply"))
	if err != nil {
		t.Fatal(err)
	}
	requestID := f.request(t, "topology.apply")
	input := atomicGroupInput("net_a", "child")
	child, err := f.store.CreateClientTopologyGroupAtomic(input, root.ID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if child.ParentGroupID != root.ID || child.NetworkID != root.NetworkID ||
		child.Version != 2 || child.Revision != 2 {
		t.Fatalf("nested Group projection: %+v", child)
	}
	member, err := f.store.GetMembershipByPrincipalGroup("owner_a", child.ID)
	if err != nil || member.Status != MembershipStatusActive || member.Role != "owner" ||
		!slices.Contains(member.Grants, "group.manage") {
		t.Fatalf("owner Membership: %+v, %v", member, err)
	}
	retried, err := f.store.CreateClientTopologyGroupAtomic(input, root.ID, requestID)
	if err != nil || retried.ID != child.ID || retried.Version != child.Version ||
		countAtomicGroups(t, f.store, "child") != 1 {
		t.Fatalf("lost-response retry created a second Group: %+v, %v", retried, err)
	}
	tampered := input
	tampered.Name = "different-child"
	if _, err := f.store.CreateClientTopologyGroupAtomic(tampered, root.ID, requestID); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("changed request input accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, "different-child") != 0 {
		t.Fatal("changed retry inserted a Group")
	}
}

func TestClientTopologyGroupCreateCustomTrustDomainAndForgery(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	if _, err := f.store.db.Exec(`UPDATE principals SET trust_domain_id='team-domain' WHERE id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	input := atomicGroupInput("net_a", "custom-domain-root")
	input.TrustDomainID = "team-domain"
	root, err := f.store.CreateClientTopologyGroupAtomic(input, "", f.request(t, "topology.apply"))
	if err != nil || root.TrustDomainID != "team-domain" {
		t.Fatalf("legitimate custom trust domain rejected: %+v, %v", root, err)
	}
	child := atomicGroupInput("net_a", "custom-domain-child")
	child.TrustDomainID = "team-domain"
	if _, err := f.store.CreateClientTopologyGroupAtomic(child, root.ID, f.request(t, "topology.apply")); err != nil {
		t.Fatalf("custom-domain parent rejected: %v", err)
	}
	forged := atomicGroupInput("net_a", "forged-domain-child")
	if _, err := f.store.CreateClientTopologyGroupAtomic(forged, root.ID, f.request(t, "topology.apply")); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("forged owner trust domain accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, forged.Name) != 0 {
		t.Fatal("forged trust domain left a Group")
	}
}

func TestClientTopologyGroupCreateRequiresGuardLockRow(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	if _, err := f.store.db.Exec(`DELETE FROM client_topology_group_create_guard_v2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	input := atomicGroupInput("net_a", "missing-lock-row")
	if _, err := f.store.CreateClientTopologyGroupAtomic(input, "", f.request(t, "topology.apply")); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("missing writer guard row accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, input.Name) != 0 {
		t.Fatal("missing writer guard row left a Group")
	}
}

func TestClientTopologyNestedGroupFailuresLeaveNoGroupOrMembership(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	root, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "root"), "",
		f.request(t, "topology.apply"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		group     Group
		parent    string
		operation string
		want      error
	}{
		{"wrong_network", atomicGroupInput("net_b", "wrong-network-child"), root.ID, "topology.apply", ErrNetworkConflict},
		{"missing_parent", atomicGroupInput("net_a", "missing-parent-child"), "missing", "topology.apply", ErrGroupNotFound},
		{"status_route", atomicGroupInput("net_a", "status-route-child"), root.ID, "status.snapshot", ErrNetworkPermission},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeMemberships := countAtomicOwnerMemberships(t, f.store)
			if _, err := f.store.CreateClientTopologyGroupAtomic(tt.group, tt.parent,
				f.request(t, tt.operation)); !errors.Is(err, tt.want) {
				t.Fatalf("create err=%v, want %v", err, tt.want)
			}
			if countAtomicGroups(t, f.store, tt.group.Name) != 0 {
				t.Fatal("failed create left a root Group")
			}
			if countAtomicOwnerMemberships(t, f.store) != beforeMemberships {
				t.Fatal("failed create left an owner Membership")
			}
		})
	}
	if _, err := f.store.RevokeMembershipForPrincipalGroup("owner_a", root.ID, "synthetic revoke"); err != nil {
		t.Fatal(err)
	}
	beforeMemberships := countAtomicOwnerMemberships(t, f.store)
	if _, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "revoked-parent-child"),
		root.ID, f.request(t, "topology.apply")); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked parent group.manage accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, "revoked-parent-child") != 0 {
		t.Fatal("revoked parent left a child Group")
	}
	if countAtomicOwnerMemberships(t, f.store) != beforeMemberships {
		t.Fatal("revoked parent left an owner Membership")
	}
}

func TestClientTopologyGroupCreateMembershipFailureRollsBackAndRetries(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	requestID := f.request(t, "topology.apply")
	input := atomicGroupInput("net_a", "trigger-failed-child")
	_, err := f.store.db.Exec(`CREATE TRIGGER synthetic_membership_failure
BEFORE INSERT ON memberships WHEN NEW.principal_id='owner_a'
BEGIN SELECT RAISE(ABORT,'synthetic membership insert failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateClientTopologyGroupAtomic(input, "", requestID); err == nil {
		t.Fatal("injected Membership failure was accepted")
	}
	if countAtomicGroups(t, f.store, input.Name) != 0 {
		t.Fatal("Membership failure left an orphan Group")
	}
	var ledger int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM client_topology_group_creates_v2 WHERE request_id=?`,
		requestID).Scan(&ledger); err != nil || ledger != 0 {
		t.Fatalf("failed transaction left request ledger=%d err=%v", ledger, err)
	}
	if _, err := f.store.db.Exec(`DROP TRIGGER synthetic_membership_failure`); err != nil {
		t.Fatal(err)
	}
	created, err := f.store.CreateClientTopologyGroupAtomic(input, "", requestID)
	if err != nil || created.ID == "" || countAtomicGroups(t, f.store, input.Name) != 1 {
		t.Fatalf("same request failed after rollback: %+v, %v", created, err)
	}
}

func TestClientTopologyGroupCreateCurrentDeviceAndNetworkGuard(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	requestID := f.request(t, "topology.apply")
	device, err := f.store.GetClientDevice("owner_a", "phone_a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeClientDevice("owner_a", "phone_a", device.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "revoked-device"),
		"", requestID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked device accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, "revoked-device") != 0 {
		t.Fatal("revoked device left a Group")
	}
	// An active Network is not authority for a Client-less direct Control call.
	if _, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "missing-request"),
		"", ""); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("Client-less ACTIVE Network create accepted: %v", err)
	}
}

func TestClientTopologyGroupCreateRejectsForeignOwnerHubAndRevokedKey(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change string
	}{
		{"foreign_owner", `UPDATE networks_v2 SET owner_id='owner_b' WHERE id='net_a'`},
		{"foreign_hub", `UPDATE networks_v2 SET hub_id='foreign_hub' WHERE id='net_a'`},
		{"revoked_owner_key", `UPDATE owner_approval_keys_v2 SET state='REVOKED' WHERE owner_id='owner_a'`},
		{"stale_session_epoch", `UPDATE client_devices_v2 SET session_epoch=session_epoch+1 WHERE owner_id='owner_a'`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newAtomicTopologyGroupFixture(t)
			requestID := f.request(t, "topology.apply")
			if _, err := f.store.db.Exec(tt.change); err != nil {
				t.Fatal(err)
			}
			input := atomicGroupInput("net_a", tt.name)
			if _, err := f.store.CreateClientTopologyGroupAtomic(input, "", requestID); !errors.Is(err, ErrNetworkPermission) {
				t.Fatalf("stale or foreign authority accepted: %v", err)
			}
			if countAtomicGroups(t, f.store, input.Name) != 0 || countAtomicOwnerMemberships(t, f.store) != 0 {
				t.Fatal("rejected request left a Group or Membership")
			}
		})
	}
}

func TestClientTopologyGroupCreateRejectsPausedNetworkAndArchivedParent(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	root, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "root"), "",
		f.request(t, "topology.apply"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE networks_v2 SET state='PAUSED' WHERE id='net_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "paused-network"),
		"", f.request(t, "topology.apply")); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("paused Network accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, "paused-network") != 0 {
		t.Fatal("paused Network left a Group")
	}
	if _, err := f.store.db.Exec(`UPDATE networks_v2 SET state='ACTIVE' WHERE id='net_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE groups SET state='ARCHIVED' WHERE id=?`, root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "archived-parent"),
		root.ID, f.request(t, "topology.apply")); !errors.Is(err, ErrGroupParentOwnerScope) {
		t.Fatalf("archived parent accepted: %v", err)
	}
	if countAtomicGroups(t, f.store, "archived-parent") != 0 {
		t.Fatal("archived parent left a Group")
	}
}

func TestClientTopologyGroupCreateV41MigrationRestart(t *testing.T) {
	f := newAtomicTopologyGroupFixture(t)
	requestID := f.request(t, "topology.apply")
	input := atomicGroupInput("net_a", "restart-root")
	root, err := f.store.CreateClientTopologyGroupAtomic(input, "", requestID)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := f.store.db.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&version); err != nil || version != CurrentV2SchemaVersion {
		t.Fatalf("schema version=%d want=%d err=%v", version, CurrentV2SchemaVersion, err)
	}
	// Keep this independent of the fixture Store's lifetime and prove that a
	// second handle sees the v41 request map and existing parent Group after
	// all current additive migrations have also been applied.
	var path string
	if err := f.store.db.QueryRow(`PRAGMA database_list`).Scan(new(int), new(string), &path); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetGroup(root.ID)
	if err != nil || got.ID != root.ID {
		t.Fatalf("v41 restart lost Group: %+v, %v", got, err)
	}
	var mapped string
	if err := reopened.db.QueryRow(`SELECT group_id FROM client_topology_group_creates_v2 WHERE group_id=?`,
		root.ID).Scan(&mapped); err != nil || mapped != root.ID {
		t.Fatalf("v41 restart lost request mapping: %q %v", mapped, err)
	}
	retried, err := reopened.CreateClientTopologyGroupAtomic(input, "", requestID)
	if err != nil || retried.ID != root.ID || countAtomicGroups(t, reopened, input.Name) != 1 {
		t.Fatalf("v41 restart retry duplicated Group: %+v, %v", retried, err)
	}
}
