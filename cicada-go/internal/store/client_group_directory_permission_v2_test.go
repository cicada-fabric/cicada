package store

import (
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"
)

func newClientDirectoryFixture(t *testing.T) (*atomicTopologyGroupFixture, *Group, *Membership) {
	t.Helper()
	f := newAtomicTopologyGroupFixture(t)
	g, err := f.store.CreateClientTopologyGroupAtomic(atomicGroupInput("net_a", "directory-group"), "", f.request(t, "topology.apply"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.store.CreatePrincipal(Principal{ID: "synthetic-directory-agent", Kind: PrincipalKindAgent, OwnerID: "owner_a", Name: "Synthetic agent", DisplayName: "Synthetic display", Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.store.CreateMembership(Membership{PrincipalID: p.ID, GroupID: g.ID, Role: "monitor", Roles: []string{"monitor", "member"}, Grants: []string{"task.read", "artifact.share"}, Authorization: map[string]any{"synthetic.other": map[string]any{"enabled": true}}, Status: MembershipStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	return f, g, m
}

func TestClientGroupDirectoryPermissionPreservesScopeAndFences(t *testing.T) {
	f, g, m := newClientDirectoryFixture(t)
	changed, name, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(f.request(t, "topology.apply"), "owner_a", g.ID, m.ID, true, m.Version)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Synthetic display" || changed.Version != m.Version+1 || changed.Revision != m.Revision+1 || changed.Role != m.Role || !reflect.DeepEqual(changed.Roles, m.Roles) || !reflect.DeepEqual(changed.Authorization, m.Authorization) || !reflect.DeepEqual(changed.Grants, append(slices.Clone(m.Grants), "directory.read")) {
		t.Fatalf("permission changed unrelated authority: %+v", changed)
	}
	for _, action := range []string{"directory.read", "message.ask", "message.send", "space.read", "group.manage"} {
		allowed, err := f.store.MembershipAllows(m.PrincipalID, g.ID, action)
		if err != nil || allowed != (action == "directory.read") {
			t.Fatalf("%s allowed=%v err=%v", action, allowed, err)
		}
	}
	if _, _, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(f.request(t, "topology.apply"), "owner_a", g.ID, m.ID, false, m.Version); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale preview accepted: %v", err)
	}
	revoked, _, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(f.request(t, "topology.apply"), "owner_a", g.ID, m.ID, false, changed.Version)
	if err != nil || revoked.Version != m.Version+2 || revoked.Revision != m.Revision+2 || !reflect.DeepEqual(revoked.Grants, m.Grants) || !reflect.DeepEqual(revoked.Authorization, m.Authorization) || !reflect.DeepEqual(revoked.Roles, m.Roles) {
		t.Fatalf("exact revoke: %+v %v", revoked, err)
	}
	allowed, err := f.store.MembershipAllows(m.PrincipalID, g.ID, "directory.read")
	if err != nil || allowed {
		t.Fatalf("revoked directory still allowed: %v %v", allowed, err)
	}
}

func TestClientGroupDirectoryPermissionRejectsCurrentAuthorityChanges(t *testing.T) {
	cases := []struct{ name, sql string }{
		{"revoked_device", `UPDATE client_devices_v2 SET state='REVOKED'`},
		{"old_device_epoch", `UPDATE client_devices_v2 SET session_epoch=session_epoch+1`},
		{"revoked_owner_key", `UPDATE owner_approval_keys_v2 SET state='REVOKED'`},
		{"inactive_owner", `UPDATE principals SET status='revoked' WHERE id='owner_a'`},
		{"foreign_network", `UPDATE networks_v2 SET owner_id='other' WHERE id='net_a'`},
		{"inactive_network", `UPDATE networks_v2 SET state='PAUSED' WHERE id='net_a'`},
		{"wrong_hub", `UPDATE networks_v2 SET hub_id='foreign-hub' WHERE id='net_a'`},
		{"inactive_group", `UPDATE groups SET state='PAUSED'`},
		{"foreign_group", `UPDATE groups SET owner_principal_id='other'`},
		{"foreign_principal", `UPDATE principals SET owner_id='other' WHERE id='synthetic-directory-agent'`},
		{"inactive_principal", `UPDATE principals SET status='revoked' WHERE id='synthetic-directory-agent'`},
		{"revoked_membership", `UPDATE memberships SET status='revoked' WHERE principal_id='synthetic-directory-agent'`},
		{"expired_membership", `UPDATE memberships SET expires_at='2000-01-01T00:00:00Z' WHERE principal_id='synthetic-directory-agent'`},
		{"future_membership", `UPDATE memberships SET effective_at='2999-01-01T00:00:00Z' WHERE principal_id='synthetic-directory-agent'`},
		{"malformed_expiry", `UPDATE memberships SET expires_at='bad' WHERE principal_id='synthetic-directory-agent'`},
		{"exhausted_revision", `UPDATE memberships SET revision=9223372036854775807 WHERE principal_id='synthetic-directory-agent'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, g, m := newClientDirectoryFixture(t)
			request := f.request(t, "topology.apply")
			if _, err := f.store.db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			before, err := f.store.GetMembership(m.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(request, "owner_a", g.ID, m.ID, true, m.Version); err == nil {
				t.Fatal("changed authority accepted")
			}
			after, err := f.store.GetMembership(m.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected action changed Membership: %v", err)
			}
		})
	}
}

func TestClientGroupDirectoryPermissionRequiresAcceptedOperationAndCAS(t *testing.T) {
	f, g, m := newClientDirectoryFixture(t)
	cases := []struct {
		name, owner, group, request string
		version                     int64
	}{
		{"missing_request", "owner_a", g.ID, "", m.Version},
		{"forged_request", "owner_a", g.ID, "forged-request", m.Version},
		{"wrong_operation", "owner_a", g.ID, f.request(t, "topology.snapshot"), m.Version},
		{"wrong_owner", "other", g.ID, f.request(t, "topology.apply"), m.Version},
		{"wrong_group", "owner_a", "forged-group", f.request(t, "topology.apply"), m.Version},
		{"missing_CAS", "owner_a", g.ID, f.request(t, "topology.apply"), 0},
		{"stale_CAS", "owner_a", g.ID, f.request(t, "topology.apply"), m.Version + 1},
		{"exhausted_version", "owner_a", g.ID, f.request(t, "topology.apply"), math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(tc.request, tc.owner, tc.group, m.ID, true, tc.version); err == nil {
				t.Fatal("untrusted scope accepted")
			}
		})
	}
	after, err := f.store.GetMembership(m.ID)
	if err != nil || !reflect.DeepEqual(m, after) {
		t.Fatalf("negative input changed member: %v", err)
	}
}

func TestClientGroupDirectoryPermissionRevokesAuthorizationEntry(t *testing.T) {
	f, g, m := newClientDirectoryFixture(t)
	auth := m.Authorization
	auth["directory.read"] = true
	m, err := f.store.UpdateMembershipAuthorization(m.ID, m.Roles, append(m.Grants, "directory.read", "directory.read"), auth, m.Version)
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(f.request(t, "topology.apply"), "owner_a", g.ID, m.ID, false, m.Version)
	if err != nil || slices.Contains(changed.Grants, "directory.read") || changed.Authorization["directory.read"] != nil || changed.Authorization["synthetic.other"] == nil {
		t.Fatalf("parallel grant/authorization not revoked: %+v %v", changed, err)
	}
}

func TestClientGroupDirectoryPermissionExternalStoreRevocationWins(t *testing.T) {
	f, g, m := newClientDirectoryFixture(t)
	request := f.request(t, "topology.apply")
	var dbSequence int
	var dbName, dbPath string
	if err := f.store.db.QueryRow(`PRAGMA database_list`).Scan(&dbSequence, &dbName, &dbPath); err != nil {
		t.Fatal(err)
	}
	other, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE memberships SET status='revoked' WHERE id=?`, m.ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := f.store.SetClientGroupDirectoryPermissionForClientRequest(request, "owner_a", g.ID, m.ID, true, m.Version)
		result <- err
	}()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrMembershipNotActive) {
			t.Fatalf("external revoke lost: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked permission write")
	}
	after, err := f.store.GetMembership(m.ID)
	if err != nil || after.Version != m.Version || slices.Contains(after.Grants, "directory.read") {
		t.Fatalf("external revoked member changed: %+v %v", after, err)
	}
}
