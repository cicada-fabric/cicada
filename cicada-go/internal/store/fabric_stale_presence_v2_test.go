package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMarkStaleEndpointsUsesOnlyCurrentLiveV2LeaseAsPresence(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	owner, err := s.CreatePrincipal(Principal{
		ID: "owner_presence", Kind: PrincipalKindHuman, OwnerID: "owner_presence",
		TrustDomainID: "domain_presence", Name: "owner", Status: PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(Group{
		ID: "group_presence", OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID,
		Name: "presence", State: GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}

	createEndpoint := func(endpointID, status, bindingStatus, leaseOwner, leaseExpiresAt string) (*Endpoint, *SessionBinding) {
		t.Helper()
		principal, err := s.CreatePrincipal(Principal{
			ID: "pr_" + endpointID, Kind: PrincipalKindAgent, OwnerID: owner.ID,
			TrustDomainID: owner.TrustDomainID, Name: endpointID, Status: PrincipalStatusActive,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(Membership{
			PrincipalID: principal.ID, GroupID: group.ID, Role: "member",
			Status: MembershipStatusActive,
		}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.UpsertEndpoint(Endpoint{
			ID: endpointID, Name: endpointID, Role: "thread", Harness: "codex",
			NativeSessionID: "native_" + endpointID, MachineID: "node_presence",
			Owner: owner.ID, Status: status,
		})
		if err != nil {
			t.Fatal(err)
		}
		if bindingStatus == "" {
			return endpoint, nil
		}
		binding, err := s.CreateSessionBinding(SessionBinding{
			ID: "bind_" + endpointID, EndpointID: endpoint.ID,
			PrincipalID: principal.ID, GroupID: group.ID,
			NativeSessionID: endpoint.NativeSessionID, NodeID: "node_presence",
			Epoch: 1, LeaseOwner: leaseOwner, LeaseExpiresAt: leaseExpiresAt,
			Status: bindingStatus, CredentialHash: "credential_" + endpointID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return endpoint, binding
	}

	currentNow := time.Now().UTC()
	liveExpiry := currentNow.Add(time.Hour).Format(time.RFC3339Nano)
	expired := currentNow.Add(-time.Minute).Format(time.RFC3339Nano)
	oldSeen := currentNow.Add(-time.Hour).Format(time.RFC3339)
	cutoff := currentNow.Add(-time.Minute).Format(time.RFC3339)

	live, liveBinding := createEndpoint("ep_presence_live", "online", SessionBindingStatusLeased,
		"lease_live", liveExpiry)
	expiredEndpoint, _ := createEndpoint("ep_presence_expired", "online", SessionBindingStatusLeased,
		"lease_expired", expired)
	revoked, _ := createEndpoint("ep_presence_revoked", "online", SessionBindingStatusRevoked,
		"lease_revoked", liveExpiry)
	superseded, _ := createEndpoint("ep_presence_superseded", "online", SessionBindingStatusSuperseded,
		"lease_old_epoch", liveExpiry)
	left, _ := createEndpoint("ep_presence_left", "left", "", "", "")
	offline, _ := createEndpoint("ep_presence_offline", "offline", SessionBindingStatusLeased,
		"lease_offline", liveExpiry)
	legacy, err := s.UpsertEndpoint(Endpoint{
		ID: "ep_presence_legacy", Name: "legacy", Role: "thread", Harness: "codex",
		NativeSessionID: "native_presence_legacy", MachineID: "node_presence", Status: "online",
	})
	if err != nil {
		t.Fatal(err)
	}
	replaced, oldBinding := createEndpoint("ep_presence_replaced", "online", SessionBindingStatusLeased,
		"lease_old", liveExpiry)
	replaced, err = s.GetEndpointV2(replaced.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE session_bindings SET status = ? WHERE id = ?`,
		SessionBindingStatusSuperseded, oldBinding.ID); err != nil {
		t.Fatal(err)
	}
	currentBinding, err := s.CreateSessionBinding(SessionBinding{
		ID: "bind_ep_presence_replaced_current", EndpointID: replaced.ID,
		PrincipalID: "pr_" + replaced.ID, GroupID: group.ID, NativeSessionID: replaced.NativeSessionID,
		NodeID: "node_presence", Epoch: oldBinding.Epoch + 1, LeaseOwner: "lease_current_expired",
		LeaseExpiresAt: expired, Status: SessionBindingStatusLeased,
		CredentialHash: "credential_replaced_current",
	})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.BindingID != oldBinding.ID {
		t.Fatalf("fixture did not initially bind the old epoch: %#v", replaced)
	}

	// This malformed/migrating row points at another Endpoint's valid binding.
	// A lease must never protect an Endpoint other than its own current READY mapping.
	crossPointer, _ := createEndpoint("ep_presence_cross_pointer", "online", "", "", "")
	if _, err := s.db.Exec(`UPDATE fabric_endpoints SET binding_id = ?, migration_state = ? WHERE id = ?`,
		liveBinding.ID, EndpointMigrationReady, crossPointer.ID); err != nil {
		t.Fatal(err)
	}

	for _, endpoint := range []*Endpoint{live, expiredEndpoint, revoked, superseded, left, offline, legacy, replaced, crossPointer} {
		if _, err := s.db.Exec(`UPDATE fabric_endpoints SET last_seen = ? WHERE id = ?`, oldSeen, endpoint.ID); err != nil {
			t.Fatal(err)
		}
	}

	staleIDs, err := s.MarkStaleEndpoints(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	gotStale := make(map[string]bool, len(staleIDs))
	for _, id := range staleIDs {
		gotStale[id] = true
	}
	for _, endpointID := range []string{expiredEndpoint.ID, revoked.ID, superseded.ID, legacy.ID, replaced.ID, crossPointer.ID} {
		if !gotStale[endpointID] {
			t.Errorf("inactive, expired, unbound, or non-current endpoint %q was not marked stale: %#v", endpointID, staleIDs)
		}
	}
	for _, endpointID := range []string{live.ID, left.ID, offline.ID} {
		if gotStale[endpointID] {
			t.Errorf("current live lease or terminal endpoint %q was included in stale results: %#v", endpointID, staleIDs)
		}
	}
	if currentBinding.ID == oldBinding.ID {
		t.Fatal("replacement binding did not use a new identity")
	}

	for endpointID, wantStatus := range map[string]string{
		live.ID: "online", left.ID: "left", offline.ID: "offline",
		expiredEndpoint.ID: "offline", revoked.ID: "offline", superseded.ID: "offline",
		legacy.ID: "offline", replaced.ID: "offline", crossPointer.ID: "offline",
	} {
		endpoint, err := s.GetEndpointV2(endpointID)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Status != wantStatus {
			t.Errorf("Endpoint %q status=%q, want %q", endpointID, endpoint.Status, wantStatus)
		}
		if endpoint.LastSeen != oldSeen {
			t.Errorf("stale sweep rewrote last_seen for %q: got %q want %q", endpointID, endpoint.LastSeen, oldSeen)
		}
	}
}
