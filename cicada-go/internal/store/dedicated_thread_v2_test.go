package store

import (
	"errors"
	"testing"
	"time"
)

func setDedicatedThreadTestNative(t *testing.T, s *Store, endpointID, nativeID string) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE fabric_endpoints SET harness='codex-rebound',native_session_id=? WHERE id=?`, nativeID, endpointID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE session_bindings SET native_session_id=? WHERE endpoint_id=?`, nativeID, endpointID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func dedicatedThreadNetworkGuard(t *testing.T, s *Store, endpointID, networkID string) error {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return guardDedicatedThreadNetworkTrafficTx(tx, endpointID, networkID, time.Now().UTC())
}

func TestDedicatedThreadOrdinaryTargetsCannotReuseKnownSensitiveNative(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	if _, err := f.store.db.Exec(`UPDATE groups SET context_policy=? WHERE id=?`, DedicatedThreadContextPolicy, f.group.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeSessionBinding(f.sourceBinding.ID,
		f.sourceBinding.Epoch, "synthetic native-history test"); err != nil {
		t.Fatal(err)
	}
	alias, _ := addLocalDeliveryEndpoint(t, f.store, "group_other", "ep_same_native_ordinary_target",
		"ordinary target", f.nodeID, []string{"message.receive"}, "session_alias_target")
	setDedicatedThreadTestNative(t, f.store, alias.ID, f.source.NativeSessionID)
	group, err := f.store.CreateGroup(Group{ID: "group_ordinary_third", Name: "ordinary third",
		OwnerPrincipalID: "owner_local", TrustDomainID: "domain_local", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateMembership(Membership{PrincipalID: alias.PrincipalID,
		GroupID: group.ID, Role: "member", Status: MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.JoinEndpointGroup(alias.ID, group.ID); !errors.Is(err, ErrDedicatedThreadContextConflict) {
		t.Fatalf("ordinary target admitted a native with a retained dedicated Group association: %v", err)
	}
}

func TestDedicatedThreadLeaveAndRevocationHistoryFencesNewEndpointIDs(t *testing.T) {
	for _, withdraw := range []string{"leave", "revoke"} {
		t.Run(withdraw, func(t *testing.T) {
			f := newLocalDeliveryAuthorizationFixture(t)
			oldNative := f.source.NativeSessionID
			if withdraw == "leave" {
				if _, err := f.store.LeaveEndpointGroup(f.source.ID, f.group.ID,
					f.sourceBinding.ID, f.sourceBinding.Epoch, "synthetic history test"); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.store.RevokeSessionBinding(f.sourceBinding.ID,
				f.sourceBinding.Epoch, "synthetic history test"); err != nil {
				t.Fatal(err)
			}

			sensitive, err := f.store.CreateGroup(Group{ID: "group_dedicated_history",
				Name: "dedicated history", OwnerPrincipalID: "owner_local",
				TrustDomainID: "domain_local", State: GroupStateActive,
				ContextPolicy: DedicatedThreadContextPolicy})
			if err != nil {
				t.Fatal(err)
			}
			principal, err := f.store.CreatePrincipal(Principal{ID: "pr_new_after_" + withdraw,
				Kind: PrincipalKindAgent, OwnerID: "owner_local", TrustDomainID: "domain_local",
				Name: "new Endpoint", Status: PrincipalStatusActive})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.CreateMembership(Membership{PrincipalID: principal.ID,
				GroupID: sensitive.ID, Role: "member", Status: MembershipStatusActive}); err != nil {
				t.Fatal(err)
			}
			newEndpoint, err := f.store.UpsertEndpoint(Endpoint{ID: "ep_new_after_" + withdraw,
				Name: "new Endpoint", Role: "thread", Harness: "codex-rebound", NativeSessionID: oldNative,
				MachineID: f.nodeID, Owner: "owner_local", Status: "online"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.store.CreateSessionBinding(SessionBinding{EndpointID: newEndpoint.ID,
				PrincipalID: principal.ID, GroupID: sensitive.ID, NativeSessionID: oldNative,
				NodeID: f.nodeID, Epoch: 1, LeaseOwner: "lease_new_after_" + withdraw,
				LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
				Status:         SessionBindingStatusLeased, CredentialHash: localDeliveryDigest("new session " + withdraw)})
			if !errors.Is(err, ErrDedicatedThreadContextConflict) {
				t.Fatalf("new Endpoint ID reused native identity after %s: %v", withdraw, err)
			}
		})
	}
}

func TestDedicatedThreadNetworkPolicyAllowsOrdinarySharingButFencesSensitiveScopes(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := f.store.CreateNetwork(Network{ID: "net_ordinary_thread_context", HubID: hubID,
		Name: "ordinary Network", OwnerID: "owner_local"})
	if err != nil {
		t.Fatal(err)
	}
	if err := dedicatedThreadNetworkGuard(t, f.store, f.source.ID, ordinary.ID); err != nil {
		t.Fatalf("ordinary Network rejected ordinary multi-scope native history: %v", err)
	}

	dedicated, err := f.store.CreateNetwork(Network{ID: "net_dedicated_thread_context", HubID: hubID,
		Name: "dedicated Network", OwnerID: "owner_local", ContextPolicy: DedicatedThreadContextPolicy})
	if err != nil {
		t.Fatal(err)
	}
	if err := dedicatedThreadNetworkGuard(t, f.store, f.source.ID, dedicated.ID); !errors.Is(err, ErrDedicatedThreadContextConflict) {
		t.Fatalf("dedicated Network allowed known Group history outside its scope: %v", err)
	}

	insideGroup, err := f.store.CreateGroup(Group{ID: "group_in_dedicated_network",
		NetworkID: dedicated.ID, Name: "inside dedicated Network", OwnerPrincipalID: "owner_local",
		TrustDomainID: "domain_local", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	insideEndpoint, _ := addLocalDeliveryEndpoint(t, f.store, insideGroup.ID,
		"ep_inside_dedicated_network", "inside", f.nodeID, []string{"message.send"}, "inside-network-session")
	if err := dedicatedThreadNetworkGuard(t, f.store, insideEndpoint.ID, dedicated.ID); err != nil {
		t.Fatalf("dedicated Network rejected its own mapped Group: %v", err)
	}
}
