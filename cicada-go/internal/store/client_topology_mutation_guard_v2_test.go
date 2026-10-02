package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"runtime"
	"testing"
	"time"
)

type clientTopologyStoreMutationFixture struct {
	store     *Store
	hubID     string
	groups    [2]*Group
	endpoints [2]*Endpoint
	bindings  [2]*SessionBinding
	members   [2]*Membership
}

// The Store unit fixture retains the existing PREPARING compatibility path.
// Control tests independently cover signed Network/Node enrollment and actual
// authenticated ClientWire packets. These tests use real AcceptClientRequest
// metadata and real OwnerDeviceGrant registration, never a fabricated ledger.
func newClientTopologyStoreMutationFixture(t *testing.T, mapped bool) *clientTopologyStoreMutationFixture {
	t.Helper()
	s, _, _, _ := newClientDeviceFixture(t)
	f := &clientTopologyStoreMutationFixture{store: s}
	if phase, err := s.NetworkMode(); err != nil || phase != NetworkModePreparing {
		t.Fatalf("disposable fixture has no PREPARING compatibility scope: %v", err)
	}
	var err error
	f.hubID, err = s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE principals SET trust_domain_id='owner_a' WHERE id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	networkID := ""
	if mapped {
		networkID = "synthetic-canvas-network"
		if _, err := s.CreateNetwork(Network{ID: networkID, Name: networkID, HubID: f.hubID, OwnerID: "owner_a", State: NetworkStateActive}); err != nil {
			t.Fatal(err)
		}
	}
	for i, suffix := range []string{"source", "target"} {
		f.groups[i], err = s.CreateGroup(Group{ID: "synthetic-canvas-" + suffix, NetworkID: networkID,
			Name: suffix, OwnerPrincipalID: "owner_a", TrustDomainID: "owner_a", State: GroupStateActive, ContextPolicy: "group_scoped"})
		if err != nil {
			t.Fatal(err)
		}
		principal, err := s.CreatePrincipal(Principal{ID: "synthetic-canvas-principal-" + suffix, Name: suffix,
			Kind: PrincipalKindAgent, OwnerID: "owner_a", TrustDomainID: "owner_a", Status: PrincipalStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		f.members[i], err = s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: f.groups[i].ID,
			Roles: []string{"member"}, Grants: []string{"message.send", "message.receive"},
			Authorization: map[string]any{"synthetic.other": true}, Status: MembershipStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		f.endpoints[i], err = s.UpsertEndpoint(Endpoint{ID: "synthetic-canvas-endpoint-" + suffix, Name: suffix,
			Owner: "owner_a", Harness: "codex", NativeSessionID: "synthetic-native-" + suffix, MachineID: "synthetic-node", Status: "online"})
		if err != nil {
			t.Fatal(err)
		}
		f.bindings[i], err = s.CreateSessionBinding(SessionBinding{EndpointID: f.endpoints[i].ID, PrincipalID: principal.ID,
			GroupID: f.groups[i].ID, NativeSessionID: f.endpoints[i].NativeSessionID, NodeID: "synthetic-node"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateMembership(Membership{PrincipalID: f.members[0].PrincipalID, GroupID: f.groups[1].ID,
		Grants: []string{"message.send"}, Status: MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *clientTopologyStoreMutationFixture) request(t *testing.T, operation string) string {
	t.Helper()
	device, err := f.store.GetClientDevice("owner_a", "phone_a")
	if err != nil {
		t.Fatal(err)
	}
	var sequence uint64
	if err := f.store.db.QueryRow(`SELECT COALESCE(MAX(sequence),0)+1 FROM client_device_requests_v2
WHERE owner_id=? AND device_id=? AND session_epoch=?`, device.OwnerID, device.DeviceID, device.SessionEpoch).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	id := NewID("synthetic_canvas")
	digest := sha256.Sum256([]byte(id))
	accepted, err := f.store.AcceptClientRequest(AcceptClientRequestInput{OwnerID: device.OwnerID, DeviceID: device.DeviceID,
		SessionEpoch: device.SessionEpoch, Sequence: sequence, OperationID: id, RouteOperation: operation, CiphertextDigest: hex.EncodeToString(digest[:])})
	if err != nil || accepted == nil || accepted.Outcome != ClientRequestOutcomeNew || accepted.Request == nil {
		t.Fatalf("actual Store request acceptance failed: %v", err)
	}
	return accepted.Request.ID
}

func (f *clientTopologyStoreMutationFixture) proposal() CommunicationLinkProposal {
	return CommunicationLinkProposal{SourceEndpointID: f.endpoints[0].ID, SourceGroupID: f.groups[0].ID,
		TargetEndpointID: f.endpoints[1].ID, TargetGroupID: f.groups[1].ID, ActorOwnerID: "owner_a",
		Direction: "forward", Actions: []string{"send"}, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
}

func (f *clientTopologyStoreMutationFixture) mutate(kind, requestID, ownerID string) error {
	switch kind {
	case "parent":
		_, err := f.store.SetGroupParentForClientRequest(requestID, ownerID, f.groups[0].ID, f.groups[1].ID, f.groups[0].Version)
		return err
	case "join":
		_, err := f.store.JoinEndpointGroupForClientRequest(requestID, ownerID, f.endpoints[0].ID, f.groups[1].ID)
		return err
	case "authorization":
		_, err := f.store.UpdateClientTopologyMembershipAuthorizationForClientRequest(requestID, ownerID, f.groups[0].ID,
			f.members[0].ID, []string{"monitor"}, []string{"message.send", "message.receive", "artifact.share"},
			f.members[0].Authorization, f.members[0].Version)
		return err
	case "proposal":
		input := f.proposal()
		input.ActorOwnerID = ownerID
		_, err := f.store.ProposeCommunicationLinkForClientRequest(requestID, ownerID, input)
		return err
	default:
		panic("unknown synthetic mutation")
	}
}

type clientTopologyStoreMutationSnapshot struct {
	Groups      []Group
	Memberships []Membership
	Endpoints   []Endpoint
	Bindings    []SessionBinding
	Joins       [][]EndpointGroupMembership
	Links       []CommunicationLink
}

func (f *clientTopologyStoreMutationFixture) snapshot(t *testing.T) clientTopologyStoreMutationSnapshot {
	t.Helper()
	var result clientTopologyStoreMutationSnapshot
	for i := range f.groups {
		group, err := f.store.GetGroup(f.groups[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		result.Groups = append(result.Groups, *group)
		members, err := f.store.ListMemberships(MembershipFilter{GroupID: group.ID, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		result.Memberships = append(result.Memberships, members...)
		endpoint, err := f.store.GetEndpointWithIdentity(f.endpoints[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		result.Endpoints = append(result.Endpoints, *endpoint)
		binding, err := f.store.GetSessionBinding(f.bindings[i].ID)
		if err != nil {
			t.Fatal(err)
		}
		result.Bindings = append(result.Bindings, *binding)
		joins, err := f.store.ListEndpointGroupMemberships(endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		result.Joins = append(result.Joins, joins)
	}
	var err error
	result.Links, err = f.store.ListCommunicationLinksForOwner("owner_a", 100)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestClientTopologyMutationGuardCurrentAcceptedOperations(t *testing.T) {
	f := newClientTopologyStoreMutationFixture(t, false)
	for _, kind := range []string{"parent", "join", "authorization", "proposal"} {
		t.Run(kind, func(t *testing.T) {
			before := f.snapshot(t)
			if err := f.mutate(kind, f.request(t, "topology.apply"), "owner_a"); err != nil {
				t.Fatalf("current request rejected: %v", err)
			}
			after := f.snapshot(t)
			if reflect.DeepEqual(before, after) {
				t.Fatal("accepted mutation was not persisted")
			}
			switch kind {
			case "parent":
				if after.Groups[0].ParentGroupID != f.groups[1].ID || after.Groups[0].Version != before.Groups[0].Version+1 {
					t.Fatal("parent CAS changed the wrong Group")
				}
				f.groups[0] = &after.Groups[0]
			case "join":
				if len(after.Joins[0]) != 2 || !reflect.DeepEqual(before.Endpoints, after.Endpoints) || !reflect.DeepEqual(before.Bindings, after.Bindings) {
					t.Fatal("Group join replaced native state")
				}
			case "authorization":
				current, err := f.store.GetMembership(f.members[0].ID)
				if err != nil || current.Version != f.members[0].Version+1 || current.Revision != f.members[0].Revision+1 ||
					current.Role != "monitor" || !reflect.DeepEqual(current.Authorization, f.members[0].Authorization) {
					t.Fatalf("Membership CAS changed unrelated authorization: %v", err)
				}
				f.members[0] = current
			case "proposal":
				if len(after.Links) != 1 || after.Links[0].State != CommunicationLinkProposed || after.Links[0].Version != 1 {
					t.Fatal("proposal acquired routing authority")
				}
			}
		})
	}
}

func TestClientTopologyMutationGuardRequiresAcceptedApply(t *testing.T) {
	f := newClientTopologyStoreMutationFixture(t, false)
	wrongPurpose := f.request(t, "topology.snapshot")
	current := f.request(t, "topology.apply")
	for _, kind := range []string{"parent", "join", "authorization", "proposal"} {
		for _, tc := range []struct{ name, requestID, ownerID string }{
			{"missing_request", "", "owner_a"}, {"forged_request", "synthetic-forged", "owner_a"},
			{"wrong_purpose", wrongPurpose, "owner_a"}, {"wrong_owner", current, "other_owner"},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				before := f.snapshot(t)
				if err := f.mutate(kind, tc.requestID, tc.ownerID); !errors.Is(err, ErrNetworkPermission) {
					t.Fatalf("untrusted accepted request: %v", err)
				}
				if !reflect.DeepEqual(before, f.snapshot(t)) {
					t.Fatal("request refusal changed persisted business state")
				}
			})
		}
	}
	if _, err := f.store.db.Exec(`UPDATE network_mode_v2 SET phase='ACTIVE' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"parent", "join", "authorization", "proposal"} {
		t.Run(kind+"/unmapped_group_in_active_mode", func(t *testing.T) {
			before := f.snapshot(t)
			if err := f.mutate(kind, f.request(t, "topology.apply"), "owner_a"); !errors.Is(err, ErrNetworkPermission) {
				t.Fatalf("legacy unmapped Group bypassed ACTIVE Network mode: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("unmapped Group refusal changed persisted business state")
			}
		})
	}
}

func TestClientTopologyMutationGuardCurrentScopeRefusals(t *testing.T) {
	for _, tc := range []struct{ name, sql, kind string }{
		{"revoked_device", `UPDATE client_devices_v2 SET state='REVOKED'`, "parent"},
		{"old_epoch", `UPDATE client_devices_v2 SET session_epoch=session_epoch+1`, "authorization"},
		{"revoked_owner_key", `UPDATE owner_approval_keys_v2 SET state='REVOKED'`, "parent"},
		{"completed_request", `UPDATE client_device_requests_v2 SET status='FAILED'`, "authorization"},
		{"inactive_owner", `UPDATE principals SET status='revoked' WHERE id='owner_a'`, "parent"},
		{"foreign_group", `UPDATE groups SET owner_principal_id='other_owner'`, "parent"},
		{"inactive_group", `UPDATE groups SET state='PAUSED'`, "authorization"},
		{"inactive_network", `UPDATE networks_v2 SET state='PAUSED'`, "parent"},
		{"foreign_network_owner", `UPDATE networks_v2 SET owner_id='other_owner'`, "authorization"},
		{"foreign_hub", `UPDATE networks_v2 SET hub_id='other_hub'`, "parent"},
		{"foreign_principal", `UPDATE principals SET owner_id='other_owner' WHERE kind='agent'`, "authorization"},
		{"revoked_membership", `UPDATE memberships SET status='revoked'`, "authorization"},
		{"expired_membership", `UPDATE memberships SET expires_at='2000-01-01T00:00:00Z'`, "authorization"},
		{"future_membership", `UPDATE memberships SET effective_at='2999-01-01T00:00:00Z'`, "authorization"},
		{"exhausted_revision", `UPDATE memberships SET revision=9223372036854775807`, "authorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newClientTopologyStoreMutationFixture(t, true)
			request := f.request(t, "topology.apply")
			if _, err := f.store.db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			if err := f.mutate(tc.kind, request, "owner_a"); err == nil {
				t.Fatal("changed current authority accepted")
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("current-scope refusal changed persisted business state")
			}
		})
	}
}

func TestClientTopologyMutationGuardMembershipCAS(t *testing.T) {
	f := newClientTopologyStoreMutationFixture(t, true)
	member := f.members[0]
	for _, tc := range []struct {
		name, groupID string
		version       int64
		want          error
	}{
		{"missing_CAS", member.GroupID, 0, ErrNetworkPermission},
		{"stale_CAS", member.GroupID, member.Version + 1, ErrVersionConflict},
		{"exhausted_CAS", member.GroupID, math.MaxInt64, ErrNetworkPermission},
		{"wrong_group", f.groups[1].ID, member.Version, ErrMembershipNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.snapshot(t)
			_, err := f.store.UpdateClientTopologyMembershipAuthorizationForClientRequest(f.request(t, "topology.apply"), "owner_a",
				tc.groupID, member.ID, []string{"monitor"}, []string{"message.broadcast"}, member.Authorization, tc.version)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Membership CAS guard = %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("Membership CAS refusal changed persisted business state")
			}
		})
	}
}

func TestClientTopologyMutationGuardJoinMembershipLifetime(t *testing.T) {
	for _, tc := range []struct{ name, update string }{
		{"revoked_target", `status='revoked'`},
		{"future_target", `effective_at='2999-01-01T00:00:00Z'`},
		{"expired_target", `expires_at='2000-01-01T00:00:00Z'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newClientTopologyStoreMutationFixture(t, false)
			request := f.request(t, "topology.apply")
			if _, err := f.store.db.Exec(`UPDATE memberships SET `+tc.update+` WHERE principal_id=? AND group_id=?`, f.members[0].PrincipalID, f.groups[1].ID); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			if err := f.mutate("join", request, "owner_a"); !errors.Is(err, ErrMembershipNotActive) {
				t.Fatalf("inactive target Membership joined: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("target Membership refusal changed joins, binding or business versions")
			}
		})
	}
}

func TestClientTopologyMutationGuardExternalStoreRevocationWins(t *testing.T) {
	for _, kind := range []string{"parent", "join", "authorization", "proposal"} {
		t.Run(kind, func(t *testing.T) {
			f := newClientTopologyStoreMutationFixture(t, false)
			request := f.request(t, "topology.apply")
			before := f.snapshot(t)
			var sequence int
			var name, path string
			if err := f.store.db.QueryRow(`PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil {
				t.Fatal(err)
			}
			other, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			tx, err := other.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.Exec(`UPDATE client_devices_v2 SET state='REVOKED' WHERE owner_id='owner_a' AND device_id='phone_a'`); err != nil {
				t.Fatal(err)
			}
			started, result := make(chan struct{}), make(chan error, 1)
			go func() {
				close(started)
				result <- f.mutate(kind, request, "owner_a")
			}()
			<-started
			// Wait until this real Store mutation has entered its critical
			// section while the other connection still owns SQLite's writer
			// lock. No test hook or scheduling sleep stands in for the writer.
			deadline := time.Now().Add(5 * time.Second)
			for {
				if !f.store.mu.TryLock() {
					break
				}
				f.store.mu.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("mutation never entered its Store critical section")
				}
				runtime.Gosched()
			}
			select {
			case err := <-result:
				t.Fatalf("mutation finished before the external writer committed: %v", err)
			default:
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrNetworkPermission) {
					t.Fatalf("second-connection revocation lost to accepted request: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("mutation did not finish after the external writer committed")
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("external revocation refusal changed persisted business state")
			}
		})
	}
}
