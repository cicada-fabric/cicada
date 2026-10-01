package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func clientTopologyAdmissionRequest(t *testing.T, s *Store, operation string, sequence int) string {
	t.Helper()
	device, err := s.GetClientDevice("owner_a", "phone_a")
	if err != nil {
		t.Fatal(err)
	}
	requestID := "req_admission_" + NewID("synthetic")
	stamp := now()
	_, err = s.db.Exec(`INSERT INTO client_device_requests_v2
(id,owner_id,device_id,session_epoch,sequence,operation_id,route_operation,ciphertext_digest,status,created_at,updated_at)
VALUES (?,'owner_a','phone_a',?,?,?,?,?,'PROCESSING',?,?)`, requestID, device.SessionEpoch,
		sequence, requestID, operation, strings.Repeat("b", 64), stamp, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return requestID
}

func topologyAdmissionGroup(t *testing.T, f networkTaskFixture) Group {
	t.Helper()
	group, err := f.s.CreateClientTopologyGroupAtomic(Group{
		NetworkID: f.publisher.scope.NetworkID, OwnerPrincipalID: "owner_a", TrustDomainID: "domain",
		Name: "owner-created admission group", State: GroupStateActive, ContextPolicy: "group_scoped",
		IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated",
	}, "", clientTopologyAdmissionRequest(t, f.s, "topology.apply", 100))
	if err != nil {
		t.Fatal(err)
	}
	return *group
}

func topologyAdmissionPreview(t *testing.T, f networkTaskFixture, group Group, endpoint networkTaskTestEndpoint, sequence int) *ClientTopologyEndpointAdmissionPreview {
	t.Helper()
	preview, err := f.s.PreviewClientTopologyEndpointAdmissionForClientRequest(
		clientTopologyAdmissionRequest(t, f.s, ClientTopologyEndpointAdmissionPreviewOperation, sequence),
		"owner_a", endpoint.scope.NetworkID, group.ID, endpoint.scope.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	return preview
}

func topologyAdmissionInput(preview ClientTopologyEndpointAdmissionPreview) ClientTopologyEndpointAdmissionInput {
	return ClientTopologyEndpointAdmissionInput{
		NetworkID: preview.NetworkID, GroupID: preview.GroupID,
		EndpointID: preview.EndpointID, ExpectedEndpointMigrationState: preview.EndpointMigrationState,
		ExpectedNetworkVersion: preview.NetworkVersion,
		ExpectedGroupVersion:   preview.GroupVersion, ExpectedNetworkMembership: preview.NetworkMembershipRevision,
		ExpectedEndpointNetwork: preview.EndpointNetworkRevision, NetworkAccessBindingID: preview.NetworkAccessBindingID,
		NetworkAccessEpoch: preview.NetworkAccessEpoch, ExpectedMembership: preview.MembershipRevision,
		NativeBindingID: preview.NativeBindingID, NativeBindingEpoch: preview.NativeBindingEpoch,
		ExistingGroupBindingID: preview.ExistingGroupBindingID, ExistingGroupBindingEpoch: preview.ExistingGroupBindingEpoch,
		ExpectedEndpointGroup: preview.EndpointGroupRevision,
	}
}

func TestClientTopologySameOwnerEndpointAdmissionIsPreviewedAndMinimal(t *testing.T) {
	f := newNetworkTaskFixture(t)
	group := topologyAdmissionGroup(t, f)
	preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
	if preview.OwnerPrincipalID != "owner_a" || preview.GroupID != group.ID ||
		preview.EndpointID != f.publisher.scope.EndpointID || preview.NetworkAccessEpoch != f.publisher.scope.AccessEpoch ||
		preview.EndpointMigrationState != EndpointMigrationPendingGroup ||
		preview.NativeBindingID == "" || preview.NativeBindingEpoch == 0 ||
		preview.AdmissionRoles == nil || len(preview.AdmissionRoles) != 1 || preview.AdmissionRoles[0] != "member" ||
		len(preview.AdmissionGrants) != 0 || preview.HistoryIncluded || preview.KeyGrantCreated ||
		!preview.ExistingThreadMemoryRetained {
		t.Fatalf("same-owner preview did not state the minimum admission boundary: %+v", preview)
	}
	input := topologyAdmissionInput(*preview)
	member, endpointGroup, err := f.s.AdmitClientTopologyEndpointForClientRequest(
		clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", input)
	if err != nil {
		t.Fatal(err)
	}
	if member.Status != MembershipStatusActive || member.Role != "member" || len(member.Grants) != 0 ||
		endpointGroup.Status != "active" || endpointGroup.EndpointID != preview.EndpointID ||
		endpointGroup.GroupID != group.ID {
		t.Fatalf("admission granted more than the minimum membership/reference: member=%+v endpointGroup=%+v", member, endpointGroup)
	}
	current, err := f.s.GetMembershipByPrincipalGroup(preview.EndpointPrincipalID, group.ID)
	if err != nil || current.ID != member.ID || len(current.Grants) != 0 {
		t.Fatalf("minimum Membership was not persisted: member=%+v err=%v", current, err)
	}
	if active, err := f.s.IsEndpointGroupActive(preview.EndpointID, group.ID); err != nil || !active {
		t.Fatalf("Endpoint reference was not active under the new minimum Membership: active=%v err=%v", active, err)
	}
	var migrationState string
	if err := f.s.db.QueryRow(`SELECT migration_state FROM fabric_endpoints WHERE id=?`, preview.EndpointID).Scan(&migrationState); err != nil || migrationState != EndpointMigrationReady {
		t.Fatalf("network-only Endpoint was not transitioned atomically into the multi-Group topology model: migration=%q err=%v", migrationState, err)
	}
	var keyGrantCount int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=? AND endpoint_id=?`,
		group.ID, preview.EndpointID).Scan(&keyGrantCount); err != nil {
		t.Fatal(err)
	}
	if keyGrantCount != 0 {
		t.Fatalf("admission silently created a historical/content key grant: %d", keyGrantCount)
	}
}

func TestClientTopologyDirectoryOnlyNetworkMemberAdmissionAddsOnlyGroupMembership(t *testing.T) {
	f := newDirectoryOnlyNetworkFixture(t)
	if _, err := f.s.EnsureNetworkDirectNativeBinding(f.publisher.scope); err != nil {
		t.Fatalf("register current native identity without Network traffic grants: %v", err)
	}
	group := topologyAdmissionGroup(t, f)
	preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
	if preview.AdmissionRoles == nil || len(preview.AdmissionRoles) != 1 || preview.AdmissionRoles[0] != "member" ||
		len(preview.AdmissionGrants) != 0 || preview.HistoryIncluded || preview.KeyGrantCreated {
		t.Fatalf("directory-only admission preview expanded authority: %+v", preview)
	}
	member, endpointGroup, err := f.s.AdmitClientTopologyEndpointForClientRequest(
		clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", topologyAdmissionInput(*preview))
	if err != nil {
		t.Fatal(err)
	}
	if member.Status != MembershipStatusActive || member.Role != "member" || len(member.Grants) != 0 ||
		endpointGroup.Status != "active" || endpointGroup.EndpointID != preview.EndpointID ||
		endpointGroup.GroupID != group.ID {
		t.Fatalf("directory-only admission did not remain member-only: member=%+v endpointGroup=%+v", member, endpointGroup)
	}
	var directCandidateCount, collaborationGrantCount, groupKeyGrantCount int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM network_direct_key_candidates_v2 WHERE network_id=? AND endpoint_id=?`,
		preview.NetworkID, preview.EndpointID).Scan(&directCandidateCount); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM network_collaboration_key_grants_v2 WHERE network_id=? AND endpoint_id=?`,
		preview.NetworkID, preview.EndpointID).Scan(&collaborationGrantCount); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE group_id=? AND endpoint_id=?`,
		preview.GroupID, preview.EndpointID).Scan(&groupKeyGrantCount); err != nil {
		t.Fatal(err)
	}
	if directCandidateCount != 0 || collaborationGrantCount != 0 || groupKeyGrantCount != 0 {
		t.Fatalf("member-only admission created network or Group key authority: direct=%d collaboration=%d group=%d",
			directCandidateCount, collaborationGrantCount, groupKeyGrantCount)
	}
}

func TestClientTopologyEndpointAdmissionFencesOwnerAndCurrentTopology(t *testing.T) {
	t.Run("wrong hub network denied", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		group := topologyAdmissionGroup(t, f)
		if _, err := f.s.db.Exec(`UPDATE networks_v2 SET hub_id='hub_foreign' WHERE id=?`, f.publisher.scope.NetworkID); err != nil {
			t.Fatal(err)
		}
		_, err := f.s.PreviewClientTopologyEndpointAdmissionForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, ClientTopologyEndpointAdmissionPreviewOperation, 101),
			"owner_a", f.publisher.scope.NetworkID, group.ID, f.publisher.scope.EndpointID)
		if !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("Client from another Hub previewed network Endpoint admission: %v", err)
		}
	})
	t.Run("cross-owner group denied", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		group := topologyAdmissionGroup(t, f)
		if _, err := f.s.CreatePrincipal(Principal{ID: "owner_b", Kind: PrincipalKindHuman,
			OwnerID: "owner_b", TrustDomainID: "owner_b", Name: "owner b", Status: PrincipalStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`UPDATE groups SET owner_principal_id='owner_b' WHERE id=?`, group.ID); err != nil {
			t.Fatal(err)
		}
		_, err := f.s.PreviewClientTopologyEndpointAdmissionForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, ClientTopologyEndpointAdmissionPreviewOperation, 101),
			"owner_a", f.publisher.scope.NetworkID, group.ID, f.publisher.scope.EndpointID)
		if !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("Owner could preview an Endpoint admission into another Owner's Group: %v", err)
		}
	})
	t.Run("stale network fence denied atomically", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		group := topologyAdmissionGroup(t, f)
		preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
		if _, err := f.s.db.Exec(`UPDATE networks_v2 SET state='PAUSED' WHERE id=?`, preview.NetworkID); err != nil {
			t.Fatal(err)
		}
		_, _, err := f.s.AdmitClientTopologyEndpointForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", topologyAdmissionInput(*preview))
		if !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("paused Network remained admissible after preview: %v", err)
		}
		if _, err := f.s.GetMembershipByPrincipalGroup(f.publisher.scope.PrincipalID, group.ID); !errors.Is(err, ErrMembershipNotFound) {
			t.Fatalf("failed admission left Group Membership: %v", err)
		}
	})
	t.Run("network membership revoked after preview", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		group := topologyAdmissionGroup(t, f)
		preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
		if _, err := f.s.db.Exec(`UPDATE network_memberships_v2 SET status='revoked'
WHERE network_id=? AND principal_id=?`, preview.NetworkID, f.publisher.scope.PrincipalID); err != nil {
			t.Fatal(err)
		}
		_, _, err := f.s.AdmitClientTopologyEndpointForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", topologyAdmissionInput(*preview))
		if !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("revoked Network Membership admitted without a revision change: %v", err)
		}
		if _, err := f.s.GetMembershipByPrincipalGroup(f.publisher.scope.PrincipalID, group.ID); !errors.Is(err, ErrMembershipNotFound) {
			t.Fatalf("revoked Network membership left Group authority: %v", err)
		}
	})
	t.Run("group manage membership expiry after preview", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		group := topologyAdmissionGroup(t, f)
		preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
		if _, err := f.s.db.Exec(`UPDATE memberships SET expires_at=? WHERE principal_id='owner_a' AND group_id=?`,
			time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), group.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err := f.s.AdmitClientTopologyEndpointForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", topologyAdmissionInput(*preview))
		if !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("expired Group manage Membership remained authorized: %v", err)
		}
		if _, err := f.s.GetMembershipByPrincipalGroup(f.publisher.scope.PrincipalID, group.ID); !errors.Is(err, ErrMembershipNotFound) {
			t.Fatalf("expired Owner authority left Group Membership: %v", err)
		}
	})
	t.Run("native binding stale epoch or revoked status", func(t *testing.T) {
		for _, test := range []struct {
			name string
			sql  string
			want error
		}{
			{name: "epoch", sql: `UPDATE network_direct_native_bindings_v2 SET epoch=epoch+1 WHERE endpoint_id=?`, want: ErrVersionConflict},
			{name: "status", sql: `UPDATE network_direct_native_bindings_v2 SET status='revoked' WHERE endpoint_id=?`, want: ErrNetworkPermission},
		} {
			t.Run(test.name, func(t *testing.T) {
				f := newNetworkTaskFixture(t)
				group := topologyAdmissionGroup(t, f)
				preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
				if _, err := f.s.db.Exec(test.sql, preview.EndpointID); err != nil {
					t.Fatal(err)
				}
				_, _, err := f.s.AdmitClientTopologyEndpointForClientRequest(
					clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", topologyAdmissionInput(*preview))
				if !errors.Is(err, test.want) {
					t.Fatalf("stale native binding was admitted: %v, want %v", err, test.want)
				}
				if _, err := f.s.GetMembershipByPrincipalGroup(f.publisher.scope.PrincipalID, group.ID); !errors.Is(err, ErrMembershipNotFound) {
					t.Fatalf("stale native binding left Group Membership: %v", err)
				}
			})
		}
	})
	t.Run("revoked history is not silently restored", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		group := topologyAdmissionGroup(t, f)
		member, err := f.s.UpsertMembership(Membership{PrincipalID: f.publisher.scope.PrincipalID,
			GroupID: group.ID, Role: "member", Status: MembershipStatusRevoked, Grants: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		preview := topologyAdmissionPreview(t, f, group, f.publisher, 101)
		input := topologyAdmissionInput(*preview)
		input.ExpectedMembership = member.Revision
		_, _, err = f.s.AdmitClientTopologyEndpointForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", input)
		if !errors.Is(err, ErrVersionConflict) && !errors.Is(err, ErrNetworkPermission) {
			t.Fatalf("revoked Group membership was implicitly restored or accepted: %v", err)
		}
		current, getErr := f.s.GetMembership(member.ID)
		if getErr != nil || current.Status != MembershipStatusRevoked || current.Revision != member.Revision {
			t.Fatalf("failed restore changed existing membership: %+v err=%v", current, getErr)
		}
	})
}

func TestClientTopologyEndpointAdmissionUsesDedicatedThreadHistoryGuard(t *testing.T) {
	makePriorGroup := func(t *testing.T, f networkTaskFixture) {
		t.Helper()
		prior, err := f.s.CreateGroup(Group{ID: "group_prior_context_" + NewID("synthetic"),
			NetworkID: f.publisher.scope.NetworkID, Name: "prior shared scope",
			OwnerPrincipalID: "owner_a", TrustDomainID: "domain", State: GroupStateActive,
			ContextPolicy: "group_scoped"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.CreateMembership(Membership{PrincipalID: f.publisher.scope.PrincipalID,
			GroupID: prior.ID, Role: "member", Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.AssociateEndpoint(f.publisher.scope.EndpointID,
			f.publisher.scope.PrincipalID, prior.ID, ""); err != nil {
			t.Fatalf("explicitly migrate Endpoint into prior Group for history fixture: %v", err)
		}
	}

	t.Run("preview rejects known prior Group scope", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		makePriorGroup(t, f)
		target := topologyAdmissionGroup(t, f)
		if _, err := f.s.db.Exec(`UPDATE groups SET context_policy=? WHERE id=?`, DedicatedThreadContextPolicy, target.ID); err != nil {
			t.Fatal(err)
		}
		_, err := f.s.PreviewClientTopologyEndpointAdmissionForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, ClientTopologyEndpointAdmissionPreviewOperation, 101),
			"owner_a", f.publisher.scope.NetworkID, target.ID, f.publisher.scope.EndpointID)
		if !errors.Is(err, ErrDedicatedThreadContextConflict) {
			t.Fatalf("dedicated Group preview ignored known native context history: %v", err)
		}
	})
	t.Run("commit rechecks dedicated policy after preview", func(t *testing.T) {
		f := newNetworkTaskFixture(t)
		makePriorGroup(t, f)
		target := topologyAdmissionGroup(t, f)
		preview := topologyAdmissionPreview(t, f, target, f.publisher, 101)
		if _, err := f.s.db.Exec(`UPDATE groups SET context_policy=? WHERE id=?`, DedicatedThreadContextPolicy, target.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err := f.s.AdmitClientTopologyEndpointForClientRequest(
			clientTopologyAdmissionRequest(t, f.s, "topology.apply", 102), "owner_a", topologyAdmissionInput(*preview))
		if !errors.Is(err, ErrDedicatedThreadContextConflict) {
			t.Fatalf("stale preview bypassed dedicated-thread history guard: %v", err)
		}
		if _, err := f.s.GetMembershipByPrincipalGroup(f.publisher.scope.PrincipalID, target.ID); !errors.Is(err, ErrMembershipNotFound) {
			t.Fatalf("blocked admission left Membership authority: %v", err)
		}
	})
}
