package store

import (
	"errors"
	"testing"
	"time"
)

func addNetworkLeaveAccess(t *testing.T, f *sameGroupSealedV1Fixture,
	networkID string, endpoint sameGroupSealedV1EndpointFixture) NetworkAccessScope {
	t.Helper()
	grants := `["direct.receive","direct.send","directory.discover","directory.publish"]`
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json=?,status='active'
WHERE network_id=? AND principal_id=?`, grants, networkID, endpoint.principal); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2
SET status='active',discoverable=1,nickname=?,updated_at=?
WHERE network_id=? AND endpoint_id=?`, endpoint.id, now(), networkID, endpoint.id); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.GetNetworkMembership(networkID, endpoint.principal)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := f.store.GetEndpointNetworkMembership(networkID, endpoint.id)
	if err != nil {
		t.Fatal(err)
	}
	accessID := NewID("netaccess")
	leaseOwner := "network-leave-" + endpoint.id
	leaseExpiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := f.store.db.Exec(`INSERT INTO network_access_sessions_v2
(id,network_id,endpoint_id,principal_id,native_session_id,node_id,epoch,lease_owner,
 lease_expires_at,status,credential_hash,owner_key_id,created_at,updated_at)
VALUES(?,?,?,?,?,?,1,?,?,'active',?,?,?,?)`, accessID, networkID, endpoint.id,
		endpoint.principal, endpoint.binding.NativeSessionID, endpoint.nodeID, leaseOwner,
		leaseExpiry, "synthetic-network-leave-access-"+endpoint.id, f.ownerKeyID, now(), now()); err != nil {
		t.Fatal(err)
	}
	return NetworkAccessScope{NetworkID: networkID, PrincipalID: endpoint.principal,
		EndpointID: endpoint.id, AccessSessionID: accessID, AccessEpoch: 1,
		LeaseOwner: leaseOwner, MembershipID: membership.ID,
		MembershipRevision:         membership.Revision,
		EndpointMembershipRevision: enrollment.Revision}
}

func TestLastGroupLeavePreservesIndependentNetworkAccess(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	if err := f.store.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	sourceScope := addNetworkLeaveAccess(t, f, networkID, f.source)
	_ = addNetworkLeaveAccess(t, f, networkID, f.target)

	beforeBinding, err := f.store.EnsureNetworkDirectNativeBinding(sourceScope)
	if err != nil || beforeBinding.NativeSessionID != f.source.binding.NativeSessionID {
		t.Fatalf("pre-leave Network native binding=%#v err=%v", beforeBinding, err)
	}
	if entries, err := f.store.ListNetworkDirectory(sourceScope, 10); err != nil || len(entries) != 2 {
		t.Fatalf("pre-leave directory entries=%d err=%v", len(entries), err)
	}

	remaining, err := f.store.LeaveEndpointGroup(f.source.id, f.groupID,
		f.source.binding.ID, f.source.binding.Epoch, "synthetic Group-only leave")
	if err != nil || remaining != "" {
		t.Fatalf("last Group leave remaining=%q err=%v", remaining, err)
	}
	endpoint, err := f.store.GetEndpointV2(f.source.id)
	if err != nil || endpoint.Status == "left" || endpoint.GroupID != "" || endpoint.BindingID != "" ||
		endpoint.PrincipalID != f.source.principal || endpoint.NativeSessionID != f.source.binding.NativeSessionID ||
		endpoint.MachineID != f.source.nodeID {
		t.Fatalf("Group-only leave damaged the Network Endpoint: endpoint=%#v err=%v", endpoint, err)
	}
	oldBinding, err := f.store.GetSessionBinding(f.source.binding.ID)
	if err != nil || oldBinding.Status != SessionBindingStatusRevoked || oldBinding.Epoch <= f.source.binding.Epoch {
		t.Fatalf("old Group binding remained current: binding=%#v err=%v", oldBinding, err)
	}
	groupMembership, err := f.store.GetEndpointGroupMembership(f.source.id, f.groupID)
	if err != nil || groupMembership.Status != "revoked" {
		t.Fatalf("Group membership remained active after leave: %#v %v", groupMembership, err)
	}
	if active, err := f.store.IsEndpointGroupActive(f.source.id, f.groupID); err != nil || active {
		t.Fatalf("old Group actor remained active: active=%v err=%v", active, err)
	}
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		f.groupID, f.source.id, f.target.id); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("old Group actor retained peer-key access: %v", err)
	}

	afterBinding, err := f.store.EnsureNetworkDirectNativeBinding(sourceScope)
	if err != nil || afterBinding.ID != beforeBinding.ID || afterBinding.Epoch != beforeBinding.Epoch ||
		afterBinding.NativeSessionID != beforeBinding.NativeSessionID {
		t.Fatalf("Group leave changed independent Network binding: before=%#v after=%#v err=%v",
			beforeBinding, afterBinding, err)
	}
	if entries, err := f.store.ListNetworkDirectory(sourceScope, 10); err != nil || len(entries) != 2 {
		t.Fatalf("Network directory stopped working after Group-only leave: entries=%d err=%v", len(entries), err)
	}
	if allowed, err := f.store.NetworkAllows(networkID, f.source.principal, f.source.id, "direct.send"); err != nil || !allowed {
		t.Fatalf("Network-only direct authority changed after Group leave: allowed=%v err=%v", allowed, err)
	}
}

func TestGlobalEndpointLeaveRevokesOnlyItsNetworkEnrollment(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	if err := f.store.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	sourceScope := addNetworkLeaveAccess(t, f, networkID, f.source)
	targetScope := addNetworkLeaveAccess(t, f, networkID, f.target)
	sourcePrincipalMembership, err := f.store.GetNetworkMembership(networkID, f.source.principal)
	if err != nil {
		t.Fatal(err)
	}
	sourceNetworkBinding, err := f.store.EnsureNetworkDirectNativeBinding(sourceScope)
	if err != nil {
		t.Fatal(err)
	}
	targetNetworkBinding, err := f.store.EnsureNetworkDirectNativeBinding(targetScope)
	if err != nil {
		t.Fatal(err)
	}
	targetMembership, err := f.store.GetNetworkMembership(networkID, f.target.principal)
	if err != nil {
		t.Fatal(err)
	}
	targetEnrollment, err := f.store.GetEndpointNetworkMembership(networkID, f.target.id)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.LeaveEndpointAllGroups(f.source.id, f.source.binding.ID,
		f.source.binding.Epoch, "synthetic global Endpoint leave"); err != nil {
		t.Fatal(err)
	}

	endpoint, err := f.store.GetEndpointV2(f.source.id)
	if err != nil || endpoint.Status != "left" || endpoint.GroupID != f.groupID ||
		endpoint.PrincipalID != f.source.principal || endpoint.NativeSessionID != f.source.binding.NativeSessionID {
		t.Fatalf("denied Group rejoin changed the globally-left Endpoint: %#v %v", endpoint, err)
	}
	groupMembership, err := f.store.GetEndpointGroupMembership(f.source.id, f.groupID)
	if err != nil || groupMembership.Status != "revoked" {
		t.Fatalf("global leave Group edge was restored: %#v %v", groupMembership, err)
	}
	principalMembershipAfter, err := f.store.GetNetworkMembership(networkID, f.source.principal)
	if err != nil || principalMembershipAfter.Status != "active" ||
		principalMembershipAfter.Revision != sourcePrincipalMembership.Revision {
		t.Fatalf("global Endpoint leave changed Principal Network membership: %#v %v",
			principalMembershipAfter, err)
	}
	endpointEnrollment, err := f.store.GetEndpointNetworkMembership(networkID, f.source.id)
	if err != nil || endpointEnrollment.Status != "revoked" ||
		endpointEnrollment.Revision <= sourceScope.EndpointMembershipRevision {
		t.Fatalf("global leave did not revoke this Endpoint's Network enrollment: %#v %v",
			endpointEnrollment, err)
	}
	access, err := f.store.GetNetworkAccessSessionByID(sourceScope.AccessSessionID)
	if err != nil || access.Status != "revoked" || access.Epoch != sourceScope.AccessEpoch+1 ||
		access.LeaseOwner != "" || access.LeaseExpiresAt != "" {
		t.Fatalf("global leave did not fence this Endpoint's Network credential: %#v %v", access, err)
	}
	if _, err := f.store.EnsureNetworkDirectNativeBinding(sourceScope); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old Network access still obtained native authority after global leave: %v", err)
	}
	if entries, err := f.store.ListNetworkDirectory(sourceScope, 10); !errors.Is(err, ErrNetworkPermission) || len(entries) != 0 {
		t.Fatalf("old Network session still read directory: entries=%d err=%v", len(entries), err)
	}
	otherDirectory, err := f.store.ListNetworkDirectory(targetScope, 10)
	if err != nil {
		t.Fatalf("sibling Network session lost directory access: %v", err)
	}
	for _, entry := range otherDirectory {
		if entry.EndpointID == f.source.id {
			t.Fatal("globally-left Endpoint remained visible in the Network directory")
		}
	}
	if allowed, err := f.store.NetworkAllows(networkID, f.source.principal, f.source.id, "direct.send"); err != nil || allowed {
		t.Fatalf("globally-left Endpoint regained Network send: allowed=%v err=%v", allowed, err)
	}
	if err := f.store.NetworkGuardGroup(f.source.principal, f.source.id, f.groupID, networkID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("mapped Group became active without Network rejoin: %v", err)
	}

	otherAccess, err := f.store.GetNetworkAccessSessionByID(targetScope.AccessSessionID)
	if err != nil || otherAccess.Status != "active" || otherAccess.Epoch != targetScope.AccessEpoch ||
		otherAccess.LeaseOwner != targetScope.LeaseOwner {
		t.Fatalf("Endpoint leave changed its sibling access session: %#v %v", otherAccess, err)
	}
	otherPrincipalMembership, err := f.store.GetNetworkMembership(networkID, f.target.principal)
	if err != nil || otherPrincipalMembership.Status != "active" ||
		otherPrincipalMembership.Revision != targetMembership.Revision {
		t.Fatalf("Endpoint leave changed another Principal membership: %#v %v", otherPrincipalMembership, err)
	}
	otherEnrollment, err := f.store.GetEndpointNetworkMembership(networkID, f.target.id)
	if err != nil || otherEnrollment.Status != "active" || otherEnrollment.Revision != targetEnrollment.Revision {
		t.Fatalf("Endpoint leave changed another Endpoint enrollment: %#v %v", otherEnrollment, err)
	}
	otherDirectBinding, err := f.store.EnsureNetworkDirectNativeBinding(targetScope)
	if err != nil || otherDirectBinding.ID != targetNetworkBinding.ID ||
		otherDirectBinding.Epoch != targetNetworkBinding.Epoch {
		t.Fatalf("Endpoint leave changed another Endpoint's direct binding: %#v %v", otherDirectBinding, err)
	}
	if allowed, err := f.store.NetworkAllows(networkID, f.target.principal, f.target.id, "direct.send"); err != nil || !allowed {
		t.Fatalf("Endpoint leave damaged the other Endpoint's Network authority: allowed=%v err=%v", allowed, err)
	}
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		f.groupID, f.source.id, f.target.id); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("old Group Node actor still accessed peers after global leave: %v", err)
	}
	if sourceNetworkBinding.Status != "active" || sourceNetworkBinding.NativeSessionID != f.source.binding.NativeSessionID {
		t.Fatalf("global Endpoint leave mutated another writer identity: %#v", sourceNetworkBinding)
	}
}
