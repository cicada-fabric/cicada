package store

import (
	"errors"
	"testing"
	"time"
)

func TestNetworkArtifactEndpointLeaveDeniesScopedMetadata(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.store.CreateNetwork(Network{ID: "net-artifact-scope", HubID: hubID,
		OwnerID: f.ownerID, Name: "Artifact scope"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.store.GetGroup(f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareGroupNetworkMapping(group.ID, network.ID,
		"synthetic explicit mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.store.GetEndpointV2(f.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), network.ID,
		endpoint.PrincipalID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'artifact agent',0,?,?)`, network.ID, endpoint.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.PrincipalID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	membership, err = f.store.UpdateMembershipAuthorization(membership.ID,
		membership.Roles, []string{"artifact.read"}, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := f.store.CreateArtifact(Artifact{ID: "synthetic-network-artifact", Name: "evidence",
		Path: "evidence.txt",
		Kind: "evidence", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.store.CreateArtifactRefV2(ArtifactRefV2Input{ArtifactID: legacy.ID,
		GroupID: group.ID, Scopes: []string{ArtifactRefV2ScopeMetadata}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetSessionBinding(f.bindingID)
	if err != nil {
		t.Fatal(err)
	}
	scope := NativeActorScope{PrincipalID: endpoint.PrincipalID, EndpointID: endpoint.ID,
		GroupID: group.ID, NetworkID: network.ID, MembershipID: membership.ID,
		MembershipRevision: membership.Revision, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
	if _, err := f.store.AuthorizeArtifactRefV2ForActor(scope, ref.ID,
		[]string{ArtifactRefV2ScopeMetadata}, time.Now().UTC()); err != nil {
		t.Fatalf("current Endpoint metadata read: %v", err)
	}
	if _, err := f.store.AuthorizeArtifactRefV2ForActor(scope, ref.ID,
		[]string{ArtifactRefV2ScopeSummary}, time.Now().UTC()); !errors.Is(err, ErrArtifactRefV2ScopeDenied) {
		t.Fatalf("single-ref summary read ignored its missing scope: %v", err)
	}
	refs, err := f.store.ListArtifactRefsV2ForActor(scope, 10)
	if err != nil || len(refs) != 1 {
		t.Fatalf("current Endpoint list: %#v %v", refs, err)
	}
	if refs[0].ID != ref.ID || refs[0].Name != "evidence" || refs[0].Summary != "" || refs[0].Digest != "" ||
		len(refs[0].Scopes) != 1 || refs[0].Scopes[0] != ArtifactRefV2ScopeMetadata {
		t.Fatalf("list exposed fields denied by the reference scopes: %#v", refs[0])
	}
	if err := f.store.LeaveEndpointNetwork(network.ID, endpoint.ID, 1); err != nil {
		t.Fatal(err)
	}
	// The Principal remains a member. Only this Endpoint's Network enrollment
	// was revoked; its stale native actor must no longer expose ref metadata.
	if _, err := f.store.AuthorizeArtifactRefV2ForActor(scope, ref.ID,
		[]string{ArtifactRefV2ScopeMetadata}, time.Now().UTC()); !errors.Is(err, ErrArtifactRefV2Denied) {
		t.Fatalf("departed Endpoint read metadata: %v", err)
	}
	if _, err := f.store.ListArtifactRefsV2ForActor(scope, 10); !errors.Is(err, ErrArtifactRefV2Denied) {
		t.Fatalf("departed Endpoint listed metadata: %v", err)
	}
}
