package store

import (
	"errors"
	"testing"
	"time"
)

// This fixture starts with an existing native Group grant, then explicitly
// maps it and enrolls the same Endpoint in two separate Networks. The direct
// SQL enrollment is synthetic trusted setup; the test exercises the live
// Store Guard, signed manifest, revocation and native binding invariants.
func TestNetworkGroupKeyGrantRevisionFence(t *testing.T) {
	f := newGroupEndpointKeyGrantFixture(t)
	legacyManifest := f.preview(t)
	legacyProof := f.sign(t, f.ownerIdentity, legacyManifest)
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	networkA, err := f.store.CreateNetwork(Network{ID: "net-key-grant-a", HubID: hubID,
		OwnerID: f.ownerID, Name: "Key grant A"})
	if err != nil {
		t.Fatal(err)
	}
	networkB, err := f.store.CreateNetwork(Network{ID: "net-key-grant-b", HubID: hubID,
		OwnerID: f.ownerID, Name: "Key grant B"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.store.GetGroup(f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareGroupNetworkMapping(f.groupID, networkA.ID,
		"synthetic explicit mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ApproveGroupNetworkMapping(f.groupID, networkA.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	endpoint, err := f.store.GetEndpointV2(f.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, networkID := range []string{networkA.ID, networkB.ID} {
		if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), networkID,
			endpoint.PrincipalID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'key agent',0,?,?)`, networkID, endpoint.ID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	otherEndpoint, err := f.store.GetEndpointV2(f.otherEndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), networkA.ID,
		otherEndpoint.PrincipalID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
VALUES(?,?,'active',1,'other agent',0,?,?)`, networkA.ID, otherEndpoint.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := f.store.NetworkGuardGroup(endpoint.PrincipalID, otherEndpoint.ID,
		f.groupID, networkA.ID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("mixed Principal/Endpoint identities passed Network Guard: %v", err)
	}
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, legacyProof); err == nil {
		t.Fatal("pre-mapping signed proof became valid after explicit mapping")
	}
	currentManifest := f.preview(t)
	if currentManifest.Digest == legacyManifest.Digest ||
		currentManifest.GroupRevision <= legacyManifest.GroupRevision {
		t.Fatal("mapping failed to advance signed Group authorization generation")
	}
	acceptedProof := f.sign(t, f.ownerIdentity, currentManifest)
	accepted, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, acceptedProof)
	if err != nil || accepted.CurrentStatus != GroupEndpointKeyGrantCurrent {
		t.Fatalf("mapped current grant: %#v %v", accepted, err)
	}
	unacceptedManifest := f.preview(t)
	unacceptedProof := f.sign(t, f.ownerIdentity, unacceptedManifest)
	if err := f.store.RevokeNetworkMembership(networkA.ID, endpoint.PrincipalID, 1); err != nil {
		t.Fatal(err)
	}
	// A fresh signed Network Join can restore the same Principal and Endpoint,
	// but it cannot roll back the signed Group authorization generation.
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND principal_id=?`, stamp, networkA.ID, endpoint.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND endpoint_id=?`, stamp, networkA.ID, endpoint.ID); err != nil {
		t.Fatal(err)
	}
	grant, err := f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
	if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
		t.Fatalf("accepted pre-revoke proof revived: %#v %v", grant, err)
	}
	for _, proof := range [][]byte{acceptedProof, unacceptedProof} {
		if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
			f.endpointID, f.ownerKeyID, proof); err == nil {
			t.Fatal("old signed proof was accepted after revocation and rejoin")
		}
	}
	freshManifest := f.preview(t)
	if freshManifest.Digest == currentManifest.Digest ||
		freshManifest.EndpointJoinRevision <= currentManifest.EndpointJoinRevision {
		t.Fatal("Network revoke failed to advance signed Endpoint join generation")
	}
	freshProof := f.sign(t, f.ownerIdentity, freshManifest)
	fresh, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, freshProof)
	if err != nil || fresh.CurrentStatus != GroupEndpointKeyGrantCurrent {
		t.Fatalf("fresh Owner proof denied: %#v %v", fresh, err)
	}
	var currentEndpointRevision int64
	if err := f.store.db.QueryRow(`SELECT revision FROM endpoint_network_memberships_v2
WHERE network_id=? AND endpoint_id=?`, networkA.ID, endpoint.ID).Scan(&currentEndpointRevision); err != nil {
		t.Fatal(err)
	}
	if err := f.store.LeaveEndpointNetwork(networkA.ID, endpoint.ID, currentEndpointRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND endpoint_id=?`, stamp, networkA.ID, endpoint.ID); err != nil {
		t.Fatal(err)
	}
	grant, err = f.store.GetGroupEndpointKeyGrant(f.ownerID, f.groupID, f.endpointID)
	if err != nil || grant.CurrentStatus != GroupEndpointKeyGrantStale {
		t.Fatalf("Endpoint leave revived old proof: %#v %v", grant, err)
	}
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, freshProof); err == nil {
		t.Fatal("old proof accepted after Endpoint left and rejoined Network")
	}
	lastManifest := f.preview(t)
	lastProof := f.sign(t, f.ownerIdentity, lastManifest)
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		f.endpointID, f.ownerKeyID, lastProof); err != nil {
		t.Fatalf("fresh proof after Endpoint rejoin: %v", err)
	}
	binding, err := f.store.GetSessionBinding(f.bindingID)
	if err != nil || binding.EndpointID != f.endpointID || binding.Epoch != freshManifest.BindingEpoch {
		t.Fatalf("Network revoke changed native writer: %#v %v", binding, err)
	}
	var otherMembership, otherEndpointRevision int64
	if err := f.store.db.QueryRow(`SELECT revision FROM network_memberships_v2 WHERE network_id=? AND principal_id=?`,
		networkB.ID, endpoint.PrincipalID).Scan(&otherMembership); err != nil {
		t.Fatal(err)
	}
	if err := f.store.db.QueryRow(`SELECT revision FROM endpoint_network_memberships_v2 WHERE network_id=? AND endpoint_id=?`,
		networkB.ID, endpoint.ID).Scan(&otherEndpointRevision); err != nil {
		t.Fatal(err)
	}
	if otherMembership != 1 || otherEndpointRevision != 1 {
		t.Fatalf("other Network authorization changed: membership=%d endpoint=%d", otherMembership, otherEndpointRevision)
	}
}
