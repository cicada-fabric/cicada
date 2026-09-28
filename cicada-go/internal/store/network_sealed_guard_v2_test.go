package store

import (
	"errors"
	"testing"
)

func mapSealedFixtureNetwork(t *testing.T, f *sameGroupSealedV1Fixture) string {
	t.Helper()
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.store.CreateNetwork(Network{ID: NewID("net"), HubID: hubID,
		Name: "synthetic sealed scope", OwnerID: f.ownerID})
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.store.GetGroup(f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic sealed test mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	return network.ID
}

func enrollSealedFixtureNetwork(t *testing.T, f *sameGroupSealedV1Fixture, networkID string,
	endpoint sameGroupSealedV1EndpointFixture) {
	t.Helper()
	stamp := now()
	if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,status,created_at,updated_at) VALUES(?,?,?,'active',?,?)`,
		NewID("nm"), networkID, endpoint.principal, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,nickname,created_at,updated_at) VALUES(?,?,'active',?,?,?)`,
		networkID, endpoint.id, endpoint.id, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func mappedSealedFixture(t *testing.T) (*sameGroupSealedV1Fixture, string) {
	t.Helper()
	f := newSameGroupSealedV1Fixture(t)
	networkID := mapSealedFixtureNetwork(t, f)
	for _, endpoint := range []sameGroupSealedV1EndpointFixture{f.source, f.target, f.sameNode} {
		enrollSealedFixtureNetwork(t, f, networkID, endpoint)
		// Mapping changes the Group revision; signed key grants must name it.
		f.grant(t, endpoint.id)
	}
	return f, networkID
}

func enqueueMappedSealedSend(t *testing.T, f *sameGroupSealedV1Fixture, messageID string) {
	t.Helper()
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		messageID, "SEND", "", "")
	if _, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
		NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
		SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
		MessageID: messageID, DataScope: SameGroupSealedV1DataScope, Ciphertext: wire,
	}); err != nil {
		t.Fatal(err)
	}
}

func revokeSealedFixtureNetwork(t *testing.T, f *sameGroupSealedV1Fixture, networkID string) {
	t.Helper()
	membership, err := f.store.GetNetworkMembership(networkID, f.target.principal)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeNetworkMembership(networkID, f.target.principal, membership.Revision); err != nil {
		t.Fatal(err)
	}
}

func rejoinSealedFixtureNetwork(t *testing.T, f *sameGroupSealedV1Fixture, networkID string) {
	t.Helper()
	// Synthetic re-enrollment models a new approved Join without changing the
	// original Group/native binding or the already persisted ciphertext.
	stamp := now()
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND principal_id=?`, stamp, networkID, f.target.principal); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND endpoint_id=?`, stamp, networkID, f.target.id); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkSealedPeerKeyRequiresCurrentEnrollment(t *testing.T) {
	f := newSameGroupSealedV1Fixture(t)
	networkID := mapSealedFixtureNetwork(t, f)
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		f.groupID, f.source.id, f.target.id); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("unenrolled mapped pair got peer key: %v", err)
	}
	enrollSealedFixtureNetwork(t, f, networkID, f.source)
	f.grant(t, f.source.id)
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		f.groupID, f.source.id, f.target.id); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("unenrolled mapped target got peer key: %v", err)
	}
	enrollSealedFixtureNetwork(t, f, networkID, f.target)
	f.grant(t, f.target.id)
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		f.groupID, f.source.id, f.target.id); err != nil {
		t.Fatalf("current enrolled pair lost peer key: %v", err)
	}
}

func TestNetworkSealedClaimAndPreInjectionFenceRevocation(t *testing.T) {
	for _, stage := range []string{"before claim", "after claim", "rejoin before old claim", "rejoin before old authorization"} {
		t.Run(stage, func(t *testing.T) {
			f, networkID := mappedSealedFixture(t)
			messageID := NewID("msg")
			enqueueMappedSealedSend(t, f, messageID)
			input := sameGroupSealedV1ClaimInput(f.target, "consumer_network_sealed")
			var attemptID string
			if stage == "after claim" || stage == "rejoin before old authorization" {
				claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential, input)
				if err != nil || len(claims) != 1 {
					t.Fatalf("current mapped message was not claimed: attempts=%d err=%v", len(claims), err)
				}
				attemptID = claims[0].AttemptID
			}
			revokeSealedFixtureNetwork(t, f, networkID)
			if stage == "rejoin before old claim" || stage == "rejoin before old authorization" {
				rejoinSealedFixtureNetwork(t, f, networkID)
			}
			if attemptID == "" {
				claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential, input)
				if err != nil || len(claims) != 0 {
					t.Fatalf("revoked or rejoined member claimed old ciphertext: attempts=%d err=%v", len(claims), err)
				}
				return
			}
			if _, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(f.targetNode.nodeCredential,
				messageID, attemptID); !errors.Is(err, ErrSameGroupSealedV1Denied) {
				t.Fatalf("revoked or rejoined member authorized old attempt: %v", err)
			}
		})
	}
}

func TestNetworkLinkSealedPreInjectionRejectsRejoinedEnrollment(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	// The historical invite fixture predates explicit Endpoint owner fields.
	// A mapped Network must have the same trusted Owner on Endpoint and Principal.
	for _, side := range []struct{ endpointID, ownerID string }{
		{f.link.SourceEndpointID, f.base.source.ownerID},
		{f.link.TargetEndpointID, f.base.target.ownerID},
	} {
		if _, err := f.base.store.db.Exec(`UPDATE fabric_endpoints SET owner=? WHERE id=? AND owner=''`,
			side.ownerID, side.endpointID); err != nil {
			t.Fatal(err)
		}
	}
	// This fixture creates its Link first. Assign Network IDs without changing
	// Group revisions to model the production order (mapping before Link).
	network, err := f.base.store.CreateNetwork(Network{ID: NewID("net"), HubID: f.base.hubID,
		Name: "synthetic cross-Group Link scope", OwnerID: f.base.source.ownerID})
	if err != nil {
		t.Fatal(err)
	}
	for _, groupID := range []string{f.link.SourceGroupID, f.link.TargetGroupID} {
		if _, err := f.base.store.db.Exec(`UPDATE groups SET network_id=? WHERE id=?`, network.ID, groupID); err != nil {
			t.Fatal(err)
		}
	}
	stamp := now()
	for _, side := range []struct{ principalID, endpointID, grant string }{
		{f.link.SourcePrincipalID, f.link.SourceEndpointID, "direct.send"},
		{f.link.TargetPrincipalID, f.link.TargetEndpointID, "direct.receive"},
	} {
		if _, err := f.base.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,grants_json,status,created_at,updated_at)
VALUES(?,?,?,?,'active',?,?)`, NewID("nm"), network.ID, side.principalID,
			`["`+side.grant+`"]`, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,nickname,created_at,updated_at)
VALUES(?,?,'active',?,?,?)`, network.ID, side.endpointID, side.endpointID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
		t.Fatal(err)
	}
	claims, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "network-link-target",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("mapped Link message was not claimed: attempts=%d err=%v", len(claims), err)
	}
	membership, err := f.base.store.GetNetworkMembership(network.ID, f.link.TargetPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.base.store.RevokeNetworkMembership(network.ID, f.link.TargetPrincipalID, membership.Revision); err != nil {
		t.Fatal(err)
	}
	// The same target is enrolled again before it attempts to consume the old
	// claim. Current grants alone would permit this stale ciphertext.
	stamp = now()
	if _, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND principal_id=?`, stamp, network.ID, f.link.TargetPrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active',revision=revision+1,updated_at=?
WHERE network_id=? AND endpoint_id=?`, stamp, network.ID, f.link.TargetEndpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, f.messageID, claims[0].AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("rejoined Link endpoint authorized pre-revocation ciphertext: %v", err)
	}
}
