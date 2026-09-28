package fabric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestGlobalEndpointLeaveThenGroupOnlyJoinDoesNotRestoreNetwork(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterOwnerApprovalKeyLocal("owner", owner.Public()); err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	const (
		nodeID     = "synthetic-leave-node"
		nodeToken  = "synthetic-leave-node-credential"
		deviceID   = "synthetic-leave-client-device"
		nativeID   = "synthetic-leave-native-session"
		networkID  = "network-after-global-leave"
		endpointID = "leave-source"
	)
	now := time.Now().UTC()
	deviceGrant, err := owner.SignOwnerDeviceGrant("owner", deviceID, device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: "owner", OwnerKeyID: owner.Public().ID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	codeHash := sha256.Sum256([]byte("synthetic-global-leave-pairing-code"))
	codeDigest := hex.EncodeToString(codeHash[:])
	if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, "synthetic leave Node",
		HashSessionCredential(nodeToken), codeDigest, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConfirmPendingNodeDeviceBinding("owner", deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	joined, err := service.JoinForNodeCredential(nodeToken, JoinInput{
		GroupID: group.ID, EndpointName: endpointID, Harness: "codex", NativeSessionID: nativeID,
	})
	if err != nil {
		t.Fatal(err)
	}

	network, err := persistence.CreateNetwork(store.Network{ID: networkID, HubID: hubID,
		Name: "synthetic Network", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PrepareGroupNetworkMapping(group.ID, network.ID,
		"synthetic explicit mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := persistence.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	grants := []string{"directory.discover", "directory.publish"}
	invitation := "synthetic-global-leave-invitation-token"
	if err := persistence.IssueNetworkInvitation(network.ID, "owner", "owner", invitation,
		now.Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	proof, err := owner.SignOwnerNetworkJoinGrant("owner", hubID, network.ID, nodeID, nativeID,
		store.NetworkInvitationDigest(invitation), owner.Public().ID, grants, true,
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.JoinNetworkForNodeCredential(nodeToken, NetworkJoinInput{
		NetworkID: network.ID, InvitationToken: invitation, OwnerJoinProof: string(proof),
		Harness: "codex", NativeSessionID: nativeID, EndpointName: endpointID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatalf("current mapped Group actor: %v", err)
	}
	if err := service.Leave(actor, "synthetic global leave"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old Group session survived global leave: %v", err)
	}

	// A later Group Join is not a Network rejoin. The mapped Group's normal
	// admission Guard must reject it before rotating the Endpoint or binding.
	if _, err := service.JoinForNodeCredential(nodeToken, JoinInput{
		GroupID: group.ID, EndpointName: endpointID, Harness: "codex", NativeSessionID: nativeID,
	}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("Group-only rejoin restored a globally-left Network Endpoint: %v", err)
	}
	endpoint, err := persistence.GetEndpointV2(joined.Endpoint.ID)
	if err != nil || endpoint.Status != "left" || endpoint.ID != joined.Endpoint.ID {
		t.Fatalf("denied Group rejoin changed Endpoint: %#v %v", endpoint, err)
	}
	groupMembership, err := persistence.GetEndpointGroupMembership(joined.Endpoint.ID, group.ID)
	if err != nil || groupMembership.Status != "revoked" {
		t.Fatalf("denied Group rejoin restored Group enrollment: %#v %v", groupMembership, err)
	}
	principalMembership, err := persistence.GetNetworkMembership(network.ID, joined.Endpoint.PrincipalID)
	if err != nil || principalMembership.Status != "active" || principalMembership.Revision != 1 {
		t.Fatalf("global leave changed Principal Network membership: %#v %v", principalMembership, err)
	}
	endpointEnrollment, err := persistence.GetEndpointNetworkMembership(network.ID, joined.Endpoint.ID)
	if err != nil || endpointEnrollment.Status != "revoked" || endpointEnrollment.Revision != 2 {
		t.Fatalf("global leave did not revoke Endpoint Network enrollment: %#v %v", endpointEnrollment, err)
	}
	if allowed, err := persistence.NetworkAllows(network.ID, joined.Endpoint.PrincipalID,
		joined.Endpoint.ID, "direct.send"); err != nil || allowed {
		t.Fatalf("Group-only rejoin restored Network direct authority: allowed=%v err=%v", allowed, err)
	}
}
