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

func TestMappedActiveNetworkRunsWithoutControlAndKeepsNativeGroupBinding(t *testing.T) {
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
	const nodeToken = "synthetic-active-network-node-token"
	const nodeID = "synthetic-active-network-node"
	const deviceID = "synthetic-active-network-device"
	now := time.Now().UTC()
	deviceGrant, err := owner.SignOwnerDeviceGrant("owner", deviceID, device.Public(), hubID, e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: "owner", OwnerKeyID: owner.Public().ID, DeviceID: deviceID,
		DevicePublic: device.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	codeHash := sha256.Sum256([]byte("synthetic-active-network-pairing-code"))
	codeDigest := hex.EncodeToString(codeHash[:])
	if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, "synthetic node", HashSessionCredential(nodeToken), codeDigest, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConfirmPendingNodeDeviceBinding("owner", deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	networkA, err := persistence.CreateNetwork(store.Network{ID: "synthetic-network-a", HubID: hubID, Name: "A", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	networkB, err := persistence.CreateNetwork(store.Network{ID: "synthetic-network-b", HubID: hubID, Name: "B", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	joinNetwork := func(networkID, nativeID, name string) *NetworkJoinResult {
		t.Helper()
		invite := "synthetic-invite-" + networkID + "-" + nativeID + "-0123456789"
		grants := []string{"directory.discover", "directory.publish"}
		if err := persistence.IssueNetworkInvitation(networkID, "owner", "owner", invite, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := owner.SignOwnerNetworkJoinGrant("owner", hubID, networkID, nodeID, nativeID, store.NetworkInvitationDigest(invite), owner.Public().ID, grants, true, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		joined, err := service.JoinNetworkForNodeCredential(nodeToken, NetworkJoinInput{NetworkID: networkID, InvitationToken: invite, OwnerJoinProof: string(proof), Harness: "codex", NativeSessionID: nativeID, EndpointName: name})
		if err != nil {
			t.Fatal(err)
		}
		return joined
	}
	firstA := joinNetwork(networkA.ID, "synthetic-native-a", "a")
	firstB := joinNetwork(networkA.ID, "synthetic-native-b", "b")
	if firstA.Endpoint.GroupID != "" || firstB.Endpoint.GroupID != "" {
		t.Fatal("Network registration silently joined a Group")
	}
	if _, err := persistence.PrepareGroupNetworkMapping(group.ID, networkA.ID, "synthetic reviewed mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := persistence.ApproveGroupNetworkMapping(group.ID, networkA.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []store.Endpoint{firstA.Endpoint, firstB.Endpoint} {
		if _, err := persistence.CreateMembership(store.Membership{PrincipalID: endpoint.PrincipalID, GroupID: group.ID, Role: "member", Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"}, Status: store.MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	joinedA, err := service.JoinForNodeCredential(nodeToken, JoinInput{GroupID: group.ID, Harness: "codex", NativeSessionID: "synthetic-native-a"})
	if err != nil {
		t.Fatal(err)
	}
	joinedB, err := service.JoinForNodeCredential(nodeToken, JoinInput{GroupID: group.ID, Harness: "codex", NativeSessionID: "synthetic-native-b"})
	if err != nil {
		t.Fatal(err)
	}
	if joinedA.Endpoint.ID != firstA.Endpoint.ID || joinedB.Endpoint.ID != firstB.Endpoint.ID || joinedA.Endpoint.PrincipalID != firstA.Endpoint.PrincipalID {
		t.Fatal("explicit Group Join replaced Network-only identity")
	}
	bindingBefore, err := persistence.GetActiveSessionBinding(joinedA.Endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondA := joinNetwork(networkB.ID, "synthetic-native-a", "a")
	bindingAfter, err := persistence.GetActiveSessionBinding(joinedA.Endpoint.ID)
	if err != nil || secondA.Endpoint.ID != joinedA.Endpoint.ID || bindingAfter.ID != bindingBefore.ID || bindingAfter.Epoch != bindingBefore.Epoch {
		t.Fatalf("second Network Join changed native writer: before=%#v after=%#v err=%v", bindingBefore, bindingAfter, err)
	}
	if err := persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	actorA, err := service.Authenticate(joinedA.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	actorB, err := service.Authenticate(joinedB.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.TouchEndpoint(joinedB.Endpoint.ID, "offline"); err != nil {
		t.Fatal(err)
	}
	if err := service.Authorize(actorA, "message.ask"); err != nil {
		t.Fatalf("sender authorization failed: %v", err)
	}
	if _, err := service.Resolve(actorA, ResolveInput{Query: joinedB.Endpoint.ID}); err != nil {
		t.Fatalf("offline peer resolution failed: %v", err)
	}
	request, err := service.Ask(actorA, AskInput{Target: joinedB.Endpoint.ID, Question: "synthetic offline question", IdempotencyKey: "synthetic-offline-question"})
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := service.Receive(actorB, ReceiveInput{Limit: 10})
	if err != nil || len(mailbox.Messages) != 1 || mailbox.Messages[0].Message.RequestID != request.RequestID {
		t.Fatalf("mapped offline queue not delivered: %#v %v", mailbox, err)
	}
	if _, err := service.Reply(actorB, ReplyInput{RequestID: request.RequestID, Body: "synthetic reply"}); err != nil {
		t.Fatal(err)
	}
	response, err := service.Receive(actorA, ReceiveInput{Limit: 10})
	if err != nil || len(response.Messages) != 1 || response.Messages[0].Message.Kind != "reply" || response.Messages[0].Message.RequestID != request.RequestID {
		t.Fatalf("mapped standalone RPC failed: %#v %v", response, err)
	}
}

func TestMappedNetworkGuardsLegacyGroupSessionBeforeAndAfterActivation(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	joined, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "legacy", EndpointName: "legacy", Harness: "codex", NativeSessionID: "synthetic-legacy-native", NodeID: "synthetic-node"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "legacy-peer", EndpointName: "legacy-peer", Harness: "codex", NativeSessionID: "synthetic-legacy-peer-native", NodeID: "synthetic-node"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Send(actor, SendInput{Target: peer.Endpoint.ID, Body: "synthetic queued message"}); err != nil {
		t.Fatal(err)
	}
	task, err := persistence.CreateSharedTask(store.SharedTask{GroupID: group.ID, Objective: "synthetic task", AcceptanceCriteria: "synthetic evidence"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = persistence.ReadySharedTask(task.ID, task.Revision, actor.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	networkA, err := persistence.CreateNetwork(store.Network{ID: "network-a", HubID: hubID, Name: "A", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateNetwork(store.Network{ID: "network-b", HubID: hubID, Name: "B", OwnerID: "owner"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Authorize(actor, "directory.read"); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.PrepareGroupNetworkMapping(group.ID, networkA.ID, "synthetic explicit choice", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := persistence.ApproveGroupNetworkMapping(group.ID, networkA.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("mapped group accepted unregistered legacy session: %v", err)
	}
	if err := service.Authorize(actor, "directory.read"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cached actor bypassed mapping: %v", err)
	}
	for _, action := range []string{"task.read", "artifact.read", "message.receive"} {
		if err := service.Authorize(actor, action); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("cached actor bypassed %s: %v", action, err)
		}
	}
	if deliveries, err := service.ClaimNodeDeliveries("synthetic-node", NodeClaimInput{ConsumerID: "synthetic-consumer", Limit: 10}); err != nil || len(deliveries) != 0 {
		t.Fatalf("mapped pending message reached Node: %#v %v", deliveries, err)
	}
	if _, err := persistence.ClaimSharedTask(task.ID, task.Revision, actor.PrincipalID, actor.EndpointID, "synthetic-claim", 300); !errors.Is(err, store.ErrNetworkPermission) {
		t.Fatalf("direct Store Task claim bypassed Network: %v", err)
	}
	if _, err := persistence.AuthorizeArtifactRefV2(actor.PrincipalID, group.ID, "synthetic-ref", []string{store.ArtifactRefV2ScopeMetadata}, time.Now().UTC()); !errors.Is(err, store.ErrArtifactRefV2Denied) {
		t.Fatalf("direct Store artifact read bypassed Network: %v", err)
	}
	if err := persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("active Network accepted old session: %v", err)
	}
	if _, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "new", EndpointName: "new", Harness: "codex", NativeSessionID: "synthetic-new-native", NodeID: "synthetic-node"}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("old Join bypassed Network-only enrollment: %v", err)
	}
}
