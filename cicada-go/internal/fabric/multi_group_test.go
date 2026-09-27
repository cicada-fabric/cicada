package fabric

import (
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestOneNativeEndpointUsesTwoGroupsWithoutCrossGroupMailboxLeak(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		ID: "grp_secondary", Name: "secondary", OwnerPrincipalID: owner.ID,
		TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Join(JoinInput{GroupID: groupA.ID, PrincipalName: "multi",
		EndpointName: "multi", Harness: "codex", NativeSessionID: "native-multi",
		NodeID: "node-multi"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(store.Membership{
		PrincipalID: first.Endpoint.PrincipalID, GroupID: groupB.ID, Role: "member",
		Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"},
	}); err != nil {
		t.Fatal(err)
	}
	second, err := service.Join(JoinInput{GroupID: groupB.ID, EndpointID: first.Endpoint.ID,
		EndpointName: "multi", Harness: "codex", NativeSessionID: "native-multi",
		NodeID: "node-multi"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Endpoint.ID != first.Endpoint.ID || second.Endpoint.NativeSessionID != first.Endpoint.NativeSessionID ||
		second.BindingID != first.BindingID || second.NetworkCard.GroupID != groupB.ID {
		t.Fatalf("second group replaced native identity or returned wrong scope: first=%#v second=%#v", first, second)
	}
	if _, err := service.Authenticate(first.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("rotated first credential remained valid: %v", err)
	}
	actorA, err := service.AuthenticateForGroup(second.SessionToken, groupA.ID)
	if err != nil {
		t.Fatal(err)
	}
	actorB, err := service.AuthenticateForGroup(second.SessionToken, groupB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if actorA.EndpointID != actorB.EndpointID || actorA.BindingID != actorB.BindingID || actorA.GroupID == actorB.GroupID {
		t.Fatalf("scoped actors should share one binding but distinct memberships: A=%#v B=%#v", actorA, actorB)
	}
	if card, err := service.WhoAmI(actorB); err != nil || card.GroupID != groupB.ID || card.EndpointID != first.Endpoint.ID {
		t.Fatalf("secondary scope whoami=%#v err=%v", card, err)
	}
	peer, err := service.Join(JoinInput{GroupID: groupB.ID, PrincipalName: "peer",
		EndpointName: "peer", Harness: "codex", NativeSessionID: "native-peer",
		NodeID: "node-peer"})
	if err != nil {
		t.Fatal(err)
	}
	peerActor, err := service.Authenticate(peer.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(actorA, ResolveInput{Query: peer.Endpoint.ID}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("group A resolved B-only endpoint: %v", err)
	}
	if card, err := service.Resolve(peerActor, ResolveInput{Query: first.Endpoint.ID}); err != nil || card.GroupID != groupB.ID {
		t.Fatalf("group B cannot resolve multi-group endpoint: %#v err=%v", card, err)
	}
	request, err := service.Ask(peerActor, AskInput{Target: first.Endpoint.ID, Question: "group B question"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Request(actorA, request.RequestID); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("group A read group B request: %v", err)
	}
	if _, err := service.Reply(actorA, ReplyInput{RequestID: request.RequestID, Body: "wrong scope"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("group A replied to group B request: %v", err)
	}
	inA, err := service.Receive(actorA, ReceiveInput{Limit: 10})
	if err != nil || len(inA.Messages) != 0 {
		t.Fatalf("group A read group B mailbox: %#v err=%v", inA, err)
	}
	inB, err := service.Receive(actorB, ReceiveInput{Limit: 10})
	if err != nil || len(inB.Messages) != 1 || inB.Messages[0].ReceiverGroupID != groupB.ID {
		t.Fatalf("group B missed its request: %#v err=%v", inB, err)
	}
	deliveries, err := service.ClaimNodeDeliveries("node-multi", NodeClaimInput{ConsumerID: "node-consumer", Limit: 10})
	if err != nil || len(deliveries) != 1 || deliveries[0].GroupID != groupB.ID ||
		deliveries[0].NativeSessionID != first.Endpoint.NativeSessionID {
		t.Fatalf("Node claim lost group/native scope: %#v err=%v", deliveries, err)
	}
	if _, err := service.Reply(actorB, ReplyInput{RequestID: request.RequestID, Body: "group B answer"}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RevokeMembershipForPrincipalGroup(actorB.PrincipalID, groupB.ID, "leave B"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateForGroup(second.SessionToken, groupB.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked group B still authenticated: %v", err)
	}
	if _, err := service.AuthenticateForGroup(second.SessionToken, groupA.ID); err != nil {
		t.Fatalf("revoking secondary group broke primary binding: %v", err)
	}
	membershipB, err := persistence.GetMembershipByPrincipalGroup(actorB.PrincipalID, groupB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RestoreMembership(membershipB.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.JoinEndpointGroup(first.Endpoint.ID, groupB.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RevokeMembershipForPrincipalGroup(actorA.PrincipalID, groupA.ID, "leave A"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateForGroup(second.SessionToken, groupA.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked primary group still authenticated: %v", err)
	}
	if _, err := service.AuthenticateForGroup(second.SessionToken, groupB.ID); err != nil {
		t.Fatalf("revoking primary group broke remaining secondary binding: %v", err)
	}
	if _, err := persistence.RevokeMembershipForPrincipalGroup(actorB.PrincipalID, groupB.ID, "leave last group"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateForGroup(second.SessionToken, groupB.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("last Group revocation did not fence native binding: %v", err)
	}
}

func TestLeaveGroupPreservesOtherScopeAndLastLeaveFencesBinding(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		ID: "grp_leave_secondary", Name: "secondary", OwnerPrincipalID: owner.ID,
		TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	joinedA, err := service.Join(JoinInput{GroupID: groupA.ID, PrincipalName: "multi",
		EndpointName: "multi", Harness: "codex", NativeSessionID: "native-leave",
		NodeID: "node-leave"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(store.Membership{
		PrincipalID: joinedA.Endpoint.PrincipalID, GroupID: groupB.ID, Role: "member",
		Grants: []string{"directory.read", "message.receive"},
	}); err != nil {
		t.Fatal(err)
	}
	joinedB, err := service.Join(JoinInput{GroupID: groupB.ID, EndpointID: joinedA.Endpoint.ID,
		Harness: "codex", NativeSessionID: "native-leave", NodeID: "node-leave"})
	if err != nil {
		t.Fatal(err)
	}
	actorB, err := service.AuthenticateForGroup(joinedB.SessionToken, groupB.ID)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := service.LeaveGroup(actorB, "leave B only")
	if err != nil || remaining != groupA.ID {
		t.Fatalf("leave B: remaining=%q err=%v", remaining, err)
	}
	if _, err := service.AuthenticateForGroup(joinedB.SessionToken, groupB.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("left Group remained accessible: %v", err)
	}
	actorA, err := service.AuthenticateForGroup(joinedB.SessionToken, groupA.ID)
	if err != nil {
		t.Fatalf("leave B broke Group A: %v", err)
	}
	remaining, err = service.LeaveGroup(actorA, "leave last Group")
	if err != nil || remaining != "" {
		t.Fatalf("last leave: remaining=%q err=%v", remaining, err)
	}
	if _, err := service.AuthenticateForGroup(joinedB.SessionToken, groupA.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("last leave retained native binding: %v", err)
	}
	endpoint, err := persistence.GetEndpointV2(joinedA.Endpoint.ID)
	if err != nil || endpoint.Status != "left" || endpoint.NativeSessionID != "native-leave" {
		t.Fatalf("last leave lost native identity or remained visible: %#v err=%v", endpoint, err)
	}
}

func TestNestedGroupDoesNotInheritPrincipalOrEndpointAuthorization(t *testing.T) {
	service, persistence, parent := newFabricTestService(t)
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	child, err := persistence.CreateGroup(store.Group{ID: "grp_nested_child", Name: "child",
		OwnerPrincipalID: owner.ID, TrustDomainID: "domain", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.SetGroupParent(child.ID, parent.ID, child.Version); err != nil {
		t.Fatal(err)
	}
	joined, err := service.Join(JoinInput{GroupID: parent.ID, PrincipalName: "parent-only",
		EndpointName: "parent-only", Harness: "codex", NativeSessionID: "native-parent-only", NodeID: "node-parent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateForGroup(joined.SessionToken, child.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("child scope inherited from parent = %v", err)
	}
	if _, err := service.Join(JoinInput{GroupID: child.ID, EndpointID: joined.Endpoint.ID,
		Harness: "codex", NativeSessionID: "native-parent-only", NodeID: "node-parent"}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("child Join inherited parent Membership = %v", err)
	}
	if _, err := service.AuthenticateForGroup(joined.SessionToken, parent.ID); err != nil {
		t.Fatalf("failed child Join damaged parent scope: %v", err)
	}
}
