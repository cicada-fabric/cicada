package fabric

import (
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestJoinCannotCreateOwnerEndpointInForeignGroup(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	ownerB, err := persistence.CreatePrincipal(store.Principal{
		ID: "owner-b", Kind: store.PrincipalKindHuman, OwnerID: "owner-b",
		TrustDomainID: "domain", Name: "owner-b", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		ID: "group-b-owner-b", Name: "group-b", OwnerPrincipalID: ownerB.ID,
		TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Join(JoinInput{
		GroupID: groupB.ID, PrincipalName: "must-not-exist", EndpointName: "must-not-exist",
		Harness: "codex", NativeSessionID: "foreign-group-new-session", NodeID: "node-a",
	})
	if !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("Join into another owner's Group returned %v, want not-authorized", err)
	}
	endpoint, err := persistence.GetEndpointV2BySession("codex", "foreign-group-new-session")
	if err != nil || endpoint != nil {
		t.Fatalf("rejected Join created an Endpoint: %#v err=%v", endpoint, err)
	}
	principals, err := persistence.ListPrincipals(store.PrincipalFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, principal := range principals {
		if principal.Name == "must-not-exist" {
			t.Fatalf("rejected Join created an A-owned Principal in B's Group: %#v", principal)
		}
	}
	groupMemberships, err := persistence.ListMemberships(store.MembershipFilter{GroupID: groupB.ID, Limit: 10})
	if err != nil || len(groupMemberships) != 0 {
		t.Fatalf("rejected Join created Group B membership: %#v err=%v", groupMemberships, err)
	}
	// The Service can still join its configured owner's normal Group.
	joined, err := service.Join(JoinInput{
		GroupID: groupA.ID, PrincipalName: "owner-a-peer", EndpointName: "owner-a-peer",
		Harness: "codex", NativeSessionID: "owner-a-session", NodeID: "node-a",
	})
	if err != nil || joined.Endpoint.Owner != "owner" {
		t.Fatalf("ordinary owner-A Join failed: joined=%#v err=%v", joined, err)
	}
}

func TestJoinCannotRejoinExistingEndpointIntoForeignGroup(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	ownerB, err := persistence.CreatePrincipal(store.Principal{
		ID: "rejoin-owner-b", Kind: store.PrincipalKindHuman, OwnerID: "rejoin-owner-b",
		TrustDomainID: "domain", Name: "owner-b", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		ID: "rejoin-group-b", Name: "group-b", OwnerPrincipalID: ownerB.ID,
		TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := service.Join(JoinInput{
		GroupID: groupA.ID, PrincipalName: "existing-owner-a-peer", EndpointName: "existing-owner-a-peer",
		Harness: "codex", NativeSessionID: "existing-owner-a-session", NodeID: "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Even a separately present membership is not authority for the fixed
	// owner-A Service to move/rejoin its Endpoint into owner B's Group.
	if _, err := persistence.CreateMembership(store.Membership{
		PrincipalID: joined.Endpoint.PrincipalID, GroupID: groupB.ID, Role: "member",
		Grants: []string{"directory.read", "message.send"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.GetEndpointGroupMembership(joined.Endpoint.ID, groupB.ID); !errors.Is(err, store.ErrEndpointGroupNotFound) {
		t.Fatalf("test precondition unexpectedly joined Endpoint to B: %v", err)
	}

	_, err = service.Join(JoinInput{
		GroupID: groupB.ID, EndpointID: joined.Endpoint.ID,
		EndpointName: joined.Endpoint.Name, Harness: "codex", NativeSessionID: joined.Endpoint.NativeSessionID,
		NodeID: "node-a",
	})
	if !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("rejoin into another owner's Group returned %v, want not-authorized", err)
	}
	if _, err := persistence.GetEndpointGroupMembership(joined.Endpoint.ID, groupB.ID); !errors.Is(err, store.ErrEndpointGroupNotFound) {
		t.Fatalf("rejected rejoin added Endpoint-to-Group relation: %v", err)
	}
	active, err := persistence.GetActiveSessionBinding(joined.Endpoint.ID)
	if err != nil || active.ID != joined.BindingID || active.Epoch != joined.BindingEpoch {
		t.Fatalf("rejected rejoin rotated the original binding: binding=%#v err=%v", active, err)
	}
	if _, err := service.Authenticate(joined.SessionToken); err != nil {
		t.Fatalf("rejected rejoin invalidated original A Group session: %v", err)
	}
}

func TestJoinRejectsOwnerGroupFromDifferentTrustDomain(t *testing.T) {
	service, persistence, _ := newFabricTestService(t)
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	foreignDomainGroup, err := persistence.CreateGroup(store.Group{
		ID: "group-owner-a-other-domain", Name: "other-domain", OwnerPrincipalID: owner.ID,
		TrustDomainID: "other-domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Join(JoinInput{
		GroupID: foreignDomainGroup.ID, PrincipalName: "wrong-domain-peer", EndpointName: "wrong-domain-peer",
		Harness: "codex", NativeSessionID: "wrong-domain-session", NodeID: "node-a",
	}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("Join crossed configured trust domain: %v", err)
	}
	if endpoint, err := persistence.GetEndpointV2BySession("codex", "wrong-domain-session"); err != nil || endpoint != nil {
		t.Fatalf("trust-domain rejection created an Endpoint: %#v err=%v", endpoint, err)
	}
}
