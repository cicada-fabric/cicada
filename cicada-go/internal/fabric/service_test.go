package fabric

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func newFabricTestService(t *testing.T) (*Service, *store.Store, store.Group) {
	t.Helper()
	persistence, err := store.New(filepath.Join(t.TempDir(), "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: "owner", Kind: store.PrincipalKindHuman, OwnerID: "owner",
		TrustDomainID: "domain", Name: "owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		Name: "group-a", OwnerPrincipalID: owner.ID, TrustDomainID: "domain",
		State: store.GroupStateActive, ContextPolicy: "group_scoped",
		IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated",
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(persistence, "owner", "domain")
	if err != nil {
		t.Fatal(err)
	}
	return service, persistence, *group
}

func TestExplicitJoinIsIdempotentAndRotatesBindingCredential(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	input := JoinInput{
		GroupID: group.ID, PrincipalName: "optimizer", EndpointName: "optimizer",
		Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a",
		Workspace: "/workspace/a",
	}
	first, err := service.Join(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Join(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Endpoint.ID != second.Endpoint.ID || first.Endpoint.PrincipalID != second.Endpoint.PrincipalID {
		t.Fatalf("rejoin changed identity: first=%#v second=%#v", first.Endpoint, second.Endpoint)
	}
	if first.BindingID != second.BindingID || second.BindingEpoch <= first.BindingEpoch || !second.Reused {
		t.Fatalf("rejoin did not fence the old binding: first=%#v second=%#v", first, second)
	}
	if _, err := service.Authenticate(first.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old credential remained valid: %v", err)
	}
	actor, err := service.Authenticate(second.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if actor.EndpointID != first.Endpoint.ID || actor.BindingEpoch != second.BindingEpoch {
		t.Fatalf("unexpected actor: %#v", actor)
	}
	membership, err := persistence.GetMembershipByPrincipalGroup(actor.PrincipalID, actor.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	if membership.Role != "member" {
		t.Fatalf("join automatically granted role %q", membership.Role)
	}
}

func TestDirectoryIsGroupScopedAndNeverGuesses(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	join := func(groupID, principal, session, node string) *JoinResult {
		t.Helper()
		result, err := service.Join(JoinInput{
			GroupID: groupID, PrincipalName: principal, EndpointName: "benchmark",
			Harness: "codex", NativeSessionID: session, NodeID: node,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	a := join(groupA.ID, "a", "native-a", "node-a")
	b1 := join(groupA.ID, "b1", "native-b1", "node-b1")
	b2 := join(groupA.ID, "b2", "native-b2", "node-b2")
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		Name: "group-b", OwnerPrincipalID: owner.ID, TrustDomainID: "domain",
		State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := join(groupB.ID, "c", "native-c", "node-c")
	actor, err := service.Authenticate(a.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	cards, err := service.List(actor, "", "", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 3 {
		t.Fatalf("group A directory size=%d cards=%#v", len(cards), cards)
	}
	if _, err := service.Resolve(actor, ResolveInput{Query: c.Endpoint.ID}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("cross-group stable ID leaked: %v", err)
	}
	if _, err := service.Resolve(actor, ResolveInput{Query: "benchmark"}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous alias was guessed: %v", err)
	}
	resolved, err := service.Resolve(actor, ResolveInput{Query: b1.Endpoint.ID})
	if err != nil || resolved.EndpointID != b1.Endpoint.ID {
		t.Fatalf("stable resolve=%#v err=%v", resolved, err)
	}
	_ = b2
}

func TestActorForgeryAndRevocationFailClosed(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	joined, err := service.Join(JoinInput{
		GroupID: group.ID, PrincipalName: "agent", EndpointName: "agent",
		Harness: "codex", NativeSessionID: "native-agent", NodeID: "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	forged := actor
	forged.PrincipalID = "attacker"
	if err := service.Authorize(forged, "directory.read"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forged actor accepted: %v", err)
	}
	if _, err := persistence.RevokeMembership(actor.MembershipID, "test revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked membership authenticated: %v", err)
	}
}

func TestUnjoinedNativeSessionIsNotDirectoryObject(t *testing.T) {
	service, _, group := newFabricTestService(t)
	joined, err := service.Join(JoinInput{
		GroupID: group.ID, PrincipalName: "a", EndpointName: "a",
		Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Resolve(actor, ResolveInput{Query: "native-u"}); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
		t.Fatalf("unjoined session became addressable: %v", err)
	}
}

func TestLeaveRevokesOnlyCurrentSessionBinding(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	joined, err := service.Join(JoinInput{
		GroupID: group.ID, PrincipalName: "agent", EndpointName: "agent",
		Harness: "codex", NativeSessionID: "native-agent", NodeID: "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Leave(actor, "test leave"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("left binding remained authenticated: %v", err)
	}
	membership, err := persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	if membership.Status != store.MembershipStatusActive {
		t.Fatalf("leave revoked principal membership: %#v", membership)
	}
	rejoined, err := service.Join(JoinInput{
		GroupID: group.ID, PrincipalID: actor.PrincipalID, EndpointName: "agent",
		Harness: "codex", NativeSessionID: "native-agent", NodeID: "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rejoined.Endpoint.ID != joined.Endpoint.ID || rejoined.Endpoint.PrincipalID != actor.PrincipalID {
		t.Fatalf("rejoin did not preserve identity: before=%#v after=%#v", joined.Endpoint, rejoined.Endpoint)
	}
}
