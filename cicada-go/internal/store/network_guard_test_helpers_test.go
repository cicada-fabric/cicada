package store

import (
	"errors"
	"sync"
	"testing"
)

// preparingNetworkActorFixture registers a real local Group/Principal/
// Endpoint relation for tests that exercise legacy routes while the disposable
// Store is still explicitly in PREPARING. It does not manufacture Network
// enrollment or owner-bound Node authority; tests that need ACTIVE Network
// behavior must use the signed Network fixtures instead.
var preparingNetworkActorFixtureMu sync.Mutex

func preparingNetworkActorFixture(t *testing.T, s *Store, groupID, principalID, endpointID string) {
	t.Helper()
	if groupID == "" || principalID == "" || endpointID == "" {
		t.Fatalf("invalid preparing Network actor fixture: group=%q principal=%q endpoint=%q", groupID, principalID, endpointID)
	}
	preparingNetworkActorFixtureMu.Lock()
	defer preparingNetworkActorFixtureMu.Unlock()

	phase, err := s.NetworkMode()
	if err != nil {
		t.Fatal(err)
	}
	if phase != NetworkModePreparing {
		t.Fatalf("legacy actor fixture requires explicit %s migration state; got %q", NetworkModePreparing, phase)
	}

	group, err := s.GetGroup(groupID)
	if errors.Is(err, ErrGroupNotFound) {
		group, err = s.CreateGroup(Group{ID: groupID, Name: groupID, State: GroupStateActive})
	}
	if err != nil {
		t.Fatalf("ensure fixture Group %q: %v", groupID, err)
	}
	if group.NetworkID != "" {
		t.Fatalf("preparing actor fixture cannot stand in for mapped Network %q", group.NetworkID)
	}

	principal, err := s.GetPrincipal(principalID)
	if errors.Is(err, ErrPrincipalNotFound) {
		principal, err = s.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
			Name: "synthetic fixture " + principalID, Status: PrincipalStatusActive})
	}
	if err != nil {
		t.Fatalf("ensure fixture Principal %q: %v", principalID, err)
	}
	if principal.Status != PrincipalStatusActive {
		t.Fatalf("fixture Principal %q is not active", principalID)
	}

	if _, err := s.GetMembershipByPrincipalGroup(principalID, groupID); errors.Is(err, ErrMembershipNotFound) {
		if _, err := s.CreateMembership(Membership{PrincipalID: principalID, GroupID: groupID,
			Role: "member", Status: MembershipStatusActive}); err != nil {
			t.Fatalf("create fixture Group membership: %v", err)
		}
	} else if err != nil {
		t.Fatalf("read fixture Group membership: %v", err)
	}

	endpoint, err := s.GetEndpointV2(endpointID)
	if errors.Is(err, ErrEndpointNotFound) {
		endpoint, err = s.UpsertEndpointV2(Endpoint{ID: endpointID, Name: endpointID,
			Harness: "synthetic-test", NativeSessionID: "synthetic-native-" + endpointID,
			MachineID: "synthetic-node-" + endpointID, PrincipalID: principalID,
			GroupID: groupID, Status: "online"})
	} else if err == nil && (endpoint.PrincipalID != principalID || endpoint.GroupID != groupID) {
		t.Fatalf("fixture endpoint %q belongs to %s/%s, cannot reuse for %s/%s",
			endpointID, endpoint.PrincipalID, endpoint.GroupID, principalID, groupID)
	}
	if err != nil {
		t.Fatalf("ensure explicitly associated fixture Endpoint %q: %v", endpointID, err)
	}
}

func preparingRelayRouteFixture(t *testing.T, s *Store, request FabricRequest) {
	t.Helper()
	preparingNetworkActorFixture(t, s, request.SenderGroupID,
		request.SenderPrincipalID, request.SenderEndpointID)
	preparingNetworkActorFixture(t, s, request.ReceiverGroupID,
		request.ReceiverPrincipalID, request.ReceiverEndpointID)
}

func createPreparingRelayRequestFixture(t *testing.T, s *Store,
	request FabricRequest) (*FabricRequest, error) {
	t.Helper()
	preparingRelayRouteFixture(t, s, request)
	return s.CreateFabricRequest(request)
}

func createPreparingRelayMessageFixture(t *testing.T, s *Store,
	input RelayMessageInput) (*RelayMessageRecord, error) {
	t.Helper()
	security := relayMessageSecurityInput(input)
	preparingNetworkActorFixture(t, s, security.SenderGroupID,
		security.SenderPrincipalID, security.SenderEndpointID)
	preparingNetworkActorFixture(t, s, security.ReceiverGroupID,
		security.ReceiverPrincipalID, security.ReceiverEndpointID)
	return s.EnqueueRelayMessage(input)
}

func preparingRelaySealedSenderFixture(t *testing.T, s *Store) {
	t.Helper()
	preparingNetworkActorFixture(t, s, "group-a", "principal-a", "ep-a")
}

func TestPreparingRelayGuardRejectsRouteWithUnregisteredEndpoint(t *testing.T) {
	s := newRelayV2TestStore(t)
	defer s.Close()
	request := relayTestAsk("rq-unregistered-route", "msg-unregistered-route",
		"digest-unregistered-route", "key-unregistered-route", "body")
	request.SenderEndpointID = "ep-not-registered"
	if _, err := s.CreateFabricRequest(request); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("unregistered sender route was accepted: %v", err)
	}
}

func TestPreparingTaskClaimRejectsUnregisteredEndpoint(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := createTask(t, s, groupID, "synthetic task fixture")
	ready, err := s.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSharedTask(task.ID, ready.Revision,
		"principal-without-endpoint", "ep-without-row", "forged-claim", 300); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("unregistered endpoint claim was accepted: %v", err)
	}
}

func claimPreparingSharedTaskFixture(t *testing.T, s *Store, taskID string,
	expectedRevision int64, principalID, endpointID, key string,
	leaseSeconds int) (*SharedTask, error) {
	t.Helper()
	task, err := s.GetSharedTask(taskID)
	if err != nil {
		return nil, err
	}
	preparingNetworkActorFixture(t, s, task.GroupID, principalID, endpointID)
	return s.ClaimSharedTask(taskID, expectedRevision, principalID, endpointID, key, leaseSeconds)
}

func proposePreparingSharedTaskHandoffFixture(t *testing.T, s *Store,
	input SharedTaskHandoff) (*SharedTaskHandoff, error) {
	t.Helper()
	preparingNetworkActorFixture(t, s, input.GroupID, input.FromPrincipalID, input.FromEndpointID)
	preparingNetworkActorFixture(t, s, input.GroupID, input.ToPrincipalID, input.ToEndpointID)
	return s.ProposeSharedTaskHandoff(input)
}
