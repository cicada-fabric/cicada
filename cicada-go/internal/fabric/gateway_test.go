package fabric

import (
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func grantRepresentative(t *testing.T, persistence *store.Store, actor Actor) {
	t.Helper()
	membership, err := persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	grants := append([]string(nil), membership.Grants...)
	grants = append(grants, "federation.represent")
	if _, err := persistence.UpdateMembershipAuthorization(membership.ID, []string{"monitor"}, grants, membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredFederationBodyWritersPreserveHistoricalRead(t *testing.T) {
	service, persistence, groupA := newFabricTestService(t)
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{
		Name: "group-b", OwnerPrincipalID: owner.ID, TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, actorA1 := joinFabricPeer(t, service, groupA.ID, "a1", "native-a1", "node-a")
	ma, actorMAOld := joinFabricPeer(t, service, groupA.ID, "ma", "native-ma", "node-a")
	mb, actorMBOld := joinFabricPeer(t, service, groupB.ID, "mb", "native-mb", "node-b")
	grantRepresentative(t, persistence, actorMAOld)
	grantRepresentative(t, persistence, actorMBOld)
	actorMA, err := service.Authenticate(ma.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	actorMB, err := service.Authenticate(mb.SessionToken)
	if err != nil {
		t.Fatal(err)
	}

	contract, err := persistence.CreateFederationContract(store.FederationContract{
		SourceGroupID: groupA.ID, TargetGroupID: groupB.ID,
		Capability: "benchmark.read", Scopes: []string{"public-result"},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	repA, err := persistence.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: groupA.ID, PrincipalID: actorMA.PrincipalID, EndpointID: actorMA.EndpointID,
		Scopes: []string{"public-result"}, ContractID: contract.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	repB, err := persistence.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: groupB.ID, PrincipalID: actorMB.PrincipalID, EndpointID: actorMB.EndpointID,
		Scopes: []string{"public-result"}, ContractID: contract.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339)
	historical, err := persistence.CreateFederationRequest(store.FederationRequest{
		ID: "frequest_historical", OriginRequestID: "rq_historical",
		SourceGroupID: groupA.ID, TargetGroupID: groupB.ID,
		SourceRepresentativeEndpointID:   actorMA.EndpointID,
		TargetRepresentativeEndpointID:   actorMB.EndpointID,
		SourceRepresentativeAssignmentID: repA.ID, TargetRepresentativeAssignmentID: repB.ID,
		OriginPrincipalID: actorA1.PrincipalID, Capability: "benchmark.read", ContractID: contract.ID,
		RequestDigest: "synthetic-historical-request-digest", Scopes: []string{"public-result"},
		Deadline: deadline, MaxHops: 2, State: store.FederationRequestPending,
	})
	if err != nil {
		t.Fatal(err)
	}

	readable, err := service.FederationRequest(actorMA, historical.ID)
	if err != nil || readable == nil || readable.ID != historical.ID || readable.State != store.FederationRequestPending {
		t.Fatalf("historical Federation status is no longer readable: request=%#v err=%v", readable, err)
	}

	retiredWrites := []struct {
		name string
		call func() error
	}{
		{"federate", func() error {
			_, err := service.Federate(actorMA, FederateInput{
				OriginRequestID: "rq_new", TargetGroupID: groupB.ID, Capability: "benchmark.read",
				ContractID: contract.ID, SourceRepresentativeAssignmentID: repA.ID,
				TargetRepresentativeAssignmentID: repB.ID, Scopes: []string{"public-result"},
				Deadline: deadline, MaxHops: 2,
			})
			return err
		}},
		{"submit result", func() error {
			_, err := service.SubmitFederationResult(actorMB, FederationResultInput{
				FederationRequestID: historical.ID, LocalRequestID: "rq_local_historical",
			})
			return err
		}},
		{"accept result", func() error {
			_, err := service.AcceptFederationResult(actorMA, historical.ID)
			return err
		}},
	}
	for _, attempt := range retiredWrites {
		if err := attempt.call(); !errors.Is(err, ErrFederationBodyWritesRetired) {
			t.Errorf("%s returned %v, want explicit Federation body-write retirement", attempt.name, err)
		}
	}

	requests, err := persistence.ListFederationRequests(store.FederationRequestFilter{SourceGroupID: groupA.ID, Limit: 10})
	if err != nil || len(requests) != 1 || requests[0].ID != historical.ID || requests[0].State != store.FederationRequestPending {
		t.Fatalf("retired Federation writes changed historical state or created a new request: %#v err=%v", requests, err)
	}
	for _, endpointID := range []string{actorMA.EndpointID, actorMB.EndpointID} {
		inbox, err := persistence.ListRelayInbox(endpointID, 0, 10)
		if err != nil || len(inbox) != 0 {
			t.Fatalf("retired Federation writes created peer relay messages for %s: %#v err=%v", endpointID, inbox, err)
		}
	}
}
