package fabric

import (
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

func TestMonitorMediatedCrossGroupCollaboration(t *testing.T) {
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
	a1, actorA1 := joinFabricPeer(t, service, groupA.ID, "a1", "native-a1", "node-a")
	ma, actorMAOld := joinFabricPeer(t, service, groupA.ID, "ma", "native-ma", "node-a")
	b1, actorB1 := joinFabricPeer(t, service, groupB.ID, "b1", "native-b1", "node-b")
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
	if _, err := service.ClaimRepresentation(actorMA, repA.ID, 300); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ClaimRepresentation(actorMB, repB.ID, 300); err != nil {
		t.Fatal(err)
	}

	// A1 can only ask its own representative. The normal direct A1 -> B1 path
	// remains denied by TestDirectCrossGroupMessageIsDenied.
	origin, err := service.Ask(actorA1, AskInput{Target: ma.Endpoint.ID, Question: "What is B1's best result?"})
	if err != nil {
		t.Fatal(err)
	}
	federated, err := service.Federate(actorMA, FederateInput{
		OriginRequestID: origin.RequestID, TargetGroupID: groupB.ID,
		Capability: "benchmark.read", ContractID: contract.ID,
		SourceRepresentativeAssignmentID: repA.ID, TargetRepresentativeAssignmentID: repB.ID,
		Scopes: []string{"public-result"}, Deadline: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339), MaxHops: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	mailboxMB, err := service.Receive(actorMB, ReceiveInput{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	foundFederationRequest := false
	for _, item := range mailboxMB.Messages {
		if item.Message != nil && item.Message.Kind == "federation_request" && item.Message.RequestID == federated.ID {
			foundFederationRequest = true
		}
	}
	if !foundFederationRequest {
		t.Fatalf("MB did not receive gateway request: %#v", mailboxMB.Messages)
	}
	accepted, err := service.AcceptFederation(actorMB, federated.ID)
	if err != nil || accepted.State != store.FederationRequestInProgress {
		t.Fatalf("target acceptance did not begin work: %#v err=%v", accepted, err)
	}

	local, err := service.Ask(actorMB, AskInput{Target: b1.Endpoint.ID, Question: "Return the public benchmark result"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Reply(actorB1, ReplyInput{RequestID: local.RequestID, Body: "best=42.7"}); err != nil {
		t.Fatal(err)
	}
	submitted, err := service.SubmitFederationResult(actorMB, FederationResultInput{
		FederationRequestID: federated.ID, LocalRequestID: local.RequestID,
		EvidenceRefs: []string{"evidence:benchmark-run-7"}, VerificationLevel: "producer-reply",
	})
	if err != nil || submitted.State != store.FederationRequestResultSubmitted {
		t.Fatalf("result submission failed: %#v err=%v", submitted, err)
	}
	if submitted.ProducerEndpointID != b1.Endpoint.ID || submitted.ProducerPrincipalID != actorB1.PrincipalID {
		t.Fatalf("true producer provenance was lost: %#v", submitted)
	}
	mailboxMA, err := service.Receive(actorMA, ReceiveInput{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	foundFederationResult := false
	for _, item := range mailboxMA.Messages {
		if item.Message != nil && item.Message.Kind == "federation_result" && item.Message.RequestID == federated.ID {
			foundFederationResult = true
		}
	}
	if !foundFederationResult {
		t.Fatalf("MA did not receive gateway result: %#v", mailboxMA.Messages)
	}
	closed, err := service.AcceptFederationResult(actorMA, federated.ID)
	if err != nil || closed.State != store.FederationRequestClosed {
		t.Fatalf("source result acceptance did not close request: %#v err=%v", closed, err)
	}
	mailboxA1, err := service.Receive(actorA1, ReceiveInput{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	foundReply := false
	for _, item := range mailboxA1.Messages {
		if item.Message != nil && item.Message.Kind == "reply" && item.Message.RequestID == origin.RequestID && item.Message.Body == "best=42.7" {
			foundReply = true
		}
	}
	if !foundReply {
		t.Fatalf("federated result did not return to original A1 request: %#v", mailboxA1.Messages)
	}
	_ = a1
}
