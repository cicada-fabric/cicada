package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newGatewayV2TestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeGatewayV2Schema(); err != nil {
		s.Close()
		t.Fatal(err)
	}
	return s
}

type gatewayFixture struct {
	store     *Store
	contract  *FederationContract
	sourceRep *RepresentativeAssignment
	targetRep *RepresentativeAssignment
}

func newGatewayFixture(t *testing.T) gatewayFixture {
	t.Helper()
	s := newGatewayV2TestStore(t)
	for _, principal := range []Principal{
		{ID: "principal-a", Kind: PrincipalKindAgent, Name: "worker-a"},
		{ID: "principal-ma", Kind: PrincipalKindAgent, Name: "monitor-a"},
		{ID: "principal-b", Kind: PrincipalKindAgent, Name: "worker-b"},
		{ID: "principal-mb", Kind: PrincipalKindAgent, Name: "monitor-b"},
	} {
		if _, err := s.CreatePrincipal(principal); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	for _, group := range []Group{
		{ID: "group-a", Name: "paper", State: GroupStateActive},
		{ID: "group-b", Name: "kernel", State: GroupStateActive},
	} {
		if _, err := s.CreateGroup(group); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	for _, membership := range []Membership{
		{ID: "membership-a", PrincipalID: "principal-a", GroupID: "group-a", Role: "worker", Grants: []string{"federation.request"}},
		{ID: "membership-ma", PrincipalID: "principal-ma", GroupID: "group-a", Role: "monitor", Grants: []string{"federation.represent"}},
		{ID: "membership-b", PrincipalID: "principal-b", GroupID: "group-b", Role: "worker", Grants: []string{"federation.produce"}},
		{ID: "membership-mb", PrincipalID: "principal-mb", GroupID: "group-b", Role: "monitor", Grants: []string{"federation.represent"}},
	} {
		if _, err := s.CreateMembership(membership); err != nil {
			s.Close()
			t.Fatal(err)
		}
	}
	contract, err := s.CreateFederationContract(FederationContract{
		ID: "contract-benchmark-v1", SourceGroupID: "group-a", TargetGroupID: "group-b",
		Capability: "kernel.benchmark.read", Scopes: []string{"public-benchmark", "artifact:read"},
		ExpiresAt: time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339), Version: 1,
	})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	sourceRep, err := s.CreateRepresentativeAssignment(RepresentativeAssignment{
		ID: "rep-a", GroupID: "group-a", PrincipalID: "principal-ma", EndpointID: "endpoint-ma",
		Scopes: []string{"public-benchmark", "artifact:read"}, ContractID: contract.ID,
	})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	targetRep, err := s.CreateRepresentativeAssignment(RepresentativeAssignment{
		ID: "rep-b", GroupID: "group-b", PrincipalID: "principal-mb", EndpointID: "endpoint-mb",
		Scopes: []string{"public-benchmark", "artifact:read"}, ContractID: contract.ID,
	})
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	return gatewayFixture{store: s, contract: contract, sourceRep: sourceRep, targetRep: targetRep}
}

func (f gatewayFixture) request(deadline time.Time) FederationRequest {
	return FederationRequest{
		ID: "frequest-1", OriginRequestID: "ask-1", SourceGroupID: "group-a", TargetGroupID: "group-b",
		SourceRepresentativeEndpointID: "endpoint-ma", TargetRepresentativeEndpointID: "endpoint-mb",
		SourceRepresentativeAssignmentID: f.sourceRep.ID, TargetRepresentativeAssignmentID: f.targetRep.ID,
		OriginPrincipalID: "principal-a", Capability: f.contract.Capability, ContractID: f.contract.ID,
		Scopes: []string{"public-benchmark"}, ArtifactRefs: []string{"artifact-input-v1"},
		Deadline: deadline.UTC().Format(time.RFC3339), MaxHops: 2,
	}
}

func TestGatewayV2SchemaAndPublicRecordsAreAdditive(t *testing.T) {
	f := newGatewayFixture(t)
	defer f.store.Close()
	card, err := f.store.CreateGroupCard(GroupCard{
		ID: "card-b", GroupID: "group-b", Version: 3,
		PublicCapabilities:        []string{"kernel.benchmark.read"},
		RepresentativeEndpointIDs: []string{"endpoint-mb"},
		SecuritySummary:           map[string]any{"e2ee": true, "scope": "public-benchmark"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if card.Version != 3 || card.Digest == "" || len(card.PublicCapabilities) != 1 || len(card.RepresentativeEndpointIDs) != 1 {
		t.Fatalf("group card fields were not durable: %#v", card)
	}
	retry, err := f.store.CreateGroupCard(GroupCard{ID: "different-id", GroupID: "group-b", Version: 3, PublicCapabilities: []string{"kernel.benchmark.read"}, RepresentativeEndpointIDs: []string{"endpoint-mb"}, SecuritySummary: map[string]any{"e2ee": true, "scope": "public-benchmark"}})
	if err != nil || retry.ID != card.ID {
		t.Fatalf("same card version was not idempotent: %#v err=%v", retry, err)
	}
	if _, err := f.store.CreateGroupCard(GroupCard{GroupID: "group-b", Version: 3, PublicCapabilities: []string{"different"}}); !errors.Is(err, ErrGatewayDigestConflict) {
		t.Fatalf("different card digest did not conflict: %v", err)
	}
	var tables int
	if err := f.store.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'gateway_v2_%'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables < 7 {
		t.Fatalf("gateway schema is incomplete: %d tables", tables)
	}
}

func TestGatewayV2OfflineMailboxAndAcceptedIsNotCompleted(t *testing.T) {
	f := newGatewayFixture(t)
	defer f.store.Close()
	request, err := f.store.CreateFederationRequest(f.request(time.Now().Add(30 * time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if request.State != FederationRequestPending {
		t.Fatalf("new request should wait for target acceptance: %#v", request)
	}
	queued, err := f.store.ListRepresentativeMailbox("group-b", "endpoint-mb", 10)
	if err != nil || len(queued) != 1 || queued[0].State != RepresentativeMailboxReady {
		t.Fatalf("offline representative request was not queued: %#v err=%v", queued, err)
	}
	claimedAssignment, err := f.store.ClaimRepresentative(RepresentativeClaimInput{AssignmentID: f.targetRep.ID, OwnerID: "adapter-b", LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.ClaimRepresentativeMailbox(RepresentativeMailboxClaimInput{GroupID: "group-b", RepresentativeEndpointID: "endpoint-mb", RepresentativeAssignmentID: f.targetRep.ID, OwnerID: "adapter-b", Epoch: claimedAssignment.Epoch, Limit: 10})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("durable mailbox claim failed: %#v err=%v", claimed, err)
	}
	accepted, err := f.store.AcceptFederationRequest(request.ID, "adapter-b", claimedAssignment.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State != FederationRequestAccepted || accepted.ClosedAt != "" || accepted.ResultAcceptedAt != "" {
		t.Fatalf("ACCEPTED was treated as completed: %#v", accepted)
	}
}

func TestGatewayV2OwnerEpochFencesDualActiveRepresentatives(t *testing.T) {
	f := newGatewayFixture(t)
	defer f.store.Close()
	request, err := f.store.CreateFederationRequest(f.request(time.Now().Add(30 * time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	old, err := f.store.ClaimRepresentative(RepresentativeClaimInput{AssignmentID: f.targetRep.ID, OwnerID: "adapter-old", LeaseExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	newOwner, err := f.store.TakeoverRepresentative(RepresentativeClaimInput{AssignmentID: f.targetRep.ID, OwnerID: "adapter-new", LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339), ExpectedEpoch: old.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	if newOwner.Epoch <= old.Epoch || newOwner.OwnerID != "adapter-new" {
		t.Fatalf("takeover did not fence old owner: old=%#v new=%#v", old, newOwner)
	}
	if _, err := f.store.AcceptFederationRequest(request.ID, "adapter-old", old.Epoch); !errors.Is(err, ErrGatewayStaleEpoch) && !errors.Is(err, ErrGatewayLeaseOwner) {
		t.Fatalf("stale representative accepted request: %v", err)
	}
	var wg sync.WaitGroup
	owners := []string{"concurrent-a", "concurrent-b", "concurrent-c", "concurrent-d"}
	results := make([]error, len(owners))
	for i := range owners {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = f.store.ClaimRepresentative(RepresentativeClaimInput{AssignmentID: f.sourceRep.ID, OwnerID: owners[i], LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339)})
		}(i)
	}
	wg.Wait()
	successes := 0
	for _, claimErr := range results {
		if claimErr == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent claim had %d owners, want exactly one: %#v", successes, results)
	}
}

func TestGatewayV2PausedRepresentativeCannotReactivateItself(t *testing.T) {
	f := newGatewayFixture(t)
	defer f.store.Close()
	if _, err := f.store.db.Exec(`UPDATE gateway_v2_representatives SET status = ? WHERE id = ?`, RepresentativeAssignmentPaused, f.targetRep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ClaimRepresentative(RepresentativeClaimInput{
		AssignmentID: f.targetRep.ID, OwnerID: "paused-owner",
		LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339),
	}); !errors.Is(err, ErrGatewayInvalidState) {
		t.Fatalf("paused representative reclaimed itself: %v", err)
	}
	if _, err := f.store.CreateFederationRequest(f.request(time.Now().Add(30 * time.Minute))); !errors.Is(err, ErrGatewayAuthorization) {
		t.Fatalf("request routed through paused representative: %v", err)
	}
}

func TestGatewayV2ContractScopeDeadlineAndProvenance(t *testing.T) {
	f := newGatewayFixture(t)
	defer f.store.Close()
	badScope := f.request(time.Now().Add(30 * time.Minute))
	badScope.Scopes = []string{"private-secret"}
	if _, err := f.store.CreateFederationRequest(badScope); !errors.Is(err, ErrGatewayScopeDenied) {
		t.Fatalf("out-of-contract scope was accepted: %v", err)
	}
	badDeadline := f.request(time.Now().Add(3 * time.Hour))
	if _, err := f.store.CreateFederationRequest(badDeadline); !errors.Is(err, ErrGatewayDeadline) {
		t.Fatalf("deadline beyond contract was accepted: %v", err)
	}
	request, err := f.store.CreateFederationRequest(f.request(time.Now().Add(30 * time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.store.ClaimRepresentative(RepresentativeClaimInput{AssignmentID: f.targetRep.ID, OwnerID: "adapter-b", LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptFederationRequest(request.ID, "adapter-b", claim.Epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BeginFederationRequest(request.ID, "adapter-b", claim.Epoch); err != nil {
		t.Fatal(err)
	}
	result, err := f.store.SubmitFederationResult(FederationResult{
		ID: "result-1", RequestID: request.ID, Digest: "result-digest-1",
		ProducerPrincipalID: "principal-b", ProducerEndpointID: "endpoint-b1", ProducerGroupID: "group-b",
		ArtifactRefs: []string{"artifact-output-v4"}, EvidenceRefs: []string{"evidence-run-4"}, ProvenanceRefs: []string{"trace-b1"}, VerificationLevel: "producer-self-reported",
	}, "adapter-b", claim.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != FederationRequestResultSubmitted || result.ProducerPrincipalID != "principal-b" || result.ProducerEndpointID != "endpoint-b1" || len(result.EvidenceRefs) != 1 || len(result.ProvenanceRefs) != 1 {
		t.Fatalf("producer provenance was not retained: %#v", result)
	}
	sourceClaim, err := f.store.ClaimRepresentative(RepresentativeClaimInput{AssignmentID: f.sourceRep.ID, OwnerID: "adapter-a", LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := f.store.AcceptFederationResult(request.ID, "result-1", "adapter-a", sourceClaim.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.State != FederationRequestResultAccepted || accepted.ClosedAt != "" {
		t.Fatalf("result acceptance skipped explicit close: %#v", accepted)
	}
	closed, err := f.store.SettleFederationRequest(request.ID, "adapter-a", sourceClaim.Epoch)
	if err != nil || closed.State != FederationRequestClosed {
		t.Fatalf("settle did not close request: %#v err=%v", closed, err)
	}
}

func TestGatewayV2DigestConflictExpiryCancelAndLateResult(t *testing.T) {
	f := newGatewayFixture(t)
	defer f.store.Close()
	firstInput := f.request(time.Now().Add(30 * time.Minute))
	firstInput.RequestDigest = "request-digest-one"
	first, err := f.store.CreateFederationRequest(firstInput)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.store.CreateFederationRequest(firstInput)
	if err != nil || retry.ID != first.ID {
		t.Fatalf("same origin/digest was not idempotent: %#v err=%v", retry, err)
	}
	conflict := firstInput
	conflict.RequestDigest = "request-digest-two"
	if _, err := f.store.CreateFederationRequest(conflict); !errors.Is(err, ErrGatewayDigestConflict) {
		t.Fatalf("different digest did not conflict: %v", err)
	}
	claim, err := f.store.ClaimRepresentative(RepresentativeClaimInput{AssignmentID: f.targetRep.ID, OwnerID: "adapter-b", LeaseExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ExpireFederationRequest(first.ID, "local deadline"); err != nil {
		t.Fatal(err)
	}
	late, err := f.store.SubmitFederationResult(FederationResult{ID: "late-result", RequestID: first.ID, Digest: "late-digest", ProducerPrincipalID: "principal-b", ProducerGroupID: "group-b", EvidenceRefs: []string{"late-evidence"}}, "adapter-b", claim.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if late.State != FederationRequestLateResult || late.LateResultAt == "" {
		t.Fatalf("late result reopened responsibility or was not recorded: %#v", late)
	}
	stored, err := f.store.GetFederationResult("late-result")
	if err != nil || stored.State != FederationResultLate || stored.LateForState != FederationRequestExpired {
		t.Fatalf("late result provenance/state was not durable: %#v err=%v", stored, err)
	}
	second := f.request(time.Now().Add(30 * time.Minute))
	second.ID, second.OriginRequestID = "frequest-cancel", "ask-cancel"
	cancelled, err := f.store.CreateFederationRequest(second)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err = f.store.CancelFederationRequest(cancelled.ID, "operator cancelled")
	if err != nil || cancelled.State != FederationRequestCancelled {
		t.Fatalf("cancel transition failed: %#v err=%v", cancelled, err)
	}
}
