package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type endpointKeyCandidateFixture struct {
	store    *Store
	identity *e2ee.Identity
	binding  *SessionBinding
}

func newEndpointKeyCandidateFixture(t *testing.T) *endpointKeyCandidateFixture {
	t.Helper()
	persistence, err := New(filepath.Join(t.TempDir(), "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })

	endpoint, err := persistence.UpsertEndpoint(Endpoint{
		ID: "ep_candidate", Name: "candidate", Harness: "codex",
		NativeSessionID: "native-candidate", MachineID: "node_candidate",
		Owner: "owner_candidate",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := persistence.CreatePrincipal(Principal{
		ID: "pr_candidate", Kind: PrincipalKindAgent, OwnerID: "owner_candidate",
		Name: "candidate", Status: PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(Group{
		ID: "grp_candidate", OwnerPrincipalID: principal.ID, Name: "candidate group",
		State: GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(Membership{
		PrincipalID: principal.ID, GroupID: group.ID, Role: "member",
	}); err != nil {
		t.Fatal(err)
	}
	binding, err := persistence.CreateSessionBinding(SessionBinding{
		ID: "bind_candidate", EndpointID: endpoint.ID, PrincipalID: principal.ID,
		GroupID: group.ID, NativeSessionID: endpoint.NativeSessionID,
		NodeID: endpoint.MachineID,
	})
	if err != nil {
		t.Fatal(err)
	}
	leased, err := persistence.AcquireSessionBindingLease(binding.ID, "adapter_candidate",
		binding.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &endpointKeyCandidateFixture{store: persistence, identity: identity, binding: leased}
}

func (fixture *endpointKeyCandidateFixture) attestation(t *testing.T, identity *e2ee.Identity, bindingID string, epoch uint64) []byte {
	t.Helper()
	proof, err := identity.SignEndpointKeyAttestation("ep_candidate", "pr_candidate",
		"node_candidate", bindingID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (fixture *endpointKeyCandidateFixture) register(t *testing.T, identity *e2ee.Identity, bindingID string, epoch uint64) (*EndpointKeyCandidate, error) {
	t.Helper()
	return fixture.store.RegisterEndpointKeyCandidate("ep_candidate", "pr_candidate",
		bindingID, epoch, fixture.attestation(t, identity, bindingID, epoch))
}

func TestRegisterEndpointKeyCandidateSameKeyRejoinRefreshesEpoch(t *testing.T) {
	fixture := newEndpointKeyCandidateFixture(t)
	first, err := fixture.register(t, fixture.identity, fixture.binding.ID, fixture.binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != EndpointKeyCandidateStateCandidate || first.EndpointID != "ep_candidate" ||
		first.PrincipalID != "pr_candidate" || first.OwnerID != "owner_candidate" ||
		first.NodeID != "node_candidate" || first.KeyID != fixture.identity.Public().ID ||
		first.BindingID != fixture.binding.ID || first.BindingEpoch != fixture.binding.Epoch ||
		len(first.Proof) == 0 || first.ProofDigest == "" || first.Version != 1 {
		t.Fatalf("unexpected candidate: key=%q state=%q binding=%q epoch=%d version=%d", first.KeyID, first.State, first.BindingID, first.BindingEpoch, first.Version)
	}

	if _, err := fixture.register(t, fixture.identity, fixture.binding.ID, fixture.binding.Epoch); err != nil {
		t.Fatalf("same key retry was not idempotent: %v", err)
	}
	retry, err := fixture.store.GetEndpointKeyCandidate(first.EndpointID)
	if err != nil || retry.Version != first.Version {
		t.Fatalf("same key retry changed candidate version: got %d want %d err=%v", candidateVersion(retry), first.Version, err)
	}

	released, err := fixture.store.ReleaseSessionBindingLease(fixture.binding.ID,
		"adapter_candidate", fixture.binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	rejoined, err := fixture.store.AcquireSessionBindingLease(fixture.binding.ID,
		"adapter_candidate", released.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	rejoinProof := fixture.attestation(t, fixture.identity, rejoined.ID, rejoined.Epoch)
	refreshed, err := fixture.store.RegisterEndpointKeyCandidate("ep_candidate", "pr_candidate",
		rejoined.ID, rejoined.Epoch, rejoinProof)
	if err != nil {
		t.Fatalf("same key was rejected after binding rejoin: %v", err)
	}
	if refreshed.KeyID != first.KeyID || refreshed.BindingID != rejoined.ID ||
		refreshed.BindingEpoch != rejoined.Epoch || refreshed.Version != first.Version+1 ||
		!bytes.Equal(refreshed.Proof, rejoinProof) {
		t.Fatalf("rejoin did not refresh candidate proof/binding: key=%q binding=%q epoch=%d version=%d", refreshed.KeyID, refreshed.BindingID, refreshed.BindingEpoch, refreshed.Version)
	}
}

func TestRegisterEndpointKeyCandidateRejectsSubstitutionAndStaleBinding(t *testing.T) {
	fixture := newEndpointKeyCandidateFixture(t)
	first, err := fixture.register(t, fixture.identity, fixture.binding.ID, fixture.binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}

	otherIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.register(t, otherIdentity, fixture.binding.ID, fixture.binding.Epoch); !errors.Is(err, ErrEndpointKeyConflict) {
		t.Fatalf("different public key did not conflict: %v", err)
	}
	if current, err := fixture.store.GetEndpointKeyCandidate(first.EndpointID); err != nil || current.KeyID != first.KeyID {
		t.Fatalf("substitution changed the candidate: got %#v err=%v", current, err)
	}

	staleEpoch := fixture.binding.Epoch
	released, err := fixture.store.ReleaseSessionBindingLease(fixture.binding.ID,
		"adapter_candidate", fixture.binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	current, err := fixture.store.AcquireSessionBindingLease(fixture.binding.ID,
		"adapter_candidate", released.Epoch, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	fixture.binding = current
	staleProof := fixture.attestation(t, fixture.identity, fixture.binding.ID, staleEpoch)
	if _, err := fixture.store.RegisterEndpointKeyCandidate(first.EndpointID, first.PrincipalID,
		fixture.binding.ID, staleEpoch, staleProof); !errors.Is(err, ErrSessionBindingStaleEpoch) {
		t.Fatalf("stale binding epoch was accepted: %v", err)
	}
	if _, err := fixture.store.RegisterEndpointKeyCandidate(first.EndpointID, first.PrincipalID,
		"bind_previous", fixture.binding.Epoch, fixture.attestation(t, fixture.identity, "bind_previous", fixture.binding.Epoch)); !errors.Is(err, ErrSessionBindingNotFound) {
		t.Fatalf("stale binding ID was accepted: %v", err)
	}
}

func candidateVersion(candidate *EndpointKeyCandidate) int64 {
	if candidate == nil {
		return 0
	}
	return candidate.Version
}

func TestRegisterEndpointKeyCandidateRejectsLeftEndpoint(t *testing.T) {
	fixture := newEndpointKeyCandidateFixture(t)
	if err := fixture.store.LeaveEndpointAllGroups("ep_candidate", fixture.binding.ID,
		fixture.binding.Epoch, "left for test"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.register(t, fixture.identity, fixture.binding.ID, fixture.binding.Epoch); !errors.Is(err, ErrMembershipNotActive) {
		t.Fatalf("left Endpoint accepted a key candidate: %v", err)
	}
}

func TestRegisterEndpointKeyCandidateConcurrentSubstitutionHasSingleWinner(t *testing.T) {
	fixture := newEndpointKeyCandidateFixture(t)
	secondIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proofs := [][]byte{
		fixture.attestation(t, fixture.identity, fixture.binding.ID, fixture.binding.Epoch),
		fixture.attestation(t, secondIdentity, fixture.binding.ID, fixture.binding.Epoch),
	}
	identities := []string{fixture.identity.Public().ID, secondIdentity.Public().ID}
	const attemptsPerIdentity = 6
	start := make(chan struct{})
	type result struct {
		keyID string
		err   error
	}
	results := make(chan result, attemptsPerIdentity*len(proofs))
	var wait sync.WaitGroup
	for identityIndex := range proofs {
		for attempt := 0; attempt < attemptsPerIdentity; attempt++ {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				candidate, err := fixture.store.RegisterEndpointKeyCandidate("ep_candidate", "pr_candidate",
					fixture.binding.ID, fixture.binding.Epoch, proofs[index])
				keyID := ""
				if candidate != nil {
					keyID = candidate.KeyID
				}
				results <- result{keyID: keyID, err: err}
			}(identityIndex)
		}
	}
	close(start)
	wait.Wait()
	close(results)

	accepted := map[string]int{}
	conflicts := 0
	for result := range results {
		if result.err == nil {
			accepted[result.keyID]++
		} else if errors.Is(result.err, ErrEndpointKeyConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent registration failed unexpectedly: %v", result.err)
		}
	}
	if len(accepted) != 1 || conflicts != attemptsPerIdentity {
		t.Fatalf("concurrent key registration did not have one winner: accepted=%v conflicts=%d", accepted, conflicts)
	}
	for winner := range accepted {
		if winner != identities[0] && winner != identities[1] {
			t.Fatalf("unexpected winning key %q", winner)
		}
		candidate, err := fixture.store.GetEndpointKeyCandidate("ep_candidate")
		if err != nil || candidate.KeyID != winner {
			t.Fatalf("stored candidate differs from concurrent winner: %#v err=%v", candidate, err)
		}
	}
}

func TestGetEndpointKeyCandidateMissing(t *testing.T) {
	fixture := newEndpointKeyCandidateFixture(t)
	if _, err := fixture.store.GetEndpointKeyCandidate("ep_absent"); !errors.Is(err, ErrEndpointKeyNotFound) {
		t.Fatalf("missing candidate returned wrong error: %v", err)
	}
	if _, err := fixture.store.GetEndpointKeyCandidate(""); !errors.Is(err, ErrEndpointKeyNotFound) {
		t.Fatalf("empty Endpoint returned wrong error: %v", err)
	}
	if _, err := fixture.register(t, fixture.identity, fixture.binding.ID, fixture.binding.Epoch); err != nil {
		t.Fatal(err)
	}
	candidate, err := fixture.store.GetEndpointKeyCandidate("ep_candidate")
	if err != nil || candidate.Public.ID != candidate.KeyID || len(candidate.Public.KEMPublic) == 0 || len(candidate.Public.SigningPublic) == 0 {
		t.Fatalf("candidate public identity was not readable: %#v err=%v", candidate, err)
	}
}
