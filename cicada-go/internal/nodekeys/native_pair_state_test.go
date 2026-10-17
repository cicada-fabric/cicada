package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Real Owner/candidate signatures and disposable SQLite. Message digests/byte
// counts below are explicitly synthetic storage inputs, not peer deliveries.
type nativePairStateFixture struct {
	state     *CryptoState
	root      string
	owner     *e2ee.Identity
	hub       wire.HubIdentity
	scope     e2ee.OwnerNativePairScope
	bootstrap e2ee.OwnerNativePairClaims
	evidence  wire.NativePairPeerEvidence
	now       time.Time
}

func newNativePairStateFixture(t *testing.T, trust bool) *nativePairStateFixture {
	t.Helper()
	f := &nativePairStateFixture{root: t.TempDir(), now: time.Date(2026, 10, 17, 16, 0, 0, 0, time.UTC)}
	keys := make([]*e2ee.Identity, 7)
	for i := range keys {
		var err error
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.state.Close() })
	f.owner = keys[1]
	f.hub = wire.HubIdentity{Contract: "android-hub-v1", HubID: "synthetic-pair-hub", Public: keys[0].Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	fp, _ := wire.HubFingerprint(f.hub)
	stamp := func(d time.Duration) string { return f.now.Add(d).Format(time.RFC3339Nano) }
	a := e2ee.OwnerAppNodeScope{Version: 1, Origin: "https://synthetic-pair.invalid", HubID: f.hub.HubID, HubFingerprint: fp, AccountID: "synthetic-account", AccountSessionID: "synthetic-session", AccountSessionExpiresAt: stamp(15 * time.Minute), OwnerID: "synthetic-owner", OwnerPublic: f.owner.Public(), OwnerKeyVersion: 1, DeviceID: wire.AccountDeviceIDPrefix + strings.Repeat("a", 32), DevicePublic: keys[2].Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, TransportPolicy: wire.AppNodeTransportHTTPS}
	f.scope = e2ee.OwnerNativePairScope{Actor: a, NodeControlBindingVersion: 9, CredentialCommitment: strings.Repeat("b", 64), Node: e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-node-binding", OwnerID: a.OwnerID, HubID: a.HubID, NodeID: "synthetic-pair-node", NodeName: "Synthetic Node", ClientDeviceID: a.DeviceID, OwnerKeyID: a.OwnerPublic.ID, CredentialVersion: 7, BindingVersion: 6, NodePublic: keys[3].Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(keys[3].Public()), NodeKeyVersion: 1, NodeKeyEpoch: 4, HubNodeControlPublic: keys[4].Public(), HubNodeControlFingerprint: nodewire.IdentityFingerprint(keys[4].Public()), HubNodeControlKeyVersion: 1, ApprovedRequestID: "synthetic-approved", ApprovedRequestVersion: 1, ApprovedCandidateDigest: strings.Repeat("c", 64), ApprovedAt: stamp(-time.Minute), State: "ACTIVE"}}
	f.scope.NodeTupleDigest, _ = wire.NativePairNodeTupleDigest(f.scope)
	f.bootstrap = e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairBootstrapCommit, Scope: f.scope, RequestID: strings.Repeat("1", 32), Nonce: strings.Repeat("d", 64), IssuedAt: stamp(0), ExpiresAt: stamp(5 * time.Minute), Bootstrap: &e2ee.NativePairBootstrapClaims{PairID: strings.Repeat("2", 32), NetworkID: "synthetic-pair-network", GroupID: "synthetic-pair-group", GroupLabel: "Synthetic pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: stamp(0), JoinUntil: stamp(10 * time.Minute), PeerExpiresAt: stamp(time.Hour), PrepareRequestID: strings.Repeat("3", 32), PreparePacketDigest: strings.Repeat("4", 64), ServerNonce: strings.Repeat("5", 64)}}
	proof, err := e2ee.SignOwnerNativePair(f.owner, f.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	p := wire.NativePairConsentPlan{Format: wire.NativePairFormat, PairID: f.bootstrap.Bootstrap.PairID, ExpectedRevision: 3, PlanID: strings.Repeat("6", 32), Scope: f.scope, BootstrapProofDigest: wire.NativePairProofDigest(proof), NetworkID: f.bootstrap.Bootstrap.NetworkID, NetworkVersion: 1, GroupID: f.bootstrap.Bootstrap.GroupID, GroupVersion: 1, GroupRevision: 7, ProjectedSlotAMembership: 5, ProjectedSlotBMembership: 5, GroupGrants: wire.NativePairGroupGrants(), Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: stamp(0), ExpiresAt: stamp(5 * time.Minute), PeerExpiresAt: stamp(time.Hour)}
	for i := 0; i < 2; i++ {
		letter := string(rune('A' + i))
		suffix := strings.ToLower(letter)
		s := wire.NativePairSlot{Slot: letter, Generation: 1, AttemptID: strings.Repeat(string(rune('7'+i)), 32), NativeSessionID: "synthetic-native-" + suffix, Runtime: "codex", EndpointID: "synthetic-endpoint-" + suffix, PrincipalID: "synthetic-principal-" + suffix, NodeID: f.scope.Node.NodeID, NetworkAccessBindingID: "synthetic-network-binding-" + suffix, NetworkAccessEpoch: 1, NetworkMembershipRevision: 8, EndpointNetworkRevision: 9, BindingID: "synthetic-group-binding-" + suffix, BindingEpoch: 10, LeaseOwner: "synthetic-lease-" + suffix, LeaseCeiling: p.PeerExpiresAt, MembershipRevision: 4, EndpointJoinRevision: 3, CandidateVersion: 2, CandidatePublic: keys[5+i].Public()}
		s.CandidateAttestation, err = keys[5+i].SignEndpointKeyAttestation(s.EndpointID, s.PrincipalID, s.NodeID, s.BindingID, s.BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(s.CandidateAttestation)
		s.CandidateProofDigest = hex.EncodeToString(h[:])
		s.CandidateFingerprint, _ = PeerKeyFingerprint(s.CandidatePublic)
		m := wire.NativePairGroupKeyManifest{NativePairGroupKeyClaims: wire.NativePairGroupKeyClaims{Version: 1, Operation: "group-endpoint-key-grant:v1", HubID: a.HubID, OwnerID: a.OwnerID, PrincipalID: s.PrincipalID, GroupID: p.GroupID, GroupRevision: int64(p.GroupRevision), EndpointID: s.EndpointID, NodeID: s.NodeID, BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, MembershipRevision: 5, EndpointJoinRevision: int64(s.EndpointJoinRevision), CandidateVersion: int64(s.CandidateVersion), CandidateKeyID: s.CandidatePublic.ID, CandidateFingerprint: s.CandidateFingerprint, CandidateProofDigest: s.CandidateProofDigest, CandidatePublicIdentity: s.CandidatePublic, OwnerKeyID: f.owner.Public().ID, IssuedAt: p.PreparedAt, ExpiresAt: p.PeerExpiresAt}, CandidateAttestation: s.CandidateAttestation}
		m.CandidateBindingDigest, _ = wire.NativePairGroupBindingDigest(m)
		m.Digest, _ = wire.NativePairGroupManifestDigest(m)
		if i == 0 {
			p.SlotA = s
			p.SlotAKeyManifest = m
		} else {
			p.SlotB = s
			p.SlotBKeyManifest = m
		}
	}
	p.Digest, _ = wire.NativePairPlanDigest(p)
	f.evidence = wire.NativePairPeerEvidence{ContractRevision: wire.NativePairContractRevision, Plan: p, BootstrapOwnerProof: proof}
	ad, _ := wire.NativePairSlotDigest(p.SlotA)
	bd, _ := wire.NativePairSlotDigest(p.SlotB)
	for i, s := range []wire.NativePairSlot{p.SlotA, p.SlotB} {
		peer, manifest := p.SlotB, p.SlotAKeyManifest
		if i == 1 {
			peer, manifest = p.SlotA, p.SlotBKeyManifest
		}
		c := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairSlotConsent, Scope: f.scope, RequestID: strings.Repeat(string(rune('a'+i)), 32), Nonce: strings.Repeat("f", 64), IssuedAt: stamp(0), ExpiresAt: p.ExpiresAt, Consent: &e2ee.NativePairConsentClaims{PairID: p.PairID, ExpectedRevision: p.ExpectedRevision, PlanID: p.PlanID, PlanDigest: p.Digest, SlotADigest: ad, SlotBDigest: bd, Slot: s.Slot, SlotGeneration: s.Generation, SlotAttemptID: s.AttemptID, NativeSessionID: s.NativeSessionID, PeerNativeSessionID: peer.NativeSessionID, ActivateWhenBoth: true, PlanExpiresAt: p.ExpiresAt, PeerExpiresAt: p.PeerExpiresAt}}
		consent, err := e2ee.SignOwnerNativePair(f.owner, c)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := f.owner.SignOwnerLinkKeyGrant(a.OwnerID, "group-endpoint-key-grant:v1", manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, f.now, f.now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.evidence.SlotAOwnerConsent = consent
			f.evidence.SlotAGroupKeyProof = grant
		} else {
			f.evidence.SlotBOwnerConsent = consent
			f.evidence.SlotBGroupKeyProof = grant
		}
	}
	if err := wire.VerifyNativePairPeerEvidence(f.evidence, f.hub, f.owner.Public(), f.scope.NodeTupleDigest, f.now); err != nil {
		t.Fatal("invalid synthetic pair evidence", err)
	}
	if trust {
		f.trust(t)
	}
	return f
}

func (f *nativePairStateFixture) trust(t *testing.T) {
	t.Helper()
	fp, _ := PeerKeyFingerprint(f.owner.Public())
	if _, err := f.state.TrustOwnerApprovalKeyLocal(f.scope.Actor.OwnerID, f.owner.Public().ID, f.owner.Public(), fp); err != nil {
		t.Fatal(err)
	}
}
func (f *nativePairStateFixture) require(t *testing.T) {
	t.Helper()
	if _, err := f.state.RequireNativePairPolicy(context.Background(), f.hub, f.scope, f.evidence.BootstrapOwnerProof, f.now); err != nil {
		t.Fatal(err)
	}
}
func (f *nativePairStateFixture) message(round int, reply bool) NativePairMessage {
	a, b := f.evidence.Plan.SlotA.EndpointID, f.evidence.Plan.SlotB.EndpointID
	if round%2 != 0 {
		a, b = b, a
	}
	kind := "ASK"
	if reply {
		a, b = b, a
		kind = "REPLY"
	}
	id := fmt.Sprintf("synthetic-%s-%d", kind, round)
	h := sha256.Sum256([]byte("synthetic-storage-probe:" + id))
	return NativePairMessage{MessageID: id, RequestID: fmt.Sprintf("synthetic-request-%d", round), Kind: kind, SenderEndpointID: a, ReceiverEndpointID: b, Digest: hex.EncodeToString(h[:]), PlaintextBytes: 8192, CiphertextBytes: 128 * 1024}
}

func TestNativePairPolicyPinAndRequiredMarkerAreAtomicAndRetained(t *testing.T) {
	ctx := context.Background()
	f := newNativePairStateFixture(t, false)
	if _, err := f.state.RequireNativePairPolicy(ctx, f.hub, f.scope, f.evidence.BootstrapOwnerProof, f.now); !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("Hub self-reported Owner key became a local pin")
	}
	f.trust(t)
	if _, err := f.state.db.Exec(`CREATE TRIGGER synthetic_pair_abort BEFORE INSERT ON node_native_pair_policies BEGIN SELECT RAISE(ABORT,'synthetic atomic failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.RequireNativePairPolicy(ctx, f.hub, f.scope, f.evidence.BootstrapOwnerProof, f.now); err == nil {
		t.Fatal("injected failed policy commit continued")
	}
	var count int
	if err := f.state.db.QueryRow(`SELECT count(*) FROM node_native_pair_nodes`).Scan(&count); err != nil || count != 0 {
		t.Fatal("crash/failure retained versions without policy marker", err)
	}
	if _, err := f.state.db.Exec(`DROP TRIGGER synthetic_pair_abort`); err != nil {
		t.Fatal(err)
	}
	f.require(t)
	var credential, control uint64
	if err := f.state.db.QueryRow(`SELECT credential_version,control_binding_version FROM node_native_pair_nodes`).Scan(&credential, &control); err != nil || credential != 7 || control != 9 {
		t.Fatal("versions were guessed instead of pinned together", err)
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if yes, err := f.state.NativePairPolicyRequired(ctx, f.evidence.Plan.GroupID); err != nil || !yes {
		t.Fatal("restart lost required-policy marker", err)
	}
	if yes, err := f.state.NativePairPolicyRequired(ctx, "synthetic-legacy-group"); err != nil || yes {
		t.Fatal("ordinary Group was marked as a Pair", err)
	}
	f.now = f.now.Add(2 * time.Hour)
	f.require(t) // Existing exact metadata is history only.
	changed := f.bootstrap
	changed.Scope.Node.CredentialVersion++
	changed.Scope.NodeControlBindingVersion++
	changed.Scope.NodeTupleDigest, _ = wire.NativePairNodeTupleDigest(changed.Scope)
	b := *changed.Bootstrap
	b.PairID = strings.Repeat("c", 32)
	b.GroupID = "synthetic-replacement-group"
	changed.Bootstrap = &b
	proof, err := e2ee.SignOwnerNativePair(f.owner, changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.RequireNativePairPolicy(ctx, f.hub, changed.Scope, proof, f.now.Add(-2*time.Hour)); !errors.Is(err, ErrNativePairConflict) {
		t.Fatal("later proof silently changed pinned versions", err)
	}
	if yes, _ := f.state.NativePairPolicyRequired(ctx, b.GroupID); yes {
		t.Fatal("conflicting version created partial policy")
	}
}

func TestNativePairDurableBudgetCountsBothDirectionsAndSubmissionsOnce(t *testing.T) {
	ctx := context.Background()
	f := newNativePairStateFixture(t, true)
	f.require(t)
	pair := f.evidence.Plan.PairID
	for round := 0; round < 4; round++ {
		ask, reply := f.message(round, false), f.message(round, true)
		if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil || existing {
			t.Fatal("new ASK reservation failed", err)
		}
		if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil || !existing {
			t.Fatal("sender/receiver retry double charged", err)
		}
		bad := ask
		bad.Digest = strings.Repeat("f", 64)
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, bad, f.now); !errors.Is(err, ErrNativePairConflict) {
			t.Fatal("changed packet reused message identity", err)
		}
		next := f.message(round+1, false)
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, next, f.now); !errors.Is(err, ErrNativePairBudget) {
			t.Fatal("UNKNOWN ASK released the outstanding reservation", err)
		}
		if err := f.state.ConfirmNativePairAdmission(ctx, pair, ask.MessageID, ask.Digest); err != nil {
			t.Fatal(err)
		}
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, reply, f.now); err != nil {
			t.Fatal(err)
		}
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, next, f.now); !errors.Is(err, ErrNativePairBudget) {
			t.Fatal("UNKNOWN Reply released the ASK", err)
		}
		if err := f.state.ConfirmNativePairAdmission(ctx, pair, reply.MessageID, reply.Digest); err != nil {
			t.Fatal(err)
		}
		for _, m := range []NativePairMessage{ask, reply} {
			slot := f.evidence.Plan.SlotA
			if slot.EndpointID != m.ReceiverEndpointID {
				slot = f.evidence.Plan.SlotB
			}
			if existing, err := f.state.ReserveNativePairSubmission(ctx, f.evidence, m, slot.NativeSessionID, f.now); err != nil || existing {
				t.Fatal("first native reservation failed", err)
			}
			if existing, err := f.state.ReserveNativePairSubmission(ctx, f.evidence, m, slot.NativeSessionID, f.now); err != nil || !existing {
				t.Fatal("native retry authorized a second invocation", err)
			}
			if _, err := f.state.ReserveNativePairSubmission(ctx, f.evidence, m, "synthetic-foreign-session", f.now); err == nil {
				t.Fatal("native reservation adopted another actual SID")
			}
		}
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(4, false), f.now); !errors.Is(err, ErrNativePairBudget) {
		t.Fatal("fifth root ASK admitted", err)
	}
	var messages, plain, cipher, submissions int
	if err := f.state.db.QueryRow(`SELECT count(*),sum(plaintext_bytes),sum(ciphertext_bytes) FROM node_native_pair_messages`).Scan(&messages, &plain, &cipher); err != nil {
		t.Fatal(err)
	}
	if err := f.state.db.QueryRow(`SELECT count(*) FROM node_native_pair_submissions`).Scan(&submissions); err != nil || messages != 8 || plain != 65536 || cipher != 1048576 || submissions != 8 {
		t.Fatal("pair totals charged more than once or lost reservations", err)
	}
}

func TestNativePairBudgetReopenExpiryAndMissingEvidenceFailClosed(t *testing.T) {
	ctx := context.Background()
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ask := f.message(0, false)
	missing := f.evidence
	missing.SlotBOwnerConsent = nil
	if _, err := f.state.ReserveNativePairMessage(ctx, missing, ask, f.now); err == nil {
		t.Fatal("missing second consent downgraded to legacy rights")
	}
	child := ask
	child.ParentRequestID = "synthetic-parent"
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, child, f.now); err == nil {
		t.Fatal("causal ASK admitted")
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(1, false), f.now); !errors.Is(err, ErrNativePairBudget) {
		t.Fatal("restart reset UNKNOWN budget", err)
	}
	f.now = f.now.Add(2 * time.Hour)
	if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil || !existing {
		t.Fatal("exact historical reservation lookup failed", err)
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(0, true), f.now); err == nil {
		t.Fatal("expired evidence admitted a new business packet")
	}
	old, err := f.state.NativePairPolicyForGroup(ctx, f.evidence.Plan.GroupID)
	if err != nil || !bytes.Equal(old.BootstrapProof, f.evidence.BootstrapOwnerProof) {
		t.Fatal("recovery changed original policy proof", err)
	}
}

func TestNativePairConcurrentIndependentHandlesReserveOneMessage(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	other, err := OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	results := make(chan bool, 12)
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			state := f.state
			if i%2 == 1 {
				state = other
			}
			old, err := state.ReserveNativePairMessage(context.Background(), f.evidence, f.message(0, false), f.now)
			results <- old
			failures <- err
		}(i)
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	created := 0
	for old := range results {
		if !old {
			created++
		}
	}
	if created != 1 {
		t.Fatal("concurrent processes double charged or replaced the winner")
	}
}

func TestNativePairRequiredGroupRejectsMissingOrForeignEvidence(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ctx := context.Background()
	group := f.evidence.Plan.GroupID
	if required, err := f.state.VerifyNativePairGroupEvidence(ctx, group, &f.evidence, f.now); err != nil || !required {
		t.Fatal("retained Group rejected its complete evidence", err)
	}
	if required, err := f.state.VerifyNativePairGroupEvidence(ctx, group, nil, f.now); !required || !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("missing bundle enabled legacy fallback", err)
	}
	foreign := f.evidence
	foreign.Plan.GroupID = "synthetic-foreign-group"
	if required, err := f.state.VerifyNativePairGroupEvidence(ctx, group, &foreign, f.now); !required || !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("bundle replaced the actual routed Group", err)
	}
	if required, err := f.state.VerifyNativePairGroupEvidence(ctx, "synthetic-legacy-group", &f.evidence, f.now); required || !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("Pair evidence authorized an unrelated legacy Group", err)
	}
	if required, err := f.state.VerifyNativePairGroupEvidence(ctx, "synthetic-legacy-group", nil, f.now); required || err != nil {
		t.Fatal("ordinary legacy Group behavior changed", err)
	}
}

func TestNativePairOwnerRevocationStopsFreshWorkAndRetainsRecovery(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ctx := context.Background()
	ask := f.message(0, false)
	pair := f.evidence.Plan.PairID
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.state.ConfirmNativePairAdmission(ctx, pair, ask.MessageID, ask.Digest); err != nil {
		t.Fatal(err)
	}
	nativeID := f.evidence.Plan.SlotB.NativeSessionID
	if _, err := f.state.ReserveNativePairSubmission(ctx, f.evidence, ask, nativeID, f.now); err != nil {
		t.Fatal(err)
	}
	trust, err := f.state.GetNodeOwnerKeyTrustLocal(f.scope.Actor.OwnerID, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if required, err := f.state.VerifyNativePairGroupEvidence(ctx, f.evidence.Plan.GroupID, &f.evidence, f.now); !required || !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("restart accepted a revoked independent Owner pin", err)
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(0, true), f.now); !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("revoked pin admitted fresh reply work", err)
	}
	// existing=true is a lookup result; neither method admits a new invocation.
	if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil || !existing {
		t.Fatal("revocation discarded an original request reservation", err)
	}
	if existing, err := f.state.ReserveNativePairSubmission(ctx, f.evidence, ask, nativeID, f.now); err != nil || !existing {
		t.Fatal("revocation discarded the original native submission marker", err)
	}
	var messages, submissions int
	if err := f.state.db.QueryRow(`SELECT count(*) FROM node_native_pair_messages`).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := f.state.db.QueryRow(`SELECT count(*) FROM node_native_pair_submissions`).Scan(&submissions); err != nil || messages != 1 || submissions != 1 {
		t.Fatal("recovery changed retained charges or native submissions", err)
	}
}

func TestNativePairCancellationRetainsBudgetAndExactRequestCorrelation(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ctx := context.Background()
	pair := f.evidence.Plan.PairID
	for round := 0; round < 4; round++ {
		ask := f.message(round, false)
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, f.now); err != nil {
			t.Fatal(err)
		}
		if err := f.state.CloseNativePairRequest(ctx, pair, ask.RequestID, ask.ReceiverEndpointID, "CANCELLED"); !errors.Is(err, ErrNativePairConflict) {
			t.Fatal("foreign sender cancelled the outstanding request", err)
		}
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(round+1, false), f.now); !errors.Is(err, ErrNativePairBudget) {
			t.Fatal("failed cancellation released an outstanding request", err)
		}
		for retry := 0; retry < 2; retry++ {
			if err := f.state.CloseNativePairRequest(ctx, pair, ask.RequestID, ask.SenderEndpointID, "CANCELLED"); err != nil {
				t.Fatal("exact terminal recovery was not idempotent", err)
			}
		}
		if err := f.state.CloseNativePairRequest(ctx, pair, ask.RequestID, ask.SenderEndpointID, "EXPIRED"); !errors.Is(err, ErrNativePairConflict) {
			t.Fatal("recovery replaced an existing terminal outcome", err)
		}
		if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(round, true), f.now); !errors.Is(err, ErrNativePairBudget) {
			t.Fatal("cancelled request admitted a new reply", err)
		}
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(4, false), f.now); !errors.Is(err, ErrNativePairBudget) {
		t.Fatal("restart refunded cancelled root request budgets", err)
	}
	var count, bytes int
	if err := f.state.db.QueryRow(`SELECT count(*),sum(plaintext_bytes) FROM node_native_pair_messages WHERE terminal='CANCELLED'`).Scan(&count, &bytes); err != nil || count != 4 || bytes != 4*8192 {
		t.Fatal("cancellation lost original message or byte reservations", err)
	}
}

func TestNativePairPolicyRecoveryAfterJoinWindowPreservesPeerDeadline(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ctx := context.Background()
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.state, err = OpenCryptoState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	late := f.now.Add(11 * time.Minute)
	p, err := f.state.RequireNativePairPolicy(ctx, f.hub, f.scope, f.evidence.BootstrapOwnerProof, late)
	if err != nil || p.JoinUntil != f.bootstrap.Bootstrap.JoinUntil || p.PeerExpiresAt != f.bootstrap.Bootstrap.PeerExpiresAt || !bytes.Equal(p.BootstrapProof, f.evidence.BootstrapOwnerProof) {
		t.Fatal("late recovery rejected or replaced an already accepted policy", err)
	}
	// This checks the Owner-policy layer only. Current live leases and an exact
	// accepted Node Join receipt remain independently necessary at the caller.
	ask := f.message(0, false)
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, late); err != nil {
		t.Fatal("Join admission deadline shortened the existing peer consent", err)
	}
	fresh, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	fp, err := PeerKeyFingerprint(f.owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.TrustOwnerApprovalKeyLocal(f.scope.Actor.OwnerID, f.owner.Public().ID, f.owner.Public(), fp); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.RequireNativePairPolicy(ctx, f.hub, f.scope, f.evidence.BootstrapOwnerProof, late); !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("expired Join window admitted a previously unknown policy", err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, p.PeerExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.ReserveNativePairMessage(ctx, f.evidence, f.message(0, true), deadline); !errors.Is(err, ErrNativePairPolicy) {
		t.Fatal("historical recovery extended the signed peer deadline", err)
	}
	if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, ask, deadline); err != nil || !existing {
		t.Fatal("expired peer consent discarded an existing request's recovery identity", err)
	}
}
