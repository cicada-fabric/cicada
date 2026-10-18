package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// A scripted PQ actor exercises the public App actions, real proof validation,
// encrypted vault and wire envelopes. It is not a Hub Store/Guard or Runtime.
type pairActorFixture struct {
	t                   *testing.T
	n                   *nodeActorFixture
	c                   *nativeController
	bootstrap           wire.NativePairBootstrapChallenge
	bootstrapProof      []byte
	plan                wire.NativePairConsentPlan
	result              wire.NativePairResult
	posts               map[string][][]byte
	receipts            map[string][]byte
	consents            []string
	available           bool
	unavailableDocument bool
	drop, deny          string
	fence               string
	badProjection       bool
	readExpired         bool
}

func newPairActorFixture(t *testing.T) *pairActorFixture {
	t.Helper()
	n := newNodeActorFixture(t)
	if err := n.c.Dispatch(context.Background(), Action{Kind: ActionPreviewNode, NodeCode: n.code}); err != nil {
		t.Fatal(err)
	}
	n.approve(t)
	f := &pairActorFixture{t: t, n: n, c: n.c, posts: map[string][][]byte{}, receipts: map[string][]byte{}, available: true}
	f.c.cfg.HTTP = f
	return f
}

func (f *pairActorFixture) Do(req *http.Request) (*http.Response, error) {
	reply := func(raw []byte, status int) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), Request: req}, nil
	}
	if req.URL.Path == wire.NativePairCapabilitiesPath {
		if !f.available && !f.unavailableDocument {
			return reply(nil, 404)
		}
		cap := wire.NativePairCapabilities{Format: wire.NativePairFormat, ContractRevision: wire.NativePairContractRevision, Available: f.available, ServeMode: "--hub-nodes-only",
			TransportPolicy: wire.AppNodeTransportHTTPS, PeerTransport: "SEALED_RELAY", Policy: e2ee.NativePairFixedPeerPolicy(),
			HTTPOperations: []string{wire.OperationNativePairBootstrapPrepare, wire.OperationNativePairBootstrapComplete, wire.OperationNativePairSlotReject, wire.OperationNativePairConsentPrepare, wire.OperationNativePairConsentComplete, wire.OperationNativePairStatus, wire.OperationNativePairRevoke, wire.OperationNativePairReconcile},
			NodeOperations: []string{wire.OperationNativePairNodeDescribe, wire.OperationNativePairNodeJoin, wire.OperationNativePairNodeReconcile}}
		raw, _ := json.Marshal(cap)
		return reply(raw, 200)
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/owner/native-pairs/") {
		return f.n.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	p, err := wire.DecodeNativePairPacket(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	r := p.Packet.Route
	if req.URL.Path != wire.NativePairHTTPPath(r.Operation) {
		f.t.Fatal("wrong dedicated route")
	}
	f.posts[r.Operation] = append(f.posts[r.Operation], bytes.Clone(raw))
	index := pairOriginalRecord
	if r.Operation == wire.OperationNativePairReconcile {
		index = pairRecoveryRecord
	}
	saved, _, found, err := f.c.vault.LoadState(pairNamespaces[index])
	defer clear(saved)
	var durable pairRequestRecord
	if err != nil || !found || decodeStateJSON(saved, &durable) != nil || !bytes.Equal(durable.Packet, raw) {
		f.t.Fatal("Pair POST preceded exact encrypted vault persistence")
	}
	if f.deny == r.Operation {
		return reply([]byte("unsigned synthetic refusal"), 403)
	}
	digest := wire.NativePairPacketDigest(raw)
	response := f.receipts[digest]
	if response == nil {
		binding := clientwire.Binding{HubID: r.HubID, OwnerID: r.OwnerID, DeviceID: r.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
		device := f.c.device.Public()
		open := func(out any) {
			if err := wire.OpenRequestAt(f.n.n2.hubKey, &device, binding, r, raw, out, f.n.n2.now); err != nil {
				f.t.Fatal(err)
			}
		}
		var body any
		if f.fence == r.Operation {
			input, err := pairMutationDTO(&durable)
			if err != nil {
				f.t.Fatal(err)
			}
			open(input)
			body = wire.NativePairRejectionFence{Format: wire.NativePairFormat, Operation: r.Operation, RequestID: r.OperationID, RequestPacketDigest: digest, PairID: durable.Target.PairID, State: "REJECTED_FENCED", NoEffect: true, ErrorCode: "TARGET_UNAVAILABLE", ObservedAt: f.n.stamp(f.n.n2.now)}
		} else {
			switch r.Operation {
			case wire.OperationNativePairBootstrapPrepare:
				var q wire.NativePairBootstrapPrepare
				open(&q)
				proof, err := e2ee.VerifyOwnerNativePair(f.c.owner.Public(), q.OwnerProof, e2ee.OwnerNativePairBootstrapPreview, f.n.n2.now)
				if err != nil {
					f.t.Fatal(err)
				}
				scope := proof.Scope
				scope.NodeControlBindingVersion = 1
				scope.CredentialCommitment = strings.Repeat("b", 64)
				scope.NodeTupleDigest, _ = wire.NativePairNodeTupleDigest(scope)
				b := e2ee.NativePairBootstrapClaims{PairID: strings.Repeat("a", 32), NetworkID: "synthetic-pair-network", GroupID: "synthetic-pair-group", GroupLabel: proof.Bootstrap.GroupLabel, Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy(),
					PreparedAt: f.n.stamp(f.n.n2.now), JoinUntil: f.n.stamp(f.n.n2.now.Add(10 * time.Minute)), PeerExpiresAt: f.n.stamp(f.n.n2.now.Add(time.Hour)), PrepareRequestID: r.OperationID, PreparePacketDigest: digest, ServerNonce: strings.Repeat("c", 64)}
				f.bootstrap = wire.NativePairBootstrapChallenge{Format: wire.NativePairFormat, RequestID: r.OperationID, RequestPacketDigest: digest, Scope: scope, Bootstrap: b, ProofExpiresAt: f.n.stamp(f.n.n2.now.Add(5 * time.Minute)), ObservedAt: b.PreparedAt}
				body = f.bootstrap
			case wire.OperationNativePairBootstrapComplete:
				var q wire.NativePairBootstrapComplete
				open(&q)
				proof, err := e2ee.VerifyOwnerNativePair(f.c.owner.Public(), q.OwnerProof, e2ee.OwnerNativePairBootstrapCommit, f.n.n2.now)
				if err != nil || !reflect.DeepEqual(proof.Bootstrap, &f.bootstrap.Bootstrap) {
					f.t.Fatal("bootstrap target changed")
				}
				f.bootstrapProof = bytes.Clone(q.OwnerProof)
				f.result = wire.NativePairResult{Format: wire.NativePairFormat, PairID: proof.Bootstrap.PairID, State: wire.NativePairWaitingJoin, Outcome: "COMPLETED", ControlRevision: 1, SlotAState: wire.NativePairSlotReserved, SlotBState: wire.NativePairSlotReserved, PeerExpiresAt: proof.Bootstrap.PeerExpiresAt, AdministrativePermission: true}
				body = f.forRequest(r, digest)
			case wire.OperationNativePairStatus:
				var q wire.NativePairStatusRequest
				open(&q)
				v := f.forRequest(r, digest)
				if f.readExpired {
					v.Outcome = "READ_EXPIRED"
					v.ErrorCode = "READ_EXPIRED"
				}
				body = v
			case wire.OperationNativePairConsentPrepare:
				var q wire.NativePairConsentPrepare
				open(&q)
				f.makePlan()
				body = wire.NativePairPlanChallenge{Format: wire.NativePairFormat, RequestID: r.OperationID, RequestPacketDigest: digest, Plan: f.plan, ObservedAt: f.plan.PreparedAt}
			case wire.OperationNativePairConsentComplete:
				var q wire.NativePairConsentComplete
				open(&q)
				proof, err := e2ee.VerifyOwnerNativePair(f.c.owner.Public(), q.OwnerProof, e2ee.OwnerNativePairSlotConsent, f.n.n2.now)
				if err != nil || wire.ValidateNativePairConsentTarget(proof, f.plan) != nil {
					f.t.Fatal("slot proof did not bind the exact reviewed plan")
				}
				manifest := f.plan.SlotAKeyManifest
				if proof.Consent.Slot == "B" {
					manifest = f.plan.SlotBKeyManifest
				}
				grant, err := e2ee.VerifyOwnerLinkKeyGrant(q.GroupKeyProof, f.c.owner.Public(), f.c.state.OwnerID, "group-endpoint-key-grant:v1", manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, f.n.n2.now)
				if err != nil || grant.IssuedAt != manifest.IssuedAt || grant.ExpiresAt != manifest.ExpiresAt {
					f.t.Fatal("group key proof changed the reviewed manifest's exact lifetime", err)
				}
				f.consents = append(f.consents, proof.Consent.Slot)
				f.result.State = wire.NativePairWaitingConsent
				f.result.SlotAState = wire.NativePairSlotConsentRecorded
				if len(f.consents) == 2 {
					f.result.State = wire.NativePairActive
					f.result.ControlRevision++
					f.result.SlotAState = wire.NativePairSlotActive
					f.result.SlotBState = wire.NativePairSlotActive
					f.result.SlotA.MembershipRevision = f.plan.ProjectedSlotAMembership
					f.result.SlotB.MembershipRevision = f.plan.ProjectedSlotBMembership
					if f.badProjection {
						f.result.SlotB.EndpointJoinRevision++
					}
				}
				body = f.forRequest(r, digest)
			case wire.OperationNativePairRevoke:
				var q wire.NativePairRevoke
				open(&q)
				f.result.State = wire.NativePairRevoked
				f.result.ControlRevision++
				f.result.AdministrativePermission = false
				for _, slot := range []*wire.NativePairSlot{f.result.SlotA, f.result.SlotB} {
					if slot != nil {
						slot.MembershipRevision++
						slot.NetworkMembershipRevision++
						clearPairActorCandidate(slot)
					}
				}
				body = f.forRequest(r, digest)
			case wire.OperationNativePairSlotReject:
				var q wire.NativePairSlotReject
				open(&q)
				claims, err := e2ee.VerifyOwnerNativePair(f.c.owner.Public(), q.OwnerProof, e2ee.OwnerNativePairSlotReject, f.n.n2.now)
				if err != nil || claims.Reject.ExpectedRevision != f.result.ControlRevision {
					f.t.Fatal("invalid exact rejection")
				}
				if claims.Reject.Slot == "A" {
					f.result.SlotA = nil
					f.result.SlotAState = wire.NativePairSlotReserved
				} else {
					f.result.SlotB = nil
					f.result.SlotBState = wire.NativePairSlotReserved
				}
				f.result.ControlRevision++
				body = f.forRequest(r, digest)
			case wire.OperationNativePairReconcile:
				var q wire.NativePairReconcileRequest
				open(&q)
				original, err := wire.DecodeNativePairPacket(q.OriginalPacket)
				if err != nil {
					f.t.Fatal(err)
				}
				od := wire.NativePairPacketDigest(q.OriginalPacket)
				receipt := f.receipts[od]
				if receipt == nil {
					f.t.Fatal("test reconcile needs a committed original")
				}
				body = wire.NativePairReconciled{Format: wire.NativePairFormat, RequestID: r.OperationID, RequestPacketDigest: digest, PairID: f.result.PairID, OriginalOperation: original.Packet.Route.Operation, OriginalRequestID: original.Packet.Route.OperationID, OriginalPacketDigest: od, State: "COMPLETED", ReceiptPacket: receipt, ObservedAt: f.n.stamp(f.n.n2.now)}
			default:
				f.t.Fatal("unexpected Pair operation")
			}
		}
		response, err = wire.SealResponse(f.n.n2.hubKey, device, r, body)
		if err != nil {
			f.t.Fatal(err)
		}
		f.receipts[digest] = response
	}
	if f.drop == r.Operation {
		f.drop = ""
		return nil, errors.New("synthetic response lost after commit")
	}
	return reply(response, 200)
}

func (f *pairActorFixture) forRequest(r clientwire.Route, digest string) wire.NativePairResult {
	v := f.result
	v.Operation, v.RequestID, v.RequestPacketDigest = r.Operation, r.OperationID, digest
	v.ObservedAt = f.n.stamp(f.n.n2.now)
	return v
}

func clearPairActorCandidate(slot *wire.NativePairSlot) {
	slot.CandidateVersion, slot.CandidatePublic = 0, e2ee.PublicIdentity{}
	slot.CandidateFingerprint, slot.CandidateProofDigest, slot.CandidateAttestation = "", "", nil
}

func (f *pairActorFixture) joinSyntheticSlots() {
	f.t.Helper()
	end := f.result.PeerExpiresAt
	for i := 0; i < 2; i++ {
		key, err := e2ee.NewIdentity()
		if err != nil {
			f.t.Fatal(err)
		}
		letter := string(rune('A' + i))
		suffix := strings.ToLower(letter)
		s := wire.NativePairSlot{Slot: letter, Generation: 1, AttemptID: strings.Repeat(string(rune('7'+i)), 32), NativeSessionID: "synthetic-native-" + suffix, Runtime: "codex", EndpointID: "synthetic-endpoint-" + suffix, PrincipalID: "synthetic-principal-" + suffix, NodeID: f.bootstrap.Scope.Node.NodeID, NetworkAccessBindingID: "synthetic-network-binding-" + suffix, NetworkAccessEpoch: 1, NetworkMembershipRevision: 1, EndpointNetworkRevision: 1, BindingID: "synthetic-group-binding-" + suffix, BindingEpoch: 1, LeaseOwner: "synthetic-lease-" + suffix, LeaseCeiling: end, MembershipRevision: 1, EndpointJoinRevision: 1, CandidateVersion: 1, CandidatePublic: key.Public()}
		s.CandidateAttestation, err = key.SignEndpointKeyAttestation(s.EndpointID, s.PrincipalID, s.NodeID, s.BindingID, s.BindingEpoch)
		if err != nil {
			f.t.Fatal(err)
		}
		h := sha256.Sum256(s.CandidateAttestation)
		s.CandidateProofDigest = hex.EncodeToString(h[:])
		s.CandidateFingerprint = pairActorPeerFingerprint(s.CandidatePublic)
		if i == 0 {
			f.result.SlotA = &s
		} else {
			f.result.SlotB = &s
		}
	}
	f.result.State = wire.NativePairWaitingConsent
	f.result.ControlRevision = 3
	f.result.SlotAState = wire.NativePairSlotCandidateReady
	f.result.SlotBState = wire.NativePairSlotCandidateReady
}

func pairActorPeerFingerprint(p e2ee.PublicIdentity) string {
	h := sha256.New()
	h.Write([]byte("cicada/nodekeys/peer-key-fingerprint/v1\x00"))
	h.Write(p.KEMPublic)
	h.Write(p.SigningPublic)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (f *pairActorFixture) makePlan() {
	b := f.bootstrap.Bootstrap
	p := wire.NativePairConsentPlan{Format: wire.NativePairFormat, PairID: b.PairID, ExpectedRevision: f.result.ControlRevision, PlanID: strings.Repeat("6", 32), Scope: f.bootstrap.Scope, BootstrapProofDigest: wire.NativePairProofDigest(f.bootstrapProof), NetworkID: b.NetworkID, NetworkVersion: 1, GroupID: b.GroupID, GroupVersion: 1, GroupRevision: 1, ProjectedSlotAMembership: 2, ProjectedSlotBMembership: 2, GroupGrants: wire.NativePairGroupGrants(), Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: f.n.stamp(f.n.n2.now), ExpiresAt: f.n.stamp(f.n.n2.now.Add(5 * time.Minute)), PeerExpiresAt: b.PeerExpiresAt, SlotA: *f.result.SlotA, SlotB: *f.result.SlotB}
	for i, s := range []wire.NativePairSlot{p.SlotA, p.SlotB} {
		m := wire.NativePairGroupKeyManifest{NativePairGroupKeyClaims: wire.NativePairGroupKeyClaims{Version: 1, Operation: "group-endpoint-key-grant:v1", HubID: p.Scope.Actor.HubID, OwnerID: p.Scope.Actor.OwnerID, PrincipalID: s.PrincipalID, GroupID: p.GroupID, GroupRevision: int64(p.GroupRevision), EndpointID: s.EndpointID, NodeID: s.NodeID, BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, MembershipRevision: int64(s.MembershipRevision + 1), EndpointJoinRevision: int64(s.EndpointJoinRevision), CandidateVersion: int64(s.CandidateVersion), CandidateKeyID: s.CandidatePublic.ID, CandidateFingerprint: s.CandidateFingerprint, CandidateProofDigest: s.CandidateProofDigest, CandidatePublicIdentity: s.CandidatePublic, OwnerKeyID: p.Scope.Actor.OwnerPublic.ID, IssuedAt: p.PreparedAt, ExpiresAt: p.PeerExpiresAt}, CandidateAttestation: s.CandidateAttestation}
		m.CandidateBindingDigest, _ = wire.NativePairGroupBindingDigest(m)
		m.Digest, _ = wire.NativePairGroupManifestDigest(m)
		if i == 0 {
			p.SlotAKeyManifest = m
		} else {
			p.SlotBKeyManifest = m
		}
	}
	p.Digest, _ = wire.NativePairPlanDigest(p)
	if err := wire.ValidateNativePairPlan(p, f.c.hub); err != nil {
		f.t.Fatal("invalid scripted plan", err)
	}
	f.plan = p
}

func (f *pairActorFixture) dispatch(a Action) error { return f.c.Dispatch(context.Background(), a) }
func (f *pairActorFixture) prepareSlots() {
	f.t.Helper()
	if err := f.dispatch(Action{Kind: ActionPreparePair, Pair: PairAction{Label: "Synthetic dialogue"}}); err != nil {
		f.t.Fatal(err)
	}
	s := f.c.Snapshot()
	if err := f.dispatch(Action{Kind: ActionCompletePair, Pair: PairAction{PairID: s.Pair.PairID, ReviewID: s.Pair.ReviewID, ConfirmBootstrap: true}}); err != nil {
		f.t.Fatal(err)
	}
	f.joinSyntheticSlots()
	if err := f.dispatch(Action{Kind: ActionRefreshPair}); err != nil {
		f.t.Fatal(err)
	}
	if err := f.dispatch(Action{Kind: ActionPreparePairConsent, Pair: PairAction{PairID: f.result.PairID}}); err != nil {
		f.t.Fatal(err)
	}
}
func (f *pairActorFixture) approve(slot string) error {
	s := f.c.Snapshot()
	return f.dispatch(Action{Kind: ActionApprovePairSlot, Pair: PairAction{PairID: s.Pair.PairID, ReviewID: s.Pair.ReviewID, Slot: slot, ConfirmSlot: true}})
}

func TestPairControllerTwoExplicitConsentsAndProjectedActivation(t *testing.T) {
	f := newPairActorFixture(t)
	owner, device := f.c.owner.Public().ID, f.c.device.Public().ID
	f.prepareSlots()
	s := f.c.Snapshot()
	if s.Pair.State != "WAITING_CONSENT" || !s.Pair.AdministrativePermission || s.Pair.Slots[0].ConsentRecorded {
		t.Fatal("plan prematurely authorized a slot")
	}
	if f.dispatch(Action{Kind: ActionApprovePairSlot, Pair: PairAction{PairID: s.Pair.PairID, ReviewID: s.Pair.ReviewID, Slot: "A"}}) == nil || len(f.consents) != 0 {
		t.Fatal("slot consent bypassed explicit confirmation")
	}
	if err := f.approve("A"); err != nil {
		t.Fatal(err)
	}
	s = f.c.Snapshot()
	if s.Pair.State != "WAITING_CONSENT" || !s.Pair.Slots[0].ConsentRecorded || s.Pair.Slots[1].ConsentRecorded || s.Pair.ReviewID == "" {
		t.Fatal("first consent activated peers or lost the second review")
	}
	if f.approve("A") == nil || len(f.consents) != 1 {
		t.Fatal("first slot was silently signed twice")
	}
	if err := f.dispatch(Action{Kind: ActionPreparePairConsent, Pair: PairAction{PairID: s.Pair.PairID}}); err != nil {
		t.Fatal(err)
	}
	if !f.c.Snapshot().Pair.Slots[0].ConsentRecorded || f.approve("A") == nil {
		t.Fatal("reviewing the unchanged plan forgot the already recorded first consent")
	}
	if err := f.approve("B"); err != nil {
		t.Fatal(err)
	}
	s = f.c.Snapshot()
	if s.Pair.State != "ACTIVE" || !s.Pair.Current || !s.Pair.Slots[0].ConsentRecorded || !s.Pair.Slots[1].ConsentRecorded || s.Pair.ReviewID != "" {
		t.Fatal("second consent failed projected activation")
	}
	if f.c.owner.Public().ID != owner || f.c.device.Public().ID != device {
		t.Fatal("Pair flow replaced existing local keys")
	}
	before := len(f.posts[wire.OperationNativePairStatus])
	f.c.Snapshot()
	f.c.Snapshot()
	if len(f.posts[wire.OperationNativePairStatus]) != before {
		t.Fatal("idle snapshot polled Pair")
	}
	if err := f.dispatch(Action{Kind: ActionRevokePair, Pair: PairAction{PairID: s.Pair.PairID, ReviewID: s.Pair.StateReviewID, ConfirmRevoke: true}}); err != nil || f.c.Snapshot().Pair.State != "REVOKED" {
		t.Fatal("explicit revoke failed", err)
	}
}

func TestPairControllerDelayedClicksKeepManifestTimeAndFreshOwnerIntent(t *testing.T) {
	f := newPairActorFixture(t)
	f.prepareSlots()
	for i, slot := range []string{"A", "B"} {
		f.n.n2.now = f.n.n2.now.Add(time.Duration(i+2) * time.Second)
		if err := f.approve(slot); err != nil {
			t.Fatal(err)
		}
		raw := f.posts[wire.OperationNativePairConsentComplete][i]
		packet, err := wire.DecodeNativePairPacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		var q wire.NativePairConsentComplete
		device := f.c.device.Public()
		r := packet.Packet.Route
		binding := clientwire.Binding{HubID: r.HubID, OwnerID: r.OwnerID, DeviceID: r.DeviceID, SessionEpoch: wire.HandshakeEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
		if err := wire.OpenRequestAt(f.n.n2.hubKey, &device, binding, r, raw, &q, time.Time{}); err != nil {
			t.Fatal(err)
		}
		intent, err := e2ee.VerifyOwnerNativePair(f.c.owner.Public(), q.OwnerProof, e2ee.OwnerNativePairSlotConsent, f.n.n2.now)
		if err != nil || intent.IssuedAt != f.n.stamp(f.n.n2.now) || intent.IssuedAt == f.plan.PreparedAt {
			t.Fatal("click reused the old plan time for its fresh Owner intent", err)
		}
	}
	if f.c.Snapshot().Pair.State != string(wire.NativePairActive) {
		t.Fatal("delayed distinct clicks did not activate their exact reviewed plan")
	}
}

func TestPairControllerRejectsActivationOutsideProjectedMembership(t *testing.T) {
	f := newPairActorFixture(t)
	f.prepareSlots()
	if err := f.approve("A"); err != nil {
		t.Fatal(err)
	}
	f.badProjection = true
	if f.approve("B") == nil || !f.c.hasPairPending() || f.c.Snapshot().Pair.State == "ACTIVE" {
		t.Fatal("unreviewed endpoint revision became active")
	}
}

func TestPairControllerLostConsentUsesExactOriginalAndDetachedReconcile(t *testing.T) {
	f := newPairActorFixture(t)
	f.prepareSlots()
	f.drop = wire.OperationNativePairConsentComplete
	if f.approve("A") == nil || !f.c.hasPairPending() || len(f.consents) != 1 {
		t.Fatal("lost response was treated as confirmed")
	}
	original := bytes.Clone(f.c.pairOriginal.Packet)
	defer clear(original)
	f.deny = wire.OperationNativePairConsentComplete
	if err := f.dispatch(Action{Kind: ActionRecoverPair}); err != nil {
		t.Fatal(err)
	}
	requests := f.posts[wire.OperationNativePairConsentComplete]
	if len(requests) != 2 || !bytes.Equal(requests[0], original) || !bytes.Equal(requests[1], original) || len(f.posts[wire.OperationNativePairReconcile]) != 1 || len(f.consents) != 1 || f.c.hasPairPending() {
		t.Fatal("recovery regenerated an original, duplicated consent, or trusted unsigned HTTP")
	}
	if f.c.Snapshot().Pair.AdministrativePermission || f.c.Snapshot().Pair.State == "ACTIVE" {
		t.Fatal("historical reconciliation became current peer authority")
	}
	f.n.n2.now = f.n.n2.now.Add(2 * time.Hour)
	f.n.reopen(t)
	f.c = f.n.c
	if f.c.hasPairPending() || f.c.Snapshot().Pair.AdministrativePermission || f.c.Snapshot().Pair.State == "ACTIVE" {
		t.Fatal("restart restored expired administrative authority")
	}
}

func TestPairControllerAbsentCapabilitiesSendNoOwnerProof(t *testing.T) {
	for _, mode := range []string{"http-404", "available-false"} {
		t.Run(mode, func(t *testing.T) {
			f := newPairActorFixture(t)
			f.available = false
			f.unavailableDocument = mode == "available-false"
			if f.dispatch(Action{Kind: ActionPreparePair, Pair: PairAction{Label: "Synthetic dialogue"}}) == nil || len(f.posts) != 0 || f.c.hasPairPending() {
				t.Fatal("missing public capability emitted an Owner proof")
			}
		})
	}
}

func TestPairControllerRejectsOnlyReviewedSlotAndClearsConsentPlan(t *testing.T) {
	f := newPairActorFixture(t)
	f.prepareSlots()
	if err := f.dispatch(Action{Kind: ActionRefreshPair}); err != nil {
		t.Fatal(err)
	}
	s := f.c.Snapshot()
	if f.dispatch(Action{Kind: ActionRejectPairSlot, Pair: PairAction{PairID: s.Pair.PairID, ReviewID: "stale-review", Slot: "A"}}) == nil || len(f.posts[wire.OperationNativePairSlotReject]) != 0 {
		t.Fatal("stale review signed rejection")
	}
	if err := f.dispatch(Action{Kind: ActionRejectPairSlot, Pair: PairAction{PairID: s.Pair.PairID, ReviewID: s.Pair.StateReviewID, Slot: "A"}}); err != nil {
		t.Fatal(err)
	}
	s = f.c.Snapshot()
	if s.Pair.Slots[0].NativeSessionID != "" || s.Pair.Slots[1].NativeSessionID == "" || s.Pair.ReviewID != "" || containsAction(s.AvailableActions, ActionApprovePairSlot) || len(f.consents) != 0 {
		t.Fatal("rejection authorized a peer, removed the other slot, or retained stale consent plan")
	}
}

func TestPairControllerExpiredReadAndIncompleteActiveNeverGrantAdministration(t *testing.T) {
	for _, mode := range []string{"read-expired", "incomplete-active"} {
		t.Run(mode, func(t *testing.T) {
			f := newPairActorFixture(t)
			f.prepareSlots()
			if mode == "read-expired" {
				f.readExpired = true
				if err := f.dispatch(Action{Kind: ActionRefreshPair}); err != nil {
					t.Fatal(err)
				}
				if f.c.Snapshot().Pair.Current || f.c.Snapshot().Pair.AdministrativePermission || f.c.hasPairPending() {
					t.Fatal("expired read retained live administration")
				}
			} else {
				f.result.State = wire.NativePairActive
				if f.dispatch(Action{Kind: ActionRefreshPair}) == nil || f.c.Snapshot().Pair.State == "ACTIVE" || !f.c.hasPairPending() {
					t.Fatal("incomplete active slots granted authority")
				}
			}
		})
	}
}

func TestPairControllerKnownMutationFencesSettleOnlyOriginalWithoutPermission(t *testing.T) {
	for _, op := range []string{wire.OperationNativePairBootstrapComplete, wire.OperationNativePairConsentPrepare, wire.OperationNativePairConsentComplete, wire.OperationNativePairSlotReject, wire.OperationNativePairRevoke} {
		t.Run(op, func(t *testing.T) {
			f := newPairActorFixture(t)
			if op == wire.OperationNativePairBootstrapComplete {
				if err := f.dispatch(Action{Kind: ActionPreparePair, Pair: PairAction{Label: "Synthetic fence"}}); err != nil {
					t.Fatal(err)
				}
			} else {
				f.prepareSlots()
			}
			before := f.c.Snapshot().Pair.State
			f.fence = op
			s := f.c.Snapshot()
			action := Action{Pair: PairAction{PairID: s.Pair.PairID, ReviewID: s.Pair.StateReviewID, Slot: "A"}}
			switch op {
			case wire.OperationNativePairBootstrapComplete:
				action.Kind = ActionCompletePair
				action.Pair.ReviewID = s.Pair.ReviewID
				action.Pair.ConfirmBootstrap = true
			case wire.OperationNativePairConsentPrepare:
				action.Kind = ActionPreparePairConsent
			case wire.OperationNativePairConsentComplete:
				action.Kind = ActionApprovePairSlot
				action.Pair.ReviewID = s.Pair.ReviewID
				action.Pair.ConfirmSlot = true
			case wire.OperationNativePairSlotReject:
				action.Kind = ActionRejectPairSlot
			case wire.OperationNativePairRevoke:
				action.Kind = ActionRevokePair
				action.Pair.ConfirmRevoke = true
			}
			if err := f.dispatch(action); err != nil {
				t.Fatal(err)
			}
			s = f.c.Snapshot()
			if s.Pair.State != before || s.Pair.Current || s.Pair.AdministrativePermission || s.Pair.ErrorCode != "APP_PAIR_REQUEST_FENCED" || f.c.hasPairPending() || !f.c.pairOriginal.Applied || len(f.consents) != 0 {
				t.Fatal("known no-effect fence changed domain state, left uncertainty, or granted permission")
			}
		})
	}
}
