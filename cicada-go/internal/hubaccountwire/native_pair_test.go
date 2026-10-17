package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type nativePairFixture struct {
	f         appNodeCryptoFixture
	scope     e2ee.OwnerNativePairScope
	bootstrap e2ee.OwnerNativePairClaims
	plan      NativePairConsentPlan
	evidence  NativePairPeerEvidence
}

func nativePairClaims(f nativePairFixture, purpose string, id string) e2ee.OwnerNativePairClaims {
	return e2ee.OwnerNativePairClaims{Version: 1, Purpose: purpose, Scope: f.scope, RequestID: id, Nonce: strings.Repeat("d", 64), IssuedAt: formatUTC(f.f.now), ExpiresAt: formatUTC(f.f.now.Add(time.Minute))}
}

func nativePairTestFixture(t *testing.T) nativePairFixture { return nativePairSizedFixture(t, false) }

func nativePairSizedFixture(t *testing.T, maximum bool) nativePairFixture {
	t.Helper()
	f := nativePairFixture{f: appNodeCrypto(t)}
	if maximum {
		f.f.now = f.f.now.Add(999999999 * time.Nanosecond)
		f.f.hub.HubID = strings.Repeat("h", 128)
		f.f.scope.HubID = f.f.hub.HubID
		f.f.scope.HubFingerprint, _ = HubFingerprint(f.f.hub)
		f.f.scope.Origin = "https://" + strings.Repeat("&", 504)
		f.f.scope.AccountID = strings.Repeat("a", 128)
		f.f.scope.AccountSessionID = strings.Repeat("s", 128)
		f.f.scope.OwnerID = strings.Repeat("o", 128)
		f.f.scope.AccountSessionExpiresAt = formatUTC(f.f.now.Add(14 * time.Minute))
		f.f.scope.OwnerKeyVersion = math.MaxInt64 - 1
		f.f.scope.AccountEpoch = math.MaxInt64 - 1
		f.f.scope.DeviceEpoch = math.MaxInt64 - 1
		f.f.scope.ClientSessionEpoch = math.MaxInt64 - 1
	}
	token := func(s string) string {
		if maximum {
			return s + strings.Repeat("x", 128-len(s))
		}
		return "synthetic-" + s
	}
	keys := make([]*e2ee.Identity, 4)
	for i := range keys {
		var err error
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	f.scope = e2ee.OwnerNativePairScope{Actor: f.f.scope, NodeControlBindingVersion: 1, CredentialCommitment: strings.Repeat("b", 64)}
	f.scope.Node = e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-owner-binding", OwnerID: f.scope.Actor.OwnerID, HubID: f.scope.Actor.HubID, NodeID: "synthetic-node", NodeName: "Synthetic pair Node", ClientDeviceID: f.scope.Actor.DeviceID, OwnerKeyID: f.f.owner.Public().ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: keys[0].Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(keys[0].Public()), NodeKeyVersion: 1, NodeKeyEpoch: 1, HubNodeControlPublic: keys[1].Public(), HubNodeControlFingerprint: nodewire.IdentityFingerprint(keys[1].Public()), HubNodeControlKeyVersion: 1, ApprovedRequestID: "synthetic-node-approved", ApprovedRequestVersion: 1, ApprovedCandidateDigest: strings.Repeat("c", 64), ApprovedAt: formatUTC(f.f.now.Add(-time.Minute)), State: "ACTIVE"}
	if maximum {
		f.scope.Node.OwnerBindingID = token("owner-binding")
		f.scope.Node.NodeID = token("node")
		f.scope.Node.NodeName = strings.Repeat("<", 128)
		f.scope.Node.ApprovedRequestID = token("approved")
		f.scope.Node.BindingVersion = math.MaxInt64 - 1
		f.scope.Node.CredentialVersion = math.MaxInt64 - 1
		f.scope.Node.NodeKeyVersion = math.MaxInt64 - 1
		f.scope.Node.NodeKeyEpoch = math.MaxInt64 - 1
		f.scope.Node.HubNodeControlKeyVersion = math.MaxInt64 - 1
		f.scope.Node.ApprovedRequestVersion = math.MaxInt64 - 1
		f.scope.NodeControlBindingVersion = math.MaxInt64 - 1
	}
	f.scope.NodeTupleDigest, _ = NativePairNodeTupleDigest(f.scope)
	f.bootstrap = nativePairClaims(f, e2ee.OwnerNativePairBootstrapCommit, strings.Repeat("1", 32))
	f.bootstrap.Bootstrap = &e2ee.NativePairBootstrapClaims{PairID: strings.Repeat("2", 32), NetworkID: "synthetic-pair-network", GroupID: "synthetic-pair-group", GroupLabel: "Synthetic pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: formatUTC(f.f.now), JoinUntil: formatUTC(f.f.now.Add(10 * time.Minute)), PeerExpiresAt: formatUTC(f.f.now.Add(time.Hour)), PrepareRequestID: strings.Repeat("3", 32), PreparePacketDigest: strings.Repeat("4", 64), ServerNonce: strings.Repeat("5", 64)}
	if maximum {
		f.bootstrap.Bootstrap.NetworkID = token("network")
		f.bootstrap.Bootstrap.GroupID = token("group")
		f.bootstrap.Bootstrap.GroupLabel = strings.Repeat("<", 128)
	}
	bproof, err := e2ee.SignOwnerNativePair(f.f.owner, f.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	f.plan = NativePairConsentPlan{Format: NativePairFormat, PairID: f.bootstrap.Bootstrap.PairID, ExpectedRevision: 2, PlanID: strings.Repeat("6", 32), Scope: f.scope, BootstrapProofDigest: NativePairProofDigest(bproof), NetworkID: f.bootstrap.Bootstrap.NetworkID, NetworkVersion: 1, GroupID: f.bootstrap.Bootstrap.GroupID, GroupVersion: 1, GroupRevision: 1, ProjectedSlotAMembership: 2, ProjectedSlotBMembership: 2, GroupGrants: NativePairGroupGrants(), Policy: e2ee.NativePairFixedPeerPolicy(), PreparedAt: formatUTC(f.f.now), ExpiresAt: formatUTC(f.f.now.Add(5 * time.Minute)), PeerExpiresAt: f.bootstrap.Bootstrap.PeerExpiresAt}
	if maximum {
		f.plan.ExpectedRevision = math.MaxInt64 - 1
		f.plan.NetworkVersion = math.MaxInt64 - 1
		f.plan.GroupVersion = math.MaxInt64 - 1
		f.plan.GroupRevision = math.MaxInt64 - 1
		f.plan.ProjectedSlotAMembership = math.MaxInt64 - 1
		f.plan.ProjectedSlotBMembership = math.MaxInt64 - 1
	}
	for i := 0; i < 2; i++ {
		letter := string(rune('A' + i))
		suffix := strings.ToLower(letter)
		s := NativePairSlot{Slot: letter, Generation: 1, AttemptID: strings.Repeat(string(rune('7'+i)), 32), NativeSessionID: "synthetic-native-" + suffix, Runtime: "codex", EndpointID: "synthetic-endpoint-" + suffix, PrincipalID: "synthetic-principal-" + suffix, NodeID: f.scope.Node.NodeID, NetworkAccessBindingID: "synthetic-network-binding-" + suffix, NetworkAccessEpoch: 1, NetworkMembershipRevision: 1, EndpointNetworkRevision: 1, BindingID: "synthetic-group-binding-" + suffix, BindingEpoch: 1, LeaseOwner: "synthetic-lease-" + suffix, LeaseCeiling: f.plan.PeerExpiresAt, MembershipRevision: 1, EndpointJoinRevision: 1, CandidateVersion: 1, CandidatePublic: keys[2+i].Public()}
		if maximum {
			s.Generation = 16
			s.NativeSessionID = token("native-" + suffix)
			s.EndpointID = token("endpoint-" + suffix)
			s.PrincipalID = token("principal-" + suffix)
			s.NetworkAccessBindingID = token("network-binding-" + suffix)
			s.BindingID = token("group-binding-" + suffix)
			s.LeaseOwner = token("lease-" + suffix)
			s.NetworkAccessEpoch = math.MaxInt64 - 1
			s.NetworkMembershipRevision = math.MaxInt64 - 1
			s.EndpointNetworkRevision = math.MaxInt64 - 1
			s.BindingEpoch = math.MaxInt64 - 1
			s.MembershipRevision = math.MaxInt64 - 2
			s.EndpointJoinRevision = math.MaxInt64 - 1
			s.CandidateVersion = math.MaxInt64 - 1
		}
		s.CandidateAttestation, err = keys[2+i].SignEndpointKeyAttestation(s.EndpointID, s.PrincipalID, s.NodeID, s.BindingID, s.BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(s.CandidateAttestation)
		s.CandidateProofDigest = hex.EncodeToString(h[:])
		s.CandidateFingerprint = nativePairPeerFingerprint(s.CandidatePublic)
		m := NativePairGroupKeyManifest{NativePairGroupKeyClaims: NativePairGroupKeyClaims{Version: 1, Operation: "group-endpoint-key-grant:v1", HubID: f.scope.Actor.HubID, OwnerID: f.scope.Actor.OwnerID, PrincipalID: s.PrincipalID, GroupID: f.plan.GroupID, GroupRevision: int64(f.plan.GroupRevision), EndpointID: s.EndpointID, NodeID: s.NodeID, BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, MembershipRevision: int64(s.MembershipRevision + 1), EndpointJoinRevision: int64(s.EndpointJoinRevision), CandidateVersion: int64(s.CandidateVersion), CandidateKeyID: s.CandidatePublic.ID, CandidateFingerprint: s.CandidateFingerprint, CandidateProofDigest: s.CandidateProofDigest, CandidatePublicIdentity: s.CandidatePublic, OwnerKeyID: f.f.owner.Public().ID, IssuedAt: f.plan.PreparedAt, ExpiresAt: f.plan.PeerExpiresAt}, CandidateAttestation: s.CandidateAttestation}
		m.CandidateBindingDigest, _ = NativePairGroupBindingDigest(m)
		m.Digest, _ = NativePairGroupManifestDigest(m)
		if i == 0 {
			f.plan.SlotA = s
			f.plan.SlotAKeyManifest = m
		} else {
			f.plan.SlotB = s
			f.plan.SlotBKeyManifest = m
		}
	}
	f.plan.Digest, _ = NativePairPlanDigest(f.plan)
	f.evidence = NativePairPeerEvidence{ContractRevision: NativePairContractRevision, Plan: f.plan, BootstrapOwnerProof: bproof}
	for i, s := range []NativePairSlot{f.plan.SlotA, f.plan.SlotB} {
		c := nativePairSlotConsent(f, s)
		raw, err := e2ee.SignOwnerNativePair(f.f.owner, c)
		if err != nil {
			t.Fatal(err)
		}
		m := f.plan.SlotAKeyManifest
		if i == 1 {
			m = f.plan.SlotBKeyManifest
		}
		gp, err := f.f.owner.SignOwnerLinkKeyGrant(f.scope.Actor.OwnerID, "group-endpoint-key-grant:v1", m.Digest, m.CandidateBindingDigest, uint64(m.CandidateVersion), e2ee.OwnerLinkGrantSideSource, f.f.now, f.f.now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.evidence.SlotAOwnerConsent = raw
			f.evidence.SlotAGroupKeyProof = gp
		} else {
			f.evidence.SlotBOwnerConsent = raw
			f.evidence.SlotBGroupKeyProof = gp
		}
	}
	return f
}

func nativePairSlotConsent(f nativePairFixture, s NativePairSlot) e2ee.OwnerNativePairClaims {
	c := nativePairClaims(f, e2ee.OwnerNativePairSlotConsent, strings.Repeat("9", 32))
	other := f.plan.SlotB
	if s.Slot == "B" {
		other = f.plan.SlotA
		c.RequestID = strings.Repeat("a", 32)
	}
	a, _ := NativePairSlotDigest(f.plan.SlotA)
	b, _ := NativePairSlotDigest(f.plan.SlotB)
	c.Consent = &e2ee.NativePairConsentClaims{PairID: f.plan.PairID, ExpectedRevision: f.plan.ExpectedRevision, PlanID: f.plan.PlanID, PlanDigest: f.plan.Digest, SlotADigest: a, SlotBDigest: b, Slot: s.Slot, SlotGeneration: s.Generation, SlotAttemptID: s.AttemptID, NativeSessionID: s.NativeSessionID, PeerNativeSessionID: other.NativeSessionID, ActivateWhenBoth: true, PlanExpiresAt: f.plan.ExpiresAt, PeerExpiresAt: f.plan.PeerExpiresAt}
	return c
}

func nativePairContext(c e2ee.OwnerNativePairClaims) NativePairRequestContext {
	s := c.Scope.Actor
	nonce, _ := hex.DecodeString(c.Nonce)
	return NativePairRequestContext{Origin: s.Origin, HubID: s.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountSessionID: s.AccountSessionID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, ClientSessionEpoch: s.ClientSessionEpoch, RequestID: c.RequestID, ClientNonce: nonce, IssuedAt: c.IssuedAt}
}

func TestNativePairIndependentPolicyEvidence(t *testing.T) {
	f := nativePairTestFixture(t)
	check := func(e NativePairPeerEvidence, now time.Time) error {
		return VerifyNativePairPeerEvidence(e, f.f.hub, f.f.owner.Public(), f.scope.NodeTupleDigest, now)
	}
	if err := check(f.evidence, f.f.now); err != nil {
		t.Fatal(err)
	}
	// Administration has expired, but independently consented peers remain live.
	if err := check(f.evidence, f.f.now.Add(20*time.Minute)); err != nil {
		t.Fatal("admin expiry revoked peer evidence", err)
	}
	if err := ValidateNativePairPlanForConsent(f.plan, f.f.hub, f.f.now.Add(20*time.Minute)); err == nil {
		t.Fatal("expired administration accepted")
	}
	if err := check(f.evidence, f.f.now.Add(time.Hour)); err == nil {
		t.Fatal("exclusive peer deadline accepted")
	}
	wrong, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyNativePairPeerEvidence(f.evidence, f.f.hub, wrong.Public(), f.scope.NodeTupleDigest, f.f.now) == nil {
		t.Fatal("untrusted Owner accepted")
	}
	if VerifyNativePairPeerEvidence(f.evidence, f.f.hub, f.f.owner.Public(), "", f.f.now) == nil {
		t.Fatal("missing pinned Node tuple accepted")
	}
	cases := []struct {
		name string
		edit func(*NativePairPeerEvidence)
	}{
		{"missing_bootstrap", func(e *NativePairPeerEvidence) { e.BootstrapOwnerProof = nil }},
		{"missing_slot", func(e *NativePairPeerEvidence) { e.SlotBOwnerConsent = nil }},
		{"missing_group_proof", func(e *NativePairPeerEvidence) { e.SlotAGroupKeyProof = nil }},
		{"swapped_slot", func(e *NativePairPeerEvidence) {
			e.SlotAOwnerConsent, e.SlotBOwnerConsent = e.SlotBOwnerConsent, e.SlotAOwnerConsent
		}},
		{"swapped_group_proof", func(e *NativePairPeerEvidence) {
			e.SlotAGroupKeyProof, e.SlotBGroupKeyProof = e.SlotBGroupKeyProof, e.SlotAGroupKeyProof
		}},
		{"expanded_budget", func(e *NativePairPeerEvidence) { e.Plan.Policy.MaxMessages++ }},
		{"new_sid", func(e *NativePairPeerEvidence) { e.Plan.SlotA.NativeSessionID = "synthetic-other-sid" }},
		{"source_revision", func(e *NativePairPeerEvidence) { e.Plan.SlotA.MembershipRevision++ }},
		{"projected_revision", func(e *NativePairPeerEvidence) { e.Plan.SlotAKeyManifest.MembershipRevision++ }},
		{"attestation", func(e *NativePairPeerEvidence) { e.Plan.SlotA.CandidateAttestation[0] ^= 1 }},
		{"wrong_node_epoch", func(e *NativePairPeerEvidence) { e.Plan.Scope.Node.NodeKeyEpoch++ }},
		{"other_pair", func(e *NativePairPeerEvidence) { e.Plan.PairID = strings.Repeat("f", 32) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(f.evidence)
			var e NativePairPeerEvidence
			_ = json.Unmarshal(raw, &e)
			tc.edit(&e)
			if check(e, f.f.now) == nil {
				t.Fatal("invalid/downgraded evidence accepted")
			}
		})
	}
	c := nativePairSlotConsent(f, f.plan.SlotA)
	p := f.plan
	p.Policy.MaxMessages++
	if ValidateNativePairConsentTarget(c, p) == nil {
		t.Fatal("target helper trusted stale digest")
	}
}

func TestNativePairCanonicalStableAuthorityDigests(t *testing.T) {
	f := nativePairTestFixture(t)
	s := f.scope
	s.Node.NodeName = "renamed display"
	s.Actor.AccountSessionID = "different-login"
	s.Actor.AccountSessionExpiresAt = formatUTC(f.f.now.Add(30 * time.Minute))
	d, _ := NativePairNodeTupleDigest(s)
	if d != f.scope.NodeTupleDigest {
		t.Fatal("label/login made authority stale")
	}
	s.Node.CredentialVersion++
	d, _ = NativePairNodeTupleDigest(s)
	if d == f.scope.NodeTupleDigest {
		t.Fatal("credential rotation preserved authority digest")
	}
	p := f.plan
	p.SlotA.Generation = 17
	p.Digest, _ = NativePairPlanDigest(p)
	if ValidateNativePairPlan(p, f.f.hub) == nil {
		t.Fatal("slot generation cap ignored")
	}
	p = f.plan
	p.GroupGrants = append(NativePairGroupGrants(), "message.send")
	p.Digest, _ = NativePairPlanDigest(p)
	if ValidateNativePairPlan(p, f.f.hub) == nil {
		t.Fatal("broad grants accepted")
	}
}

func TestNativePairRealPQPacketsAndRecovery(t *testing.T) {
	f := nativePairTestFixture(t)
	c := nativePairSlotConsent(f, f.plan.SlotA)
	q := NativePairConsentComplete{Format: NativePairFormat, Context: nativePairContext(c), SessionToken: bytes.Repeat([]byte{7}, MaxSessionTokenBytes), OwnerProof: f.evidence.SlotAOwnerConsent, GroupKeyProof: f.evidence.SlotAGroupKeyProof}
	raw, err := SealClientRequest(f.f.device, f.f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.f.hub, q, f.f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := f.f.device.Public()
	var got NativePairConsentComplete
	if err = OpenRequestAt(f.f.hubPrivate, &pub, b, r, raw, &got, f.f.now); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(q, got) {
		t.Fatal("PQ request changed")
	}
	res := NativePairResult{Format: NativePairFormat, Operation: r.Operation, RequestID: r.OperationID, RequestPacketDigest: NativePairPacketDigest(raw), PairID: f.plan.PairID, State: NativePairWaitingConsent, Outcome: "COMPLETED", ControlRevision: 2, AdministrativePermission: true, SlotAState: NativePairSlotConsentRecorded, SlotBState: NativePairSlotCandidateReady, PeerExpiresAt: f.plan.PeerExpiresAt, ObservedAt: formatUTC(f.f.now)}
	receipt, err := SealResponse(f.f.hubPrivate, pub, r, res)
	if err != nil {
		t.Fatal(err)
	}
	var result NativePairResult
	if err = OpenClientResponse(f.f.device, f.f.hub, raw, receipt, &result); err != nil {
		t.Fatal(err)
	}
	res.RequestPacketDigest = strings.Repeat("0", 64)
	bad, err := SealResponse(f.f.hubPrivate, pub, r, res)
	if err != nil {
		t.Fatal(err)
	}
	if OpenClientResponse(f.f.device, f.f.hub, raw, bad, &result) == nil {
		t.Fatal("wrong original digest accepted")
	}
	// Detached recovery carries no live session bearer or Owner proof.
	ctx := q.Context
	ctx.RequestID = strings.Repeat("b", 32)
	ctx.IssuedAt = formatUTC(f.f.now.Add(30 * time.Minute))
	recovery := NativePairReconcileRequest{Format: NativePairFormat, Context: ctx, PairID: f.plan.PairID, OriginalPacket: raw}
	rr, err := SealClientRequest(f.f.device, f.f.hub, recovery)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err = NewClientRoute(f.f.hub, recovery, pub)
	if err != nil {
		t.Fatal(err)
	}
	var rg NativePairReconcileRequest
	if OpenRequestAt(f.f.hubPrivate, &pub, b, r, rr, &rg, f.f.now.Add(30*time.Minute)) != nil {
		t.Fatal("recovery required fresh admission")
	}
	rc := NativePairReconciled{Format: NativePairFormat, RequestID: r.OperationID, RequestPacketDigest: NativePairPacketDigest(rr), PairID: f.plan.PairID, OriginalOperation: OperationNativePairConsentComplete, OriginalRequestID: c.RequestID, OriginalPacketDigest: NativePairPacketDigest(raw), State: "COMPLETED", ReceiptPacket: receipt, ObservedAt: ctx.IssuedAt}
	response, err := SealResponse(f.f.hubPrivate, pub, r, rc)
	if err != nil {
		t.Fatal(err)
	}
	var recovered NativePairReconciled
	if OpenClientResponse(f.f.device, f.f.hub, rr, response, &recovered) != nil || ValidateNativePairReconcileTarget(recovered, f.plan.PairID, raw) != nil {
		t.Fatal("exact recovery failed")
	}
	if ValidateNativePairReconcileTarget(recovered, strings.Repeat("f", 32), raw) == nil {
		t.Fatal("other pair recovery accepted")
	}
	if err = OpenRequestAt(f.f.hubPrivate, &pub, b, r, rr, &rg, f.f.now.Add(31*time.Minute+time.Second)); err == nil {
		t.Fatal("stale diagnostic request accepted")
	}
	if clientwire.Version != 1 {
		t.Fatal("frozen wire changed")
	}
}

func TestNativePairActualPQPayloadSizes(t *testing.T) {
	f := nativePairSizedFixture(t, true)
	raw, _ := json.Marshal(f.evidence)
	plan, _ := json.Marshal(f.plan)
	t.Logf("real_pq_bytes bootstrap=%d consentA=%d consentB=%d groupA=%d groupB=%d plan=%d evidence=%d", len(f.evidence.BootstrapOwnerProof), len(f.evidence.SlotAOwnerConsent), len(f.evidence.SlotBOwnerConsent), len(f.evidence.SlotAGroupKeyProof), len(f.evidence.SlotBGroupKeyProof), len(plan), len(raw))
	carrierProbe, _ := json.Marshal(struct {
		Evidence NativePairPeerEvidence `json:"native_pair_evidence"`
		Metadata []byte                 `json:"existing_metadata"`
	}{f.evidence, make([]byte, 32*1024)})
	_, route, err := RequestRoute(f.f.hub, f.scope.Actor.OwnerID, f.scope.Actor.DeviceID, strings.Repeat("d", 32), OperationNativePairConsentPrepare, HandshakeEpoch, f.f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	ch := NativePairPlanChallenge{Format: NativePairFormat, RequestID: route.OperationID, RequestPacketDigest: strings.Repeat("e", 64), Plan: f.plan, ObservedAt: formatUTC(f.f.now)}
	body, _ := json.Marshal(ch)
	binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID, SessionEpoch: route.SessionEpoch, HubKeyVersion: f.f.hub.KeyVersion, DeviceKeyVersion: DeviceKeyVersion}
	inner, err := clientwire.SealResponseWithLimits(f.f.hubPrivate, f.f.device.Public(), binding, responseRoute(route), body, MaxNativePairBodyBytes, MaxNativePairInnerPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	var ip clientwire.Packet
	_ = json.Unmarshal(inner, &ip)
	packet, _ := json.Marshal(Packet{Format: PacketFormat, Version: PacketVersion, SenderPublicIdentity: f.f.hub.Public, Packet: ip})
	t.Logf("max_boundary carrier_with_32KiB_metadata=%d plan_response_plaintext=%d plan_response_inner=%d plan_response_packet=%d", len(carrierProbe), len(body), len(inner), len(packet))
	if len(raw) > MaxNativePairEvidenceBytes || len(plan) > MaxNativePairPlanBytes {
		t.Fatal("full real evidence does not fit")
	}
	carrier, _ := json.Marshal(struct {
		Evidence         NativePairPeerEvidence `json:"native_pair_evidence"`
		ExistingMetadata []byte                 `json:"existing_metadata"`
	}{f.evidence, make([]byte, 32*1024)})
	if len(carrier) > MaxNativePairCarrierBytes {
		t.Fatal("full evidence plus bounded metadata does not fit carrier")
	}
	if ValidateNativePairPlan(f.plan, f.f.hub) != nil || VerifyNativePairPeerEvidence(f.evidence, f.f.hub, f.f.owner.Public(), f.scope.NodeTupleDigest, f.f.now) != nil {
		t.Fatal("maximum valid evidence rejected")
	}
	a, _ := NativePairSlotDigest(f.plan.SlotA)
	bd, _ := NativePairSlotDigest(f.plan.SlotB)
	c := nativePairClaims(f, e2ee.OwnerNativePairConsentPreview, strings.Repeat("d", 32))
	c.Consent = &e2ee.NativePairConsentClaims{PairID: f.plan.PairID, ExpectedRevision: f.plan.ExpectedRevision, SlotADigest: a, SlotBDigest: bd, PeerExpiresAt: f.plan.PeerExpiresAt}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, c)
	if err != nil {
		t.Fatal(err)
	}
	q := NativePairConsentPrepare{Format: NativePairFormat, Context: nativePairContext(c), SessionToken: bytes.Repeat([]byte{7}, MaxSessionTokenBytes), OwnerProof: proof}
	original, err := SealClientRequest(f.f.device, f.f.hub, q)
	if err != nil {
		t.Fatal("maximum prepare request rejected", err)
	}
	ch.RequestPacketDigest = NativePairPacketDigest(original)
	sealed, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, ch)
	if err != nil {
		t.Fatal("maximum Plan response rejected", err)
	}
	var opened NativePairPlanChallenge
	if OpenClientResponse(f.f.device, f.f.hub, original, sealed, &opened) != nil || ValidateNativePairPlanTarget(q, original, opened, f.evidence.BootstrapOwnerProof, f.f.hub, f.f.now) != nil {
		t.Fatal("maximum Plan response/target roundtrip failed")
	}
	frame, err := DecodeNativePairPacket(sealed)
	if err != nil {
		t.Fatal(err)
	}
	frame.Packet.Route.Direction = clientwire.DirectionRequest
	oversizeRequest, _ := json.Marshal(frame)
	if _, err = DecodeNativePairPacket(oversizeRequest); err == nil {
		t.Fatal("request borrowed larger response cap")
	}
	t.Logf("maximum_prepare_request=%d maximum_plan_response=%d", len(original), len(sealed))
	for _, p := range [][]byte{f.evidence.BootstrapOwnerProof, f.evidence.SlotAOwnerConsent, f.evidence.SlotBOwnerConsent} {
		if len(p) > e2ee.MaxOwnerNativePairProofBytes {
			t.Fatal("real proof exceeds cap")
		}
	}
	t.Logf("real_pq_bytes bootstrap=%d consentA=%d consentB=%d groupA=%d groupB=%d plan=%d evidence=%d carrier_with_32KiB_metadata=%d", len(f.evidence.BootstrapOwnerProof), len(f.evidence.SlotAOwnerConsent), len(f.evidence.SlotBOwnerConsent), len(f.evidence.SlotAGroupKeyProof), len(f.evidence.SlotBGroupKeyProof), len(plan), len(raw), len(carrier))
}

func TestNativePairOwnerReviewsExactServerTargets(t *testing.T) {
	f := nativePairTestFixture(t)
	c := nativePairClaims(f, e2ee.OwnerNativePairBootstrapPreview, f.bootstrap.Bootstrap.PrepareRequestID)
	c.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: f.bootstrap.Bootstrap.GroupLabel, Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, c)
	if err != nil {
		t.Fatal(err)
	}
	q := NativePairBootstrapPrepare{Format: NativePairFormat, Context: nativePairContext(c), SessionToken: bytes.Repeat([]byte{7}, MaxSessionTokenBytes), OwnerProof: proof}
	raw, err := SealClientRequest(f.f.device, f.f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	b := *f.bootstrap.Bootstrap
	b.PreparePacketDigest = NativePairPacketDigest(raw)
	ch := NativePairBootstrapChallenge{Format: NativePairFormat, RequestID: c.RequestID, RequestPacketDigest: NativePairPacketDigest(raw), Scope: f.scope, Bootstrap: b, ProofExpiresAt: formatUTC(f.f.now.Add(5 * time.Minute)), ObservedAt: formatUTC(f.f.now)}
	if err = ValidateNativePairBootstrapTarget(q, raw, ch, f.f.hub, f.f.now); err != nil {
		t.Fatal(err)
	}
	_, route, _ := NewClientRoute(f.f.hub, q, f.f.device.Public())
	reply, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), route, ch)
	if err != nil {
		t.Fatal(err)
	}
	var opened NativePairBootstrapChallenge
	if OpenClientResponse(f.f.device, f.f.hub, raw, reply, &opened) != nil {
		t.Fatal("valid bootstrap response rejected")
	}
	for _, edit := range []func(*NativePairBootstrapChallenge){
		func(v *NativePairBootstrapChallenge) { v.Bootstrap.Policy.MaxRootAsks++ },
		func(v *NativePairBootstrapChallenge) {
			v.Bootstrap.JoinUntil = formatUTC(f.f.now.Add(11 * time.Minute))
		},
		func(v *NativePairBootstrapChallenge) { v.ProofExpiresAt = formatUTC(f.f.now.Add(6 * time.Minute)) },
		func(v *NativePairBootstrapChallenge) { v.Scope.Node.NodeName = "unreviewed label" },
		func(v *NativePairBootstrapChallenge) {
			v.RequestPacketDigest = strings.Repeat("f", 64)
			v.Bootstrap.PreparePacketDigest = v.RequestPacketDigest
		},
	} {
		v := ch
		edit(&v)
		if ValidateNativePairBootstrapTarget(q, raw, v, f.f.hub, f.f.now) == nil {
			t.Fatal("unreviewed bootstrap target accepted")
		}
	}
	a, _ := NativePairSlotDigest(f.plan.SlotA)
	bd, _ := NativePairSlotDigest(f.plan.SlotB)
	c = nativePairClaims(f, e2ee.OwnerNativePairConsentPreview, strings.Repeat("b", 32))
	c.Consent = &e2ee.NativePairConsentClaims{PairID: f.plan.PairID, ExpectedRevision: f.plan.ExpectedRevision, SlotADigest: a, SlotBDigest: bd, PeerExpiresAt: f.plan.PeerExpiresAt}
	proof, err = e2ee.SignOwnerNativePair(f.f.owner, c)
	if err != nil {
		t.Fatal(err)
	}
	pq := NativePairConsentPrepare{Format: NativePairFormat, Context: nativePairContext(c), SessionToken: q.SessionToken, OwnerProof: proof}
	pr, err := SealClientRequest(f.f.device, f.f.hub, pq)
	if err != nil {
		t.Fatal(err)
	}
	pc := NativePairPlanChallenge{Format: NativePairFormat, RequestID: c.RequestID, RequestPacketDigest: NativePairPacketDigest(pr), Plan: f.plan, ObservedAt: formatUTC(f.f.now)}
	if err = ValidateNativePairPlanTarget(pq, pr, pc, f.evidence.BootstrapOwnerProof, f.f.hub, f.f.now); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*NativePairConsentPlan){
		func(p *NativePairConsentPlan) { p.PairID = strings.Repeat("f", 32) },
		func(p *NativePairConsentPlan) { p.Scope.Node.NodeName = "unreviewed" },
		func(p *NativePairConsentPlan) { p.SlotA.NativeSessionID = "unreviewed-sid" },
	} {
		p := pc
		p.Plan = f.plan
		edit(&p.Plan)
		p.Plan.Digest, _ = NativePairPlanDigest(p.Plan)
		if ValidateNativePairPlanTarget(pq, pr, p, f.evidence.BootstrapOwnerProof, f.f.hub, f.f.now) == nil {
			t.Fatal("unreviewed plan target accepted")
		}
	}
	if ValidateNativePairPlanTarget(pq, pr, pc, nil, f.f.hub, f.f.now) == nil {
		t.Fatal("missing selected bootstrap accepted")
	}
}

func TestNativePairMaximumReceiptAndLegacyBounds(t *testing.T) {
	f := nativePairTestFixture(t)
	c := nativePairSlotConsent(f, f.plan.SlotA)
	q := NativePairConsentComplete{Format: NativePairFormat, Context: nativePairContext(c), SessionToken: bytes.Repeat([]byte{7}, MaxSessionTokenBytes), OwnerProof: f.evidence.SlotAOwnerConsent, GroupKeyProof: f.evidence.SlotAGroupKeyProof}
	original, err := SealClientRequest(f.f.device, f.f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	ctx := q.Context
	ctx.RequestID = strings.Repeat("b", 32)
	rq := NativePairReconcileRequest{Format: NativePairFormat, Context: ctx, PairID: f.plan.PairID, OriginalPacket: original}
	raw, err := SealClientRequest(f.f.device, f.f.hub, rq)
	if err != nil {
		t.Fatal(err)
	}
	b, r, _ := NewClientRoute(f.f.hub, rq, f.f.device.Public())
	// Opaque bounded maximum exercises framing, not permission to settle a
	// business action. Real historical receipts still need their own verification.
	result := NativePairReconciled{Format: NativePairFormat, RequestID: r.OperationID, RequestPacketDigest: NativePairPacketDigest(raw), PairID: f.plan.PairID, OriginalOperation: OperationNativePairConsentComplete, OriginalRequestID: c.RequestID, OriginalPacketDigest: NativePairPacketDigest(original), State: "COMPLETED", ReceiptPacket: make([]byte, MaxNativePairReceiptBytes), ObservedAt: ctx.IssuedAt}
	reply, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), r, result)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeNativePairPacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) <= MaxPacketBytes {
		t.Fatal("maximum receipt did not exercise explicit pair decoder")
	}
	if _, err = DecodePacket(reply); err == nil {
		t.Fatal("legacy default decoder enlarged")
	}
	var got NativePairReconciled
	if OpenClientResponse(f.f.device, f.f.hub, raw, reply, &got) != nil || !bytes.Equal(got.ReceiptPacket, result.ReceiptPacket) {
		t.Fatal("maximum nested receipt roundtrip failed")
	}
	for _, op := range []string{OperationAppNodeReconcile, OperationActivationStatus, "unknown.operation", OperationNativePairStatus} {
		bad := p
		bad.Packet.Route.Operation = op
		frame, _ := json.Marshal(bad)
		if _, err = DecodeNativePairPacket(frame); err == nil {
			t.Fatal("large frame borrowed legacy/ordinary decoder", op)
		}
		badRoute := r
		badRoute.Operation = op
		if _, err = clientwire.SealNativePairReconcileRequest(f.f.device, f.f.hub.Public, b, badRoute, []byte("{}")); err == nil {
			t.Fatal("large crypto entry accepted another operation", op)
		}
	}
	if _, err = clientwire.SealNativePairReconcileRequest(f.f.device, f.f.hub.Public, b, r, make([]byte, MaxNativePairReconcileBodyBytes+1)); err == nil {
		t.Fatal("reconcile body cap+1 accepted")
	}
	if _, err = clientwire.SealRequestWithLimits(f.f.device, f.f.hub.Public, b, r, []byte("{}"), MaxNativePairReconcileBodyBytes, MaxNativePairReconcileInnerPacketBytes); err == nil {
		t.Fatal("generic crypto ceiling enlarged")
	}
	if _, err = clientwire.OpenNativePairReconcileRequest(f.f.hubPrivate, f.f.device.Public(), b, r, make([]byte, MaxNativePairReconcileInnerPacketBytes+1)); err == nil {
		t.Fatal("reconcile inner cap+1 accepted")
	}
	result.ReceiptPacket = append(result.ReceiptPacket, 0)
	if _, err = SealResponse(f.f.hubPrivate, f.f.device.Public(), r, result); err == nil {
		t.Fatal("receipt cap+1 accepted")
	}
	if _, err = DecodeNativePairPacket(append(reply, bytes.Repeat([]byte{' '}, MaxNativePairReconcilePacketBytes-len(reply)+1)...)); err == nil {
		t.Fatal("large outer cap+1 accepted")
	}
	if ValidateNativePairCarrierSize(struct {
		Body []byte `json:"body"`
	}{make([]byte, MaxNativePairCarrierBytes)}) == nil {
		t.Fatal("oversized carrier accepted")
	}
	exactCarrier := json.RawMessage(`"` + strings.Repeat("x", MaxNativePairCarrierBytes-2) + `"`)
	if ValidateNativePairCarrierSize(exactCarrier) != nil {
		t.Fatal("carrier exact cap rejected")
	}
	exactCarrier = json.RawMessage(`"` + strings.Repeat("x", MaxNativePairCarrierBytes-1) + `"`)
	if ValidateNativePairCarrierSize(exactCarrier) == nil {
		t.Fatal("carrier cap+1 accepted")
	}
	if _, err = DecodeNativePairPacket(original); err != nil {
		t.Fatal("ordinary pair request rejected")
	}
	legacy, _ := NewAppNodeStatus(f.f.session, "", f.f.now)
	legacyPacket, err := SealClientRequest(f.f.device, f.f.hub, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeNativePairPacket(legacyPacket); err == nil {
		t.Fatal("explicit pair decoder accepted small legacy operation")
	}
	t.Logf("maximum_receipt=%d reconcile_packet=%d legacy_outer_limit=%d pair_reconcile_outer_limit=%d", MaxNativePairReceiptBytes, len(reply), MaxPacketBytes, MaxNativePairReconcilePacketBytes)
}

func TestNativePairUnknownPrepareRecoveryAfterSessionExpiry(t *testing.T) {
	f := nativePairTestFixture(t)
	c := nativePairClaims(f, e2ee.OwnerNativePairBootstrapPreview, f.bootstrap.Bootstrap.PrepareRequestID)
	c.Bootstrap = &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}
	proof, err := e2ee.SignOwnerNativePair(f.f.owner, c)
	if err != nil {
		t.Fatal(err)
	}
	q := NativePairBootstrapPrepare{Format: NativePairFormat, Context: nativePairContext(c), SessionToken: bytes.Repeat([]byte{7}, MaxSessionTokenBytes), OwnerProof: proof}
	original, err := SealClientRequest(f.f.device, f.f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	_, or, _ := NewClientRoute(f.f.hub, q, f.f.device.Public())
	bp := *f.bootstrap.Bootstrap
	bp.PreparePacketDigest = NativePairPacketDigest(original)
	challenge := NativePairBootstrapChallenge{Format: NativePairFormat, RequestID: or.OperationID, RequestPacketDigest: NativePairPacketDigest(original), Scope: f.scope, Bootstrap: bp, ProofExpiresAt: formatUTC(f.f.now.Add(5 * time.Minute)), ObservedAt: formatUTC(f.f.now)}
	fence := NativePairBootstrapFence{Format: NativePairFormat, Operation: or.Operation, RequestID: or.OperationID, RequestPacketDigest: NativePairPacketDigest(original), State: "REJECTED_FENCED", NoEffect: true, ErrorCode: "PROOF_EXPIRED", ObservedAt: formatUTC(f.f.now.Add(30 * time.Minute))}
	for _, admitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unadmitted_fence", true: "committed_challenge"}[admitted], func(t *testing.T) {
			var receiptBody any = fence
			pairID := ""
			state := "REJECTED_FENCED"
			if admitted {
				receiptBody = challenge
				pairID = bp.PairID
				state = "COMPLETED"
			}
			receipt, err := SealResponse(f.f.hubPrivate, f.f.device.Public(), or, receiptBody)
			if err != nil {
				t.Fatal(err)
			}
			ctx := q.Context
			ctx.RequestID = strings.Repeat("c", 32)
			ctx.AccountSessionID = "synthetic-replacement-login"
			ctx.IssuedAt = fence.ObservedAt
			rq := NativePairReconcileRequest{Format: NativePairFormat, Context: ctx, OriginalPacket: original}
			raw, err := SealClientRequest(f.f.device, f.f.hub, rq)
			if err != nil {
				t.Fatal("unknown PairID recovery rejected", err)
			}
			binding, route, _ := NewClientRoute(f.f.hub, rq, f.f.device.Public())
			pub := f.f.device.Public()
			var opened NativePairReconcileRequest
			if OpenRequestAt(f.f.hubPrivate, &pub, binding, route, raw, &opened, f.f.now.Add(30*time.Minute)) != nil {
				t.Fatal("recovery depended on original login")
			}
			result := NativePairReconciled{Format: NativePairFormat, RequestID: route.OperationID, RequestPacketDigest: NativePairPacketDigest(raw), PairID: pairID, OriginalOperation: or.Operation, OriginalRequestID: or.OperationID, OriginalPacketDigest: NativePairPacketDigest(original), State: state, ReceiptPacket: receipt, ObservedAt: ctx.IssuedAt}
			rr, err := SealResponse(f.f.hubPrivate, pub, route, result)
			if err != nil {
				t.Fatal(err)
			}
			var recovered NativePairReconciled
			if OpenClientResponse(f.f.device, f.f.hub, raw, rr, &recovered) != nil || ValidateNativePairReconcileTarget(recovered, "", original) != nil {
				t.Fatal("unknown prepare history did not reconcile")
			}
			if admitted {
				var got NativePairBootstrapChallenge
				if OpenClientResponse(f.f.device, f.f.hub, original, receipt, &got) != nil || got.Bootstrap.PairID != pairID {
					t.Fatal("original allocated PairID lost")
				}
				if ValidateNativePairBootstrapTarget(q, original, got, f.f.hub, f.f.now.Add(30*time.Minute)) == nil {
					t.Fatal("expired historical challenge became new authority")
				}
			} else {
				var got NativePairBootstrapFence
				if OpenClientResponse(f.f.device, f.f.hub, original, receipt, &got) != nil || !got.NoEffect {
					t.Fatal("no-effect fence unavailable")
				}
			}
			result.State = "ABSENT"
			result.ReceiptPacket = nil
			if _, err = SealResponse(f.f.hubPrivate, pub, route, result); err == nil {
				t.Fatal("bare ABSENT settled mutation")
			}
		})
	}
	fence.NoEffect = false
	if _, err = SealResponse(f.f.hubPrivate, f.f.device.Public(), or, fence); err == nil {
		t.Fatal("effectful bootstrap fence accepted")
	}
	// The exception never applies to a known-pair operation.
	rq := NativePairReconcileRequest{Format: NativePairFormat, Context: q.Context, OriginalPacket: original}
	rq.Context.RequestID = strings.Repeat("f", 32)
	p, err := DecodePacket(original)
	if err != nil {
		t.Fatal(err)
	}
	p.Packet.Route.Operation = OperationNativePairConsentComplete
	rq.OriginalPacket, _ = json.Marshal(p)
	if _, err = SealClientRequest(f.f.device, f.f.hub, rq); err == nil {
		t.Fatal("unknown PairID exception broadened")
	}
}
