package hubaccountwire_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestNativePairActualPeerCarriersMaximumPQ(t *testing.T) {
	hub, owner, evidence, current, now := wire.NativePairCarrierFixtureForTest(t, true)
	p := evidence.Plan
	side := func(s wire.NativePairSlot, m wire.NativePairGroupKeyManifest, proof []byte, membership uint64) store.SameGroupSealedV1EndpointEvidence {
		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var manifest store.GroupEndpointKeyGrantManifest
		if err = json.Unmarshal(encoded, &manifest); err != nil {
			t.Fatal(err)
		}
		stamp := current.ObservedAt
		return store.SameGroupSealedV1EndpointEvidence{EndpointID: s.EndpointID, PrincipalID: s.PrincipalID,
			OwnerID: p.Scope.Actor.OwnerID, NodeID: s.NodeID, GroupID: p.GroupID,
			BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, NativeSessionID: s.NativeSessionID,
			GroupRevision: int64(p.GroupRevision), MembershipRevision: int64(membership), EndpointJoinRevision: int64(s.EndpointJoinRevision),
			Candidate: store.EndpointKeyCandidate{EndpointID: s.EndpointID, PrincipalID: s.PrincipalID,
				OwnerID: p.Scope.Actor.OwnerID, NodeID: s.NodeID, Public: s.CandidatePublic, KeyID: s.CandidatePublic.ID,
				BindingID: s.BindingID, BindingEpoch: s.BindingEpoch, Proof: s.CandidateAttestation, ProofDigest: s.CandidateProofDigest,
				State: store.EndpointKeyCandidateStateCandidate, Version: int64(s.CandidateVersion), CreatedAt: stamp, UpdatedAt: stamp},
			Grant: &store.OwnerGroupEndpointKeyGrant{ID: strings.Repeat("g", 128), OwnerID: p.Scope.Actor.OwnerID,
				GroupID: p.GroupID, EndpointID: s.EndpointID, OwnerKeyID: owner.ID, Manifest: manifest,
				SignedProof: proof, AcceptedAt: stamp, CurrentStatus: store.GroupEndpointKeyGrantCurrent}}
	}
	sender := side(p.SlotA, p.SlotAKeyManifest, evidence.SlotAGroupKeyProof, p.ProjectedSlotAMembership)
	receiver := side(p.SlotB, p.SlotBKeyManifest, evidence.SlotBGroupKeyProof, p.ProjectedSlotBMembership)
	scope := store.NativeContextScopeMetadata{HubID: hub.HubID, NetworkID: p.NetworkID, GroupID: p.GroupID, GroupContextPolicy: "group_scoped"}
	peer := store.SameGroupSealedV1PeerKey{HubID: hub.HubID, GroupID: p.GroupID, NativeContextScope: scope,
		Sender: sender, Receiver: receiver, NativePairEvidence: &evidence, NativePairCurrent: &current}
	// The old peer-key DTO intentionally hides the receiver's native locator.
	// The new independent CURRENT observation still carries the approved SID.
	peer.Receiver.NativeSessionID = ""
	id := strings.Repeat("m", 256)
	authorization := store.SameGroupSealedV1DeliveryAuthorization{AttemptID: id, MessageID: id,
		Digest: strings.Repeat("d", 64), EndpointID: receiver.EndpointID, NodeID: receiver.NodeID,
		OwnerID: receiver.OwnerID, BindingID: receiver.BindingID, BindingEpoch: receiver.BindingEpoch,
		NativeSessionID: receiver.NativeSessionID, DataScope: store.SameGroupSealedV1DataScope,
		ParentRequestID: id, NativeContextScope: scope,
		Route: store.RelaySealedV1Route{MessageID: id, RequestID: id, ReplyTo: id,
			SenderEndpointID: sender.EndpointID, ReceiverEndpointID: receiver.EndpointID, Kind: "reply"},
		Sender: sender, Receiver: receiver, NativePairEvidence: &evidence, NativePairCurrent: &current}
	if err := wire.VerifyNativePairPeerAuthorization(true, &evidence, &current, hub, owner,
		p.Scope.NodeTupleDigest, sender.EndpointID, receiver.EndpointID, now); err != nil {
		t.Fatal(err)
	}
	for name, carrier := range map[string]any{"peer_key": peer, "delivery_authorization": authorization} {
		raw, err := json.Marshal(carrier)
		if err != nil || wire.ValidateNativePairCarrierSize(carrier) != nil {
			t.Fatalf("%s complete real-PQ carrier size %d exceeds frozen %d: %v", name, len(raw), wire.MaxNativePairCarrierBytes, err)
		}
		if bytes.Count(raw, []byte(`"native_pair_evidence":`)) != 1 || bytes.Count(raw, []byte(`"native_pair_current":`)) != 1 {
			t.Fatal("carrier duplicated evidence or omitted independent current coordinates")
		}
		t.Logf("synthetic maximum %s=%d limit=%d", name, len(raw), wire.MaxNativePairCarrierBytes)
	}
	encodedCurrent, _ := json.Marshal(current)
	if len(encodedCurrent) > wire.MaxNativePairPeerCurrentBytes {
		t.Fatal("current coordinates exceed 4 KiB")
	}
	t.Logf("synthetic maximum current=%d limit=%d", len(encodedCurrent), wire.MaxNativePairPeerCurrentBytes)
	// The unchanged legacy token grammar admits HTML-sensitive characters.
	// Measure a complete typed authorization, including their actual JSON
	// expansion; the native-pair carrier ceiling still rejects it unchanged.
	authorization.AttemptID = "synthetic-current-claim-attempt"
	authorization.ParentRequestID = ""
	authorization.MessageID = "reply-" + strings.Repeat("&", 250)
	authorization.Route.MessageID = authorization.MessageID
	authorization.Route.RequestID = "ask-" + strings.Repeat("&", 252)
	authorization.Route.ReplyTo = "original-" + strings.Repeat("&", 247)
	expanded, _ := json.Marshal(authorization)
	if wire.ValidateNativePairCarrierSize(authorization) == nil {
		t.Fatal("oversized actual JSON expansion bypassed frozen carrier ceiling")
	}
	t.Logf("synthetic expanded authorization rejected=%d limit=%d", len(expanded), wire.MaxNativePairCarrierBytes)
	peer.NativePairEvidence, peer.NativePairCurrent = nil, nil
	legacy, _ := json.Marshal(peer)
	if bytes.Contains(legacy, []byte(`"native_pair_`)) {
		t.Fatal("legacy DTO did not omit both native-pair additions")
	}
}
