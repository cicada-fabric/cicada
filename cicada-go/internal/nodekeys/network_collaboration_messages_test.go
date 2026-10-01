package nodekeys

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func testNetworkCollaborationEvidence(t *testing.T, state *CryptoState, purpose, ownerID,
	hubID, networkID, endpointID, principalID, nodeID, bindingID, nativeSessionID string,
	owner, endpoint *e2ee.Identity) NetworkCollaborationEvidence {
	t.Helper()
	ownerFingerprint, err := PeerKeyFingerprint(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyLocal(ownerID, owner.Public().ID,
		owner.Public(), ownerFingerprint); err != nil {
		t.Fatal(err)
	}
	endpointFingerprint, err := PeerKeyFingerprint(endpoint.Public())
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := endpoint.SignNetworkDirectKeyAttestation(hubID, networkID,
		endpointID, principalID, nodeID, bindingID, 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest := networkCollaborationManifest{Version: 1, HubID: hubID,
		NetworkID: networkID, EndpointID: endpointID, PrincipalID: principalID,
		OwnerID: ownerID, NodeID: nodeID,
		NativeSessionDigest: e2ee.NetworkDirectNativeSessionDigest(nativeSessionID),
		BindingID:           bindingID, BindingEpoch: 1, MembershipRevision: 1,
		EndpointEnrollmentRevision: 1,
		Candidate: networkCollaborationManifestCandidate{NetworkID: networkID,
			EndpointID: endpointID, PrincipalID: principalID, OwnerID: ownerID, NodeID: nodeID,
			BindingID:    bindingID,
			BindingEpoch: 1, Public: endpoint.Public(), Fingerprint: endpointFingerprint,
			Attestation: attestation, Version: 1}}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := e2ee.NetworkCollaborationManifestDigest(purpose, canonical)
	issuedAt, expiresAt := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)
	proof, err := owner.SignOwnerNetworkCollaborationKeyGrant(purpose, hubID,
		networkID, endpointID, ownerID, manifestDigest, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	evidence := NetworkCollaborationEvidence{ManifestCanonical: canonical, Purpose: purpose,
		ExpectedAttestation: e2ee.NetworkDirectKeyAttestation{Version: 1, HubID: hubID,
			NetworkID: networkID, EndpointID: endpointID, PrincipalID: principalID,
			NodeID: nodeID, BindingID: bindingID, BindingEpoch: 1, Public: endpoint.Public()},
		Attestation: attestation, ExpectedGrant: e2ee.OwnerNetworkCollaborationKeyGrant{
			Version: 1, Purpose: purpose, HubID: hubID, NetworkID: networkID,
			EndpointID: endpointID, OwnerID: ownerID, OwnerKeyID: owner.Public().ID,
			ManifestDigest: manifestDigest}, GrantProof: proof, OwnerPublic: owner.Public()}
	if _, err := e2ee.VerifyOwnerNetworkCollaborationKeyGrant(evidence.GrantProof,
		owner.Public(), evidence.ExpectedGrant, time.Now().UTC()); err != nil {
		t.Fatalf("synthetic Owner collaboration grant did not verify: %v", err)
	}
	if _, err := e2ee.VerifyNetworkDirectKeyAttestation(evidence.Attestation,
		evidence.ExpectedAttestation); err != nil {
		t.Fatalf("synthetic Endpoint attestation did not verify: %v", err)
	}
	return evidence
}

func TestNetworkCollaborationNodeDurableSealOpenAndPurposeFence(t *testing.T) {
	for _, purpose := range []string{e2ee.NetworkCollaborationPurposeTask, e2ee.NetworkCollaborationPurposeBroadcast} {
		t.Run(purpose, func(t *testing.T) {
			ctx := context.Background()
			senderState, err := OpenCryptoState(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer senderState.Close()
			receiverState, err := OpenCryptoState(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer receiverState.Close()
			senderOwner, receiverOwner := newTestIdentity(t), newTestIdentity(t)
			sender, receiver := newTestIdentity(t), newTestIdentity(t)
			senderEvidence := testNetworkCollaborationEvidence(t, senderState, purpose,
				"owner_sender", "hub_synthetic", "net_synthetic", "ep_sender", "pr_sender",
				"node_sender", "native_binding_sender", "native_sender", senderOwner, sender)
			receiverEvidence := testNetworkCollaborationEvidence(t, senderState, purpose,
				"owner_receiver", "hub_synthetic", "net_synthetic", "ep_receiver", "pr_receiver",
				"node_receiver", "native_binding_receiver", "native_receiver", receiverOwner, receiver)
			for _, entry := range []struct {
				id     string
				public e2ee.PublicIdentity
			}{{"owner_sender", senderOwner.Public()}, {"owner_receiver", receiverOwner.Public()}} {
				fingerprint, err := PeerKeyFingerprint(entry.public)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := receiverState.TrustOwnerApprovalKeyLocal(entry.id,
					entry.public.ID, entry.public, fingerprint); err != nil {
					t.Fatal(err)
				}
			}
			route := e2ee.NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
				MessageID: "synthetic-collaboration-message", Kind: "SEND",
				SenderEndpointID: "ep_sender", SenderPrincipalID: "pr_sender", SenderOwnerID: "owner_sender",
				SenderMembershipRevision: 1, SenderEnrollmentRevision: 1, SenderBindingEpoch: 1,
				SenderKeyID: sender.Public().ID, ReceiverEndpointID: "ep_receiver",
				ReceiverPrincipalID: "pr_receiver", ReceiverOwnerID: "owner_receiver",
				ReceiverMembershipRevision: 1, ReceiverEnrollmentRevision: 1,
				ReceiverBindingEpoch: 1, ReceiverKeyID: receiver.Public().ID}
			messageContext := e2ee.NetworkCollaborationMessageContext{Purpose: purpose, Route: route}
			body := []byte(`{"synthetic":"sealed collaboration content"}`)
			operationID, err := NetworkCollaborationOperationID(messageContext, body)
			if err != nil {
				t.Fatal(err)
			}
			outbound, err := senderState.SealOutboundNetworkCollaborationMessage(ctx,
				sender, messageContext, senderEvidence, receiverEvidence, operationID, body)
			if err != nil || outbound.Reused || outbound.Sequence != 1 {
				t.Fatalf("seal: %#v %v", outbound, err)
			}
			retry, err := senderState.SealOutboundNetworkCollaborationMessage(ctx,
				sender, messageContext, senderEvidence, receiverEvidence, operationID, body)
			if err != nil || !retry.Reused || !bytes.Equal(retry.Envelope, outbound.Envelope) {
				t.Fatalf("durable retry: %#v %v", retry, err)
			}
			opened, err := receiverState.OpenInboundNetworkCollaborationMessage(ctx,
				receiver, messageContext, senderEvidence, receiverEvidence, outbound.Envelope)
			if err != nil || opened.Duplicate || !bytes.Equal(opened.Plaintext, body) {
				t.Fatalf("open: %#v %v", opened, err)
			}
			duplicate, err := receiverState.OpenInboundNetworkCollaborationMessage(ctx,
				receiver, messageContext, senderEvidence, receiverEvidence, outbound.Envelope)
			if err != nil || !duplicate.Duplicate {
				t.Fatalf("exact replay: %#v %v", duplicate, err)
			}
			wrongPurpose := messageContext
			if purpose == e2ee.NetworkCollaborationPurposeTask {
				wrongPurpose.Purpose = e2ee.NetworkCollaborationPurposeBroadcast
			} else {
				wrongPurpose.Purpose = e2ee.NetworkCollaborationPurposeTask
			}
			if _, err := receiverState.OpenInboundNetworkCollaborationMessage(ctx,
				receiver, wrongPurpose, senderEvidence, receiverEvidence, outbound.Envelope); err == nil {
				t.Fatal("ciphertext opened under a different collaboration purpose")
			}
			trusted, err := receiverState.GetNodeOwnerKeyTrustLocal("owner_sender", senderOwner.Public().ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := receiverState.RevokeNodeOwnerKeyTrustLocal("owner_sender",
				senderOwner.Public().ID, trusted.Version); err != nil {
				t.Fatal(err)
			}
			if _, err := receiverState.OpenInboundNetworkCollaborationMessage(ctx,
				receiver, messageContext, senderEvidence, receiverEvidence, outbound.Envelope); err == nil {
				t.Fatal("revoked Node-local Owner trust still opened collaboration ciphertext")
			}
		})
	}
}
