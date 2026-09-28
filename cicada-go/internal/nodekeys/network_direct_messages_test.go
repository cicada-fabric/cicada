package nodekeys

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func testNetworkDirectEvidence(t *testing.T, state *CryptoState, owner,
	endpoint *e2ee.Identity, ownerID, hubID, networkID, endpointID,
	principalID, nodeID, bindingID string) NetworkDirectEvidence {
	t.Helper()
	fingerprint, err := PeerKeyFingerprint(owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyLocal(ownerID, owner.Public().ID,
		owner.Public(), fingerprint); err != nil {
		t.Fatal(err)
	}
	attestation, err := endpoint.SignNetworkDirectKeyAttestation(hubID, networkID,
		endpointID, principalID, nodeID, bindingID, 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest := struct {
		HubID                      string `json:"hub_id"`
		NetworkID                  string `json:"network_id"`
		EndpointID                 string `json:"endpoint_id"`
		PrincipalID                string `json:"principal_id"`
		OwnerID                    string `json:"owner_id"`
		NodeID                     string `json:"node_id"`
		BindingID                  string `json:"binding_id"`
		BindingEpoch               uint64 `json:"binding_epoch"`
		MembershipRevision         int64  `json:"membership_revision"`
		EndpointEnrollmentRevision int64  `json:"endpoint_enrollment_revision"`
		Candidate                  struct {
			BindingID    string              `json:"binding_id"`
			BindingEpoch uint64              `json:"binding_epoch"`
			Public       e2ee.PublicIdentity `json:"public_identity"`
			Attestation  []byte              `json:"attestation"`
		} `json:"candidate"`
	}{HubID: hubID, NetworkID: networkID, EndpointID: endpointID,
		PrincipalID: principalID, OwnerID: ownerID, NodeID: nodeID,
		BindingID: bindingID, BindingEpoch: 1, MembershipRevision: 1,
		EndpointEnrollmentRevision: 1}
	manifest.Candidate.BindingID = bindingID
	manifest.Candidate.BindingEpoch = 1
	manifest.Candidate.Public = endpoint.Public()
	manifest.Candidate.Attestation = attestation
	canonical, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := e2ee.NetworkDirectManifestDigest(canonical)
	acceptedAt := time.Now().UTC()
	proof, err := owner.SignOwnerNetworkDirectKeyGrant(hubID, networkID, endpointID,
		ownerID, digest, acceptedAt.Add(-time.Minute), acceptedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return NetworkDirectEvidence{ManifestCanonical: canonical,
		ExpectedAttestation: e2ee.NetworkDirectKeyAttestation{Version: 1,
			HubID: hubID, NetworkID: networkID, EndpointID: endpointID,
			PrincipalID: principalID, NodeID: nodeID, BindingID: bindingID,
			BindingEpoch: 1, Public: endpoint.Public()},
		Attestation: attestation, ExpectedGrant: e2ee.OwnerNetworkDirectKeyGrant{
			Version: 1, HubID: hubID, NetworkID: networkID, EndpointID: endpointID,
			OwnerID: ownerID, OwnerKeyID: owner.Public().ID, ManifestDigest: digest},
		GrantProof: proof, AcceptedAt: acceptedAt, OwnerPublic: owner.Public()}
}

func TestNetworkDirectNodeDurableSealOpenAndOwnerTrust(t *testing.T) {
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
	senderEvidence := testNetworkDirectEvidence(t, senderState, senderOwner, sender,
		"owner_sender", "hub_synthetic", "net_synthetic", "ep_sender", "pr_sender",
		"node_sender", "native_binding_sender")
	receiverEvidence := testNetworkDirectEvidence(t, senderState, receiverOwner, receiver,
		"owner_receiver", "hub_synthetic", "net_synthetic", "ep_receiver", "pr_receiver",
		"node_receiver", "native_binding_receiver")
	// Inbound trust is installed independently in the receiver's private state.
	for _, entry := range []struct {
		id     string
		public e2ee.PublicIdentity
	}{
		{"owner_sender", senderOwner.Public()}, {"owner_receiver", receiverOwner.Public()},
	} {
		fingerprint, err := PeerKeyFingerprint(entry.public)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiverState.TrustOwnerApprovalKeyLocal(entry.id, entry.public.ID,
			entry.public, fingerprint); err != nil {
			t.Fatal(err)
		}
	}
	route := e2ee.NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
		MessageID: "msg_synthetic", Kind: "SEND", SenderEndpointID: "ep_sender",
		SenderPrincipalID: "pr_sender", SenderOwnerID: "owner_sender",
		SenderMembershipRevision: 1, SenderEnrollmentRevision: 1, SenderBindingEpoch: 1,
		SenderKeyID: sender.Public().ID, ReceiverEndpointID: "ep_receiver",
		ReceiverPrincipalID: "pr_receiver", ReceiverOwnerID: "owner_receiver",
		ReceiverMembershipRevision: 1, ReceiverEnrollmentRevision: 1,
		ReceiverBindingEpoch: 1, ReceiverKeyID: receiver.Public().ID}
	body := []byte("synthetic private direct message")
	operationID, err := NetworkDirectOperationID(route, body)
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := senderState.SealOutboundNetworkDirectMessage(ctx, sender, route,
		senderEvidence, receiverEvidence, operationID, body)
	if err != nil || outbound.Reused || outbound.Sequence != 1 {
		t.Fatalf("seal: %#v %v", outbound, err)
	}
	retry, err := senderState.SealOutboundNetworkDirectMessage(ctx, sender, route,
		senderEvidence, receiverEvidence, operationID, body)
	if err != nil || !retry.Reused || !bytes.Equal(retry.Envelope, outbound.Envelope) {
		t.Fatalf("durable retry: %#v %v", retry, err)
	}
	inbound, err := receiverState.OpenInboundNetworkDirectMessage(ctx, receiver, route,
		senderEvidence, receiverEvidence, outbound.Envelope)
	if err != nil || inbound.Duplicate || !bytes.Equal(inbound.Plaintext, body) {
		t.Fatalf("open: %#v %v", inbound, err)
	}
	duplicate, err := receiverState.OpenInboundNetworkDirectMessage(ctx, receiver, route,
		senderEvidence, receiverEvidence, outbound.Envelope)
	if err != nil || !duplicate.Duplicate {
		t.Fatalf("replay: %#v %v", duplicate, err)
	}
	changed := route
	changed.NetworkID = "net_other"
	if _, err := receiverState.OpenInboundNetworkDirectMessage(ctx, receiver, changed,
		senderEvidence, receiverEvidence, outbound.Envelope); err == nil {
		t.Fatal("Network selector changed signed context")
	}
	trusted, err := receiverState.GetNodeOwnerKeyTrustLocal("owner_sender", senderOwner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiverState.RevokeNodeOwnerKeyTrustLocal("owner_sender",
		senderOwner.Public().ID, trusted.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := receiverState.OpenInboundNetworkDirectMessage(ctx, receiver, route,
		senderEvidence, receiverEvidence, outbound.Envelope); err == nil {
		t.Fatal("revoked local Owner trust still opened ciphertext")
	}
}
