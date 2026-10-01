package e2ee

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestNetworkDirectEnvelopeBindsNetworkAndEnrollment(t *testing.T) {
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	context := NetworkDirectContext{
		HubID: "hub_synthetic", NetworkID: "net_a", MessageID: "msg_one", Kind: "SEND",
		SenderEndpointID: "ep_sender", SenderPrincipalID: "principal_sender", SenderOwnerID: "owner_sender",
		SenderMembershipRevision: 2, SenderEnrollmentRevision: 3, SenderBindingEpoch: 1, SenderKeyID: sender.Public().ID,
		ReceiverEndpointID: "ep_receiver", ReceiverPrincipalID: "principal_receiver", ReceiverOwnerID: "owner_receiver",
		ReceiverMembershipRevision: 4, ReceiverEnrollmentRevision: 5, ReceiverBindingEpoch: 1, ReceiverKeyID: receiver.Public().ID,
	}
	wire, err := SealNetworkDirectMessage(sender, receiver.Public(), context, []byte("private synthetic"), 7)
	if err != nil {
		t.Fatal(err)
	}
	opened, sequence, err := OpenNetworkDirectMessage(receiver, sender.Public(), context, wire)
	if err != nil || string(opened) != "private synthetic" || sequence != 7 {
		t.Fatalf("open exact route: sequence=%d err=%v", sequence, err)
	}
	for name, change := range map[string]func(*NetworkDirectContext){
		"network":             func(c *NetworkDirectContext) { c.NetworkID = "net_b" },
		"causal parent":       func(c *NetworkDirectContext) { c.ParentRequestID = "rq_parent" },
		"hub":                 func(c *NetworkDirectContext) { c.HubID = "hub_other" },
		"sender enrollment":   func(c *NetworkDirectContext) { c.SenderEnrollmentRevision++ },
		"receiver membership": func(c *NetworkDirectContext) { c.ReceiverMembershipRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := context
			change(&changed)
			if _, _, err := OpenNetworkDirectMessage(receiver, sender.Public(), changed, wire); err == nil {
				t.Fatal("changed trusted Network route opened")
			}
		})
	}
	var envelope NetworkDirectEnvelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Context.NetworkID = "net_b"
	tampered, _ := json.Marshal(envelope)
	if _, _, err := OpenNetworkDirectMessage(receiver, sender.Public(), context, tampered); err == nil {
		t.Fatal("tampered untrusted header opened")
	}
	askContext := context
	askContext.Kind = "REQUEST"
	askContext.RequestID = "rq_child"
	askContext.MessageID = "msg_child"
	askContext.ParentRequestID = "rq_parent"
	askWire, err := SealNetworkDirectMessage(sender, receiver.Public(), askContext,
		[]byte("synthetic child ask"), 8)
	if err != nil {
		t.Fatal(err)
	}
	opened, sequence, err = OpenNetworkDirectMessage(receiver, sender.Public(), askContext, askWire)
	if err != nil || string(opened) != "synthetic child ask" || sequence != 8 {
		t.Fatalf("open causal request: sequence=%d err=%v", sequence, err)
	}
	changedParent := askContext
	changedParent.ParentRequestID = "rq_other_parent"
	if _, _, err := OpenNetworkDirectMessage(receiver, sender.Public(), changedParent, askWire); err == nil {
		t.Fatal("changed causal parent opened child ask")
	}
	replyContext := askContext
	replyContext.Kind = "REPLY"
	replyContext.MessageID = "msg_reply"
	replyContext.ReplyTo = "msg_child"
	replyWire, err := SealNetworkDirectMessage(sender, receiver.Public(), replyContext,
		[]byte("synthetic causal reply"), 9)
	if err != nil {
		t.Fatalf("REPLY with route-derived causal parent rejected: %v", err)
	}
	if opened, sequence, err = OpenNetworkDirectMessage(receiver, sender.Public(), replyContext, replyWire); err != nil || string(opened) != "synthetic causal reply" || sequence != 9 {
		t.Fatalf("open causal REPLY: sequence=%d err=%v", sequence, err)
	}
	replyContext.ParentRequestID = "rq_other_parent"
	if _, _, err := OpenNetworkDirectMessage(receiver, sender.Public(), replyContext, replyWire); err == nil {
		t.Fatal("changed REPLY causal parent opened")
	}
}

func TestNetworkDirectKeyAndOwnerProofsAreSeparate(t *testing.T) {
	endpoint, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := endpoint.SignNetworkDirectKeyAttestation("hub_a", "net_a", "ep_a", "principal_a", "node_a", "native_a", 2)
	if err != nil {
		t.Fatal(err)
	}
	expected := NetworkDirectKeyAttestation{HubID: "hub_a", NetworkID: "net_a", EndpointID: "ep_a", PrincipalID: "principal_a", NodeID: "node_a", BindingID: "native_a", BindingEpoch: 2}
	public, err := VerifyNetworkDirectKeyAttestation(attestation, expected)
	if err != nil || public.ID != endpoint.Public().ID {
		t.Fatalf("verify candidate: %v", err)
	}
	expected.NetworkID = "net_b"
	if _, err := VerifyNetworkDirectKeyAttestation(attestation, expected); err == nil {
		t.Fatal("cross-Network candidate accepted")
	}
	now := time.Now().UTC()
	digest := bytes.Repeat([]byte("a"), 64)
	proof, err := owner.SignOwnerNetworkDirectKeyGrant("hub_a", "net_a", "ep_a", "owner_a", string(digest), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claim := OwnerNetworkDirectKeyGrant{HubID: "hub_a", NetworkID: "net_a", EndpointID: "ep_a", OwnerID: "owner_a", ManifestDigest: string(digest)}
	if _, err := VerifyOwnerNetworkDirectKeyGrant(proof, owner.Public(), claim, now); err != nil {
		t.Fatal(err)
	}
	claim.ManifestDigest = string(bytes.Repeat([]byte("b"), 64))
	if _, err := VerifyOwnerNetworkDirectKeyGrant(proof, owner.Public(), claim, now); err == nil {
		t.Fatal("different current manifest accepted")
	}
}
