package e2ee

import (
	"bytes"
	"encoding/json"
	"testing"
)

func endpointTestContext(sender, receiver PublicIdentity) EndpointMessageContext {
	return EndpointMessageContext{
		MessageID: "msg_1", Kind: "REQUEST", RequestID: "rq_1",
		SenderEndpointID: "ep_a", SenderPrincipalID: "pr_a", SenderOwnerID: "user_a",
		SenderGroupID: "grp_a", SenderMembershipRevision: 3,
		SenderBindingEpoch: 2, SenderKeyID: sender.ID,
		ReceiverEndpointID: "ep_b", ReceiverPrincipalID: "pr_b", ReceiverOwnerID: "user_b",
		ReceiverGroupID: "grp_b", ReceiverMembershipRevision: 4,
		ReceiverBindingEpoch: 5, ReceiverKeyID: receiver.ID,
		LinkID: "link_1", LinkRevision: 7, TransportHubID: "hub_1",
	}
}

func TestEndpointEnvelopeBindsKeysRouteAndRequest(t *testing.T) {
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrongReceiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	context := endpointTestContext(sender.Public(), receiver.Public())
	plaintext := []byte("private benchmark result")
	wire, err := SealEndpointMessage(sender, receiver.Public(), context, plaintext, 11)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, plaintext) {
		t.Fatal("endpoint envelope exposed plaintext")
	}
	opened, sequence, err := OpenEndpointMessage(receiver, sender.Public(), context, wire)
	if err != nil || sequence != 11 || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open pinned endpoint envelope: sequence=%d err=%v", sequence, err)
	}
	if _, _, err := OpenEndpointMessage(wrongReceiver, sender.Public(), context, wire); err == nil {
		t.Fatal("wrong receiver key opened message")
	}
	for name, mutate := range map[string]func(*EndpointMessageContext){
		"sender group":    func(c *EndpointMessageContext) { c.SenderGroupID = "grp_other" },
		"receiver group":  func(c *EndpointMessageContext) { c.ReceiverGroupID = "grp_other" },
		"link revision":   func(c *EndpointMessageContext) { c.LinkRevision++ },
		"request":         func(c *EndpointMessageContext) { c.RequestID = "rq_other" },
		"binding epoch":   func(c *EndpointMessageContext) { c.ReceiverBindingEpoch++ },
		"member revision": func(c *EndpointMessageContext) { c.SenderMembershipRevision++ },
		"Hub":             func(c *EndpointMessageContext) { c.TransportHubID = "hub_other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := context
			mutate(&changed)
			if _, _, err := OpenEndpointMessage(receiver, sender.Public(), changed, wire); err == nil {
				t.Fatal("changed trusted route opened ciphertext")
			}
		})
	}
	var envelope EndpointMessageEnvelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Context.ReceiverGroupID = "grp_other"
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEndpointMessage(receiver, sender.Public(), context, tampered); err == nil {
		t.Fatal("tampered outer header opened ciphertext")
	}
	envelope.Context = context
	envelope.Signature[0] ^= 1
	tampered, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEndpointMessage(receiver, sender.Public(), context, tampered); err == nil {
		t.Fatal("tampered route signature opened ciphertext")
	}
	if _, err := SealEndpointMessage(sender, receiver.Public(), context, plaintext, 0); err == nil {
		t.Fatal("zero sequence accepted")
	}
	if _, err := SealEndpointMessage(sender, wrongReceiver.Public(), context, plaintext, 12); err == nil {
		t.Fatal("context accepted wrong receiver public key")
	}
	tooLarge := make([]byte, maxEndpointPlaintext+1)
	if _, err := SealEndpointMessage(sender, receiver.Public(), context, tooLarge, 13); err == nil {
		t.Fatal("oversized endpoint plaintext accepted")
	}
	if _, _, err := OpenEndpointMessage(receiver, sender.Public(), context, make([]byte, maxEndpointWire+1)); err == nil {
		t.Fatal("oversized endpoint envelope accepted")
	}
}

func TestEndpointEnvelopeRejectsMalformedCorrelationAndUnknownFields(t *testing.T) {
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	context := endpointTestContext(sender.Public(), receiver.Public())
	context.Kind = "REPLY"
	if _, err := SealEndpointMessage(sender, receiver.Public(), context, []byte("answer"), 1); err == nil {
		t.Fatal("reply without parent message id accepted")
	}
	context.ReplyTo = "msg_parent"
	context.LinkID = "link bad\npolicy"
	if _, err := SealEndpointMessage(sender, receiver.Public(), context, []byte("answer"), 1); err == nil {
		t.Fatal("control character in link identity accepted")
	}
	context.LinkID = "link_1"
	wire, err := SealEndpointMessage(sender, receiver.Public(), context, []byte("answer"), 1)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		t.Fatal(err)
	}
	object["untrusted_policy"] = "approved"
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEndpointMessage(receiver, sender.Public(), context, mutated); err == nil {
		t.Fatal("unknown unsigned policy field was accepted")
	}
	if _, _, err := OpenEndpointMessage(receiver, sender.Public(), context, append(wire, []byte("{}")...)); err == nil {
		t.Fatal("trailing object was accepted")
	}
}
