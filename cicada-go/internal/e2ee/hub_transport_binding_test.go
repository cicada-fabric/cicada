package e2ee

import (
	"crypto/sha256"
	"testing"
)

func TestHubTransportBindingDomainAndIdentity(t *testing.T) {
	hub, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("CICADA SYNTHETIC HUB TRANSPORT TEST ONLY"))
	sig, err := SignHubTransportBinding(hub, digest)
	if err != nil || VerifyHubTransportBinding(hub.Public(), digest, sig) != nil {
		t.Fatal("valid binding rejected")
	}
	if VerifyHubTransportBinding(other.Public(), digest, sig) == nil {
		t.Fatal("wrong signing identity accepted")
	}
	wrong := digest
	wrong[0] ^= 1
	if VerifyHubTransportBinding(hub.Public(), wrong, sig) == nil {
		t.Fatal("wrong digest accepted")
	}
	if verifyAppNodeSignature(hub.Public(), "cicada/hub/transport-binding/v2\x00", digest, sig) == nil {
		t.Fatal("wrong signature version accepted")
	}
	if _, err := SignHubTransportBinding(nil, digest); err == nil {
		t.Fatal("nil identity accepted")
	}
	if _, err := SignHubTransportBinding(hub, [32]byte{}); err == nil {
		t.Fatal("zero digest accepted")
	}
	if VerifyHubTransportBinding(hub.Public(), [32]byte{}, sig) == nil {
		t.Fatal("zero digest verified")
	}
}
