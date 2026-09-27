package e2ee

import (
	"encoding/json"
	"testing"
)

func TestEndpointKeyAttestationBindsCurrentSessionAndPossession(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation("ep_a", "pr_a", "node_a", "bind_a", 7)
	if err != nil {
		t.Fatal(err)
	}
	public, err := VerifyEndpointKeyAttestation(proof, "ep_a", "pr_a", "node_a", "bind_a", 7)
	if err != nil || public.ID != identity.Public().ID {
		t.Fatalf("valid attestation rejected: key=%q err=%v", public.ID, err)
	}
	for name, claims := range map[string]struct {
		endpoint, principal, node, binding string
		epoch                              uint64
	}{
		"endpoint":  {"ep_other", "pr_a", "node_a", "bind_a", 7},
		"principal": {"ep_a", "pr_other", "node_a", "bind_a", 7},
		"node":      {"ep_a", "pr_a", "node_other", "bind_a", 7},
		"binding":   {"ep_a", "pr_a", "node_a", "bind_other", 7},
		"epoch":     {"ep_a", "pr_a", "node_a", "bind_a", 8},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyEndpointKeyAttestation(proof, claims.endpoint, claims.principal,
				claims.node, claims.binding, claims.epoch); err == nil {
				t.Fatal("attestation accepted changed trusted binding")
			}
		})
	}
	var parsed EndpointKeyAttestation
	if err := json.Unmarshal(proof, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Public.KEMPublic[0] ^= 1
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEndpointKeyAttestation(tampered, "ep_a", "pr_a", "node_a", "bind_a", 7); err == nil {
		t.Fatal("attestation accepted changed public key")
	}
	if _, err := identity.SignEndpointKeyAttestation("../escape", "pr_a", "node_a", "bind_a", 7); err == nil {
		t.Fatal("attestation accepted unsafe Endpoint ID")
	}
}
