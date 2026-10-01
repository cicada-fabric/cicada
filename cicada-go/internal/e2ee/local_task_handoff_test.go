package e2ee

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestLocalTaskHandoffProofBindsExactLocalEnvelopeAndTaskEpoch(t *testing.T) {
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := LocalTaskHandoffProofClaims{
		Version: 1, Purpose: "LOCAL_NODE", HandoffID: "handoff_synthetic",
		TaskID: "task_synthetic", HubID: "hub_synthetic", GroupID: "group_synthetic",
		FromPrincipalID: "agent_source", FromOwnerID: "owner_synthetic",
		FromEndpointID: "endpoint_source", FromBindingID: "binding_source", FromBindingEpoch: 3,
		FromMembershipRevision: 4, FromJoinRevision: 5, FromKeyID: sender.Public().ID,
		FromKeyVersion: 2, ToPrincipalID: "agent_target", ToOwnerID: "owner_synthetic",
		ToEndpointID: "endpoint_target", ToBindingID: "binding_target", ToBindingEpoch: 7,
		ToMembershipRevision: 8, ToJoinRevision: 9, ToKeyID: receiver.Public().ID,
		ToKeyVersion: 6, TaskRevision: 11, FromOwnerEpoch: 13,
		MessageID:     "shared-task-handoff.v1:1790812800000:handoff_synthetic",
		MessageDigest: strings.Repeat("a", 64), ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339Nano),
		RequiredArtifactRefsHash: strings.Repeat("b", 64), IssuedAt: now.Format(time.RFC3339Nano),
	}
	proof, err := sender.SignLocalTaskHandoffProof(claims)
	if err != nil {
		t.Fatalf("sign synthetic local handoff proof: %v", err)
	}
	verified, err := VerifyLocalTaskHandoffProof(proof, sender.Public(), claims, now.Add(time.Second))
	if err != nil || verified.Claims != claims || verified.KeyID != sender.Public().ID {
		t.Fatalf("verify exact local handoff proof: %+v err=%v", verified, err)
	}

	for name, mutate := range map[string]func(*LocalTaskHandoffProofClaims){
		"ciphertext digest": func(c *LocalTaskHandoffProofClaims) { c.MessageDigest = strings.Repeat("c", 64) },
		"receiver binding":  func(c *LocalTaskHandoffProofClaims) { c.ToBindingEpoch++ },
		"task epoch":        func(c *LocalTaskHandoffProofClaims) { c.FromOwnerEpoch++ },
		"artifact set":      func(c *LocalTaskHandoffProofClaims) { c.RequiredArtifactRefsHash = strings.Repeat("d", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			expected := claims
			mutate(&expected)
			if _, err := VerifyLocalTaskHandoffProof(proof, sender.Public(), expected, now.Add(time.Second)); err == nil {
				t.Fatal("modified expected handoff claim verified")
			}
		})
	}
	if _, err := VerifyLocalTaskHandoffProof(proof, receiver.Public(), claims, now.Add(time.Second)); err == nil {
		t.Fatal("another Endpoint key verified the handoff proof")
	}
	changed := bytes.Replace(proof, []byte(`"task_revision":11`), []byte(`"task_revision":12`), 1)
	if bytes.Equal(changed, proof) {
		t.Fatal("test failed to change the signed task revision")
	}
	if _, err := VerifyLocalTaskHandoffProof(changed, sender.Public(), claims, now.Add(time.Second)); err == nil {
		t.Fatal("tampered proof bytes verified")
	}
}
