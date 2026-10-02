package nodewire

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func recoveryTestRequest(t *testing.T) RecoveryRequest {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return RecoveryRequest{Nonce: nonce, Origin: "https://synthetic.invalid", CredentialDigest: "synthetic-digest", RestoreDigest: RecoveryDigest([]byte("restore")), PlanDigest: RecoveryDigest([]byte("plan")), Operations: []RecoveryOperationQuery{{OperationID: "old-op", Sequence: 7, RequestDigest: RecoveryDigest([]byte("old packet"))}}}
}
func recoveryTestStatus(b Binding, q RecoveryRequest) RecoveryStatus {
	return RecoveryStatus{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKey.ID, NodeKeyVersion: b.NodeKeyVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyID: b.HubKey.ID, HubKeyVersion: b.HubKeyVersion, CredentialVersion: 1, AcceptedHighwater: 40, Operations: []RecoveryOperationStatus{{RecoveryOperationQuery: q.Operations[0], State: "COMPLETE"}}}
}
func TestRecoveryEnvelopeDomainAndExactRequestBinding(t *testing.T) {
	node, hub, b, _ := testBinding(t)
	q := recoveryTestRequest(t)
	packet, err := SealRecoveryRequest(node, b, q)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(packet, []byte(q.PlanDigest)) {
		t.Fatal("encrypted metadata leaked")
	}
	opened, err := OpenRecoveryRequest(hub, b, packet)
	if err != nil || !bytes.Equal(opened.Nonce, q.Nonce) {
		t.Fatalf("open request: %v", err)
	}
	if _, err = OpenRequest(hub, b.NodeKey, b, packet); err == nil {
		t.Fatal("recovery domain accepted for normal dispatch")
	}
	response, err := SealRecoveryResponse(hub, b, q, packet, recoveryTestStatus(b, q))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRecoveryResponse(node, b, q, packet, response); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*RecoveryRequest){"nonce": func(x *RecoveryRequest) { x.Nonce = append([]byte(nil), x.Nonce...); x.Nonce[0] ^= 1 }, "origin": func(x *RecoveryRequest) { x.Origin = "https://other.invalid" }, "credential": func(x *RecoveryRequest) { x.CredentialDigest = "other-digest" }, "restore": func(x *RecoveryRequest) { x.RestoreDigest = RecoveryDigest([]byte("other")) }, "plan": func(x *RecoveryRequest) { x.PlanDigest = RecoveryDigest([]byte("other")) }, "operation": func(x *RecoveryRequest) {
		x.Operations = append([]RecoveryOperationQuery(nil), x.Operations...)
		x.Operations[0].RequestDigest = RecoveryDigest([]byte("other"))
	}}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			changed := q
			change(&changed)
			if _, err := OpenRecoveryResponse(node, b, changed, packet, response); err == nil {
				t.Fatal("response accepted changed request")
			}
		})
	}
	if _, err = OpenRecoveryResponse(node, b, q, append(packet, ' '), response); err == nil {
		t.Fatal("response accepted different request packet")
	}
	for name, change := range map[string]func(*Binding){"Hub": func(x *Binding) { x.HubID = "other" }, "Node": func(x *Binding) { x.NodeID = "other" }, "epoch": func(x *Binding) { x.NodeKeyEpoch++ }, "version": func(x *Binding) { x.BindingVersion++ }} {
		t.Run(name, func(t *testing.T) {
			changed := b
			change(&changed)
			if _, err := OpenRecoveryRequest(hub, changed, packet); err == nil {
				t.Fatal("transplanted binding accepted")
			}
		})
	}
	forged, _ := e2ee.NewIdentity()
	wrong := b
	wrong.NodeKey = forged.Public()
	forgedPacket, err := SealRecoveryRequest(forged, wrong, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRecoveryRequest(hub, b, forgedPacket); err == nil {
		t.Fatal("bearer without approved private key accepted")
	}
}
func TestRecoveryEnvelopeBoundsAndMetadataOnly(t *testing.T) {
	node, hub, b, r := testBinding(t)
	q := recoveryTestRequest(t)
	for name, change := range map[string]func(*RecoveryRequest){"oversize": func(x *RecoveryRequest) { x.Operations = make([]RecoveryOperationQuery, MaxRecoveryOperations+1) }, "duplicate": func(x *RecoveryRequest) { x.Operations = append(x.Operations, x.Operations[0]) }, "zero sequence": func(x *RecoveryRequest) {
		x.Operations = append([]RecoveryOperationQuery(nil), x.Operations...)
		x.Operations[0].Sequence = 0
	}, "rawpath": func(x *RecoveryRequest) { x.Origin = "https://synthetic.invalid/%2F" }, "userinfo": func(x *RecoveryRequest) { x.Origin = "https://token@synthetic.invalid" }} {
		t.Run(name, func(t *testing.T) {
			bad := q
			change(&bad)
			if _, err := SealRecoveryRequest(node, b, bad); err == nil {
				t.Fatal("invalid query accepted")
			}
		})
	}
	if _, err := OpenRecoveryRequest(hub, b, make([]byte, MaxRecoveryPacketBytes+1)); err == nil {
		t.Fatal("oversized packet accepted")
	}
	normal, err := SealRequest(node, b.HubKey, b, r, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenRecoveryRequest(hub, b, normal); err == nil {
		t.Fatal("normal packet accepted as recovery")
	}
	packet, _ := SealRecoveryRequest(node, b, q)
	status := recoveryTestStatus(b, q)
	status.Operations[0].State = "RESULT_ACCEPTED"
	reply, _ := SealRecoveryResponse(hub, b, q, packet, status)
	if _, err = OpenRecoveryResponse(node, b, q, packet, reply); err == nil {
		t.Fatal("invented result acceptance state accepted")
	}
}
