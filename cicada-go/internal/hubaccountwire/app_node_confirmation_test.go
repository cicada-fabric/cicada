package hubaccountwire_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestAppNodeConfirmationUsesActualStoreDTOAndDurableSequence(t *testing.T) {
	keys := make([]*e2ee.Identity, 5)
	for i := range keys {
		var err error
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	stamp := func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	hub := wire.HubIdentity{Contract: "android-hub-v1", HubID: "synthetic-n3-hub", Public: keys[0].Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	fp, err := wire.HubFingerprint(hub)
	if err != nil {
		t.Fatal(err)
	}
	code := "23456789ABCD"
	digest, err := wire.AppNodeCodeDigest(hub.HubID, code)
	if err != nil {
		t.Fatal(err)
	}
	scope := e2ee.OwnerAppNodeScope{Version: 1, Origin: "https://synthetic-n3.invalid", HubID: hub.HubID, HubFingerprint: fp, AccountID: "synthetic-account", AccountSessionID: "synthetic-session", AccountSessionExpiresAt: stamp(now.Add(14 * time.Minute)), OwnerID: "synthetic-owner", OwnerPublic: keys[1].Public(), OwnerKeyVersion: 1,
		DeviceID: "accountdev_" + strings.Repeat("a", 32), DevicePublic: keys[2].Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, HeadVersion: 1, TransportPolicy: wire.AppNodeTransportHTTPS}
	n := e2ee.OwnerAppNodeCandidate{RequestID: "nctrlreq_synthetic", Version: 1, Mode: "INITIAL", State: "PENDING", HubID: hub.HubID, NodeID: "synthetic-node", NodeName: "Synthetic Node", NodePublic: keys[3].Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(keys[3].Public()), NodeKeyEpoch: 1,
		HubNodeControlPublic: keys[4].Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: nodewire.IdentityFingerprint(keys[4].Public()), CandidateDigest: strings.Repeat("b", 64), CodeDigest: digest, ExpiresAt: stamp(now.Add(10 * time.Minute))}
	grant := e2ee.OwnerAppNodeGrantClaims{Purpose: e2ee.OwnerAppNodeGrantPurpose, Scope: scope, GrantID: strings.Repeat("c", 32), ExpectedHeadVersion: 0, Profile: wire.AppNodeProfileInitial, PrepareRequestID: strings.Repeat("d", 32), PreparePacketDigest: strings.Repeat("e", 64), PreviewProofDigest: strings.Repeat("f", 64), ServerNonce: strings.Repeat("1", 64), Candidate: &n, AllowedOperations: wire.AppNodeAllowedOperations(), ReadNodeStatus: true, ConfirmationLimit: 1,
		PreparedAt: stamp(now), ProofExpiresAt: stamp(now.Add(5 * time.Minute)), LeaseExpiresAt: stamp(now.Add(15 * time.Minute))}
	original, err := wire.SealAppNodeConfirmation(keys[2], hub, grant, code, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	var packet clientwire.Packet
	if err := json.Unmarshal(original, &packet); err != nil {
		t.Fatal(err)
	}
	binding := clientwire.Binding{HubID: hub.HubID, OwnerID: scope.OwnerID, DeviceID: scope.DeviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	if _, err := clientwire.OpenRequest(keys[0], keys[2].Public(), binding, original); err != nil {
		t.Fatal(err)
	}
	approved := store.NodeControlKeyBinding{OwnerBindingID: "synthetic-binding", OwnerID: scope.OwnerID, HubID: hub.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: scope.DeviceID, OwnerKeyID: scope.OwnerPublic.ID, NodeCredentialVersion: 1, BindingVersion: 1,
		NodeKeyID: n.NodePublic.ID, NodePublicIdentity: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: 1, HubKeyID: n.HubNodeControlPublic.ID, HubPublicIdentity: n.HubNodeControlPublic, HubKeyFingerprint: n.HubNodeControlFingerprint, HubKeyVersion: 1,
		ApprovedRequestID: n.RequestID, ApprovedRequestVersion: 1, ApprovedCandidateDigest: n.CandidateDigest, ApprovedOwnerDeviceID: scope.DeviceID, ApprovedOwnerKeyID: scope.OwnerPublic.ID, ApprovedAt: stamp(now), State: "ACTIVE", Version: 1}
	reply := func(result any) []byte {
		body, err := json.Marshal(map[string]any{"request_id": "clientreq_synthetic", "operation_id": packet.Route.OperationID, "ok": true, "result": result})
		if err != nil {
			t.Fatal(err)
		}
		r := packet.Route
		r.Direction = clientwire.DirectionResponse
		r.Sequence = 7
		r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
		r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
		raw, err := clientwire.SealResponse(keys[0], keys[2].Public(), binding, r, body)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := reply(approved)
	out, err := wire.OpenAppNodeConfirmationResponse(keys[2], hub, grant, original, raw, 7)
	if err != nil || !out.OK || out.Binding == nil || out.Binding.OwnerBindingID != approved.OwnerBindingID || out.Binding.CredentialVersion != approved.NodeCredentialVersion {
		t.Fatal("actual Store DTO failed exact public mapping", err)
	}
	if _, err := wire.OpenAppNodeConfirmationResponse(keys[2], hub, grant, original, raw, 8); err == nil {
		t.Fatal("response sequence hint reset counters")
	}
	approved.ApprovedCandidateDigest = strings.Repeat("0", 64)
	if _, err := wire.OpenAppNodeConfirmationResponse(keys[2], hub, grant, original, reply(approved), 7); err == nil {
		t.Fatal("unrelated confirmed binding settled original action")
	}
	grant.GrantID = strings.Repeat("2", 32)
	if _, err := wire.OpenAppNodeConfirmationResponse(keys[2], hub, grant, original, raw, 7); err == nil {
		t.Fatal("old packet borrowed later grant")
	}
}
