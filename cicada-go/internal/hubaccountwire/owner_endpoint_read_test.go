package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestOwnerEndpointReadProofPurposeWindowAndExactRequest(t *testing.T) {
	f := appNodeCrypto(t)
	node, _ := e2ee.NewIdentity()
	hub, _ := e2ee.NewIdentity()
	binding := e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-owner-binding", OwnerID: f.scope.OwnerID, HubID: f.scope.HubID, NodeID: "synthetic-node",
		ClientDeviceID: f.scope.DeviceID, OwnerKeyID: f.owner.Public().ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: node.Public(), NodeKeyVersion: 1, NodeKeyEpoch: 1,
		HubNodeControlPublic: hub.Public(), HubNodeControlKeyVersion: 1, ApprovedRequestVersion: 1, State: "ACTIVE"}
	q, err := NewOwnerEndpointRead(f.session, f.scope, binding, "", 64, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := SealClientRequest(f.device, f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, q, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened OwnerEndpointReadRequest
	pub := f.device.Public()
	if err = OpenRequestAt(f.hubPrivate, &pub, b, r, packet, &opened, f.now); err != nil {
		t.Fatal(err)
	}
	claims, err := e2ee.VerifyOwnerEndpointRead(f.owner.Public(), opened.OwnerProof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*e2ee.OwnerEndpointReadClaims){
		func(v *e2ee.OwnerEndpointReadClaims) { v.Purpose = e2ee.OwnerAppNodeStatusGrantPurpose },
		func(v *e2ee.OwnerEndpointReadClaims) { v.Node.NodeKeyEpoch++ },
		func(v *e2ee.OwnerEndpointReadClaims) { v.Scope.DeviceEpoch++ },
		func(v *e2ee.OwnerEndpointReadClaims) { v.Cursor = "other-endpoint" },
		func(v *e2ee.OwnerEndpointReadClaims) { v.Limit = 1 },
		func(v *e2ee.OwnerEndpointReadClaims) { v.RequestID = strings.Repeat("1", 32) },
		func(v *e2ee.OwnerEndpointReadClaims) { v.Nonce = strings.Repeat("a", 64) },
	} {
		var proof e2ee.OwnerEndpointReadProof
		if json.Unmarshal(q.OwnerProof, &proof) != nil {
			t.Fatal("synthetic proof")
		}
		mutate(&proof.Claims)
		changed, _ := json.Marshal(proof)
		if _, err = e2ee.VerifyOwnerEndpointRead(f.owner.Public(), changed, f.now); err == nil {
			t.Fatal("signature did not bind changed read scope")
		}
	}
	if _, err = e2ee.VerifyOwnerEndpointRead(f.owner.Public(), q.OwnerProof, f.now.Add(time.Minute)); err == nil {
		t.Fatal("expired proof accepted")
	}
	claims.ExpiresAt = formatUTC(f.now.Add(61 * time.Second))
	if _, err = e2ee.SignOwnerEndpointRead(f.owner, claims); err == nil {
		t.Fatal("unbounded read lifetime signed")
	}
	page := OwnerEndpointReadResult{Format: OwnerEndpointReadResultFormat, RequestID: q.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(packet), HubID: f.hub.HubID,
		OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, NodeID: binding.NodeID, State: AppNodeCompleted, CapturedAt: formatUTC(f.now), Freshness: "SNAPSHOT_ONLY",
		Endpoints: []OwnerEndpointCard{{EndpointID: "ep-a", Name: "原线程", Workspace: "C:\\synthetic", Harness: "codex", Presence: "offline"}}}
	response, err := SealResponse(f.hubPrivate, f.device.Public(), r, page)
	if err != nil {
		t.Fatal(err)
	}
	var result OwnerEndpointReadResult
	if OpenClientResponse(f.device, f.hub, packet, response, &result) != nil || VerifyOwnerEndpointReadResult(result, q, packet) != nil {
		t.Fatal("PQ result lost original read scope")
	}
	result.NextCursor = "wrong-row"
	if VerifyOwnerEndpointReadResult(result, q, packet) == nil {
		t.Fatal("response cursor moved outside actual page")
	}
}

func TestOwnerEndpointReadDoesNotExpandFrozenActivation(t *testing.T) {
	if !reflect.DeepEqual(ActivationAllowedOperations(), []string{"nodes.list", "session.capabilities"}) {
		t.Fatal("activation operations changed")
	}
	if !reflect.DeepEqual(AppNodeStatusAllowedOperations(), []string{}) {
		t.Fatal("N3 status proof acquired business operations")
	}
}

func TestOwnerEndpointReadPublicAvailabilityIsBoundedAndHubSpecific(t *testing.T) {
	f := appNodeCrypto(t)
	fp, err := HubFingerprint(f.hub)
	if err != nil {
		t.Fatal(err)
	}
	c := OwnerEndpointReadCapabilities{Format: OwnerEndpointReadCapabilitiesFormat, ContractRevision: OwnerEndpointReadContractRevision, Available: true,
		HubID: f.hub.HubID, HubFingerprint: fp, MaxPageRows: 64, MaxPageBytes: MaxOwnerEndpointPageBytes, MaxProofSeconds: 60}
	raw, _ := json.Marshal(c)
	if parsed, err := ParseOwnerEndpointReadCapabilities(append(raw, '\n'), f.hub); err != nil || !parsed.Available {
		t.Fatal("valid availability refused", err)
	}
	c.Available = false
	raw, _ = json.Marshal(c)
	if parsed, err := ParseOwnerEndpointReadCapabilities(raw, f.hub); err != nil || parsed.Available {
		t.Fatal("unavailable mode became authorization", err)
	}
	c.HubFingerprint = strings.Repeat("a", 64)
	raw, _ = json.Marshal(c)
	if _, err = ParseOwnerEndpointReadCapabilities(raw, f.hub); err == nil {
		t.Fatal("foreign Hub availability accepted")
	}
	if _, err = ParseOwnerEndpointReadCapabilities([]byte(strings.Repeat(" ", MaxOwnerEndpointCapabilitiesBytes+1)), f.hub); err == nil {
		t.Fatal("unbounded availability response accepted")
	}
}
