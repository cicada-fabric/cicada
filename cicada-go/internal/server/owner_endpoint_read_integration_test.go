package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestOwnerEndpointReadRealTCPRequiresExactOwnerProofAndCurrentNode(t *testing.T) {
	a := nativePairTCP(t)
	capStatus, capRaw := n3HTTP(t, a.f, http.MethodGet, wire.OwnerEndpointReadPath, "", nil)
	capabilities, err := wire.ParseOwnerEndpointReadCapabilities(capRaw, a.f.hub)
	if capStatus != http.StatusOK || err != nil || !capabilities.Available {
		t.Fatal("Owner directory availability did not bind trusted Hub", capStatus, err)
	}
	registration := nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: "synthetic-owner-private-directory", Name: "原线程名称", Workspace: "/synthetic/owner-private"}
	nodePacket := a.nodeSeal(t, nodewire.EndpointRegisterOperation, 1, registration)
	nodeReply := endpointNodeReply(t, a, nodePacket, a.nodePost(t, nodePacket, http.StatusOK))
	if !nodeReply.OK {
		t.Fatal("registration for directory refused")
	}
	q, err := wire.NewOwnerEndpointRead(a.session, a.scope.Actor, a.scope.Node, "", 64, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet := a.seal(t, q)
	status, response := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointReadPath, "", packet)
	if status != http.StatusOK {
		t.Fatal("Owner-signed private directory refused", status)
	}
	var page wire.OwnerEndpointReadResult
	if wire.OpenClientResponse(a.device, a.f.hub, packet, response, &page) != nil || wire.VerifyOwnerEndpointReadResult(page, q, packet) != nil ||
		len(page.Endpoints) != 1 || page.Endpoints[0].Name != registration.Name || page.Endpoints[0].Workspace != registration.Workspace || page.Endpoints[0].Presence != "offline" {
		t.Fatal("exact private zero-rights page lost binding")
	}
	if status, retry := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointReadPath, "", packet); status != 200 || !bytes.Equal(response, retry) {
		t.Fatal("private read retry changed original receipt")
	}
	// A signed device/account envelope cannot replace the independent Owner proof.
	bad, err := wire.NewOwnerEndpointRead(a.session, a.scope.Actor, a.scope.Node, "", 64, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var proof e2ee.OwnerEndpointReadProof
	if json.Unmarshal(bad.OwnerProof, &proof) != nil {
		t.Fatal("proof fixture")
	}
	proof.Signature[0] ^= 1
	bad.OwnerProof, _ = json.Marshal(proof)
	if status, _ := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointReadPath, "", a.seal(t, bad)); status != http.StatusForbidden {
		t.Fatal("account/device signature bypassed Owner proof", status)
	}
	if !reflect.DeepEqual(wire.ActivationAllowedOperations(), []string{"nodes.list", "session.capabilities"}) {
		t.Fatal("old activation grant silently widened")
	}
	if _, err = a.f.db.RevokeNodeDeviceBinding(a.scope.Actor.OwnerID, a.scope.Node.OwnerBindingID, int64(a.scope.Node.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if status, _ := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointReadPath, "", packet); status != http.StatusForbidden {
		t.Fatal("revoked Node returned cached paths", status)
	}
}
