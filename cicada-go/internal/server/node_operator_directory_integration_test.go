package server

import (
	"encoding/json"
	"net/http"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestNodeOperatorDirectoryRealTCPZeroRightsAndProfileSeparation(t *testing.T) {
	a := nativePairTCP(t)
	status, raw := n3HTTP(t, a.f, http.MethodGet, wire.OwnerEndpointReadPath+"?profile="+nodewire.NodeOperatorProfile, "", nil)
	caps, err := nodewire.ParseNodeOperatorCapabilities(raw, a.nodeBinding())
	if status != http.StatusOK || err != nil || !caps.Available {
		t.Fatal("Node profile did not bind approved Node pin", status, err)
	}
	status, raw = n3HTTP(t, a.f, http.MethodGet, wire.OwnerEndpointReadPath, "", nil)
	if _, err = wire.ParseOwnerEndpointReadCapabilities(raw, a.f.hub); status != http.StatusOK || err != nil {
		t.Fatal("Node profile changed original Owner format", err)
	}
	registration := nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: "synthetic-operator-original", Name: "合成原线程", Workspace: "/synthetic/operator/private"}
	packet := a.nodeSeal(t, nodewire.EndpointRegisterOperation, 1, registration)
	if r := endpointNodeReply(t, a, packet, a.nodePost(t, packet, http.StatusOK)); !r.OK {
		t.Fatal("registration", r.ErrorCode)
	}
	list := a.nodeSeal(t, nodewire.EndpointDirectoryOperation, 2, nodewire.EndpointDirectoryRequest{})
	r := endpointNodeReply(t, a, list, a.nodePost(t, list, http.StatusOK))
	var page nodewire.EndpointDirectoryResult
	if !r.OK || json.Unmarshal(r.Result, &page) != nil || len(page.Endpoints) != 1 || page.Endpoints[0].Name != registration.Name || page.Endpoints[0].NativeSessionID != registration.NativeSessionID || page.Endpoints[0].Presence != "offline" || page.Endpoints[0].StateDigest == "" {
		t.Fatal("operator list did not include zero-rights self metadata", r.ErrorCode)
	}
	bad := a.nodeSeal(t, nodewire.EndpointDirectoryOperation, 3, map[string]any{"owner_id": "forged", "limit": 64})
	if refusal := endpointNodeReply(t, a, bad, a.nodePost(t, bad, http.StatusOK)); refusal.OK || refusal.ErrorCode != nodewire.ErrEndpointContext.Error() {
		t.Fatal("caller Owner selector became authority")
	}
	member, err := a.f.db.GetEndpointV2(page.Endpoints[0].EndpointID)
	if err != nil || member.GroupID != "" || member.BindingID != "" {
		t.Fatal("operator discovery created communication scope", err)
	}
}
