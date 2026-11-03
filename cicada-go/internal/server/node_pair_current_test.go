package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type retiredNodePairBody struct{ reads int }

func (b *retiredNodePairBody) Read([]byte) (int, error) {
	b.reads++
	return 0, http.ErrBodyReadAfterClose
}

func TestNodePairCurrentOnlyPublicAdmission(t *testing.T) {
	f, _ := newNodePairScopedTLSFixture(t)
	status, raw := n3HTTP(t, f, http.MethodGet, wire.NodePairTrustCapabilitiesPath, "", nil)
	var old wire.NodePairTrustCapabilities
	if status != http.StatusOK || json.Unmarshal(raw, &old) != nil || old.Available {
		t.Fatal("retired pairing was advertised")
	}
	status, raw = n3HTTP(t, f, http.MethodGet, wire.NodePairTrustScopedCapabilitiesPath, "", nil)
	if status != http.StatusOK {
		t.Fatal("current native TLS pairing discovery was disabled")
	}
	if _, err := wire.DecodeNodePairTrustScopedCapabilities(raw); err != nil {
		t.Fatal("current pairing capabilities changed")
	}
	handler := f.http.Config.Handler
	for _, op := range wire.NodePairTrustContractCapabilities().Operations {
		body := &retiredNodePairBody{}
		req := httptest.NewRequest(http.MethodPost, wire.NodePairTrustHTTPPath(op), body)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusGone || body.reads != 0 {
			t.Fatal("retired public pairing admission read a body or remained enabled", op)
		}
	}
}
