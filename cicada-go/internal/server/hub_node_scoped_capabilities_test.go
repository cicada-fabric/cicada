package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestHubNodeScopedCapabilitiesAvailableAndStrict(t *testing.T) {
	f, _ := newNodePairTLSFixture(t)
	for _, path := range []string{wire.AppNodeScopedCapabilitiesPath, wire.NodePairTrustScopedCapabilitiesPath} {
		status, raw := n3HTTP(t, f, http.MethodGet, path, "", nil)
		if status != http.StatusOK {
			t.Fatalf("discovery status %d", status)
		}
		if path == wire.AppNodeScopedCapabilitiesPath {
			var c wire.AppNodeScopedCapabilities
			if json.Unmarshal(raw, &c) != nil || !c.Available || !reflect.DeepEqual(c, wire.AppNodeScopedContractCapabilities(wire.AppNodeTransportHTTPS)) {
				t.Fatal("scoped authority metadata")
			}
		} else {
			var c wire.NodePairTrustScopedCapabilities
			if json.Unmarshal(raw, &c) != nil || !c.Available || !reflect.DeepEqual(c, wire.NodePairTrustScopedContractCapabilities()) {
				t.Fatal("scoped NPT metadata")
			}
		}
		status, _ = n3HTTP(t, f, http.MethodPost, path, "", []byte(`{}`))
		if status != http.StatusMethodNotAllowed {
			t.Fatal("discovery accepted POST")
		}
	}
	for _, op := range wire.AppNodeScopedHTTPOperations() {
		status, _ := n3HTTP(t, f, http.MethodPost, wire.AppNodeScopedHTTPPath(op), "", []byte(`{}`))
		if status != http.StatusForbidden {
			t.Fatal("available scoped route accepted an unauthenticated packet", status)
		}
	}
}
