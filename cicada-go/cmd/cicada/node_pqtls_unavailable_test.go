//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

func TestProductNodePQUnavailableHubFailsBeforeIdentityOrListener(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "never-created-hub-state")
	t.Setenv("CICADA_STATE_DIR", stateDir)
	err := serve([]string{"--fabric-only", "--node-pqtls-config", filepath.Join(stateDir, "missing-private-config.json")})
	if !errors.Is(err, pqtls.ErrUnavailable) {
		t.Fatalf("unavailable product did not fail closed: %v", err)
	}
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unavailable transport initialized Hub identity/state")
	}
}

func TestProductNodePQUnavailableClientNeverEmitsNodeAuthentication(t *testing.T) {
	var received atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(204) }))
	defer foreign.Close()
	root := t.TempDir()
	for _, name := range []string{"cert.pem", "key.pem", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("SYNTHETIC UNAVAILABLE BUILD TEST ONLY"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := nodetransport.Config{Version: 1, Role: "node", Origin: "https://" + strings.TrimPrefix(foreign.URL, "http://"), CertificateFile: "cert.pem", PrivateKeyFile: "key.pem", TrustFile: "ca.pem", Identity: nodetransport.Identity{Kind: "node", HubID: "synthetic-hub", NodeID: "synthetic-node", TLSEpoch: 17, DNSName: "node.synthetic.invalid"}, Peers: []nodetransport.Approval{{Identity: nodetransport.Identity{Kind: "hub", HubID: "synthetic-hub", DNSName: "hub.synthetic.invalid"}, PinKind: "certificate-sha256", PinSHA256: strings.Repeat("ab", 32)}}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "transport.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", path)
	for _, test := range []struct {
		name string
		ctx  context.Context
	}{
		{"no_agent_context", context.Background()},
		{"pinned_without_checked_transport", withMachineHubContext(context.Background(), machineHubContext{
			HubID: cfg.Identity.HubID, NodeID: cfg.Identity.NodeID, Origin: cfg.Origin,
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := sendMachineNodeHeartbeat(test.ctx, cfg.Origin, "synthetic-node", "cicada_node_SYNTHETIC_NEVER_ACCEPTED")
			t.Logf("observed error=%v authority_unavailable=%t pq_build_unavailable=%t HTTP_received=%d",
				err, errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable), errors.Is(err, pqtls.ErrUnavailable), received.Load())
			if !errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable) {
				t.Fatalf("unchecked Node context error=%v, want current-authority rejection", err)
			}
			if got := received.Load(); got != 0 {
				t.Fatalf("unchecked Node context emitted %d HTTP requests", got)
			}
		})
	}
}
