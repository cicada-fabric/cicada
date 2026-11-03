package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/store"
)

func newNodePairTLSFixture(t *testing.T) (*hubAccountTCPFixture, hubtransport.DiscoveryCandidate) {
	t.Helper()
	f := &hubAccountTCPFixture{stateDir: filepath.Join(t.TempDir(), "SYNTHETIC-node-pair-Hub")}
	f.dbPath = filepath.Join(f.stateDir, "cicada.sqlite3")
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.client != nil {
			f.client.CloseIdleConnections()
		}
		if f.http != nil {
			f.http.Close()
		}
		if f.db != nil {
			f.db.Close()
		}
	})
	id, err := f.db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	origin, err := hubtransport.DefaultOrigin(id)
	if err != nil {
		t.Fatal(err)
	}
	f.setup, err = f.db.InitializeHubOwnerLocal("SYNTHETIC TLS pairing Owner", origin, false)
	if err != nil {
		t.Fatal(err)
	}
	f.ids, err = hubidentity.LoadOrCreate(f.stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = hubowner.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.auth, err = hubauth.NewServiceWithNodeAuthority(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.hub, err = f.auth.HubIdentity()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := hubtransport.InitializeProfile(f.stateDir, f.ids.ClientControl, f.hub, f.ids.NodeControl.Public(), origin, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.BindHubNativeTLSLocal(profile.DescriptorText()); err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHubNodesHandler(f.owner, f.auth, nodes).(*hubNodesHandler)
	if handler.base.control != nil {
		t.Fatal("pairing constructed Control inference")
	}
	f.http = httptest.NewUnstartedServer(handler)
	f.http.TLS = profile.TLSConfig()
	// httptest otherwise inserts its unrelated fallback leaf when the numeric
	// first probe sends no SNI. Production ServeTLS uses this profile directly.
	f.http.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return profile.TLSConfig(), nil }
	f.http.StartTLS()
	dial := f.http.Listener.Addr().String()
	candidate, err := hubtransport.DiscoverCandidate(context.Background(), dial)
	if err != nil || candidate.DescriptorText != profile.DescriptorText() {
		t.Fatal("real public descriptor discovery", err)
	}
	f.client, err = hubtransport.NewHTTPClient(candidate.Descriptor, dial, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Keep logical origin and numeric locator separate; no global trust mutation.
	f.http.URL = origin
	return f, candidate
}

// Historical codec/Store receipt tests stay independent of public admission.
// Current public enrollment is covered by the separate Node-scoped TLS flow.
func TestNodePairTrustRetiredRealTLSPublicOperationsReject(t *testing.T) {
	f, _ := newNodePairTLSFixture(t)
	status, raw := n3HTTP(t, f, http.MethodGet, wire.NodePairTrustCapabilitiesPath, "", nil)
	var caps wire.NodePairTrustCapabilities
	if status != http.StatusOK || json.Unmarshal(raw, &caps) != nil || caps.Available {
		t.Fatal("retired pairing was advertised")
	}
	for _, op := range caps.Operations {
		t.Run(op, func(t *testing.T) {
			path := wire.NodePairTrustHTTPPath(op)
			status, raw := n3HTTP(t, f, http.MethodPost, path, "", []byte(`{}`))
			if status != http.StatusGone || !bytes.Contains(raw, []byte("NODE_PAIR_PROTOCOL_UNSUPPORTED")) {
				t.Fatal("retired public pairing operation was not refused", status)
			}
			status, _ = n3HTTP(t, f, http.MethodPost, path, "SYNTHETIC-forbidden-bearer", []byte(`{}`))
			if status != http.StatusBadRequest {
				t.Fatal("retired pairing accepted a credential header", status)
			}
		})
	}
}
