//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/server"
)

// These RoundTrippers prove client wiring only. TLS evidence comes from the
// real OpenSSL-backed product listeners in TestNativeNetworkBridgePQJoinRenew.
type networkBridgeRoundTripper func(*http.Request) (*http.Response, error)

func (f networkBridgeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestNativeNetworkBridgeTransportSelectionAndHubIsolation(t *testing.T) {
	nativeID := "synthetic-network-transport-thread"
	workspace := prepareMCPJoinSessionRecord(t, nativeID)
	// A managed Hub must use its own transport, not the global one-shot config.
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	var calls [2]int
	for i, origin := range []string{"http://hub-a.synthetic.invalid", "http://hub-b.synthetic.invalid"} {
		token := "synthetic-token-" + string(rune('a'+i))
		transport := networkBridgeRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls[i]++
			if r.URL.Scheme+"://"+r.URL.Host != origin || r.Method != http.MethodPost ||
				r.Header.Get("Authorization") != "CicadaNode "+token || r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("request escaped its selected Hub or changed authorization")
			}
			var input map[string]any
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input["network_id"] != "synthetic-network" ||
				input["native_session_id"] != nativeID || input["harness"] != "codex" {
				t.Fatal("bridge changed Network/native identity")
			}
			if r.URL.Path == "/v2/fabric/node/networks/renew" && input["endpoint_id"] != "synthetic-endpoint" {
				t.Fatal("renewal changed Endpoint identity")
			}
			return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
		})
		bridge := &machineAgentJoinBridge{ctx: withMachineHubContext(context.Background(), machineHubContext{Origin: origin, NodeTransport: transport}), baseURL: origin, nodeToken: token}
		_, err := bridge.joinNetwork(localNetworkJoinRequest{Version: localJoinProtocolVersion, Operation: "network_join", NetworkID: "synthetic-network", InvitationToken: "synthetic-invitation", OwnerJoinProof: "synthetic-proof", Harness: "codex", NativeSessionID: nativeID, Workspace: workspace})
		if err == nil || err.Error() != "Hub rejected Network Join with HTTP 403" {
			t.Fatalf("selected Join transport was not used: %v", err)
		}
		_, err = bridge.renewNetwork(localNetworkRenewRequest{Version: localJoinProtocolVersion, Operation: "network_renew", NetworkID: "synthetic-network", EndpointID: "synthetic-endpoint", Harness: "codex", NativeSessionID: nativeID, Workspace: workspace})
		if err == nil || err.Error() != "Hub rejected Network Renew with HTTP 403" {
			t.Fatalf("selected renewal transport was not used: %v", err)
		}
	}
	if calls != [2]int{2, 2} {
		t.Fatalf("per-Hub transports were not isolated: %v", calls)
	}
}

func TestNativeNetworkBridgeTransportConfigurationFailsBeforeRequest(t *testing.T) {
	nativeID := "synthetic-network-config-thread"
	workspace := prepareMCPJoinSessionRecord(t, nativeID)
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	var calls atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(403) }))
	t.Cleanup(plain.Close)
	for _, origin := range []string{plain.URL, ":invalid-url"} {
		bridge := &machineAgentJoinBridge{ctx: context.Background(), baseURL: origin, nodeToken: "synthetic-token"}
		_, err := bridge.joinNetwork(localNetworkJoinRequest{Version: localJoinProtocolVersion, Operation: "network_join", NetworkID: "synthetic-network", InvitationToken: "synthetic-invitation", OwnerJoinProof: "synthetic-proof", Harness: "codex", NativeSessionID: nativeID, Workspace: workspace})
		if !errors.Is(err, nodetransport.ErrConfiguration) {
			t.Fatalf("Join lost configuration error before request construction: %v", err)
		}
		_, err = bridge.renewNetwork(localNetworkRenewRequest{Version: localJoinProtocolVersion, Operation: "network_renew", NetworkID: "synthetic-network", EndpointID: "synthetic-endpoint", Harness: "codex", NativeSessionID: nativeID, Workspace: workspace})
		if !errors.Is(err, nodetransport.ErrConfiguration) {
			t.Fatalf("renewal lost configuration error before request construction: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid PQ configuration fell back to plaintext HTTP")
	}
}

func TestNativeNetworkBridgeTransportRejectsRedirect(t *testing.T) {
	nativeID := "synthetic-network-redirect-thread"
	workspace := prepareMCPJoinSessionRecord(t, nativeID)
	calls := 0
	transport := networkBridgeRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "hub.synthetic.invalid" {
			t.Fatal("Node authorization followed a redirect")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://other.synthetic.invalid/leak"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	bridge := &machineAgentJoinBridge{ctx: withMachineHubContext(context.Background(), machineHubContext{NodeTransport: transport}), baseURL: "http://hub.synthetic.invalid", nodeToken: "synthetic-token"}
	_, joinErr := bridge.joinNetwork(localNetworkJoinRequest{Version: localJoinProtocolVersion, Operation: "network_join", NetworkID: "synthetic-network", InvitationToken: "synthetic-invitation", OwnerJoinProof: "synthetic-proof", Harness: "codex", NativeSessionID: nativeID, Workspace: workspace})
	_, renewErr := bridge.renewNetwork(localNetworkRenewRequest{Version: localJoinProtocolVersion, Operation: "network_renew", NetworkID: "synthetic-network", EndpointID: "synthetic-endpoint", Harness: "codex", NativeSessionID: nativeID, Workspace: workspace})
	if joinErr == nil || renewErr == nil || calls != 2 {
		t.Fatalf("Join/renew redirect policy changed: calls=%d join=%v renew=%v", calls, joinErr, renewErr)
	}
}

// Reuses real Store/Fabric/native registration and the tagged product TLS
// fixture. Session metadata is synthetic; this is not a native Runtime run.
func TestNativeNetworkBridgePQJoinRenew(t *testing.T) {
	f := newNativeNetworkBindingFixture(t)
	root, pins := productPQFixtures(t)
	hub, _ := machineHubFrom(f.bridge.ctx)
	address, frontAddress := productFreeAddress(t), productFreeAddress(t)
	identity := func(kind, name, nodeID string, epoch uint64) nodetransport.Identity {
		return nodetransport.Identity{Kind: kind, HubID: hub.HubID, NodeID: nodeID, TLSEpoch: epoch, DNSName: name + ".synthetic.invalid"}
	}
	binding, err := f.persistence.CurrentNodeTransportBinding(f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	hubIdentity, nodeIdentity := identity("hub", "hub", "", 0), identity("node", "node-a", f.nodeID, 17)
	hubCfg := &nodetransport.Config{Version: 1, Role: "hub", Listen: address, CertificateFile: filepath.Join(root, "hub.pem"), PrivateKeyFile: filepath.Join(root, "hub.key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: hubIdentity,
		Peers: []nodetransport.Approval{{Identity: nodeIdentity, PinKind: "certificate-sha256", PinSHA256: pins["node-a"], OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, CredentialVersion: binding.CredentialVersion}}}
	hubCfg, err = loadHubPQTransport(writeProductPQConfig(t, root, "network-hub", hubCfg))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	var joins, renewals atomic.Int32
	inner := server.NewFabricHandler(f.service, "")
	observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/fabric/node/networks/join" || r.URL.Path == "/v2/fabric/node/networks/renew" {
			state, err := pqtls.StateFromContext(r.Context())
			if err != nil || r.TLS != nil || state.TLSVersion != "TLSv1.3" || state.Group != "MLKEM768" ||
				state.CipherSuite != "TLS_AES_256_GCM_SHA384" || state.PeerSignature != "ML-DSA-65" || state.ALPN != "http/1.1" ||
				state.VerificationResult != 0 || state.Peer.NodeID != f.nodeID || state.Peer.BindingEpoch != 17 {
				t.Error("Network Join/renew did not arrive with real verified strict Node PQ state")
			}
			if r.URL.Path == "/v2/fabric/node/networks/join" {
				joins.Add(1)
			} else {
				renewals.Add(1)
			}
		}
		inner.ServeHTTP(w, r)
	})
	front := newControlHTTPServer("", 0, observed)
	front.Addr = frontAddress
	done := make(chan error, 1)
	go func() { done <- serveProductHTTP(ctx, front, f.service, hubCfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(12 * time.Second):
			t.Error("Network PQ product listeners failed cleanup")
		}
	})
	for i := 0; ; i++ {
		response, err := (&http.Client{Timeout: 100 * time.Millisecond}).Get("http://" + frontAddress + "/healthz")
		if err == nil {
			response.Body.Close()
			break
		}
		if i >= 100 {
			t.Fatal("Network PQ product Hub did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	base := "http://" + frontAddress
	// A valid application credential alone cannot enter the Node route through
	// the ordinary listener. This request must not reach the observed handler.
	plain, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v2/fabric/node/networks/join", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	plain.Header.Set("Authorization", "CicadaNode "+hub.Token)
	response, err := (&http.Client{Timeout: time.Second}).Do(plain)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || joins.Load() != 0 {
		t.Fatal("ordinary listener allowed Node Join without PQ authentication")
	}
	nodeCfg := &nodetransport.Config{Version: 1, Role: "node", Origin: "https://" + address, ApplicationOrigin: base, CertificateFile: filepath.Join(root, "node-a.pem"), PrivateKeyFile: filepath.Join(root, "node-a.key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: nodeIdentity,
		Peers: []nodetransport.Approval{{Identity: hubIdentity, PinKind: "certificate-sha256", PinSHA256: pins["hub"]}}}
	hub.Origin = base
	if err := configureMachinePQTransport(&hub, writeProductPQConfig(t, root, "network-node", nodeCfg)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.NodeTransport.(interface{ CloseIdleConnections() }).CloseIdleConnections() })
	bridge := &machineAgentJoinBridge{ctx: withMachineHubContext(ctx, hub), baseURL: base, stateDir: f.bridge.stateDir, nodeID: f.nodeID, nodeToken: hub.Token}
	join := f.join
	join.Version, join.Operation = localJoinProtocolVersion, "network_join"
	joined, err := bridge.joinNetwork(join)
	if err != nil {
		t.Fatal(err)
	}
	nativeBefore := f.binding(t, joined.Endpoint.ID)
	renewed, err := bridge.renewNetwork(localNetworkRenewRequest{Version: localJoinProtocolVersion, Operation: "network_renew", NetworkID: f.networkID, EndpointID: joined.Endpoint.ID, Harness: "codex", NativeSessionID: f.nativeID, Workspace: f.workspace})
	if err != nil {
		t.Fatal(err)
	}
	nativeAfter := f.binding(t, joined.Endpoint.ID)
	if joins.Load() != 1 || renewals.Load() != 1 || renewed.Endpoint.ID != joined.Endpoint.ID || renewed.Endpoint.NativeSessionID != f.nativeID ||
		renewed.BindingEpoch <= joined.BindingEpoch || nativeBefore.ID == "" || nativeAfter.ID != nativeBefore.ID || nativeAfter.Epoch != nativeBefore.Epoch {
		t.Fatal("PQ Join/renew changed Endpoint/native continuity or failed access renewal")
	}
	t.Logf("actual strict Node PQ Join=1 Renew=1; TLSv1.3 MLKEM768 TLS_AES_256_GCM_SHA384 ML-DSA-65 http/1.1; access epochs %d→%d, native epoch %d unchanged; ordinary listener rejected", joined.BindingEpoch, renewed.BindingEpoch, nativeAfter.Epoch)
}
