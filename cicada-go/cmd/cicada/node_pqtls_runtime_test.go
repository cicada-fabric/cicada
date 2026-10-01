//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/server"
)

func productPQFixtures(t *testing.T) (string, map[string]string) {
	t.Helper()
	bin, base := os.Getenv("PQTLS_TEST_OPENSSL"), os.Getenv("PQTLS_TEST_ARTIFACT_DIR")
	if bin == "" || base == "" {
		t.Fatal("pinned OpenSSL and private synthetic artifact directory required")
	}
	root, err := os.MkdirTemp(base, "synthetic-product-pqtls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("private TLS fixture cleanup failed")
		}
	})
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal("synthetic OpenSSL fixture command failed")
		}
		return out
	}
	for _, ca := range []string{"ca", "wrong-ca"} {
		run("req", "-new", "-x509", "-newkey", "ML-DSA-65", "-nodes", "-keyout", ca+".key", "-out", ca+".pem", "-days", "1", "-subj", "/CN=CICADA SYNTHETIC PRODUCT TEST ONLY "+ca, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
	}
	pins := map[string]string{}
	for _, name := range []string{"hub", "node-a", "node-b", "old-node-a"} {
		run("req", "-new", "-newkey", "ML-DSA-65", "-nodes", "-keyout", name+".key", "-out", name+".csr", "-subj", "/CN=CICADA SYNTHETIC PRODUCT TEST ONLY "+name)
		purpose := "clientAuth"
		if name == "hub" {
			purpose = "serverAuth"
		}
		ext := "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + purpose + "\nsubjectAltName=DNS:" + name + ".synthetic.invalid\n"
		if err := os.WriteFile(filepath.Join(root, name+".ext"), []byte(ext), 0600); err != nil {
			t.Fatal(err)
		}
		run("x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", name+".pem", "-days", "1", "-extfile", name+".ext")
		data, err := os.ReadFile(filepath.Join(root, name+".pem"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatal("invalid synthetic certificate")
		}
		sum := sha256.Sum256(block.Bytes)
		pins[name] = hex.EncodeToString(sum[:])
		if err := os.Chmod(filepath.Join(root, name+".key"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("synthetic private TLS fixtures: independent ML-DSA-65 CA/Hub/Node keys; one-day validity; never deployment material")
	return root, pins
}

func productFreeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeProductPQConfig(t *testing.T, root, name string, cfg *nodetransport.Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProductNodePQRuntimeRouterRelayAndCurrentCertificateAuthority(t *testing.T) {
	if os.Getenv("PQTLS_PRODUCT_AGENT_CHILD") == "1" {
		if err := runMachineAgent([]string{"--id", os.Getenv("PQTLS_CHILD_NODE_ID"), "--control-url", os.Getenv("PQTLS_CHILD_ORIGIN"), "--state-dir", os.Getenv("PQTLS_CHILD_NODE_STATE"), "--pqtls-config", os.Getenv("PQTLS_CHILD_CONFIG"), "--relay-only", "--once"}); err != nil {
			t.Fatal("separate production Node Agent process failed")
		}
		return
	}
	fixture := newMachineSealedReceiveFixtureWithActions(t, false, "ask", []string{"ask", "reply"})
	root, pins := productPQFixtures(t)
	hubID, err := fixture.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	address, frontAddress := productFreeAddress(t), productFreeAddress(t)
	identity := func(name, nodeID string, epoch uint64) nodetransport.Identity {
		kind := "node"
		if name == "hub" {
			kind = "hub"
		}
		return nodetransport.Identity{Kind: kind, HubID: hubID, NodeID: nodeID, TLSEpoch: epoch, DNSName: name + ".synthetic.invalid"}
	}
	hubCfg := &nodetransport.Config{Version: 1, Role: "hub", Listen: address, CertificateFile: filepath.Join(root, "hub.pem"), PrivateKeyFile: filepath.Join(root, "hub.key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: identity("hub", "", 0)}
	for _, entry := range []struct {
		name, id string
		epoch    uint64
	}{{"node-a", fixture.sourceNodeID, 17}, {"node-b", fixture.targetNodeID, 29}} {
		b, err := fixture.store.CurrentNodeTransportBinding(entry.id)
		if err != nil {
			t.Fatal(err)
		}
		hubCfg.Peers = append(hubCfg.Peers, nodetransport.Approval{Identity: identity(entry.name, entry.id, entry.epoch), PinKind: "certificate-sha256", PinSHA256: pins[entry.name], OwnerID: b.OwnerID, OwnerKeyID: b.OwnerKeyID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, CredentialVersion: b.CredentialVersion})
	}
	hubPath := writeProductPQConfig(t, root, "hub-config", hubCfg)
	hubCfg, err = loadHubPQTransport(hubPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	var callsMu sync.Mutex
	var remoteA []string
	var authenticatedHTTP atomic.Int64
	var profileObserved atomic.Bool
	inner := server.NewFabricHandler(fixture.service, "synthetic-manager-token") // Control is absent by construction.
	observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/relay/nodes/") {
			authenticatedHTTP.Add(1)
			state, err := pqtls.StateFromContext(r.Context())
			if err != nil || r.TLS != nil || state.Group != "MLKEM768" || state.PeerSignature != "ML-DSA-65" {
				t.Error("product request lost verified PQ context")
			} else {
				profileObserved.Store(true)
			}
			if strings.Contains(r.URL.Path, "/"+fixture.sourceNodeID+"/") {
				callsMu.Lock()
				remoteA = append(remoteA, r.RemoteAddr)
				callsMu.Unlock()
			}
		}
		inner.ServeHTTP(w, r)
	})
	front := newControlHTTPServer("", 0, observed)
	front.Addr = frontAddress
	done := make(chan error, 1)
	go func() { done <- serveProductHTTP(ctx, front, fixture.service, hubCfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(12 * time.Second):
			t.Error("product listener/SSE cleanup did not finish")
		}
	})
	ready := false
	for i := 0; i < 100; i++ {
		response, err := (&http.Client{Timeout: 100 * time.Millisecond}).Get("http://" + frontAddress + "/healthz")
		if err == nil {
			response.Body.Close()
			ready = true
			break
		}
		select {
		case err := <-done:
			t.Fatalf("product listener exited: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("product Hub did not start")
	}
	makeContext := func(name, nodeID, token string, epoch uint64) (context.Context, *nodetransport.Config) {
		c := &nodetransport.Config{Version: 1, Role: "node", Origin: "https://" + address, ApplicationOrigin: "http://" + frontAddress, CertificateFile: filepath.Join(root, name+".pem"), PrivateKeyFile: filepath.Join(root, name+".key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: identity(name, nodeID, epoch), Peers: []nodetransport.Approval{{Identity: identity("hub", "", 0), PinKind: "certificate-sha256", PinSHA256: pins["hub"]}}}
		path := writeProductPQConfig(t, root, name+"-config", c)
		hub := machineHubContext{HubID: hubID, Origin: c.LogicalOrigin(), NodeID: nodeID, Token: token}
		if err := configureMachinePQTransport(&hub, path); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { hub.NodeTransport.(interface{ CloseIdleConnections() }).CloseIdleConnections() })
		return withMachineHubContext(ctx, hub), c
	}
	ctxA, cfgA := makeContext("node-a", fixture.sourceNodeID, fixture.sourceToken, 17)
	ctxB, _ := makeContext("node-b", fixture.targetNodeID, fixture.targetToken, 29)
	base := "http://" + frontAddress // isolated logical origin; ALL peer traffic maps to PQ HTTPS.
	// A separate test executable process runs the actual Agent flag/state/lock,
	// authorization probe, heartbeat and durable reconciliation paths. No native
	// runtime is constructed and the source inbox is deliberately empty.
	nodeState, err := os.MkdirTemp(root, "agent-state-")
	if err != nil {
		t.Fatal(err)
	}
	if err := persistMachineNodeIdentity(filepath.Join(machineNodeStateDir(nodeState, fixture.sourceNodeID), "identity.json"), machineNodeCredentialPath(nodeState, fixture.sourceNodeID), &machineNodeIdentity{Version: 1, NodeID: fixture.sourceNodeID, RelayToken: fixture.sourceToken}); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithTimeout(ctx, 10*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, executable, "-test.run=^TestProductNodePQRuntimeRouterRelayAndCurrentCertificateAuthority$", "-test.v")
	child.Env = append(os.Environ(), "PQTLS_PRODUCT_AGENT_CHILD=1", "PQTLS_CHILD_NODE_ID="+fixture.sourceNodeID, "PQTLS_CHILD_ORIGIN="+base, "PQTLS_CHILD_NODE_STATE="+nodeState, "PQTLS_CHILD_CONFIG="+filepath.Join(root, "node-a-config.json"), "CICADA_HUB_ID="+hubID)
	childOutput, err := child.CombinedOutput()
	if err != nil {
		t.Fatal("separate actual Node Agent PQ process exited unsuccessfully")
	}
	t.Logf("separate relay-only Node Agent process exit=0 transcript_sha256=%x bytes=%d", sha256.Sum256(childOutput), len(childOutput))
	callsMu.Lock()
	remoteA = nil
	callsMu.Unlock()
	if err := sendMachineNodeHeartbeat(ctxA, base, fixture.sourceNodeID, fixture.sourceToken); err != nil {
		t.Fatalf("actual Node heartbeat: %v", err)
	}
	input := fabric.NodeSealedLinkAskInput{LinkID: fixture.link.ID, MessageID: fixture.messageID, RequestID: fixture.requestID, IdempotencyKey: "synthetic-product-pq-ask", DataScope: fixture.dataScope, ExpiresAt: fixture.link.ExpiresAt, Ciphertext: fixture.ciphertext}
	for i := 0; i < 2; i++ {
		if err := machineAPIJSON(ctxA, base+"/v2/relay/nodes/"+fixture.sourceNodeID+"/sealed/ask", http.MethodPost, input, nil); err != nil {
			t.Fatalf("PQ sealed durable Ask: %v", err)
		}
	}
	stored, err := fixture.store.GetRelaySealedV1(fixture.messageID)
	if err != nil || stored.Route.RequestID != fixture.requestID || !bytes.Equal(stored.Ciphertext, fixture.ciphertext) {
		t.Fatal("Router/Relay did not persist one exact sealed request")
	}
	callsMu.Lock()
	sameConnection := len(remoteA) >= 3 && remoteA[0] == remoteA[1] && remoteA[1] == remoteA[2]
	callsMu.Unlock()
	if !sameConnection {
		t.Fatal("Node HTTP keepalive was not reused")
	}

	t.Run("other-certificate-cannot-borrow-bearer", func(t *testing.T) {
		borrowed, _ := machineHubFrom(ctxA)
		borrowed.Token = fixture.targetToken
		bad := withMachineHubContext(ctx, borrowed)
		err := machineAPIJSON(bad, base+"/v2/relay/nodes/"+fixture.targetNodeID+"/heartbeat", http.MethodPost, map[string]any{}, nil)
		if !machineAPIHasStatus(err, http.StatusUnauthorized) {
			t.Fatal("other Node certificate borrowed current bearer")
		}
	})
	t.Run("ordinary-frontdoor-no-peer-bypass", func(t *testing.T) {
		r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+frontAddress+"/v2/relay/nodes/"+fixture.sourceNodeID+"/heartbeat", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "CicadaNode "+fixture.sourceToken)
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("ordinary listener accepted enrolled Node")
		}
	})
	t.Run("Client-frontdoor-contract-preserved", func(t *testing.T) {
		client, err := machineNodeHTTPClient(ctxA, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Get(base + "/v2/client/capabilities")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var capabilities struct {
			Revision string `json:"contract_revision"`
		}
		if json.NewDecoder(response.Body).Decode(&capabilities) != nil || response.StatusCode != 200 || capabilities.Revision != "client-hub-v1.6.1" {
			t.Fatal("Client negotiation boundary changed")
		}
	})
	t.Run("logical-origin-whitelist-before-auth", func(t *testing.T) {
		before := authenticatedHTTP.Load()
		err := sendMachineNodeHeartbeat(ctxA, cfgA.Origin, fixture.sourceNodeID, fixture.sourceToken)
		if err == nil || authenticatedHTTP.Load() != before {
			t.Fatal("unapproved logical origin reached Node transport")
		}
	})
	t.Run("pin-SAN-trust-origin-old-cert-no-auth-data", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			mutate func(*nodetransport.Config)
		}{
			{"pin", func(c *nodetransport.Config) { c.Peers[0].PinSHA256 = strings.Repeat("ab", 32) }},
			{"SAN", func(c *nodetransport.Config) { c.Peers[0].Identity.DNSName = "wrong.synthetic.invalid" }},
			{"trust", func(c *nodetransport.Config) { c.TrustFile = filepath.Join(root, "wrong-ca.pem") }},
			{"origin", func(c *nodetransport.Config) { c.Origin = "https://" + frontAddress }},
			{"old-certificate", func(c *nodetransport.Config) {
				c.CertificateFile = filepath.Join(root, "old-node-a.pem")
				c.PrivateKeyFile = filepath.Join(root, "old-node-a.key")
				c.Identity = identity("old-node-a", fixture.sourceNodeID, 16)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := *cfgA
				c.Peers = append([]nodetransport.Approval(nil), cfgA.Peers...)
				tc.mutate(&c)
				transport, err := nodetransport.NewTransport(&c)
				if err != nil {
					t.Fatal(err)
				}
				defer transport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
				badHub, _ := machineHubFrom(ctxA)
				badHub.NodeTransport = transport
				before := authenticatedHTTP.Load()
				err = sendMachineNodeHeartbeat(withMachineHubContext(ctx, badHub), base, fixture.sourceNodeID, fixture.sourceToken)
				if err == nil || authenticatedHTTP.Load() != before {
					t.Fatal("mismatched transport emitted Node HTTP authentication")
				}
			})
		}
	})

	streamCtx, stopStream := context.WithCancel(ctxB)
	wake, revoked := make(chan struct{}, 8), make(chan error, 1)
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		runMachineRelayEventStream(streamCtx, base, fixture.targetNodeID, wake, revoked)
	}()
	defer func() {
		stopStream()
		select {
		case <-streamDone:
		case <-time.After(4 * time.Second):
			t.Error("Node SSE goroutine leaked")
		}
	}()
	select {
	case <-wake:
	case <-ctx.Done():
		t.Fatal("Node outbound PQ SSE never became ready")
	}
	// Disconnect the first outbound SSE, then reconnect before claiming the
	// already persisted message. Cancellation must join the original worker.
	stopStream()
	select {
	case <-streamDone:
	case <-time.After(3 * time.Second):
		t.Fatal("first PQ SSE worker did not stop")
	}
	reconnectedCtx, stopReconnectedStream := context.WithCancel(ctxB)
	defer stopReconnectedStream()
	reconnectedDone := make(chan struct{})
	go func() {
		defer close(reconnectedDone)
		runMachineRelayEventStream(reconnectedCtx, base, fixture.targetNodeID, wake, revoked)
	}()
	defer func() {
		stopReconnectedStream()
		select {
		case <-reconnectedDone:
		case <-time.After(4 * time.Second):
			t.Error("reconnected Node SSE goroutine leaked")
		}
	}()
	select {
	case <-wake:
	case <-ctx.Done():
		t.Fatal("PQ SSE reconnect never became ready")
	}
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	if err := machineAPIJSON(ctxB, base+"/v2/relay/nodes/"+fixture.targetNodeID+"/sealed/claim", http.MethodPost, fabric.NodeClaimInput{ConsumerID: "synthetic-pq-consumer", Limit: 10}, &claimed); err != nil {
		t.Fatal(err)
	}
	if len(claimed.Deliveries) != 1 || claimed.Deliveries[0].MessageID != fixture.messageID || claimed.Deliveries[0].NodeID != fixture.targetNodeID || !bytes.Equal(claimed.Deliveries[0].Ciphertext, fixture.ciphertext) {
		t.Fatal("offline sealed message did not reach exact current Node over PQ")
	}
	bindingB, err := fixture.store.CurrentNodeTransportBinding(fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.RevokeNodeDeviceBinding(bindingB.OwnerID, bindingB.BindingID, bindingB.BindingVersion); err != nil {
		t.Fatal(err)
	}
	select {
	case <-revoked:
	case <-time.After(5 * time.Second):
		t.Fatal("live PQ SSE did not observe current Store revocation")
	}
	select {
	case <-reconnectedDone:
	case <-time.After(time.Second):
		t.Fatal("revoked Node SSE loop did not stop")
	}
	if err := sendMachineNodeHeartbeat(ctxB, base, fixture.targetNodeID, fixture.targetToken); !machineAPIHasStatus(err, http.StatusUnauthorized) {
		t.Fatal("revoked Node accepted another request on its PQ pool")
	}
	if !profileObserved.Load() {
		t.Fatal("actual product Router never saw verified PQ state")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(fixture.databasePath, "private message for the original session"); err != nil {
		t.Fatal("Hub persisted sealed message plaintext")
	}
	t.Log("actual product Fabric-only Hub/Node PQ HTTPS: pure profile, keepalive, outbound SSE, offline durable sealed Ask/claim, idempotency, current Store revocation; Control not constructed; no native/model consumption claim")
}

func TestProductNodePQRejectsClassicalTLSAndPlainHTTPBeforeAuthentication(t *testing.T) {
	root, pins := productPQFixtures(t)
	var received atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			received.Add(1)
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	})
	for _, tlsServer := range []bool{false, true} {
		name := "plain-HTTP"
		if tlsServer {
			name = "classical-Go-TLS"
		}
		t.Run(name, func(t *testing.T) {
			var foreign *httptest.Server
			if tlsServer {
				foreign = httptest.NewTLSServer(handler)
			} else {
				foreign = httptest.NewServer(handler)
			}
			defer foreign.Close()
			cfg := &nodetransport.Config{Version: 1, Role: "node", Origin: "https://" + strings.TrimPrefix(strings.TrimPrefix(foreign.URL, "http://"), "https://"), CertificateFile: filepath.Join(root, "node-a.pem"), PrivateKeyFile: filepath.Join(root, "node-a.key"), TrustFile: filepath.Join(root, "ca.pem"), Identity: nodetransport.Identity{Kind: "node", HubID: "synthetic", NodeID: "a", TLSEpoch: 17, DNSName: "node-a.synthetic.invalid"}, Peers: []nodetransport.Approval{{Identity: nodetransport.Identity{Kind: "hub", HubID: "synthetic", DNSName: "hub.synthetic.invalid"}, PinKind: "certificate-sha256", PinSHA256: pins["hub"]}}}
			transport, err := nodetransport.NewTransport(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Origin+"/v2/relay/nodes/a/heartbeat", strings.NewReader(`{}`))
			r.Header.Set("Authorization", "CicadaNode SYNTHETIC NEVER ACCEPTED")
			_, err = (&http.Client{Transport: transport, CheckRedirect: rejectNodeRedirect}).Do(r)
			if err == nil || errors.Is(err, context.Canceled) || received.Load() != 0 {
				t.Fatal("downgrade transport emitted Node auth data")
			}
		})
	}
}
