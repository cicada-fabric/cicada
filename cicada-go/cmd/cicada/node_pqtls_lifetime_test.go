//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bufio"
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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func productLifetimeLeaf(t *testing.T, root, name string, start, end time.Time) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Getenv("PQTLS_TEST_OPENSSL"), "x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", name+"-lifetime.pem", "-not_before", start.UTC().Format("20060102150405Z"), "-not_after", end.UTC().Format("20060102150405Z"), "-extfile", name+".ext")
	cmd.Dir = root
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("synthetic short-lived ML-DSA certificate command failed")
	}
	data, err := os.ReadFile(filepath.Join(root, name+"-lifetime.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid synthetic lifetime certificate")
	}
	digest := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(digest[:])
}

// Observe real Conn.Write even if http.Request.Write changes error wrapping.
type lifetimeObservedWriter struct {
	conn    net.Conn
	written int
	err     error
}

func (w *lifetimeObservedWriter) Write(data []byte) (int, error) {
	n, err := w.conn.Write(data)
	w.written += n
	if err != nil {
		w.err = err
	}
	return n, err
}

// Synthetic session metadata; real product Store, PQ listeners and connections.
// A single finite certificate window covers retained HTTP and idle/active SSE.
func TestProductNodePQCertificateLifetime(t *testing.T) {
	runtimeStartupDNS(t)
	f := newNativeNetworkBindingFixture(t)
	root, _ := productPQFixtures(t)
	hub, _ := machineHubFrom(f.bridge.ctx)
	idleNodeID := "node_synthetic_lifetime_idle"
	idleToken, idleDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	codeDigest := sha256.Sum256([]byte("synthetic lifetime idle Node pairing code"))
	if _, err = f.persistence.CreatePendingNodeDeviceBinding(idleNodeID, "Synthetic lifetime idle Node", idleDigest, hex.EncodeToString(codeDigest[:]), time.Now().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.persistence.ConfirmPendingNodeDeviceBinding(f.ownerID, f.deviceID, hex.EncodeToString(codeDigest[:])); err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idleKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	activeBinding := productManagedPQEnroll(t, f.persistence, f.nodeID, hub.Token, f.ownerID, f.deviceID, nodeKey, hubKey)
	idleActiveBinding := productManagedPQEnroll(t, f.persistence, idleNodeID, idleToken, f.ownerID, f.deviceID, idleKey, hubKey)
	address, frontAddress := productFreeAddress(t), productFreeAddress(t)
	material := productManagedPQCA(t, filepath.Join(root, "managed-ca"), hub.HubID, productManagedPQOrigin(t, address), "http://"+frontAddress, 12*time.Second)
	end := material.notAfter
	active := productManagedPQActivate(t, material, productManagedPQNodeInput{DB: f.persistence, Owner: f.ownerIdentity, Node: nodeKey, Hub: hubKey, Binding: activeBinding, Token: hub.Token, StateRoot: hub.StateDir, WriterRoot: hub.WriterRoot, PQOrigin: productManagedPQOrigin(t, address), LogicalOrigin: "http://" + frontAddress, DNSName: "node-a.synthetic.invalid"}, end)
	idleRoot := filepath.Join(root, "idle-node-state")
	idleActive := productManagedPQActivate(t, material, productManagedPQNodeInput{DB: f.persistence, Owner: f.ownerIdentity, Node: idleKey, Hub: hubKey, Binding: idleActiveBinding, Token: idleToken, StateRoot: idleRoot, WriterRoot: idleRoot, PQOrigin: productManagedPQOrigin(t, address), LogicalOrigin: "http://" + frontAddress, DNSName: "node-b.synthetic.invalid"}, end)
	binding, err := f.persistence.CurrentNodeTransportBinding(f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	idleBinding, err := f.persistence.CurrentNodeTransportBinding(idleNodeID)
	if err != nil {
		t.Fatal("read initial idle Node authority")
	}
	beforeActive, err := f.persistence.GetNodeTLSAuthorityReservationLocal(active.RequestID)
	if err != nil {
		t.Fatal("read initial active Node TLS reservation")
	}
	beforeIdle, err := f.persistence.GetNodeTLSAuthorityReservationLocal(idleActive.RequestID)
	if err != nil {
		t.Fatal("read initial idle Node TLS reservation")
	}
	hubCfg := &active.HubConfig
	hubCfg.Listen = address
	hubCfg.Peers = []nodetransport.Approval{productManagedPQApproval(t, f.persistence, active), productManagedPQApproval(t, f.persistence, idleActive)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var joinCalls, streamCalls atomic.Int32
	inner := server.NewFabricHandlerWithNodeTLSCurrent(f.service, "", func(credential, nodeID string, packet []byte) ([]byte, error) {
		return control.ReadNodeTLSCurrentPacket(f.persistence, hubKey, credential, nodeID, packet)
	})
	front := newControlHTTPServer("", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := pqtls.StateFromContext(r.Context())
		if r.URL.Path != "/healthz" && (err != nil || !state.ValidAt(time.Now()) || !state.VerifiedNotAfter.Equal(end) || r.TLS != nil) {
			t.Error("actual product handler lacked current observed certificate validity")
		}
		if r.URL.Path == "/v2/fabric/node/networks/join" {
			joinCalls.Add(1)
		}
		if strings.HasPrefix(r.URL.Path, "/v2/relay/nodes/") && strings.HasSuffix(r.URL.Path, "/events") {
			streamCalls.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
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
			t.Error("lifetime listener cleanup did not finish")
		}
	})
	for i := 0; ; i++ {
		response, err := (&http.Client{Timeout: 100 * time.Millisecond}).Get("http://" + frontAddress + "/healthz")
		if err == nil {
			response.Body.Close()
			break
		}
		if i >= 100 {
			t.Fatal("lifetime product listener did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	nodeCfg := &active.NodeConfig
	client, err := pqtls.NewClient(nodeCfg.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	dial := func() net.Conn {
		t.Helper()
		c, err := client.DialContext(ctx, "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	keepalive := dial()
	input := fabric.NetworkJoinInput{NetworkID: f.networkID, InvitationToken: f.join.InvitationToken, OwnerJoinProof: f.join.OwnerJoinProof, Harness: "codex", NativeSessionID: f.nativeID, EndpointName: "Synthetic lifetime Endpoint"}
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	joinRequest := func() *http.Request {
		t.Helper()
		r, err := http.NewRequest(http.MethodPost, "https://"+address+"/v2/fabric/node/networks/join", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "CicadaNode "+hub.Token)
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	r := joinRequest()
	if err := r.Write(keepalive); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(keepalive), r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 201 {
		t.Fatalf("positive enrolled Join status %d err %v", response.StatusCode, err)
	}
	idleCfg := idleActive.NodeConfig
	idleClient, err := pqtls.NewClient(idleCfg.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	var streams []chan error
	for i := 0; i < 2; i++ {
		streamClient, nodeID, token := client, f.nodeID, hub.Token
		if i == 1 {
			streamClient, nodeID, token = idleClient, idleNodeID, idleToken
		}
		c, err := streamClient.DialContext(ctx, "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		r, err := http.NewRequest(http.MethodGet, "https://"+address+"/v2/relay/nodes/"+nodeID+"/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "CicadaNode "+token)
		if err := r.Write(c); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), r)
		if err != nil || response.StatusCode != 200 {
			t.Fatal("actual product SSE did not start")
		}
		reader := bufio.NewReader(response.Body)
		line, err := reader.ReadString('\n')
		if err != nil || line != "event: ready\n" {
			t.Fatal("actual product SSE ready missing")
		}
		finished := make(chan error, 1)
		streams = append(streams, finished)
		go func() { _, err := io.Copy(io.Discard, reader); response.Body.Close(); finished <- err }()
	}
	stopHints := make(chan struct{})
	hintsDone := make(chan struct{})
	go func() {
		defer close(hintsDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopHints:
				return
			case <-ticker.C:
				f.service.NotifyNodeClaimHint(f.nodeID)
			}
		}
	}()
	defer func() { close(stopHints); <-hintsDone }()
	if time.Until(end) < time.Second {
		t.Fatal("lifetime product setup exhausted finite validity window")
	}
	<-time.After(time.Until(end) + 20*time.Millisecond)
	observedWrite := &lifetimeObservedWriter{conn: keepalive}
	if err := joinRequest().Write(observedWrite); err == nil || observedWrite.written != 0 || !errors.Is(observedWrite.err, pqtls.ErrCertificateValidity) {
		t.Fatalf("retained client post-expiry write bytes=%d request=%v transport=%v", observedWrite.written, err, observedWrite.err)
	}
	for _, finished := range streams {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("expired SSE did not terminate within recheck/IO bound")
		}
	}
	if joinCalls.Load() != 1 || streamCalls.Load() != 2 {
		t.Fatalf("expired product handler dispatched: join %d streams %d", joinCalls.Load(), streamCalls.Load())
	}
	fresh, err := client.DialContext(ctx, "tcp", address)
	if fresh != nil {
		fresh.Close()
	}
	if err == nil {
		t.Fatal("fresh expired connection accepted")
	}
	for _, expected := range []struct {
		nodeID, requestID string
		binding           *store.NodeTransportBinding
		reservation       *store.NodeTLSAuthoritySnapshot
	}{{f.nodeID, active.RequestID, binding, beforeActive}, {idleNodeID, idleActive.RequestID, idleBinding, beforeIdle}} {
		after, err := f.persistence.CurrentNodeTransportBinding(expected.nodeID)
		if err != nil || after == nil {
			t.Fatal("read post-expiry Node binding")
		}
		// Current TLS authority is a time-filtered view and must disappear.
		// The durable Owner/credential binding itself must remain unchanged.
		if after.TLSAuthority != nil {
			t.Fatal("expired TLS authority remained current")
		}
		beforeBinding, afterBinding := *expected.binding, *after
		beforeBinding.TLSAuthority, afterBinding.TLSAuthority = nil, nil
		if !reflect.DeepEqual(beforeBinding, afterBinding) {
			t.Fatal("expiry changed persistent Node binding")
		}
		persisted, err := f.persistence.GetNodeTLSAuthorityReservationLocal(expected.requestID)
		if err != nil || !reflect.DeepEqual(persisted, expected.reservation) {
			t.Fatal("expiry changed persistent TLS claims/grant/ACK/activation/version")
		}
	}
	t.Log("real short-lived Hub/Node ML-DSA certificates: enrolled Join succeeded before expiry; retained client refused new authentication bytes; two SSEs terminated; no authority reset or post-expiry dispatch")
}
