package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// This protected same-UID describe fixture asserts an already approved binding.
// It tests the consumer fence, not the Owner approval protocol itself.
func syntheticNativeNodePin(t *testing.T, f nativeNodeFixture, address string) LocalNodeConnectionPin {
	t.Helper()
	p := syntheticLocalNodePin(t, privateLocalNodeRoot(t), "SYNTHETIC-native-consumer")
	p.HubID, p.APIOrigin = f.metadata.HubID, f.d.Claims.Origin
	p.Binding.HubKeyID, p.Binding.HubFingerprint = f.metadata.KeyID, f.metadata.Fingerprint
	p.HubTransportDescriptor, p.HubDialAddress = f.text, address
	if err := validateLocalNodePin(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNativeNodeSelectedMCPHeartbeatAndNetworkUseSameVerifiedPool(t *testing.T) {
	f := newNativeNodeFixture(t)
	var calls atomic.Int32
	business := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if "https://"+r.Host != f.d.Claims.Origin || !strings.Contains(r.Header.Get("Authorization"), "SYNTHETIC") {
			t.Error("consumer lost logical origin or synthetic authorization")
		}
		_, _ = w.Write([]byte("{}"))
	})
	first, second := f.server(t, f.metadata, business), f.server(t, f.metadata, business)
	pin := syntheticNativeNodePin(t, f, first.Listener.Addr().String())
	var live atomic.Pointer[LocalNodeConnectionPin]
	live.Store(&pin)
	mockLocalNode(t, pin, func(r *localNodeDescribeResponse) { r.Description.Connection = *live.Load() }, false)
	m, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: pin.UserRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer close(m.stop)
	defer m.selectedNodeHTTPPool().close()
	ctx := harness.SessionContext{Harness: "codex", NativeSessionID: "SYNTHETIC-thread", MachineID: pin.NodeID, Workspace: pin.UserRoot}
	network := networkCLIState{Version: 1, APIOrigin: pin.APIOrigin, NetworkID: "SYNTHETIC-network", EndpointID: "SYNTHETIC-endpoint", Harness: ctx.Harness,
		NativeSessionID: ctx.NativeSessionID, NodeID: ctx.MachineID, Workspace: ctx.Workspace, SessionToken: "SYNTHETIC-network-session"}
	stateFile := filepath.Join(pin.UserRoot, "SYNTHETIC-network-session.json")
	if err := os.WriteFile(stateFile, mustJSON(network), 0600); err != nil {
		t.Fatal(err)
	}
	h := &codexFrozenHeartbeat{connection: m.localNode, nativeHTTP: m.selectedNodeHTTPPool(), cache: mcpCachedSession{ConnectionPin: &pin, APIOrigin: pin.APIOrigin, SessionToken: "SYNTHETIC-session", GroupID: "SYNTHETIC-group"}}
	consumers := []struct {
		name string
		call func() error
	}{
		{"MCP", func() error {
			_, e := m.requestWithGroup(http.MethodPost, "/v2/fabric/SYNTHETIC-request", map[string]string{"body": "SYNTHETIC"}, "CicadaSession SYNTHETIC-session", "SYNTHETIC-group")
			return e
		}},
		{"heartbeat", func() error { _, e := h.renew(context.Background()); return e }},
		{"NetworkDirect", func() error {
			_, e := m.networkDirectHTTP(network, http.MethodGet, "/v2/fabric/networks/SYNTHETIC-network/direct", nil)
			return e
		}},
		{"NetworkDirectory", func() error {
			_, e := m.networkToolLocked("cicada_network_directory", map[string]any{"network_id": network.NetworkID}, ctx, "SYNTHETIC-scope", stateFile)
			return e
		}},
	}
	for _, route := range []string{first.Listener.Addr().String(), second.Listener.Addr().String()} {
		next := pin
		next.HubDialAddress = route
		live.Store(&next)
		for _, consumer := range consumers {
			if err := consumer.call(); err != nil {
				t.Fatal(consumer.name, "did not use selected numeric TLS route", err)
			}
			if m.nativeHTTP.address != route || m.nativeHTTP.descriptor != pin.HubTransportDescriptor || m.localNode.Pin != pin || *h.cache.ConnectionPin != pin {
				t.Fatal("consumer rewrote its original authority pin or retained stale routing")
			}
		}
	}
	if calls.Load() != 8 {
		t.Fatal("missing consumer request", calls.Load())
	}
	// Even a protected local describe cannot make the private CA pool accept
	// a different TLS installation. No HTTP authorization reaches that server.
	other := newNativeNodeFixture(t)
	var leaked atomic.Int32
	bad := other.server(t, other.metadata, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	next := pin
	next.HubDialAddress = bad.Listener.Addr().String()
	live.Store(&next)
	for _, consumer := range consumers {
		if err := consumer.call(); err == nil {
			t.Fatal(consumer.name, "accepted wrong private CA")
		}
	}
	if leaked.Load() != 0 || calls.Load() != 8 {
		t.Fatal("TLS failure leaked a credential or fell back")
	}
	// Every consumer must also recheck the live binding before any HTTP request.
	changed := pin
	changed.Binding.NodeKeyEpoch++
	live.Store(&changed)
	for _, consumer := range consumers {
		if err := consumer.call(); err == nil {
			t.Fatal(consumer.name, "accepted changed binding")
		}
	}
	if calls.Load() != 8 {
		t.Fatal("changed binding sent business")
	}
}

func TestNativeNodeOutboxRelocationPreservesOriginalPinAndUncertainOperation(t *testing.T) {
	f := newNativeNodeFixture(t)
	pin := syntheticNativeNodePin(t, f, "127.0.0.1:443")
	scope := connectionOutboxScope(pin)
	s := connectionOutbox(t, pin)
	input := mcpOutboxInput{Target: "SYNTHETIC-peer", Body: "SYNTHETIC_ORIGINAL_UNCERTAIN_BODY"}
	op, _, err := s.prepare(scope, "send", "SYNTHETIC-exact-retry", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.markAttempt(scope, op.OperationID); err != nil {
		t.Fatal(err)
	}
	original, err := s.markError(scope, op.OperationID, mcpOutboxStatusUnknown, errors.New("SYNTHETIC lost response"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	readPin := func() []byte {
		t.Helper()
		db, err := sql.Open("sqlite", mcpOutboxSQLiteURI(pin.MCPOutboxStateFile, "mode=ro&immutable=1"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var raw []byte
		if err := db.QueryRow("SELECT pin FROM mcp_outbox_connection_pin WHERE slot=1").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	originalPin := readPin()
	changed := pin
	changed.HubDialAddress = "[::1]:8443"
	resumed := connectionOutbox(t, changed)
	recovered, created, err := resumed.prepare(scope, "send", "SYNTHETIC-exact-retry", input)
	if err != nil || created || recovered != original {
		t.Fatal("relocation replaced original uncertain operation", err)
	}
	if _, _, err := resumed.prepare(scope, "send", "SYNTHETIC-exact-retry", mcpOutboxInput{Target: input.Target, Body: "SYNTHETIC_REPLACEMENT"}); !errors.Is(err, errMCPOutboxConflict) {
		t.Fatal("exact retry allowed replacement", err)
	}
	if err := resumed.close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalPin, readPin()) {
		t.Fatal("numeric relocation rewrote persisted authority pin")
	}
	before := outboxFiles(t, pin.MCPOutboxStateFile)
	for _, kind := range []string{"binding", "epoch", "path", "node", "hub", "descriptor", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			p := changed
			switch kind {
			case "binding":
				p.Binding.BindingID += "-other"
			case "epoch":
				p.Binding.NodeKeyEpoch++
			case "path":
				p.MCPSessionStateFile += "-other"
			case "node":
				p.NodeID += "-other"
			case "hub":
				p.HubID += "-other"
			case "descriptor":
				p.HubTransportDescriptor += "x"
			case "legacy":
				p.HubTransportDescriptor, p.HubDialAddress = "", ""
			}
			if _, err := connectionOutbox(t, p).load(scope, op.OperationID); err == nil {
				t.Fatal("changed authority adopted uncertain outbox")
			}
			requireOutboxFilesUnchanged(t, pin.MCPOutboxStateFile, before)
		})
	}
}

func TestNativeNodeDiscoveryLargeLegalPinAndStrictReplyBounds(t *testing.T) {
	f := newNativeNodeFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC SIZE TEST CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: bytes.Repeat([]byte{0}, 7600)}}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil || len(der) > hubtransport.MaxRootCertificateBytes {
		t.Fatal("synthetic CA size", err)
	}
	ids, err := existingHubNodeIdentities(hubControlConfig(filepath.Dir(f.file), ""))
	if err != nil {
		t.Fatal(err)
	}
	c := f.d.Claims
	c.RootCertificateDER = der
	d, err := hubtransport.SignDescriptor(ids.ClientControl, c)
	if err != nil {
		t.Fatal(err)
	}
	f.d, f.text = d, ""
	f.text, err = hubtransport.EncodeDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	pin := syntheticNativeNodePin(t, f, "127.0.0.1:443")
	// Linux PATH_MAX includes the trailing NUL. Use a legal 4095-byte path
	// with short components, below the protocol's 4096-byte ceiling.
	longPath := pin.UserRoot + "/" + strings.Repeat("a/", (4095-len(pin.UserRoot)-2)/2)
	longPath += strings.Repeat("z", 4095-len(longPath))
	pin.WriterRoot, pin.MCPSessionStateFile, pin.MCPOutboxStateFile = longPath, longPath, longPath
	raw, _ := json.Marshal(pin)
	if err := validateLocalNodePin(pin); len(raw) <= 32<<10 || len(raw) > localNodeMaxPinBytes || err != nil {
		t.Fatal("large legal public descriptor/pin was rejected", len(raw), err)
	}
	var mode atomic.Int32
	mockLocalNode(t, pin, func(r *localNodeDescribeResponse) {
		switch mode.Load() {
		case 1:
			r.Description.Nonce = strings.Repeat("b", 64)
		case 2:
			r.Description.InstanceID = strings.Repeat("b", 32)
		case 3:
			r.Description.LocatorDigest = strings.Repeat("b", 64)
		case 4:
			r.Description.Connection.WriterRoot += "x"
		case 5:
			r.Error = strings.Repeat("x", localNodeMaxReplyBytes)
		}
	}, false)
	selection := LocalNodeSelection{UserRoot: pin.UserRoot}
	if got, err := ResolveLocalNodeConnection(context.Background(), selection, &pin); err != nil || got.Pin != pin {
		t.Fatal("bounded large pin did not survive live describe", err)
	}
	for _, n := range []int32{1, 2, 3, 4, 5} {
		mode.Store(n)
		if _, err := ResolveLocalNodeConnection(context.Background(), selection, &pin); err == nil {
			t.Fatal("large reply bypassed original live fence", n)
		}
	}
	oversize := pin
	oversize.HubTransportDescriptor = strings.Repeat("x", localNodeMaxPinBytes)
	if !errors.Is(validateLocalNodePin(oversize), ErrLocalNodeDiscoveryLimit) {
		t.Fatal("oversize pin was accepted")
	}
	request, _ := json.Marshal(localNodeDescribeRequest{1, "local_node_describe", strings.Repeat("a", 64), strings.Repeat("a", 32), strings.Repeat("a", 64)})
	if len(request)+1 > localNodeMaxRequestBytes || localNodeMaxRequestBytes != 1024 {
		t.Fatal("request capacity changed with reply capacity")
	}
}
