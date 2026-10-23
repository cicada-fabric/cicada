package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

type nativeNodeFixture struct {
	d          hubtransport.Descriptor
	text, file string
	profile    *hubtransport.Profile
	metadata   machineNodeControlHubIdentity
}

func newNativeNodeFixture(t *testing.T) nativeNodeFixture {
	t.Helper()
	state, d, text := setupNativeHub(t)
	config := hubControlConfig(state, "")
	ids, err := existingHubNodeIdentities(config)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	profile, err := loadHubNativeTLS(config, db, ids)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(state, "SYNTHETIC-public-transport.txt")
	if err = os.WriteFile(file, []byte(text+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	meta := machineNodeControlHubIdentity{Version: nodewire.Version, Algorithm: e2ee.Algorithm, HubID: d.Claims.Hub.HubID, KeyID: d.Claims.NodeControl.ID,
		KeyVersion: 1, Fingerprint: nodewire.IdentityFingerprint(d.Claims.NodeControl), PublicIdentity: d.Claims.NodeControl}
	return nativeNodeFixture{d: d, text: text, file: file, profile: profile, metadata: meta}
}

func (f nativeNodeFixture) server(t *testing.T, metadata machineNodeControlHubIdentity, business http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/node/identity" {
			if r.Header.Get("Authorization") != "" {
				t.Error("public identity probe sent a credential")
			}
			_ = json.NewEncoder(w).Encode(metadata)
			return
		}
		if business != nil {
			business.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	s.TLS = f.profile.TLSConfig()
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func activateTestNativeNode(t *testing.T, f nativeNodeFixture, address string) (machineHubContext, *machineNodeIdentity, *machineNodeControlClient) {
	t.Helper()
	root := privateLocalNodeRoot(t)
	const node = "SYNTHETIC-native-node"
	selection, origin, err := resolveMachineNativeSelection(root, node, f.file, address, "http://127.0.0.1:1", "", false)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := loadOrCreateMachineNodeIdentity(root, node)
	if err != nil {
		t.Fatal(err)
	}
	hub := machineHubContext{Origin: origin, NodeID: node, StateDir: root, WriterRoot: root, WriterScope: "SYNTHETIC-native-scope", Token: identity.RelayToken, approvedHubID: &atomic.Pointer[string]{}}
	if err = activateMachineNativeSelection(context.Background(), &hub, selection); err != nil {
		t.Fatal(err)
	}
	if err = persistMachineNativeMarker(root, node, identity); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.NativeTransport.CloseIdleConnections)
	client, err := openMachineNodeControlClient(root, origin, node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { machineNodeControlClients.Delete(client.statePath) })
	return hub, identity, client
}

func TestNativeNodeFirstTrustPersistsWithoutOwnerApprovalOrTokenRewrite(t *testing.T) {
	f := newNativeNodeFixture(t)
	s := f.server(t, f.metadata, nil)
	hub, identity, client := activateTestNativeNode(t, f, s.Listener.Addr().String())
	if hub.HubID != "" || hub.approvedHubID.Load() != nil || client.bindingReady() {
		t.Fatal("transport trust promoted an unapproved Node")
	}
	before, err := os.ReadFile(machineNodeCredentialPath(hub.StateDir, hub.NodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	if err = persistMachineNativeMarker(hub.StateDir, hub.NodeID, identity); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(machineNodeCredentialPath(hub.StateDir, hub.NodeID))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("marker rewrote original bearer")
	}
	clear(after)
	saved, exists, err := readMachineNativeState(hub.StateDir, hub.NodeID)
	if err != nil || !exists || saved.HubTransportDescriptor != f.text || saved.HubDialAddress != s.Listener.Addr().String() {
		t.Fatal("native metadata was not persisted")
	}
	selection, origin, err := resolveMachineNativeSelection(hub.StateDir, hub.NodeID, "", "", "http://127.0.0.1:1", "", false)
	if err != nil || selection == nil || origin != f.d.Claims.Origin {
		t.Fatal("restart lost explicit native trust")
	}
	selection.transport.CloseIdleConnections()
	ctx := withMachineHubContext(context.Background(), hub)
	metadata, err := machineNodeControlGetHubIdentity(ctx, client)
	if err != nil || metadata.KeyID != f.metadata.KeyID {
		t.Fatal("first identity did not use native transport")
	}
	if hub.approvedHubID.Load() != nil || client.bindingReady() {
		t.Fatal("metadata claimed Owner approval")
	}
	oneShot := machineHubContext{Origin: hub.Origin, NodeID: hub.NodeID, StateDir: hub.StateDir}
	httpClient, err := machineNodeHTTPClient(withMachineHubContext(context.Background(), oneShot), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := httpClient.Get(hub.Origin + "/v2/node/identity")
	if err != nil {
		t.Fatal("saved one-shot transport failed")
	}
	r.Body.Close()
}

func TestNativeNodeChangedAddressValidatesBeforePersistAndKeepsOriginalBytes(t *testing.T) {
	f := newNativeNodeFixture(t)
	first := f.server(t, f.metadata, nil)
	hub, _, client := activateTestNativeNode(t, f, first.Listener.Addr().String())
	keyPath, _ := machineNodeControlPaths(hub.StateDir, hub.NodeID)
	keyBefore, _ := os.ReadFile(keyPath)
	defer clear(keyBefore)
	client.mu.Lock()
	client.state.PendingPacket = []byte("CICADA SYNTHETIC ORIGINAL ENCRYPTED PACKET TEST ONLY")
	if err := client.persistLocked(); err != nil {
		t.Fatal(err)
	}
	client.mu.Unlock()
	stateBefore, _ := os.ReadFile(client.statePath)
	defer clear(stateBefore)
	wrong := f.metadata
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrong.PublicIdentity = other.Public()
	wrong.KeyID = other.Public().ID
	wrong.Fingerprint = nodewire.IdentityFingerprint(other.Public())
	var business atomic.Int32
	bad := f.server(t, wrong, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { business.Add(1) }))
	selection, _, err := resolveMachineNativeSelection(hub.StateDir, hub.NodeID, "", bad.Listener.Addr().String(), hub.Origin, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err = activateMachineNativeSelection(context.Background(), &hub, selection); err == nil {
		t.Fatal("wrong Node-Control destination accepted")
	}
	selection.transport.CloseIdleConnections()
	stateAfter, _ := os.ReadFile(client.statePath)
	defer clear(stateAfter)
	if !bytes.Equal(stateBefore, stateAfter) || business.Load() != 0 {
		t.Fatal("failed relocation changed state or sent business")
	}
	second := f.server(t, f.metadata, nil)
	selection, _, err = resolveMachineNativeSelection(hub.StateDir, hub.NodeID, "", second.Listener.Addr().String(), hub.Origin, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err = activateMachineNativeSelection(context.Background(), &hub, selection); err != nil {
		t.Fatal(err)
	}
	defer selection.transport.CloseIdleConnections()
	if !bytes.Equal(client.state.PendingPacket, []byte("CICADA SYNTHETIC ORIGINAL ENCRYPTED PACKET TEST ONLY")) || client.state.HubDialAddress != second.Listener.Addr().String() {
		t.Fatal("relocation lost original packet or route")
	}
	keyAfter, _ := os.ReadFile(keyPath)
	defer clear(keyAfter)
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("relocation changed Node identity")
	}
}

func TestNativeNodePartialInitAndLostStateNeverFallBack(t *testing.T) {
	f := newNativeNodeFixture(t)
	root := privateLocalNodeRoot(t)
	node := "SYNTHETIC-partial"
	identity, _, err := loadOrCreateMachineNodeIdentity(root, node)
	if err != nil {
		t.Fatal(err)
	}
	client, err := openMachineNodeControlClient(root, f.d.Claims.Origin, node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { machineNodeControlClients.Delete(client.statePath) })
	if _, _, err = resolveMachineNativeSelection(root, node, "", "", "http://127.0.0.1:1", "", false); err == nil {
		t.Fatal("partial state fell back to default origin")
	}
	if _, err = machineSavedNativeTransport(machineHubContext{StateDir: root, NodeID: node, Origin: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("one-shot ignored partial original origin")
	}
	if err = persistMachineNativeMarker(root, node, identity); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readMachineNativeState(root, node); err == nil {
		t.Fatal("cleared native descriptor became legacy")
	}
	keyPath, _ := machineNodeControlPaths(root, node)
	if err = os.Remove(client.statePath); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readMachineNativeState(root, node); err == nil {
		t.Fatal("lost state reopened initial setup")
	}
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readMachineNativeState(root, node); err == nil {
		t.Fatal("lost state/key ignored durable native marker")
	}
}

func TestNativeNodeConflictingModesDescriptorOrOriginRejectBeforeNetwork(t *testing.T) {
	f := newNativeNodeFixture(t)
	s := f.server(t, f.metadata, nil)
	hub, _, _ := activateTestNativeNode(t, f, s.Listener.Addr().String())
	for _, tc := range []struct {
		file, address, base, pq string
		explicit                bool
	}{
		{f.file, s.Listener.Addr().String(), "https://foreign.synthetic.invalid", "", true},
		{f.file, s.Listener.Addr().String(), hub.Origin, "SYNTHETIC-PQ-CONFIG", true},
		{"", "hub.synthetic.invalid:443", hub.Origin, "", true},
	} {
		if selection, _, err := resolveMachineNativeSelection(hub.StateDir, hub.NodeID, tc.file, tc.address, tc.base, tc.pq, tc.explicit); err == nil {
			if selection != nil {
				selection.transport.CloseIdleConnections()
			}
			t.Fatal("conflicting routing selection accepted")
		}
	}
	legacyRoot := privateLocalNodeRoot(t)
	if _, _, err := resolveMachineNativeSelection(legacyRoot, "SYNTHETIC", "", "127.0.0.1:443", hub.Origin, "", true); err == nil {
		t.Fatal("locator without public trust accepted")
	}
	if !strings.HasPrefix(f.text, hubtransport.DescriptorPrefix) {
		t.Fatal("wrong public carrier")
	}
}

func TestNativeNodeInvalidRelocationTLSNeverPersistsOrSendsBusiness(t *testing.T) {
	f := newNativeNodeFixture(t)
	first := f.server(t, f.metadata, nil)
	hub, _, client := activateTestNativeNode(t, f, first.Listener.Addr().String())
	original, err := os.ReadFile(client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	var bundle struct {
		CAKeyDER []byte `json:"ca_key_der"`
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(f.file), "native-tls", "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &bundle) != nil {
		t.Fatal("synthetic profile parse")
	}
	clear(raw)
	defer clear(bundle.CAKeyDER)
	caKey, err := x509.ParsePKCS8PrivateKey(bundle.CAKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(f.d.Claims.RootCertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	originalCert, err := f.profile.TLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"SAN", "SPKI", "CA"} {
		t.Run(kind, func(t *testing.T) {
			var business atomic.Int32
			bad := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { business.Add(1) }))
			key := originalCert.PrivateKey.(*ecdsa.PrivateKey)
			name := f.d.Claims.ServerName
			if kind == "SAN" {
				name = "wrong.SYNTHETIC.invalid"
			}
			if kind == "SPKI" {
				key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind != "CA" {
				leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
					DNSNames: []string{name}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
				if e != nil {
					t.Fatal(e)
				}
				bad.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			}
			bad.StartTLS() // CA case intentionally uses httptest's unrelated CA.
			defer bad.Close()
			selection, _, e := resolveMachineNativeSelection(hub.StateDir, hub.NodeID, "", bad.Listener.Addr().String(), hub.Origin, "", true)
			if e != nil {
				t.Fatal(e)
			}
			defer selection.transport.CloseIdleConnections()
			if e = activateMachineNativeSelection(context.Background(), &hub, selection); e == nil {
				t.Fatal("invalid TLS relocation accepted")
			}
			after, e := os.ReadFile(client.statePath)
			defer clear(after)
			if e != nil || !bytes.Equal(original, after) || business.Load() != 0 {
				t.Fatal("TLS failure changed state or sent credentials")
			}
		})
	}
}

func TestNativeNodeOriginalKeyAndCredentialLossNeverRegenerates(t *testing.T) {
	f := newNativeNodeFixture(t)
	s := f.server(t, f.metadata, nil)
	for _, kind := range []string{"NodeControlKey", "relay.token", "identity.json"} {
		t.Run(kind, func(t *testing.T) {
			hub, _, client := activateTestNativeNode(t, f, s.Listener.Addr().String())
			path, _ := machineNodeControlPaths(hub.StateDir, hub.NodeID)
			if kind != "NodeControlKey" {
				path = filepath.Join(machineNodeStateDir(hub.StateDir, hub.NodeID), kind)
			}
			before, e := os.ReadFile(client.statePath)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(before)
			if e = os.Remove(path); e != nil {
				t.Fatal(e)
			}
			if selection, _, e := resolveMachineNativeSelection(hub.StateDir, hub.NodeID, "", "", hub.Origin, "", true); e == nil {
				if selection != nil {
					selection.transport.CloseIdleConnections()
				}
				t.Fatal("lost original material accepted")
			}
			if kind == "NodeControlKey" {
				machineNodeControlClients.Delete(client.statePath)
				if _, e := openMachineNodeControlClient(hub.StateDir, hub.Origin, hub.NodeID); e == nil {
					t.Fatal("existing state regenerated original private key")
				}
			}
			after, e := os.ReadFile(client.statePath)
			defer clear(after)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("missing material rewrote original state")
			}
			if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("lost original material was replaced")
			}
		})
	}
}

func TestNativeNodeMultiHubSelectionPreservesIndependentScopes(t *testing.T) {
	a, b := newNativeNodeFixture(t), newNativeNodeFixture(t)
	root := privateLocalNodeRoot(t)
	path := filepath.Join(root, "SYNTHETIC-hubs.json")
	config := machineHubConfigFile{Version: 1, Hubs: []machineHubConfig{
		{HubID: a.metadata.HubID, NodeID: "SYNTHETIC-node", HubConnectionFile: a.file, HubDialAddress: "127.0.0.1:443"},
		{HubID: b.metadata.HubID, NodeID: "SYNTHETIC-node", HubConnectionFile: b.file, HubDialAddress: "[::1]:8443"},
	}}
	write := func(c machineHubConfigFile) {
		t.Helper()
		if err := os.WriteFile(path, mustJSON(c), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(config)
	entries, err := loadMachineHubConfig(path)
	if err != nil || len(entries) != 2 || entries[0].ControlURL != a.d.Claims.Origin || entries[1].ControlURL != b.d.Claims.Origin || machineHubStateDir(root, entries[0]) == machineHubStateDir(root, entries[1]) {
		t.Fatal("native registry mixed scopes", err)
	}
	for _, kind := range []string{"origin", "hub", "PQ", "DNS"} {
		changed := machineHubConfigFile{Version: 1, Hubs: append([]machineHubConfig(nil), config.Hubs...)}
		switch kind {
		case "origin":
			changed.Hubs[0].ControlURL = b.d.Claims.Origin
		case "hub":
			changed.Hubs[0].HubID = b.metadata.HubID
		case "PQ":
			changed.Hubs[0].PQTLSConfig = "SYNTHETIC-must-not-open"
		case "DNS":
			changed.Hubs[0].HubDialAddress = "SYNTHETIC.invalid:443"
		}
		write(changed)
		if _, err := loadMachineHubConfig(path); err == nil {
			t.Fatal("native registry accepted conflicting", kind)
		}
	}
}
