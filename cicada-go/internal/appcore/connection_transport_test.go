package appcore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// This fixture uses the production numeric-dial TLS client and real PQ packets
// over a local TLS socket. The account authority is the synthetic actor above;
// it does not establish real Hub Guard or physical Windows acceptance.
type appTLSFixture struct {
	actor      *activationActorFixture
	descriptor hubtransport.Descriptor
	ca         *x509.Certificate
	caKey      *ecdsa.PrivateKey
	leaf       tls.Certificate
	mu         sync.Mutex
	gets       atomic.Int32
	wrongHub   atomic.Bool
}

func newAppTLSFixture(t *testing.T) *appTLSFixture {
	t.Helper()
	f := &appTLSFixture{actor: newActivationActorFixture(t)}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC APP TEST CA ONLY"},
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.caKey = key
	u, _ := url.Parse(f.actor.material.Origin)
	f.leaf = f.makeLeaf(t, u.Hostname(), f.ca.NotBefore, f.ca.NotAfter)
	leaf, err := x509.ParseCertificate(f.leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.descriptor, err = hubtransport.SignDescriptor(f.actor.hubKey, hubtransport.Claims{
		Format: hubtransport.DescriptorFormat, Version: hubtransport.Version, Origin: f.actor.material.Origin,
		Hub: f.actor.hub, HubFingerprint: f.actor.material.HubFingerprint, NodeControl: node.Public(), NodeControlKeyVersion: 1,
		TransportEpoch: 1, ServerName: u.Hostname(), RootCertificateDER: f.ca.Raw, ServerSPKISHA256: hex.EncodeToString(pin[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *appTLSFixture) makeLeaf(t *testing.T, name string, before, after time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC APP TEST LEAF ONLY"},
		DNSNames: []string{name}, NotBefore: before, NotAfter: after, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *appTLSFixture) serve(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || req.TLS.Version < tls.VersionTLS13 || "https://"+req.Host != f.descriptor.Claims.Origin {
			t.Error("App request lost verified TLS or its original logical origin")
		}
		if req.Method == http.MethodGet {
			f.gets.Add(1)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.wrongHub.Load() && req.URL.Path == "/v2/client/identity" {
			wrong := f.actor.hub
			wrong.HubID = "hub_SYNTHETIC_WRONG_LIVE_IDENTITY"
			_ = json.NewEncoder(w).Encode(wrong)
			return
		}
		response, err := f.actor.Do(req)
		if err != nil {
			// Even under verified TLS, an HTTP error is not an authenticated
			// application receipt and cannot settle an uncertain PQ request.
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "SYNTHETIC UNAUTHENTICATED HTTP ERROR ONLY")
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (f *appTLSFixture) bootstrap(t *testing.T, descriptor hubtransport.Descriptor) string {
	t.Helper()
	code, err := wire.EncodeActivationCode(f.actor.material)
	if err != nil {
		t.Fatal(err)
	}
	text, err := hubtransport.EncodeBootstrap(descriptor, code)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func (f *appTLSFixture) controller(t *testing.T, root string) (*nativeController, *connectionHTTPProbe) {
	t.Helper()
	legacy := new(connectionHTTPProbe)
	controller, err := NewController(Config{HTTP: legacy, Now: func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.actor.now
	}, OpenVault: fixtureVaultOpener(root, "synthetic vault passphrase"), DiscoverVaults: NewProfileDiscovery(root)})
	if err != nil {
		t.Fatal(err)
	}
	c := controller.(*nativeController)
	f.mu.Lock()
	f.actor.beforePost = func(operation string, packet []byte) {
		raw, _, found, err := c.vault.LoadState(appStateNamespace)
		defer clear(raw)
		if err != nil || !found {
			t.Error("HTTP preceded durable App state")
			return
		}
		state, err := decodeDurableState(raw)
		if err != nil || state.Transport == nil || state.Transport.DialAddress != c.connectionAddress() {
			t.Error("HTTP preceded retained transport persistence")
			return
		}
		pending := state.Pending
		if operation == wire.OperationActivationStatus {
			pending = state.Recovery
		}
		if pending == nil || !bytes.Equal(pending.Request, packet) {
			t.Error("HTTP preceded exact PQ packet persistence")
		}
	}
	f.mu.Unlock()
	t.Cleanup(func() { _ = c.Close() })
	return c, legacy
}

func TestAppDirectTLSConnectPersistsPublicTrustWithoutGrantingAuthority(t *testing.T) {
	f := newAppTLSFixture(t)
	s := f.serve(t, f.leaf)
	root := filepath.Join(t.TempDir(), "vaults")
	c, legacy := f.controller(t, root)
	code := f.bootstrap(t, f.descriptor)
	action := Action{Kind: ActionConnect, HubAddress: s.Listener.Addr().String(), BootstrapCode: code}
	if err := c.Dispatch(context.Background(), action); err != nil {
		t.Fatal(err)
	}
	view := c.Snapshot()
	if !view.Hub.Verified || view.Hub.TransportState != HubTransportVerified || view.Hub.Address != action.HubAddress ||
		view.Hub.Origin != f.actor.material.Origin || view.Management != ManagementUnavailable || view.Authorization.Confirmed || legacy.calls != 0 {
		t.Fatal("verified connection changed identity scope, fell back or granted authority")
	}
	stateBytes, _, found, err := c.vault.LoadState(appStateNamespace)
	defer clear(stateBytes)
	if err != nil || !found {
		t.Fatal("missing encrypted local profile")
	}
	state, err := decodeDurableState(stateBytes)
	if err != nil || state.Transport == nil || !reflect.DeepEqual(state.Transport.Descriptor, f.descriptor) || state.Transport.DialAddress != action.HubAddress {
		t.Fatal("public transport record not retained in original encrypted state")
	}
	public, _ := json.Marshal(state.Transport)
	if bytes.Contains(public, []byte(f.actor.material.Code)) || bytes.Contains(public, []byte("activation_code")) ||
		strings.Contains(fmt.Sprintf("%+v %#v", action, action), code) {
		t.Fatal("bootstrap secret escaped its reviewed boundary")
	}
	snapshot, _ := json.Marshal(view)
	if bytes.Contains(snapshot, []byte(f.actor.material.Code)) || bytes.Contains(snapshot, []byte(code)) {
		t.Fatal("bootstrap leaked into snapshot")
	}
	path, _ := scopeVaultPath(root, cardScope(c.connection))
	rawVault, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawVault, []byte(f.actor.material.Code)) || bytes.Contains(rawVault, public) {
		t.Fatal("transport or activation saved as plaintext")
	}
	f.mu.Lock()
	postCount := len(f.actor.posts)
	f.mu.Unlock()
	if postCount != 0 || f.gets.Load() != 2 {
		t.Fatal("first connect sent business traffic before consent")
	}
}

func TestAppDirectTLSRejectsUntrustedTransportAndLiveHub(t *testing.T) {
	f := newAppTLSFixture(t)
	other := newAppTLSFixture(t)
	for _, mode := range []string{"wrong-root", "wrong-san", "wrong-spki", "expired-leaf", "wrong-live-hub"} {
		t.Run(mode, func(t *testing.T) {
			d := cloneLocalTransport(&localTransportRecord{Descriptor: f.descriptor}).Descriptor
			cert := f.leaf
			switch mode {
			case "wrong-root":
				d.Claims.RootCertificateDER = other.ca.Raw
			case "wrong-spki":
				d.Claims.ServerSPKISHA256 = strings.Repeat("0", 64)
			case "wrong-san":
				cert = f.makeLeaf(t, "wrong.synthetic.invalid", f.ca.NotBefore, f.ca.NotAfter)
			case "expired-leaf":
				cert = f.makeLeaf(t, d.Claims.ServerName, f.ca.NotBefore, f.ca.NotBefore.Add(time.Hour))
			}
			if mode == "wrong-san" || mode == "expired-leaf" {
				leaf, _ := x509.ParseCertificate(cert.Certificate[0])
				pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				d.Claims.ServerSPKISHA256 = hex.EncodeToString(pin[:])
			}
			var err error
			d, err = hubtransport.SignDescriptor(f.actor.hubKey, d.Claims)
			if err != nil {
				t.Fatal(err)
			}
			f.wrongHub.Store(mode == "wrong-live-hub")
			before := f.gets.Load()
			s := f.serve(t, cert)
			c, legacy := f.controller(t, filepath.Join(t.TempDir(), "vaults"))
			err = c.Dispatch(context.Background(), Action{Kind: ActionConnect, HubAddress: s.Listener.Addr().String(), BootstrapCode: f.bootstrap(t, d)})
			view := c.Snapshot()
			if err == nil || view.Hub.Verified || view.Hub.TransportState != HubTransportFailed || c.vault != nil || legacy.calls != 0 {
				t.Fatal("untrusted transport established profile or fallback")
			}
			if mode != "wrong-live-hub" && f.gets.Load() != before {
				t.Fatal("TLS rejection happened after HTTP")
			}
			f.mu.Lock()
			posts := len(f.actor.posts)
			f.mu.Unlock()
			if posts != 0 {
				t.Fatal("business secret sent to untrusted Hub")
			}
		})
	}
}

func TestAppDirectInputRejectsBeforeHTTP(t *testing.T) {
	f := newAppTLSFixture(t)
	code := f.bootstrap(t, f.descriptor)
	for _, action := range []Action{
		{Kind: ActionConnect, BootstrapCode: code},
		{Kind: ActionConnect, HubAddress: "127.0.0.1:8443"},
		{Kind: ActionConnect, HubAddress: "hub.synthetic.invalid:8443", BootstrapCode: code},
		{Kind: ActionConnect, HubAddress: "127.0.0.1:8443", BootstrapCode: "SYNTHETIC_INVALID_SECRET"},
		{Kind: ActionConnect, HubAddress: "127.0.0.1:8443", BootstrapCode: code, ActivationCode: "SYNTHETIC_LEGACY"},
	} {
		c, legacy := f.controller(t, t.TempDir())
		if err := c.Dispatch(context.Background(), action); err == nil || legacy.calls != 0 || c.httpClient() != nil {
			t.Fatal("invalid direct input reached HTTP")
		}
		if strings.Contains(c.Snapshot().Hub.Address, "SECRET") {
			t.Fatal("invalid address retained in public view")
		}
	}
}

func TestAppDirectRestartAndLocatorChangePreserveOwnerAndExactPending(t *testing.T) {
	f := newAppTLSFixture(t)
	s := f.serve(t, f.leaf)
	root := filepath.Join(t.TempDir(), "vaults")
	c, legacy := f.controller(t, root)
	ctx := context.Background()
	address := s.Listener.Addr().String()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, HubAddress: address, BootstrapCode: f.bootstrap(t, f.descriptor)}); err != nil {
		t.Fatal(err)
	}
	imported := syntheticOwnerImport(t)
	defer clear(imported.KEMPrivatePKCS8)
	defer clear(imported.SigningPrivatePKCS8)
	if err := c.Dispatch(ctx, Action{Kind: ActionImportOwner, OwnerImport: &imported}); err != nil {
		t.Fatal(err)
	}
	owner := c.owner.Public().ID
	scope := c.vault.Scope()
	f.mu.Lock()
	f.actor.lost = wire.OperationActivationPrepare
	f.mu.Unlock()
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err == nil {
		t.Fatal("unauthenticated HTTP error reported activation success")
	}
	original := bytes.Clone(c.state.Pending.Request)
	defer clear(original)
	if c.state.Pending == nil || len(c.state.Pending.Response) != 0 || c.Snapshot().Management != ManagementUnavailable {
		t.Fatal("uncertain pending request was discarded or authorized")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	path, _ := scopeVaultPath(root, scope)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, resumedLegacy := f.controller(t, root)
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	profiles := c.Snapshot().Profiles
	if len(profiles) != 1 || !profiles[0].Direct {
		t.Fatal("direct profile not discovered")
	}
	id := profiles[0].ID
	// An invalid address must not be echoed or stored. A wrong TLS server
	// must not consume or modify the original encrypted uncertain packet.
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: id, HubAddress: "SYNTHETIC_PRIVATE_INPUT"}); err == nil || c.Snapshot().Hub.Address != "" {
		t.Fatal("invalid locator accepted or exposed")
	}
	other := newAppTLSFixture(t)
	wrong := other.serve(t, other.leaf)
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: id, HubAddress: wrong.Listener.Addr().String()}); err == nil || c.Snapshot().Hub.Verified {
		t.Fatal("wrong TLS locator resumed profile")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed address edit changed encrypted profile")
	}
	if !bytes.Equal(c.state.Pending.Request, original) || c.state.Transport.DialAddress != address {
		t.Fatal("failed locator edit changed pending or saved address")
	}
	second := f.serve(t, f.leaf)
	newAddress := second.Listener.Addr().String()
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: id, HubAddress: newAddress}); err != nil {
		t.Fatal(err)
	}
	if c.vault.Scope() != scope || c.owner.Public().ID != owner || c.connection.Origin != scope.Origin || c.state.Transport.DialAddress != newAddress ||
		c.Snapshot().Hub.TransportState != HubTransportVerified || legacy.calls != 0 || resumedLegacy.calls != 0 {
		t.Fatal("locator change replaced identity, scope or trust")
	}
	f.mu.Lock()
	posts := make([][]byte, len(f.actor.posts))
	copy(posts, f.actor.posts)
	f.mu.Unlock()
	if len(posts) < 2 || !bytes.Equal(posts[0], original) || !bytes.Equal(posts[1], original) {
		t.Fatalf("restart did not resend exact original packet (posts=%d)", len(posts))
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: "synthetic secure meadow 42!"}); err != nil {
		t.Fatal(err)
	}
	if c.owner.Public().ID != owner || c.Snapshot().Management != ManagementUnavailable || c.Snapshot().Authorization.Confirmed {
		t.Fatal("finite activation changed Owner or bypassed login")
	}
}

func TestAppDirectSavedProfileDoesNotNeedExpiredBootstrap(t *testing.T) {
	f := newAppTLSFixture(t)
	s := f.serve(t, f.leaf)
	root := filepath.Join(t.TempDir(), "vaults")
	c, _ := f.controller(t, root)
	ctx := context.Background()
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, HubAddress: s.Listener.Addr().String(), BootstrapCode: f.bootstrap(t, f.descriptor)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	owner := c.owner.Public().ID
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.actor.now = f.actor.now.Add(48 * time.Hour)
	f.mu.Unlock()
	c, legacy := f.controller(t, root)
	if err := c.Dispatch(ctx, Action{Kind: ActionDiscoverProfiles}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionResumeProfile, ProfileID: c.Snapshot().Profiles[0].ID}); err != nil {
		t.Fatal(err)
	}
	if !c.Snapshot().Hub.Verified || c.owner.Public().ID != owner || legacy.calls != 0 {
		t.Fatal("expired installer material prevented safe saved-profile unlock")
	}
}

func TestAppTransportReplacementRejectsImplicitRotation(t *testing.T) {
	f := newAppTLSFixture(t)
	card := HubConnectionCard{Origin: f.actor.material.Origin, HubID: f.actor.material.HubID, HubFingerprint: f.actor.material.HubFingerprint}
	old := &localTransportRecord{Format: localTransportFormat, Version: 1, Descriptor: f.descriptor, DialAddress: "127.0.0.1:8443"}
	for _, mode := range []string{"locator", "resign", "higher-epoch", "lower-epoch", "new-ca", "new-spki", "new-node", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			next := cloneLocalTransport(old)
			switch mode {
			case "locator":
				next.DialAddress = "[::1]:9443"
			case "higher-epoch":
				next.Descriptor.Claims.TransportEpoch++
			case "lower-epoch":
				next.Descriptor.Claims.TransportEpoch = 0
			case "new-ca":
				next.Descriptor.Claims.RootCertificateDER = newAppTLSFixture(t).ca.Raw
			case "new-spki":
				next.Descriptor.Claims.ServerSPKISHA256 = strings.Repeat("0", 64)
			case "new-node":
				node, _ := e2ee.NewIdentity()
				next.Descriptor.Claims.NodeControl = node.Public()
			case "legacy":
				next = nil
			}
			if next != nil && mode != "lower-epoch" {
				var err error
				next.Descriptor, err = hubtransport.SignDescriptor(f.actor.hubKey, next.Descriptor.Claims)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := validateLocalTransportReplacement(old, next, card)
			allowed := mode == "locator" || mode == "resign"
			if (err == nil) != allowed {
				t.Fatal("implicit transport trust replacement policy changed")
			}
		})
	}
}

func TestAppDirectReconnectCannotReplaceSavedTrustAtHigherEpoch(t *testing.T) {
	f := newAppTLSFixture(t)
	s := f.serve(t, f.leaf)
	root := filepath.Join(t.TempDir(), "vaults")
	c, legacy := f.controller(t, root)
	ctx := context.Background()
	action := Action{Kind: ActionConnect, HubAddress: s.Listener.Addr().String(), BootstrapCode: f.bootstrap(t, f.descriptor)}
	if err := c.Dispatch(ctx, action); err != nil {
		t.Fatal(err)
	}
	scope := c.vault.Scope()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	path, _ := scopeVaultPath(root, scope)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneLocalTransport(&localTransportRecord{Descriptor: f.descriptor}).Descriptor
	next.Claims.TransportEpoch++
	next, err = hubtransport.SignDescriptor(f.actor.hubKey, next.Claims)
	if err != nil {
		t.Fatal(err)
	}
	action.BootstrapCode = f.bootstrap(t, next)
	c, trap := f.controller(t, root)
	if err := c.Dispatch(ctx, action); err == nil || c.Snapshot().ErrorCode != "HUB_TRANSPORT_SCOPE_MISMATCH" || c.Snapshot().Hub.Verified {
		t.Fatal("new bootstrap implicitly rotated saved transport trust")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || legacy.calls != 0 || trap.calls != 0 {
		t.Fatal("rejected transport replacement altered saved profile or fell back")
	}
}

func TestAppDirectFactoryFailureClosesReturnedPoolWithoutFallback(t *testing.T) {
	f := newAppTLSFixture(t)
	legacy, direct := new(connectionHTTPProbe), new(connectionHTTPProbe)
	controller, err := NewController(Config{HTTP: legacy, DirectHTTPFactory: func(hubtransport.Descriptor, string, time.Duration) (HTTPDoer, error) {
		return direct, errors.New("SYNTHETIC PRIVATE FACTORY ERROR")
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	if err := controller.Dispatch(context.Background(), Action{Kind: ActionConnect, HubAddress: "127.0.0.1:8443", BootstrapCode: f.bootstrap(t, f.descriptor)}); err == nil ||
		legacy.calls != 0 || direct.calls != 0 || direct.closed != 1 || controller.Snapshot().ErrorCode != "HUB_TLS_UNVERIFIED" {
		t.Fatal("failed direct factory leaked resources or fell back")
	}
}
