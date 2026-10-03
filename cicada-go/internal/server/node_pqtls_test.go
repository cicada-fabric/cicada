package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// Synthetic context tests verify request Guard only. Real TLS is separately
// exercised by tagged product runtime tests; these do not prove a handshake.
type syntheticPQStateConn struct {
	net.Conn
	state pqtls.State
}

func TestNetworkSessionTransportDerivesNodeAcrossIndependentAccessEpochs(t *testing.T) {
	service, db, _ := newRelayNodeTestService(t)
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	binding := bindRelayNodeTestCredential(t, db, "network-node", digest)
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterOwnerApprovalKeyLocal("owner", ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	network, err := db.CreateNetwork(store.Network{ID: "synthetic-pq-network", HubID: binding.HubID, Name: "synthetic PQ authority", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	invite := "synthetic-pq-network-invitation-test-only"
	grants := []string{"directory.discover", "directory.publish"}
	if err := db.IssueNetworkInvitation(network.ID, "owner", "owner", invite, time.Now().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	proof, err := ownerKey.SignOwnerNetworkJoinGrant("owner", binding.HubID, network.ID, binding.NodeID, "native-network-pq", store.NetworkInvitationDigest(invite), ownerKey.Public().ID, grants, true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	joined, err := service.JoinNetworkForNodeCredential(token, fabric.NetworkJoinInput{NetworkID: network.ID, InvitationToken: invite, OwnerJoinProof: string(proof), Harness: "codex", NativeSessionID: "native-network-pq", EndpointName: "synthetic-network-pq"})
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	pin[0] = 0xcd
	identity := nodetransport.Identity{Kind: "node", HubID: binding.HubID, NodeID: binding.NodeID, TLSEpoch: 29, DNSName: "network-node.synthetic.invalid"}
	cfg := &nodetransport.Config{Peers: []nodetransport.Approval{{Identity: identity, PinKind: "certificate-sha256", PinSHA256: hex.EncodeToString(pin[:]), OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.ID, BindingVersion: binding.Version, CredentialVersion: binding.NodeCredentialVersion}}}
	state := pqtls.State{VerifiedNotBefore: time.Now().Add(-time.Minute), VerifiedNotAfter: time.Now().Add(time.Hour), TLSVersion: "TLSv1.3", Group: "MLKEM768", CipherSuite: "TLS_AES_256_GCM_SHA384", PeerSignature: "ML-DSA-65", ALPN: "http/1.1", HostnameVerified: true, Peer: identity.TLSIdentity(), CertificateSHA256: pin}
	ctx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: state})
	handler := WithNodePQTransport(NewFabricHandler(service, ""), service, cfg, true)
	call := func(token string, stateCtx context.Context) int {
		r := httptest.NewRequest(http.MethodGet, "/v2/fabric/networks/"+network.ID+"/whoami", nil).WithContext(stateCtx)
		r.Header.Set("Authorization", "Cicada-Network-Session "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if derived, err := service.NodeForTransportAuthorization("Cicada-Network-Session "+joined.SessionToken, "", network.ID); err != nil || derived.NodeID != binding.NodeID {
		t.Fatal("current Network session failed independent Node derivation")
	}
	if code := call(joined.SessionToken, ctx); code != http.StatusUnauthorized {
		t.Fatalf("operator-only Network TLS authorization status %d", code)
	}
	renewed, err := service.RenewNetworkForNodeCredential(token, fabric.NetworkRenewInput{NetworkID: network.ID, EndpointID: joined.Endpoint.ID, Harness: "codex", NativeSessionID: "native-network-pq"})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.BindingEpoch == joined.BindingEpoch {
		t.Fatal("access epoch did not advance")
	}
	if derived, err := service.NodeForTransportAuthorization("Cicada-Network-Session "+renewed.SessionToken, "", network.ID); err != nil || derived.NodeID != binding.NodeID {
		t.Fatal("independent access epoch invalidated Node derivation")
	}
	if code := call(renewed.SessionToken, ctx); code != http.StatusUnauthorized {
		t.Fatal("operator coordinates manufactured current TLS authority")
	}
	for _, interval := range []struct {
		name          string
		before, after time.Time
	}{
		{"missing", time.Time{}, time.Time{}},
		{"expired", time.Now().Add(-time.Hour), time.Now().Add(-time.Second)},
		{"future", time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
		{"inverted", time.Now().Add(time.Hour), time.Now().Add(-time.Hour)},
	} {
		t.Run(interval.name, func(t *testing.T) {
			invalid := state
			invalid.VerifiedNotBefore, invalid.VerifiedNotAfter = interval.before, interval.after
			invalidCtx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: invalid})
			if code := call(renewed.SessionToken, invalidCtx); code != http.StatusUnauthorized {
				t.Fatalf("invalid interval allowed buffered request: %d", code)
			}
			checkCtx := context.WithValue(invalidCtx, nodeTransportCheckKey{}, nodeTransportCheck(func() bool { return true }))
			if nodePQTransportValidityCurrent(checkCtx) {
				t.Fatal("event-write validity fence trusted an invalid interval")
			}
		})
	}
	state.Peer.NodeID = "different-node"
	foreignCtx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: state})
	if code := call(renewed.SessionToken, foreignCtx); code != http.StatusUnauthorized {
		t.Fatal("foreign certificate borrowed Network session")
	}
}

func (c syntheticPQStateConn) PQTLSState() pqtls.State { return c.state }

func TestStrictNodeTransportKeepsClientBootstrapAndBlocksOrdinaryPeerRoutes(t *testing.T) {
	service, _, _ := newRelayNodeTestService(t)
	inner := NewFabricHandler(service, "synthetic-manager-token")
	front := WithNodePQTransport(inner, service, nil, false)
	for _, path := range []string{"/v2/relay/nodes/node/events", "/v2/fabric/node/join", "/v2/fabric/join", "/v2/fabric/whoami", "/v2/fabric/node/networks/join", "/v2/fabric/networks/network/directory", "/v2/artifacts/a", "/v2/node/control/rpc", "/v2/node/control/key-upgrade"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("Authorization", "Bearer synthetic-manager-token")
			w := httptest.NewRecorder()
			front.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("unenforced ordinary route: %d", w.Code)
			}
		})
	}
	for _, path := range []string{"/healthz", "/v2/client/capabilities", "/v2/client/identity", "/v2/node/identity", "/v2/nodes/device-code", "/v2/node/device-code/pending/status"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			a, b := httptest.NewRecorder(), httptest.NewRecorder()
			inner.ServeHTTP(a, r)
			front.ServeHTTP(b, r)
			if a.Code != b.Code || a.Body.String() != b.Body.String() {
				t.Fatal("Client/bootstrap boundary changed")
			}
		})
	}
}

func TestNodeCertificateCannotBorrowOtherNodeAndCurrentAuthorityFencesReuse(t *testing.T) {
	service, db, group := newRelayNodeTestService(t)
	// Reuse only the synthetic test authority, never deployment material.
	tokenA, digestA, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindingA := bindRelayNodeTestCredential(t, db, "node-a", digestA)
	tokenB, digestB, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, db, "node-b", digestB)
	var pin [32]byte
	pin[0] = 0xab
	identity := nodetransport.Identity{Kind: "node", HubID: bindingA.HubID, NodeID: "node-a", TLSEpoch: 17, DNSName: "node-a.synthetic.invalid"}
	approval := nodetransport.Approval{Identity: identity, PinKind: "certificate-sha256", PinSHA256: hex.EncodeToString(pin[:]), OwnerID: bindingA.OwnerID, OwnerKeyID: bindingA.OwnerKeyID, BindingID: bindingA.ID, BindingVersion: bindingA.Version, CredentialVersion: bindingA.NodeCredentialVersion}
	cfg := &nodetransport.Config{Peers: []nodetransport.Approval{approval}}
	state := pqtls.State{VerifiedNotBefore: time.Now().Add(-time.Minute), VerifiedNotAfter: time.Now().Add(time.Hour), TLSVersion: "TLSv1.3", Group: "MLKEM768", CipherSuite: "TLS_AES_256_GCM_SHA384", PeerSignature: "ML-DSA-65", ALPN: "http/1.1", HostnameVerified: true, Peer: identity.TLSIdentity(), CertificateSHA256: pin}
	ctx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: state})
	handler := WithNodePQTransport(NewFabricHandler(service, ""), service, cfg, true)
	call := func(path, authorization string, ctx context.Context) int {
		r := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := call("/v2/relay/nodes/node-a/events", "CicadaNode "+tokenB, ctx); code != http.StatusUnauthorized {
		t.Fatalf("borrowed bearer status %d", code)
	}
	if code := call("/v2/relay/nodes/node-a/claim", "CicadaNode "+tokenA, ctx); code != http.StatusUnauthorized {
		t.Fatal("operator-only TLS epoch accepted without Store authority")
	}
	joined, err := service.JoinForNodeCredential(tokenB, fabric.JoinInput{GroupID: group.ID, Harness: "codex", NativeSessionID: "native-b"})
	if err != nil {
		t.Fatal(err)
	}
	if code := call("/v2/fabric/whoami", "CicadaSession "+joined.SessionToken, ctx); code != http.StatusUnauthorized {
		t.Fatal("borrowed Session accepted by another Node certificate")
	}
	oldState := state
	oldState.Peer.BindingEpoch = 16
	oldCtx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: oldState})
	if code := call("/v2/relay/nodes/node-a/claim", "CicadaNode "+tokenA, oldCtx); code != http.StatusUnauthorized {
		t.Fatal("old transport epoch accepted")
	}
	if _, err := db.RevokeNodeDeviceBinding(bindingA.OwnerID, bindingA.ID, bindingA.Version); err != nil {
		t.Fatal(err)
	}
	if code := call("/v2/relay/nodes/node-a/claim", "CicadaNode "+tokenA, ctx); code != http.StatusUnauthorized {
		t.Fatal("revoked binding accepted on reused TLS context")
	}
}

// These are synthetic verified-Store snapshot checks, not a native handshake
// or a Store issuance test. Production snapshots come from Store's live read.
func TestNodePQTransportActiveExactAuthorityAndQueuedEventFence(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	var certificate, spki [32]byte
	certificate[0] = 1
	spki[0] = 2
	hash := strings.Repeat("a", 64)
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 1, RequestID: "synthetic-request", HubID: "synthetic-hub", NodeID: "synthetic-node", OwnerID: "synthetic-owner", OwnerKeyID: "synthetic-owner-key", OwnerKeyVersion: 1, ClientDeviceID: "synthetic-device", ClientDeviceVersion: 1, OwnerBindingID: "synthetic-binding", OwnerBindingVersion: 1, CredentialDigest: "synthetic-digest", CredentialVersion: 1, NodeControlKeyID: "synthetic-node-control", NodeControlKeyVersion: 1, NodeControlKeyEpoch: 1, NodeControlBindingVersion: 1, HubControlKeyID: "synthetic-hub-control", HubControlKeyVersion: 1, CSRDERHash: hash, SPKIDERHash: hex.EncodeToString(spki[:]), IssuerSPKIHash: hash, IssuerDERHash: hash, RootDERHash: hash, IssuerGeneration: "synthetic-generation", Role: "node", DNSName: "node.synthetic.invalid", Serial: "00000000000000000000000000000001", TLSEpoch: 1, NotBefore: at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(time.Hour).Format(time.RFC3339), HubSPKIHash: hash, HubTrustAnchorDERHash: hash, HubPQOrigin: "https://hub.synthetic.invalid", ApplicationOrigin: "https://hub.synthetic.invalid", ApplicationProtocol: e2ee.NodeTLSApplicationProtocol, PQProfile: e2ee.NodeTLSPQProfile, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), Nonce: hash}
	a := &store.NodeTLSAuthoritySnapshot{State: store.NodeTLSActive, RowVersion: 5, Claims: c, Grant: []byte("synthetic verified proof placeholder"), InstallAck: []byte("synthetic verified ACK placeholder"), Activation: []byte("synthetic verified activation placeholder"), LeafCertificatePEM: []byte("synthetic verified leaf placeholder"), LeafDERHash: hex.EncodeToString(certificate[:])}
	b := &store.NodeTransportBinding{HubID: c.HubID, NodeID: c.NodeID, OwnerID: c.OwnerID, OwnerKeyID: c.OwnerKeyID, BindingID: c.OwnerBindingID, BindingVersion: 1, CredentialVersion: 1, TLSAuthority: a}
	s := pqtls.State{VerifiedNotBefore: at.Add(-time.Minute), VerifiedNotAfter: at.Add(time.Hour), Peer: pqtls.Identity{Kind: "node", HubID: c.HubID, NodeID: c.NodeID, BindingEpoch: c.TLSEpoch, DNSName: c.DNSName}, CertificateSHA256: certificate, SPKISHA256: spki}
	if !nodeTLSAuthorityMatches(b, s, at) {
		t.Fatal("exact current ACTIVE tuple rejected")
	}
	for _, name := range []string{"same-SPKI-other-DER", "same-DER-other-SPKI", "old-epoch", "DNS", "revoked", "missing"} {
		t.Run(name, func(t *testing.T) {
			bad := s
			copyBinding := *b
			copyAuthority := *a
			copyBinding.TLSAuthority = &copyAuthority
			switch name {
			case "same-SPKI-other-DER":
				bad.CertificateSHA256[1] = 3
			case "same-DER-other-SPKI":
				bad.SPKISHA256[1] = 3
			case "old-epoch":
				bad.Peer.BindingEpoch = 2
			case "DNS":
				bad.Peer.DNSName = "other.synthetic.invalid"
			case "revoked":
				copyAuthority.State = store.NodeTLSRevoked
			case "missing":
				copyBinding.TLSAuthority = nil
			}
			if nodeTLSAuthorityMatches(&copyBinding, bad, at) {
				t.Fatal("noncurrent exact authority accepted")
			}
		})
	}
	ctx := pqtls.HTTPConnContext(context.Background(), syntheticPQStateConn{state: s})
	checks := 0
	ctx = context.WithValue(ctx, nodeTransportCheckKey{}, nodeTransportCheck(func() bool { checks++; return nodeTLSAuthorityMatches(b, s, time.Now()) }))
	if !nodePQTransportValidityCurrent(ctx) || checks != 1 {
		t.Fatal("queued event omitted current authority check")
	}
	a.State = store.NodeTLSRevoked // Revocation after enqueue, before event-write check.
	if nodePQTransportValidityCurrent(ctx) || checks != 2 {
		t.Fatal("queued event reused time-only authorization")
	}
}

// The native gate runs a real Hub listener and Node client in distinct child
// processes. All signing keys/CA state are synthetic and disappear with TempDir.
type nodeTLSProcessFixture struct {
	DBPath, RequestID, NodeToken          string
	HubConfig, NodeConfig, OtherDERConfig nodetransport.Config
}

func nodeTLSProcessNative(t *testing.T) bool {
	t.Helper()
	if e := pqtls.Available(); e != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" || !errors.Is(e, pqtls.ErrUnavailable) {
			t.Fatal("requested native provider unavailable")
		}
		return false
	}
	return true
}
func nodeTLSProcessWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal("private disposable fixture write failed")
	}
}
func nodeTLSProcessCA(t *testing.T, dir string) ([]byte, []byte, []byte, time.Time) {
	t.Helper()
	executable := os.Getenv("PQTLS_TEST_OPENSSL")
	if executable == "" || !filepath.IsAbs(executable) {
		t.Fatal("explicit official OpenSSL fixture executable required")
	}
	cli := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
		if _, e := cmd.CombinedOutput(); e != nil {
			t.Fatal("synthetic official CA command failed; output suppressed")
		}
	}
	cli("req", "-new", "-x509", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=CICADA SYNTHETIC TWO PROCESS ROOT ONLY", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
	cli("req", "-new", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "issuer.key", "-out", "issuer.csr", "-subj", "/CN=CICADA SYNTHETIC TWO PROCESS ISSUER ONLY")
	nodeTLSProcessWrite(t, filepath.Join(dir, "issuer.ext"), []byte("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"))
	cli("x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "issuer.pem", "-days", "1", "-extfile", "issuer.ext")
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal("read disposable CA fixture")
		}
		return b
	}
	root := read("root.pem")
	return append(read("issuer.pem"), root...), root, read("issuer.key"), time.Now().UTC().Truncate(time.Second)
}
func nodeTLSProcessBuild(t *testing.T, dir string) nodeTLSProcessFixture {
	t.Helper()
	dbPath := filepath.Join(dir, "hub.sqlite3")
	db, e := store.New(dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.CreatePrincipal(store.Principal{ID: "synthetic-owner", Kind: store.PrincipalKindHuman, OwnerID: "synthetic-owner", TrustDomainID: "synthetic-domain", Name: "synthetic-owner", Status: store.PrincipalStatusActive}); e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	node, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	hub, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	device, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	registered, e := db.RegisterOwnerApprovalKeyLocal("synthetic-owner", owner.Public())
	if e != nil {
		t.Fatal(e)
	}
	hubID, e := db.GetClientHubID()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	deviceGrant, e := owner.SignOwnerDeviceGrant("synthetic-owner", "synthetic-device", device.Public(), hubID, e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	client, e := db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: "synthetic-owner", OwnerKeyID: registered.KeyID, DeviceID: "synthetic-device", DevicePublic: device.Public(), OwnerDeviceGrant: deviceGrant})
	if e != nil {
		t.Fatal(e)
	}
	token, digest, e := fabric.NewNodeCredential()
	if e != nil {
		t.Fatal(e)
	}
	fingerprint := func(p e2ee.PublicIdentity) string {
		h := sha256.New()
		h.Write([]byte("cicada/node-control/key-fingerprint/v1\x00"))
		h.Write(p.KEMPublic)
		h.Write([]byte{0})
		h.Write(p.SigningPublic)
		return hex.EncodeToString(h.Sum(nil))
	}
	code := sha256.Sum256([]byte("synthetic native TLS process owner approval code"))
	codeDigest := hex.EncodeToString(code[:])
	candidate, e := db.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{Mode: store.NodeControlPairingInitial, NodeID: "synthetic-node", NodeName: "synthetic-node", CredentialDigest: digest, CodeDigest: codeDigest, NodePublicIdentity: node.Public(), NodeFingerprint: fingerprint(node.Public()), ProofPacket: []byte("synthetic application possession fixture"), HubPublicIdentity: hub.Public(), HubKeyVersion: 1, HubFingerprint: fingerprint(hub.Public()), ExpiresAt: now.Add(10 * time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	binding, e := db.ConfirmNodeControlKeyRequest("synthetic-owner", client.DeviceID, codeDigest, candidate.Version, candidate.CandidateDigest, candidate.HubNodeControlKeyID, candidate.HubNodeControlFingerprint)
	if e != nil {
		t.Fatal(e)
	}
	chain, root, issuerKey, at := nodeTLSProcessCA(t, dir)
	defer clear(issuerKey)
	issuer, issuerProfile, e := pqtls.ImportTLSIssuer(chain, issuerKey, root, "node", at)
	if e != nil {
		t.Fatal(e)
	}
	defer issuer.Destroy()
	hubIssuer, _, e := pqtls.ImportTLSIssuer(chain, issuerKey, root, "hub", at)
	if e != nil {
		t.Fatal(e)
	}
	defer hubIssuer.Destroy()
	hubTLSKey, hubCSR, e := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "hub", DNSName: "hub.synthetic.invalid"})
	if e != nil {
		t.Fatal(e)
	}
	defer hubTLSKey.Destroy()
	hubParams := pqtls.TLSLeafParameters{TLSCSRParameters: hubCSR.Parameters, NotBefore: at, NotAfter: at.Add(time.Hour), ExpectedSPKIHash: hubCSR.SPKIDERHash}
	hubParams.Serial[15] = 99
	hubLeaf, e := hubIssuer.IssueTLSLeaf(hubCSR.CSRPEM, hubParams, at)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := hubTLSKey.ExportPEM()
	if e != nil {
		t.Fatal(e)
	}
	nodeTLSProcessWrite(t, filepath.Join(dir, "hub.key"), secret)
	clear(secret)
	nodeTLSProcessWrite(t, filepath.Join(dir, "hub-chain.pem"), append(append([]byte(nil), hubLeaf.CertificatePEM...), chain...))
	nodeTLSProcessWrite(t, filepath.Join(dir, "root.pem"), root)
	stateRoot := filepath.Join(dir, "node-state")
	writerRoot := filepath.Join(dir, "writer-root")
	cryptoRoot := filepath.Join(dir, "node-crypto")
	for _, p := range []string{stateRoot, writerRoot, cryptoRoot} {
		if os.Mkdir(p, 0700) != nil {
			t.Fatal("private local roots")
		}
	}
	trust, e := nodekeys.OpenCryptoState(cryptoRoot)
	if e != nil {
		t.Fatal(e)
	}
	defer trust.Close()
	ownerFP, e := nodekeys.PeerKeyFingerprint(owner.Public())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = trust.TrustOwnerApprovalKeyLocal("synthetic-owner", owner.Public().ID, owner.Public(), ownerFP); e != nil {
		t.Fatal(e)
	}
	installer := &nodetransport.LocalTLSInstaller{StateRoot: stateRoot, WriterRoot: writerRoot, HubID: hubID, NodeID: binding.NodeID, OwnerTrust: trust, NodeControlIdentity: node, CurrentBinding: func() (nodetransport.TLSLocalBinding, error) {
		current, e := db.NodeControlKeyForCredential(digest, binding.NodeID)
		if e != nil {
			return nodetransport.TLSLocalBinding{}, e
		}
		return nodetransport.TLSLocalBinding{Control: *current, OwnerKeyVersion: uint64(registered.Version), ClientDeviceVersion: uint64(client.Version)}, nil
	}, KnownApplicationPublicKeys: func() ([][]byte, error) {
		return [][]byte{owner.Public().SigningPublic, node.Public().SigningPublic, hub.Public().SigningPublic, device.Public().SigningPublic}, nil
	}, CurrentActiveAuthority: func() (*store.NodeTLSAuthoritySnapshot, error) {
		current, e := db.CurrentNodeTransportBinding(binding.NodeID)
		if e != nil {
			return nil, e
		}
		return current.TLSAuthority, nil
	}}
	hash := func(h [32]byte) string { return hex.EncodeToString(h[:]) }
	request := nodetransport.TLSPreparationRequest{RequestID: "synthetic-two-process-tls", DNSName: "node.synthetic.invalid", HubDNSName: "hub.synthetic.invalid", HubPQOrigin: "https://hub.synthetic.invalid", ApplicationOrigin: "https://hub.synthetic.invalid", HubSPKIHash: hash(hubCSR.SPKIDERHash), HubTrustAnchorDERHash: hash(issuerProfile.TrustAnchorDERHash), IssuerGeneration: "synthetic-two-process-issuer", IssuerSPKIHash: hash(issuerProfile.SPKIDERHash), IssuerDERHash: hash(issuerProfile.CertificateDERHash), RootDERHash: hash(issuerProfile.TrustAnchorDERHash)}
	prepared, e := installer.Prepare(request, at)
	if e != nil {
		t.Fatal(e)
	}
	reservation, e := db.ReserveNodeTLSCandidate(store.NodeTLSCandidateInput{RequestID: request.RequestID, NodeID: binding.NodeID, CredentialDigest: digest, CSRPEM: prepared.CSRPEM, IssuerChainPEM: chain, TrustAnchorPEM: root, Parameters: pqtls.TLSCSRParameters{Role: "node", DNSName: request.DNSName}, Issuer: issuerProfile, IssuerGeneration: request.IssuerGeneration, NotBefore: at, NotAfter: at.Add(time.Hour), HubSPKIHash: request.HubSPKIHash, HubTrustAnchorDERHash: request.HubTrustAnchorDERHash, HubPQOrigin: request.HubPQOrigin, ApplicationOrigin: request.ApplicationOrigin, GrantIssuedAt: at, GrantExpiresAt: at.Add(time.Hour), GrantNonce: strings.Repeat("a", 64)})
	if e != nil {
		t.Fatal(e)
	}
	grant, e := e2ee.SignOwnerTLSLeafGrant(owner, reservation.Claims)
	if e != nil {
		t.Fatal(e)
	}
	action := store.NodeTLSAuthorityActionInput{RequestID: request.RequestID, NodeID: binding.NodeID, CredentialDigest: digest, ExpectedVersion: reservation.RowVersion}
	signed, e := db.IssueNodeTLSLeaf(store.NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, issuer)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := installer.Stage(*signed, chain, root, root, time.Now().UTC().Truncate(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	action.ExpectedVersion = signed.RowVersion
	installed, e := db.RecordNodeTLSInstallAck(store.NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
	if e != nil {
		t.Fatal(e)
	}
	action.ExpectedVersion = installed.RowVersion
	activationClaims, e := db.PrepareNodeTLSActivation(action, strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	activation, e := e2ee.SignNodeTLSActivation(hub, activationClaims)
	if e != nil {
		t.Fatal(e)
	}
	active, e := db.ActivateNodeTLSGrant(store.NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: activation})
	if e != nil {
		t.Fatal(e)
	}
	nodeCfg, e := installer.Apply(*active, time.Now().UTC().Truncate(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	// Re-signing is confined to this negative fixture: same TLS key and SPKI,
	// different exact DER/serial. Production issuance never repeats a reservation.
	otherParams, e := store.NodeTLSLeafParameters(active.Claims)
	if e != nil {
		t.Fatal(e)
	}
	otherParams.Serial[15] = 88
	otherLeaf, e := issuer.IssueTLSLeaf(active.CSRPEM, otherParams, time.Now().UTC().Truncate(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	nodeTLSProcessWrite(t, filepath.Join(dir, "other-node-chain.pem"), append(append([]byte(nil), otherLeaf.CertificatePEM...), chain...))
	otherCfg := *nodeCfg
	otherCfg.CertificateFile = filepath.Join(dir, "other-node-chain.pem")
	hubCfg := nodetransport.Config{Version: 1, Role: "hub", Listen: "127.0.0.1:0", CertificateFile: filepath.Join(dir, "hub-chain.pem"), PrivateKeyFile: filepath.Join(dir, "hub.key"), TrustFile: filepath.Join(dir, "root.pem"), Identity: nodetransport.Identity{Kind: "hub", HubID: hubID, DNSName: "hub.synthetic.invalid"}, Peers: []nodetransport.Approval{{Identity: nodeCfg.Identity, PinKind: "spki-sha256", PinSHA256: active.Claims.SPKIDERHash, OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.OwnerBindingID, BindingVersion: int64(binding.BindingVersion), CredentialVersion: int64(binding.NodeCredentialVersion)}}}
	return nodeTLSProcessFixture{dbPath, request.RequestID, token, hubCfg, *nodeCfg, otherCfg}
}
func nodeTLSProcessChild(t *testing.T, role, path, address string) {
	t.Helper()
	wire, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("read private child fixture")
	}
	var fixture nodeTLSProcessFixture
	if json.Unmarshal(wire, &fixture) != nil {
		t.Fatal("decode private child fixture")
	}
	if role == "hub" {
		db, e := store.New(fixture.DBPath)
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		service, e := fabric.NewService(db, "synthetic-owner", "synthetic-domain")
		if e != nil {
			t.Fatal(e)
		}
		var server *http.Server
		stopped := make(chan error, 1)
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v2/relay/native-probe":
				w.WriteHeader(http.StatusOK)
			case "/v2/relay/native-queued":
				current, e := db.GetNodeTLSAuthorityReservationLocal(fixture.RequestID)
				if e != nil {
					t.Fatal(e)
				}
				if e = db.RevokeNodeTLSGrantLocal(fixture.RequestID, current.RowVersion); e != nil {
					t.Fatal(e)
				}
				if nodePQTransportValidityCurrent(r.Context()) {
					t.Fatal("revoked queued native event remained authorized")
				}
				w.WriteHeader(http.StatusUnauthorized)
			case "/healthz":
				w.WriteHeader(http.StatusNoContent)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					stopped <- server.Shutdown(ctx)
				}()
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		listener, e := pqtls.Listen("tcp", fixture.HubConfig.Listen, fixture.HubConfig.TLSConfig())
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		server = &http.Server{Handler: WithNodePQTransport(inner, service, &fixture.HubConfig, true), ConnContext: pqtls.HTTPConnContext, ReadHeaderTimeout: 5 * time.Second}
		fmt.Fprintln(os.Stdout, "CICADA_TLS_READY "+listener.Addr().String())
		timer := time.AfterFunc(25*time.Second, func() { server.Close() })
		defer timer.Stop()
		if e = server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
		select {
		case e := <-stopped:
			if e != nil {
				t.Fatal("native Hub child did not shut down cleanly")
			}
		case <-time.After(6 * time.Second):
			t.Fatal("native Hub child stop signal missing")
		}
		return
	}
	call := func(cfg nodetransport.Config, paths []string, want []int) {
		t.Helper()
		client, e := pqtls.NewClient(cfg.TLSConfig())
		if e != nil {
			t.Fatal(e)
		}
		transport, e := client.HTTPTransport(address)
		if e != nil {
			t.Fatal(e)
		}
		defer transport.CloseIdleConnections()
		httpClient := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return pqtls.ErrIdentity }}
		for index, path := range paths {
			req, e := http.NewRequest(http.MethodGet, "https://"+address+path, nil)
			if e != nil {
				t.Fatal(e)
			}
			req.Header.Set("Authorization", "CicadaNode "+fixture.NodeToken)
			response, e := httpClient.Do(req)
			if e != nil {
				t.Fatal("native child request failed")
			}
			body, e := io.ReadAll(io.LimitReader(response.Body, 8192))
			response.Body.Close()
			if e != nil || response.StatusCode != want[index] {
				t.Fatal("native child Guard status mismatch")
			}
			if path == "/v2/relay/native-queued" && bytes.Contains(body, []byte("event:")) {
				t.Fatal("revoked queued event leaked")
			}
		}
	}
	call(fixture.NodeConfig, []string{"/v2/relay/native-probe"}, []int{http.StatusOK})
	call(fixture.OtherDERConfig, []string{"/v2/relay/native-probe"}, []int{http.StatusUnauthorized})
	call(fixture.NodeConfig, []string{"/v2/relay/native-probe", "/v2/relay/native-queued", "/v2/relay/native-probe", "/healthz"}, []int{http.StatusOK, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusNoContent})
}
func TestNodePQTransportNativeTwoProcessActiveDERAndQueuedRevoke(t *testing.T) {
	if role := os.Getenv("CICADA_TLS_PROCESS_ROLE"); role != "" {
		if !nodeTLSProcessNative(t) {
			t.Fatal("native child unavailable")
		}
		nodeTLSProcessChild(t, role, os.Getenv("CICADA_TLS_PROCESS_FIXTURE"), os.Getenv("CICADA_TLS_PROCESS_ADDRESS"))
		return
	}
	if !nodeTLSProcessNative(t) {
		return
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private native fixture directory")
	}
	fixture := nodeTLSProcessBuild(t, dir)
	wire, e := json.Marshal(fixture)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "private-process-fixture.json")
	nodeTLSProcessWrite(t, path, wire)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	child := func(role, address string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodePQTransportNativeTwoProcessActiveDERAndQueuedRevoke$", "-test.count=1", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "CICADA_TLS_PROCESS_ROLE="+role, "CICADA_TLS_PROCESS_FIXTURE="+path, "CICADA_TLS_PROCESS_ADDRESS="+address)
		return cmd
	}
	server := child("hub", "")
	stdout, e := server.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	server.Stderr = io.Discard
	if e = server.Start(); e != nil {
		t.Fatal("start native Hub child")
	}
	waited := false
	defer func() {
		if !waited {
			server.Process.Kill()
			server.Wait()
		}
	}()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "CICADA_TLS_READY ") {
				ready <- strings.TrimPrefix(scanner.Text(), "CICADA_TLS_READY ")
				return
			}
		}
		ready <- ""
	}()
	var address string
	select {
	case address = <-ready:
	case <-ctx.Done():
		t.Fatal("native Hub child readiness timeout")
	}
	if address == "" {
		t.Fatal("native Hub child exited before readiness")
	}
	nodeChild := child("node", address)
	if output, e := nodeChild.CombinedOutput(); e != nil {
		_ = output
		t.Fatal("native Node child gate failed; child payload suppressed")
	}
	err := server.Wait()
	waited = true
	if err != nil {
		t.Fatal("native Hub child gate did not exit zero")
	}
}
