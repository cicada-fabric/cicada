package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

type controlTLSActivationFixture struct {
	c                *Control
	owner, node, hub *e2ee.Identity
	device           *store.ClientDevice
	binding          *store.NodeControlKeyBinding
	digest, path     string
}

func controlTLSActivationIdentity(t *testing.T) *e2ee.Identity {
	t.Helper()
	i, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func newControlTLSActivationFixture(t *testing.T) controlTLSActivationFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic-activation.sqlite3")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	owner, node, hub, phone := controlTLSActivationIdentity(t), controlTLSActivationIdentity(t), controlTLSActivationIdentity(t), controlTLSActivationIdentity(t)
	c := &Control{store: s, nodeControlIdentity: hub}
	if _, err := s.CreatePrincipal(store.Principal{ID: "synthetic-d2-owner", OwnerID: "synthetic-d2-owner", Kind: store.PrincipalKindHuman, Name: "synthetic Owner only", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal("synthetic-d2-owner", owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	ownerDeviceGrant, err := owner.SignOwnerDeviceGrant("synthetic-d2-owner", "synthetic-d2-phone", phone.Public(), hubID, e2ee.OwnerDevicePurposeControl, at.Add(-time.Minute), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	device, err := s.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: "synthetic-d2-owner", OwnerKeyID: ownerKey.KeyID, DeviceID: "synthetic-d2-phone", DevicePublic: phone.Public(), OwnerDeviceGrant: ownerDeviceGrant})
	if err != nil {
		t.Fatal(err)
	}
	digest := fabric.HashSessionCredential("CICADA SYNTHETIC D2 RELAY TOKEN ONLY")
	nodeID := "synthetic-d2-node"
	requestNonce := bytes.Repeat([]byte{0x35}, 32)
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hubID, NodeID: nodeID, RequestNonce: requestNonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: hub.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, hub.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := c.StartNodeControlDeviceBinding(NodeControlDeviceCodeInput{Mode: store.NodeControlPairingInitial, NodeID: nodeID, NodeName: "synthetic D2 Node only", CredentialDigest: digest, RequestNonce: requestNonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: hubID, HubPublicIdentity: hub.Public(), HubKeyVersion: 1, HubFingerprint: nodewire.IdentityFingerprint(hub.Public())})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.ConfirmNodeControlDeviceCode("synthetic-d2-owner", device.DeviceID, pairing.UserCode, pairing.Candidate.CandidateDigest, pairing.Candidate.Version)
	if err != nil {
		t.Fatal(err)
	}
	return controlTLSActivationFixture{c, owner, node, hub, device, binding, digest, path}
}

func TestNodeTLSAuthorityActivationActualIdentityAndInput(t *testing.T) {
	f := newControlTLSActivationFixture(t)
	action := store.NodeTLSAuthorityActionInput{RequestID: "synthetic-uninstalled", NodeID: f.binding.NodeID, CredentialDigest: f.digest, ExpectedVersion: 4}
	nonce := e2ee.NodeTLSAuthorityDigest([]byte("synthetic-d2-activation-nonce"))
	var absent *Control
	for _, c := range []*Control{absent, {}, {store: f.c.store}, {store: f.c.store, nodeControlIdentity: controlTLSActivationIdentity(t)}} {
		if result, err := c.ActivateNodeTLSAuthorityLocal(action, nonce); result != nil || !errors.Is(err, store.ErrNodeTLSAuthorityDenied) {
			t.Fatal("missing or foreign actual HubControl identity authorized activation")
		}
	}
	for _, bad := range []string{"", strings.Repeat("0", 64), strings.ToUpper(nonce), nonce + "00"} {
		if result, err := f.c.ActivateNodeTLSAuthorityLocal(action, bad); result != nil || !errors.Is(err, store.ErrNodeTLSAuthorityDenied) {
			t.Fatal("malformed activation nonce accepted")
		}
	}
	if result, err := f.c.ActivateNodeTLSAuthorityLocal(action, nonce); result != nil || !errors.Is(err, store.ErrNodeTLSAuthorityDenied) {
		t.Fatal("missing Owner grant and install ACK became approval")
	}
}

func controlTLSActivationNative(t *testing.T) bool {
	t.Helper()
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" {
			t.Fatal("native D2 activation gate requested but adapter unavailable")
		}
		if !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal(err)
		}
		t.Log("NOT_RUN native D2 activation: typed unavailable; default identity rejection is covered")
		return false
	}
	return true
}

func controlTLSActivationCLI(t *testing.T, dir string, args ...string) {
	t.Helper()
	binary := os.Getenv("PQTLS_TEST_OPENSSL")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("native D2 activation requires pinned absolute PQTLS_TEST_OPENSSL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = dir, append(os.Environ(), "OPENSSL_CONF=/dev/null")
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("synthetic D2 certificate fixture command failed; output suppressed")
	}
}

func controlTLSActivationInstalled(t *testing.T, f controlTLSActivationFixture) *store.NodeTLSAuthoritySnapshot {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	controlTLSActivationCLI(t, dir, "req", "-new", "-x509", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=CICADA SYNTHETIC D2 ROOT ONLY", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
	controlTLSActivationCLI(t, dir, "req", "-new", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "issuer.key", "-out", "issuer.csr", "-subj", "/CN=CICADA SYNTHETIC D2 ISSUER ONLY")
	if err := os.WriteFile(filepath.Join(dir, "issuer.ext"), []byte("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"), 0600); err != nil {
		t.Fatal(err)
	}
	controlTLSActivationCLI(t, dir, "x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "issuer.pem", "-days", "1", "-extfile", "issuer.ext")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("read synthetic D2 fixture")
		}
		return data
	}
	root, chain, key := read("root.pem"), read("issuer.pem"), read("issuer.key")
	chain = append(chain, root...)
	defer clear(key)
	at := time.Now().UTC().Truncate(time.Second)
	issuer, profile, err := pqtls.ImportTLSIssuer(chain, key, root, "node", at)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Destroy()
	tlsKey, csr, err := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsKey.Destroy()
	hash := func(s string) string { return e2ee.NodeTLSAuthorityDigest([]byte("SYNTHETIC D2 ONLY: " + s)) }
	r, err := f.c.store.ReserveNodeTLSCandidate(store.NodeTLSCandidateInput{RequestID: "synthetic_d2_activation", NodeID: f.binding.NodeID, CredentialDigest: f.digest, CSRPEM: csr.CSRPEM, IssuerChainPEM: chain, TrustAnchorPEM: root, Parameters: csr.Parameters, Issuer: profile, IssuerGeneration: "synthetic_d2_issuer", NotBefore: at, NotAfter: at.Add(time.Hour), HubSPKIHash: hash("hub-spki"), HubTrustAnchorDERHash: hash("hub-trust"), HubPQOrigin: "https://hub.synthetic.invalid:7443", ApplicationOrigin: "http://127.0.0.1:8080", GrantIssuedAt: at, GrantExpiresAt: at.Add(time.Hour), GrantNonce: hash("owner-grant")})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, r.Claims)
	if err != nil {
		t.Fatal(err)
	}
	action := store.NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
	signed, err := f.c.store.IssueNodeTLSLeaf(store.NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: grant}, issuer)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := e2ee.SignNodeTLSInstallAck(f.node, e2ee.NodeTLSInstallAckClaims{Version: 1, GrantClaims: signed.Claims, GrantDigest: e2ee.NodeTLSAuthorityDigest(grant), ReservationVersion: 1, LeafDERHash: signed.LeafDERHash, IssuedAt: at.Format(time.RFC3339), ExpiresAt: signed.Claims.ExpiresAt, Nonce: hash("node-install")})
	if err != nil {
		t.Fatal(err)
	}
	action.ExpectedVersion = signed.RowVersion
	installed, err := f.c.store.RecordNodeTLSInstallAck(store.NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: ack})
	if err != nil {
		t.Fatal(err)
	}
	return installed
}

func TestNodeTLSAuthorityActivationNativeCommittedRetryAndRestart(t *testing.T) {
	if !controlTLSActivationNative(t) {
		return
	}
	f := newControlTLSActivationFixture(t)
	r := controlTLSActivationInstalled(t, f)
	action := store.NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
	nonce := e2ee.NodeTLSAuthorityDigest([]byte("synthetic_d2_hub_activation"))
	prepared, err := f.c.store.PrepareNodeTLSActivation(action, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.SignNodeTLSActivation(f.hub, prepared); err != nil {
		t.Fatal(err)
	}
	status, err := f.c.store.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: action.NodeID, CredentialDigest: f.digest})
	if err != nil || status.CurrentActive != nil || status.CurrentActiveState != store.NodeTLSAuthorityCurrentNone {
		t.Fatal("prepared signature became committed current authority")
	}
	f.c.nodeControlIdentity = controlTLSActivationIdentity(t)
	if _, err := f.c.ActivateNodeTLSAuthorityLocal(action, nonce); !errors.Is(err, store.ErrNodeTLSAuthorityDenied) {
		t.Fatal("foreign live HubControl identity signed installed leaf")
	}
	f.c.nodeControlIdentity = f.hub
	var wg sync.WaitGroup
	results := make([]*store.NodeTLSAuthoritySnapshot, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], errs[i] = f.c.ActivateNodeTLSAuthorityLocal(action, nonce) }(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i] == nil || results[i].State != store.NodeTLSActive || !bytes.Equal(results[i].Activation, results[0].Activation) {
			t.Fatal("same-intent activation did not return immutable committed winner")
		}
	}
	active := results[0]
	if err := f.c.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.c.store, err = store.New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.c.store.Close()
	retry, err := f.c.ActivateNodeTLSAuthorityLocal(action, nonce)
	if err != nil || !bytes.Equal(retry.Activation, active.Activation) || !bytes.Equal(retry.LeafCertificatePEM, active.LeafCertificatePEM) || retry.RowVersion != active.RowVersion {
		t.Fatal("restart re-signed or replaced persisted activation")
	}
	if _, err := f.c.ActivateNodeTLSAuthorityLocal(action, e2ee.NodeTLSAuthorityDigest([]byte("different-intent"))); !errors.Is(err, store.ErrNodeTLSAuthorityConflict) {
		t.Fatal("different nonce replaced committed proof")
	}
	stale := action
	stale.ExpectedVersion--
	if _, err := f.c.ActivateNodeTLSAuthorityLocal(stale, nonce); !errors.Is(err, store.ErrNodeTLSAuthorityConflict) {
		t.Fatal("different action version became exact retry")
	}
	if _, err := f.c.store.RevokeClientDevice(f.device.OwnerID, f.device.DeviceID, f.device.Version); err != nil {
		t.Fatal(err)
	}
	if result, err := f.c.ActivateNodeTLSAuthorityLocal(action, nonce); result != nil || err == nil {
		t.Fatal("revoked current Owner device recovered an activation")
	}
}
