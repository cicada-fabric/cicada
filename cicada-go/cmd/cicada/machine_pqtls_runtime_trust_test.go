package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestNodeTLSRuntimeClientRejectsLegacyEnvironmentFallback(t *testing.T) {
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", filepath.Join(t.TempDir(), "unverified-legacy-config.json"))
	before := http.DefaultTransport
	if client, err := machineNodeHTTPClient(context.Background(), 0); client != nil || !errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable) {
		t.Fatal("env-only command published unchecked transport", err)
	}
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "synthetic-hub", NodeID: "synthetic-node", Origin: "https://hub.synthetic.invalid"})
	if client, err := machineNodeHTTPClient(ctx, 0); client != nil || !errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable) {
		t.Fatal("pinned context fell back to default HTTP transport", err)
	}
	if http.DefaultTransport != before {
		t.Fatal("per-Hub runtime changed global HTTP transport")
	}
}
func TestNodeTLSRuntimeConfigureRejectsQuarantineBeforeAnyStateWrite(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private disposable root")
	}
	marker := filepath.Join(root, "nodes", ".recovery-pending", "node-other.json")
	if os.MkdirAll(filepath.Dir(marker), 0700) != nil || os.WriteFile(marker, []byte("synthetic quarantine"), 0600) != nil {
		t.Fatal("private disposable marker")
	}
	hub := machineHubContext{HubID: "synthetic-hub", NodeID: "synthetic-node", Origin: "https://hub.synthetic.invalid", StateDir: root, WriterRoot: root}
	// Invalid path is rejected without opening keys, network or global config.
	before, err := recoveryTreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureMachinePQTransport(&hub, filepath.Join(root, "legacy.json")); err == nil || hub.NodeTransport != nil || hub.TLSRuntime != nil {
		t.Fatal("quarantined/unchecked configuration was published")
	}
	after, err := recoveryTreeDigest(root)
	if err != nil || before != after {
		t.Fatal("failed configure changed Node tree")
	}
}
func TestNodeTLSRuntimeLocalReaderNeverCreatesMissingIdentity(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private disposable root")
	}
	hub := machineHubContext{HubID: "synthetic-hub", NodeID: "synthetic-node", Origin: "https://hub.synthetic.invalid", StateDir: root, WriterRoot: root}
	before, err := recoveryTreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := machineTLSExistingBinding(&hub); err == nil {
		t.Fatal("missing existing trust created an identity")
	}
	after, err := recoveryTreeDigest(root)
	if err != nil || before != after {
		t.Fatal("read-only local adapter created/chmodded state")
	}
}

// Every application/CA key below is synthetic and confined to the parent TempDir.
type runtimeStartupFixture struct {
	ActiveVersion                                   uint64
	DBPath, RequestID, Token, StateRoot, WriterRoot string
	HubConfig, NodeConfig                           nodetransport.Config
	Binding                                         *store.NodeControlKeyBinding
	Node, Hub                                       *e2ee.Identity
}

func runtimeStartupWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal("private disposable fixture write failed")
	}
}
func runtimeStartupCA(t *testing.T, dir string) ([]byte, []byte, []byte, time.Time) {
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
	runtimeStartupWrite(t, filepath.Join(dir, "issuer.ext"), []byte("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"))
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
func runtimeStartupBuild(t *testing.T, dir, origin string) runtimeStartupFixture {
	t.Helper()
	return runtimeStartupBuildScoped(t, dir, origin, filepath.Join(dir, "writer-root"), "synthetic-node")
}
func runtimeStartupBuildScoped(t *testing.T, dir, origin, writerRoot, nodeID string) runtimeStartupFixture {
	t.Helper()
	if os.MkdirAll(dir, 0700) != nil {
		t.Fatal("private fixture dir")
	}
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
	candidate, e := db.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{Mode: store.NodeControlPairingInitial, NodeID: nodeID, NodeName: nodeID, CredentialDigest: digest, CodeDigest: codeDigest, NodePublicIdentity: node.Public(), NodeFingerprint: fingerprint(node.Public()), ProofPacket: []byte("synthetic application possession fixture"), HubPublicIdentity: hub.Public(), HubKeyVersion: 1, HubFingerprint: fingerprint(hub.Public()), ExpiresAt: now.Add(10 * time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	binding, e := db.ConfirmNodeControlKeyRequest("synthetic-owner", client.DeviceID, codeDigest, candidate.Version, candidate.CandidateDigest, candidate.HubNodeControlKeyID, candidate.HubNodeControlFingerprint)
	if e != nil {
		t.Fatal(e)
	}
	chain, root, issuerKey, at := runtimeStartupCA(t, dir)
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
	runtimeStartupWrite(t, filepath.Join(dir, "hub.key"), secret)
	clear(secret)
	runtimeStartupWrite(t, filepath.Join(dir, "hub-chain.pem"), append(append([]byte(nil), hubLeaf.CertificatePEM...), chain...))
	runtimeStartupWrite(t, filepath.Join(dir, "root.pem"), root)
	stateRoot := filepath.Join(dir, "node-state")
	cryptoRoot := machineNodeStateDir(stateRoot, binding.NodeID)
	for _, p := range []string{stateRoot, writerRoot, cryptoRoot} {
		if os.MkdirAll(p, 0700) != nil {
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
	request := nodetransport.TLSPreparationRequest{RequestID: "synthetic-two-process-tls", DNSName: "node.synthetic.invalid", HubDNSName: "hub.synthetic.invalid", HubPQOrigin: origin, ApplicationOrigin: origin, HubSPKIHash: hash(hubCSR.SPKIDERHash), HubTrustAnchorDERHash: hash(issuerProfile.TrustAnchorDERHash), IssuerGeneration: "synthetic-two-process-issuer", IssuerSPKIHash: hash(issuerProfile.SPKIDERHash), IssuerDERHash: hash(issuerProfile.CertificateDERHash), RootDERHash: hash(issuerProfile.TrustAnchorDERHash)}
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
	hubCfg := nodetransport.Config{Version: 1, Role: "hub", Listen: "127.0.0.1:0", CertificateFile: filepath.Join(dir, "hub-chain.pem"), PrivateKeyFile: filepath.Join(dir, "hub.key"), TrustFile: filepath.Join(dir, "root.pem"), Identity: nodetransport.Identity{Kind: "hub", HubID: hubID, DNSName: "hub.synthetic.invalid"}, Peers: []nodetransport.Approval{{Identity: nodeCfg.Identity, PinKind: "spki-sha256", PinSHA256: active.Claims.SPKIDERHash, OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.OwnerBindingID, BindingVersion: int64(binding.BindingVersion), CredentialVersion: int64(binding.NodeCredentialVersion)}}}
	return runtimeStartupFixture{ActiveVersion: active.RowVersion, DBPath: dbPath, RequestID: request.RequestID, Token: token, HubConfig: hubCfg, NodeConfig: *nodeCfg, StateRoot: stateRoot, WriterRoot: writerRoot, Binding: binding, Node: node, Hub: hub}
}

// The DNS fixture is confined to an isolated test child. It answers only the
// synthetic Hub name and never edits hosts files, global CLI or real resolver
// configuration. Real native Dial and certificate hostname/pin checks run.
func runtimeStartupDNS(t *testing.T) {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("private DNS fixture listener")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, address, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < 12 || binary.BigEndian.Uint16(buffer[4:6]) != 1 {
				continue
			}
			at := 12
			var labels []string
			valid := true
			for {
				if at >= n {
					valid = false
					break
				}
				length := int(buffer[at])
				at++
				if length == 0 {
					break
				}
				if length > 63 || at+length > n {
					valid = false
					break
				}
				labels = append(labels, string(buffer[at:at+length]))
				at += length
			}
			if !valid || at+4 > n {
				continue
			}
			kind := binary.BigEndian.Uint16(buffer[at : at+2])
			class := binary.BigEndian.Uint16(buffer[at+2 : at+4])
			end := at + 4
			response := append([]byte(nil), buffer[:end]...)
			response[2], response[3] = 0x81, 0x80
			for k := 6; k < 12; k++ {
				response[k] = 0
			}
			if strings.ToLower(strings.Join(labels, ".")) != "hub.synthetic.invalid" || class != 1 {
				response[3] = 0x83
			} else if kind == 1 {
				response[7] = 1
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
			}
			listener.WriteToUDP(response, address)
		}
	}()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", listener.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = original; listener.Close(); <-done })
}

func runtimeStartupPersistApplicationState(t *testing.T, f runtimeStartupFixture) {
	t.Helper()
	b := f.Binding
	state := machineNodeControlState{Version: machineNodeControlStateVersion, NodeID: b.NodeID, HubOrigin: f.NodeConfig.LogicalOrigin(), HubID: b.HubID, HubKeyID: b.HubKeyID, HubFingerprint: b.HubKeyFingerprint, HubKeyVersion: b.HubKeyVersion, HubPublicIdentity: b.HubPublicIdentity, NodeKeyID: b.NodeKeyID, NodeKeyFingerprint: b.NodeKeyFingerprint, NodeKeyVersion: b.NodeKeyVersion, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, ApprovedRequestID: b.ApprovedRequestID, ApprovedRequestVersion: b.ApprovedRequestVersion, ApprovedCandidateDigest: b.ApprovedCandidateDigest}
	identityPath, statePath := machineNodeControlPaths(f.StateRoot, b.NodeID)
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	runtimeStartupWrite(t, statePath, data)
	secret, err := f.Node.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	runtimeStartupWrite(t, identityPath, secret)
	clear(secret)
	runtimeStartupWrite(t, machineNodeCredentialPath(f.StateRoot, b.NodeID), []byte(f.Token))
	data, err = json.Marshal(machineNodeIdentity{Version: machineNodeIdentityVersion, NodeID: b.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	runtimeStartupWrite(t, filepath.Join(filepath.Dir(statePath), "identity.json"), data)
}

func runtimeStartupServe(t *testing.T, f runtimeStartupFixture, address string) *store.Store {
	t.Helper()
	db, err := store.New(f.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(db, f.HubConfig.Identity.HubID, f.HubConfig.Identity.HubID)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	handler := server.NewFabricHandlerWithNodeTLSCurrent(service, "", func(credential, nodeID string, packet []byte) ([]byte, error) {
		return control.ReadNodeTLSCurrentPacket(db, f.Hub, credential, nodeID, packet)
	})
	listener, err := pqtls.Listen("tcp", address, f.HubConfig.TLSConfig())
	if err != nil {
		db.Close()
		t.Fatal("actual native Hub listener", err)
	}
	hubServer := &http.Server{Handler: server.WithNodePQTransport(handler, service, &f.HubConfig, true), ConnContext: pqtls.HTTPConnContext}
	done := make(chan error, 1)
	go func() { done <- hubServer.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hubServer.Shutdown(ctx)
		hubServer.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error("native Hub exit")
		}
		db.Close()
	})
	return db
}
func runtimeStartupProductChild(t *testing.T, root string) {
	t.Helper()
	started := time.Now()
	phase := func(name, state string) {
		t.Logf("phase=%s state=%s elapsed=%s", name, state, time.Since(started).Round(time.Millisecond))
	}
	runtimeStartupDNS(t)
	reserve := func() (net.Listener, string, string) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		return listener, address, "https://hub.synthetic.invalid:" + port
	}
	reservation, address, origin := reserve()
	defer reservation.Close()
	reservation2, address2, origin2 := reserve()
	defer reservation2.Close()
	writerRoot := filepath.Join(root, "writer-root")
	// Both real approved installations are completed before either Agent starts.
	phase("firstApply", "begin")
	f := runtimeStartupBuildScoped(t, filepath.Join(root, "hub-one"), origin, writerRoot, "synthetic-node-one")
	phase("firstApply", "complete")
	phase("secondApply", "begin")
	f2 := runtimeStartupBuildScoped(t, filepath.Join(root, "hub-two"), origin2, writerRoot, "synthetic-node-two")
	phase("secondApply", "complete")
	runtimeStartupPersistApplicationState(t, f)
	runtimeStartupPersistApplicationState(t, f2)
	reservation.Close()
	reservation2.Close()
	db := runtimeStartupServe(t, f, address)
	db2 := runtimeStartupServe(t, f2, address2)
	makeHub := func(f runtimeStartupFixture) machineHubContext {
		return machineHubContext{HubID: f.HubConfig.Identity.HubID, NodeID: f.NodeConfig.Identity.NodeID, Origin: f.NodeConfig.LogicalOrigin(), StateDir: f.StateRoot, WriterRoot: f.WriterRoot, WriterScope: "synthetic-runtime-scope"}
	}
	path := func(f runtimeStartupFixture) string {
		return filepath.Clean(filepath.Join(filepath.Dir(f.NodeConfig.PrivateKeyFile), "..", "..", "active.json"))
	}
	hub, hub2 := makeHub(f), makeHub(f2)
	before, err := recoveryTreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	phase("startup1", "begin")
	if err = configureMachinePQTransport(&hub, path(f)); err != nil {
		t.Fatal("first product checked startup", err)
	}
	phase("startup1", "complete")
	defer hub.TLSRuntime.Close()
	phase("startup2", "begin")
	if err = configureMachinePQTransport(&hub2, path(f2)); err != nil {
		t.Fatal("second same WriterRoot product startup", err)
	}
	phase("startup2", "complete")
	defer hub2.TLSRuntime.Close()
	if hub.NodeTransport == nil || hub.TLSRuntime == nil || hub2.TLSRuntime == nil {
		t.Fatal("checked sessions not published")
	}
	after, err := recoveryTreeDigest(root)
	if err != nil || before != after {
		t.Fatal("checked startup rewrote fixture state")
	}
	duplicate := makeHub(f)
	if err = configureMachinePQTransport(&duplicate, path(f)); !errors.Is(err, nodelock.ErrAgentRunning) || duplicate.TLSRuntime != nil {
		t.Fatal("same Node Agent singleton admitted", err)
	}
	if lock, err := nodelock.AcquireWriterRootExclusive(writerRoot); !errors.Is(err, nodelock.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("two runtimes did not exclude maintenance", err)
	}
	// Original Session writer serialization remains independent of shared TLS
	// startup. No native model or queue command is launched for this lock gate.
	phase("Session", "begin")
	lease, err := nodelock.AcquireNativeWriter(context.Background(), writerRoot, "synthetic-original-account", "codex", "same-original-native-session")
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	second, err := nodelock.AcquireNativeWriter(short, writerRoot, "synthetic-original-account", "codex", "same-original-native-session")
	cancel()
	if second != nil {
		second.Close()
		lease.Close()
		t.Fatal("original Session duplicate writer admitted")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		lease.Close()
		t.Fatal("original Session writer conflict classification", err)
	}
	lease.Close()
	phase("Session", "complete")
	phase("SSE", "begin")
	ctx := withMachineHubContext(context.Background(), hub)
	client, err := machineNodeHTTPClient(ctx, 5*time.Second)
	if err != nil || client.Transport != hub.NodeTransport {
		t.Fatal("published per-Hub client", err)
	}
	request, err := http.NewRequest(http.MethodGet, origin+"/v2/relay/nodes/"+hub.NodeID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "CicadaNode "+f.Token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("product Node native SSE", err)
	}
	ready := make([]byte, len("event: ready\ndata: claim\n\n"))
	_, err = io.ReadFull(response.Body, ready)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(ready) != "event: ready\ndata: claim\n\n" {
		t.Fatal("product Node SSE ready")
	}
	phase("SSE", "complete")
	if err = db.RevokeNodeTLSGrantLocal(f.RequestID, f.ActiveVersion); err != nil {
		t.Fatal("actual current revocation", err)
	}
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("revoked current authority admitted product request")
	}
	hub.TLSRuntime.Close()
	hub.TLSRuntime = nil
	hub.NodeTransport = nil
	if lock, err := nodelock.AcquireWriterRootExclusive(writerRoot); !errors.Is(err, nodelock.ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("closing one runtime released other's WriterRoot hold", err)
	}
	before, err = recoveryTreeDigest(f.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err = configureMachinePQTransport(&hub, path(f)); !errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable) {
		t.Fatal("revoked checked restart classification", err)
	}
	after, err = recoveryTreeDigest(f.StateRoot)
	if err != nil || before != after || hub.NodeTransport != nil || hub.TLSRuntime != nil {
		t.Fatal("revoked restart published or changed state")
	}
	hub2.TLSRuntime.Close()
	hub2.TLSRuntime = nil
	hub2.NodeTransport = nil
	exclusive, err := nodelock.AcquireWriterRootExclusive(writerRoot)
	if err != nil {
		t.Fatal("closed runtime locks not released", err)
	}
	if err = configureMachinePQTransport(&hub2, path(f2)); !errors.Is(err, nodelock.ErrBusy) || hub2.TLSRuntime != nil {
		exclusive.Close()
		t.Fatal("maintenance admitted new startup", err)
	}
	exclusive.Close()
	// A maintained, quarantined read obtains fresh actual committed current
	// metadata while retaining both exclusive locks. It never publishes a client.
	marker := filepath.Join(f2.StateRoot, "nodes", ".recovery-pending", "node-"+hub2.NodeID+".json")
	if os.MkdirAll(filepath.Dir(marker), 0700) != nil || os.WriteFile(marker, []byte("synthetic recovery hold"), 0600) != nil {
		t.Fatal("private recovery marker")
	}
	cap, err := nodetransport.AcquireTLSMaintenanceRead(hub2.StateDir, hub2.WriterRoot, hub2.HubID, hub2.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer cap.Close()
	o := nodetransport.RuntimeOptions{StateRoot: hub2.StateDir, WriterRoot: hub2.WriterRoot, HubID: hub2.HubID, NodeID: hub2.NodeID, ApplicationOrigin: hub2.Origin, ConfigPath: path(f2), OpenLocal: func() (*nodetransport.LocalTLSInstaller, func(), error) { return machineTLSOpenLocalIn(&hub2, cap) }, QueryCurrent: func(ctx context.Context, cfg *nodetransport.Config) (*store.NodeTLSAuthoritySnapshot, error) {
		return machineTLSQueryCurrentIn(ctx, &hub2, cfg, cap)
	}}
	before, err = recoveryTreeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	phase("maintcurrent", "begin")
	current, err := cap.ReadCurrentAuthority(context.Background(), o)
	if err != nil || current == nil || current.State != store.NodeTLSActive {
		t.Fatal("held-maintenance fresh current read", err)
	}
	after, err = recoveryTreeDigest(root)
	if err != nil || before != after || hub2.NodeTransport != nil || hub2.TLSRuntime != nil {
		t.Fatal("maintained current read wrote or published")
	}
	phase("maintcurrent", "complete")
	if err = configureMachinePQTransport(&hub2, path(f2)); !errors.Is(err, nodetransport.ErrTLSRecoveryQuarantine) {
		t.Fatal("read capability widened recovery startup", err)
	}
	if err = db2.RevokeNodeTLSGrantLocal(f2.RequestID, f2.ActiveVersion); err != nil {
		t.Fatal(err)
	}
	if _, err = cap.ReadCurrentAuthority(context.Background(), o); !errors.Is(err, nodetransport.ErrTLSCurrentAuthorityUnavailable) {
		t.Fatal("revoked current under maintenance admitted", err)
	}
	duplicateCap := *cap
	cap.Close()
	duplicateCap.Close()
	if _, err = duplicateCap.ReadCurrentAuthority(context.Background(), o); !errors.Is(err, nodetransport.ErrTLSRuntimeClosed) {
		t.Fatal("closed maintained copy admitted", err)
	}
	phase("complete", "complete")
}

func TestNodeTLSRuntimeNativeProductCheckedStartup(t *testing.T) {
	if os.Getenv("CICADA_SYNTHETIC_RUNTIME_STARTUP_CHILD") == "1" {
		runtimeStartupProductChild(t, os.Getenv("CICADA_SYNTHETIC_RUNTIME_STARTUP_ROOT"))
		return
	}
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" || !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal("requested native product startup provider unavailable")
		}
		return
	}
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private disposable root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeTLSRuntimeNativeProductCheckedStartup$", "-test.count=1", "-test.v")
	command.Env = append(os.Environ(), "CICADA_SYNTHETIC_RUNTIME_STARTUP_CHILD=1", "CICADA_SYNTHETIC_RUNTIME_STARTUP_ROOT="+root)
	output, err := command.CombinedOutput()
	t.Logf("bounded native product child phases:\n%s", output)
	if err != nil {
		t.Fatalf("bounded native product child failed: %v", err)
	}
}
