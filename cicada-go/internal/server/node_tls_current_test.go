package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

// Synthetic native current-query fixture duplicates the frozen D1 fixture
// construction so that only this disposable test retains application identities.
// No private identity is included in a status packet or validation artifact.
func nodeTLSCurrentBuild(t *testing.T, dir string) (nodeTLSProcessFixture, *e2ee.Identity, *e2ee.Identity) {
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
	hubCfg := nodetransport.Config{Version: 1, Role: "hub", Listen: "127.0.0.1:0", CertificateFile: filepath.Join(dir, "hub-chain.pem"), PrivateKeyFile: filepath.Join(dir, "hub.key"), TrustFile: filepath.Join(dir, "root.pem"), Identity: nodetransport.Identity{Kind: "hub", HubID: hubID, DNSName: "hub.synthetic.invalid"}, Peers: []nodetransport.Approval{{Identity: nodeCfg.Identity, PinKind: "spki-sha256", PinSHA256: active.Claims.SPKIDERHash, OwnerID: binding.OwnerID, OwnerKeyID: binding.OwnerKeyID, BindingID: binding.OwnerBindingID, BindingVersion: int64(binding.BindingVersion), CredentialVersion: int64(binding.NodeCredentialVersion)}}}
	return nodeTLSProcessFixture{dbPath, request.RequestID, token, hubCfg, *nodeCfg, *nodeCfg}, node, hub
}

func TestNodeTLSCurrentNativeFabricOnlyRPCAndSSE(t *testing.T) {
	if !nodeTLSProcessNative(t) {
		if !errors.Is(pqtls.Available(), pqtls.ErrUnavailable) {
			t.Fatal("default backend classification")
		}
		return
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private synthetic root")
	}
	fixture, node, hub := nodeTLSCurrentBuild(t, dir)
	db, err := store.New(fixture.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	digest := fabric.HashSessionCredential(fixture.NodeToken)
	service, err := fabric.NewService(db, fixture.HubConfig.Identity.HubID, fixture.HubConfig.Identity.HubID)
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	handler := NewFabricHandlerWithNodeTLSCurrent(service, "", func(credential, nodeID string, packet []byte) ([]byte, error) {
		reads.Add(1)
		return control.ReadNodeTLSCurrentPacket(db, hub, credential, nodeID, packet)
	})
	if handler.(*Handler).control != nil {
		t.Fatal("Fabric-only current provider constructed Control business")
	}
	listener, err := pqtls.Listen("tcp", "127.0.0.1:0", fixture.HubConfig.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: WithNodePQTransport(handler, service, &fixture.HubConfig, true), ConnContext: pqtls.HTTPConnContext}
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
		httpServer.Close()
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error("bounded synthetic listener shutdown")
		}
	}()
	pq, err := pqtls.NewClient(fixture.NodeConfig.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	transport, err := pq.HTTPTransport(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	status, err := db.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: fixture.NodeConfig.Identity.NodeID, CredentialDigest: digest})
	if err != nil || status.CurrentActive == nil {
		t.Fatal("actual committed current fixture", err)
	}
	b := status.CurrentBinding
	binding := nodewire.Binding{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyVersion: b.HubKeyVersion, NodeKeyVersion: b.NodeKeyVersion, NodeKey: b.NodePublicIdentity, HubKey: b.HubPublicIdentity}
	at := time.Now().UTC().Truncate(time.Second)
	q := nodewire.TLSCurrentRequest{Nonce: make([]byte, 32), Origin: fixture.NodeConfig.LogicalOrigin(), CredentialDigest: digest, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(nodewire.TLSCurrentLifetime).Format(time.RFC3339)}
	if _, err = rand.Read(q.Nonce); err != nil {
		t.Fatal(err)
	}
	packet, err := nodewire.SealTLSCurrentRequest(node, binding, q, at)
	if err != nil {
		t.Fatal("fresh NIST query", err)
	}
	// Native HTTPTransport binds its physical dial target. Signed q.Origin
	// remains the exact logical application origin inside the NIST packet.
	send := func(packet []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/v2/node/control/rpc", bytes.NewReader(packet))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "CicadaNode "+fixture.NodeToken)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("native fresh current RPC", err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, nodewire.MaxTLSCurrentPacketBytes+1))
		if err != nil {
			t.Fatal("bounded current response")
		}
		return response.StatusCode, data
	}
	highwater := func() uint64 {
		t.Helper()
		_, _, s, err := db.NodeControlRecoveryStatus(digest, b.NodeID, func(*store.NodeControlKeyBinding) (nodewire.RecoveryRequest, error) {
			return nodewire.RecoveryRequest{Nonce: bytes.Repeat([]byte{0x65}, 32), Origin: q.Origin, CredentialDigest: digest, RestoreDigest: strings.Repeat("a", 64), PlanDigest: strings.Repeat("b", 64)}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return s.AcceptedHighwater
	}
	before := highwater()
	code, reply := send(packet)
	if code != 200 {
		t.Fatal("Control=nil current RPC refused", code)
	}
	current, err := nodewire.OpenTLSCurrentResponse(node, binding, q, packet, reply, time.Now().UTC())
	if err != nil || current.CurrentAuthority.LeafDERHash != status.CurrentActive.LeafDERHash || current.CurrentAuthority.RowVersion != status.CurrentActive.RowVersion {
		t.Fatal("actual current snapshot differs", err)
	}
	newer := q
	newer.Nonce = bytes.Repeat([]byte{0x77}, 32)
	if _, err = nodewire.OpenTLSCurrentResponse(node, binding, newer, packet, reply, time.Now().UTC()); err == nil {
		t.Fatal("old response accepted for a new conversation")
	}
	if highwater() != before || reads.Load() != 1 {
		t.Fatal("fresh current query changed RPC highwater or provider dispatch")
	}
	// ConnContext alone must not substitute for the current strict Guard.
	unwrapped, err := pqtls.Listen("tcp", "127.0.0.1:0", fixture.HubConfig.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	unwrappedServer := &http.Server{Handler: handler, ConnContext: pqtls.HTTPConnContext}
	unwrappedDone := make(chan error, 1)
	go func() { unwrappedDone <- unwrappedServer.Serve(unwrapped) }()
	unwrappedTransport, err := pq.HTTPTransport(unwrapped.Addr().String())
	if err != nil {
		unwrappedServer.Close()
		t.Fatal(err)
	}
	unwrappedClient := &http.Client{Transport: unwrappedTransport, Timeout: 5 * time.Second}
	unwrappedRequest, _ := http.NewRequest(http.MethodPost, "https://"+unwrapped.Addr().String()+"/v2/node/control/rpc", bytes.NewReader(packet))
	unwrappedRequest.Header.Set("Authorization", "CicadaNode "+fixture.NodeToken)
	unwrappedResponse, err := unwrappedClient.Do(unwrappedRequest)
	if err != nil {
		unwrappedServer.Close()
		t.Fatal("native unwrapped negative request", err)
	}
	unwrappedResponse.Body.Close()
	unwrappedTransport.CloseIdleConnections()
	unwrappedServer.Close()
	<-unwrappedDone
	if unwrappedResponse.StatusCode != 403 || reads.Load() != 1 {
		t.Fatal("native context without current Guard reached provider")
	}
	// Production Relay/SSE remains reachable with Control business absent.
	request, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/v2/relay/nodes/"+b.NodeID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "CicadaNode "+fixture.NodeToken)
	stream, err := client.Do(request)
	if err != nil {
		t.Fatal("native Fabric-only SSE", err)
	}
	ready := make([]byte, len("event: ready\ndata: claim\n\n"))
	_, err = io.ReadFull(stream.Body, ready)
	stream.Body.Close()
	if err != nil || stream.StatusCode != 200 || string(ready) != "event: ready\ndata: claim\n\n" {
		t.Fatal("production Fabric-only SSE ready")
	}
	if err = db.RevokeNodeTLSGrantLocal(fixture.RequestID, status.CurrentActive.RowVersion); err != nil {
		t.Fatal("actual TLS revoke", err)
	}
	code, _ = send(packet)
	if code != 401 || reads.Load() != 1 || highwater() != before {
		t.Fatal("revoked current query reached provider or replay admission", code)
	}
}

func TestNodeTLSCurrentFabricOnlyRejectsUnauthenticatedProviderUse(t *testing.T) {
	var called atomic.Int32
	h := &Handler{nodeTLSCurrent: func(string, string, []byte) ([]byte, error) { called.Add(1); return nil, nil }}
	request, _ := http.NewRequest(http.MethodPost, "https://hub.synthetic.invalid/v2/node/control/rpc", nil)
	response := newNodeTLSCurrentRecorder()
	h.nodeTLSCurrentStatus(response, request, "synthetic-digest", "synthetic-node", []byte("synthetic packet"))
	if response.status != 403 || called.Load() != 0 {
		t.Fatal("missing native TLS context reached current provider")
	}
}

type nodeTLSCurrentRecorder struct {
	header http.Header
	status int
}

func newNodeTLSCurrentRecorder() *nodeTLSCurrentRecorder {
	return &nodeTLSCurrentRecorder{header: make(http.Header)}
}
func (r *nodeTLSCurrentRecorder) Header() http.Header            { return r.header }
func (r *nodeTLSCurrentRecorder) WriteHeader(code int)           { r.status = code }
func (r *nodeTLSCurrentRecorder) Write(data []byte) (int, error) { return len(data), nil }
