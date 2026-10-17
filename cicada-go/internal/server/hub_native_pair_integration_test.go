package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type nativePairTCPActor struct {
	f             *hubAccountTCPFixture
	owner, device *e2ee.Identity
	scope         e2ee.OwnerNativePairScope
	session       wire.AppNodeSession
}

// Real N2/N3 PQ over disposable TCP. The keys/Node are synthetic and there is
// no Runtime, native SID, queue invocation, Control inference or DB grant setup.
func nativePairTCP(t *testing.T) *nativePairTCPActor {
	t.Helper()
	f := newHubNodesTCPFixture(t)
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	enroll, ch, _, _ := n2Prepare(t, f, *material, device, owner)
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-pair-tcp", "synthetic pair fixture password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &wire.ActivationResult{})
	login := n2Login(t, f, device, enroll.DeviceID, "synthetic-pair-tcp", "synthetic pair fixture password")
	session := wire.AppNodeSession{Hub: f.hub, Origin: f.setup.Origin, AccountID: f.setup.AccountID, OwnerID: f.setup.OwnerID, DeviceID: enroll.DeviceID, AccountEpoch: login.AccountEpoch, DeviceEpoch: login.DeviceEpoch, Token: login.SessionToken}
	statusRequest, err := wire.NewAppNodeStatus(session, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, initial := n3Authority(t, f, device, statusRequest)
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	status, raw := n3HTTP(t, f, http.MethodGet, "/v2/node/identity", "", nil)
	var nodeHub nodebinding.HubIdentity
	if status != 200 || json.Unmarshal(raw, &nodeHub) != nil {
		t.Fatal("synthetic Node public identity unavailable")
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID = "synthetic-pair-tcp-node"
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: nodeID, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: nodeHub.PublicIdentity, HubKeyVersion: nodeHub.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, nodeHub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	input := nodeControlPairingInput{NodeID: nodeID, NodeName: "Synthetic bounded pair Node", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: f.hub.HubID, HubPublicIdentity: nodeHub.PublicIdentity, HubKeyVersion: nodeHub.KeyVersion, HubFingerprint: nodeHub.Fingerprint}
	request, _ := json.Marshal(input)
	status, raw = n3HTTP(t, f, http.MethodPost, "/v2/nodes/device-code", "", request)
	var code nodebinding.DeviceCode
	if status != http.StatusCreated || json.Unmarshal(raw, &code) != nil {
		t.Fatal("real synthetic Node proof refused")
	}
	p, err := wire.NewAppNodePrepare(session, initial.Result.Authority.Scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: code.UserCode}, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, _, preview := n3Authority(t, f, device, p)
	c, err := wire.NewAppNodeComplete(session, p, original, *preview.Challenge, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n3Authority(t, f, device, c)
	confirm, err := wire.SealAppNodeConfirmation(device, f.hub, preview.Challenge.Claims, code.UserCode, initial.Result.Authority.Counters.LastRequestSequence+1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	status, reply := n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != 200 {
		t.Fatal("actual Node confirmation refused")
	}
	confirmed, err := wire.OpenAppNodeConfirmationResponse(device, f.hub, preview.Challenge.Claims, confirm, reply, initial.Result.Authority.Counters.NextResponseSequence)
	if err != nil || !confirmed.OK || confirmed.Binding == nil {
		t.Fatal("actual Node confirmation authentication failed", err)
	}
	scope := initial.Result.Authority.Scope
	scope.HeadVersion = 0
	return &nativePairTCPActor{f: f, owner: owner, device: device, scope: e2ee.OwnerNativePairScope{Actor: scope, Node: *confirmed.Binding}, session: session}
}

func (a *nativePairTCPActor) context(t *testing.T) wire.NativePairRequestContext {
	t.Helper()
	s := a.scope.Actor
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return wire.NativePairRequestContext{Origin: s.Origin, HubID: s.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountSessionID: s.AccountSessionID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, ClientSessionEpoch: s.ClientSessionEpoch, RequestID: id, ClientNonce: nonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}
func (a *nativePairTCPActor) preview(t *testing.T) wire.NativePairBootstrapPrepare {
	t.Helper()
	c := a.context(t)
	at, _ := time.Parse(time.RFC3339Nano, c.IssuedAt)
	claims := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairBootstrapPreview, Scope: a.scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano), Bootstrap: &e2ee.NativePairBootstrapClaims{GroupLabel: "Synthetic TCP pair", Runtime: "codex", SlotCount: 2, Policy: e2ee.NativePairFixedPeerPolicy()}}
	proof, err := e2ee.SignOwnerNativePair(a.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	return wire.NativePairBootstrapPrepare{Format: wire.NativePairFormat, Context: c, SessionToken: a.session.Token, OwnerProof: proof}
}
func (a *nativePairTCPActor) seal(t *testing.T, body any) []byte {
	t.Helper()
	raw, err := wire.SealClientRequest(a.device, a.f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (a *nativePairTCPActor) post(t *testing.T, op string, raw []byte) []byte {
	t.Helper()
	start := time.Now()
	status, packet := n3HTTP(t, a.f, http.MethodPost, wire.NativePairHTTPPath(op), "", raw)
	t.Logf("synthetic native-pair HTTP operation=%s request_bytes=%d response_bytes=%d elapsed_us=%d status=%d", op, len(raw), len(packet), time.Since(start).Microseconds(), status)
	if status != 200 {
		t.Fatal("guarded development protocol HTTP refused", op, status)
	}
	return packet
}

func TestNativePairPreparationRealTCPExactBootstrapAndRecovery(t *testing.T) {
	a := nativePairTCP(t)
	status, raw := n3HTTP(t, a.f, http.MethodGet, wire.NativePairCapabilitiesPath, "", nil)
	var caps wire.NativePairCapabilities
	if status != 200 || json.Unmarshal(raw, &caps) != nil || caps.Available || caps.ServeMode != "--hub-nodes-only" {
		t.Fatal("preparation incorrectly advertises readiness")
	}
	if _, err := wire.DecodeNativePairCapabilities(raw); err == nil {
		t.Fatal("supported App could create a pending action from unavailable discovery")
	}
	// This is an explicit development API probe, not the App discovery flow or
	// a complete/native conversation acceptance. It exercises authenticated HTTP.
	q := a.preview(t)
	original := a.seal(t, q)
	reply := a.post(t, wire.OperationNativePairBootstrapPrepare, original)
	var ch wire.NativePairBootstrapChallenge
	if wire.OpenClientResponse(a.device, a.f.hub, original, reply, &ch) != nil || wire.ValidateNativePairBootstrapTarget(q, original, ch, a.f.hub, time.Now().UTC()) != nil {
		t.Fatal("HTTP challenge changed Owner target")
	}
	if retry := a.post(t, wire.OperationNativePairBootstrapPrepare, original); !bytes.Equal(reply, retry) {
		t.Fatal("HTTP exact retry changed challenge")
	}
	c := a.context(t)
	claims := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairBootstrapCommit, Scope: ch.Scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: ch.ProofExpiresAt, Bootstrap: &ch.Bootstrap}
	proof, err := e2ee.SignOwnerNativePair(a.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	complete := wire.NativePairBootstrapComplete{Format: wire.NativePairFormat, Context: c, SessionToken: a.session.Token, OwnerProof: proof}
	packet := a.seal(t, complete)
	committed := a.post(t, wire.OperationNativePairBootstrapComplete, packet)
	var result wire.NativePairResult
	if wire.OpenClientResponse(a.device, a.f.hub, packet, committed, &result) != nil || result.State != wire.NativePairWaitingJoin || result.SlotA != nil || result.SlotB != nil {
		t.Fatal("HTTP bootstrap inferred peer identities or permissions")
	}
	rq := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: a.context(t), PairID: result.PairID, OriginalPacket: packet}
	rpacket := a.seal(t, rq)
	recovered := a.post(t, wire.OperationNativePairReconcile, rpacket)
	var rr wire.NativePairReconciled
	if wire.OpenClientResponse(a.device, a.f.hub, rpacket, recovered, &rr) != nil || !bytes.Equal(rr.ReceiptPacket, committed) || wire.ValidateNativePairReconcileTarget(rr, result.PairID, packet) != nil {
		t.Fatal("HTTP recovery lost exact committed receipt")
	}
	networks, err := a.f.db.ListNetworks()
	if err != nil || len(networks) != 1 || networks[0].ID != ch.Bootstrap.NetworkID {
		t.Fatal("exact retries duplicated the private Network")
	}
	if !reflect.DeepEqual(ch.Scope.Actor.OwnerPublic, a.owner.Public()) || ch.Scope.Node.NodeID != a.scope.Node.NodeID {
		t.Fatal("Owner/Node identity changed")
	}
	for _, path := range []string{"/v2/fabric/node/join", "/v2/fabric/node/networks/join", "/v2/fabric/snapshot", "/v1/workers"} {
		status, _ := n3HTTP(t, a.f, http.MethodPost, path, "", []byte(`{}`))
		if status != 404 {
			t.Fatal("preparation opened an unrelated surface", path, status)
		}
	}
}

func TestNativePairPreparationRealTCPUnadmittedOriginalAndNegativeFrames(t *testing.T) {
	a := nativePairTCP(t)
	q := a.preview(t)
	original := a.seal(t, q)
	rq := wire.NativePairReconcileRequest{Format: wire.NativePairFormat, Context: a.context(t), OriginalPacket: original}
	rpacket := a.seal(t, rq)
	reply := a.post(t, wire.OperationNativePairReconcile, rpacket)
	var rr wire.NativePairReconciled
	if wire.OpenClientResponse(a.device, a.f.hub, rpacket, reply, &rr) != nil || rr.State != "REJECTED_FENCED" || rr.PairID != "" || wire.ValidateNativePairReconcileTarget(rr, "", original) != nil {
		t.Fatal("unknown-ID original did not receive authenticated permanent no-effect fence")
	}
	var fence wire.NativePairBootstrapFence
	if wire.OpenClientResponse(a.device, a.f.hub, original, rr.ReceiptPacket, &fence) != nil || !fence.NoEffect {
		t.Fatal("original no-effect fence failed authentication")
	}
	if late := a.post(t, wire.OperationNativePairBootstrapPrepare, original); !bytes.Equal(late, rr.ReceiptPacket) {
		t.Fatal("late original escaped permanent fence")
	}
	networks, err := a.f.db.ListNetworks()
	if err != nil || len(networks) != 0 {
		t.Fatal("fenced original created domain state")
	}
	for _, body := range [][]byte{[]byte(`{}`), append(append([]byte(nil), original...), ' '), bytes.Repeat([]byte{'x'}, wire.MaxNativePairOriginalBytes+1)} {
		status, _ := n3HTTP(t, a.f, http.MethodPost, wire.NativePairHTTPPath(wire.OperationNativePairBootstrapPrepare), "", body)
		if status != http.StatusForbidden && status != http.StatusRequestEntityTooLarge {
			t.Fatal("invalid HTTP frame admitted", status)
		}
	}
	r, err := http.NewRequest(http.MethodPost, a.f.http.URL+wire.NativePairHTTPPath(wire.OperationNativePairBootstrapPrepare), bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", "https://another-synthetic.invalid")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("wrong origin admitted")
	}
	// A registered, logged-in device can create its own valid PQ envelope but
	// cannot supply Owner authority. Bypass only the local client validator to
	// exercise the server's independent proof requirement.
	missing := a.preview(t)
	missing.OwnerProof = nil
	binding, route, err := wire.NewClientRoute(a.f.hub, missing, a.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(missing)
	inner, err := clientwire.SealRequestWithLimits(a.device, a.f.hub.Public, binding, route, body, wire.MaxNativePairBodyBytes, wire.MaxNativePairInnerPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	var ip clientwire.Packet
	if json.Unmarshal(inner, &ip) != nil {
		t.Fatal("synthetic packet projection failed")
	}
	noOwner, _ := json.Marshal(wire.Packet{Format: wire.PacketFormat, Version: wire.PacketVersion, SenderPublicIdentity: a.device.Public(), Packet: ip})
	if status, _ := n3HTTP(t, a.f, http.MethodPost, wire.NativePairHTTPPath(wire.OperationNativePairBootstrapPrepare), "", noOwner); status != http.StatusForbidden {
		t.Fatal("account/device login became Owner authority")
	}
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forged := a.preview(t)
	var fp e2ee.OwnerNativePairProof
	if json.Unmarshal(forged.OwnerProof, &fp) != nil {
		t.Fatal("synthetic Owner proof malformed")
	}
	fp.Claims.Scope.Actor.OwnerPublic = other.Public()
	fp.Claims.Scope.Node.OwnerKeyID = other.Public().ID
	forged.OwnerProof, err = e2ee.SignOwnerNativePair(other, fp.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := n3HTTP(t, a.f, http.MethodPost, wire.NativePairHTTPPath(wire.OperationNativePairBootstrapPrepare), "", a.seal(t, forged)); status != http.StatusForbidden {
		t.Fatal("logged-in device replaced the existing Owner key")
	}
	wrong := a.preview(t)
	if json.Unmarshal(wrong.OwnerProof, &fp) != nil {
		t.Fatal("synthetic Owner proof malformed")
	}
	fp.Claims.Scope.Node.NodeID = "synthetic-other-node"
	wrong.OwnerProof, err = e2ee.SignOwnerNativePair(a.owner, fp.Claims)
	if err != nil {
		t.Fatal(err)
	}
	wrongPacket := a.seal(t, wrong)
	wrongReply := a.post(t, wire.OperationNativePairBootstrapPrepare, wrongPacket)
	var wrongFence wire.NativePairBootstrapFence
	if wire.OpenClientResponse(a.device, a.f.hub, wrongPacket, wrongReply, &wrongFence) != nil || !wrongFence.NoEffect {
		t.Fatal("Owner proof adopted an unapproved Node tuple")
	}
}
