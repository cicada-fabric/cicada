package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type n3StoreFixture struct {
	db                                           *Store
	path                                         string
	hubPrivate, owner, device, nodeControl, node *e2ee.Identity
	hub                                          wire.HubIdentity
	session                                      wire.AppNodeSession
	scope                                        e2ee.OwnerAppNodeScope
	now                                          time.Time
	code                                         string
}

// N2 history and Node proof rows below are visibly synthetic Store guard
// fixtures, not proof of the prior HTTP enrollment or Node proof ceremony.
// Every N3 Owner signature and N3/Client PQ packet in these tests is real.
func n3Fixture(t *testing.T, completedN2 bool) *n3StoreFixture {
	t.Helper()
	f := &n3StoreFixture{path: filepath.Join(t.TempDir(), "state", "cicada.sqlite3"), now: time.Now().UTC(), code: "23456789ABCD"}
	var err error
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	setup, err := f.db.InitializeHubOwnerLocal("Synthetic N3 transaction fixture", "https://n3.synthetic.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	keys := []**e2ee.Identity{&f.hubPrivate, &f.owner, &f.device, &f.nodeControl, &f.node}
	for _, k := range keys {
		*k, err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.db.RegisterOwnerApprovalKeyLocal(setup.OwnerID, f.owner.Public()); err != nil {
		t.Fatal(err)
	}
	deviceID := wire.AccountDeviceIDPrefix + strings.Repeat("a", 32)
	proof, err := f.owner.SignOwnerDeviceGrant(setup.OwnerID, deviceID, f.device.Public(), setup.HubID, e2ee.OwnerDevicePurposeControl, f.now, f.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{OwnerID: setup.OwnerID, OwnerKeyID: f.owner.Public().ID, DeviceID: deviceID, DevicePublic: f.device.Public(), OwnerDeviceGrant: proof}); err != nil {
		t.Fatal(err)
	}
	f.hub = wire.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: f.hubPrivate.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	fp, err := wire.HubFingerprint(f.hub)
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{7}, wire.MaxSessionTokenBytes)
	f.session = wire.AppNodeSession{Hub: f.hub, Origin: setup.Origin, AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: deviceID, AccountEpoch: 1, DeviceEpoch: 1, Token: token}
	f.scope = e2ee.OwnerAppNodeScope{Version: 1, Origin: setup.Origin, HubID: setup.HubID, HubFingerprint: fp, AccountID: setup.AccountID, AccountSessionID: strings.Repeat("c", 32), AccountSessionExpiresAt: appNodeStamp(f.now.Add(time.Hour)), OwnerID: setup.OwnerID, OwnerPublic: f.owner.Public(), OwnerKeyVersion: 1, DeviceID: deviceID, DevicePublic: f.device.Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, TransportPolicy: wire.AppNodeTransportHTTPS}
	pub, _ := json.Marshal(f.device.Public())
	if _, err = f.db.db.Exec(`INSERT INTO hub_account_credentials_v1 VALUES(?,?,?,'PBKDF2-SHA256-600000-v1',?,?,1)`, setup.AccountID, setup.OwnerID, "synthetic-n3", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.db.Exec(`INSERT INTO hub_account_devices_v1 VALUES(?,?,?,?,1,'ACTIVE',?)`, setup.AccountID, setup.OwnerID, deviceID, string(pub), appNodeStamp(f.now)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.db.Exec(`INSERT INTO hub_account_sessions_v1 VALUES(?,?,?,?,1,1,1,?,'ACTIVE',?)`, f.scope.AccountSessionID, setup.AccountID, setup.OwnerID, deviceID, AccountDigest("session-token", token), f.scope.AccountSessionExpiresAt); err != nil {
		t.Fatal(err)
	}
	n2 := wire.ActivationBinding{Format: wire.ActivationFormat, Purpose: wire.PurposeInitialActivation, Origin: setup.Origin, HubID: setup.HubID, HubFingerprint: fp, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ActivationID: strings.Repeat("b", 32), SetupEpoch: 1, AccountEpoch: 1, DeviceEpoch: 1, OwnerPublic: f.owner.Public(), DeviceID: deviceID, DevicePublic: f.device.Public(), AllowedOperations: wire.ActivationAllowedOperations(), LeaseExpiresAt: appNodeStamp(f.now.Add(-time.Minute))}
	bind, _ := json.Marshal(n2)
	material, _ := json.Marshal(wire.ActivationMaterial{Format: wire.ActivationFormat, ActivationID: n2.ActivationID})
	state := "PREPARED"
	if completedN2 {
		state = "COMPLETED"
	}
	if _, err = f.db.db.Exec(`INSERT INTO hub_owner_activation_v1(activation_id,account_id,owner_id,material_json,code_digest,epoch,state,binding_json,created_at) VALUES(?,?,?,?,?,1,?,?,?)`, n2.ActivationID, setup.AccountID, setup.OwnerID, string(material), strings.Repeat("e", 64), state, string(bind), appNodeStamp(f.now)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.db.Exec(`INSERT INTO hub_app_leases_v1 VALUES(?,?,?,?,?,1,1,?,?,'ACTIVE')`, setup.OwnerID, deviceID, setup.AccountID, n2.ActivationID, string(bind), f.owner.Public().ID, n2.LeaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	f.candidate(t, f.code, "synthetic-n3-node")
	return f
}

func (f *n3StoreFixture) candidate(t *testing.T, code, nodeID string) {
	t.Helper()
	digest, err := wire.AppNodeCodeDigest(f.hub.HubID, code)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.db.StartNodeControlKeyRequest(NodeControlKeyRequestInput{Mode: "INITIAL", NodeID: nodeID, NodeName: "Synthetic relay-only Node", CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), CodeDigest: digest, NodePublicIdentity: f.node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(f.node.Public()), ProofPacket: []byte("SYNTHETIC-STORE-GUARD-NOT-A-NODE-PROOF"), HubPublicIdentity: f.nodeControl.Public(), HubKeyVersion: 1, HubFingerprint: nodewire.IdentityFingerprint(f.nodeControl.Public()), ExpiresAt: f.now.Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
}
func (f *n3StoreFixture) input(t *testing.T, body any, at time.Time) (HubAppNodeAuthorityInput, HubAppNodeSeal) {
	t.Helper()
	raw, err := wire.SealClientRequest(f.device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := wire.NewClientRoute(f.hub, body, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	// Authenticate the same typed body before the Store boundary, as HTTP does.
	var opened any
	switch body.(type) {
	case wire.AppNodePrepare:
		opened = &wire.AppNodePrepare{}
	case wire.AppNodeComplete:
		opened = &wire.AppNodeComplete{}
	case wire.AppNodeCancel:
		opened = &wire.AppNodeCancel{}
	case wire.AppNodeStatusRequest:
		opened = &wire.AppNodeStatusRequest{}
	case wire.AppNodeReconcileRequest:
		opened = &wire.AppNodeReconcileRequest{}
	}
	pub := f.device.Public()
	if err = wire.OpenRequestAt(f.hubPrivate, &pub, b, r, raw, opened, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reflect.ValueOf(opened).Elem().Interface(), body) {
		t.Fatal("authenticated Store input changed")
	}
	return HubAppNodeAuthorityInput{Hub: f.hub, NodeControlPublic: f.nodeControl.Public(), Device: f.device.Public(), Packet: raw, Body: body, At: at}, func(v any) ([]byte, error) { return wire.SealResponse(f.hubPrivate, f.device.Public(), r, v) }
}
func (f *n3StoreFixture) call(t *testing.T, body any, at time.Time) (HubAppNodeAuthorityInput, wire.AppNodeResponse, []byte) {
	t.Helper()
	in, seal := f.input(t, body, at)
	packet, err := f.db.ProcessHubAppNodeAuthority(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.OpenAppNodeResponse(f.device, f.hub, in.Packet, packet)
	if err != nil {
		t.Fatal("invalid sealed Store response", err)
	}
	return in, out, packet
}
func (f *n3StoreFixture) prepare(t *testing.T, scope e2ee.OwnerAppNodeScope, target wire.AppNodePrepareTarget, at time.Time) (wire.AppNodePrepare, HubAppNodeAuthorityInput, wire.AppNodeChallenge) {
	t.Helper()
	p, err := wire.NewAppNodePrepare(f.session, scope, target, f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	in, out, _ := f.call(t, p, at)
	if out.Challenge == nil {
		t.Fatal("prepare rejected", out.Result.ErrorCode)
	}
	return p, in, *out.Challenge
}
func (f *n3StoreFixture) activate(t *testing.T) e2ee.OwnerAppNodeGrantClaims {
	t.Helper()
	p, in, ch := f.prepare(t, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}, f.now)
	c, err := wire.NewAppNodeComplete(f.session, p, in.Packet, ch, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ := f.call(t, c, f.now.Add(time.Second))
	if out.Result == nil || out.Result.State != wire.AppNodeCompleted || out.Result.Authority.State != wire.AppNodeActive {
		t.Fatal("grant not active")
	}
	return ch.Claims
}

func (f *n3StoreFixture) client(t *testing.T, g e2ee.OwnerAppNodeGrantClaims, sequence uint64, at time.Time) HubAppNodeClientInput {
	t.Helper()
	raw, err := wire.SealAppNodeConfirmation(f.device, f.hub, g, f.code, sequence, at)
	if err != nil {
		t.Fatal(err)
	}
	b := clientwire.Binding{HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, SessionEpoch: g.Scope.ClientSessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: 1}
	opened, err := clientwire.OpenRequest(f.hubPrivate, f.device.Public(), b, raw)
	if err != nil {
		t.Fatal(err)
	}
	r := opened.Route
	return HubAppNodeClientInput{Hub: f.hub, NodeControlPublic: f.nodeControl.Public(), Device: f.device.Public(), Packet: raw, Route: r, Code: f.code, CandidateDigest: g.Candidate.CandidateDigest, CandidateVersion: g.Candidate.Version, At: at, Seal: func(seq uint64, id string, binding *NodeControlKeyBinding, code string) ([]byte, error) {
		body := struct {
			Error       string `json:"error,omitempty"`
			OK          bool   `json:"ok"`
			OperationID string `json:"operation_id"`
			RequestID   string `json:"request_id"`
			Result      any    `json:"result,omitempty"`
		}{Error: code, OK: code == "", OperationID: r.OperationID, RequestID: id}
		if binding != nil {
			body.Result = binding
		}
		plain, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reply := r
		reply.Direction = clientwire.DirectionResponse
		reply.Sequence = seq
		reply.SenderKeyID, reply.ReceiverKeyID = reply.ReceiverKeyID, reply.SenderKeyID
		reply.SenderKeyVersion, reply.ReceiverKeyVersion = reply.ReceiverKeyVersion, reply.SenderKeyVersion
		return clientwire.SealResponse(f.hubPrivate, f.device.Public(), b, reply, plain)
	}}
}

func TestN3StoreAtomicConfirmationSealFailureExactRetryAndProvenance(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	in := f.client(t, g, 1, f.now.Add(2*time.Second))
	originalSeal := in.Seal
	in.Seal = func(uint64, string, *NodeControlKeyBinding, string) ([]byte, error) {
		return nil, errors.New("synthetic seal failure")
	}
	if _, err := f.db.ProcessHubAppNodeClient(in); err == nil {
		t.Fatal("seal failure committed")
	}
	d, err := f.db.GetClientDevice(g.Scope.OwnerID, g.Scope.DeviceID)
	if err != nil || d.LastRequestSeq != 0 || d.NextResponseSeq != 1 {
		t.Fatal("failed seal consumed counters", err)
	}
	var bindings int
	_ = f.db.db.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2 WHERE node_id='synthetic-n3-node'`).Scan(&bindings)
	if bindings != 0 {
		t.Fatal("failed seal left Node effect")
	}
	in.Seal = originalSeal
	packet, err := f.db.ProcessHubAppNodeClient(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, g, in.Packet, packet, 1)
	if err != nil || !out.OK || out.Binding == nil {
		t.Fatal("actual atomic response invalid", err)
	}
	retry, err := f.db.ProcessHubAppNodeClient(in)
	if err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("lost response did not recover exact ciphertext", err)
	}
	d, _ = f.db.GetClientDevice(g.Scope.OwnerID, g.Scope.DeviceID)
	if d.LastRequestSeq != 1 || d.NextResponseSeq != 2 {
		t.Fatal("retry consumed another slot")
	}
	status, err := wire.NewAppNodeStatus(f.session, g.GrantID, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, snap, _ := f.call(t, status, f.now.Add(3*time.Second))
	if snap.Result.Authority.RemainingConfirmations != 0 || len(snap.Result.Authority.AllowedOperations) != 0 || snap.Result.Node == nil || snap.Result.Node.Connectivity != "UNKNOWN" || snap.Result.Authority.ConfirmationProvenanceID == "" {
		t.Fatal("confirmed grant/provenance/unknown liveness missing")
	}
	second := f.client(t, g, 2, f.now.Add(4*time.Second))
	denied, err := f.db.ProcessHubAppNodeClient(second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, g, second.Packet, denied, 2)
	if err != nil || got.OK || got.Error != "CONFIRMATION_USED" {
		t.Fatal("one-use budget reused", err)
	}
}

func TestN3StoreConcurrentPrepareWinnerAndCompleteHeadCAS(t *testing.T) {
	f := n3Fixture(t, true)
	target := wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}
	p1, err := wire.NewAppNodePrepare(f.session, f.scope, target, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := wire.NewAppNodePrepare(f.session, f.scope, target, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	inputs := make([]HubAppNodeAuthorityInput, 2)
	seals := make([]HubAppNodeSeal, 2)
	inputs[0], seals[0] = f.input(t, p1, f.now)
	inputs[1], seals[1] = f.input(t, p2, f.now)
	packets := make([][]byte, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range inputs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			packets[i], errs[i] = f.db.ProcessHubAppNodeAuthority(inputs[i], seals[i])
		}(i)
	}
	wg.Wait()
	winners := 0
	var winner int
	var ch wire.AppNodeChallenge
	for i := range packets {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		out, err := wire.OpenAppNodeResponse(f.device, f.hub, inputs[i].Packet, packets[i])
		if err != nil {
			t.Fatal(err)
		}
		if out.Challenge != nil {
			winners++
			winner = i
			ch = *out.Challenge
		} else if out.Result.ErrorCode != "AUTHORITY_CONFLICT" {
			t.Fatal("wrong concurrent loser")
		}
	}
	if winners != 1 {
		t.Fatal("pending proposal did not have one winner")
	}
	prepare := p1
	if winner == 1 {
		prepare = p2
	}
	complete, err := wire.NewAppNodeComplete(f.session, prepare, inputs[winner].Packet, ch, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, out, packet := f.call(t, complete, f.now.Add(time.Second))
	if out.Result.Authority.CurrentHeadVersion != 1 {
		t.Fatal("prepare published head or complete missed CAS")
	}
	_, seal := f.input(t, complete, f.now.Add(2*time.Second))
	retry, err := f.db.ProcessHubAppNodeAuthority(in, seal)
	if err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("complete retry changed receipt", err)
	}
}

func TestN3StoreMissingCompletedN2AndInactiveHumanDenyAuthorityKeepDiagnostics(t *testing.T) {
	for _, kind := range []string{"missing-completion", "inactive-human", "wrong-kind", "changed-client-epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := n3Fixture(t, kind != "missing-completion")
			if kind == "inactive-human" {
				if _, err := f.db.db.Exec(`UPDATE principals SET status='inactive' WHERE id=?`, f.scope.OwnerID); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "wrong-kind" {
				if _, err := f.db.db.Exec(`UPDATE principals SET kind='ai' WHERE id=?`, f.scope.OwnerID); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "changed-client-epoch" {
				if _, err := f.db.AdvanceClientDeviceSessionEpoch(f.scope.OwnerID, f.scope.DeviceID, 1); err != nil {
					t.Fatal(err)
				}
			}
			p, err := wire.NewAppNodePrepare(f.session, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}, f.owner, f.now)
			if err != nil {
				t.Fatal(err)
			}
			_, out, _ := f.call(t, p, f.now)
			if out.Result == nil || out.Result.State != wire.AppNodeRejectedFenced || len(out.Result.Authority.AllowedOperations) != 0 {
				t.Fatal("account login established Node authority")
			}
			status, _ := wire.NewAppNodeStatus(f.session, "", f.now)
			_, diag, _ := f.call(t, status, f.now)
			if diag.Result.Node != nil || len(diag.Result.Authority.AllowedOperations) != 0 {
				t.Fatal("diagnostic regained authority")
			}
		})
	}
}

func TestN3StoreReadExistingLifecycleAndRelayOnlyObservation(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	confirm := f.client(t, g, 1, f.now.Add(2*time.Second))
	if _, err := f.db.ProcessHubAppNodeClient(confirm); err != nil {
		t.Fatal(err)
	}
	scope := f.scope
	scope.HeadVersion = 1
	early, err := wire.NewAppNodePrepare(f.session, scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetPrevious, PreviousGrantID: g.GrantID}, f.owner, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ := f.call(t, early, f.now.Add(3*time.Second))
	if out.Result == nil || out.Result.ErrorCode != "AUTHORITY_CONFLICT" {
		t.Fatal("early ACTIVE same-session refresh admitted")
	}
	cancel, err := wire.NewAppNodeCancel(f.session, g.GrantID, 1, f.now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ = f.call(t, cancel, f.now.Add(4*time.Second))
	if out.Result.Authority.LoginRequired || out.Result.Node != nil || len(out.Result.Authority.AllowedOperations) != 0 || out.Result.Authority.CurrentHeadVersion != 2 || out.Result.Authority.LatestGrantID != g.GrantID || out.Result.Authority.ConfirmationProvenanceID == "" {
		t.Fatal("self-cancel lost published provenance")
	}
	scope.HeadVersion = 2
	p, in, ch := f.prepare(t, scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetPrevious, PreviousGrantID: g.GrantID}, f.now.Add(5*time.Second))
	if ch.Claims.Binding == nil || ch.Claims.Candidate != nil || ch.Claims.Profile != wire.AppNodeProfileStatus || ch.Claims.ConfirmationLimit != 0 {
		t.Fatal("status preview adopted another candidate/profile")
	}
	complete, err := wire.NewAppNodeComplete(f.session, p, in.Packet, ch, f.owner, f.now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, out, _ = f.call(t, complete, f.now.Add(6*time.Second))
	if err := wire.ValidateAppNodeLiveResult(*out.Result, ch.Claims, f.hub, f.now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	// The accepted relay-only heartbeat never makes this Node worker-available.
	if _, err = f.db.db.Exec(`UPDATE machines SET last_seen=? WHERE id=?`, appNodeStamp(f.now.Add(7*time.Second)), g.Candidate.NodeID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		offset time.Duration
		state  string
	}{{"connected", 8 * time.Second, "CONNECTED"}, {"stale", 130 * time.Second, "STALE"}} {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := wire.NewAppNodeStatus(f.session, ch.Claims.GrantID, f.now.Add(tc.offset))
			_, snapshot, _ := f.call(t, status, f.now.Add(tc.offset))
			if snapshot.Result.Node == nil || snapshot.Result.Node.Connectivity != tc.state || len(snapshot.Result.Authority.AllowedOperations) != 0 {
				t.Fatal("relay heartbeat projection wrong")
			}
		})
	}
	var workerState string
	_ = f.db.db.QueryRow(`SELECT status FROM machines WHERE id=?`, g.Candidate.NodeID).Scan(&workerState)
	if workerState != "offline" {
		t.Fatal("liveness changed Worker availability")
	}
	for _, tc := range []struct{ name, stamp string }{{"future", appNodeStamp(f.now.Add(time.Hour))}, {"pre-approval", appNodeStamp(f.now)}, {"malformed", "synthetic-invalid-heartbeat"}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.db.db.Exec(`UPDATE machines SET last_seen=? WHERE id=?`, tc.stamp, g.Candidate.NodeID); err != nil {
				t.Fatal(err)
			}
			status, _ := wire.NewAppNodeStatus(f.session, ch.Claims.GrantID, f.now.Add(10*time.Second))
			_, snapshot, _ := f.call(t, status, f.now.Add(10*time.Second))
			if snapshot.Result.Node == nil || snapshot.Result.Node.Connectivity != "UNKNOWN" || snapshot.Result.Node.Known || !snapshot.Result.Node.Stale {
				t.Fatal("unaccepted heartbeat became connected")
			}
		})
	}
	// Authenticated but stale request context never receives current Node data.
	staleSession := f.session
	staleSession.AccountEpoch++
	status, _ := wire.NewAppNodeStatus(staleSession, ch.Claims.GrantID, f.now.Add(11*time.Second))
	_, snapshot, _ := f.call(t, status, f.now.Add(11*time.Second))
	if snapshot.Result.Node != nil || len(snapshot.Result.Authority.AllowedOperations) != 0 || !snapshot.Result.Authority.LoginRequired {
		t.Fatal("stale context received live Node")
	}
	// A packet tagged with READ_EXISTING cannot reuse the old INITIAL body.
	forged := g
	forged.GrantID = ch.Claims.GrantID
	bad := f.client(t, forged, 2, f.now.Add(12*time.Second))
	packet, err := f.db.ProcessHubAppNodeClient(bad)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, forged, bad.Packet, packet, 2)
	if err != nil || denied.OK || denied.Error != "CONFIRMATION_USED" {
		t.Fatal("READ_EXISTING acquired confirmation", err)
	}
}

func TestN3StoreReconcileFencesUnadmittedExactMutationAndReadExpiry(t *testing.T) {
	f := n3Fixture(t, true)
	p, err := wire.NewAppNodePrepare(f.session, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, originalSeal := f.input(t, p, f.now)
	intent, err := e2ee.VerifyOwnerAppNodePreview(f.owner.Public(), p.OwnerIntent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := wire.NewAppNodeReconcile(f.session, wire.AppNodeOriginalAuthority, strings.Repeat("f", 32), original.Packet, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	query, seal := f.input(t, wrong, f.now.Add(time.Second))
	query.Original, query.OriginalSeal = &original, originalSeal
	if _, err = f.db.ProcessHubAppNodeAuthority(query, seal); err == nil {
		t.Fatal("wrong grant settled another original")
	}
	reconcile, err := wire.NewAppNodeReconcile(f.session, wire.AppNodeOriginalAuthority, intent.GrantID, original.Packet, f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	query, seal = f.input(t, reconcile, f.now.Add(2*time.Second))
	query.Original, query.OriginalSeal = &original, originalSeal
	packet, err := f.db.ProcessHubAppNodeAuthority(query, seal)
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.OpenAppNodeResponse(f.device, f.hub, query.Packet, packet)
	if err != nil || out.Reconciled == nil || out.Reconciled.State != wire.AppNodeRejectedFenced {
		t.Fatal("mutation not authoritatively fenced", err)
	}
	if err := wire.ValidateAppNodeReconcileTarget(*out.Reconciled, wire.AppNodeOriginalAuthority, original.Packet); err != nil {
		t.Fatal(err)
	}
	late, err := f.db.ProcessHubAppNodeAuthority(original, originalSeal)
	if err != nil || !bytes.Equal(late, out.Reconciled.ReceiptPacket) {
		t.Fatal("late original escaped fence", err)
	}
	var count int
	_ = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1`).Scan(&count)
	if count != 0 {
		t.Fatal("fenced preview created grant")
	}
	// Unadmitted pure reads can close after sixty seconds without a permanent
	// effect/fence. They cannot be used to settle the mutation above.
	s, _ := wire.NewAppNodeStatus(f.session, "", f.now)
	read, readSeal := f.input(t, s, f.now.Add(2*time.Minute))
	raw, err := f.db.ProcessHubAppNodeAuthority(read, readSeal)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := wire.OpenAppNodeResponse(f.device, f.hub, read.Packet, raw)
	if err != nil || settled.Result.State != wire.AppNodeReadExpired || settled.Result.Node != nil {
		t.Fatal("aged read stranded", err)
	}
	// Aged reconciliation reconstructs from permanent target history after
	// its optional five-minute outer cache has expired.
	query.At = f.now.Add(7 * time.Minute)
	again, err := f.db.ProcessHubAppNodeAuthority(query, seal)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := wire.OpenAppNodeResponse(f.device, f.hub, query.Packet, again)
	if err != nil || !bytes.Equal(recovered.Reconciled.ReceiptPacket, out.Reconciled.ReceiptPacket) {
		t.Fatal("aged diagnostic lost target fence", err)
	}
}

func TestN3StoreReadOnlyExpiryDoesNotWriteGrantAndPollingHasNoLifetimeQuota(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	for i := 0; i < 140; i++ {
		at := f.now.Add(time.Duration(i) * time.Second)
		s, _ := wire.NewAppNodeStatus(f.session, g.GrantID, at)
		f.call(t, s, at)
	}
	var n int
	_ = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_node_reads_v1`).Scan(&n)
	if n > wire.MaxAppNodeReadCacheEntriesPerDevice {
		t.Fatal("read cache unbounded")
	}
	s, _ := wire.NewAppNodeStatus(f.session, g.GrantID, f.now.Add(16*time.Minute))
	_, snapshot, _ := f.call(t, s, f.now.Add(16*time.Minute))
	if snapshot.Result.Authority.LoginRequired || len(snapshot.Result.Authority.AllowedOperations) != 0 || snapshot.Result.Authority.State != wire.AppNodeExpired || snapshot.Result.Node != nil {
		t.Fatal("expired grant read current state")
	}
	var state string
	_ = f.db.db.QueryRow(`SELECT state FROM hub_app_node_grants_v1 WHERE grant_id=?`, g.GrantID).Scan(&state)
	if state != wire.AppNodeActive {
		t.Fatal("read-only status mutated grant")
	}
	d, _ := f.db.GetClientDevice(g.Scope.OwnerID, g.Scope.DeviceID)
	if d.LastRequestSeq != 0 || d.NextResponseSeq != 1 {
		t.Fatal("status consumed Client counters")
	}
}

func TestN3StoreClientReconcileSlotFenceCounterConflictAndDurableRecovery(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	original := f.client(t, g, 1, f.now.Add(2*time.Second))
	reconcile, err := wire.NewAppNodeReconcile(f.session, wire.AppNodeOriginalClient, g.GrantID, original.Packet, f.now.Add(16*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	query, seal := f.input(t, reconcile, f.now.Add(16*time.Minute))
	query.OriginalClient = &original
	packet, err := f.db.ProcessHubAppNodeAuthority(query, seal)
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.OpenAppNodeResponse(f.device, f.hub, query.Packet, packet)
	if err != nil || out.Reconciled.State != wire.AppNodeRejectedFenced {
		t.Fatal("expired unadmitted mutation not fenced", err)
	}
	receipt, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, g, original.Packet, out.Reconciled.ReceiptPacket, 1)
	if err != nil || receipt.OK {
		t.Fatal("fence did not use original route and reserved sequence", err)
	}
	late, err := f.db.ProcessHubAppNodeClient(original)
	if err != nil || !bytes.Equal(late, out.Reconciled.ReceiptPacket) {
		t.Fatal("late confirm escaped fence", err)
	}
	d, _ := f.db.GetClientDevice(g.Scope.OwnerID, g.Scope.DeviceID)
	if d.LastRequestSeq != 1 || d.NextResponseSeq != 2 {
		t.Fatal("fence did not consume exactly its next slot")
	}
	if err = f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := f.db.ProcessHubAppNodeClient(original)
	if err != nil || !bytes.Equal(recovered, late) {
		t.Fatal("restart lost permanent exact fence", err)
	}
	// Gapped sequence and changed-epoch requests never reset/skip a counter.
	for _, kind := range []string{"gap", "epoch"} {
		t.Run(kind, func(t *testing.T) {
			future := f.client(t, g, 3, f.now.Add(3*time.Second))
			if kind == "epoch" {
				if _, err := f.db.AdvanceClientDeviceSessionEpoch(g.Scope.OwnerID, g.Scope.DeviceID, 1); err != nil {
					t.Fatal(err)
				}
				future = f.client(t, g, 2, f.now.Add(3*time.Second))
			}
			r, _ := wire.NewAppNodeReconcile(f.session, wire.AppNodeOriginalClient, g.GrantID, future.Packet, f.now.Add(16*time.Minute))
			q, s := f.input(t, r, f.now.Add(16*time.Minute))
			q.OriginalClient = &future
			if _, err := f.db.ProcessHubAppNodeAuthority(q, s); !errors.Is(err, ErrClientRequestSequence) {
				t.Fatal("counter conflict was authoritatively settled", err)
			}
		})
	}
}

func TestN3StoreUnconfirmedTerminalCanUseNewInitialButConfirmedCannot(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		name := "unconfirmed"
		if confirmed {
			name = "confirmed"
		}
		t.Run(name, func(t *testing.T) {
			f := n3Fixture(t, true)
			g := f.activate(t)
			if confirmed {
				in := f.client(t, g, 1, f.now.Add(2*time.Second))
				if _, err := f.db.ProcessHubAppNodeClient(in); err != nil {
					t.Fatal(err)
				}
			}
			cancel, _ := wire.NewAppNodeCancel(f.session, g.GrantID, 1, f.now.Add(3*time.Second))
			f.call(t, cancel, f.now.Add(3*time.Second))
			code := "3456789ABCDE"
			f.candidate(t, code, "synthetic-other-node")
			scope := f.scope
			scope.HeadVersion = 2
			p, err := wire.NewAppNodePrepare(f.session, scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: code}, f.owner, f.now.Add(4*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			_, out, _ := f.call(t, p, f.now.Add(4*time.Second))
			if confirmed {
				if out.Result == nil || out.Result.ErrorCode != "AUTHORITY_CONFLICT" {
					t.Fatal("successful provenance silently adopted another Node")
				}
			} else if out.Challenge == nil || out.Challenge.Claims.Candidate.NodeID != "synthetic-other-node" || out.Challenge.Claims.Scope.HeadVersion != 3 {
				t.Fatal("unconfirmed first code stranded explicit new INITIAL")
			}
		})
	}
}

func TestN3StoreRestoreAndSecurityRevocationPreserveIdentityCountersAndHistory(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	original := f.client(t, g, 1, f.now.Add(2*time.Second))
	packet, err := f.db.ProcessHubAppNodeClient(original)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := f.db.HubAccountCredential(g.Scope.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := f.db.GetClientDevice(g.Scope.OwnerID, g.Scope.DeviceID)
	if err = f.db.fenceHubAccountRestore(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	setup, epoch, err := f.db.HubAccountSetup()
	if err != nil || epoch != 2 || setup.OwnerID != g.Scope.OwnerID || setup.AccountID != g.Scope.AccountID {
		t.Fatal("restore changed identity coordinates", err)
	}
	after, _ := f.db.GetClientDevice(g.Scope.OwnerID, g.Scope.DeviceID)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("restore reset Client identity/counters")
	}
	current, err := f.db.HubAccountCredential(g.Scope.AccountID)
	if err != nil || !reflect.DeepEqual(current, credential) {
		t.Fatal("restore rotated password credential", err)
	}
	key, err := f.db.GetOwnerApprovalKey(g.Scope.OwnerID, g.Scope.OwnerPublic.ID)
	if err != nil || !reflect.DeepEqual(key.Public, g.Scope.OwnerPublic) {
		t.Fatal("restore rotated Owner", err)
	}
	status, _ := wire.NewAppNodeStatus(f.session, g.GrantID, f.now.Add(3*time.Second))
	_, snapshot, _ := f.call(t, status, f.now.Add(3*time.Second))
	if snapshot.Result.Authority.State != wire.AppNodeRevoked || snapshot.Result.Node != nil || len(snapshot.Result.Authority.AllowedOperations) != 0 {
		t.Fatal("restore revived N3")
	}
	retry, err := f.db.ProcessHubAppNodeClient(original)
	if err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("restore erased historical outcome", err)
	}
	if _, err = f.db.RevokeOwnerApprovalKeyLocal(g.Scope.OwnerID, g.Scope.OwnerPublic.ID, 1); err != nil {
		t.Fatal(err)
	}
	status, _ = wire.NewAppNodeStatus(f.session, g.GrantID, f.now.Add(4*time.Second))
	_, snapshot, _ = f.call(t, status, f.now.Add(4*time.Second))
	if snapshot.Result.Authority.RootState != wire.RootUnavailableState || snapshot.Result.Node != nil {
		t.Fatal("revoked Root regained status authority")
	}
	for _, stmt := range []string{`DELETE FROM hub_app_node_heads_v1`, `DELETE FROM hub_app_node_grants_v1`, `DELETE FROM hub_app_node_operations_v1`, `DELETE FROM hub_app_node_provenance_v1`, `UPDATE hub_app_node_grants_v1 SET remaining=1 WHERE remaining=0`, `UPDATE hub_app_node_heads_v1 SET head_version=0`} {
		if _, err = f.db.db.Exec(stmt); err == nil {
			t.Fatal("permanent N3 history/floor could be erased or reset")
		}
	}
}
