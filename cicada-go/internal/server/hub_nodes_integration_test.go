package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func newHubNodesTCPFixture(t *testing.T) *hubAccountTCPFixture {
	t.Helper()
	tcp := httptest.NewUnstartedServer(nil)
	f := &hubAccountTCPFixture{stateDir: filepath.Join(t.TempDir(), "state")}
	f.dbPath = filepath.Join(f.stateDir, "cicada.sqlite3")
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.setup, err = f.db.InitializeHubOwnerLocal("Synthetic N3 TCP Owner", "http://"+tcp.Listener.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	f.ids, err = hubidentity.LoadOrCreate(f.stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = hubowner.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.auth, err = hubauth.NewServiceWithNodeAuthority(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.hub, err = f.auth.HubIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := hubnodes.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHubNodesHandler(f.owner, f.auth, nodes).(*hubNodesHandler)
	if h.base.control != nil {
		t.Fatal("Hub Nodes composition created Control")
	}
	tcp.Config.Handler = h
	tcp.Start()
	f.http = tcp
	t.Cleanup(func() { f.http.Close(); f.db.Close() })
	return f
}

func n3HTTP(t *testing.T, f *hubAccountTCPFixture, method, path, token string, raw []byte) (int, []byte) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		r, err := http.NewRequest(method, f.http.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", f.setup.Origin)
		if token != "" {
			r.Header.Set("Authorization", "CicadaNode "+token)
		}
		client := f.client
		if client == nil {
			client = http.DefaultClient
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxPacketBytes+1))
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode == http.StatusTooManyRequests || (response.StatusCode == http.StatusServiceUnavailable && wire.NodePairTrustHTTPPath(hubauth.NodePairTrustOperationForPath(path)) == path) {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		return response.StatusCode, data
	}
	t.Fatal("synthetic N3 admission did not recover")
	return 0, nil
}
func n3Authority(t *testing.T, f *hubAccountTCPFixture, device *e2ee.Identity, body any) ([]byte, []byte, wire.AppNodeResponse) {
	t.Helper()
	raw, err := wire.SealClientRequest(device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	_, route, err := wire.NewClientRoute(f.hub, body, device.Public())
	if err != nil {
		t.Fatal(err)
	}
	status, packet := n3HTTP(t, f, http.MethodPost, wire.AppNodeHTTPPath(route.Operation), "", raw)
	if status != http.StatusOK {
		t.Fatalf("N3 authority %s HTTP %d", route.Operation, status)
	}
	out, err := wire.OpenAppNodeResponse(device, f.hub, raw, packet)
	if err != nil {
		t.Fatal("N3 response crypto/schema", err)
	}
	return raw, packet, out
}

func TestN3HubNodesRealTCPActivationProofConfirmHeartbeatAndReadExisting(t *testing.T) {
	f := newHubNodesTCPFixture(t)
	status, metadata := n3HTTP(t, f, http.MethodGet, wire.AppNodeCapabilitiesPath, "", nil)
	caps, err := wire.DecodeAppNodeCapabilities(metadata)
	if status != 200 || err != nil || caps.TransportPolicy != wire.AppNodeTransportLoopbackTest {
		t.Fatal("bounded public discovery unavailable", status, err)
	}
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
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-n3-tcp", "synthetic retained N3 account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &wire.ActivationResult{})
	login := n2Login(t, f, device, enroll.DeviceID, "synthetic-n3-tcp", "synthetic retained N3 account password")
	session := wire.AppNodeSession{Hub: f.hub, Origin: f.setup.Origin, AccountID: f.setup.AccountID, OwnerID: f.setup.OwnerID, DeviceID: enroll.DeviceID, AccountEpoch: login.AccountEpoch, DeviceEpoch: login.DeviceEpoch, Token: login.SessionToken}
	query, err := wire.NewAppNodeStatus(session, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, bootstrap := n3Authority(t, f, device, query)
	if bootstrap.Result.Authority.RootState != wire.RootActiveState || bootstrap.Result.Authority.LoginRequired || bootstrap.Result.Authority.CurrentHeadVersion != 0 || bootstrap.Result.Node != nil {
		t.Fatal("login silently adopted Node authority or missed retained Root")
	}

	// Real independent Node proof, local bearer and both full application keys.
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	status, raw := n3HTTP(t, f, http.MethodGet, "/v2/node/identity", "", nil)
	var nodeHub nodebinding.HubIdentity
	if status != 200 || json.Unmarshal(raw, &nodeHub) != nil {
		t.Fatal("Node public identity unavailable")
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "synthetic-n3-tcp-node"
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.hub.HubID, NodeID: nodeID, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: nodeHub.PublicIdentity, HubKeyVersion: nodeHub.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, nodeHub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	input := nodeControlPairingInput{NodeID: nodeID, NodeName: "Synthetic Ubuntu relay Node", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: f.hub.HubID, HubPublicIdentity: nodeHub.PublicIdentity, HubKeyVersion: nodeHub.KeyVersion, HubFingerprint: nodeHub.Fingerprint}
	request, _ := json.Marshal(input)
	status, raw = n3HTTP(t, f, http.MethodPost, "/v2/nodes/device-code", "", request)
	var code nodebinding.DeviceCode
	if status != http.StatusCreated || json.Unmarshal(raw, &code) != nil || code.Candidate == nil {
		t.Fatal("real Node proof refused", status)
	}
	p, err := wire.NewAppNodePrepare(session, bootstrap.Result.Authority.Scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: code.UserCode}, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, previewPacket, preview := n3Authority(t, f, device, p)
	if preview.Challenge == nil || !reflect.DeepEqual(preview.Challenge.Claims.Candidate.NodePublic, node.Public()) || !reflect.DeepEqual(preview.Challenge.Claims.Candidate.HubNodeControlPublic, nodeHub.PublicIdentity) {
		t.Fatal("Owner preview did not resolve exact Node keys")
	}
	status, retry := n3HTTP(t, f, http.MethodPost, wire.AppNodeHTTPPath(wire.OperationAppNodePrepare), "", original)
	if status != 200 || !bytes.Equal(retry, previewPacket) {
		t.Fatal("lost preview response changed")
	}
	c, err := wire.NewAppNodeComplete(session, p, original, *preview.Challenge, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, published := n3Authority(t, f, device, c)
	if published.Result.Authority.State != wire.AppNodeActive || published.Result.Authority.RemainingConfirmations != 1 || published.Result.Node != nil {
		t.Fatal("grant completion implicitly confirmed Node")
	}
	g := preview.Challenge.Claims
	confirm, err := wire.SealAppNodeConfirmation(device, f.hub, g, code.UserCode, bootstrap.Result.Authority.Counters.LastRequestSequence+1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	status, confirmedPacket := n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != 200 {
		t.Fatal("N3 atomic confirmation refused", status)
	}
	confirmed, err := wire.OpenAppNodeConfirmationResponse(device, f.hub, g, confirm, confirmedPacket, bootstrap.Result.Authority.Counters.NextResponseSequence)
	if err != nil || !confirmed.OK || confirmed.Binding == nil {
		t.Fatal("confirmed response tuple failed", err)
	}
	status, retry = n3HTTP(t, f, http.MethodPost, "/v2/client/rpc", "", confirm)
	if status != 200 || !bytes.Equal(retry, confirmedPacket) {
		t.Fatal("lost confirmation response was redispatched")
	}
	binding := nodewire.Binding{HubID: f.hub.HubID, NodeID: nodeID, BindingID: confirmed.Binding.OwnerBindingID, BindingVersion: confirmed.Binding.BindingVersion, NodeKeyEpoch: confirmed.Binding.NodeKeyEpoch, NodeKeyVersion: confirmed.Binding.NodeKeyVersion, HubKeyVersion: confirmed.Binding.HubNodeControlKeyVersion, NodeKey: node.Public(), HubKey: nodeHub.PublicIdentity}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: binding.HubID, NodeID: nodeID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch, Sequence: 1, OperationID: "synthetic-n3-node-status", Operation: "node.binding.status", SenderKeyID: node.Public().ID, SenderKeyVersion: binding.NodeKeyVersion, ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	nodeRequest, err := nodewire.SealRequest(node, binding.HubKey, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	status, nodeReply := n3HTTP(t, f, http.MethodPost, "/v2/node/control/rpc", token, nodeRequest)
	opened, err := nodewire.OpenResponse(node, binding.HubKey, binding, nodeReply)
	if status != 200 || err != nil || opened.Route.OperationID != route.OperationID {
		t.Fatal("exact Node PQ binding-status unavailable", status, err)
	}
	status, retry = n3HTTP(t, f, http.MethodPost, "/v2/node/control/rpc", token, nodeRequest)
	if status != 200 || !bytes.Equal(retry, nodeReply) {
		t.Fatal("Node status response retry changed")
	}
	route.Sequence = 2
	route.Operation = "node.jobs.list"
	route.OperationID = "synthetic-n3-forbidden-node-jobs"
	forbidden, err := nodewire.SealRequest(node, binding.HubKey, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, "/v2/node/control/rpc", token, forbidden)
	if status != http.StatusForbidden {
		t.Fatal("pure Hub allowed Node Worker RPC", status)
	}
	query, _ = wire.NewAppNodeStatus(session, g.GrantID, time.Now().UTC())
	_, _, unknown := n3Authority(t, f, device, query)
	if unknown.Result.Node == nil || unknown.Result.Node.Connectivity != "UNKNOWN" || unknown.Result.Authority.RemainingConfirmations != 0 {
		t.Fatal("binding was treated as heartbeat")
	}
	status, _ = n3HTTP(t, f, http.MethodPost, "/v2/relay/nodes/"+nodeID+"/heartbeat", token, []byte(`{}`))
	if status != http.StatusNoContent {
		t.Fatal("relay-only heartbeat refused", status)
	}
	claimPath := "/v2/fabric/node/networks/direct/claim"
	claim, _ := json.Marshal(map[string]any{"node_id": nodeID, "consumer_id": "synthetic-n3-node-consumer", "limit": 1})
	status, _ = n3HTTP(t, f, http.MethodPost, claimPath, token, claim)
	if status != http.StatusOK {
		t.Fatal("idle exact Node claim unavailable", status)
	}
	status, _ = n3HTTP(t, f, http.MethodPost, claimPath, "", claim)
	if status != http.StatusUnauthorized {
		t.Fatal("claim accepted missing Node credential", status)
	}
	wrongClaim, _ := json.Marshal(map[string]any{"node_id": "synthetic-n3-other-node", "consumer_id": "synthetic-n3-node-consumer", "limit": 1})
	status, _ = n3HTTP(t, f, http.MethodPost, claimPath, token, wrongClaim)
	if status != http.StatusForbidden {
		t.Fatal("claim accepted another Node ID", status)
	}
	query, _ = wire.NewAppNodeStatus(session, g.GrantID, time.Now().UTC())
	_, _, connected := n3Authority(t, f, device, query)
	if connected.Result.Node == nil || connected.Result.Node.Connectivity != "CONNECTED" || wire.ValidateAppNodeLiveResult(*connected.Result, g, f.hub, time.Now().UTC()) != nil {
		if connected.Result.Node != nil {
			t.Logf("synthetic timestamp diagnostics: state=%s heartbeat=%s observed=%s approved=%s", connected.Result.Node.Connectivity, connected.Result.Node.LastHeartbeatAt, connected.Result.Node.ObservedAt, confirmed.Binding.ApprovedAt)
		}
		t.Fatal("accepted relay heartbeat did not produce exact live observation")
	}
	machines, err := f.db.ListMachines()
	if err != nil || len(machines) != 1 || machines[0].Status != "offline" {
		t.Fatal("Node liveness created/made a Worker available", err)
	}
	// Fresh same-session terminal status can close old authority without login.
	cancel, _ := wire.NewAppNodeCancel(session, g.GrantID, 1, time.Now().UTC())
	_, _, cancelled := n3Authority(t, f, device, cancel)
	if cancelled.Result.Authority.LoginRequired || cancelled.Result.Authority.CurrentHeadVersion != 2 || cancelled.Result.Node != nil {
		t.Fatal("self-cancel lost current login or retained Node authority")
	}
	query, _ = wire.NewAppNodeStatus(session, "", time.Now().UTC())
	_, _, current := n3Authority(t, f, device, query)
	p, err = wire.NewAppNodePrepare(session, current.Result.Authority.Scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetPrevious, PreviousGrantID: g.GrantID}, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, _, preview = n3Authority(t, f, device, p)
	if preview.Challenge == nil || preview.Challenge.Claims.Profile != wire.AppNodeProfileStatus || preview.Challenge.Claims.Binding.NodeID != nodeID {
		t.Fatal("status-only reauthorization lost exact binding")
	}
	c, err = wire.NewAppNodeComplete(session, p, original, *preview.Challenge, owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, read := n3Authority(t, f, device, c)
	if read.Result.Authority.CurrentHeadVersion != 3 || read.Result.Authority.RemainingConfirmations != 0 || len(read.Result.Authority.AllowedOperations) != 0 {
		t.Fatal("READ_EXISTING broadened authority")
	}
	// Reconciliation authenticates the exact historical original through HTTP,
	// without a fresh lease or a second Node effect.
	reconcile, err := wire.NewAppNodeReconcile(session, wire.AppNodeOriginalClient, g.GrantID, confirm, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, recovered := n3Authority(t, f, device, reconcile)
	if recovered.Reconciled.State != wire.AppNodeCompleted || !bytes.Equal(recovered.Reconciled.ReceiptPacket, confirmedPacket) || wire.ValidateAppNodeReconcileTarget(*recovered.Reconciled, wire.AppNodeOriginalClient, confirm) != nil {
		t.Fatal("HTTP recovery lost exact confirmation provenance")
	}
	readRequest, _ := wire.NewAppNodeStatus(session, read.Result.Authority.GrantID, time.Now().UTC())
	unadmittedRead, err := wire.SealClientRequest(device, f.hub, readRequest)
	if err != nil {
		t.Fatal(err)
	}
	reconcile, err = wire.NewAppNodeReconcile(session, wire.AppNodeOriginalAuthority, read.Result.Authority.GrantID, unadmittedRead, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, settled := n3Authority(t, f, device, reconcile)
	if settled.Reconciled.State != wire.AppNodeReadExpired || len(settled.Reconciled.ReceiptPacket) != 0 {
		t.Fatal("unadmitted pure HTTP read could not close safely")
	}
	status, late := n3HTTP(t, f, http.MethodPost, wire.AppNodeHTTPPath(wire.OperationAppNodeStatus), "", unadmittedRead)
	var closed wire.AppNodeResult
	if status != 200 || wire.OpenClientResponse(device, f.hub, unadmittedRead, late, &closed) != nil || closed.State != wire.AppNodeReadExpired || closed.Node != nil {
		t.Fatal("late read escaped exact READ_EXPIRED settlement")
	}
	// Unsupported management surfaces are absent from this composition.
	for _, path := range []string{"/v1/status", "/v1/workers", "/v2/client/devices/enroll", "/v2/client/rpc/recover", "/v2/node/control/key-upgrade", "/v2/fabric/node/networks/direct/send", "/v2/fabric/node/networks/direct/ask", "/v2/fabric/node/networks/join"} {
		status, _ := n3HTTP(t, f, http.MethodPost, path, "", []byte(`{}`))
		if status != http.StatusNotFound {
			t.Fatalf("unexpected old business path %s HTTP %d", path, status)
		}
	}
}
