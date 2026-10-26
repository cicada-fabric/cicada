//go:build cicada_owner_groups_integration

package appcore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
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
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Actual App, TCP Router, account/Owner services, SQLite and PQ envelopes.
// No Runtime or physical Windows is involved. Only public feature discovery is
// enabled in the fixture while its production availability flag remains false;
// every private request still goes through the actual server's full Guard.
type threadGroupHTTPFixture struct {
	t                              *testing.T
	c                              *nativeController
	root, dbPath, stateDir, origin string
	db                             *store.Store
	auth                           *hubauth.Service
	nodes                          *hubnodes.Service
	http                           *httptest.Server
	client                         HTTPDoer
	before, after                  string
	posts                          map[string][][]byte
	responses                      map[string][]byte
	statuses                       map[string]int
}

func newThreadGroupHTTPFixture(t *testing.T) *threadGroupHTTPFixture {
	t.Helper()
	f := &threadGroupHTTPFixture{t: t, root: t.TempDir(), client: NewHTTPClient(), posts: map[string][][]byte{}, responses: map[string][]byte{}, statuses: map[string]int{}}
	f.dbPath, f.stateDir = filepath.Join(f.root, "hub.sqlite3"), filepath.Join(f.root, "hub-identity")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.origin = "http://" + listener.Addr().String()
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.InitializeHubOwnerLocal("Synthetic App query recovery", f.origin, true); err != nil {
		t.Fatal(err)
	}
	f.start(listener)
	f.open()
	t.Cleanup(func() {
		if f.c != nil {
			_ = f.c.Close()
		}
		f.http.Close()
		_ = f.db.Close()
	})
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	code, err := wire.EncodeActivationCode(*material)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []Action{{Kind: ActionConnect, ActivationCode: code}, {Kind: ActionGenerateOwner},
		{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-query-user", Password: n2SyntheticPassword},
		{Kind: ActionLogin, Username: "synthetic-query-user", Password: n2SyntheticPassword}} {
		f.dispatch(action)
	}
	f.enrollNodeAndNetwork()
	f.enableDiscovery()
	return f
}

func (f *threadGroupHTTPFixture) start(listener net.Listener) {
	f.t.Helper()
	ids, err := hubidentity.LoadOrCreate(f.stateDir, "")
	if err != nil {
		f.t.Fatal(err)
	}
	owner, err := hubowner.NewService(f.db, ids)
	if err != nil {
		f.t.Fatal(err)
	}
	f.auth, err = hubauth.NewServiceWithNodeAuthority(f.db, ids)
	if err != nil {
		f.t.Fatal(err)
	}
	f.nodes, err = hubnodes.NewService(f.db, ids)
	if err != nil {
		f.t.Fatal(err)
	}
	f.http = httptestServer(f.t, listener, server.NewHubNodesHandler(owner, f.auth, f.nodes))
}

func (f *threadGroupHTTPFixture) open() {
	f.t.Helper()
	c, err := NewController(Config{HTTP: f, OpenVault: fixtureVaultOpener(filepath.Join(f.root, "vaults"), "synthetic query vault passphrase"), DiscoverVaults: NewProfileDiscovery(filepath.Join(f.root, "vaults")), AllowLoopbackHTTP: true})
	if err != nil {
		f.t.Fatal(err)
	}
	f.c = c.(*nativeController)
}

func (f *threadGroupHTTPFixture) dispatch(action Action) {
	f.t.Helper()
	if err := f.c.Dispatch(context.Background(), action); err != nil {
		if action.Kind == ActionRecoverThreadGroup && f.c.threadGroups.recovery != nil {
			r, o := f.c.threadGroups.recovery, f.c.threadGroups.original
			device, _ := f.c.device.E2EE()
			var result wire.OwnerEndpointGroupsResult
			op := wire.OpenOwnerEndpointGroupsResponse(device, f.c.hub, r.Packet, f.responses[wire.OwnerEndpointGroupsHTTPPath(r.Route.Operation)], &result)
			q, de := f.c.threadGroupDTO(r, o)
			ve := wire.VerifyOwnerEndpointGroupsResult(q, r.Packet, result, f.c.hub)
			te := f.c.verifyThreadGroupResultTarget(r, &result, o)
			f.t.Logf("synthetic diagnostic HTTP=%d original=%s outer=%s/%s NodeMatch=%v receiptBytes=%d open=%v DTO=%v wire=%v target=%v", f.statuses[wire.OwnerEndpointGroupsHTTPPath(r.Route.Operation)], o.Route.Operation, result.State, result.ErrorCode, result.NodeID == r.NodeID, len(result.ReceiptPacket), op, de, ve, te)
			f.t.Logf("synthetic account gates pairReady=%v nodeReady=%v inspected=%v needsCheck=%v canBegin=%v context=%v", f.c.pairAccountReady(), f.c.nodeAccountReady(), f.c.sessionInspected, f.c.sessionNeedsCheck, f.c.canBeginOperation(), f.c.node.Context != nil)
			if q != nil && f.c.node.Context != nil {
				_, p := threadGroupRequestParts(q)
				claims, e := e2ee.VerifyOwnerEndpointGroupsRequest(f.c.owner.Public(), p, wire.OwnerEndpointGroupsOwnerPurpose(r.Route.Operation), time.Time{})
				if e == nil {
					a, b := reflect.ValueOf(claims.Scope), reflect.ValueOf(f.c.node.Context.Authority.Scope)
					var differences []string
					for i := 0; i < a.NumField(); i++ {
						if !reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
							differences = append(differences, a.Type().Field(i).Name)
						}
					}
					f.t.Logf("synthetic scope differing field names=%v", differences)
				}
			}
			if len(result.ReceiptPacket) != 0 {
				_, ne := f.c.openThreadGroupResult(o, result.ReceiptPacket, nil)
				f.t.Logf("synthetic nested original verification=%v", ne)
			}
		}
		f.t.Fatalf("actual Core action %s: %v (Group=%s Node=%s local=%s)", action.Kind, err, f.c.Snapshot().ThreadGroups.ErrorCode, f.c.Snapshot().Node.ErrorCode, f.c.Snapshot().LocalCollaboration.ErrorCode)
	}
}

func (f *threadGroupHTTPFixture) enableDiscovery() {
	// Pre-availability integration gate only: no server authorization changes.
	f.c.threadGroups.discoveryTried, f.c.threadGroups.available = true, true
	f.c.publish()
	f.t.Log("fixture enables public Group availability only; actual private HTTP Guard remains authoritative")
}

func (f *threadGroupHTTPFixture) Do(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return f.client.Do(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	req.Body = io.NopCloser(bytes.NewReader(raw))
	path := req.URL.Path
	f.posts[path] = append(f.posts[path], bytes.Clone(raw))
	if len(path) >= len("/v2/owner/endpoint-groups/") && path[:len("/v2/owner/endpoint-groups/")] == "/v2/owner/endpoint-groups/" {
		index := threadGroupOriginal
		if path == wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsReconcile) {
			index = threadGroupRecovery
		}
		saved, _, found, err := f.c.vault.LoadState(threadGroupNamespaces[index])
		defer clear(saved)
		record, de := decodeThreadGroupRecord(saved)
		if err != nil || !found || de != nil || !bytes.Equal(record.Packet, raw) {
			f.t.Fatal("real HTTP preceded exact Group vault persistence")
		}
	}
	if f.before == path {
		f.before = ""
		return nil, errors.New("synthetic connection lost before Hub admission")
	}
	var response *http.Response
	for attempt := 0; attempt < 80; attempt++ {
		req.Body = io.NopCloser(bytes.NewReader(raw))
		response, err = f.client.Do(req)
		if err != nil {
			return response, err
		}
		if response.StatusCode != http.StatusTooManyRequests || attempt == 79 {
			break
		}
		response.Body.Close()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	f.responses[path] = bytes.Clone(body)
	f.statuses[path] = response.StatusCode
	response.Body = io.NopCloser(bytes.NewReader(body))
	if f.after == path && response.StatusCode == http.StatusOK {
		f.after = ""
		response.Body.Close()
		return nil, errors.New("synthetic connection lost after actual Hub reply")
	}
	return response, nil
}

func (f *threadGroupHTTPFixture) enrollNodeAndNetwork() {
	f.t.Helper()
	ctx := context.Background()
	node, err := e2ee.NewIdentity()
	if err != nil {
		f.t.Fatal(err)
	}
	hub, err := f.nodes.Identity()
	if err != nil {
		f.t.Fatal(err)
	}
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		f.t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		f.t.Fatal(err)
	}
	const id = "synthetic-app-query-node"
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID, NodeID: id, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion})
	if err != nil {
		f.t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		f.t.Fatal(err)
	}
	// Production Node service validates its independent synthetic proof. All
	// App approvals and subsequent Node/Owner operations use the real TCP Router.
	code, err := f.nodes.Start(ctx, nodebinding.Input{NodeID: id, NodeName: "Synthetic query Node", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: hub.HubID, HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint})
	if err != nil {
		f.t.Fatal(err)
	}
	f.dispatch(Action{Kind: ActionPreviewNode, NodeCode: code.UserCode})
	s := f.c.Snapshot()
	if s.Node.Candidate == nil {
		f.t.Fatal("actual Node review absent")
	}
	f.dispatch(Action{Kind: ActionApproveNode, NodeReviewID: s.Node.Candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true})
	if f.c.nodeConfirmation == nil {
		f.t.Fatal("actual original Node binding absent")
	}
	n := f.c.nodeConfirmation.Binding
	nonce, err = wire.NewNonce()
	if err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().UTC()
	report := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: n.HubID, NodeID: n.NodeID, OwnerBindingID: n.OwnerBindingID, NodeKeyEpoch: n.NodeKeyEpoch, LocalUserScope: "uid:1000", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	userProof, err := e2ee.SignLocalDomainUserReport(node, report)
	if err != nil {
		f.t.Fatal(err)
	}
	binding := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
	operationID, err := wire.NewRequestID()
	if err != nil {
		f.t.Fatal(err)
	}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch, Sequence: 1, OperationID: operationID, Operation: wire.OperationLocalDomainNodeAvailable, SenderKeyID: binding.NodeKey.ID, SenderKeyVersion: binding.NodeKeyVersion, ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	plain, err := json.Marshal(wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: report.LocalUserScope, LocalUserReport: userProof})
	if err != nil {
		f.t.Fatal(err)
	}
	packet, err := nodewire.SealRequest(node, binding.HubKey, binding, route, plain)
	if err != nil {
		f.t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, f.origin+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Authorization", "CicadaNode "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", f.origin)
	response, err := f.client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 {
		f.t.Fatal("actual Node user-report HTTP refused", response.StatusCode, err)
	}
	opened, err := nodewire.OpenResponse(node, binding.HubKey, binding, raw)
	if err != nil {
		f.t.Fatal(err)
	}
	want := route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	var reply struct {
		OK        bool   `json:"ok"`
		ErrorCode string `json:"error_code"`
	}
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &reply) != nil || !reply.OK {
		f.t.Fatal("actual Node user-report authentication", reply.ErrorCode)
	}
	f.dispatch(Action{Kind: ActionRefreshLocalCollaboration})
	f.dispatch(Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: "Synthetic query Network", GroupName: "Synthetic original Group"}})
	f.dispatch(Action{Kind: ActionActivateLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ReviewID: f.c.Snapshot().LocalCollaboration.ReviewID, ConfirmActivation: true}})
}

func (f *threadGroupHTTPFixture) read() {
	f.dispatch(Action{Kind: ActionReadThreadGroups, ThreadGroups: ThreadGroupAction{GestureID: f.c.Snapshot().ThreadGroups.GestureID}})
}

func (f *threadGroupHTTPFixture) prepare() {
	f.read()
	f.dispatch(Action{Kind: ActionPrepareThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: f.c.Snapshot().ThreadGroups.GestureID, Change: "CREATE_GROUP", Name: "Synthetic independent G2"}})
}

func (f *threadGroupHTTPFixture) sql(statement string, args ...any) {
	f.t.Helper()
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		f.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(statement, args...); err != nil {
		f.t.Fatal("synthetic fault injection", err)
	}
}

func (f *threadGroupHTTPFixture) lostApply() []byte {
	f.t.Helper()
	f.prepare()
	f.after = wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply)
	r := f.c.Snapshot().ThreadGroups.Review
	if r == nil {
		f.t.Fatal("real Hub review missing")
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionApplyThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID, Confirm: true}}); err == nil || !f.c.hasThreadGroupPending() {
		f.t.Fatal("lost actual apply result was settled")
	}
	return bytes.Clone(f.c.threadGroups.original.Packet)
}

func (f *threadGroupHTTPFixture) restart() {
	f.t.Helper()
	if err := f.c.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.c = nil
	f.http.Close()
	if err := f.db.Close(); err != nil {
		f.t.Fatal(err)
	}
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		f.t.Fatal(err)
	}
	listener, err := net.Listen("tcp", f.origin[len("http://"):])
	if err != nil {
		f.t.Fatal(err)
	}
	f.start(listener)
	f.open()
	resumeN2App(f.t, f.c)
}

func TestThreadGroupRealHubNewLoginReplacesOnlyLostQueryAcrossRestart(t *testing.T) {
	f := newThreadGroupHTTPFixture(t)
	original := f.lostApply()
	path := wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsReconcile)
	for attempt := 0; attempt < 2; attempt++ {
		f.before = path
		if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}); err == nil {
			t.Fatal("lost query was successful")
		}
	}
	old := bytes.Clone(f.c.threadGroups.recovery.Packet)
	posts := f.posts[path]
	if len(posts) != 2 || !bytes.Equal(posts[0], posts[1]) {
		t.Fatal("same-session query retry changed its exact packet")
	}
	ownerID, deviceID := f.c.state.OwnerKeyID, f.c.state.DeviceKeyID
	f.dispatch(Action{Kind: ActionLogout})
	f.restart()
	if !f.c.hasThreadGroupPending() || !bytes.Equal(original, f.c.threadGroups.original.Packet) || !bytes.Equal(old, f.c.threadGroups.recovery.Packet) {
		t.Fatal("restart changed pending original/query")
	}
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
		t.Fatal("recovery bypassed current login")
	}
	f.dispatch(Action{Kind: ActionLogin, Username: "synthetic-query-user", Password: n2SyntheticPassword})
	f.dispatch(Action{Kind: ActionRecoverThreadGroup})
	if f.c.hasThreadGroupPending() || !bytes.Equal(original, f.c.threadGroups.original.Packet) || bytes.Equal(old, f.c.threadGroups.recovery.Packet) || f.c.state.OwnerKeyID != ownerID || f.c.state.DeviceKeyID != deviceID {
		t.Fatal("new login changed original/keys or failed to replace only the read-only wrapper")
	}
	if len(f.posts[wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply)]) != 1 {
		t.Fatal("recovery dispatched another apply")
	}
	// A late old wrapper cannot execute business or resurrect the old login.
	req, err := http.NewRequest(http.MethodPost, f.origin+path, bytes.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", f.origin)
	req.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("late old session did not remain rejected", response.StatusCode)
	}
}

func TestThreadGroupRealHubExpiredQueryReleasesOnlyWrapper(t *testing.T) {
	f := newThreadGroupHTTPFixture(t)
	original := f.lostApply()
	path := wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsReconcile)
	f.after = path
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
		t.Fatal("lost wrapper response was successful")
	}
	old := bytes.Clone(f.c.threadGroups.recovery.Packet)
	id := f.c.threadGroups.recovery.Route.OperationID
	// Model bounded read-cache eviction without changing any immutable floor or
	// original mutation. The next exact query receives real READ_EXPIRED.
	f.sql(`DELETE FROM hub_endpoint_groups_owner_reads_v1 WHERE operation_id=?`, id)
	if f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
		t.Fatal("expired query declared original success")
	}
	if !f.c.hasThreadGroupPending() || !bytes.Equal(original, f.c.threadGroups.original.Packet) || f.c.threadGroups.recovery != nil || f.c.threadGroups.recoveryResponse != nil {
		t.Fatal("READ_EXPIRED discarded original or retained a dead wrapper")
	}
	f.dispatch(Action{Kind: ActionRecoverThreadGroup})
	if f.c.hasThreadGroupPending() || !bytes.Equal(original, f.c.threadGroups.original.Packet) || bytes.Equal(old, f.c.threadGroups.recovery.Packet) {
		t.Fatal("fresh query failed to settle exact original")
	}
}

func TestThreadGroupRealHubUnknownOriginalKeepsIntentAndAllowsFreshQueries(t *testing.T) {
	f := newThreadGroupHTTPFixture(t)
	original := f.lostApply()
	id := f.c.threadGroups.original.Route.OperationID
	// Deliberate disposable-store damage: retain the permanent original floor
	// but remove its synthetic receipt. No grants or business state are added.
	f.sql(`DROP TRIGGER hub_endpoint_groups_owner_operations_v1_no_delete`)
	f.sql(`DELETE FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?`, id)
	path := wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsReconcile)
	for attempt := 0; attempt < 2; attempt++ {
		if f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
			t.Fatal("unknown original became success")
		}
		if !f.c.hasThreadGroupPending() || !bytes.Equal(original, f.c.threadGroups.original.Packet) || f.c.threadGroups.recovery != nil || f.c.threadGroups.recoveryResponse != nil || f.c.threadGroups.response != nil {
			t.Fatal("terminal empty query settled original or poisoned response cache")
		}
	}
	posts := f.posts[path]
	if len(posts) != 2 || bytes.Equal(posts[0], posts[1]) || len(f.posts[wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply)]) != 1 {
		t.Fatal("terminal query was reused forever or business original was redispatched")
	}
}

func TestThreadGroupRealHubReadAndPrepareLostResponses(t *testing.T) {
	f := newThreadGroupHTTPFixture(t)
	for _, operation := range []string{wire.OperationOwnerEndpointGroupsRead, wire.OperationOwnerEndpointGroupsPrepare} {
		if operation == wire.OperationOwnerEndpointGroupsPrepare {
			f.read()
		}
		path := wire.OwnerEndpointGroupsHTTPPath(operation)
		f.after = path
		action := Action{Kind: ActionReadThreadGroups, ThreadGroups: ThreadGroupAction{GestureID: f.c.Snapshot().ThreadGroups.GestureID}}
		if operation == wire.OperationOwnerEndpointGroupsPrepare {
			action.Kind = ActionPrepareThreadGroup
			action.ThreadGroups.Change = "CREATE_GROUP"
			action.ThreadGroups.Name = "Synthetic recovered review"
		}
		if err := f.c.Dispatch(context.Background(), action); err == nil || !f.c.hasThreadGroupPending() {
			t.Fatal("lost real Hub response was settled")
		}
		original := bytes.Clone(f.c.threadGroups.original.Packet)
		f.dispatch(Action{Kind: ActionRecoverThreadGroup})
		if f.c.hasThreadGroupPending() || !bytes.Equal(original, f.c.threadGroups.original.Packet) || operation == wire.OperationOwnerEndpointGroupsRead && f.c.Snapshot().ThreadGroups.Current {
			t.Fatal("original receipt recovery changed ciphertext or refreshed historical cards")
		}
		if operation == wire.OperationOwnerEndpointGroupsPrepare {
			r := f.c.Snapshot().ThreadGroups.Review
			if r == nil {
				t.Fatal("exact prepare review missing")
			}
			f.dispatch(Action{Kind: ActionDismissThreadGroup, ThreadGroups: ThreadGroupAction{GestureID: r.GestureID}})
		}
	}
}
