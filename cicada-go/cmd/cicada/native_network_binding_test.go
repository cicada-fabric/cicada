package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Real Store + Fabric HTTP + owner-only Node socket + MCP, without Control.
// The Codex session record is synthetic: this is not native Runtime evidence.
type nativeNetworkBindingFixture struct {
	persistence                                                          *store.Store
	db                                                                   *sql.DB
	service                                                              *fabric.Service
	bridge                                                               *machineAgentJoinBridge
	mcp                                                                  *mcpServer
	networkID, ownerID, deviceID, nativeID, nodeID, workspace, statePath string
	join                                                                 localNetworkJoinRequest
	sequence                                                             uint64
	failure                                                              atomic.Int32 // 1: reject before commit; 2: lose response after commit.
	joinCalls, renewCalls                                                atomic.Int32
}

func newNativeNetworkBindingFixture(t *testing.T) *nativeNetworkBindingFixture {
	t.Helper()
	f := &nativeNetworkBindingFixture{networkID: "net_native_join_synthetic", ownerID: "owner_native_join_synthetic", deviceID: "phone_native_join_synthetic", nativeID: "thread_native_join_synthetic", nodeID: "node_native_join_synthetic"}
	f.workspace = prepareMCPJoinSessionRecord(t, f.nativeID)
	t.Setenv("CODEX_THREAD_ID", f.nativeID)
	t.Setenv("CODEX_SESSION_ID", "")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "")
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_MACHINE_ID", f.nodeID)
	t.Setenv("CICADA_WORKSPACE", f.workspace)
	databasePath := filepath.Join(t.TempDir(), "synthetic.sqlite3")
	var err error
	f.persistence, err = store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.persistence.Close() })
	f.db, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Close() })
	if _, err = f.persistence.CreatePrincipal(store.Principal{ID: f.ownerID, Kind: store.PrincipalKindHuman, OwnerID: f.ownerID, TrustDomainID: f.ownerID, Name: "Synthetic owner", Status: store.PrincipalStatusActive}); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.persistence.RegisterOwnerApprovalKeyLocal(f.ownerID, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := f.persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerKey.SignOwnerDeviceGrant(f.ownerID, f.deviceID, deviceKey.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: f.ownerID, OwnerKeyID: ownerKey.Public().ID, DeviceID: f.deviceID, DevicePublic: deviceKey.Public(), OwnerDeviceGrant: proof}); err != nil {
		t.Fatal(err)
	}
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic native join one-time code"))
	codeDigest := hex.EncodeToString(digest[:])
	if _, err = f.persistence.CreatePendingNodeDeviceBinding(f.nodeID, f.nodeID, nodeDigest, codeDigest, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.persistence.ConfirmPendingNodeDeviceBinding(f.ownerID, f.deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = f.persistence.CreateNetwork(store.Network{ID: f.networkID, HubID: hubID, Name: "Synthetic DIRECTORY-only Network", OwnerID: f.ownerID}); err != nil {
		t.Fatal(err)
	}
	if err = f.persistence.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	f.service, err = fabric.NewService(f.persistence, f.ownerID, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(f.service, "")
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/fabric/node/networks/join":
			f.joinCalls.Add(1)
		case "/v2/fabric/node/networks/renew":
			f.renewCalls.Add(1)
		case "/v2/fabric/networks/" + f.networkID + "/direct/native-binding":
			if f.failure.Load() == 1 {
				http.Error(w, "synthetic registration unavailable", 503)
				return
			}
			if f.failure.Load() == 2 {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, r)
				if recorder.Code != 201 && recorder.Code != 200 {
					t.Errorf("registration did not commit before loss: %d", recorder.Code)
				}
				http.Error(w, "synthetic lost registration response", 502)
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(hub.Close)
	nodeState := shortLocalJoinStateDir(t)
	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(nodeState, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	ctx, cancel := context.WithCancel(withMachineHubContext(context.Background(), machineHubContext{
		HubID: hubID, Origin: hub.URL, NodeID: f.nodeID, StateDir: nodeState, Token: nodeToken,
		WriterRoot: nodeState, WriterScope: machineNativeWriterScope(), RequireNativeContext: true, NativeContexts: registry,
	}))
	t.Cleanup(cancel)
	f.bridge, err = startMachineAgentJoinBridge(ctx, nodeState, hub.URL, f.nodeID, nodeToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.bridge.Close() })
	t.Setenv("CICADA_NODE_STATE_DIR", nodeState)
	t.Setenv("CICADA_HUB_ID", hubID)
	invitation := "synthetic-native-join-invitation-aaaaaaaaaaaaaaaaaaaa"
	grants := []string{"directory.discover", "directory.publish"}
	if err = f.persistence.IssueNetworkInvitation(f.networkID, f.ownerID, f.ownerID, invitation, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	joinProof, err := ownerKey.SignOwnerNetworkJoinGrant(f.ownerID, hubID, f.networkID, f.nodeID, f.nativeID, store.NetworkInvitationDigest(invitation), ownerKey.Public().ID, grants, true, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.join = localNetworkJoinRequest{NetworkID: f.networkID, InvitationToken: invitation, OwnerJoinProof: string(joinProof), Harness: "codex", NativeSessionID: f.nativeID, Workspace: f.workspace}
	f.mcp = newMCPServer(hub.URL, "", "")
	t.Cleanup(func() { close(f.mcp.stop) })
	scope, _, err := mcpSessionScope(hub.URL, harness.SessionContext{Harness: "codex", NativeSessionID: f.nativeID, MachineID: f.nodeID, Workspace: f.workspace})
	if err != nil {
		t.Fatal(err)
	}
	joinRoot, stateRoot := t.TempDir(), t.TempDir()
	for _, root := range []string{joinRoot, stateRoot} {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CICADA_NETWORK_JOIN_DIR", joinRoot)
	t.Setenv("CICADA_NETWORK_SESSION_DIR", stateRoot)
	joinDir, err := privateNetworkScopeDir(joinRoot, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := privateNetworkScopeDir(stateRoot, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	f.statePath, err = mcpNetworkFile(stateDir, f.networkID, ".session.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNewPrivateNetworkFile(filepath.Join(joinDir, f.networkID+".invitation"), []byte(invitation)); err != nil {
		t.Fatal(err)
	}
	if err = writeNewPrivateNetworkFile(filepath.Join(joinDir, f.networkID+".proof.json"), joinProof); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *nativeNetworkBindingFixture) state(t *testing.T) networkCLIState {
	t.Helper()
	data, err := readPrivateNetworkFile(f.statePath, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	var state networkCLIState
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.statePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("accepted credential state is not private")
	}
	if state.NativeSessionID != f.nativeID || state.NodeID != f.nodeID || state.EndpointID == "" || state.SessionToken == "" {
		t.Fatal("accepted native identity was not retained")
	}
	return state
}
func (f *nativeNetworkBindingFixture) clientRequest(t *testing.T, operation string) string {
	t.Helper()
	f.sequence++
	digest := sha256.Sum256([]byte(fmt.Sprintf("synthetic verified request %d", f.sequence)))
	accepted, err := f.persistence.AcceptClientRequest(store.AcceptClientRequestInput{OwnerID: f.ownerID, DeviceID: f.deviceID, SessionEpoch: 1, Sequence: f.sequence, OperationID: fmt.Sprintf("synthetic_native_request_%d", f.sequence), RouteOperation: operation, CiphertextDigest: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	return accepted.Request.ID
}
func (f *nativeNetworkBindingFixture) binding(t *testing.T, endpointID string) store.NetworkDirectNativeBinding {
	t.Helper()
	var b store.NetworkDirectNativeBinding
	if err := f.db.QueryRow(`SELECT id,endpoint_id,principal_id,node_id,native_session_id,epoch,status FROM network_direct_native_bindings_v2 WHERE endpoint_id=?`, endpointID).Scan(&b.ID, &b.EndpointID, &b.PrincipalID, &b.NodeID, &b.NativeSessionID, &b.Epoch, &b.Status); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNativeNetworkJoinDirectoryOnlyAdmissionWithoutControl(t *testing.T) {
	f := newNativeNetworkBindingFixture(t)
	// A model-supplied caller ID is not an accepted tool field.
	if _, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID, "endpoint_id": "forged", "sender": "forged"}); err == nil {
		t.Fatal("model caller identity accepted")
	}
	value, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID})
	if err != nil {
		t.Fatal(err)
	}
	state := f.state(t)
	binding := f.binding(t, state.EndpointID)
	if binding.ID == "" || binding.Epoch != 1 || binding.NativeSessionID != f.nativeID || binding.NodeID != f.nodeID {
		t.Fatal("JOIN omitted original native binding")
	}
	encoded, _ := json.Marshal(value)
	if bytes.Contains(encoded, []byte(state.SessionToken)) || bytes.Contains(encoded, []byte(f.join.OwnerJoinProof)) {
		t.Fatal("JOIN exposed private credentials")
	}
	endpoint, err := f.persistence.GetEndpointV2(state.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.GroupID != "" || endpoint.BindingID != "" {
		t.Fatal("Network JOIN granted a Group writer")
	}
	group, err := f.persistence.CreateClientTopologyGroupAtomic(store.Group{NetworkID: f.networkID, OwnerPrincipalID: f.ownerID, TrustDomainID: f.ownerID, Name: "Synthetic explicit Owner Group", State: store.GroupStateActive, ContextPolicy: "group_scoped", IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated"}, "", f.clientRequest(t, "topology.apply"))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := f.persistence.PreviewClientTopologyEndpointAdmissionForClientRequest(f.clientRequest(t, store.ClientTopologyEndpointAdmissionPreviewOperation), f.ownerID, f.networkID, group.ID, state.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	input := store.ClientTopologyEndpointAdmissionInput{NetworkID: f.networkID, GroupID: group.ID, EndpointID: state.EndpointID, ExpectedEndpointMigrationState: preview.EndpointMigrationState, ExpectedNetworkVersion: preview.NetworkVersion, ExpectedGroupVersion: preview.GroupVersion, ExpectedNetworkMembership: preview.NetworkMembershipRevision, ExpectedEndpointNetwork: preview.EndpointNetworkRevision, NetworkAccessBindingID: preview.NetworkAccessBindingID, NetworkAccessEpoch: preview.NetworkAccessEpoch, NativeBindingID: preview.NativeBindingID, NativeBindingEpoch: preview.NativeBindingEpoch}
	forged := input
	forged.NativeBindingEpoch++
	if _, _, err = f.persistence.AdmitClientTopologyEndpointForClientRequest(f.clientRequest(t, "topology.apply"), f.ownerID, forged); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("forged native epoch admitted: %v", err)
	}
	// Renew access before Owner apply: stale preview must fail although native ID/epoch stays stable.
	oldToken := state.SessionToken
	if _, err = f.mcp.callTool("cicada_network_renew", map[string]any{"network_id": f.networkID}); err != nil {
		t.Fatal(err)
	}
	state = f.state(t)
	currentBinding := f.binding(t, state.EndpointID)
	if currentBinding.ID != binding.ID || currentBinding.Epoch != binding.Epoch {
		t.Fatal("renewal replaced native identity")
	}
	if _, err = f.service.AuthenticateForNetwork(oldToken, f.networkID); err == nil {
		t.Fatal("old access credential remained authorized")
	}
	if _, _, err = f.persistence.AdmitClientTopologyEndpointForClientRequest(f.clientRequest(t, "topology.apply"), f.ownerID, input); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("old access preview admitted: %v", err)
	}
	preview, err = f.persistence.PreviewClientTopologyEndpointAdmissionForClientRequest(f.clientRequest(t, store.ClientTopologyEndpointAdmissionPreviewOperation), f.ownerID, f.networkID, group.ID, state.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	input.NetworkAccessEpoch = preview.NetworkAccessEpoch
	if _, _, err = f.persistence.AdmitClientTopologyEndpointForClientRequest(f.clientRequest(t, "topology.apply"), "forged_owner", input); err == nil {
		t.Fatal("forged Owner admitted Group")
	}
	member, reference, err := f.persistence.AdmitClientTopologyEndpointForClientRequest(f.clientRequest(t, "topology.apply"), f.ownerID, input)
	if err != nil {
		t.Fatal(err)
	}
	if member.Role != "member" || len(member.Grants) != 0 || reference.EndpointID != state.EndpointID || preview.HistoryIncluded || preview.KeyGrantCreated {
		t.Fatal("Owner admission expanded authority")
	}
	for _, grant := range []string{"direct.send", "direct.receive", "message.broadcast", "network.admin.invite"} {
		allowed, err := f.persistence.NetworkAllows(f.networkID, endpoint.PrincipalID, state.EndpointID, grant)
		if err != nil || allowed {
			t.Fatalf("directory-only member gained %s: %v", grant, err)
		}
	}
	var keyCount int
	if err = f.db.QueryRow(`SELECT count(*) FROM group_endpoint_key_grants_v2 WHERE endpoint_id=?`, state.EndpointID).Scan(&keyCount); err != nil || keyCount != 0 {
		t.Fatal("admission silently created Group keys")
	}
	actor, err := f.service.AuthenticateForNetwork(state.SessionToken, f.networkID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.NetworkDirectPeerKey(actor, "ep_other_synthetic"); !errors.Is(err, fabric.ErrNotFoundOrNotAuthorized) {
		t.Fatalf("DIRECT peer key permission was not denied: %v", err)
	}
	if _, err = f.service.SendNetworkDirectSealed(f.bridge.nodeToken, fabric.NetworkDirectSendInput{
		NetworkID: f.networkID, NetworkSessionToken: state.SessionToken, TargetEndpointID: "ep_other_synthetic",
		MessageID: "msg_synthetic_denied", Ciphertext: []byte("synthetic opaque fixture")}); !errors.Is(err, fabric.ErrPermissionDenied) {
		t.Fatalf("DIRECT SEND was not denied by current Network permission: %v", err)
	}
	if _, err = f.mcp.callTool("cicada_publish_endpoint_key_candidate", map[string]any{"network_id": f.networkID}); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("DIRECT key publication was not denied by the real guard: %v", err)
	}
	var candidateCount int
	if err = f.db.QueryRow(`SELECT count(*) FROM network_direct_key_candidates_v2 WHERE endpoint_id=?`, state.EndpointID).Scan(&candidateCount); err != nil || candidateCount != 0 {
		t.Fatal("directory-only JOIN published a key candidate")
	}

	if f.joinCalls.Load() != 1 || f.renewCalls.Load() != 1 {
		t.Fatal("JOIN/renewal did not use narrow existing HTTP paths")
	}
}

func TestNativeNetworkBindingPartialFailureRetainsCredentialAndStableIDs(t *testing.T) {
	for _, mode := range []int32{1, 2} {
		t.Run(fmt.Sprintf("failure_%d", mode), func(t *testing.T) {
			f := newNativeNetworkBindingFixture(t)
			f.failure.Store(mode)
			value, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID})
			if err == nil || value != nil || !strings.Contains(err.Error(), "NETWORK_NATIVE_BINDING_PENDING") {
				t.Fatal("partial registration claimed completed JOIN")
			}
			state := f.state(t)
			actor, err := f.service.AuthenticateForNetwork(state.SessionToken, f.networkID)
			if err != nil {
				t.Fatal("accepted access credential was lost")
			}
			accessID := actor.BindingID
			var nativeBinding store.NetworkDirectNativeBinding
			if mode == 2 {
				nativeBinding = f.binding(t, state.EndpointID)
			}
			// Renewal may itself commit before another registration failure. Its fresh
			// credential must replace the now-fenced token even though MCP returns error.
			oldToken := state.SessionToken
			if _, err = f.mcp.callTool("cicada_network_renew", map[string]any{"network_id": f.networkID}); err == nil {
				t.Fatal("registration failure claimed successful renewal")
			}
			state = f.state(t)
			if state.SessionToken == oldToken {
				t.Fatal("failed renewal did not retain newly accepted access")
			}
			if _, err = f.service.AuthenticateForNetwork(oldToken, f.networkID); err == nil {
				t.Fatal("fenced old token remains authorized")
			}
			f.failure.Store(0)
			// Repeated JOIN follows existing credential renewal, without resending invitation/proof.
			if _, err = f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID}); err != nil {
				t.Fatal(err)
			}
			recovered := f.state(t)
			current, err := f.service.AuthenticateForNetwork(recovered.SessionToken, f.networkID)
			if err != nil {
				t.Fatal(err)
			}
			binding := f.binding(t, recovered.EndpointID)
			if recovered.EndpointID != state.EndpointID || recovered.NativeSessionID != f.nativeID || current.BindingID != accessID || binding.Epoch != 1 {
				t.Fatal("retry replaced accepted endpoint/access session/native identity")
			}
			if mode == 2 && (binding.ID != nativeBinding.ID || binding.Epoch != nativeBinding.Epoch) {
				t.Fatal("response-loss retry replaced committed native binding")
			}
			if f.joinCalls.Load() != 1 || f.renewCalls.Load() != 2 {
				t.Fatal("partial retry repeated JOIN instead of renewing accepted scope")
			}
			_, expiryErr := time.Parse(time.RFC3339Nano, current.LeaseExpiresAt)
			if expiryErr != nil {
				t.Fatal("recovered lease was lost")
			}
		})
	}
}

func TestNativeNetworkBindingRejectsForgedHubIdentity(t *testing.T) {
	for _, field := range []string{"endpoint", "principal", "node", "native", "epoch", "id", "status"} {
		t.Run(field, func(t *testing.T) {
			binding := store.NetworkDirectNativeBinding{ID: "native_synthetic", EndpointID: "ep_synthetic", PrincipalID: "principal_synthetic", NodeID: "node_synthetic", NativeSessionID: "thread_synthetic", Epoch: 1, Status: "active"}
			switch field {
			case "endpoint":
				binding.EndpointID = "forged"
			case "principal":
				binding.PrincipalID = "forged"
			case "node":
				binding.NodeID = "forged"
			case "native":
				binding.NativeSessionID = "old_thread"
			case "epoch":
				binding.Epoch = 0
			case "id":
				binding.ID = ""
			case "status":
				binding.Status = "superseded"
			}
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/whoami") {
					_ = json.NewEncoder(w).Encode(networkDirectCurrentActor{NetworkID: "net_synthetic", EndpointID: "ep_synthetic", PrincipalID: "principal_synthetic"})
					return
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 0 {
					t.Error("registration accepted model identity fields")
				}
				_ = json.NewEncoder(w).Encode(binding)
			}))
			defer hub.Close()
			bridge := &machineAgentJoinBridge{ctx: context.Background(), baseURL: hub.URL, nodeID: "node_synthetic"}
			if _, _, err := bridge.ensureNetworkNativeBinding("net_synthetic", "ep_synthetic", "thread_synthetic", "synthetic-private-token", "principal_synthetic"); err == nil {
				t.Fatal("forged or old native binding accepted")
			}
		})
	}
}

func TestNativeNetworkBindingReconcilesCommittedScopeBlock(t *testing.T) {
	f := newNativeNetworkBindingFixture(t)
	hub, _ := machineHubFrom(f.bridge.ctx)
	hub.NativeContexts = nil
	blockedBridge := &machineAgentJoinBridge{ctx: withMachineHubContext(context.Background(), hub),
		baseURL: f.bridge.baseURL, stateDir: f.bridge.stateDir, nodeID: f.nodeID, nodeToken: f.bridge.nodeToken}
	request := f.join
	request.Version = localJoinProtocolVersion
	request.Operation = "network_join"
	joined, decision, err := blockedBridge.joinNetworkWithScope(request)
	recovery, ok := localJoinRecoveryFromError(err)
	if !ok || joined != nil || decision != nil || !recovery.RecoveryRecordSaved || recovery.ReasonCode != "SCOPE_CHECK_UNAVAILABLE" {
		t.Fatal("scope block exposed accepted credential or omitted durable recovery")
	}
	var bindingCount int
	if err = f.db.QueryRow(`SELECT count(*) FROM network_direct_native_bindings_v2`).Scan(&bindingCount); err != nil || bindingCount != 0 {
		t.Fatal("blocked native scope registered a native destination")
	}
	value, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID})
	if err != nil {
		t.Fatal(err)
	}
	state := f.state(t)
	if state.EndpointID != recovery.EndpointID {
		t.Fatal("exact scope recovery created a replacement Endpoint")
	}
	binding := f.binding(t, state.EndpointID)
	if binding.NativeSessionID != f.nativeID {
		t.Fatal("exact scope recovery created a replacement native Thread")
	}
	response, ok := value.(map[string]any)
	if !ok {
		t.Fatal("missing explicit recovered result")
	}
	status, ok := response["join_recovery"].(*localJoinRecoveryStatus)
	if !ok || status.RecoveryState != localJoinRecoveryDone || status.NativeHistoryCoverage != nodeinbox.NativeContextHistoryCoverageCicadaKnownOnly {
		t.Fatal("recovered scope omitted known-history coverage")
	}
}

func TestNativeNetworkBindingRejectsOldOwnerNodeAndNativeContext(t *testing.T) {
	for _, cause := range []string{"owner", "node", "native", "binding"} {
		t.Run(cause, func(t *testing.T) {
			f := newNativeNetworkBindingFixture(t)
			if _, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID}); err != nil {
				t.Fatal(err)
			}
			state := f.state(t)
			switch cause {
			case "owner":
				var keyID string
				if err := f.db.QueryRow(`SELECT owner_key_id FROM network_access_sessions_v2 WHERE endpoint_id=?`, state.EndpointID).Scan(&keyID); err != nil {
					t.Fatal(err)
				}
				key, err := f.persistence.GetOwnerApprovalKey(f.ownerID, keyID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.persistence.RevokeOwnerApprovalKeyLocal(f.ownerID, keyID, key.Version); err != nil {
					t.Fatal(err)
				}
			case "node":
				if _, err := f.db.Exec(`UPDATE fabric_endpoints SET machine_id='node_forged' WHERE id=?`, state.EndpointID); err != nil {
					t.Fatal(err)
				}
			case "native":
				if _, err := f.db.Exec(`UPDATE fabric_endpoints SET native_session_id='thread_old_synthetic' WHERE id=?`, state.EndpointID); err != nil {
					t.Fatal(err)
				}
			case "binding":
				if _, err := f.db.Exec(`UPDATE network_direct_native_bindings_v2 SET status='revoked' WHERE endpoint_id=?`, state.EndpointID); err != nil {
					t.Fatal(err)
				}
			}
			endpoint, err := f.persistence.GetEndpointV2(state.EndpointID)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.bridge.ensureNetworkNativeBinding(f.networkID, state.EndpointID, f.nativeID, state.SessionToken, endpoint.PrincipalID); err == nil {
				t.Fatal("old Owner/Node/native binding bypassed the real backend guard")
			}
		})
	}
}

func TestNativeNetworkRenewalBeyondHistoryBoundPreservesAccessAndPolicy(t *testing.T) {
	f := newNativeNetworkBindingFixture(t)
	if _, err := f.mcp.callTool("cicada_network_join", map[string]any{"network_id": f.networkID}); err != nil {
		t.Fatal(err)
	}
	initial := f.state(t)
	nativeBinding := f.binding(t, initial.EndpointID)
	initialActor, err := f.service.AuthenticateForNetwork(initial.SessionToken, f.networkID)
	if err != nil {
		t.Fatal(err)
	}
	for renewal := 1; renewal <= 80; renewal++ {
		operation := "cicada_network_renew"
		if renewal%2 == 0 {
			operation = "cicada_network_join"
		}
		if _, err := f.mcp.callTool(operation, map[string]any{"network_id": f.networkID}); err != nil {
			t.Fatalf("renewal %d failed: %v", renewal, err)
		}
		state := f.state(t)
		actor, err := f.service.AuthenticateForNetwork(state.SessionToken, f.networkID)
		if err != nil {
			t.Fatalf("renewal %d lost its accepted credential: %v", renewal, err)
		}
		if state.EndpointID != initial.EndpointID || state.NativeSessionID != initial.NativeSessionID || actor.BindingID != initialActor.BindingID || actor.BindingEpoch != uint64(renewal)+initialActor.BindingEpoch {
			t.Fatalf("renewal %d changed native/enrollment identity or failed to rotate access epoch", renewal)
		}
	}
	state := f.state(t)
	currentNative := f.binding(t, state.EndpointID)
	if currentNative.ID != nativeBinding.ID || currentNative.Epoch != nativeBinding.Epoch {
		t.Fatal("directory access rotation replaced native binding")
	}
	if _, err := f.service.AuthenticateForNetwork(initial.SessionToken, f.networkID); err == nil {
		t.Fatal("initial access token remained authorized after eighty renewals")
	}
	hub, _ := machineHubFrom(f.bridge.ctx)
	historyDB, err := sql.Open("sqlite", filepath.Join(f.bridge.stateDir, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer historyDB.Close()
	var historyRows int
	if err := historyDB.QueryRow(`SELECT count(*) FROM node_native_context_history_v1`).Scan(&historyRows); err != nil || historyRows != 1 {
		t.Fatalf("directory access rotation exhausted native history: rows=%d err=%v", historyRows, err)
	}
	var anchor string
	var generation uint64
	if err := historyDB.QueryRow(`SELECT binding_id,binding_epoch FROM node_native_context_history_v1`).Scan(&anchor, &generation); err != nil || anchor != initialActor.BindingID || generation != initialActor.BindingEpoch {
		t.Fatal("history no longer records its stable enrollment anchor")
	}
	// Ordinary history permits explicitly recorded scope reuse. Tightening the
	// current authoritative Network policy must still reject that known reuse.
	seedNativeJoinContext(t, hub.NativeContexts, nodeinbox.NativeContextScopeInput{AccountID: hub.WriterScope, Harness: "codex", NativeSessionID: f.nativeID, HubID: hub.HubID, NetworkID: "net_other_synthetic", GroupID: "group_other_synthetic", ContextPolicy: nodeinbox.NativeContextPolicyGroupScoped, EndpointID: "ep_other_synthetic", BindingID: "bind_other_synthetic", BindingEpoch: 1})
	// Dedicated-Network history still rejects known reuse after repeated
	// enrollment observations; this sidecar policy is checked independently.
	latestActor, err := f.service.AuthenticateForNetwork(state.SessionToken, f.networkID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.NativeContexts.CheckAndRecordNetworkEnrollmentContext(f.bridge.ctx,
		nodeinbox.NativeContextScopeInput{AccountID: hub.WriterScope, Harness: "codex", NativeSessionID: f.nativeID,
			HubID: hub.HubID, NetworkID: f.networkID, ContextPolicy: nodeinbox.NativeContextPolicyDedicatedNetwork,
			EndpointID: state.EndpointID, BindingID: latestActor.BindingID, BindingEpoch: latestActor.BindingEpoch}); !errors.Is(err, nodeinbox.ErrNativeContextScopeConflict) {
		t.Fatalf("renewed enrollment bypassed known dedicated-scope conflict: %v", err)
	}
	// Current Hub schema permits dedicated_thread on Network policy. A
	// Network-only enrollment has no Group, so that policy is incompatible
	// and must fail closed without storing a successful renewal credential.
	if _, err := f.db.Exec(`UPDATE networks_v2 SET context_policy='dedicated_thread' WHERE id=?`, f.networkID); err != nil {
		t.Fatal(err)
	}
	value, err := f.mcp.callTool("cicada_network_renew", map[string]any{"network_id": f.networkID})
	recovery, ok := localJoinRecoveryFromError(err)
	if value != nil || !ok || recovery.ReasonCode != "SCOPE_METADATA_INVALID" || recovery.NativeHistoryCoverage != nodeinbox.NativeContextHistoryCoverageNotChecked {
		t.Fatalf("stable history anchor bypassed tightened scope policy: result=%v err=%v", value, err)
	}
	if err := historyDB.QueryRow(`SELECT count(*) FROM node_native_context_history_v1`).Scan(&historyRows); err != nil || historyRows != 2 {
		t.Fatal("scope rejection cleared or added native history")
	}
}
