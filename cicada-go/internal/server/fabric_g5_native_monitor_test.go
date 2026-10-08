package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// Synthetic production HTTP/PQ fixture; no real Native approval or model execution.
func TestMonitorEndpointCannotMutateUserApprovalHTTP(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	const apiToken = "machine-agent-control-token"
	controlPlane, err := control.New(control.Config{
		StateDir: stateDir, WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: apiToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := controlPlane.Shutdown(ctx); err != nil {
			t.Error("synthetic protocol fixture assertion failed")
		}
	})

	server := httptest.NewServer(NewHandler(controlPlane))
	t.Cleanup(server.Close)
	httpClient := server.Client()

	identityStatus, identityBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet,
		"/v2/client/identity", nil, "")
	if identityStatus != http.StatusOK {
		t.Fatal("synthetic protocol fixture assertion failed")
	}
	var hubIdentity struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(identityBody, &hubIdentity); err != nil || hubIdentity.HubID == "" {
		t.Fatal("synthetic protocol fixture assertion failed")
	}

	ownerID := controlPlane.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	syntheticGroup, err := controlPlane.CreateGroup(control.GroupCreateInput{Name: "Client node chain"})
	if err != nil {
		t.Fatal(err)
	}
	approvalStore, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approvalStore.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		_ = approvalStore.Close()
		t.Fatal(err)
	}
	if err := approvalStore.Close(); err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKey.SignOwnerDeviceGrant(ownerID, "phone-chain", deviceKey.Public(), hubIdentity.HubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID,
		"device_id": "phone-chain", "device_public_identity": deviceKey.Public(),
		"owner_device_grant": grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollStatus, _ := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
		"/v2/client/devices/enroll", enrollment, "")
	if enrollStatus != http.StatusCreated {
		t.Fatal("synthetic protocol fixture assertion failed")
	}

	binding := clientwire.Binding{
		HubID: hubIdentity.HubID, OwnerID: ownerID, DeviceID: "phone-chain",
		SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1,
	}
	sequence := uint64(0)
	callClientRPC := func(operation string, body []byte) json.RawMessage {
		t.Helper()
		sequence++
		route := clientwire.Route{
			Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
			SessionEpoch: binding.SessionEpoch, Sequence: sequence,
			OperationID: fmt.Sprintf("node-chain-%s-%d", operation, sequence), Operation: operation,
			SenderKeyID: deviceKey.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion,
			ReceiverKeyID: hubIdentity.ControlPublicIdentity.ID, ReceiverKeyVersion: binding.HubKeyVersion,
		}
		packet, err := clientwire.SealRequest(deviceKey, hubIdentity.ControlPublicIdentity, binding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		status, responseBody := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost,
			"/v2/client/rpc", packet, "")
		if status != http.StatusOK {
			t.Fatal("synthetic protocol fixture assertion failed")
		}
		opened, err := clientwire.OpenResponse(deviceKey, hubIdentity.ControlPublicIdentity, binding, responseBody)
		if err != nil {
			t.Fatal("synthetic protocol fixture assertion failed")
		}
		var envelope struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(opened.Plaintext, &envelope); err != nil || !envelope.OK {
			t.Fatal("synthetic protocol fixture assertion failed")
		}
		return envelope.Result
	}

	// Test-only durable pending approval; no Node job or Worker process is launched.
	db, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal("open synthetic store")
	}
	t.Cleanup(func() {
		if db.Close() != nil {
			t.Error("close synthetic store")
		}
	})
	machine, err := db.UpsertMachine("synthetic-g5-approval-machine", "synthetic approval", nil, "available")
	if err != nil {
		t.Fatal("seed synthetic machine")
	}
	goal, err := db.CreateGoal("synthetic-g5-approval-goal", "synthetic approval", "done", "", 50, machine.ID, "", t.TempDir())
	if err != nil {
		t.Fatal("seed synthetic Goal")
	}
	worker, err := db.CreateWorkerAtHarness("synthetic-g5-approval-worker", goal.ID, machine.ID, "codex", filepath.Join(t.TempDir(), "result"), t.TempDir())
	if err != nil {
		t.Fatal("seed synthetic Worker")
	}
	// Same test-only Owner assignment as Store's pending-approval fixture.
	seedDB, err := sql.Open("sqlite", filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal("open Owner seed")
	}
	_, seedErr := seedDB.Exec("UPDATE goals SET owner_id=? WHERE id=?", ownerID, goal.ID)
	closeErr := seedDB.Close()
	if seedErr != nil || closeErr != nil {
		t.Fatal("seed exact Goal Owner")
	}
	nodeApproval, err := db.CreateApproval("synthetic-g5-pending-approval", goal.ID, worker.ID, "item/commandExecution/requestApproval", map[string]any{"command": []string{"PUBLIC_SYNTHETIC_NEVER_EXECUTED"}})
	if err != nil {
		t.Fatal("seed pending approval")
	}
	_, _ = bindSameGroupSealedTestNode(t, db, ownerID, "phone-chain", "synthetic-g5-monitor-node")
	monitor, err := controlPlane.Fabric().Join(fabricpkg.JoinInput{GroupID: syntheticGroup.ID, PrincipalName: "synthetic_monitor", EndpointName: "synthetic_monitor", Harness: "codex", NativeSessionID: "native_synthetic_monitor", NodeID: "synthetic-g5-monitor-node"})
	if err != nil {
		t.Fatal("issue Monitor Fabric session")
	}
	membership, err := db.GetMembershipByPrincipalGroup(monitor.Endpoint.PrincipalID, syntheticGroup.ID)
	if err != nil || membership == nil {
		t.Fatal("Monitor membership unavailable")
	}
	if _, err := db.UpdateMembershipAuthorization(membership.ID, []string{"monitor"}, membership.Grants, membership.Authorization, membership.Version); err != nil {
		t.Fatal("set supported Monitor role")
	}
	before, err := db.GetApproval(nodeApproval.ID)
	if err != nil || before == nil || before.Status != "pending" {
		t.Fatal("pending approval unavailable")
	}
	// Positive: this credential really enters the Fabric Session plane.
	if status, _ := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodGet, "/v2/fabric/whoami", nil, "CicadaSession "+monitor.SessionToken); status != http.StatusOK {
		t.Fatal("issued Monitor session authentication failed")
	}
	currentMembership, err := db.GetMembershipByPrincipalGroup(monitor.Endpoint.PrincipalID, syntheticGroup.ID)
	if err != nil || currentMembership == nil || !reflect.DeepEqual(currentMembership.Roles, []string{"monitor"}) {
		t.Fatal("supported Monitor role not current")
	}
	monitorKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("synthetic Monitor signing key")
	}
	for _, route := range []string{"manager", "encrypted-client"} {
		t.Run(route, func(t *testing.T) {
			path := "/v1/approvals/" + before.ID
			payload := []byte(`{"decision":"accept"}`)
			want := http.StatusUnauthorized
			authorization := "Bearer " + monitor.SessionToken
			if route == "encrypted-client" {
				path = "/v2/client/rpc"
				want = http.StatusForbidden
				authorization = "CicadaSession " + monitor.SessionToken
				requestBody, err := json.Marshal(map[string]string{"approval_id": before.ID, "decision": "accept"})
				if err != nil {
					t.Fatal("synthetic decision payload")
				}
				forgedRoute := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest, HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID, SessionEpoch: binding.SessionEpoch, Sequence: sequence + 1, OperationID: "synthetic-monitor-forged-approval", Operation: "approvals.decide", SenderKeyID: monitorKey.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion, ReceiverKeyID: hubIdentity.ControlPublicIdentity.ID, ReceiverKeyVersion: binding.HubKeyVersion}
				payload, err = clientwire.SealRequest(monitorKey, hubIdentity.ControlPublicIdentity, binding, forgedRoute, requestBody)
				if err != nil {
					t.Fatal("seal synthetic Monitor forgery")
				}
			}
			status, response := clientNodeChainHTTP(t, httpClient, server.URL, http.MethodPost, path, payload, authorization)
			if status != want {
				t.Fatal("Monitor credential reached wrong approval boundary")
			}
			if route == "encrypted-client" && !bytes.Contains(response, []byte("Client packet authentication failed")) {
				t.Fatal("Monitor forgery did not reach enrolled-device packet authentication")
			}
			after, err := db.GetApproval(before.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("denial changed pending approval")
			}
		})
	}
	decisionBody, err := json.Marshal(map[string]string{"approval_id": nodeApproval.ID, "decision": "accept"})
	if err != nil {
		t.Fatal(err)
	}
	var decided store.Approval
	if err := json.Unmarshal(callClientRPC("approvals.decide", decisionBody), &decided); err != nil ||
		decided.ID != nodeApproval.ID || decided.Status != "resolved" || decided.Decision != "accept" {
		t.Fatal("synthetic protocol fixture assertion failed")
	}
}

// No fake/default SID: this selector is NOT_RUN outside the live owned Native fixture.
func TestFabricDirectoryHidesRealUnjoinedNativeThreadHTTP(t *testing.T) {
	sid := os.Getenv("CICADA_G5_LIVE_UNJOINED_SID")
	if sid == "" {
		t.Skip("NOT_RUN: live owned Native SID is required")
	}
	if len(sid) != 36 || sid[8] != '-' || sid[13] != '-' || sid[18] != '-' || sid[23] != '-' {
		t.Fatal("malformed live Native SID")
	}
	if _, err := hex.DecodeString(strings.ReplaceAll(sid, "-", "")); err != nil {
		t.Fatal("malformed live Native SID")
	}
	f := newFabricG5PrivacyFixture(t, false)
	for _, route := range []string{"members", "list"} {
		code, data := f.call(t, http.MethodGet, "/v2/fabric/"+route, "", nil)
		var cards struct {
			Endpoints []fabricpkg.NetworkCard `json:"endpoints"`
		}
		if code != http.StatusOK || json.Unmarshal(data, &cards) != nil || len(cards.Endpoints) != 2 || bytes.Contains(data, []byte(sid)) {
			t.Fatal("live unjoined U visible or directory positive failed")
		}
		for _, card := range cards.Endpoints {
			if card.NativeSessionID != "" || (card.EndpointID != f.caller.Endpoint.ID && card.EndpointID != f.peer.Endpoint.ID) {
				t.Fatal("directory disclosed Native or foreign scope")
			}
		}

	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		code, data := f.call(t, http.MethodPost, "/v2/fabric/"+route, "", fabricpkg.ResolveInput{Query: f.peer.Endpoint.ID})
		var card fabricpkg.NetworkCard
		if code != http.StatusOK || json.Unmarshal(data, &card) != nil || card.EndpointID != f.peer.Endpoint.ID || card.NativeSessionID != "" {
			t.Fatal("authorized peer positive failed")
		}
		code, data = f.call(t, http.MethodPost, "/v2/fabric/"+route, "", fabricpkg.ResolveInput{Query: sid})
		if code != http.StatusNotFound {
			t.Fatal("unjoined Native thread resolved")
		}
		for _, peer := range []*fabricpkg.JoinResult{f.caller, f.peer, f.foreign} {
			if bytes.Contains(data, []byte(peer.SessionToken)) || bytes.Contains(data, []byte(peer.Endpoint.NativeSessionID)) {
				t.Fatal("lookup disclosed credential or Native ID")
			}
		}
	}
}
