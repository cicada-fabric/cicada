package n3_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// The actual App process retains its Owner signer throughout Node approval.
// Only the Node protocol actor is synthetic. These tests do not accept the
// production Node adapter/MCP, native queue, Hook bridge or Windows behavior.
type endpointSecurityFixture struct {
	f        *hubFixture
	app      *appProcess
	node     *appPairNodeFixture
	original appcore.Snapshot
	do       func(appcore.Action) appcore.Snapshot
}

func newEndpointSecurityFixture(t *testing.T) *endpointSecurityFixture {
	t.Helper()
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "endpoint-security-actual-app.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	var initial appActorCheckpoint
	readJSON(t, marker, &initial)
	v := &endpointSecurityFixture{f: f, app: app, original: initial.Current}
	sequence := 0
	v.do = func(action appcore.Action) appcore.Snapshot {
		t.Helper()
		sequence++
		reply := commandApp(t, f, app, sequence, appActorCommand{Action: &action})
		s := reply.Current
		if reply.ActionFailed || reply.ClockMode != "WALL_CLOCK" ||
			s.Account.OwnerID != v.original.Account.OwnerID || s.Account.DeviceID != v.original.Account.DeviceID ||
			s.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID || s.Account.OwnerFingerprint != v.original.Account.OwnerFingerprint ||
			s.Hub.Fingerprint != v.original.Hub.Fingerprint || s.Management != appcore.ManagementUnavailable {
			t.Fatal("actual App approval changed identity, failed, or claimed general management")
		}
		return s
	}
	v.node = newAppPairNodeFixtureID(t, f, v.do, "synthetic-n3-endpoint-security-primary")
	return v
}

func endpointSecurityRegistration(sid string) nodewire.EndpointRegistration {
	return nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: sid,
		Name: "Synthetic same display name", Workspace: `C:\synthetic\当前线程\workspace`}
}

func endpointSecurityResult(t *testing.T, n *appPairNodeFixture, request appPairNodeRequest, response appPairNodeHTTPResult) nodewire.EndpointRegistrationResult {
	t.Helper()
	if response.err != nil || response.status != http.StatusOK {
		t.Fatal("actual Node Endpoint operation did not return an authenticated result", response.status)
	}
	reply := n.openRPC(t, request, response.response)
	var result nodewire.EndpointRegistrationResult
	if !reply.OK || json.Unmarshal(reply.Result, &result) != nil || result.EndpointID == "" || len(result.StateDigest) != 64 {
		t.Fatal("actual Node Endpoint operation did not settle its exact typed result", reply.ErrorCode)
	}
	return result
}

func endpointSecurityRefusal(t *testing.T, n *appPairNodeFixture, operation string, body any, expected error) {
	t.Helper()
	request := n.prepareRPC(t, operation, body)
	response := n.postRPC(t, request, false)
	if response.err != nil || response.status != http.StatusOK {
		t.Fatal("known Endpoint refusal was not authenticated", response.status)
	}
	reply := n.openRPC(t, request, response.response)
	if reply.OK || reply.ErrorCode != expected.Error() {
		t.Fatal("known Endpoint refusal became success or an uncertain outcome", reply.ErrorCode)
	}
	retry := n.postRPC(t, request, false)
	if retry.err != nil || retry.status != http.StatusOK || !bytes.Equal(response.response, retry.response) {
		t.Fatal("known refusal did not retain its exact authenticated receipt")
	}
}

// Observe only the disposable Hub's persisted database while its process is
// stopped. mode=ro prevents this oracle from creating authority or fixing state.
func (v *endpointSecurityFixture) assertRows(t *testing.T, endpoints map[string]string, count int) {
	t.Helper()
	v.f.hub.kill(t)
	u := url.URL{Scheme: "file", Path: filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3")}
	u.RawQuery = "mode=ro"
	db := must(sql.Open("sqlite", u.String()))
	defer db.Close()
	var total int
	if err := db.QueryRow(`SELECT count(*) FROM fabric_endpoints WHERE harness='codex'`).Scan(&total); err != nil || total != count {
		t.Fatal("registration/leave/replay created or lost a native identity", total, err)
	}
	for id, status := range endpoints {
		var owner, node, actual, workspace string
		if err := db.QueryRow(`SELECT owner,machine_id,status,workspace FROM fabric_endpoints WHERE id=?`, id).
			Scan(&owner, &node, &actual, &workspace); err != nil || owner != v.original.Account.OwnerID || node != v.node.id || actual != status ||
			workspace != endpointSecurityRegistration("").Workspace {
			t.Fatal("persisted Endpoint identity, metadata or presence changed", err)
		}
		for _, table := range []string{"session_bindings", "endpoint_group_memberships", "endpoint_network_memberships_v2", "network_access_sessions_v2", "group_endpoint_key_grants_v2"} {
			var rights int
			if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE endpoint_id=?`, id).Scan(&rights); err != nil || rights != 0 {
				t.Fatal("metadata-only registration manufactured business authority", table, rights, err)
			}
		}
		var memberships int
		if err := db.QueryRow(`SELECT count(*) FROM memberships WHERE principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=?)`, id).Scan(&memberships); err != nil || memberships != 0 {
			t.Fatal("metadata-only registration manufactured a Principal Group membership", memberships, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal("read-only disposable evidence DB failed to close", err)
	}
	v.f.start(t)
}

func TestN3EndpointSecurityZeroAuthorityAndIdentityRetention(t *testing.T) {
	v := newEndpointSecurityFixture(t)
	n := v.node
	in := endpointSecurityRegistration("synthetic-endpoint-original-A")
	var first, second, reused nodewire.EndpointRegistrationResult
	n.rpc(t, nodewire.EndpointRegisterOperation, in, &first)
	if first.Name != in.Name || first.Workspace != in.Workspace || first.Presence != "offline" || first.Reused {
		t.Fatal("first metadata registration changed display coordinates or claimed online authority")
	}
	other := in
	other.NativeSessionID = "synthetic-endpoint-original-B"
	n.rpc(t, nodewire.EndpointRegisterOperation, other, &second)
	if second.EndpointID == first.EndpointID || second.Name != first.Name || second.Workspace != first.Workspace {
		t.Fatal("equal human labels collapsed two original native identities")
	}
	renamed := in
	renamed.Name = "SYNTHETIC UNREVIEWED REPLACEMENT"
	n.rpc(t, nodewire.EndpointRegisterOperation, renamed, &reused)
	if !reused.Reused || reused.EndpointID != first.EndpointID || reused.Name != first.Name || reused.StateDigest != first.StateDigest {
		t.Fatal("repeat registration silently renamed, moved or reauthorized an existing identity")
	}
	moved := in
	moved.Workspace = "/synthetic/unreviewed/workspace"
	endpointSecurityRefusal(t, n, nodewire.EndpointRegisterOperation, moved, nodewire.ErrEndpointConflict)
	// A legitimate original Node token cannot select a different Node through
	// an otherwise real encrypted packet. This is a route-substitution test;
	// second-approved-Node adoption needs a separate actual App flow.
	forged := n.prepareRPC(t, nodewire.EndpointRegisterOperation, in)
	wrongBinding := n.binding
	wrongBinding.NodeID = "synthetic-n3-endpoint-security-other"
	forged.Route.NodeID = wrongBinding.NodeID
	plain := must(json.Marshal(in))
	forged.Packet = must(nodewire.SealRequest(n.key, wrongBinding.HubKey, wrongBinding, forged.Route, plain))
	clear(plain)
	wrongNode := n.postRPC(t, forged, false)
	if wrongNode.err != nil || wrongNode.status != http.StatusForbidden {
		t.Fatal("original Node credential selected another Node route", wrongNode.status)
	}
	// A Node credential and a public Endpoint ID are not a native Session
	// credential. These routes authenticate before either directory or writes.
	forgedSession, _, err := fabric.NewSessionCredential()
	if err != nil {
		t.Fatal(err)
	}
	for _, authorization := range []struct {
		header string
		status int
	}{{"CicadaNode " + n.token, http.StatusUnauthorized}, {"CicadaSession " + n.token, http.StatusUnauthorized},
		{"CicadaSession " + first.EndpointID, http.StatusUnauthorized}, {"CicadaSession " + forgedSession, http.StatusForbidden}} {
		for _, target := range []struct{ method, path string }{{http.MethodGet, "/v2/fabric/whoami"}, {http.MethodPost, "/v2/fabric/endpoint-keys"}} {
			code, _ := n.http(t, target.method, target.path, authorization.header, "", map[string]any{})
			if code != authorization.status {
				t.Fatal("metadata/Node credentials reached native communication authority", code)
			}
		}
	}
	v.assertRows(t, map[string]string{first.EndpointID: "offline", second.EndpointID: "offline"}, 2)
	t.Log("ENDPOINT_SECURITY actual_App_Owner_approval=true Control_inference=false synthetic_Node_PQ_TCP=true zero_business_authority=true duplicate_labels_distinct_ids=true repeat_read_only=true wrong_Node_fenced=true native_adapter_MCP_Windows_NOT_RUN=true")
}

func TestN3EndpointSecurityLeaveCASAndExactReplay(t *testing.T) {
	v := newEndpointSecurityFixture(t)
	n := v.node
	in := endpointSecurityRegistration("synthetic-endpoint-leave-A")
	var first, second nodewire.EndpointRegistrationResult
	n.rpc(t, nodewire.EndpointRegisterOperation, in, &first)
	other := in
	other.NativeSessionID = "synthetic-endpoint-leave-B"
	n.rpc(t, nodewire.EndpointRegisterOperation, other, &second)
	leave := nodewire.EndpointLeave{Harness: in.Harness, NativeSessionID: in.NativeSessionID, StateDigest: strings.Repeat("0", 64)}
	endpointSecurityRefusal(t, n, nodewire.EndpointLeaveOperation, leave, nodewire.ErrEndpointConflict)
	leave.NativeSessionID = "synthetic-endpoint-missing"
	endpointSecurityRefusal(t, n, nodewire.EndpointLeaveOperation, leave, nodewire.ErrEndpointUnavailable)
	v.assertRows(t, map[string]string{first.EndpointID: "offline", second.EndpointID: "offline"}, 2)
	leave.NativeSessionID, leave.StateDigest = in.NativeSessionID, first.StateDigest
	request := n.prepareRPC(t, nodewire.EndpointLeaveOperation, leave)
	response := n.postRPC(t, request, false)
	left := endpointSecurityResult(t, n, request, response)
	if left.EndpointID != first.EndpointID || left.Presence != "left" || left.StateDigest == first.StateDigest {
		t.Fatal("current explicit leave did not withdraw only its original identity")
	}
	v.assertRows(t, map[string]string{first.EndpointID: "left", second.EndpointID: "offline"}, 2)
	retry := n.postRPC(t, request, false)
	if retry.err != nil || retry.status != http.StatusOK || !bytes.Equal(response.response, retry.response) {
		t.Fatal("leave exact receipt did not survive actual Hub restart")
	}
	leave.StateDigest = first.StateDigest
	endpointSecurityRefusal(t, n, nodewire.EndpointLeaveOperation, leave, nodewire.ErrEndpointConflict)
	var current nodewire.EndpointRegistrationResult
	n.rpc(t, nodewire.EndpointRegisterOperation, in, &current)
	if current.EndpointID != left.EndpointID || current.Presence != "left" || current.StateDigest != left.StateDigest || !current.Reused {
		t.Fatal("repeat registration revived a left Endpoint or replaced its native identity")
	}
	v.assertRows(t, map[string]string{first.EndpointID: "left", second.EndpointID: "offline"}, 2)
	t.Log("ENDPOINT_SECURITY exact_leave_CAS=true stale_digest_signed_refusal=true durable_exact_receipt=true other_Endpoint_unchanged=true original_metadata_retained=true zero_rights_only=true Group_Network_withdrawal_NOT_RUN=true")
}

func TestN3EndpointSecurityRegistrationFaultRecovery(t *testing.T) {
	for _, mode := range []string{"before-forward", "drop-after-response", "unsigned-403", "corrupt-response"} {
		t.Run(mode, func(t *testing.T) {
			v := newEndpointSecurityFixture(t)
			n := v.node
			in := endpointSecurityRegistration("synthetic-endpoint-fault-" + mode)
			request := n.prepareRPC(t, nodewire.EndpointRegisterOperation, in)
			_, release := v.f.proxy.armMethod("/v2/node/control/rpc", http.MethodPost, mode, 1)
			defer release()
			lost := n.postRPC(t, request, true)
			if mode == "unsigned-403" {
				if lost.err != nil || lost.status != http.StatusForbidden {
					t.Fatal("unsigned refusal fault did not reach the intended boundary")
				}
			} else if mode == "corrupt-response" {
				if lost.err != nil || lost.status != http.StatusOK {
					t.Fatal("opaque response corruption did not reach the intended boundary")
				}
				if _, err := nodewire.OpenResponse(n.key, n.binding.HubKey, n.binding, lost.response); err == nil {
					t.Fatal("corrupt response authenticated as a Hub decision")
				}
			} else if lost.err == nil {
				t.Fatal("transport loss did not remain uncertain")
			}
			var trace []exchange
			for _, observed := range v.f.proxy.snapshot() {
				if observed.Method == http.MethodPost && observed.Path == "/v2/node/control/rpc" && observed.RequestSHA256 == hash(request.Packet) {
					trace = append(trace, observed)
				}
			}
			if len(trace) != 1 || trace[0].RequestSHA256 != hash(request.Packet) || trace[0].Forwarded != (mode != "before-forward") {
				t.Fatal("fault evidence did not preserve original request/forwarding history")
			}
			// Closing the App child does not revoke the Node's independent
			// approval. Only the owned Hub restarts; Node Runtime is NOT_RUN.
			v.app.kill(t)
			v.f.hub.kill(t)
			v.f.start(t)
			persisted := must(os.ReadFile(filepath.Join(v.f.dir, "app-pair-original-node-"+request.Route.OperationID+".packet")))
			if !bytes.Equal(persisted, request.Packet) {
				t.Fatal("uncertain recovery replaced the original persisted packet")
			}
			request.Packet = persisted
			recovered := n.postRPC(t, request, false)
			result := endpointSecurityResult(t, n, request, recovered)
			if result.Presence != "offline" || result.Reused || result.Name != in.Name || result.Workspace != in.Workspace {
				t.Fatal("recovery manufactured new authority, identity or an adopted result")
			}
			if trace[0].Forwarded && !bytes.Equal(trace[0].response, recovered.response) {
				t.Fatal("committed original receipt was not recovered byte-for-byte")
			}
			changed := in
			changed.Name = "SYNTHETIC SAME OPERATION DIFFERENT BODY"
			plain := must(json.Marshal(changed))
			changedRequest := request
			changedRequest.Packet = must(nodewire.SealRequest(n.key, n.binding.HubKey, n.binding, request.Route, plain))
			clear(plain)
			conflict := n.postRPC(t, changedRequest, false)
			if conflict.err != nil || conflict.status != http.StatusForbidden {
				t.Fatal("changed packet replaced an original operation/replay fence", conflict.status)
			}
			retry := n.postRPC(t, request, false)
			if retry.err != nil || retry.status != http.StatusOK || !bytes.Equal(recovered.response, retry.response) {
				t.Fatal("duplicate recovery changed the original authenticated receipt")
			}
			v.assertRows(t, map[string]string{result.EndpointID: "offline"}, 1)
			t.Log("ENDPOINT_SECURITY fault=" + mode + " actual_Hub_restart=true actual_App_child_closed=true original_packet_reused=true signed_receipt_verified=true one_zero_rights_Endpoint=true Node_process_restart_Runtime_NOT_RUN=true")
		})
	}
}

func TestN3EndpointSecurityConcurrentOriginalRequest(t *testing.T) {
	v := newEndpointSecurityFixture(t)
	n := v.node
	request := n.prepareRPC(t, nodewire.EndpointRegisterOperation, endpointSecurityRegistration("synthetic-endpoint-concurrent-original"))
	start := make(chan struct{})
	done := make(chan appPairNodeHTTPResult, 4)
	for range 4 {
		go func() {
			var result appPairNodeHTTPResult
			defer func() { done <- result }()
			<-start
			result = n.postRPC(t, request, false)
		}()
	}
	close(start)
	var completed [][]byte
	var rejected []int
	busy := 0
	for range 4 {
		response := <-done
		if response.err == nil && response.status == http.StatusTooManyRequests && response.RetryAfter == "1" {
			// Transport backpressure leaves the exact original request pending;
			// only the later PQ receipt can settle its original effect.
			busy++
			continue
		}
		if response.err != nil || response.status != http.StatusOK {
			var diagnostic struct {
				Error string `json:"error"`
			}
			if len(response.response) <= 2048 && json.Unmarshal(response.response, &diagnostic) == nil {
				t.Logf("ENDPOINT_SECURITY concurrent_public_HTTP_error=%q response_sha256=%s", diagnostic.Error, hash(response.response))
			}
			rejected = append(rejected, response.status)
			continue
		}
		reply := n.openRPC(t, request, response.response)
		if reply.OK {
			completed = append(completed, response.response)
		} else if reply.ErrorCode != "IN_PROGRESS" {
			t.Fatal("concurrent exact original request became a refusal or uncertain outcome", reply.ErrorCode)
		}
	}
	recovered := n.postRPC(t, request, false)
	result := endpointSecurityResult(t, n, request, recovered)
	for _, response := range completed {
		if !bytes.Equal(response, recovered.response) {
			t.Fatal("concurrent original requests produced multiple terminal receipts")
		}
	}
	if len(completed) == 0 || result.Presence != "offline" || result.Reused {
		t.Fatal("concurrent exact original request did not settle a single initial registration")
	}
	v.assertRows(t, map[string]string{result.EndpointID: "offline"}, 1)
	if len(rejected) != 0 {
		t.Log("ENDPOINT_SECURITY concurrent_original_serial_recovery_authenticated=true original_receipt=true effects_one=true")
		t.Fatal("concurrent exact original requests received non-authenticated rejection despite successful original recovery", rejected)
	}
	t.Logf("ENDPOINT_SECURITY concurrent_original_ciphertext_requests=4 busy_429_retry_after_1=%d durable_terminal_receipt_one=true effects_one=true zero_authority=true distinct_operation_ordering_NOT_RUN=true", busy)
}
