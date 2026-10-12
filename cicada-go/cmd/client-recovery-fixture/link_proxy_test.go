package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientcontract"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type linkFaultActor struct {
	owner, device *e2ee.Identity
	binding       clientwire.Binding
	sequence      uint64
}

type linkFaultFixture struct {
	dbPath, origin string
	db             *store.Store
	hubKey         e2ee.PublicIdentity
	link           *store.CommunicationLink
	handler        http.Handler
	source, target *linkFaultActor
	restart        func()
}

func newLinkFaultFixture(t *testing.T, origin, dbPath string) *linkFaultFixture {
	t.Helper()
	f := &linkFaultFixture{origin: origin, dbPath: dbPath}
	if origin == "" {
		root := t.TempDir()
		state := filepath.Join(root, "state")
		config := control.Config{StateDir: state, WorkspaceRoot: filepath.Join(root, "workspace")}
		manager, err := control.New(config)
		if err != nil {
			t.Fatal(err)
		}
		f.dbPath = filepath.Join(state, "cicada.sqlite3")
		if err := os.WriteFile(filepath.Join(state, disposableMarker), []byte("disposable\n"), 0600); err != nil {
			t.Fatal(err)
		}
		f.handler = server.NewHandler(manager)
		hub := httptest.NewServer(f.handler)
		f.origin = hub.URL
		shutdown := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := manager.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
		}
		f.restart = func() {
			hub.Close()
			shutdown()
			manager, err = control.New(config)
			if err != nil {
				t.Fatal(err)
			}
			f.handler = server.NewHandler(manager)
			hub = httptest.NewServer(f.handler)
			f.origin = hub.URL
		}
		t.Cleanup(func() { hub.Close(); shutdown() })
	}
	if err := requireDisposableDatabase(f.dbPath); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.db.Close(); err != nil {
			t.Error(err)
		}
	})
	status, body := faultHTTP(t, f.origin, "/v2/client/identity", nil)
	var identity struct {
		HubID  string              `json:"hub_id"`
		Public e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &identity) != nil {
		t.Fatal("real Hub identity unavailable")
	}
	f.hubKey = identity.Public
	localID, err := f.db.GetClientHubID()
	if err != nil || localID != identity.HubID {
		t.Fatal("Hub database identity mismatch")
	}
	actor := func(label string) *linkFaultActor {
		t.Helper()
		owner, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		device, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ownerID := "synthetic-link-fault-" + owner.Public().ID
		if err := f.db.EnsureLocalOwnerPrincipal(ownerID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public()); err != nil {
			t.Fatal(err)
		}
		deviceID := "synthetic-link-fault-" + label
		proof, err := owner.SignOwnerDeviceGrant(ownerID, deviceID, device.Public(), identity.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := json.Marshal(map[string]any{"owner_id": ownerID, "owner_key_id": owner.Public().ID, "device_id": deviceID, "device_public_identity": device.Public(), "owner_device_grant": proof})
		if err != nil {
			t.Fatal(err)
		}
		status, body := faultHTTP(t, f.origin, "/v2/client/devices/enroll", enrollment)
		var enrolled struct {
			Epoch uint64 `json:"session_epoch"`
			Key   uint64 `json:"device_key_version"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &enrolled) != nil || enrolled.Epoch == 0 || enrolled.Key == 0 {
			t.Fatal("synthetic Owner-signed enrollment rejected")
		}
		return &linkFaultActor{owner: owner, device: device, binding: clientwire.Binding{HubID: identity.HubID, OwnerID: ownerID, DeviceID: deviceID, SessionEpoch: enrolled.Epoch, HubKeyVersion: 1, DeviceKeyVersion: enrolled.Key}}
	}
	f.source, f.target = actor("source"), actor("target")
	endpoint := func(a *linkFaultActor, label string) (string, string) {
		t.Helper()
		prefix := a.owner.Public().ID
		group, err := f.db.CreateGroup(store.Group{ID: "group_fault_" + prefix, Name: "Synthetic fault " + label, OwnerPrincipalID: a.binding.OwnerID, TrustDomainID: a.binding.OwnerID, State: store.GroupStateActive})
		if err != nil {
			t.Fatal(err)
		}
		principal, err := f.db.CreatePrincipal(store.Principal{ID: "principal_fault_" + prefix, Kind: store.PrincipalKindAgent, OwnerID: a.binding.OwnerID, TrustDomainID: a.binding.OwnerID, Name: "Synthetic " + label, Status: store.PrincipalStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.CreateMembership(store.Membership{PrincipalID: principal.ID, GroupID: group.ID, Role: "member", Grants: []string{"message.ask"}}); err != nil {
			t.Fatal(err)
		}
		ep, err := f.db.UpsertEndpointV2(store.Endpoint{ID: "endpoint_fault_" + prefix, Name: "Synthetic " + label, Harness: "codex", NativeSessionID: "synthetic_native_" + prefix, MachineID: "synthetic_node_" + prefix, Owner: a.binding.OwnerID, Status: "online", PrincipalID: principal.ID, GroupID: group.ID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := f.db.CreateSessionBinding(store.SessionBinding{EndpointID: ep.ID, PrincipalID: principal.ID, GroupID: group.ID, NativeSessionID: ep.NativeSessionID, NodeID: ep.MachineID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err = f.db.AcquireSessionBindingLease(binding.ID, "synthetic_lease_"+prefix, binding.Epoch, time.Now().Add(2*time.Hour).UTC().Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := key.SignEndpointKeyAttestation(ep.ID, binding.PrincipalID, binding.NodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.RegisterEndpointKeyCandidate(ep.ID, binding.PrincipalID, binding.ID, binding.Epoch, attestation); err != nil {
			t.Fatal(err)
		}
		return ep.ID, group.ID
	}
	se, sg := endpoint(f.source, "source")
	te, tg := endpoint(f.target, "target")
	invite, err := f.db.CreateExternalThreadInvite(store.ExternalThreadInviteInput{OwnerID: f.source.binding.OwnerID, SourceEndpointID: se, SourceGroupID: sg, HubID: identity.HubID, Direction: "forward", Actions: []string{"ask", "reply"}, DataScopes: []string{"thread.message"}, ExpiresAt: time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := f.db.AcceptExternalThreadInvite(invite.Token, f.target.binding.OwnerID, te, tg)
	if err != nil {
		t.Fatal(err)
	}
	f.link, err = f.db.GetCommunicationLinkForOwner(accepted.LinkID, f.source.binding.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func faultHTTP(t *testing.T, origin, path string, body []byte) (int, []byte) {
	t.Helper()
	method := http.MethodPost
	if body == nil {
		method = http.MethodGet
	}
	r, err := http.NewRequest(method, origin+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxFixturePacket+1))
	if err != nil || len(data) > maxFixturePacket {
		t.Fatal("invalid bounded response")
	}
	return response.StatusCode, data
}

func (f *linkFaultFixture) seal(t *testing.T, a *linkFaultActor, operation string, input any) []byte {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	a.sequence++
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest, HubID: a.binding.HubID, OwnerID: a.binding.OwnerID, DeviceID: a.binding.DeviceID, SessionEpoch: a.binding.SessionEpoch, Sequence: a.sequence, OperationID: fmt.Sprintf("synthetic-fault-%d", a.sequence), Operation: operation, SenderKeyID: a.device.Public().ID, SenderKeyVersion: a.binding.DeviceKeyVersion, ReceiverKeyID: f.hubKey.ID, ReceiverKeyVersion: a.binding.HubKeyVersion}
	packet, err := clientwire.SealRequest(a.device, f.hubKey, a.binding, route, body)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func (f *linkFaultFixture) open(t *testing.T, a *linkFaultActor, packet []byte) (bool, json.RawMessage, string) {
	t.Helper()
	opened, err := clientwire.OpenResponse(a.device, f.hubKey, a.binding, packet)
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		OK        bool            `json:"ok"`
		Result    json.RawMessage `json:"result"`
		ErrorCode string          `json:"error_code"`
	}
	if err := json.Unmarshal(opened.Plaintext, &reply); err != nil {
		t.Fatal(err)
	}
	return reply.OK, reply.Result, reply.ErrorCode
}

func (f *linkFaultFixture) call(t *testing.T, a *linkFaultActor, operation string, input any) json.RawMessage {
	t.Helper()
	status, packet := faultHTTP(t, f.origin, "/v2/client/rpc", f.seal(t, a, operation, input))
	if status != http.StatusOK {
		t.Fatal("real RPC transport rejected")
	}
	ok, result, _ := f.open(t, a, packet)
	if !ok {
		t.Fatal("real RPC business operation rejected")
	}
	return result
}

func (f *linkFaultFixture) grantInput(t *testing.T, a *linkFaultActor, operation string) map[string]any {
	t.Helper()
	if operation == "link.key_grant" {
		var manifest store.CommunicationLinkKeyManifest
		if json.Unmarshal(f.call(t, a, "link.key_manifest", map[string]any{"link_id": f.link.ID}), &manifest) != nil {
			t.Fatal("manifest invalid")
		}
		side := e2ee.OwnerLinkGrantSideTarget
		if a == f.source {
			side = e2ee.OwnerLinkGrantSideSource
		}
		expiry, err := time.Parse(time.RFC3339Nano, f.link.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := a.owner.SignOwnerLinkKeyGrant(a.binding.OwnerID, f.link.ID, manifest.ContractDigest, manifest.Digest, uint64(manifest.LinkVersion), side, time.Now().Add(-time.Minute), expiry)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"link_id": f.link.ID, "side": string(side), "owner_key_id": a.owner.Public().ID, "signed_proof": proof}
	}
	policy := store.CommunicationLinkReviewPolicy{Mode: store.CommunicationLinkReviewNone, Reviewers: []store.CommunicationLinkReviewer{}}
	var preview store.CommunicationLinkReviewPolicyPreview
	if json.Unmarshal(f.call(t, a, "link.review_policy_preview", map[string]any{"link_id": f.link.ID, "policy": policy}), &preview) != nil {
		t.Fatal("policy preview invalid")
	}
	expiry, err := time.Parse(time.RFC3339Nano, preview.MaximumProofExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := a.owner.SignOwnerLinkReviewPolicy(a.binding.OwnerID, f.link.ID, preview.ContractDigest, preview.PolicyDigest, uint64(preview.LinkVersion), uint64(preview.PolicyVersion), e2ee.OwnerLinkGrantSide(preview.Side), time.Now().Add(-time.Minute), expiry)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"link_id": f.link.ID, "owner_key_id": a.owner.Public().ID, "expected_policy_version": preview.ExpectedPolicyVersion, "policy": policy, "signed_proof": proof}
}

func linkReviewGrantRowCount(t *testing.T, dbPath, linkID string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	queryErr := db.QueryRow(`SELECT count(*) FROM communication_link_review_policy_grants_v2 WHERE link_id=?`, linkID).Scan(&count)
	closeErr := db.Close()
	if queryErr != nil || closeErr != nil {
		t.Fatalf("read-only Link grant count failed: query=%v close=%v", queryErr, closeErr)
	}
	return count
}

func linkRequestRouteOperation(t *testing.T, dbPath, ownerID, deviceID, operationID string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var operation string
	queryErr := db.QueryRow(`SELECT route_operation FROM client_device_requests_v2 WHERE owner_id=? AND device_id=? AND operation_id=?`,
		ownerID, deviceID, operationID).Scan(&operation)
	closeErr := db.Close()
	if queryErr != nil || closeErr != nil {
		t.Fatalf("read exact request route failed: query=%v close=%v", queryErr, closeErr)
	}
	return operation
}

func TestLinkFaultProxyReadOnlyStatusResponseLossAcrossRestart(t *testing.T) {
	f := newLinkFaultFixture(t, "", "")
	beforeStatus, err := f.db.GetCommunicationLinkReviewPolicyForOwner(f.link.ID, f.target.binding.OwnerID)
	if err != nil || beforeStatus.LinkID != f.link.ID || !beforeStatus.Current || beforeStatus.PolicyVersion != 0 {
		t.Fatal("initial Owner-scoped status unavailable")
	}
	beforeDevice, err := f.db.GetClientDevice(f.target.binding.OwnerID, f.target.binding.DeviceID)
	if err != nil || beforeDevice.State != store.ClientDeviceActive || f.target.sequence != beforeDevice.LastRequestSeq {
		t.Fatal("initial exact device sequence unavailable")
	}
	grantsBefore := linkReviewGrantRowCount(t, f.dbPath, f.link.ID)
	if grantsBefore != 0 {
		t.Fatal("status read fixture unexpectedly starts with review grants")
	}

	packet := f.seal(t, f.target, "link.review_policy_status", map[string]any{"link_id": f.link.ID})
	var requestPacket clientwire.Packet
	if json.Unmarshal(packet, &requestPacket) != nil || requestPacket.Route.Operation != "link.review_policy_status" {
		t.Fatal("sealed status packet route was not retained")
	}
	var events bytes.Buffer
	p, err := newLinkFaultProxy(f.dbPath, f.origin, f.target.binding.OwnerID, f.target.binding.DeviceID,
		"link.review_policy_status", "response-loss", &events)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.client.CloseIdleConnections)
	proxy := httptest.NewServer(p)
	t.Cleanup(proxy.Close)
	request, err := http.NewRequest(http.MethodPost, proxy.URL+"/v2/client/rpc", bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	response, err := proxy.Client().Do(request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("original status response was not lost")
	}
	var ready struct {
		Event                    string `json:"event"`
		Mode                     string `json:"mode"`
		Operation                string `json:"operation"`
		RequestSHA256            string `json:"request_sha256"`
		ResponseSHA256           string `json:"response_sha256"`
		Scope                    string `json:"scope"`
		RequestStatus            string `json:"request_status"`
		HandlerExecuted          bool   `json:"handler_executed"`
		RequestSequence          uint64 `json:"request_sequence"`
		ReservedResponseSequence uint64 `json:"reserved_response_sequence"`
	}
	eventBytes := snapshotFaultEvents(p, &events)
	if json.Unmarshal(eventBytes, &ready) != nil || ready.Event != "FAULT_READY" || ready.Mode != "response-loss" ||
		ready.Operation != "link.review_policy_status" || ready.RequestSHA256 != packetDigest(packet) ||
		len(ready.ResponseSHA256) != 64 || ready.Scope != "REAL_HANDLER_COMPLETED_TRANSPORT" ||
		ready.RequestStatus != store.ClientRequestCompleted || !ready.HandlerExecuted ||
		ready.RequestSequence != requestPacket.Route.Sequence || ready.ReservedResponseSequence != beforeDevice.NextResponseSeq {
		t.Fatal("status fault did not prove one completed real handler response")
	}
	if bytes.Contains(eventBytes, []byte(f.target.binding.OwnerID)) || bytes.Contains(eventBytes, []byte(f.target.binding.DeviceID)) || bytes.Contains(eventBytes, packet) {
		t.Fatal("status fault evidence leaked private routing or packet bytes")
	}
	input := requestCoordinates(requestPacket, packet)
	completed, err := f.db.LookupClientRequestRecovery(input)
	if err != nil || completed.Request.Status != store.ClientRequestCompleted ||
		completed.Request.CiphertextDigest != packetDigest(packet) ||
		completed.ReservedResponseSequence != ready.ReservedResponseSequence ||
		packetDigest(completed.Request.ResponsePacket) != ready.ResponseSHA256 {
		t.Fatal("real Hub did not durably complete the exact status request before restart")
	}
	if bytes.Contains(eventBytes, completed.Request.ResponsePacket) {
		t.Fatal("status fault evidence leaked the encrypted response packet")
	}

	oldHubKey := f.hubKey
	f.restart() // Reopen the same disposable Control state; no SQL state is simulated.
	p.mu.Lock()
	p.origin = f.origin
	p.mu.Unlock()
	statusCode, identityBytes := faultHTTP(t, f.origin, "/v2/client/identity", nil)
	var identity struct {
		HubID  string              `json:"hub_id"`
		Public e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if statusCode != http.StatusOK || json.Unmarshal(identityBytes, &identity) != nil ||
		identity.HubID != f.target.binding.HubID || !reflect.DeepEqual(identity.Public, oldHubKey) {
		t.Fatal("restarted Hub identity or Control key changed")
	}
	statusCode, recovered := faultHTTP(t, proxy.URL, "/v2/client/rpc/recover", packet)
	if statusCode != http.StatusOK || packetDigest(recovered) != ready.ResponseSHA256 {
		t.Fatal("exact status recovery did not return the cached response")
	}
	ok, result, code := f.open(t, f.target, recovered)
	var afterStatus store.CommunicationLinkReviewPolicyStatus
	if !ok || code != "" || json.Unmarshal(result, &afterStatus) != nil ||
		afterStatus.LinkID != f.link.ID || afterStatus.LinkVersion != f.link.Version ||
		afterStatus.ContractDigest != f.link.ContractDigest || afterStatus.Policy.Mode != store.CommunicationLinkReviewNone || !afterStatus.Current {
		t.Fatal("recovered encrypted status DTO did not match the exact Link")
	}
	beforeStatus.VerifiedAt, afterStatus.VerifiedAt = "", ""
	if !reflect.DeepEqual(*beforeStatus, afterStatus) {
		t.Fatal("status recovery changed Owner-visible Link policy state")
	}

	reopened, err := store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	durable, err := reopened.LookupClientRequestRecovery(input)
	if err != nil || durable.Request.Status != store.ClientRequestCompleted ||
		linkRequestRouteOperation(t, f.dbPath, input.OwnerID, input.DeviceID, input.OperationID) != "link.review_policy_status" ||
		durable.Request.OperationID != input.OperationID || durable.Request.Sequence != input.Sequence ||
		durable.Request.CiphertextDigest != input.CiphertextDigest ||
		durable.ReservedResponseSequence != ready.ReservedResponseSequence ||
		!bytes.Equal(durable.Request.ResponsePacket, recovered) {
		t.Fatal("reopened durable request/response ledger differs from exact recovered packet")
	}
	afterDevice, err := reopened.GetClientDevice(f.target.binding.OwnerID, f.target.binding.DeviceID)
	if err != nil || afterDevice.LastRequestSeq != input.Sequence ||
		afterDevice.NextResponseSeq != beforeDevice.NextResponseSeq+1 {
		t.Fatal("status read consumed more than one exact device request/response sequence")
	}
	if grantsAfter := linkReviewGrantRowCount(t, f.dbPath, f.link.ID); grantsAfter != grantsBefore {
		t.Fatal("read-only status request changed durable Owner grant rows")
	}
	if statusCode, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc", packet); statusCode != http.StatusConflict {
		t.Fatal("fault proxy replayed the completed status handler")
	}
	changed := append(append([]byte(nil), packet...), '\n')
	if statusCode, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc/recover", changed); statusCode != http.StatusConflict {
		t.Fatal("changed packet crossed the exact recovery fence")
	}
}

func TestLinkFaultProxyRealHubRecovery(t *testing.T) {
	for _, operation := range []string{"link.key_grant", "link.review_policy_grant"} {
		for _, mode := range []string{"response-loss", "processing", "uncertain", "legacy"} {
			t.Run(operation+"/"+mode, func(t *testing.T) { exerciseLinkFault(t, newLinkFaultFixture(t, "", ""), operation, mode) })
		}
	}
}

func snapshotFaultEvents(p *linkFaultProxy, events *bytes.Buffer) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), events.Bytes()...)
}

// Startup fences the database before HTTP can serve. Keep one absolute caller
// deadline while probing the real identity with bounded individual requests.
func waitForUncertainHub(ctx context.Context, f *linkFaultFixture, operationID, origin string) error {
	client := &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := f.db.GetClientRequestByOperationID(f.target.binding.OwnerID, f.target.binding.DeviceID, operationID)
		if err != nil {
			return err
		}
		if state.Status == store.ClientRequestUncertain {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v2/client/identity", nil)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, maxFixturePacket+1))
				closeErr := response.Body.Close()
				var identity struct {
					HubID string `json:"hub_id"`
				}
				if response.StatusCode == http.StatusOK && readErr == nil && closeErr == nil && len(body) <= maxFixturePacket && json.Unmarshal(body, &identity) == nil {
					if identity.HubID != f.target.binding.HubID {
						return errors.New("restarted Hub identity mismatch")
					}
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestLinkFaultProxyRestartReadiness(t *testing.T) {
	f := newLinkFaultFixture(t, "", "")
	packet := f.seal(t, f.target, "link.key_grant", map[string]any{})
	if err := run([]string{"--db", f.dbPath, "--mode", "uncertain"}, bytes.NewReader(packet)); err != nil {
		t.Fatal(err)
	}
	f.restart() // Actual Control startup, never an SQL status replacement.
	unstarted := httptest.NewUnstartedServer(f.handler)
	t.Cleanup(unstarted.Close)
	origin := "http://" + unstarted.Listener.Addr().String()
	operationID := fmt.Sprintf("synthetic-fault-%d", f.target.sequence)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	started := time.Now()
	err := waitForUncertainHub(ctx, f, operationID, origin)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("database fence bypassed real listener readiness or extended deadline")
	}
	unstarted.Start()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForUncertainHub(ctx, f, operationID, origin); err != nil {
		t.Fatal("real matching Hub identity did not complete readiness")
	}
}

func exerciseLinkFault(t *testing.T, f *linkFaultFixture, operation, mode string) {
	t.Helper()
	sourceInput := f.grantInput(t, f.source, operation)
	targetInput := f.grantInput(t, f.target, operation)
	f.call(t, f.source, operation, sourceInput)
	packet := f.seal(t, f.target, operation, targetInput)
	var events bytes.Buffer
	p, err := newLinkFaultProxy(f.dbPath, f.origin, f.target.binding.OwnerID, f.target.binding.DeviceID, operation, mode, &events)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.client.CloseIdleConnections)
	proxy := httptest.NewServer(p)
	t.Cleanup(proxy.Close)
	request, err := http.NewRequest(http.MethodPost, proxy.URL+"/v2/client/rpc", bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	response, err := proxy.Client().Do(request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("original response was not lost")
	}
	var ready map[string]any
	eventBytes := snapshotFaultEvents(p, &events)
	if json.Unmarshal(eventBytes, &ready) != nil || ready["event"] != "FAULT_READY" || ready["request_sha256"] != packetDigest(packet) {
		t.Fatal("missing exact redacted FAULT_READY")
	}
	if ready["handler_executed"] != (mode == "response-loss") {
		t.Fatal("outer-ledger fault mislabeled as handler execution")
	}
	if bytes.Contains(eventBytes, []byte(f.target.binding.OwnerID)) || bytes.Contains(eventBytes, []byte(f.target.binding.DeviceID)) || bytes.Contains(eventBytes, packet) {
		t.Fatal("sensitive packet coordinates leaked")
	}
	if mode == "uncertain" {
		status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc/recover", packet)
		if status != http.StatusConflict {
			t.Fatal("uncertainty notice existed before real restart")
		}
		if f.restart != nil {
			f.restart()
			p.mu.Lock()
			p.origin = f.origin // Test-only new listener; CLI uses a fixed published port.
			p.mu.Unlock()
		} else {
			// The Root-owned gate watches this public marker and restarts only its
			// recorded Hub container. No simulated startup state mutation here.
			t.Log("FAULT_READY ROOT_RESTART_REQUIRED operation=" + operation + " request_sha256=" + packetDigest(packet))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		err := waitForUncertainHub(ctx, f, fmt.Sprintf("synthetic-fault-%d", f.target.sequence), f.origin)
		cancel()
		if err != nil {
			t.Fatal("real restart did not expose the matching Hub identity before deadline:", err)
		}
	}
	status, recovered := faultHTTP(t, proxy.URL, "/v2/client/rpc/recover", packet)
	if mode == "response-loss" {
		if status != http.StatusOK || packetDigest(recovered) != ready["response_sha256"] {
			t.Fatal("COMPLETED cached response changed")
		}
		ok, _, _ := f.open(t, f.target, recovered)
		if !ok {
			t.Fatal("real Link grant was not accepted")
		}
	} else if mode == "uncertain" {
		if status != http.StatusOK {
			t.Fatal("restart uncertainty transport failed")
		}
		ok, _, code := f.open(t, f.target, recovered)
		if ok || code != "OUTCOME_UNCERTAIN" {
			t.Fatal("invalid signed encrypted uncertainty notice")
		}
	} else {
		var failure struct {
			Code string `json:"code"`
		}
		want := "STILL_PROCESSING"
		if mode == "legacy" {
			want = "RECOVERY_UNAVAILABLE"
		}
		if status != http.StatusConflict || json.Unmarshal(recovered, &failure) != nil || failure.Code != want {
			t.Fatal("wrong outer recovery error")
		}
	}
	statusAgain, again := faultHTTP(t, proxy.URL, "/v2/client/rpc/recover", packet)
	if statusAgain != status || !bytes.Equal(again, recovered) {
		t.Fatal("exact recovery was not repeatable")
	}
	before, err := f.db.GetClientDevice(f.target.binding.OwnerID, f.target.binding.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	directStatus, directResponse := faultHTTP(t, f.origin, "/v2/client/rpc", packet)
	if mode == "response-loss" {
		if directStatus != http.StatusOK || !bytes.Equal(directResponse, recovered) {
			t.Fatal("real Hub exact retry changed cached result")
		}
	} else if directStatus != http.StatusConflict {
		t.Fatal("real Hub redispatched interrupted original request")
	}
	after, err := f.db.GetClientDevice(f.target.binding.OwnerID, f.target.binding.DeviceID)
	if err != nil || after.LastRequestSeq != before.LastRequestSeq || after.NextResponseSeq != before.NextResponseSeq {
		t.Fatal("exact retry changed durable counters")
	}
	queryDB, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	table := "communication_link_key_grants_v2"
	if operation == "link.review_policy_grant" {
		table = "communication_link_review_policy_grants_v2"
	}
	var acceptedRows int
	queryErr := queryDB.QueryRow("SELECT count(*) FROM "+table+" WHERE link_id=?", f.link.ID).Scan(&acceptedRows)
	closeErr := queryDB.Close()
	wantRows := 1
	if mode == "response-loss" {
		wantRows = 2
	}
	if queryErr != nil || closeErr != nil || acceptedRows != wantRows {
		t.Fatal("fixture created duplicate or unexpected grant effects")
	}
	if status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc", packet); status != http.StatusConflict {
		t.Fatal("proxy repeated the original handler")
	}
	if status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc/recover", append(append([]byte(nil), packet...), '\n')); status != http.StatusConflict {
		t.Fatal("changed original packet was recovered")
	}
	newPacket := f.seal(t, f.target, "link.key_grants", map[string]any{"link_id": f.link.ID})
	if status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc", newPacket); status != http.StatusConflict {
		t.Fatal("new packet passed the write fence")
	}
	if bytes.Count(snapshotFaultEvents(p, &events), []byte("FAULT_READY")) != 1 {
		t.Fatal("fault fired more than once")
	}
	// Independent enrolled source performs fresh authoritative reconciliation
	// directly on the Hub, without advancing the faulted target's counters.
	if operation == "link.key_grant" {
		var statuses []store.CommunicationLinkKeyGrantStatus
		if json.Unmarshal(f.call(t, f.source, "link.key_grants", map[string]any{"link_id": f.link.ID}), &statuses) != nil || len(statuses) != 2 {
			t.Fatal("fresh KEY reconciliation invalid")
		}
		for _, s := range statuses {
			if s.Side == "TARGET" && s.Accepted != (mode == "response-loss") {
				t.Fatal("KEY reconciliation invented or lost target acceptance")
			}
		}
	} else {
		var state store.CommunicationLinkReviewPolicyStatus
		if json.Unmarshal(f.call(t, f.source, "link.review_policy_status", map[string]any{"link_id": f.link.ID}), &state) != nil || state.LinkID != f.link.ID || state.Policy.Mode != store.CommunicationLinkReviewNone {
			t.Fatal("fresh NONE reconciliation invalid")
		}
		if mode == "response-loss" {
			if !state.Current || state.PolicyVersion != 1 || len(state.AcceptedSides) != 2 || len(state.OwnerApprovals) != 2 {
				t.Fatal("fresh NONE did not confirm the exact bilateral policy version")
			}
			for _, approval := range state.OwnerApprovals {
				proof := sourceInput["signed_proof"].([]byte)
				if approval.Side == "TARGET" {
					proof = targetInput["signed_proof"].([]byte)
				}
				if approval.Evidence == nil || !bytes.Equal(approval.Evidence.SignedProof, proof) {
					t.Fatal("fresh NONE evidence does not match the original proof")
				}
			}
		} else {
			// The existing default NONE head at version zero is Current=true.
			// It is not acceptance of the pending version-one Owner proof.
			if state.PolicyVersion != 0 || len(state.AcceptedSides) != 0 || len(state.OwnerApprovals) != 0 {
				t.Fatal("old NONE head was mistaken for the interrupted grant")
			}
		}
	}
	if status, body := faultHTTP(t, f.origin, "/v2/client/capabilities", nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"external_thread_links":false`)) {
		t.Fatal("ordinary external messages were opened")
	}
}

func TestLinkFaultProxyRejectsUnsafeIngress(t *testing.T) {
	f := newLinkFaultFixture(t, "", "")
	for _, raw := range []string{"http://localhost:8787", "http://10.0.0.1:8787", "https://127.0.0.1:8787", "http://127.0.0.1:8787/path", "http://user@127.0.0.1:8787", "http://127.0.0.1:8787?x=1"} {
		if _, err := loopbackOrigin(raw); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	for _, operation := range []string{"link.key_manifest", "link.key_grants", "link.key_grant", "link.review_policy_preview", "link.review_policy_grant"} {
		if !dedicatedLinkOperation(operation) || !clientcontract.Allows(clientcontract.RoleExternal, operation) {
			t.Fatal("dedicated operation not in current catalog")
		}
	}
	if dedicatedLinkOperation("control.submit") || dedicatedLinkOperation("link.review_policy_status") {
		t.Fatal("fault allowlist expanded")
	}
	if !dedicatedLinkStatusReadOperation("link.review_policy_status") ||
		dedicatedLinkStatusReadOperation("link.review_policy_grant") ||
		dedicatedLinkStatusReadOperation("control.submit") {
		t.Fatal("read-only status selector is not exact")
	}
	for _, mode := range []string{"processing", "uncertain", "legacy"} {
		if _, err := newLinkFaultProxy(f.dbPath, f.origin, f.target.binding.OwnerID, f.target.binding.DeviceID,
			"link.review_policy_status", mode, io.Discard); err == nil {
			t.Fatal("read-only status accepted a synthetic interruption mode")
		}
	}
	var events bytes.Buffer
	p, err := newLinkFaultProxy(f.dbPath, f.origin, f.target.binding.OwnerID, f.target.binding.DeviceID, "link.key_grant", "processing", &events)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.client.CloseIdleConnections)
	proxy := httptest.NewServer(p)
	t.Cleanup(proxy.Close)
	for _, path := range []string{"/v2/client/devices/enroll", "/v2/control/intent", "/v2/client/rpc?unexpected=1"} {
		if status, _ := faultHTTP(t, proxy.URL, path, []byte(`{}`)); status != http.StatusForbidden {
			t.Fatal("unapproved proxy path accepted")
		}
	}
	foreign := f.seal(t, f.source, "link.key_grant", map[string]any{})
	if status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc", foreign); status != http.StatusForbidden {
		t.Fatal("foreign device armed fault")
	}
	outside := f.seal(t, f.target, "control.submit", map[string]any{})
	if status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc", outside); status != http.StatusConflict {
		t.Fatal("unlisted write passed proxy")
	}
	forged := f.seal(t, f.target, "link.key_grant", map[string]any{})
	var envelope clientwire.Packet
	if err := json.Unmarshal(forged, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Route.SenderKeyID = "forged"
	forged, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := faultHTTP(t, proxy.URL, "/v2/client/rpc", forged); status != http.StatusBadGateway {
		t.Fatal("forged packet was seeded")
	}
	eventBytes := snapshotFaultEvents(p, &events)
	if bytes.Contains(eventBytes, []byte("FAULT_READY")) || !bytes.Contains(eventBytes, []byte("FAULT_FAILED")) {
		t.Fatal("failed authentication reported readiness")
	}
	if _, err := f.db.GetClientRequestByOperationID(f.target.binding.OwnerID, f.target.binding.DeviceID, envelope.Route.OperationID); err == nil {
		t.Fatal("forged packet reached durable ledger")
	}
}

func TestLinkFixtureProcessHelper(t *testing.T) {
	encoded := os.Getenv("CICADA_LINK_FIXTURE_PROCESS_ARGS")
	if encoded == "" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(encoded), &args) != nil {
		os.Exit(2)
	}
	if serveLink(args, os.Stdout) != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestLinkFaultProxyServeLifecycle(t *testing.T) {
	f := newLinkFaultFixture(t, "", "")
	args, err := json.Marshal([]string{"--db", f.dbPath, "--hub-url", f.origin, "--owner-id", f.target.binding.OwnerID, "--device-id", f.target.binding.DeviceID, "--operation", "link.key_grant", "--mode", "processing"})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestLinkFixtureProcessHelper$")
	child.Env = append(os.Environ(), "CICADA_LINK_FIXTURE_PROCESS_ARGS="+string(args))
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	})
	decoder := json.NewDecoder(output)
	var ready struct{ Event, Listen string }
	if err := decoder.Decode(&ready); err != nil || ready.Event != "READY" || ready.Listen == "" {
		t.Fatal("owned proxy did not become ready")
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	var cleanup struct {
		Event, Scope    string
		DatabaseDeleted bool `json:"database_deleted"`
	}
	if err := decoder.Decode(&cleanup); err != nil || cleanup.Event != "CLEANUP" || cleanup.Scope != "PROXY_ONLY" || cleanup.DatabaseDeleted {
		t.Fatal("owned proxy cleanup not recorded correctly")
	}
	if err := child.Wait(); err != nil {
		t.Fatal("owned proxy failed graceful shutdown")
	}
	if _, err := os.Stat(f.dbPath); err != nil {
		t.Fatal("proxy deleted Hub database")
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + ready.Listen + "/v2/client/identity")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("owned proxy listener remains after shutdown")
	}
}

// Opt-in current-image gate. The Root supervisor owns Hub launch, artifact pins,
// and actual restarts. This test never calls Docker or fabricates a crash state.
func TestClientDockerHubLinkFaultFixture(t *testing.T) {
	origin, dbPath := os.Getenv("CICADA_TEST_HUB_URL"), os.Getenv("CICADA_TEST_HUB_DB")
	if origin == "" || dbPath == "" {
		t.Skip("requires a Root-owned disposable Hub and database")
	}
	if os.Getenv("CICADA_TEST_LINK_UNCERTAIN_RESTART") != "external" {
		t.Fatal("Root-owned uncertain restart coordination required")
	}
	for _, operation := range []string{"link.key_grant", "link.review_policy_grant"} {
		for _, mode := range []string{"response-loss", "processing", "uncertain", "legacy"} {
			t.Run(operation+"/"+mode, func(t *testing.T) { exerciseLinkFault(t, newLinkFaultFixture(t, origin, dbPath), operation, mode) })
		}
	}
}
