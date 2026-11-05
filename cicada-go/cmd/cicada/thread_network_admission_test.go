package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func TestThreadNetworkLegacyGroupAdmissionRefusedBeforeEffects(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	dir := t.TempDir()
	b := machineAgentJoinBridge{baseURL: server.URL, stateDir: dir, nodeID: "synthetic-legacy-node"}
	for _, op := range []string{"endpoint_register", "native_pair_join_named"} {
		q := syntheticLocalEndpointRequest(op)
		q.APIOrigin = server.URL
		if op == "native_pair_join_named" {
			q.Name = ""
			q.PairLabel = "synthetic-legacy"
			q.Slot = "A"
		}
		if q.validate() != nil {
			t.Fatal("invalid synthetic native invocation")
		}
		if _, err := b.endpointOperation(q); err == nil || !strings.HasPrefix(err.Error(), wire.ThreadCollaborationErrorClassificationRequired) {
			t.Fatal("legacy native Group source bypassed zero registration", err)
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 || posts.Load() != 0 {
		t.Fatal("refused legacy source allocated identity or sent RPC", err)
	}
}

func TestThreadNetworkAdmissionExactRecoveryAndOtherNetworkFence(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "synthetic-network-reservations.sqlite3")
	r, err := nodeinbox.OpenNativeContextRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "synthetic-hub", NodeID: "synthetic-node", WriterScope: "uid:synthetic", NativeContexts: r})
	body := []byte(`{"synthetic_original":"zero"}`)
	a, err := reserveMachineThreadNetwork(ctx, "codex", "synthetic-sid", "synthetic-network-A", "synthetic-operation", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := *a.claim
	if _, err = reserveMachineThreadNetwork(ctx, "codex", "synthetic-sid", "synthetic-network-B", "synthetic-other", body, nil); !errors.Is(err, nodeinbox.ErrNativeContextScopeConflict) {
		t.Fatal("different Network reached effect boundary", err)
	}
	a.unresolved(ctx)
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = nodeinbox.OpenNativeContextRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx = withMachineHubContext(context.Background(), machineHubContext{HubID: "synthetic-hub", NodeID: "synthetic-node", WriterScope: "uid:synthetic", NativeContexts: r})
	a, err = reserveMachineThreadNetwork(ctx, "codex", "synthetic-sid", "synthetic-network-A", "synthetic-operation", body, &claim)
	if err != nil || a.claim.ReservationID != claim.ReservationID || a.claim.Revision != claim.Revision || a.claim.State != nodeinbox.ThreadNetworkUnresolved {
		t.Fatal("restart lost exact original", err)
	}
	scope := nodeinbox.NativeContextScopeInput{AccountID: "uid:synthetic", Harness: "codex", NativeSessionID: "synthetic-sid", HubID: "synthetic-hub", NetworkID: "synthetic-network-A", GroupID: "synthetic-group", ContextPolicy: nodeinbox.NativeContextPolicyGroupScoped, EndpointID: "synthetic-endpoint", BindingID: "synthetic-binding", BindingEpoch: 1}
	response := []byte("synthetic already-authenticated exact response")
	if err = a.accepted(ctx, scope, response); err != nil {
		t.Fatal(err)
	}
	a, err = reserveMachineThreadNetwork(ctx, "codex", "synthetic-sid", "synthetic-network-A", "synthetic-operation", body, &claim)
	if err != nil || a.claim.State != nodeinbox.ThreadNetworkAccepted {
		t.Fatal("accepted exact original not recoverable", err)
	}
	if err = a.accepted(ctx, scope, response); err != nil {
		t.Fatal("exact settle replay", err)
	}
	if _, err = reserveMachineThreadNetwork(ctx, "codex", "synthetic-sid", "synthetic-network-A", "synthetic-operation", []byte("changed"), &claim); !errors.Is(err, nodeinbox.ErrThreadNetworkOriginalConflict) {
		t.Fatal("changed original reused claim", err)
	}
}

func TestLocalDomainReservationStateProgressPreservesOriginalKey(t *testing.T) {
	c, err := openMachineNodeControlClient(t.TempDir(), "http://127.0.0.1:1", "synthetic-reservation-node")
	if err != nil {
		t.Fatal(err)
	}
	m := machineManagedLocalDomainLease{IntentID: "synthetic-intent", IntentDigest: "synthetic-digest", State: "RESERVED"}
	id := localEndpointStepID(m.IntentID, m.IntentDigest, "domain.join")
	c.state.ManagedLocalDomainLeases = map[string]machineManagedLocalDomainLease{id: m}
	r := nodeinbox.ThreadNetworkReservation{ReservationID: "synthetic-claim", Revision: 1, State: nodeinbox.ThreadNetworkReserved, HubID: "synthetic-hub", NetworkID: "synthetic-network", OperationID: "synthetic-operation", RequestDigest: "synthetic-digest"}
	for _, state := range []string{nodeinbox.ThreadNetworkReserved, nodeinbox.ThreadNetworkUnresolved, nodeinbox.ThreadNetworkAccepted, nodeinbox.ThreadNetworkAccepted} {
		r.State = state
		m, err = c.rememberLocalDomainNetworkReservation(m, &r)
		if err != nil {
			t.Fatal("same original state advance failed", state, err)
		}
	}
	clone := cloneMachineNodeControlState(c.state)
	clone.ManagedLocalDomainLeases[id].ThreadNetworkReservation.State = "changed-clone"
	if c.state.ManagedLocalDomainLeases[id].ThreadNetworkReservation.State != nodeinbox.ThreadNetworkAccepted {
		t.Fatal("rollback clone aliases live reservation")
	}
	r.State = nodeinbox.ThreadNetworkReserved
	if _, err = c.rememberLocalDomainNetworkReservation(m, &r); !errors.Is(err, errLocalEndpointIntentConflict) {
		t.Fatal("terminal reservation rolled back", err)
	}
}

func TestThreadNetworkZeroBootstrapLostJoinThenOwnerClassification(t *testing.T) {
	t.Run("exact_original", func(t *testing.T) { runThreadNetworkZeroBootstrap(t, false) })
	t.Run("fresh_explicit_register", func(t *testing.T) { runThreadNetworkZeroBootstrap(t, true) })
}

func runThreadNetworkZeroBootstrap(t *testing.T, freshRegister bool) {
	f := newNativePeerTCPConsumerFixture(t, false)
	activateLocalDomainConsumer(t, f)
	q := localDomainEndpointCommand(t, f, 0)
	f.mu.Lock()
	f.dropDomain = map[string]int{wire.OperationLocalDomainNodeJoin: 1}
	f.mu.Unlock()
	if _, err := requestMachineAgentEndpoint(f.bridge.path, q); err == nil {
		t.Fatal("lost Join ACK reported ready")
	}
	view, err := f.history.InspectThreadNetwork(f.ctx, "synthetic-tcp-consumer-account", "codex", q.NativeSessionID)
	if err != nil || view.State != nodeinbox.ThreadNetworkUnresolved {
		t.Fatal("lost remote response did not reserve Network", view, err)
	}
	claim := *view.Reservation
	_, statePath := machineNodeControlPaths(f.nodeRoot, f.nodeID)
	machineNodeControlClients.Delete(statePath)
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	result, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err == nil || result == nil || result.State != "CLASSIFICATION_REQUIRED" {
		t.Fatal("unclassified original acquired Group authority", result, err)
	}
	r, enrolled, err := f.client.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || r.Phase != endpointGroupsZeroAttested {
		t.Fatal("original zero anchor not retained", err)
	}
	key, err := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public()
	var scope wire.ThreadScopeView
	if err = f.client.callThreadCollaboration(f.ctx, f.token, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: r.Anchor.Registration.EndpointID, NetworkID: r.Anchor.NetworkID}, &scope); err != nil || scope.ActiveGroupCount != 0 {
		t.Fatal("zero member counted effective", err)
	}
	ownerCall := func(q any) ([]byte, wire.ThreadCollaborationOwnerResult) {
		t.Helper()
		packet, e := wire.SealClientRequest(f.device, f.hub, q)
		if e != nil {
			t.Fatal(e)
		}
		_, route, e := wire.NewClientRoute(f.hub, q, f.device.Public())
		if e != nil {
			t.Fatal(e)
		}
		reply := f.http(t, http.MethodPost, wire.ThreadCollaborationHTTPPath(route.Operation), "", "", packet, http.StatusOK)
		var out wire.ThreadCollaborationOwnerResult
		if wire.OpenThreadCollaborationOwnerResponse(f.device, f.hub, packet, reply, &out) != nil || wire.VerifyThreadCollaborationOwnerResult(q, packet, out, f.hub) != nil {
			t.Fatal("real Owner response")
		}
		return packet, out
	}
	prepare, e := wire.NewThreadCollaborationOwnerPrepare(f.session, f.scope.Actor, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationSetClassification, Role: &wire.ThreadRoleChange{NetworkID: scope.NetworkID, NodeID: scope.NodeID, EndpointID: scope.EndpointID, Source: scope.Source, Classification: wire.ThreadClassificationWorker, ExpectedClassificationRevision: scope.ClassificationRevision, ExpectedRelationsRevision: scope.RelationsRevision, RegistrationDigest: scope.RegistrationDigest}}, f.owner, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	packet, prepared := ownerCall(prepare)
	if prepared.Review == nil {
		t.Fatal("Owner review missing", prepared.ErrorCode)
	}
	apply, e := wire.NewThreadCollaborationOwnerApply(f.session, f.scope.Actor, prepare, packet, *prepared.Review, f.owner, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	_, applied := ownerCall(apply)
	if applied.State != "COMPLETED" {
		t.Fatal("Owner classification denied", applied.ErrorCode)
	}
	if freshRegister {
		issue := localDomainConsumerIssue(t, f, 0)
		issue.ConnectionNonce = strings.Repeat("b", 64)
		issue.ArgumentsDigest, _ = codexArgumentsDigest(map[string]any{"operation": "endpoint_register", "name": q.Name, "pair_label": "", "slot": ""})
		ticket, e := requestMachineAgentCodexContextIssue(f.bridge.path, issue)
		if e != nil {
			t.Fatal("actual fresh zero registration identity proof", e)
		}
		consumed, e := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket))
		if e != nil {
			t.Fatal(e)
		}
		binding, e := codexContextBinding(consumed.Context)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC()
		id, e := newLocalEndpointRequestID(now)
		if e != nil {
			t.Fatal(e)
		}
		fresh := localEndpointRequest{Version: localJoinProtocolVersion, Operation: "endpoint_register", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, Name: q.Name, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding, endpointGroupsOperatorContextProof: endpointGroupsOperatorContextProof{ContextTicketID: strings.Split(ticket.Ticket, ".")[0], ContextConnectionNonce: issue.ConnectionNonce}}
		registered, e := requestMachineAgentEndpoint(f.bridge.path, fresh)
		if e != nil || registered == nil || registered.State != "COMPLETED" || registered.EndpointGroups == nil || registered.Registration.EndpointID != r.Anchor.Registration.EndpointID {
			t.Fatal("fresh explicit register replaced or failed to resume zero original", e)
		}
	}
	result, err = requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || result.State != "COMPLETED" {
		t.Fatal("same original did not resume key completion", err)
	}
	current, _, err := f.client.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || current.Phase != "" || !sameEndpointGroupsAnchor(r.Anchor, current.Anchor) {
		t.Fatal("classification replaced original anchor", err)
	}
	key, err = nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), current.Anchor.Registration.EndpointID)
	if err != nil || !machineSamePublicIdentity(public, key.Public()) {
		t.Fatal("retry replaced original private key", err)
	}
	view, err = f.history.InspectThreadNetwork(f.ctx, "synthetic-tcp-consumer-account", "codex", q.NativeSessionID)
	if err != nil || view.State != nodeinbox.ThreadNetworkCurrent {
		t.Fatal("accepted Network not restored", view, err)
	}
	m := f.client.state.ManagedLocalDomainLeases[r.LeaseID]
	if m.ThreadNetworkReservation == nil || m.ThreadNetworkReservation.ReservationID != claim.ReservationID || m.ThreadNetworkReservation.Revision != claim.Revision {
		t.Fatal("exact retry replaced registry claim")
	}
	f.mu.Lock()
	joins := len(f.nodePackets[wire.OperationLocalDomainNodeJoin])
	f.mu.Unlock()
	if joins != 2 {
		t.Fatal("retry dispatched a fresh Join instead of exact recovery", joins)
	}
}
