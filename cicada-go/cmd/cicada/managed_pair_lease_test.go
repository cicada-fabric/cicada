package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func managedPairFixtureRequest(t *testing.T, f *nativePairTCPConsumerFixture) localEndpointRequest {
	t.Helper()
	now := time.Now().UTC()
	id, err := newLocalEndpointRequestID(now)
	if err != nil {
		t.Fatal(err)
	}
	return localEndpointRequest{Version: 1, Operation: "native_pair_join_named", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: f.native[0], Workspace: f.workspace, PairLabel: "Synthetic consumer pair", Slot: "A"}
}

func managedPairFixtureConnect(t *testing.T, f *nativePairTCPConsumerFixture) (localEndpointRequest, *localEndpointResult, machineManagedPairLease) {
	t.Helper()
	q := managedPairFixtureRequest(t, f)
	r, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || r == nil || r.State != "COMPLETED" || r.Join == nil {
		t.Fatalf("explicit managed connect: %v", err)
	}
	id := localEndpointStepID(q.RequestID, r.IntentDigest, "join")
	f.client.mu.Lock()
	m, ok := f.client.state.ManagedPairLeases[id]
	f.client.mu.Unlock()
	if !ok || m.State != "ACTIVE" || m.FrozenDigest == "" {
		t.Fatal("IPC completion preceded durable managed activation")
	}
	data, err := os.ReadFile(f.client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var disk machineNodeControlState
	if json.Unmarshal(data, &disk) != nil || disk.ManagedPairLeases[id].State != "ACTIVE" || bytes.Contains(data, []byte(r.Join.SessionToken)) {
		t.Fatal("managed activation missing or duplicated plaintext session token")
	}
	return q, r, m
}

func managedPairFixtureDB(t *testing.T, f *nativePairTCPConsumerFixture) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(f.root, "hub", "synthetic.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func managedPairSetSyntheticExpiry(t *testing.T, db *sql.DB, endpoint, binding string, end time.Time) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stamp := end.UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, stamp, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=? WHERE endpoint_id=?`, stamp, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedPairLeaseNodeWorkerColdBeforeFirstMCPTool(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	_, r, m := managedPairFixtureConnect(t, f)
	if f.mcp[0].isJoined() || f.mcp[1].isJoined() {
		t.Fatal("cold fixture used a model/MCP Join")
	}
	db := managedPairFixtureDB(t, f)
	// Accelerate only this disposable database's original lease deadline. This
	// is not a claim that a real five-minute Runtime wait was executed.
	f.bridge.managedLeaseMu.Lock()
	short := time.Now().UTC().Add(40 * time.Second)
	managedPairSetSyntheticExpiry(t, db, r.Join.Endpoint.ID, r.Join.BindingID, short)
	f.client.mu.Lock()
	current := f.client.state.ManagedPairLeases[m.JoinOperationID]
	current.KnownLeaseExpiresAt = short.Format(time.RFC3339Nano)
	f.client.state.ManagedPairLeases[m.JoinOperationID] = current
	if err := f.client.persistLocked(); err != nil {
		f.client.mu.Unlock()
		f.bridge.managedLeaseMu.Unlock()
		t.Fatal(err)
	}
	f.client.mu.Unlock()
	f.mu.Lock()
	before := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	f.bridge.managedLeaseMu.Unlock()
	timer := time.NewTimer(time.Until(short.Add(300 * time.Millisecond)))
	defer timer.Stop()
	<-timer.C
	_ = f.http(t, http.MethodGet, "/v2/fabric/whoami", "CicadaSession "+r.Join.SessionToken, r.Join.Endpoint.GroupID, nil, http.StatusOK)
	binding, err := f.db.GetSessionBinding(r.Join.BindingID)
	if err != nil || binding.Epoch != r.Join.BindingEpoch || binding.NativeSessionID != f.native[0] {
		t.Fatal("cold Node worker replaced native binding")
	}
	var accessEpoch uint64
	var accessEnd string
	if db.QueryRow(`SELECT epoch,lease_expires_at FROM network_access_sessions_v2 WHERE endpoint_id=?`, r.Join.Endpoint.ID).Scan(&accessEpoch, &accessEnd) != nil || accessEpoch != 1 || accessEnd != binding.LeaseExpiresAt || !parseMachineNativePairTime(binding.LeaseExpiresAt).After(short) {
		t.Fatal("cold Node worker failed atomic native/access renewal")
	}
	f.mu.Lock()
	cost := f.posts["/v2/fabric/heartbeat"] - before
	joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if cost < 1 || joins != 1 || f.mcp[0].isJoined() {
		t.Fatal("periodic cold renewal required MCP warming or redispatched Join")
	}
	t.Logf("Node-only periodic heartbeat requests=%d across shortened 40-second lease; no MCP tool/model call; original native/access epochs retained", cost)
}

func TestManagedPairLeaseUnknownJoinSurvivesRestartWithoutAutoActivation(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	q := managedPairFixtureRequest(t, f)
	f.mu.Lock()
	f.dropJoin = 1
	f.mu.Unlock()
	r, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err == nil || r == nil || r.State != "UNKNOWN" {
		t.Fatal("lost Join reply became completed activation")
	}
	id := localEndpointStepID(q.RequestID, r.IntentDigest, "join")
	f.client.mu.Lock()
	m := f.client.state.ManagedPairLeases[id]
	f.client.collectManagedPairLeasesLocked(time.Now().UTC().Add(24 * time.Hour))
	_, retained := f.client.state.ManagedPairLeases[id]
	f.client.mu.Unlock()
	if m.State != "RESERVED" || !retained {
		t.Fatal("unknown reserved Join expired into replacement capacity")
	}
	if err := f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(f.client.statePath)
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	heartbeats := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	if heartbeats != 0 {
		t.Fatal("restart promoted an uncertain historical Join")
	}
	result, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || result == nil || result.Join == nil {
		t.Fatal("explicit original intent failed recovery", err)
	}
	f.client.mu.Lock()
	active := f.client.state.ManagedPairLeases[id]
	f.client.mu.Unlock()
	if active.State != "ACTIVE" || active.Join.ExpectedGeneration != m.Join.ExpectedGeneration || active.JoinOperationID != m.JoinOperationID {
		t.Fatal("recovery changed frozen original selection")
	}
	f.mu.Lock()
	packets := f.nodePackets[wire.OperationNativePairNodeJoin]
	f.mu.Unlock()
	if len(packets) != 2 || !bytes.Equal(packets[0], packets[1]) {
		t.Fatal("restart generated a replacement Join packet")
	}
	// ACTIVE alone may resume after restart, while its last proven lease lives.
	if err := f.bridge.Close(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(f.client.statePath)
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	before := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := f.posts["/v2/fabric/heartbeat"]
		f.mu.Unlock()
		if n > before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("persisted active marker did not resume its original current lease")
}

func TestManagedPairLeaseActivationWriteFailureCannotReportCompletion(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	q := managedPairFixtureRequest(t, f)
	path := f.client.statePath
	bad := filepath.Join(f.root, "synthetic-activation-write-failure")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	var injected atomic.Bool
	f.mu.Lock()
	originalHandler := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/fabric/endpoint-keys" {
			originalHandler.ServeHTTP(w, r)
			return
		}
		buffer := httptest.NewRecorder()
		originalHandler.ServeHTTP(buffer, r)
		if buffer.Code == http.StatusOK && injected.CompareAndSwap(false, true) {
			f.client.mu.Lock()
			f.client.statePath = bad
			f.client.mu.Unlock()
		}
		for key, values := range buffer.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(buffer.Code)
		_, _ = w.Write(buffer.Body.Bytes())
	})
	f.mu.Unlock()
	t.Cleanup(func() { f.client.mu.Lock(); f.client.statePath = path; f.client.mu.Unlock() })
	r, err := requestMachineAgentEndpoint(f.bridge.path, q)
	f.client.mu.Lock()
	f.client.statePath = path
	f.client.mu.Unlock()
	if err == nil || r == nil || r.State != "UNKNOWN" || r.Join != nil || !injected.Load() {
		t.Fatal("unpersisted managed activation leaked completion")
	}
	id := localEndpointStepID(q.RequestID, r.IntentDigest, "join")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk machineNodeControlState
	if json.Unmarshal(data, &disk) != nil || disk.ManagedPairLeases[id].State != "RESERVED" {
		t.Fatal("activation failure lost original reservation")
	}
	result, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || result == nil || result.Join == nil {
		t.Fatal("original activation could not recover", err)
	}
	f.mu.Lock()
	joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if joins != 1 {
		t.Fatal("activation persistence retry sent a second Join")
	}
}

func TestManagedPairLeaseCapacityBeforeHubMutationAndSafeCollection(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	q := managedPairFixtureRequest(t, f)
	f.client.mu.Lock()
	f.client.state.ManagedPairLeases = make(map[string]machineManagedPairLease)
	for i := 0; i < maxManagedPairLiveLeases; i++ {
		f.client.state.ManagedPairLeases[string(rune('a'+i))] = machineManagedPairLease{State: "RESERVED", IssuedAt: time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)}
	}
	if err := f.client.persistLocked(); err != nil {
		f.client.mu.Unlock()
		t.Fatal(err)
	}
	f.client.mu.Unlock()
	operator, err := openCodexOperatorIntent(filepath.Join(f.root, "operator", "operator-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	refused, err := operator.call(f.bridge.path, q, f.nodeID)
	if err == nil || refused == nil || refused.State != "REFUSED" {
		t.Fatal("capacity was not an acknowledged no-dispatch refusal", err)
	}
	if err := operator.ack(refused.RequestID, refused.IntentDigest); err != nil {
		t.Fatal("capacity refusal locked client pending", err)
	}
	f.mu.Lock()
	joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if joins != 0 {
		t.Fatal("capacity check followed the Hub mutation")
	}
	f.client.mu.Lock()
	if len(f.client.state.ManagedPairLeases) != maxManagedPairLiveLeases {
		f.client.mu.Unlock()
		t.Fatal("unknown capacity was evicted")
	}
	for id, m := range f.client.state.ManagedPairLeases {
		m.State = "STOPPED"
		m.PeerCeiling = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
		f.client.state.ManagedPairLeases[id] = m
	}
	f.client.collectManagedPairLeasesLocked(time.Now().UTC())
	if len(f.client.state.ManagedPairLeases) != 0 || f.client.state.LocalEndpointAdmissionFloorMS == 0 {
		f.client.mu.Unlock()
		t.Fatal("known expired history imposed a lifetime quota")
	}
	if err := f.client.persistLocked(); err != nil {
		f.client.mu.Unlock()
		t.Fatal(err)
	}
	f.client.mu.Unlock()
	if old, err := requestMachineAgentEndpoint(f.bridge.path, q); err == nil || old == nil || old.State != "REFUSED" {
		t.Fatal("capacity repair revived old command", err)
	}
	fresh := managedPairFixtureRequest(t, f)
	completed, err := operator.call(f.bridge.path, fresh, f.nodeID)
	if err != nil || completed == nil || completed.State != "COMPLETED" {
		t.Fatal("new explicit command did not recover temporary capacity", err)
	}
}

func TestManagedPairLeaseLeaveAndCurrentAuthorityStopWithoutResurrection(t *testing.T) {
	for _, kind := range []string{"leave", "local_owner_pin", "local_epoch", "hub_pair_revoke", "expired_native_access", "ceiling"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativePairTCPConsumerFixture(t)
			q, r, m := managedPairFixtureConnect(t, f)
			db := managedPairFixtureDB(t, f)
			switch kind {
			case "leave":
				now := time.Now().UTC()
				id, err := newLocalEndpointRequestID(now)
				if err != nil {
					t.Fatal(err)
				}
				leave := localEndpointRequest{Version: 1, Operation: "endpoint_leave", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: q.APIOrigin, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace}
				result, err := requestMachineAgentEndpoint(f.bridge.path, leave)
				if err != nil || result.Registration == nil || result.Registration.Presence != "left" {
					t.Fatal("actual Leave failed", err)
				}
			case "local_owner_pin":
				crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.nodeRoot, f.nodeID))
				if err != nil {
					t.Fatal(err)
				}
				trust, err := crypto.GetNodeOwnerKeyTrustLocal(f.scope.Actor.OwnerID, f.owner.Public().ID)
				if err != nil {
					t.Fatal(err)
				}
				_, err = crypto.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version)
				_ = crypto.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "local_epoch":
				f.client.mu.Lock()
				f.client.state.NodeKeyEpoch++
				if err := f.client.persistLocked(); err != nil {
					f.client.mu.Unlock()
					t.Fatal(err)
				}
				f.client.mu.Unlock()
			case "hub_pair_revoke":
				status := f.status(t)
				c, claims := f.claims(t, e2ee.OwnerNativePairRevoke)
				target, err := wire.NativePairRevokeTargetDigest(f.scope, status.PairID, status.ControlRevision)
				if err != nil {
					t.Fatal(err)
				}
				claims.Revoke = &e2ee.NativePairRevokeClaims{PairID: status.PairID, ExpectedRevision: status.ControlRevision, PairTargetDigest: target}
				proof, err := e2ee.SignOwnerNativePair(f.owner, claims)
				if err != nil {
					t.Fatal(err)
				}
				var result wire.NativePairResult
				f.app(t, wire.NativePairRevoke{Format: wire.NativePairFormat, Context: c, SessionToken: f.session.Token, OwnerProof: proof}, &result)
				if result.State != wire.NativePairRevoked {
					t.Fatal("actual Owner revoke failed")
				}
			case "expired_native_access":
				managedPairSetSyntheticExpiry(t, db, r.Join.Endpoint.ID, r.Join.BindingID, time.Now().UTC().Add(-time.Second))
			}
			now := time.Now().UTC()
			if kind == "ceiling" {
				now = parseMachineNativePairTime(m.PeerCeiling).Add(time.Second)
			}
			f.bridge.renewManagedPairLeaseBatch(f.ctx, func() time.Time { return now })
			f.client.mu.Lock()
			stopped := f.client.state.ManagedPairLeases[m.JoinOperationID]
			f.client.mu.Unlock()
			if stopped.State != "STOPPED" {
				t.Fatalf("%s did not stop the frozen binding", kind)
			}
			f.mu.Lock()
			before := f.posts["/v2/fabric/heartbeat"]
			joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
			f.mu.Unlock()
			f.bridge.renewManagedPairLeaseBatch(f.ctx, time.Now)
			f.mu.Lock()
			after := f.posts["/v2/fabric/heartbeat"]
			f.mu.Unlock()
			if after != before || joins != 1 {
				t.Fatal("stopped lease was renewed or Join recreated")
			}
			if _, err := requestMachineAgentEndpoint(f.bridge.path, q); err == nil {
				t.Fatal("historical original connect revived stopped marker")
			}
		})
	}
}

func TestManagedPairLeaseConcurrentNodeAndSessionHeartbeatsKeepEpochs(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	_, r, m := managedPairFixtureConnect(t, f)
	db := managedPairFixtureDB(t, f)
	f.mu.Lock()
	before := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); f.bridge.renewManagedPairLeaseBatch(f.ctx, time.Now) }()
	go func() {
		defer wg.Done()
		_, err := f.bridge.httpWithAuthorization(http.MethodPost, "/v2/fabric/heartbeat", nil, "CicadaSession "+r.Join.SessionToken, r.Join.Endpoint.GroupID)
		if err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	binding, err := f.db.GetSessionBinding(r.Join.BindingID)
	var accessEpoch uint64
	var accessEnd string
	if err != nil || binding.Epoch != r.Join.BindingEpoch || db.QueryRow(`SELECT epoch,lease_expires_at FROM network_access_sessions_v2 WHERE endpoint_id=?`, r.Join.Endpoint.ID).Scan(&accessEpoch, &accessEnd) != nil || accessEpoch != 1 || accessEnd != binding.LeaseExpiresAt || parseMachineNativePairTime(accessEnd).After(parseMachineNativePairTime(m.PeerCeiling)) {
		t.Fatal("concurrent existing-session HB changed epoch or Owner ceiling")
	}
	f.mu.Lock()
	cost := f.posts["/v2/fabric/heartbeat"] - before
	joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if cost < 2 || joins != 1 {
		t.Fatal("dual heartbeat did not exercise both existing request paths")
	}
	t.Logf("concurrent Node renewal and ordinary session heartbeat requests=%d; same immutable epochs and Owner ceiling; no second Join", cost)
}

func TestManagedPairLeaseOriginalPolicySurvivesActualDualConsentTransition(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	_, first, a := managedPairFixtureConnect(t, f)
	q := managedPairFixtureRequest(t, f)
	q.NativeSessionID = f.native[1]
	q.Slot = "B"
	second, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || second == nil || second.Join == nil {
		t.Fatal("second explicit original Thread failed", err)
	}
	id := localEndpointStepID(q.RequestID, second.IntentDigest, "join")
	f.client.mu.Lock()
	b := f.client.state.ManagedPairLeases[id]
	f.client.mu.Unlock()
	f.joins[0], f.joins[1] = *first.Join, *second.Join
	f.prepareConsent(t)
	if result := f.consent(t, 0); result.State != wire.NativePairWaitingConsent {
		t.Fatal("first Owner consent unexpectedly activated pair")
	}
	f.bridge.renewManagedPairLeaseBatch(f.ctx, time.Now)
	if result := f.consent(t, 1); result.State != wire.NativePairActive {
		t.Fatal("actual dual Owner consent did not activate pair")
	}
	f.bridge.renewManagedPairLeaseBatch(f.ctx, time.Now)
	for _, before := range []machineManagedPairLease{a, b} {
		f.client.mu.Lock()
		after := f.client.state.ManagedPairLeases[before.JoinOperationID]
		f.client.mu.Unlock()
		if after.State != "ACTIVE" || after.FrozenDigest != before.FrozenDigest || after.PreparationDigest != before.PreparationDigest || after.PeerCeiling != before.PeerCeiling {
			t.Fatal("normal Owner activation was mistaken for a frozen authority change")
		}
	}
	for _, join := range f.joins {
		binding, err := f.db.GetSessionBinding(join.BindingID)
		if err != nil || binding.Epoch != join.BindingEpoch {
			t.Fatal("Owner transition or heartbeat rotated original binding")
		}
	}
	f.mu.Lock()
	joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if joins != 2 {
		t.Fatal("Owner transition dispatched a replacement Join")
	}
}

func TestManagedPairLeaseDelayedReplyUsesCurrentClockAndLeaveCAS(t *testing.T) {
	for _, kind := range []string{"clock_after_io", "leave_before_reply"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativePairTCPConsumerFixture(t)
			q, r, m := managedPairFixtureConnect(t, f)
			f.bridge.managedLeaseMu.Lock()
			defer f.bridge.managedLeaseMu.Unlock()
			var injected, late, nestedLeave atomic.Bool
			f.mu.Lock()
			handler := f.handler
			f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/v2/fabric/heartbeat" || !injected.CompareAndSwap(false, true) {
					handler.ServeHTTP(w, request)
					return
				}
				buffer := httptest.NewRecorder()
				handler.ServeHTTP(buffer, request)
				if kind == "leave_before_reply" {
					now := time.Now().UTC()
					id, err := newLocalEndpointRequestID(now)
					if err == nil {
						leave := localEndpointRequest{Version: 1, Operation: "endpoint_leave", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: q.APIOrigin, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace}
						result, err := f.bridge.endpointOperation(leave)
						if err == nil && result != nil && result.Registration != nil && result.Registration.Presence == "left" {
							nestedLeave.Store(true)
						} else {
							t.Error("actual Leave while heartbeat reply was held failed")
						}
					}
				}
				time.Sleep(20 * time.Millisecond)
				late.Store(true)
				for key, values := range buffer.Header() {
					w.Header()[key] = values
				}
				w.WriteHeader(buffer.Code)
				_, _ = w.Write(buffer.Body.Bytes())
			})
			f.mu.Unlock()
			clock := func() time.Time {
				if kind == "clock_after_io" && late.Load() {
					return parseMachineNativePairTime(m.PeerCeiling).Add(time.Second)
				}
				return time.Now()
			}
			ctx, cancel := context.WithTimeout(f.ctx, managedPairLeaseRequestTimeout)
			defer cancel()
			update := f.bridge.prepareManagedPairLeaseRenewal(ctx, f.client, m.JoinOperationID, clock)
			if update == nil || !injected.Load() {
				t.Fatal("held actual heartbeat did not yield a bounded update")
			}
			if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*update}, clock); err != nil {
				t.Fatal(err)
			}
			f.client.mu.Lock()
			stopped := f.client.state.ManagedPairLeases[m.JoinOperationID]
			f.client.mu.Unlock()
			if stopped.State != "STOPPED" {
				t.Fatal("late heartbeat revived ACTIVE state")
			}
			if kind == "leave_before_reply" {
				binding, err := f.db.GetSessionBinding(r.Join.BindingID)
				if !nestedLeave.Load() || err != nil || binding.Status != "revoked" || stopped.StopCode != "EXPLICIT_LEAVE" {
					t.Fatal("late reply overwrote actual Leave")
				}
			} else if stopped.StopCode != "HEARTBEAT_CONTEXT_INVALID" {
				t.Fatal("post-I/O clock was not authoritative")
			}
		})
	}
}

func TestManagedPairLeaseBatchNoWriteAndPersistenceRollbackPreserveSharedOutbox(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	_, _, m := managedPairFixtureConnect(t, f)
	bridge := f.bridge
	bridge.managedLeaseMu.Lock()
	locked := true
	defer func() {
		if locked {
			bridge.managedLeaseMu.Unlock()
		}
	}()
	f.client.mu.Lock()
	m = f.client.state.ManagedPairLeases[m.JoinOperationID]
	f.client.mu.Unlock()
	before, err := os.ReadFile(f.client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(f.client.statePath)
	if err != nil {
		t.Fatal(err)
	}
	noop := managedPairLeaseUpdate{ID: m.JoinOperationID, FrozenDigest: m.FrozenDigest, LeaseExpiresAt: m.KnownLeaseExpiresAt}
	if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{noop}, time.Now); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(f.client.statePath)
	afterInfo, statErr := os.Stat(f.client.statePath)
	if err != nil || statErr != nil || !bytes.Equal(before, after) || !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("unchanged heartbeat caused a state rewrite")
	}
	// Retain a genuine encrypted, read-only Node RPC in the shared outbox by
	// dropping its actual Hub response. Lease persistence must not replace it.
	var dropped atomic.Bool
	f.mu.Lock()
	handler := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/control/rpc" {
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			request.Body = io.NopCloser(bytes.NewReader(raw))
			packet, err := nodewire.DecodePacket(raw)
			if err == nil && packet.Route.Operation == nodewire.EndpointDirectoryOperation && dropped.CompareAndSwap(false, true) {
				buffer := httptest.NewRecorder()
				handler.ServeHTTP(buffer, request)
				if buffer.Code != http.StatusOK {
					t.Error("actual directory RPC did not complete before ACK loss")
				}
				w.WriteHeader(503)
				return
			}
		}
		handler.ServeHTTP(w, request)
	})
	f.mu.Unlock()
	if err := f.client.call(f.ctx, f.token, nodewire.EndpointDirectoryOperation, nodewire.EndpointDirectoryRequest{Limit: 1}, nil); err == nil {
		t.Fatal("actual shared-outbox ACK loss was not injected")
	}
	f.client.mu.Lock()
	pending := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	if len(pending.PendingPacket) == 0 {
		t.Fatal("shared exact outbox not retained")
	}
	ctx, cancel := context.WithTimeout(f.ctx, managedPairLeaseRequestTimeout)
	update := bridge.prepareManagedPairLeaseRenewal(ctx, f.client, m.JoinOperationID, time.Now)
	cancel()
	if update == nil || update.StopCode != "" {
		t.Fatal("actual pure heartbeat renewal failed")
	}
	if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*update}, time.Now); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	samePending := bytes.Equal(f.client.state.PendingPacket, pending.PendingPacket) && f.client.state.PendingOperationID == pending.PendingOperationID && f.client.state.PendingSequence == pending.PendingSequence
	known := f.client.state.ManagedPairLeases[m.JoinOperationID].KnownLeaseExpiresAt
	clone := cloneMachineNodeControlState(f.client.state)
	changed := clone.ManagedPairLeases[m.JoinOperationID]
	changed.State = "STOPPED"
	clone.ManagedPairLeases[m.JoinOperationID] = changed
	independent := f.client.state.ManagedPairLeases[m.JoinOperationID].State == "ACTIVE"
	f.client.mu.Unlock()
	if !samePending || !independent {
		t.Fatal("batch merge or rollback clone corrupted the shared outbox/marker")
	}
	time.Sleep(time.Millisecond)
	ctx, cancel = context.WithTimeout(f.ctx, managedPairLeaseRequestTimeout)
	next := bridge.prepareManagedPairLeaseRenewal(ctx, f.client, m.JoinOperationID, time.Now)
	cancel()
	if next == nil || next.StopCode != "" {
		t.Fatal("second actual heartbeat failed")
	}
	path := f.client.statePath
	bad := filepath.Join(f.root, "synthetic-batch-write-failure")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	f.client.statePath = bad
	f.client.mu.Unlock()
	err = f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*next}, time.Now)
	f.client.mu.Lock()
	f.client.statePath = path
	rollback := f.client.state.ManagedPairLeases[m.JoinOperationID].KnownLeaseExpiresAt == known && bytes.Equal(f.client.state.PendingPacket, pending.PendingPacket)
	f.client.mu.Unlock()
	if err == nil || !rollback {
		t.Fatal("failed batch write lost old proven lease or exact shared pending packet")
	}
	bridge.cancel()
	bridge.managedLeaseMu.Unlock()
	locked = false
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(path)
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		t.Fatal(err)
	}
	if f.client.state.ManagedPairLeases[m.JoinOperationID].KnownLeaseExpiresAt != known || !bytes.Equal(f.client.state.PendingPacket, pending.PendingPacket) {
		t.Fatal("restart lost failed-write rollback evidence")
	}
	if err := f.client.recoverPending(f.ctx, f.token); err != nil {
		t.Fatal("original shared RPC could not recover", err)
	}
	if f.client.state.ManagedPairLeases[m.JoinOperationID].FrozenDigest != m.FrozenDigest || len(f.client.state.PendingPacket) != 0 {
		t.Fatal("shared RPC recovery damaged managed binding")
	}
}

func TestManagedPairLeaseSelectionRefusalCanAckAndOnlyFreshCommandConnects(t *testing.T) {
	for _, kind := range []string{"typo", "duplicate_label", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativePairTCPConsumerFixture(t)
			q := managedPairFixtureRequest(t, f)
			if kind == "typo" {
				q.PairLabel = "Synthetic typo"
			} else {
				managedPairInjectSyntheticAvailable(t, f, kind)
			}
			operator, err := openCodexOperatorIntent(filepath.Join(f.root, "operator", "operator-intent.json"))
			if err != nil {
				t.Fatal(err)
			}
			refused, err := operator.call(f.bridge.path, q, f.nodeID)
			if err == nil || refused == nil || refused.State != "REFUSED" {
				t.Fatal("selection did not finish as no-dispatch refusal", err)
			}
			if err := operator.ack(refused.RequestID, refused.IntentDigest); err != nil {
				t.Fatal("selection refusal locked pending", err)
			}

			if old, err := requestMachineAgentEndpoint(f.bridge.path, q); err == nil || old == nil || old.State != "REFUSED" {
				t.Fatal("repaired directory revived old command", err)
			}
			fresh := managedPairFixtureRequest(t, f)
			result, err := operator.call(f.bridge.path, fresh, f.nodeID)
			if err != nil || result == nil || result.State != "COMPLETED" {
				t.Fatal("new corrected command could not connect", err)
			}
			f.mu.Lock()
			joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
			f.mu.Unlock()
			if joins != 1 {
				t.Fatal("refused selection issued a Join")
			}
		})
	}
}

func TestManagedPairLeaseDispatchedUpgradeWithoutMarkerCannotClaimCapacityRefusal(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	q := managedPairFixtureRequest(t, f)
	operator, err := openCodexOperatorIntent(filepath.Join(f.root, "operator", "operator-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.dropJoin = 1
	f.mu.Unlock()
	first, err := operator.call(f.bridge.path, q, f.nodeID)
	if err == nil || first == nil || first.State != "UNKNOWN" {
		t.Fatal("missing ACK became terminal", err)
	}
	f.client.mu.Lock()
	f.client.state.ManagedPairLeases = map[string]machineManagedPairLease{}
	for i := 0; i < maxManagedPairLiveLeases; i++ {
		f.client.state.ManagedPairLeases[string(rune('a'+i))] = machineManagedPairLease{State: "RESERVED"}
	}
	if err := f.client.persistLocked(); err != nil {
		f.client.mu.Unlock()
		t.Fatal(err)
	}
	f.client.mu.Unlock()
	result, err := operator.call(f.bridge.path, q, f.nodeID)
	if err == nil || result == nil || result.State != "UNKNOWN" {
		t.Fatal("absent upgrade marker invented no effect", err)
	}
	if err := operator.ack(first.RequestID, first.IntentDigest); err == nil {
		t.Fatal("unknown dispatched Join could be ACKed")
	}
	original, err := operator.prepare(q, f.nodeID)
	if err != nil || original != q {
		t.Fatal("lost original client command", err)
	}
	f.mu.Lock()
	packets := f.nodePackets[wire.OperationNativePairNodeJoin]
	f.mu.Unlock()
	if len(packets) != 2 || !bytes.Equal(packets[0], packets[1]) {
		t.Fatal("recovery issued a replacement Join")
	}
}

func TestManagedPairLeaseLocalRefusalRequiresEveryDispatchCoordinateAbsent(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	q := managedPairFixtureRequest(t, f)
	f.mu.Lock()
	f.dropJoin = 1
	f.mu.Unlock()
	r, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err == nil || r == nil {
		t.Fatal("fixture did not lose original ACK")
	}
	f.client.mu.Lock()
	original := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	id := localEndpointStepID(q.RequestID, r.IntentDigest, "join")
	// Pending packet, retained receipt, and local step are independently sufficient
	// to prevent a no-effect assertion, including malformed or mismatched metadata.
	for _, kind := range []string{"pending_id", "pending_route", "malformed_pending", "receipt", "step_request", "step_response", "step_settled"} {
		t.Run(kind, func(t *testing.T) {
			f.client.mu.Lock()
			state := cloneMachineNodeControlState(original)
			packet := bytes.Clone(state.PendingPacket)
			state.PendingPacket = nil
			state.PendingOperationID = ""
			state.NativePairReceipts = nil
			state.ManagedPairLeases = nil
			intent := state.LocalEndpointIntents[q.RequestID]
			intent.Steps = map[string]machineLocalEndpointStep{}
			state.LocalEndpointIntents[q.RequestID] = intent
			switch kind {
			case "pending_id":
				state.PendingOperationID = id
			case "pending_route":
				state.PendingPacket = packet
				state.PendingOperationID = "synthetic-other"
			case "malformed_pending":
				state.PendingPacket = []byte("synthetic malformed packet")
			case "receipt":
				state.NativePairReceipts = map[string]machineNativePairReceipt{id: {}}
			case "step_request":
				intent.Steps[id] = machineLocalEndpointStep{RequestPacket: packet}
			case "step_response":
				intent.Steps[id] = machineLocalEndpointStep{ResponsePacket: []byte("synthetic receipt")}
			case "step_settled":
				intent.Steps[id] = machineLocalEndpointStep{Settled: true}
			}
			f.client.state = state
			proved := f.client.namedJoinUndispatchedLocked(q.RequestID, r.IntentDigest)
			f.client.state = cloneMachineNodeControlState(original)
			f.client.mu.Unlock()
			if proved {
				t.Fatal("invented absence despite retained dispatch evidence")
			}
		})
	}
	// A durable failure must preserve UNKNOWN and must not install a refusal flag.
	f.client.mu.Lock()
	f.client.state.PendingPacket = nil
	f.client.state.PendingOperationID = ""
	f.client.state.PendingLocalEndpointIntentID = ""
	f.client.state.NativePairReceipts = nil
	intent := f.client.state.LocalEndpointIntents[q.RequestID]
	intent.Steps = map[string]machineLocalEndpointStep{}
	f.client.state.LocalEndpointIntents[q.RequestID] = intent
	path := f.client.statePath
	f.client.statePath = f.root
	f.client.mu.Unlock()
	fenced, err := f.client.fenceLocalNamedJoinRefusal(q.RequestID, r.IntentDigest)
	f.client.mu.Lock()
	flag := f.client.state.LocalEndpointIntents[q.RequestID].LocalJoinRefused
	f.client.state = original
	f.client.statePath = path
	f.client.mu.Unlock()
	if err == nil || fenced || flag {
		t.Fatal("failed refusal persistence permitted terminal ACK")
	}
}

func TestManagedPairLeaseTemporaryCryptoBusyDoesNotPostOrStop(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	_, _, m := managedPairFixtureConnect(t, f)
	f.bridge.managedLeaseMu.Lock()
	defer f.bridge.managedLeaseMu.Unlock()
	f.client.mu.Lock()
	m = f.client.state.ManagedPairLeases[m.JoinOperationID]
	f.client.mu.Unlock()
	path := filepath.Join(machineNodeStateDir(f.nodeRoot, f.nodeID), "node-crypto-state.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ROLLBACK`)
	f.mu.Lock()
	before := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(f.ctx, 150*time.Millisecond)
	start := time.Now()
	update := f.bridge.prepareManagedPairLeaseRenewal(ctx, f.client, m.JoinOperationID, time.Now)
	cancel()
	if update != nil || time.Since(start) > time.Second {
		t.Fatal("temporary busy became terminal or exceeded read budget")
	}
	f.mu.Lock()
	after := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	f.client.mu.Lock()
	retained := f.client.state.ManagedPairLeases[m.JoinOperationID]
	f.client.mu.Unlock()
	if before != after || retained != m {
		t.Fatal("busy read posted heartbeat or tombstoned original marker")
	}
	if _, err := db.Exec(`ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	update = f.bridge.prepareManagedPairLeaseRenewal(f.ctx, f.client, m.JoinOperationID, time.Now)
	if update == nil || update.StopCode != "" || update.FrozenDigest != m.FrozenDigest {
		t.Fatal("same live original lease failed to resume after busy cleared")
	}
	if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*update}, time.Now); err != nil {
		t.Fatal(err)
	}
}

func TestManagedPairLeaseConfirmedMissingLocalPolicyOrPinStops(t *testing.T) {
	for _, kind := range []string{"policy", "pin"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativePairTCPConsumerFixture(t)
			_, _, m := managedPairFixtureConnect(t, f)
			f.bridge.managedLeaseMu.Lock()
			defer f.bridge.managedLeaseMu.Unlock()
			db, err := sql.Open("sqlite", filepath.Join(machineNodeStateDir(f.nodeRoot, f.nodeID), "node-crypto-state.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			table := "node_native_pair_policies"
			if kind == "pin" {
				table = "node_crypto_owner_key_trust"
			}
			if _, err := db.Exec("DELETE FROM " + table); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			before := f.posts["/v2/fabric/heartbeat"]
			f.mu.Unlock()
			update := f.bridge.prepareManagedPairLeaseRenewal(f.ctx, f.client, m.JoinOperationID, time.Now)
			if update == nil || update.StopCode != "FROZEN_AUTHORITY_CHANGED" {
				t.Fatal("confirmed authority removal was not stopped")
			}
			if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*update}, time.Now); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			after := f.posts["/v2/fabric/heartbeat"]
			f.mu.Unlock()
			f.client.mu.Lock()
			stopped := f.client.state.ManagedPairLeases[m.JoinOperationID]
			f.client.mu.Unlock()
			if before != after || stopped.State != "STOPPED" {
				t.Fatal("missing authority posted or stayed active")
			}
		})
	}
}

func managedPairInjectSyntheticAvailable(t *testing.T, f *nativePairTCPConsumerFixture, kind string) {
	t.Helper()
	path := filepath.Join(f.root, "hub", "e2ee", "node-control-identity.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	hub, err := hubidentity.LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	binding := f.client.approvedBinding()
	f.mu.Lock()
	original := f.handler
	var injected atomic.Bool
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/node/control/rpc" {
			original.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		packet, err := nodewire.DecodePacket(raw)
		if err != nil || packet.Route.Operation != nodewire.NativePairAvailableOperation || !injected.CompareAndSwap(false, true) {
			original.ServeHTTP(w, r)
			return
		}
		buffer := httptest.NewRecorder()
		original.ServeHTTP(buffer, r)
		if buffer.Code != http.StatusOK {
			t.Error("actual directory failed before defensive fixture")
			w.WriteHeader(500)
			return
		}
		opened, err := nodewire.OpenResponse(f.client.identity, binding.HubKey, binding, buffer.Body.Bytes())
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		var envelope struct {
			Result nodewire.AvailableNativePairs `json:"result"`
		}
		if json.Unmarshal(opened.Plaintext, &envelope) != nil || len(envelope.Result.Pairs) != 1 {
			t.Error("actual fixture directory was not singular")
			w.WriteHeader(500)
			return
		}
		available := envelope.Result
		if kind == "duplicate_label" {
			available.Pairs = append(available.Pairs, available.Pairs[0])
		} else {
			available.Truncated = true
		}
		sealed, err := nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(packet.Route), nodeControlTestEnvelope(t, packet.Route, true, available, ""))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(sealed)
	})
	f.mu.Unlock()
}

func TestManagedPairLeaseMissingCryptoDatabaseRetainsUntilOriginalDeadline(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	_, _, initial := managedPairFixtureConnect(t, f)
	f.bridge.managedLeaseMu.Lock()
	defer f.bridge.managedLeaseMu.Unlock()
	f.client.mu.Lock()
	original := f.client.state.ManagedPairLeases[initial.JoinOperationID]
	f.client.mu.Unlock()
	path := filepath.Join(machineNodeStateDir(f.nodeRoot, f.nodeID), "node-crypto-state.sqlite")
	held := path + ".synthetic-held"
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := os.Lstat(held); err == nil {
			_ = os.Rename(held, path)
		}
	}()
	f.mu.Lock()
	before := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	if update := f.bridge.prepareManagedPairLeaseRenewal(f.ctx, f.client, original.JoinOperationID, time.Now); update != nil {
		t.Fatal("unavailable database invented a terminal authority result")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("missing original database was initialized")
	}
	f.client.mu.Lock()
	retained := f.client.state.ManagedPairLeases[original.JoinOperationID]
	f.client.mu.Unlock()
	f.mu.Lock()
	after := f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	if before != after || retained != original {
		t.Fatal("missing storage posted heartbeat or changed original marker")
	}
	if err := os.Rename(held, path); err != nil {
		t.Fatal(err)
	}
	update := f.bridge.prepareManagedPairLeaseRenewal(f.ctx, f.client, original.JoinOperationID, time.Now)
	if update == nil || update.StopCode != "" || update.FrozenDigest != original.FrozenDigest {
		t.Fatal("original database restored within lease could not resume")
	}
	if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*update}, time.Now); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock()
	renewed := f.client.state.ManagedPairLeases[original.JoinOperationID]
	f.client.mu.Unlock()
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	late := func() time.Time { return parseMachineNativePairTime(renewed.KnownLeaseExpiresAt).Add(time.Second) }
	f.mu.Lock()
	before = f.posts["/v2/fabric/heartbeat"]
	f.mu.Unlock()
	update = f.bridge.prepareManagedPairLeaseRenewal(f.ctx, f.client, original.JoinOperationID, late)
	if update == nil || update.StopCode != "LEASE_OR_CEILING_EXPIRED" {
		t.Fatal("missing storage borrowed past last known lease")
	}
	if err := f.client.applyManagedPairLeaseUpdates([]managedPairLeaseUpdate{*update}, late); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(held, path); err != nil {
		t.Fatal(err)
	}
	if update := f.bridge.prepareManagedPairLeaseRenewal(f.ctx, f.client, original.JoinOperationID, time.Now); update != nil {
		t.Fatal("restored database resurrected stopped original")
	}
	f.mu.Lock()
	after = f.posts["/v2/fabric/heartbeat"]
	joins := len(f.nodePackets[wire.OperationNativePairNodeJoin])
	f.mu.Unlock()
	if before != after || joins != 1 {
		t.Fatal("late database restoration posted heartbeat or rejoined")
	}
}
