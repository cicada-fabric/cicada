package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestLocalDomainNodeReportRealServiceBeforeThreadsAndBoundedRefresh(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	f.bridge.refreshLocalDomainReport(f.ctx, time.Now)
	f.client.mu.Lock()
	r := cloneMachineLocalDomainState(f.client.state).LocalDomainReport
	before := f.client.state.Sequence
	f.client.mu.Unlock()
	if r == nil || r.ObservedAt == "" || r.Failures != 0 || r.Current != nil || r.Hub.HubID != f.hub.HubID {
		t.Fatal("actual writer report did not publish before any Thread enrollment")
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewLocalDomainPrepare(f.session, f.scope.Actor, e2ee.LocalDomainTarget{Node: f.scope.Node, NewNetworkName: "Synthetic pre-Thread Network", GroupName: "Synthetic pre-Thread Group"}, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(f.device, f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	reply := f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainPrepare), "", "", packet, http.StatusOK)
	var challenge wire.LocalDomainChallenge
	if wire.OpenLocalDomainResponse(f.device, f.hub, packet, reply, &challenge) != nil || wire.ValidateLocalDomainChallenge(q, packet, challenge, f.hub, time.Now().UTC()) != nil || challenge.Policy.LocalUserScope != "uid:"+strconv.FormatUint(uint64(uid), 10) {
		t.Fatal("App could not independently verify actual reported writer scope")
	}
	var report e2ee.LocalDomainUserReportProof
	if json.Unmarshal(challenge.LocalUserReport, &report) != nil || report.Report.OwnerID != "" || report.Report.OwnerBindingID != f.scope.Node.OwnerBindingID || report.Report.NodeKeyEpoch != f.scope.Node.NodeKeyEpoch {
		t.Fatal("actual unhinted report changed or guessed authority")
	}
	for i := 0; i < 8; i++ {
		f.bridge.refreshLocalDomainReport(f.ctx, time.Now)
	}
	f.client.mu.Lock()
	after := f.client.state.Sequence
	f.client.mu.Unlock()
	if before != after {
		t.Fatal("repeated heartbeat/tool wakes republished the report or current read")
	}
}

func TestLocalDomainNodeReportOldHub404KeepsSharedOutboxAndBacksOff(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	f.bridge.refreshLocalDomainReport(f.ctx, time.Now)
	// The first normal report is settled. Switch only this disposable server's
	// handler; no resident service, Node key, epoch or credential is replaced.
	f.bridge.localDomainMu.Lock()
	f.client.mu.Lock()
	copy := cloneMachineNodeControlState(f.client.state)
	copy.LocalDomainReport.NextAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	f.client.state = copy
	if err := f.client.persistLocked(); err != nil {
		f.client.mu.Unlock()
		f.bridge.localDomainMu.Unlock()
		t.Fatal(err)
	}
	seq := f.client.state.Sequence
	f.client.mu.Unlock()
	f.mu.Lock()
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wire.LocalDomainCapabilitiesPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.unsupportedHandler.ServeHTTP(w, r)
	})
	f.mu.Unlock()
	f.bridge.localDomainMu.Unlock()
	f.bridge.refreshLocalDomainReport(f.ctx, time.Now)
	f.client.mu.Lock()
	s := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	if s.Sequence != seq || len(s.PendingPacket) != 0 || s.LocalDomainReport.Failures == 0 {
		t.Fatal("old Hub capability absence changed common outbox/counter")
	}
	next, err := time.Parse(time.RFC3339Nano, s.LocalDomainReport.NextAt)
	if err != nil || next.Before(time.Now().Add(time.Minute)) {
		t.Fatal("old Hub capability probe had no bounded backoff")
	}
}

func TestLocalDomainNodeReportBackoffUsesNoAdditionalServer(t *testing.T) {
	// A missing local approved binding cannot create a fresh identity merely to
	// report. This check never initializes a resident or synthetic Hub fixture.
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unapproved Node performed report HTTP") }))
	defer server.Close()
	b := &machineAgentJoinBridge{ctx: context.Background(), stateDir: t.TempDir(), baseURL: server.URL, nodeID: "synthetic-unapproved-node"}
	b.refreshLocalDomainReport(b.ctx, time.Now)
}
