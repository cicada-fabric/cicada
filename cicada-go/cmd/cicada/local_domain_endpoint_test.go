package main

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func localDomainEndpointCommand(t *testing.T, f *nativePairTCPConsumerFixture, index int) localEndpointRequest {
	t.Helper()
	issue := localDomainConsumerIssue(t, f, index)
	ticket, err := requestMachineAgentCodexContextIssue(f.bridge.path, issue)
	if err != nil {
		t.Fatal("actual private Node context issue", err)
	}
	consumed, err := requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket))
	if err != nil {
		t.Fatal("actual private Node context consume", err)
	}
	now := time.Now().UTC()
	id, err := newLocalEndpointRequestID(now)
	if err != nil {
		t.Fatal(err)
	}
	return localEndpointRequest{Version: localJoinProtocolVersion, Operation: "endpoint_register", RequestID: id, IssuedAt: now.Format(time.RFC3339Nano), APIOrigin: f.server.URL, Harness: "codex", NativeSessionID: f.native[index], Workspace: f.workspace, Name: "Synthetic explicit local Thread", LocalDomainVersion: consumed.Context.LocalDomainVersion, LocalDomain: consumed.Context.LocalDomain}
}

func TestLocalDomainEndpointHistoricalCompleteAfterRevocation(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	d := activateLocalDomainConsumer(t, f)
	q := localDomainEndpointCommand(t, f, 0)
	f.mu.Lock()
	f.dropDomain = map[string]int{wire.OperationLocalDomainNodeKeyComplete: 1}
	f.mu.Unlock()
	if _, err := requestMachineAgentEndpoint(f.bridge.path, q); err == nil {
		t.Fatal("lost completion ACK reported ready")
	}
	revoke, err := wire.NewLocalDomainRevoke(f.session, f.scope.Actor, d, f.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(f.device, f.hub, revoke)
	if err != nil {
		t.Fatal(err)
	}
	reply := f.http(t, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainRevoke), "", "", packet, http.StatusOK)
	var revoked wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(f.device, f.hub, packet, reply, &revoked) != nil || revoked.Description == nil || revoked.Description.State != wire.LocalDomainRevoked {
		t.Fatal("actual policy revoke failed")
	}
	if current, e := f.bridge.readLocalDomainCurrent(f.ctx, f.client); e != nil || current != nil {
		t.Fatal("Node did not observe no active current policy", e)
	}
	f.mu.Lock()
	joins := len(f.nodePackets[wire.OperationLocalDomainNodeJoin])
	completes := len(f.nodePackets[wire.OperationLocalDomainNodeKeyComplete])
	f.mu.Unlock()
	history, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil || history.State != "COMPLETED" || history.Join == nil {
		t.Fatal("known original completion became unavailable after revoke", err)
	}
	if _, err := f.bridge.verifyCurrentMCPBinding(history.Join.SessionToken, d.Policy.GroupID); err == nil {
		t.Fatal("historical completion restored revoked communication")
	}
	f.mu.Lock()
	changed := joins != len(f.nodePackets[wire.OperationLocalDomainNodeJoin]) || completes != len(f.nodePackets[wire.OperationLocalDomainNodeKeyComplete])
	f.mu.Unlock()
	if changed {
		t.Fatal("history recovery issued another Join/key-complete")
	}
	now := time.Now().UTC()
	fresh := q
	fresh.RequestID, _ = newLocalEndpointRequestID(now)
	fresh.IssuedAt = now.Format(time.RFC3339Nano)
	refused, err := requestMachineAgentEndpoint(f.bridge.path, fresh)
	if err == nil || refused == nil || refused.State != "REFUSED" {
		t.Fatal("absent current policy admitted or left ambiguous a fresh command")
	}
}

func TestLocalDomainEndpointLostLeaveThenRejoinCannotStopNewAdmission(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	activateLocalDomainConsumer(t, f)
	q := localDomainEndpointCommand(t, f, 0)
	first, err := requestMachineAgentEndpoint(f.bridge.path, q)
	if err != nil {
		t.Fatal(err)
	}
	issue := localDomainConsumerIssue(t, f, 0)
	issue.ToolName = "codex.operator.endpoint_leave"
	ticket, err := requestMachineAgentCodexContextIssue(f.bridge.path, issue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = requestMachineAgentCodexContextConsume(f.bridge.path, syntheticCodexContextConsume(issue, ticket.Ticket)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leave := q
	leave.Operation, leave.Name = "endpoint_leave", ""
	leave.LocalDomainVersion, leave.LocalDomain = 0, wire.LocalDomainSelection{}
	leave.RequestID, _ = newLocalEndpointRequestID(now)
	leave.IssuedAt = now.Format(time.RFC3339Nano)
	f.mu.Lock()
	f.dropDomain = map[string]int{nodewire.EndpointLeaveOperation: 1}
	f.mu.Unlock()
	if _, err = requestMachineAgentEndpoint(f.bridge.path, leave); err == nil {
		t.Fatal("lost Leave ACK reported confirmed")
	}
	if err = f.bridge.Close(); err != nil {
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
	if old, e := requestMachineAgentEndpoint(f.bridge.path, leave); e != nil || old.State != "COMPLETED" {
		t.Fatal("original Leave required a new ticket/history scan after restart", e)
	}
	fresh := localDomainEndpointCommand(t, f, 0)
	next, err := requestMachineAgentEndpoint(f.bridge.path, fresh)
	if err != nil {
		t.Fatal("new explicit same-SID admission after Leave", err)
	}
	if next.Join.Endpoint.ID != first.Join.Endpoint.ID || next.Join.Endpoint.NativeSessionID != first.Join.Endpoint.NativeSessionID || next.Join.BindingEpoch <= first.Join.BindingEpoch || next.LocalDomain.Member.MemberID == first.LocalDomain.Member.MemberID {
		t.Fatal("explicit rejoin replaced native identity or revived an old member")
	}
	if _, err = requestMachineAgentEndpoint(f.bridge.path, leave); err != nil {
		t.Fatal("old Leave receipt no longer recoverable", err)
	}
	f.client.mu.Lock()
	active := false
	for _, m := range f.client.state.ManagedLocalDomainLeases {
		if m.IntentID == fresh.RequestID && m.State == "ACTIVE" {
			active = true
		}
	}
	f.client.mu.Unlock()
	if !active {
		t.Fatal("exact old Leave replay stopped the later native admission")
	}
	if _, err = f.bridge.verifyCurrentMCPBinding(next.Join.SessionToken, next.Join.Endpoint.GroupID); err != nil {
		t.Fatal("old Leave replay revoked the newer Hub binding", err)
	}
}

func TestLocalDomainEndpointLostOriginalAcrossNodeRestart(t *testing.T) {
	for _, operation := range []string{wire.OperationLocalDomainNodeJoin, wire.OperationLocalDomainNodeKeyPrepare, wire.OperationLocalDomainNodeKeyComplete, "candidate"} {
		t.Run(operation, func(t *testing.T) {
			f := newNativePeerTCPConsumerFixture(t, false)
			activateLocalDomainConsumer(t, f)
			q := localDomainEndpointCommand(t, f, 0)
			f.mu.Lock()
			f.dropDomain = map[string]int{operation: 1}
			if operation == "candidate" {
				f.dropCandidate = 1
			}
			f.mu.Unlock()
			if _, err := requestMachineAgentEndpoint(f.bridge.path, q); err == nil {
				t.Fatal("synthetically lost actual ACK reported ready")
			}
			if err := f.bridge.Close(); err != nil {
				t.Fatal(err)
			}
			machineNodeControlClients.Delete(f.client.statePath)
			var err error
			f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
			if err != nil {
				t.Fatal(err)
			}
			result, err := requestMachineAgentEndpoint(f.bridge.path, q)
			if err != nil || result.Join == nil || result.LocalDomain == nil || result.State != "COMPLETED" {
				t.Fatal("original explicit Join did not recover after actual Node restart", err)
			}
			f.bridge.renewLocalDomainLeaseBatch(f.ctx)
			f.client.mu.Lock()
			active := 0
			for _, m := range f.client.state.ManagedLocalDomainLeases {
				if m.State == "ACTIVE" {
					active++
				}
			}
			f.client.mu.Unlock()
			if active != 1 {
				t.Fatal("ACK recovery did not retain one original managed admission", active)
			}
			if operation != "candidate" {
				f.mu.Lock()
				packets := append([][]byte(nil), f.nodePackets[operation]...)
				f.mu.Unlock()
				if len(packets) < 2 || !bytes.Equal(packets[0], packets[1]) {
					t.Fatal("restart replaced the lost original encrypted packet")
				}
			}
		})
	}
}

func TestLocalDomainEndpointRealTCPPrivateIPCExplicitJoinAndLease(t *testing.T) {
	f := newNativePeerTCPConsumerFixture(t, false)
	d := activateLocalDomainConsumer(t, f)
	var results [2]*localEndpointResult
	for i := range results {
		q := localDomainEndpointCommand(t, f, i)
		r, err := requestMachineAgentEndpoint(f.bridge.path, q)
		if err != nil {
			t.Fatal("actual explicit domain Join", err)
		}
		if r.State != "COMPLETED" || r.Join == nil || r.LocalDomain == nil || r.Registration == nil || r.NativeContextScope == nil || !r.NativeContextScope.Accepted || r.Join.Endpoint.NativeSessionID != f.native[i] || r.Join.Endpoint.Workspace != f.workspace || r.Join.Endpoint.MachineID != f.nodeID || r.Join.Endpoint.GroupID != d.Policy.GroupID || r.Join.SessionToken == "" {
			t.Fatal("domain admission did not preserve original native tuple")
		}
		if _, err = wire.VerifyLocalDomainEndpointKeyGrant(r.LocalDomain.Grant, f.hub, d.Policy.OwnerID, f.owner.Public(), time.Now().UTC()); err != nil {
			t.Fatal("actual delegated member/candidate proof chain", err)
		}
		f.client.mu.Lock()
		sequence := f.client.state.Sequence
		f.client.mu.Unlock()
		repeated, err := requestMachineAgentEndpoint(f.bridge.path, q)
		if err != nil || repeated.Join == nil || repeated.Join.SessionToken != r.Join.SessionToken || repeated.Join.BindingID != r.Join.BindingID || repeated.Join.BindingEpoch != r.Join.BindingEpoch || repeated.LocalDomain.Member != r.LocalDomain.Member {
			t.Fatal("exact private command changed original token/binding/member", err)
		}
		f.client.mu.Lock()
		after := f.client.state.Sequence
		f.client.mu.Unlock()
		if after != sequence {
			t.Fatal("exact private command issued another encrypted operation")
		}
		results[i] = r
	}
	if results[0].Join.Endpoint.ID == results[1].Join.Endpoint.ID || results[0].LocalDomain.Member.NativeSessionID == results[1].LocalDomain.Member.NativeSessionID {
		t.Fatal("two explicit Threads shared an Endpoint or fabricated SID")
	}
	f.client.mu.Lock()
	sequence := f.client.state.Sequence
	count := len(f.client.state.ManagedLocalDomainLeases)
	f.client.mu.Unlock()
	if count != 2 {
		t.Fatal("domain admission did not retain exactly its two original lease references", count)
	}
	f.bridge.renewLocalDomainLeaseBatch(f.ctx)
	f.client.mu.Lock()
	after := f.client.state.Sequence
	invalidLease := false
	for _, m := range f.client.state.ManagedLocalDomainLeases {
		if m.State != "ACTIVE" || m.FrozenDigest == "" || !time.Now().Before(parseMachineNativePairTime(m.KnownLeaseExpiresAt)) {
			invalidLease = true
		}
	}
	f.client.mu.Unlock()
	if invalidLease {
		t.Fatal("existing worker lost original domain authority")
	}
	if after != sequence {
		t.Fatal("ordinary heartbeat grew permanent Node mutation receipts")
	}
}
