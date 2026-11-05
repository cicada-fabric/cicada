package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Scripted Hub responses qualify the private Node producer's PQC/outbox
// boundary only. Actual Hub/Store/Owner/Host admission is a separate gate.
func syntheticThreadCollaborationOriginal(t *testing.T, c *machineNodeControlClient, at time.Time) (machineThreadCollaborationOriginal, wire.GroupLocksNodeAcquire) {
	t.Helper()
	original, err := wire.NewGroupLockOriginal(at)
	if err != nil {
		t.Fatal(err)
	}
	caller := wire.GroupLockHolder{NodeID: c.nodeID, EndpointID: "SYNTHETIC-original-endpoint", PrincipalID: "SYNTHETIC-original-principal", Source: wire.ThreadRegistrationSource{RegistrationID: strings.Repeat("a", 64), SourceEpoch: 1}}
	scope := wire.GroupLockScope{HubID: c.state.HubID, NetworkID: "SYNTHETIC-network", GroupID: "SYNTHETIC-group"}
	request := wire.GroupLockAcquireRequest{Scope: scope, Slot: 1, ExpectedVersion: 1, Original: original}
	digest, err := wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, caller, request)
	if err != nil {
		t.Fatal(err)
	}
	original.RequestDigest = digest
	request.Original = original
	body := wire.GroupLocksNodeAcquire{EndpointID: caller.EndpointID, Request: request}
	raw, _ := json.Marshal(body)
	return machineThreadCollaborationOriginal{Operation: wire.OperationGroupLocksAcquire, EndpointID: caller.EndpointID, Original: original, Scope: scope, Caller: caller, Harness: "codex", NativeSessionID: "SYNTHETIC-original-native-thread", Workspace: "/SYNTHETIC-owned-workspace", RegistrationDigest: strings.Repeat("b", 64), RegistrationRevision: 1, Body: raw, State: localThreadCollaborationUnknown, CreatedAt: at.UTC().Format(time.RFC3339Nano), UpdatedAt: at.UTC().Format(time.RFC3339Nano)}, body
}

func TestThreadCollaborationRPCRealPQCOutboxRecovery(t *testing.T) {
	for _, attack := range []string{"lost-response", "wrong-evidence", "wrong-receipt", "current-denial", "missing-evidence"} {
		t.Run(attack, func(t *testing.T) {
			var mu sync.Mutex
			var hub *e2ee.Identity
			var binding nodewire.Binding
			var client *machineNodeControlClient
			var original, success []byte
			var requests [][]byte
			effects := 0
			var expected machineThreadCollaborationOriginal
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := ioReadAllBounded(r)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				opened, err := nodewire.OpenRequest(hub, binding.NodeKey, binding, raw)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				requests = append(requests, bytes.Clone(raw))
				var saved machineNodeControlState
				disk, err := os.ReadFile(client.statePath)
				if err != nil || json.Unmarshal(disk, &saved) != nil {
					t.Error("private outbox was not readable before POST")
					w.WriteHeader(500)
					return
				}
				record, ok := saved.ThreadCollaborationOriginals[threadCollaborationOriginalKey(expected)]
				if !ok || !bytes.Equal(saved.PendingPacket, raw) || !bytes.Equal(record.RequestPacket, raw) || !bytes.Equal(record.Body, opened.Plaintext) {
					t.Error("POST preceded durable final body and original PQC packet")
					w.WriteHeader(500)
					return
				}
				if original == nil {
					original = bytes.Clone(raw)
					effects++
					observed := time.Now().UTC()
					expiry, _ := wire.GroupLockLeaseExpiry(nil, observed)
					receipt := wire.GroupLockReceipt{Format: wire.GroupLockReceiptFormat, Scope: expected.Scope, OperationID: expected.Original.OperationID, RequestDigest: expected.Original.RequestDigest, Slot: 1, AppliedVersion: 2, Generation: 1, Outcome: "ACQUIRED", ObservedAt: observed.Format(time.RFC3339Nano), ExpiresAt: expiry}
					evidence := wire.ThreadCollaborationNodeEvidence{Operation: expected.Operation, Original: expected.Original, RequestPacketDigest: threadCollaborationPacketDigest(raw), Outcome: localThreadCollaborationApplied}
					makeReply := func(value wire.GroupLockReceipt, proof *wire.ThreadCollaborationNodeEvidence, ok bool, code string) []byte {
						body := machineThreadCollaborationEnvelope{OK: ok, OperationID: opened.Route.OperationID, Sequence: opened.Route.Sequence, OriginalEvidence: proof, ErrorCode: code}
						if ok {
							body.Result, _ = json.Marshal(value)
						}
						plain, _ := json.Marshal(body)
						sealed, e := nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), plain)
						if e != nil {
							t.Error(e)
						}
						return sealed
					}
					success = makeReply(receipt, &evidence, true, "")
					switch attack {
					case "lost-response":
						w.WriteHeader(503)
						return
					case "wrong-evidence":
						bad := evidence
						bad.RequestPacketDigest = strings.Repeat("c", 64)
						_, _ = w.Write(makeReply(receipt, &bad, true, ""))
						return
					case "wrong-receipt":
						bad := receipt
						bad.RequestDigest = strings.Repeat("c", 64)
						_, _ = w.Write(makeReply(bad, &evidence, true, ""))
						return
					case "current-denial":
						_, _ = w.Write(makeReply(receipt, nil, false, wire.ThreadCollaborationErrorAuthorizationRequired))
						return
					case "missing-evidence":
						_, _ = w.Write(makeReply(receipt, nil, true, ""))
						return
					}
				}
				if !bytes.Equal(raw, original) {
					t.Error("recovery changed the original PQC packet")
					w.WriteHeader(409)
					return
				}
				_, _ = w.Write(success)
			}))
			defer server.Close()
			var ctxErr error
			client, ctx, hub, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
			expected, body := syntheticThreadCollaborationOriginal(t, client, time.Now().UTC())
			client.mu.Lock()
			client.state.ThreadCollaborationOriginals = map[string]machineThreadCollaborationOriginal{threadCollaborationOriginalKey(expected): expected}
			ctxErr = client.persistLocked()
			client.mu.Unlock()
			if ctxErr != nil {
				t.Fatal(ctxErr)
			}
			var result wire.GroupLockReceipt
			if err := client.callThreadCollaboration(ctx, "synthetic-node-token", expected.Operation, body, &result); err == nil {
				t.Fatal("unconfirmed or forged response was accepted")
			}
			client.mu.Lock()
			pending := bytes.Clone(client.state.PendingPacket)
			sequence := client.state.Sequence
			record := client.state.ThreadCollaborationOriginals[threadCollaborationOriginalKey(expected)]
			client.mu.Unlock()
			if len(pending) == 0 || record.State != localThreadCollaborationUnknown || len(record.ResponsePacket) != 0 {
				t.Fatal("unknown outcome lost its original or became terminal")
			}
			keyBefore, _ := client.identity.MarshalBinary()
			defer clear(keyBefore)
			machineNodeControlClients.Delete(client.statePath)
			reopened, err := openMachineNodeControlClientMode(client.stateDir, server.URL, client.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			keyAfter, _ := reopened.identity.MarshalBinary()
			defer clear(keyAfter)
			if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(reopened.state.PendingPacket, pending) {
				t.Fatal("cold reopen changed identity or original outbox")
			}
			if err = reopened.callThreadCollaboration(ctx, "synthetic-node-token", expected.Operation, body, &result); err != nil {
				t.Fatal("exact original recovery", err)
			}
			if result.OperationID != expected.Original.OperationID || reopened.state.Sequence != sequence || len(reopened.state.PendingPacket) != 0 || reopened.state.ThreadCollaborationOriginals[threadCollaborationOriginalKey(expected)].State != localThreadCollaborationApplied {
				t.Fatal("original result did not settle exactly once")
			}
			mu.Lock()
			defer mu.Unlock()
			if effects != 1 || len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
				t.Fatal("recovery dispatched a new original")
			}
		})
	}
}

func TestThreadCollaborationTerminalCollectionKeepsUnknownAndPending(t *testing.T) {
	c, _, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:1")
	now := time.Now().UTC()
	old := now.Add(-25 * time.Hour)
	a, _ := syntheticThreadCollaborationOriginal(t, c, old)
	a.State = localThreadCollaborationApplied
	a.RequestPacket = []byte("SYNTHETIC retired terminal")
	b, _ := syntheticThreadCollaborationOriginal(t, c, old)
	b.State = localThreadCollaborationUnknown
	d, _ := syntheticThreadCollaborationOriginal(t, c, old)
	d.State = localThreadCollaborationRejectedFenced
	d.RequestPacket = []byte("SYNTHETIC current pending")
	live, _ := syntheticThreadCollaborationOriginal(t, c, now.Add(-time.Hour))
	live.State = localThreadCollaborationApplied
	c.state.ThreadCollaborationOriginals = map[string]machineThreadCollaborationOriginal{threadCollaborationOriginalKey(a): a, threadCollaborationOriginalKey(b): b, threadCollaborationOriginalKey(d): d, threadCollaborationOriginalKey(live): live}
	c.state.PendingPacket = bytes.Clone(d.RequestPacket)
	c.gcThreadCollaborationOriginalsLocked(now)
	if len(c.state.ThreadCollaborationOriginals) != 3 {
		t.Fatal("terminal collection did not retire only the over-window settled original")
	}
	for _, r := range []machineThreadCollaborationOriginal{b, d, live} {
		if _, ok := c.state.ThreadCollaborationOriginals[threadCollaborationOriginalKey(r)]; !ok {
			t.Fatal("collector erased unknown/current pending/within-window original")
		}
	}
	if wire.ValidateGroupLockOriginalWindow(a.Original, now) == nil {
		t.Fatal("retired original could be admitted again")
	}
}

func TestThreadCollaborationReceiptCannotBorrowAnotherSource(t *testing.T) {
	c, _, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:1")
	original, body := syntheticThreadCollaborationOriginal(t, c, time.Now().UTC())
	original.Caller.Source.SourceEpoch++
	if _, _, _, err := threadCollaborationBodyOriginal(body); err != nil {
		t.Fatal(err)
	}
	if validateMachineThreadCollaborationState(machineNodeControlState{NodeID: c.nodeID, ThreadCollaborationOriginals: map[string]machineThreadCollaborationOriginal{threadCollaborationOriginalKey(original): original}}, c.identity) == nil {
		t.Fatal("altered registered source accepted the old digest")
	}
}

func TestThreadCollaborationHostPreparationDoesNotSpendExecution(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(map[bool]string{false: "MCP", true: "operator"}[operator], func(t *testing.T) {
			var authority localCodexContextAuthority
			now := time.Now().UTC()
			issue := syntheticCodexContextIssue()
			issue.ToolName = threadCollaborationTool(wire.OperationGroupLocksAcquire, operator)
			arguments := map[string]any{"slot": 1, "expected_version": 1, "idempotency_key": "SYNTHETIC-client-key", "recover": false}
			digest, err := codexArgumentsDigest(arguments)
			if err != nil {
				t.Fatal(err)
			}
			issue.ArgumentsDigest = digest
			source := syntheticEndpointGroupsContext()
			source.Harness, source.NativeSessionID, source.Workspace, source.TurnID, source.ToolUseID = issue.Harness, issue.NativeSessionID, issue.Workspace, issue.TurnID, issue.ToolUseID
			issued, err := authority.issueVerified(issue, "SYNTHETIC-owned-binding", now, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = authority.consume(syntheticCodexContextConsume(issue, issued.Ticket), "SYNTHETIC-owned-binding", now); err != nil {
				t.Fatal(err)
			}
			binding, err := codexContextBinding(source)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(arguments)
			id := strings.Split(issued.Ticket, ".")[0]
			q := localThreadCollaborationRequest{localEndpointGroupsRequest: localEndpointGroupsRequest{Version: 1, Operation: wire.OperationGroupLocksAcquire, APIOrigin: issue.APIOrigin, Harness: issue.Harness, NativeSessionID: issue.NativeSessionID, Workspace: issue.Workspace, ContextTicketID: id, ConnectionNonce: issue.ConnectionNonce, ToolName: issue.ToolName, ArgumentsDigest: digest, Arguments: raw, GroupID: "SYNTHETIC-exact-group", codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding}, ContextOnly: true}
			if operator {
				q.Operator = &endpointGroupsOperatorContextProof{ContextTicketID: id, ContextConnectionNonce: issue.ConnectionNonce}
			}
			if _, err = authority.authorizeThreadCollaboration(q, false, now); err != nil {
				t.Fatal("metadata preparation rejected", err)
			}
			altered := q
			altered.GroupID = "SYNTHETIC-other-group"
			if _, err = authority.authorizeThreadCollaboration(altered, false, now); err == nil {
				t.Fatal("metadata preparation moved the actual invocation's Group")
			}
			q.ContextOnly = false
			if _, err = authority.authorizeThreadCollaboration(q, true, now); err != nil {
				t.Fatal("metadata preparation consumed the business invocation", err)
			}
			if _, err = authority.authorizeThreadCollaboration(q, true, now); err == nil {
				t.Fatal("same Host invocation executed twice")
			}
			if _, err = authority.authorizeThreadCollaboration(q, false, now); err == nil {
				t.Fatal("spent execution ticket reentered metadata preparation")
			}
		})
	}
}

func TestThreadCollaborationOriginalEvidenceRejectsCurrentDenialAndUnavailable(t *testing.T) {
	c, _, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:1")
	record, _ := syntheticThreadCollaborationOriginal(t, c, time.Now().UTC())
	record.RequestPacket = []byte("SYNTHETIC original PQC framing witness")
	proof := wire.ThreadCollaborationNodeEvidence{Operation: record.Operation, Original: record.Original, RequestPacketDigest: threadCollaborationPacketDigest(record.RequestPacket), Outcome: localThreadCollaborationRejectedFenced, ErrorCode: wire.ThreadCollaborationErrorSlotBusy}
	valid := machineThreadCollaborationEnvelope{ErrorCode: proof.ErrorCode, OriginalEvidence: &proof}
	if err := validateThreadCollaborationOriginalEnvelope(record, valid); err != nil {
		t.Fatal("exact semantic no-effect evidence refused", err)
	}
	for _, kind := range []string{"current-denial", "receipt-unavailable", "another-original", "another-packet"} {
		t.Run(kind, func(t *testing.T) {
			q := valid
			p := proof
			q.OriginalEvidence = &p
			switch kind {
			case "current-denial":
				q.ErrorCode = wire.ThreadCollaborationErrorAuthorizationRequired
				q.OriginalEvidence = nil
			case "receipt-unavailable":
				q.ErrorCode = wire.ThreadCollaborationErrorReceiptUnavailable
				p.ErrorCode = q.ErrorCode
			case "another-original":
				p.Original.OperationID = strings.Repeat("d", 32)
			case "another-packet":
				p.RequestPacketDigest = strings.Repeat("e", 64)
			}
			if validateThreadCollaborationOriginalEnvelope(record, q) == nil {
				t.Fatal("unproven/current refusal became original no-effect")
			}
		})
	}
}

func TestThreadCollaborationBoundedTerminalEvictionAllowsContinuedUse(t *testing.T) {
	for _, kind := range []string{"terminal-pressure", "all-unknown"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _ := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:1")
			now := time.Now().UTC()
			c.state.ThreadCollaborationOriginals = map[string]machineThreadCollaborationOriginal{}
			var protected string
			for i := 0; i < machineThreadCollaborationOriginalLimit; i++ {
				r, _ := syntheticThreadCollaborationOriginal(t, c, now.Add(-time.Hour).Add(time.Duration(i)*time.Millisecond))
				if kind == "terminal-pressure" && i > 0 {
					r.State = localThreadCollaborationApplied
				}
				key := threadCollaborationOriginalKey(r)
				c.state.ThreadCollaborationOriginals[key] = r
				if i == 0 {
					protected = key
				}
			}
			room := c.makeThreadCollaborationOriginalRoomLocked(now)
			if kind == "terminal-pressure" {
				if !room || len(c.state.ThreadCollaborationOriginals) != machineThreadCollaborationOriginalLimit-1 {
					t.Fatal("settled journal became a lifetime operation quota")
				}
			} else if room || len(c.state.ThreadCollaborationOriginals) != machineThreadCollaborationOriginalLimit {
				t.Fatal("capacity erased an unknown original")
			}
			if _, ok := c.state.ThreadCollaborationOriginals[protected]; !ok {
				t.Fatal("terminal pressure evicted an unresolved original")
			}
		})
	}
}

func TestThreadCollaborationPendingHostGateIsExactAndReadOnly(t *testing.T) {
	c, _, _, binding := newMachineNodeControlRecoveryFixture(t, "http://127.0.0.1:1")
	original, _ := syntheticThreadCollaborationOriginal(t, c, time.Now().UTC())
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch, Sequence: 1, OperationID: "SYNTHETIC-original-carrier", Operation: original.Operation, SenderKeyID: binding.NodeKey.ID, SenderKeyVersion: binding.NodeKeyVersion, ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	packet, err := nodewire.SealRequest(c.identity, binding.HubKey, binding, route, original.Body)
	if err != nil {
		t.Fatal(err)
	}
	original.RequestPacket = packet
	c.state.PendingPacket = packet
	c.state.PendingOperation = original.Operation
	c.state.PendingOperationID = route.OperationID
	c.state.PendingSequence = 1
	c.state.PendingPlaintextDigest = threadCollaborationPacketDigest(original.Body)
	c.state.ThreadCollaborationOriginals = map[string]machineThreadCollaborationOriginal{threadCollaborationOriginalKey(original): original}
	r := machineEndpointGroupsRegistration{Anchor: wire.EndpointGroupsRegistrationAnchor{Registration: e2ee.EndpointGroupRegistration{HubID: binding.HubID, NodeID: binding.NodeID, EndpointID: original.Caller.EndpointID, PrincipalID: original.Caller.PrincipalID, Harness: original.Harness, NativeSessionID: original.NativeSessionID, Workspace: original.Workspace}, RegistrationDigest: original.RegistrationDigest, RegistrationRevision: original.RegistrationRevision}}
	q := localCodexContextIssue{Harness: original.Harness, NativeSessionID: original.NativeSessionID, Workspace: original.Workspace, ToolName: threadCollaborationTool(original.Operation, false)}
	before, _ := json.Marshal(c.state)
	if !threadCollaborationPendingNative(c.state, r, q) {
		t.Fatal("the exact pending source could not obtain a fresh recovery identity ticket")
	}
	for _, change := range []string{"native", "workspace", "operation", "anchor", "principal"} {
		t.Run(change, func(t *testing.T) {
			next, candidate := q, r
			switch change {
			case "native":
				next.NativeSessionID += "-other"
			case "workspace":
				next.Workspace += "-other"
			case "operation":
				next.ToolName = threadCollaborationTool(wire.OperationGroupLocksRenew, false)
			case "anchor":
				candidate.Anchor.RegistrationDigest = strings.Repeat("c", 64)
			case "principal":
				candidate.Anchor.Registration.PrincipalID += "-other"
			}
			if threadCollaborationPendingNative(c.state, candidate, next) {
				t.Fatal("another invocation borrowed the pending source")
			}
		})
	}
	after, _ := json.Marshal(c.state)
	if !bytes.Equal(before, after) {
		t.Fatal("issuing identity scope altered or dispatched the unknown original")
	}
}
