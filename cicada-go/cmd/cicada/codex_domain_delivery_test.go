package main

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// This fixture exercises the real MCP outbox/HTTP/private-socket dispatch with
// scripted Hub cards and Node receipts, not service cryptography or native UI.
func codexDomainDeliveryFixture(t *testing.T) (*mcpServer, *mcpOutboxHTTPFixture, mcpOutboxScope, string) {
	t.Helper()
	f := newMCPOutboxHTTPFixture(t)
	f.sourceCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	f.targetCapabilities = map[string]any{"local_peer_delivery": "sealed_v1"}
	state := shortLocalJoinStateDir(t)
	t.Setenv("CICADA_NODE_STATE_DIR", state)
	m := mcpOutboxTestServer(t, f, filepath.Join(t.TempDir(), "mcp", "sessions.json"), "domain-delivery", "endpoint-a", "group-a")
	m.sessionMu.Lock()
	m.sessionDomain = syntheticCodexDomainBinding()
	m.sessionMu.Unlock()
	scope, err := m.currentMCPOutboxScope()
	if err != nil || scope.LocalDomainVersion != 1 || scope.NativeBindingID == "" || scope.NativeBindingEpoch == 0 {
		t.Fatal("domain delivery fixture lacks its original binding", err)
	}
	return m, f, scope, state
}

func TestCodexDomainDeliveryDispatchAndReadControlCarryOriginalBinding(t *testing.T) {
	m, f, scope, state := codexDomainDeliveryFixture(t)
	var calls atomic.Int32
	codexConsumerNode(t, state, scope.NodeID, func(c net.Conn, raw json.RawMessage) {
		calls.Add(1)
		var q crossNodeGroupRequest
		if json.Unmarshal(raw, &q) != nil || q.NativeSessionID != scope.NativeSessionID || q.Workspace != scope.Workspace ||
			q.BindingID != scope.NativeBindingID || q.BindingEpoch != scope.NativeBindingEpoch {
			t.Error("delivery or control changed the original native binding")
			return
		}
		if q.Operation == "local_receive" {
			_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, LocalGroup: &localGroupResult{State: "COMPLETED"}})
			return
		}
		result := &crossNodeGroupResult{State: "OPEN", RequestID: q.RequestID}
		if q.OperationID != "" {
			original, err := m.outbox.load(scope, q.OperationID)
			if err != nil || original.codexOutboxBinding != scope.codexOutboxBinding || original.AttemptCount != 1 {
				t.Error("dispatch preceded persistence of the complete immutable binding", err)
				return
			}
			messageID, requestID, err := localSealedRPCIDs(q.OperationID)
			if err != nil {
				t.Error(err)
				return
			}
			result.MessageID, result.Delivery, result.PayloadMode = messageID, "RELAY_PERSISTED", "SEALED_V1"
			if q.Operation == "cross_node_group_ask" {
				result.RequestID = requestID
			}
		}
		_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, CrossNodeGroup: result})
	})
	for _, kind := range []string{"send", "ask", "reply"} {
		t.Run(kind, func(t *testing.T) {
			args := map[string]any{"idempotency_key": "synthetic-domain-" + kind}
			if kind == "ask" {
				args["target"], args["question"] = "endpoint-b", "synthetic private question"
			} else {
				args["body"] = "synthetic private body"
				if kind == "send" {
					args["target"] = "endpoint-b"
				} else {
					args["request_id"] = "synthetic-original-request"
				}
			}
			value, err := m.callTool("cicada_"+kind, args)
			if err != nil {
				t.Fatal("domain dispatch rejected its matching original scope", err)
			}
			result, ok := value.(map[string]any)
			if !ok || result["status"] != mcpOutboxStatusSent {
				t.Fatal("matching domain dispatch did not complete through private Node IPC")
			}
		})
	}
	t.Run("receive", func(t *testing.T) {
		if _, err := m.receiveMCPInbox("", 16); err != nil {
			t.Fatal("domain receive lost its scope projection", err)
		}
	})
	for _, operation := range []string{"local_status", "local_cancel"} {
		t.Run(operation, func(t *testing.T) {
			if _, handled, err := m.localGroupRequestControl(operation, "synthetic-original-request", ""); err != nil || !handled {
				t.Fatal("domain request control lost its scope projection", err)
			}
		})
	}
	for _, operation := range []string{"sealed_status", "sealed_cancel"} {
		t.Run(operation, func(t *testing.T) {
			q, err := m.currentSealedRPCControlRequest(operation, "synthetic-original-request", "synthetic-link", "")
			if err != nil || q.BindingID != scope.NativeBindingID || q.BindingEpoch != scope.NativeBindingEpoch {
				t.Fatal("domain sealed control lost its scope projection", err)
			}
		})
	}
	if calls.Load() != 6 || f.requests.Load() != 0 || f.receiveCalls.Load() != 0 {
		t.Fatal("domain dispatch/read/control missed private IPC or used legacy plaintext HTTP")
	}
}

func TestCodexDomainDeliveryRejectsChangedSelectorAndNativeBindingBeforeHTTP(t *testing.T) {
	m, f, scope, _ := codexDomainDeliveryFixture(t)
	outbox, err := m.ensureMCPOutbox()
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := outbox.prepare(scope, "ask", "synthetic-retained-domain", mcpOutboxInput{Target: "endpoint-b", Question: "synthetic private question"})
	if err != nil {
		t.Fatal(err)
	}
	m.sessionMu.RLock()
	trusted, public, domain := m.sessionContext, m.sessionPublic, m.sessionDomain
	m.sessionMu.RUnlock()
	for _, change := range []string{"legacy", "version", "policy", "epoch", "digest", "native-binding", "native-epoch"} {
		t.Run(change, func(t *testing.T) {
			m.sessionMu.Lock()
			m.sessionPublic, m.sessionDomain = public, domain
			switch change {
			case "legacy":
				m.sessionDomain = codexDomainBinding{}
			case "version":
				m.sessionDomain.LocalDomainVersion++
			case "policy":
				m.sessionDomain.LocalDomain.PolicyID = strings.Repeat("c", 32)
			case "epoch":
				m.sessionDomain.LocalDomain.PolicyEpoch++
			case "digest":
				m.sessionDomain.LocalDomain.PolicyDigest = strings.Repeat("d", 64)
			case "native-binding":
				m.sessionPublic.BindingID = "synthetic-new-admission"
			case "native-epoch":
				m.sessionPublic.BindingEpoch++
			}
			m.sessionMu.Unlock()
			if _, err := m.currentMCPDeliveryRequest(op, mcpOutboxInput{}, trusted); !errors.Is(err, errMCPOutboxContext) {
				t.Fatal("changed scope bypassed strict outbox matching", err)
			}
			if f.whoamiCalls.Load() != 0 || f.resolveCalls.Load() != 0 || f.requests.Load() != 0 {
				t.Fatal("changed binding reached HTTP before immutable scope verification")
			}
			if saved, err := outbox.load(scope, op.OperationID); err != nil || saved != op {
				t.Fatal("changed scope modified the historical outbox row", err)
			}
		})
	}
}
