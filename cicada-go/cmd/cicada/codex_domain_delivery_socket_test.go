package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// Exercise the selected connection, fresh discovery, real SQLite outbox and
// private IPC. Hub cards and Node receipts are synthetic; this is not a native
// Runtime or sealed-packet/Hub Guard acceptance test.
func TestCodexDomainDeliveryUsesSelectedNodeSocket(t *testing.T) {
	for _, environment := range []string{"unset", "other_deployment"} {
		t.Run(environment, func(t *testing.T) {
			m, f, scope, state := codexDomainDeliveryFixture(t)
			root := privateLocalNodeRoot(t)
			pin := syntheticLocalNodePin(t, root, scope.NodeID)
			pin.APIOrigin, pin.StateDir, pin.WriterRoot = f.server.URL, state, state
			pin.SocketPath = machineAgentJoinSocketPath(state, scope.NodeID)
			pin.MCPSessionStateFile = filepath.Join(root, "cache", "sessions.json")
			pin.MCPOutboxStateFile = filepath.Join(root, "outbox", "outbox.sqlite3")
			m.sessionStatePath, m.sessionState = pin.MCPSessionStateFile, newMCPSessionStateStore(pin.MCPSessionStateFile)
			m.outbox = newMCPOutbox(pin.MCPOutboxStateFile)
			if err := validateLocalNodePin(pin); err != nil {
				t.Fatal("invalid synthetic selected pin", err)
			}
			locator := localNodeLocator{localNodeLocatorFormat, strings.Repeat("a", 32), pin.SocketPath}
			data, _ := json.Marshal(locator)
			data = append(data, '\n')
			dir := filepath.Join(root, "run", "nodes")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, localNodeLocatorName(state, scope.NodeID)), data, 0600); err != nil {
				t.Fatal(err)
			}
			m.localNode = &LocalNodeConnection{Pin: pin, InstanceID: locator.InstanceID, LocatorDigest: localNodeDigest(data)}
			m.outbox.connectionPin = m.localNodePin()
			for _, name := range []string{"CICADA_USER_ROOT", "CICADA_NODE_STATE_DIR", "CICADA_STATE_DIR"} {
				t.Setenv(name, "")
			}
			var decoyCalls atomic.Int32
			if environment == "other_deployment" {
				decoy := shortLocalJoinStateDir(t)
				t.Setenv("CICADA_NODE_STATE_DIR", decoy)
				codexConsumerNode(t, decoy, scope.NodeID, func(net.Conn, json.RawMessage) { decoyCalls.Add(1) })
			}
			var calls atomic.Int32
			var originalAsk atomic.Pointer[crossNodeGroupRequest]
			codexConsumerNode(t, state, scope.NodeID, func(c net.Conn, raw json.RawMessage) {
				var header struct{ Operation string }
				if json.Unmarshal(raw, &header) != nil {
					t.Error("invalid synthetic private request")
					return
				}
				if header.Operation == "local_node_describe" {
					var q localNodeDescribeRequest
					_ = json.Unmarshal(raw, &q)
					_ = json.NewEncoder(c).Encode(localNodeDescribeResponse{Version: 1, Description: &localNodeDescription{
						Nonce: q.Nonce, InstanceID: locator.InstanceID, LocatorDigest: localNodeDigest(data), Connection: pin,
					}})
					return
				}
				calls.Add(1)
				var q crossNodeGroupRequest
				if json.Unmarshal(raw, &q) != nil || q.NativeSessionID != scope.NativeSessionID || q.Workspace != scope.Workspace ||
					q.NodeID != scope.NodeID || q.EndpointID != scope.EndpointID || q.GroupID != scope.GroupID ||
					q.BindingID != scope.NativeBindingID || q.BindingEpoch != scope.NativeBindingEpoch {
					t.Error("selected delivery changed its original identity or binding")
					return
				}
				saved, err := m.outbox.load(scope, q.OperationID)
				if err != nil || saved.Status != mcpOutboxStatusUnknown || saved.AttemptCount < 1 ||
					saved.codexOutboxBinding != scope.codexOutboxBinding || saved.IdempotencyKey != q.IdempotencyKey {
					t.Error("private delivery preceded durable original scope and intent", err)
					return
				}
				if q.Operation == "cross_node_group_ask" {
					if originalAsk.CompareAndSwap(nil, &q) {
						return // Lose the first response after receiving the original.
					}
					if !reflect.DeepEqual(*originalAsk.Load(), q) {
						t.Error("recovery replaced the original private ASK package")
						return
					}
				}
				message, request, err := localSealedRPCIDs(q.OperationID)
				if err != nil {
					t.Error(err)
					return
				}
				if q.Operation != "cross_node_group_ask" {
					request = q.RequestID
				}
				_ = json.NewEncoder(c).Encode(localJoinResponse{Version: 1, CrossNodeGroup: &crossNodeGroupResult{
					State: "OPEN", MessageID: message, RequestID: request, Delivery: "RELAY_PERSISTED", PayloadMode: "SEALED_V1",
				}})
			})
			if err := revalidateCodexLocalNode(context.Background(), m.localNode); err != nil {
				t.Fatal("synthetic selected Node discovery failed", err)
			}
			for _, kind := range []string{"send", "ask", "reply"} {
				t.Run(kind, func(t *testing.T) {
					args := map[string]any{"idempotency_key": "synthetic-selected-socket-" + kind}
					if kind == "ask" {
						args["target"], args["question"] = "endpoint-b", "SYNTHETIC_SELECTED_ASK"
					} else {
						args["body"] = "SYNTHETIC_SELECTED_BODY"
						if kind == "send" {
							args["target"] = "endpoint-b"
						} else {
							args["request_id"] = "synthetic-original-request"
						}
					}
					value, err := m.callTool("cicada_"+kind, args)
					if err != nil {
						t.Fatal("selected-socket dispatch rejected its original scope", err)
					}
					public := value.(map[string]any)
					operationID := public["operation_id"].(string)
					if kind == "ask" {
						if public["status"] != mcpOutboxStatusUnknown || public["retryable"] != true || originalAsk.Load() == nil {
							t.Fatal("lost selected-Node response did not retain an uncertain original ASK")
						}
						if _, present := public["request_id"]; present {
							t.Fatal("unverified same-Group ASK exposed a request ID")
						}
						before, err := m.outbox.load(scope, operationID)
						if err != nil {
							t.Fatal(err)
						}
						beforeCalls := calls.Load()
						if _, err := m.mcpOutboxStatus(operationID); err != nil || calls.Load() != beforeCalls {
							t.Fatal("status retried an uncertain operation", err)
						}
						if err := m.outbox.close(); err != nil {
							t.Fatal(err)
						}
						recovered, err := m.outbox.load(scope, operationID)
						if err != nil || recovered != before {
							t.Fatal("outbox reopen replaced the uncertain original", err)
						}
						value, err = m.mcpOutboxRetry(operationID)
						if err != nil {
							t.Fatal("original selected-Node recovery failed", err)
						}
						public = value.(map[string]any)
						if request, ok := public["request_id"].(string); !ok || request == "" {
							t.Fatal("verified ASK receipt lost its durable request ID")
						}
					}
					if public["operation_id"] != operationID || public["status"] != mcpOutboxStatusSent {
						t.Fatal("matching dispatch did not complete through the selected Node socket")
					}
				})
			}
			if calls.Load() != 4 || decoyCalls.Load() != 0 || f.requests.Load() != 0 {
				t.Fatalf("unexpected delivery route: selected_calls=%d decoy_calls=%d plaintext_calls=%d", calls.Load(), decoyCalls.Load(), f.requests.Load())
			}
		})
	}
}
