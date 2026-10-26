package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

// This exercises the production Node RPC sealing, durable original outbox,
// restart, detached reconciliation and nested receipt verification. The Hub
// response is scripted; no Group authorization or production Hub gate is claimed.
func TestEndpointGroupsRPCRecoveryKeepsExactOriginalAndRejectsFalseReadExpiry(t *testing.T) {
	for _, kind := range []string{"completed-mutation", "expired-read", "invalid-nested-read", "expired-mutation"} {
		t.Run(kind, func(t *testing.T) {
			var mu sync.Mutex
			var hub *e2ee.Identity
			var binding nodewire.Binding
			var client *machineNodeControlClient
			var original, receipt []byte
			var originals [][]byte
			diagnostics := 0
			operation := wire.OperationEndpointGroupsNodeRenew
			var body any = wire.EndpointGroupsNodeRenew{EndpointID: "synthetic-original-endpoint", RegistrationDigest: strings.Repeat("a", 64), ExpectedBindingID: "synthetic-original-binding", ExpectedBindingEpoch: 7}
			if kind == "expired-read" || kind == "invalid-nested-read" {
				operation = wire.OperationEndpointGroupsNodeDescribe
				body = wire.EndpointGroupsNodeDescribe{EndpointID: "synthetic-original-endpoint", NetworkID: "synthetic-original-network", Limit: 64}
			}
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
				if opened.Route.Operation == operation {
					originals = append(originals, bytes.Clone(raw))
					if original == nil {
						original = bytes.Clone(raw)
						ok, code, result := true, "", any(map[string]any{"synthetic_original": "settled"})
						if kind != "completed-mutation" {
							ok, code, result = false, "READ_EXPIRED", nil
						}
						receipt, err = nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, ok, result, code))
						if err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return
						}
						if kind == "invalid-nested-read" {
							packet, _ := nodewire.DecodePacket(receipt)
							packet.Envelope[0] ^= 1
							receipt, _ = json.Marshal(packet)
						}
					} else if !bytes.Equal(original, raw) {
						t.Error("recovery changed original mutation/read bytes")
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if opened.Route.Operation != wire.OperationEndpointGroupsNodeReconcile {
					t.Error("unknown replacement operation was dispatched")
					w.WriteHeader(400)
					return
				}
				diagnostics++
				var q wire.EndpointGroupsNodeReconcile
				if decodeStrictBridgeJSON(opened.Plaintext, &q) != nil || !bytes.Equal(q.OriginalPacket, original) {
					t.Error("reconcile lost exact original")
					w.WriteHeader(400)
					return
				}
				stateRaw, _ := os.ReadFile(client.statePath)
				var saved machineNodeControlState
				_ = json.Unmarshal(stateRaw, &saved)
				if !bytes.Equal(saved.PendingPacket, original) || saved.EndpointGroupsDiagnostic == nil || !bytes.Equal(saved.EndpointGroupsDiagnostic.Packet, raw) {
					t.Error("diagnostic POST preceded durable original and wrapper")
					w.WriteHeader(500)
					return
				}
				packet, _ := nodewire.DecodePacket(original)
				state := "READ_EXPIRED"
				if kind == "completed-mutation" {
					state = "COMPLETED"
				}
				result := wire.EndpointGroupsNodeReconciled{ContractRevision: wire.OwnerEndpointGroupsContractRevision, OriginalOperation: operation, OriginalOperationID: packet.Route.OperationID, OriginalSequence: packet.Route.Sequence, OriginalPacketDigest: nodewire.RecoveryDigest(original), State: state, ReceiptPacket: receipt, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				sealed, err := nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, result, ""))
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				_, _ = w.Write(sealed)
			}))
			defer server.Close()
			var err error
			client, ctx, hub, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
			q := syntheticLocalEndpointRequest("endpoint_register")
			q.APIOrigin = server.URL
			digest, err := client.retainLocalEndpointIntent(q, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if err := client.callLocalEndpoint(ctx, "synthetic-node-token", q.RequestID, digest, "groups.synthetic.original", operation, body, nil); err == nil {
				t.Fatal("lost original acknowledgement reported confirmed")
			}
			keyBefore, _ := client.identity.MarshalBinary()
			machineNodeControlClients.Delete(client.statePath)
			client, err = openMachineNodeControlClientMode(client.stateDir, server.URL, client.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			err = client.recoverNodeControlPending(ctx, "synthetic-node-token")
			if kind == "invalid-nested-read" || kind == "expired-mutation" {
				if !errors.Is(err, errMachineNodeControlOutcomeUncertain) || len(client.state.PendingPacket) == 0 || client.state.EndpointGroupsLastReadFence != nil {
					t.Fatal("unauthenticated/read-style mutation expiry settled an unknown original", err)
				}
			} else {
				if err != nil || len(client.state.PendingPacket) != 0 {
					t.Fatal("authenticated original recovery remained pending", err)
				}
				step, ok, err := client.localEndpointStep(q.RequestID, digest, "groups.synthetic.original")
				if err != nil || !ok || !step.Settled || !bytes.Equal(step.RequestPacket, original) {
					t.Fatal("original packet was not retained after recovery", err)
				}
				if kind == "expired-read" {
					if len(step.ResponsePacket) != 0 || len(step.DiagnosticResponse) == 0 || client.state.EndpointGroupsLastReadFence == nil || !bytes.Equal(client.state.EndpointGroupsLastReadFence.OriginalPacket, original) {
						t.Fatal("read no-effect fence lost its authenticated original evidence")
					}
				} else {
					var result map[string]any
					if err := client.callLocalEndpoint(ctx, "synthetic-node-token", q.RequestID, digest, "groups.synthetic.original", operation, body, &result); err != nil || result["synthetic_original"] != "settled" {
						t.Fatal("exact completed mutation could not replay its original receipt", err)
					}
				}
			}
			keyAfter, _ := client.identity.MarshalBinary()
			if !bytes.Equal(keyBefore, keyAfter) {
				t.Fatal("recovery replaced original Node identity")
			}
			mu.Lock()
			valid := len(originals) == 2 && bytes.Equal(originals[0], originals[1]) && diagnostics == 1
			mu.Unlock()
			if !valid {
				t.Fatal("recovery failed exact original retry plus one detached diagnostic")
			}
		})
	}
}
