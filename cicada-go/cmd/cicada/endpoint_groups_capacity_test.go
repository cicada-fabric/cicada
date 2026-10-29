package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func endpointGroupsCapacityBody(t *testing.T, operation string) any {
	t.Helper()
	switch operation {
	case wire.OperationEndpointGroupsNodeDescribe:
		return wire.EndpointGroupsNodeDescribe{EndpointID: "synthetic-endpoint", NetworkID: "synthetic-network", Limit: 64}
	case wire.OperationEndpointGroupsNodeKeyPrepare:
		return wire.EndpointGroupsNodeKeyPrepare{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, EndpointID: "synthetic-endpoint", GroupID: "synthetic-group", ExpectedRelationRevision: 1}
	case wire.OperationEndpointGroupsNodeKeyComplete:
		proof, err := json.Marshal(e2ee.EndpointGroupKeyProof{Claims: e2ee.EndpointGroupKeyClaims{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, ChallengeID: strings.Repeat("b", 32)}})
		if err != nil {
			t.Fatal(err)
		}
		return wire.EndpointGroupsNodeKeyComplete{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, EndpointID: "synthetic-endpoint", GroupID: "synthetic-group", ExpectedRelationRevision: 1, ChallengeID: strings.Repeat("b", 32), NodeProof: proof}
	default:
		return wire.EndpointGroupsNodeRenew{EndpointID: "synthetic-endpoint", RegistrationDigest: strings.Repeat("a", 64), ExpectedBindingID: "synthetic-binding", ExpectedBindingEpoch: 1}
	}
}

func endpointGroupsCapacityPending(t *testing.T, c *machineNodeControlClient, scope localEndpointCallScope, operation string, body any) {
	t.Helper()
	plain, err := wire.CanonicalEndpointGroupsNodeRequest(operation, body)
	if err != nil {
		t.Fatal(err)
	}
	b := machineNodeControlBindingFromState(c)
	r := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: c.state.Sequence + 1, OperationID: scope.StepID, Operation: operation, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	p, err := nodewire.SealRequest(c.identity, b.HubKey, b, r, plain)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(plain)
	c.state.Sequence, c.state.PendingSequence = r.Sequence, r.Sequence
	c.state.PendingOperationID, c.state.PendingOperation = r.OperationID, operation
	c.state.PendingPlaintextDigest = hex.EncodeToString(digest[:])
	c.state.PendingPacket, c.state.PendingLocalEndpointIntentID = p, scope.IntentID
}

// A single computed fixture allocation places the *real codec* peak exactly on
// the hard boundary. No repeated filling or discarded original history is used.
func TestEndpointGroupsCapacityExactBoundaryBeforePOST(t *testing.T) {
	for _, operation := range wire.EndpointGroupsNodeOperations()[:4] {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/over_%d", operation, extra), func(t *testing.T) {
				var posts atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					posts.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				defer server.Close()
				c, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
				q := syntheticLocalEndpointRequest("endpoint_register")
				q.APIOrigin = server.URL
				digest, err := c.retainLocalEndpointIntent(q, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				body := endpointGroupsCapacityBody(t, operation)
				scope, err := c.prepareLocalEndpointStep(q.RequestID, digest, "groups.capacity", operation, body)
				if err != nil {
					t.Fatal(err)
				}
				c.mu.Lock()
				// Existing managed reservations and an existing read fence are part
				// of S, never treated as replaceable free space by admission.
				c.state.ManagedPairLeases = map[string]machineManagedPairLease{"synthetic-reserved": {State: "RESERVED"}}
				c.state.ManagedLocalDomainLeases = map[string]machineManagedLocalDomainLease{"synthetic-reserved": {State: "RESERVED"}}
				c.state.LocalEndpointIntents["synthetic-capacity-history"] = machineLocalEndpointIntent{Steps: map[string]machineLocalEndpointStep{"synthetic-history": {Body: json.RawMessage(`""`)}}}
				c.state.EndpointGroupsRegistrations = map[string]machineEndpointGroupsRegistration{"synthetic-registration": {Anchor: wire.EndpointGroupsRegistrationAnchor{RegistrationDigest: "synthetic-registration"}}}
				base := cloneMachineNodeControlState(c.state)
				endpointGroupsCapacityPending(t, c, scope, operation, body)
				c.state.EndpointGroupsLastReadFence = &machineEndpointGroupsDiagnostic{OriginalDigest: nodewire.RecoveryDigest(c.state.PendingPacket), OriginalPacket: bytes.Clone(c.state.PendingPacket), Packet: bytes.Clone(c.state.PendingPacket), ResponsePacket: bytes.Clone(c.state.PendingPacket)}
				base.EndpointGroupsLastReadFence = c.state.EndpointGroupsLastReadFence
				peak, err := c.endpointGroupsPendingPeakLocked()
				if err != nil {
					t.Fatal(err)
				}
				padding := strings.Repeat("x", maxMachineNodeControlStateBytes-peak+extra)
				putHistory := func(s *machineNodeControlState) {
					i := s.LocalEndpointIntents["synthetic-capacity-history"]
					i.Steps["synthetic-history"] = machineLocalEndpointStep{Body: json.RawMessage(`"` + padding + `"`)}
					s.LocalEndpointIntents["synthetic-capacity-history"] = i
				}
				putHistory(&c.state)
				peak, err = c.endpointGroupsPendingPeakLocked()
				if err != nil || peak != maxMachineNodeControlStateBytes+extra {
					t.Fatal("fixture missed exact byte boundary", peak, err)
				}
				c.state = base
				putHistory(&c.state)
				if err := c.persistLocked(); err != nil {
					t.Fatal(err)
				}
				before, _ := os.ReadFile(c.statePath)
				sequence := c.state.Sequence
				c.mu.Unlock()
				err = c.callLocalEndpoint(ctx, "synthetic-node-token", q.RequestID, digest, "groups.capacity", operation, body, nil)
				if extra == 1 {
					after, _ := os.ReadFile(c.statePath)
					if !errors.Is(err, errLocalEndpointHistoryFull) || posts.Load() != 0 || c.state.Sequence != sequence || len(c.state.PendingPacket) != 0 || !bytes.Equal(before, after) {
						t.Fatal("one-byte overflow dispatched or consumed sequence/state", err, posts.Load())
					}
					return
				}
				if !machineAPIHasStatus(err, http.StatusServiceUnavailable) || posts.Load() != 1 || c.state.Sequence != sequence+1 {
					t.Fatal("just-fitting original was not durably dispatched", err, posts.Load())
				}
				pending := bytes.Clone(c.state.PendingPacket)
				before, _ = os.ReadFile(c.statePath)
				// A local registration update cannot steal recovery bytes after
				// the original is admitted, and its rollback keeps the outbox.
				r := c.state.EndpointGroupsRegistrations["synthetic-registration"]
				r.ObservedAt = "2026-10-29T00:00:00Z"
				if err := c.saveEndpointGroupsRegistration(r); !errors.Is(err, errLocalEndpointHistoryFull) {
					t.Fatal("local update consumed pending recovery capacity", err)
				}
				after, _ := os.ReadFile(c.statePath)
				if !bytes.Equal(before, after) || !bytes.Equal(pending, c.state.PendingPacket) || posts.Load() != 1 {
					t.Fatal("capacity rollback lost original or modified disk")
				}
			})
		}
	}
}

// Packet itself stays canonical; signed Envelope JSON accepts whitespace.
// Its base64 codec advances in four-byte units, so use the largest attainable
// packet at or below the limit (within three bytes of the numeric hard bound).
func endpointGroupsCapacityMaximumPacket(t *testing.T, raw []byte, limit int) []byte {
	t.Helper()
	p, err := wire.DecodeEndpointGroupsNodePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	fixed := len(raw) - base64.StdEncoding.EncodedLen(len(p.Envelope))
	envelopeSize := ((limit - fixed) / 4) * 3
	p.Envelope = append(p.Envelope, bytes.Repeat([]byte{' '}, envelopeSize-len(p.Envelope))...)
	maximum, err := json.Marshal(p)
	if err != nil || len(maximum) > limit || limit-len(maximum) >= 4 {
		t.Fatal("packet did not reach codec maximum", len(maximum), limit, err)
	}
	if _, err := wire.DecodeEndpointGroupsNodePacket(maximum); err != nil {
		t.Fatal(err)
	}
	return maximum
}

func TestEndpointGroupsCapacityMaximumCodecColdRecovery(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("read_expired_%t", expired), func(t *testing.T) {
			var c *machineNodeControlClient
			var hub *e2ee.Identity
			var binding nodewire.Binding
			var original, receipt, query, response []byte
			var queries atomic.Int32
			op := wire.OperationEndpointGroupsNodeRenew
			if expired {
				op = wire.OperationEndpointGroupsNodeKeyPrepare
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
				if opened.Route.Operation == op {
					if !bytes.Equal(raw, original) {
						t.Error("original retry bytes changed")
					}
					w.WriteHeader(503)
					return
				}
				if opened.Route.Operation != wire.OperationEndpointGroupsNodeReconcile {
					t.Error("replacement operation")
					w.WriteHeader(400)
					return
				}
				if queries.Add(1) == 1 {
					query = bytes.Clone(raw)
					packet, _ := wire.DecodeEndpointGroupsNodePacket(original)
					state := "COMPLETED"
					if expired {
						state = "READ_EXPIRED"
					}
					result := wire.EndpointGroupsNodeReconciled{ContractRevision: wire.OwnerEndpointGroupsContractRevision, OriginalOperation: op, OriginalOperationID: packet.Route.OperationID, OriginalSequence: packet.Route.Sequence, OriginalPacketDigest: nodewire.RecoveryDigest(original), State: state, ReceiptPacket: receipt, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
					response, err = nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, result, ""))
					if err != nil {
						t.Error(err)
					}
					response = endpointGroupsCapacityMaximumPacket(t, response, wire.MaxEndpointGroupsNodeReconcilePacketBytes)
					w.WriteHeader(503) // committed diagnostic acknowledgement lost
					return
				}
				if !bytes.Equal(query, raw) {
					t.Error("diagnostic retry changed bytes/operation ID/sequence")
				}
				_, _ = w.Write(response)
			}))
			defer server.Close()
			c, ctx, hub, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
			q := syntheticLocalEndpointRequest("endpoint_register")
			q.APIOrigin = server.URL
			digest, err := c.retainLocalEndpointIntent(q, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			body := endpointGroupsCapacityBody(t, op)
			scope, err := c.prepareLocalEndpointStep(q.RequestID, digest, "groups.maximum", op, body)
			if err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			endpointGroupsCapacityPending(t, c, scope, op, body)
			// Real sealed codecs with legal transport whitespace reach exact
			// original/receipt maxima without inventing cryptographic contents.
			original = endpointGroupsCapacityMaximumPacket(t, bytes.Clone(c.state.PendingPacket), wire.MaxEndpointGroupsNodeOriginalBytes)
			c.state.PendingPacket = original
			packet, err := wire.DecodeEndpointGroupsNodePacket(original)
			if err != nil {
				t.Fatal(err)
			}
			code := ""
			var result any = map[string]bool{"synthetic_transport_only": true}
			if expired {
				code, result = "READ_EXPIRED", nil
			}
			receipt, err = nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(packet.Route), nodeControlTestEnvelope(t, packet.Route, !expired, result, code))
			if err != nil {
				t.Fatal(err)
			}
			receipt = endpointGroupsCapacityMaximumPacket(t, receipt, wire.MaxEndpointGroupsNodeReceiptBytes)
			// Fit once to the projected peak, keeping an older read fence in S.
			c.state.EndpointGroupsLastReadFence = &machineEndpointGroupsDiagnostic{OriginalDigest: nodewire.RecoveryDigest(original), OriginalPacket: original, Packet: original, ResponsePacket: receipt}
			c.state.LocalEndpointIntents["synthetic-capacity-history"] = machineLocalEndpointIntent{Steps: map[string]machineLocalEndpointStep{"synthetic-history": {Body: json.RawMessage(`""`)}}}
			peak, err := c.endpointGroupsPendingPeakLocked()
			if err != nil {
				t.Fatal(err)
			}
			i := c.state.LocalEndpointIntents["synthetic-capacity-history"]
			i.Steps["synthetic-history"] = machineLocalEndpointStep{Body: json.RawMessage(`"` + strings.Repeat("x", maxMachineNodeControlStateBytes-peak) + `"`)}
			c.state.LocalEndpointIntents["synthetic-capacity-history"] = i
			if err := c.persistLocked(); err != nil {
				t.Fatal(err)
			}
			c.mu.Unlock()
			reopen := func() {
				machineNodeControlClients.Delete(c.statePath)
				c, err = openMachineNodeControlClientMode(c.stateDir, server.URL, c.nodeID, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			reopen()
			if err := c.recoverNodeControlPending(ctx, "synthetic-node-token"); !machineAPIHasStatus(err, 503) {
				t.Fatal("lost diagnostic did not remain pending", err)
			}
			reopen()
			if !bytes.Equal(c.state.PendingPacket, original) || !bytes.Equal(c.state.EndpointGroupsDiagnostic.Packet, query) {
				t.Fatal("cold reopen changed exact retained packets")
			}
			if err := c.recoverNodeControlPending(ctx, "synthetic-node-token"); err != nil {
				t.Fatal("maximum original recovery did not settle", err)
			}
			reopen()
			step, ok, err := c.localEndpointStep(q.RequestID, digest, "groups.maximum")
			if err != nil || !ok || !step.Settled || !bytes.Equal(step.RequestPacket, original) || queries.Load() != 2 || len(c.state.PendingPacket) != 0 {
				t.Fatal("original receipt/identity was lost", err)
			}
			if expired {
				if !bytes.Equal(step.DiagnosticPacket, query) || !bytes.Equal(step.DiagnosticResponse, response) || !bytes.Equal(c.state.EndpointGroupsLastReadFence.ResponsePacket, response) {
					t.Fatal("dual read-expiry diagnostics were not retained")
				}
			} else if !bytes.Equal(step.ResponsePacket, receipt) {
				t.Fatal("completed original receipt was not retained byte-for-byte")
			}
			t.Logf("CLOSED_CAPACITY_MAXIMUM original_bytes=%d query_bytes=%d receipt_bytes=%d diagnostic_response_bytes=%d cold_reopens=3 dual_read_expiry=%t", len(original), len(query), len(receipt), len(response), expired)
		})
	}
}
