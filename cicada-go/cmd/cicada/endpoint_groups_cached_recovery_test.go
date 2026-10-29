package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// This scripted authenticated transport fixture proves only the negative
// no-reconcile guard. It supplies no valid Group grant or business authority;
// full real grant installation is covered by the four-original regression.
func TestEndpointGroupsCachedResponseLocalFailureDoesNotReconcile(t *testing.T) {
	for _, kind := range []string{"canceled_complete", "cleanup_io_failure"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			var hub *e2ee.Identity
			var binding nodewire.Binding
			var response, original []byte
			var transportMu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
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
				transportMu.Lock()
				defer transportMu.Unlock()
				original = bytes.Clone(raw)
				response, err = nodewire.SealResponse(hub, binding.NodeKey, binding, nodeControlTestResponseRoute(opened.Route), nodeControlTestEnvelope(t, opened.Route, true, map[string]bool{"synthetic_transport_only": true}, ""))
				if err != nil {
					t.Error(err)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			client, ctx, hub, binding := newMachineNodeControlRecoveryFixture(t, server.URL)
			q := syntheticLocalEndpointRequest("endpoint_register")
			q.APIOrigin = server.URL
			digest, err := client.retainLocalEndpointIntent(q, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			op := wire.OperationEndpointGroupsNodeRenew
			var body any = wire.EndpointGroupsNodeRenew{EndpointID: "synthetic-original-endpoint", RegistrationDigest: strings.Repeat("a", 64), ExpectedBindingID: "synthetic-binding", ExpectedBindingEpoch: 1}
			if kind == "canceled_complete" {
				op = wire.OperationEndpointGroupsNodeKeyComplete
				proof, err := json.Marshal(e2ee.EndpointGroupKeyProof{Claims: e2ee.EndpointGroupKeyClaims{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, ChallengeID: strings.Repeat("b", 32)}})
				if err != nil {
					t.Fatal(err)
				}
				body = wire.EndpointGroupsNodeKeyComplete{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, EndpointID: "synthetic-original-endpoint", GroupID: "synthetic-group", ExpectedRelationRevision: 1, ChallengeID: strings.Repeat("b", 32), NodeProof: proof}
			}
			if err := client.callLocalEndpoint(ctx, "synthetic-node-token", q.RequestID, digest, "groups.synthetic.cached", op, body, nil); err == nil {
				t.Fatal("transport failure was not retained")
			}
			transportMu.Lock()
			originalPacket, cachedResponse := bytes.Clone(original), bytes.Clone(response)
			transportMu.Unlock()
			client.mu.Lock()
			client.state.PendingResponsePacket = bytes.Clone(cachedResponse)
			err = client.persistLocked()
			client.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			originalPath := client.statePath
			if kind == "canceled_complete" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			} else {
				blocked := filepath.Join(t.TempDir(), "synthetic-directory-not-state-file")
				if err := os.Mkdir(blocked, 0700); err != nil {
					t.Fatal(err)
				}
				client.statePath = blocked
				defer func() { client.statePath = originalPath }()
			}
			err = client.recoverNodeControlPending(ctx, "synthetic-node-token")
			if err == nil {
				t.Fatal("local settlement failure was swallowed")
			}
			if kind == "canceled_complete" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation was replaced", err)
			}
			if kind == "cleanup_io_failure" {
				// The existing secret-file helper formats this OS rename error
				// without wrapping; preserve its existing returned error.
				if !strings.HasPrefix(err.Error(), "install Node identity file: rename ") {
					t.Fatal("original storage error was replaced", err)
				}
			}
			client.mu.Lock()
			same := bytes.Equal(client.state.PendingPacket, originalPacket) && bytes.Equal(client.state.PendingResponsePacket, cachedResponse) && client.state.EndpointGroupsDiagnostic == nil
			client.mu.Unlock()
			if !same || calls.Load() != 1 {
				t.Fatal("local failure changed original or sent extra RPC", calls.Load())
			}
		})
	}
}
