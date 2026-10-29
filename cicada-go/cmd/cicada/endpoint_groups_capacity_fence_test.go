package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestEndpointGroupsCapacityDamagedRetainedFenceNeverDispatches(t *testing.T) {
	for _, kind := range []string{"unknown_origin", "mixed_profile", "wrong_epoch"} {
		t.Run(kind, func(t *testing.T) {
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				w.WriteHeader(503)
			}))
			defer server.Close()
			c, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, server.URL)
			q := syntheticLocalEndpointRequest("endpoint_register")
			q.APIOrigin = server.URL
			digest, err := c.retainLocalEndpointIntent(q, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			op := wire.OperationEndpointGroupsNodeRenew
			body := endpointGroupsCapacityBody(t, op)
			scope, err := c.prepareLocalEndpointStep(q.RequestID, digest, "groups.damaged", op, body)
			if err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			endpointGroupsCapacityPending(t, c, scope, op, body)
			original := bytes.Clone(c.state.PendingPacket)
			switch kind {
			case "unknown_origin":
				c.state.PendingLocalEndpointIntentID = "synthetic-unknown-origin"
			case "mixed_profile":
				intent := c.state.LocalEndpointIntents[q.RequestID]
				step := intent.Steps[scope.StepID]
				step.Operation = wire.OperationLocalDomainNodeJoin
				intent.Steps[scope.StepID] = step
				c.state.LocalEndpointIntents[q.RequestID] = intent
			case "wrong_epoch":
				c.state.NodeKeyEpoch++
			}
			if err := c.persistLocked(); err != nil {
				t.Fatal("damaged historical fence could not be retained", err)
			}
			before, _ := os.ReadFile(c.statePath)
			sequence := c.state.Sequence
			c.mu.Unlock()
			machineNodeControlClients.Delete(c.statePath)
			c, err = openMachineNodeControlClientMode(c.stateDir, server.URL, c.nodeID, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.recoverNodeControlPending(ctx, "synthetic-node-token"); err == nil {
				t.Fatal("damaged fence recovered through the public recovery dispatcher")
			}
			if err := c.recoverPending(ctx, "synthetic-node-token"); err == nil {
				t.Fatal("damaged original recovered through the exact retry")
			}
			if err := c.callLocalEndpoint(ctx, "synthetic-node-token", q.RequestID, digest, "groups.damaged", op, body, nil); err == nil {
				t.Fatal("damaged original was redispatched")
			}
			if err := c.call(ctx, "synthetic-node-token", wire.OperationEndpointGroupsNodeDescribe, endpointGroupsCapacityBody(t, wire.OperationEndpointGroupsNodeDescribe), nil); err == nil {
				t.Fatal("damaged fence allowed replacement work")
			}
			after, _ := os.ReadFile(c.statePath)
			if posts.Load() != 0 || !bytes.Equal(original, c.state.PendingPacket) || !bytes.Equal(before, after) || sequence != c.state.Sequence {
				t.Fatal("damaged fence changed exact bytes/sequence or dispatched", posts.Load())
			}
		})
	}
}
