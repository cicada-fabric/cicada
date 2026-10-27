package n3_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Infrastructure only: actual TCP cancellations and real PQ packets. This
// transport fixture creates no product Group grant and supplies no Runtime fact.
func TestN3OwnerGroupsExactOperationHoldSurvivesCancellation(t *testing.T) {
	node, hub := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	b := nodewire.Binding{HubID: "hub-synthetic", NodeID: "node-synthetic", BindingID: "binding-synthetic",
		BindingVersion: 1, NodeKeyEpoch: 1, HubKeyVersion: 1, NodeKeyVersion: 1, NodeKey: node.Public(), HubKey: hub.Public()}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID,
		BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, OperationID: "op-synthetic-original",
		Sequence: 521, Operation: wire.OperationEndpointGroupsNodeKeyComplete, SenderKeyID: node.Public().ID, SenderKeyVersion: 1,
		ReceiverKeyID: hub.Public().ID, ReceiverKeyVersion: 1}
	seal := func(r nodewire.Route) []byte {
		return must(nodewire.SealRequest(node, hub.Public(), b, r, []byte(`{"synthetic":"exact-hold-only"}`)))
	}
	original, changedCipher := seal(route), seal(route)
	var mu sync.Mutex
	forwarded := map[string]int{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		packet, err := nodewire.OpenRequest(hub, node.Public(), b, raw)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		clear(packet.Plaintext)
		mu.Lock()
		forwarded[hash(raw)]++
		mu.Unlock()
		reverse := packet.Route
		reverse.Direction = nodewire.DirectionResponse
		reverse.SenderKeyID, reverse.ReceiverKeyID = reverse.ReceiverKeyID, reverse.SenderKeyID
		reverse.SenderKeyVersion, reverse.ReceiverKeyVersion = reverse.ReceiverKeyVersion, reverse.SenderKeyVersion
		plain, _ := json.Marshal(map[string]any{"ok": false, "operation_id": reverse.OperationID, "sequence": reverse.Sequence, "error_code": "TARGET_NOT_AUTHORIZED"})
		response, err := nodewire.SealResponse(hub, node.Public(), b, reverse, plain)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(response)
	}))
	defer origin.Close()
	p := newFaultProxy(t, origin.URL)
	path := "/v2/node/control/rpc"
	client := &http.Client{Timeout: 3 * time.Second}
	count := func(raw []byte) int { mu.Lock(); defer mu.Unlock(); return forwarded[hash(raw)] }
	send := func(ctx context.Context, method, path string, raw []byte) error {
		req, err := http.NewRequestWithContext(ctx, method, p.server.URL+path, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		answer, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return context.Canceled
		}
		opened, err := nodewire.OpenResponse(node, hub.Public(), b, answer)
		if err == nil {
			clear(opened.Plaintext)
		}
		return err
	}
	waitAttempts := func(want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			p.mu.Lock()
			got := p.originalHold != nil && p.originalHold.attempts >= want
			p.mu.Unlock()
			if got {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("real TCP retry did not enter the original operation hold")
	}
	_, release := p.armMatch(path, http.MethodPost, route.Operation, "hold-original-before-forward", 1)
	defer release()
	reverse := route
	reverse.Direction = nodewire.DirectionResponse
	reverse.SenderKeyID, reverse.ReceiverKeyID = reverse.ReceiverKeyID, reverse.SenderKeyID
	reverse.SenderKeyVersion, reverse.ReceiverKeyVersion = reverse.ReceiverKeyVersion, reverse.SenderKeyVersion
	responseShape := must(nodewire.SealResponse(hub, node.Public(), b, reverse, []byte(`{"synthetic":"not-a-request"}`)))
	if err := send(context.Background(), http.MethodPost, path, responseShape); err == nil {
		t.Fatal("response packet was accepted as an original request")
	}
	p.mu.Lock()
	unclaimed := p.originalHold == nil && p.count == 1
	p.mu.Unlock()
	if !unclaimed {
		t.Fatal("response packet consumed the original-operation pin")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- send(ctx, http.MethodPost, path, original) }()
		waitAttempts(attempt)
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancelled original reached upstream")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled original HTTP did not finish")
		}
		if count(original) != 0 {
			t.Fatal("HTTP cancellation consumed the original operation barrier")
		}
	}
	// Different ID, sequence, ciphertext, operation, method and path cannot be
	// caught by the private original pin, even if they share this proxy.
	for _, mutation := range []func(*nodewire.Route){
		func(r *nodewire.Route) { r.OperationID = "op-synthetic-other" },
		func(r *nodewire.Route) { r.Sequence++ },
		func(r *nodewire.Route) { r.Operation = wire.OperationEndpointGroupsNodeDescribe },
	} {
		r := route
		mutation(&r)
		if err := send(context.Background(), http.MethodPost, path, seal(r)); err != nil {
			t.Fatal("unrelated authenticated packet was held")
		}
	}
	if bytes.Equal(original, changedCipher) {
		t.Fatal("synthetic ciphertext did not change")
	}
	if err := send(context.Background(), http.MethodPost, path, changedCipher); err != nil {
		t.Fatal("same ID with changed ciphertext was held")
	}
	if err := send(context.Background(), http.MethodGet, path, original); err != nil {
		t.Fatal("different method was held")
	}
	if err := send(context.Background(), http.MethodPost, "/synthetic-other-path", original); err != nil {
		t.Fatal("different path was held")
	}
	beforeRelease := count(original) // Only those two explicitly different routes.
	done := make(chan error, 1)
	go func() { done <- send(context.Background(), http.MethodPost, path, original) }()
	waitAttempts(3)
	if count(original) != beforeRelease {
		t.Fatal("same original retry escaped before explicit release")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal("released real original retry did not authenticate")
	}
	if err := send(context.Background(), http.MethodPost, path, original); err != nil {
		t.Fatal("released operation remained held")
	}
	if count(original) != beforeRelease+2 {
		t.Fatal("explicit release duplicated or lost a transport attempt")
	}
	// Rearming clears the old pin. Calling its release again must not clear
	// the newly captured gate or let its exact retry escape.
	_, releaseNew := p.armMatch(path, http.MethodPost, route.Operation, "hold-original-before-forward", 1)
	defer releaseNew()
	go func() { done <- send(context.Background(), http.MethodPost, path, changedCipher) }()
	waitAttempts(1)
	release()
	p.mu.Lock()
	stillPinned := p.originalHold != nil && p.originalHold.packetHash == hash(changedCipher)
	p.mu.Unlock()
	if !stillPinned {
		t.Fatal("old release cleared a rearmed operation")
	}
	releaseNew()
	if err := <-done; err != nil {
		t.Fatal("new exact gate did not release")
	}
	canceled := 0
	for _, ex := range p.snapshot() {
		if ex.RequestSHA256 == hash(original) && ex.FaultMode == "hold-original-before-forward" && !ex.Forwarded {
			canceled++
		}
	}
	if canceled != 2 {
		t.Fatal("cancelled exact attempts lack closed non-forwarded trace")
	}
}
