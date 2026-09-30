package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMachineHubContextPinsNodeTokenAndOrigin(t *testing.T) {
	var leaked atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer foreign.Close()
	var seen atomic.Int32
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
			return
		}
		if r.Header.Get("Authorization") != "CicadaNode node-token-a" {
			t.Error("wrong Hub token sent")
		}
		seen.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer home.Close()
	t.Setenv("CICADA_NODE_TOKEN", "stale-global-node-token")
	ctx := withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-a", Origin: home.URL, NodeID: "node-a", Token: "node-token-a"})
	if err := machineAPIJSON(ctx, home.URL+"/v2/relay/nodes/node-a/heartbeat", http.MethodPost, map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != 1 {
		t.Fatal("pinned Hub did not receive authenticated request")
	}
	if err := machineAPIJSON(ctx, foreign.URL+"/v2/relay/nodes/node-a/heartbeat", http.MethodPost, map[string]any{}, nil); err == nil || !strings.Contains(err.Error(), "pinned Hub") {
		t.Fatalf("foreign origin accepted: %v", err)
	}
	if leaked.Load() != 0 {
		t.Fatal("token was sent to another Hub")
	}
	// The shared Node HTTP client rejects redirects even when the first request
	// used an explicitly pinned origin.
	if err := machineAPIJSON(ctx, home.URL+"/v2/relay/nodes/node-a/redirect", http.MethodPost, map[string]any{}, nil); err == nil {
		t.Fatal("Node credential followed a redirect")
	}
	if leaked.Load() != 0 {
		t.Fatal("redirect leaked the token")
	}
}

func TestMachineHubRegistryRequiresExplicitDistinctHubScopes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hubs.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":1,"hubs":[{"hub_id":"hub-a","control_url":"https://a.example","node_id":"node"},{"hub_id":"hub-b","control_url":"https://b.example","node_id":"node"}]}`)
	entries, err := loadMachineHubConfig(path)
	if err != nil || len(entries) != 2 {
		t.Fatalf("valid multi-Hub registry: %v %#v", err, entries)
	}
	if machineHubStateDir(dir, entries[0]) == machineHubStateDir(dir, entries[1]) {
		t.Fatal("two Hubs share state")
	}
	write(`{"version":1,"hubs":[{"hub_id":"hub-a","control_url":"https://a.example","node_id":"node"},{"hub_id":"hub-b","control_url":"https://a.example","node_id":"node"}]}`)
	if _, err := loadMachineHubConfig(path); err == nil {
		t.Fatal("duplicate Hub origin accepted")
	}
	write(`{"version":1,"hubs":[{"hub_id":"hub-a","control_url":"https://a.example","node_id":"node"},{"hub_id":"hub-a","control_url":"https://b.example","node_id":"node"}]}`)
	if _, err := loadMachineHubConfig(path); err == nil {
		t.Fatal("duplicate Hub ID accepted")
	}
}

func TestMachineHubWorkerFailureDoesNotStopOtherHub(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- runMachineHubWorkers(context.Background(), []machineHubConfig{
			{HubID: "revoked"}, {HubID: "healthy"}}, func(ctx context.Context, entry machineHubConfig) error {
			if entry.HubID == "revoked" {
				return context.Canceled
			}
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("healthy Hub did not start")
	}
	select {
	case err := <-finished:
		t.Fatalf("revoked Hub stopped healthy Hub: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("revoked Hub failure was hidden")
		}
	case <-time.After(time.Second):
		t.Fatal("healthy Hub did not finish")
	}
}

func TestMachineTwoHubHTTPNodeCredentialsStayIndependent(t *testing.T) {
	var aCount, bCount atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "CicadaNode token-a" {
			t.Error("Hub A received another credential")
		}
		aCount.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "CicadaNode token-b" {
			t.Error("Hub B received another credential")
		}
		bCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer b.Close()
	t.Setenv("CICADA_NODE_TOKEN", "stale-global-token")
	ctxA := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-a", Origin: a.URL,
		NodeID: "node", Token: "token-a", MultiHub: true})
	ctxB := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-b", Origin: b.URL,
		NodeID: "node", Token: "token-b", MultiHub: true})
	aErr := machineAPIJSON(ctxA, a.URL+"/v2/relay/nodes/node/heartbeat", http.MethodPost, map[string]any{}, nil)
	if !machineAPIHasStatus(aErr, http.StatusForbidden) {
		t.Fatalf("revoked Hub A accepted: %v", aErr)
	}
	if err := machineAPIJSON(ctxB, b.URL+"/v2/relay/nodes/node/heartbeat", http.MethodPost, map[string]any{}, nil); err != nil {
		t.Fatalf("Hub A revocation blocked Hub B: %v", err)
	}
	if aCount.Load() != 1 || bCount.Load() != 1 {
		t.Fatalf("requests crossed Hub boundary: %d %d", aCount.Load(), bCount.Load())
	}
	if err := machineAPIJSON(ctxB, b.URL+"/v2/control/management", http.MethodPost, map[string]any{}, nil); err == nil {
		t.Fatal("multi-Hub mode used global Control management credential")
	}
}
