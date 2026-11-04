package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestMachinePublicNodeMetadataIsExactUnauthenticatedAndHubPinned(t *testing.T) {
	t.Setenv("CICADA_API_TOKEN", "SYNTHETIC_GLOBAL_CONTROL_DO_NOT_SEND")
	t.Setenv("CICADA_NODE_TOKEN", "SYNTHETIC_GLOBAL_NODE_DO_NOT_SEND")
	var callsA, callsB atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsB.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("public metadata borrowed credentials")
		}
		w.Write([]byte(`{"synthetic_hub":"B"}`))
	}))
	defer b.Close()
	var redirect atomic.Bool
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsA.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("public metadata borrowed credentials")
		}
		if redirect.Load() {
			http.Redirect(w, r, b.URL+"/v2/client/identity", http.StatusTemporaryRedirect)
			return
		}
		w.Write([]byte(`{"synthetic_hub":"A"}`))
	}))
	defer a.Close()
	ctxA := withMachineHubContext(context.Background(), machineHubContext{HubID: "synthetic-A", Origin: a.URL, NodeID: "synthetic-node", Token: "SYNTHETIC_NODE_A_DO_NOT_SEND", MultiHub: true})
	ctxB := withMachineHubContext(context.Background(), machineHubContext{HubID: "synthetic-B", Origin: b.URL, NodeID: "synthetic-node", Token: "SYNTHETIC_NODE_B_DO_NOT_SEND", MultiHub: true})
	paths := []string{wire.LocalDomainCapabilitiesPath, wire.OwnerEndpointGroupsCapabilitiesPath, "/v2/client/identity"}
	for _, path := range paths {
		for _, pair := range []struct {
			ctx         context.Context
			origin, hub string
		}{{ctxA, a.URL, "A"}, {ctxB, b.URL, "B"}} {
			var result struct {
				Hub string `json:"synthetic_hub"`
			}
			if err := machineAPIJSON(pair.ctx, pair.origin+path, http.MethodGet, nil, &result); err != nil || result.Hub != pair.hub {
				t.Fatal("pinned public metadata unavailable", err)
			}
		}
	}
	for _, input := range []struct {
		path, method string
		body         any
	}{{wire.LocalDomainCapabilitiesPath, http.MethodPost, nil}, {wire.LocalDomainCapabilitiesPath + "?query=1", http.MethodGet, nil}, {wire.OwnerEndpointGroupsCapabilitiesPath + "/other", http.MethodGet, nil}, {"/v2/client/identity", http.MethodGet, map[string]any{"synthetic": true}}, {"/v2/control/management", http.MethodGet, nil}, {"/v2/owner/local-domains", http.MethodGet, nil}} {
		before := callsA.Load()
		if machineAPIJSON(ctxA, a.URL+input.path, input.method, input.body, nil) == nil {
			t.Fatal("public GET allowance broadened to another operation")
		}
		if callsA.Load() != before {
			t.Fatal("forbidden Control request reached Hub")
		}
	}
	beforeB := callsB.Load()
	if machineAPIJSON(ctxA, b.URL+paths[0], http.MethodGet, nil, nil) == nil || callsB.Load() != beforeB {
		t.Fatal("public metadata escaped original Hub")
	}
	redirect.Store(true)
	if machineAPIJSON(ctxA, a.URL+paths[0], http.MethodGet, nil, nil) == nil || callsB.Load() != beforeB {
		t.Fatal("public metadata followed a cross-Hub redirect")
	}
	redirect.Store(false)
	// The same exact public reads also avoid legacy global auth outside the
	// manager. Ordinary non-public single-Hub Control behavior is untouched.
	for _, path := range paths {
		if err := machineAPIJSON(context.Background(), a.URL+path, http.MethodGet, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
}
