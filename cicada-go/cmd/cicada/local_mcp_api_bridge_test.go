package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fabric "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestLocalMCPMetadataRoutesAreFixedAndBounded(t *testing.T) {
	tests := []struct {
		name, operation, query, wantMethod, wantPath string
	}{
		{"whoami", "mcp_metadata_whoami", "", http.MethodGet, "/v2/fabric/whoami"},
		{"find", "mcp_metadata_find", "ep_synthetic", http.MethodPost, "/v2/fabric/find"},
		{"resolve", "mcp_metadata_resolve", "ep_synthetic", http.MethodPost, "/v2/fabric/resolve"},
		{"inspect", "mcp_metadata_inspect", "ep_synthetic", http.MethodPost, "/v2/fabric/inspect"},
		{"heartbeat", "mcp_metadata_heartbeat", "", http.MethodPost, "/v2/fabric/heartbeat"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := localMCPMetadataRequest{Operation: test.operation, Query: test.query}
			method, path, body, err := request.route()
			if err != nil || method != test.wantMethod || path != test.wantPath {
				t.Fatalf("route = %q %q, err=%v", method, path, err)
			}
			if test.name == "find" || test.name == "resolve" || test.name == "inspect" {
				var input fabric.ResolveInput
				if err := decodeStrictJSON(body, &input); err != nil || input.Query != test.query {
					t.Fatalf("Directory body is invalid: %+v, %v", input, err)
				}
			} else if len(body) != 0 {
				t.Fatal("body-free route carried request data")
			}
		})
	}
	for _, request := range []localMCPMetadataRequest{
		{Operation: "mcp_metadata_unknown"},
		{Operation: "mcp_metadata_whoami", Query: "unexpected"},
		{Operation: "mcp_metadata_find", Query: strings.Repeat("x", 4097)},
	} {
		if _, _, _, err := request.route(); err == nil {
			t.Fatalf("accepted invalid metadata request operation=%q", request.Operation)
		}
	}
}

func TestSelectedPQMetadataBridgeNeverFallsBackToMCPHTTP(t *testing.T) {
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", "")
	var requests int
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer hub.Close()
	mcp := newMCPServer(hub.URL, "ep_synthetic", "")
	mcp.pqtlsSelected = true
	mcp.hubStateDir = t.TempDir()
	defer close(mcp.stop)
	trusted := mcpTrustedContext{Harness: "codex", NativeSessionID: "thread_synthetic", NodeID: "node_synthetic", Workspace: t.TempDir()}
	public := mcpPublicJoinResult{Endpoint: storeEndpointForBridgeTest("ep_synthetic", "group_synthetic"),
		BindingID: "binding_synthetic", BindingEpoch: 1}
	mcp.setSession("cicada_session_synthetic", "ep_synthetic", "group_synthetic", trusted, "scope", public)
	_, err := mcp.apiForGroup(http.MethodGet, "/v2/fabric/whoami", nil, "group_synthetic")
	if err == nil {
		t.Fatal("selected PQ metadata unexpectedly succeeded without the local Node bridge")
	}
	if requests != 0 {
		t.Fatalf("selected PQ metadata fell back to HTTP: %d requests", requests)
	}
	_, err = mcp.requestWithGroup(http.MethodGet, "/v2/fabric/members", nil,
		"CicadaSession cicada_session_synthetic", "group_synthetic")
	if err == nil || requests != 0 {
		t.Fatal("unsupported protected route did not fail closed")
	}
}

func TestStandardMCPMetadataPathRemainsCompatible(t *testing.T) {
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", "")
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/fabric/whoami" {
			t.Errorf("unexpected compatibility request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"endpoint_id":"ep_standard"}`))
	}))
	defer hub.Close()
	mcp := newMCPServer(hub.URL, "ep_standard", "")
	defer close(mcp.stop)
	result, err := mcp.requestWithGroup(http.MethodGet, "/v2/fabric/whoami", nil,
		"CicadaSession synthetic-standard", "group_standard")
	if err != nil {
		t.Fatal("standard MCP request lost its existing HTTP path", err)
	}
	encoded, _ := json.Marshal(result)
	if string(encoded) != `{"endpoint_id":"ep_standard"}` {
		t.Fatalf("unexpected standard MCP response %s", encoded)
	}
}

func TestPQMetadataErrorFiltersCredentialEcho(t *testing.T) {
	const token = "cicada_session_synthetic_error_secret"
	message := safePQMetadataHTTPError([]byte(`{"error":"failure `+token+`"}`), token)
	if strings.Contains(message, token) || strings.Contains(message, fabric.HashSessionCredential(token)) {
		t.Fatal("protected MCP error sanitizer exposed a credential or credential hash")
	}
}

func storeEndpointForBridgeTest(endpointID, groupID string) store.Endpoint {
	return store.Endpoint{ID: endpointID, GroupID: groupID, PrincipalID: "principal_synthetic", Owner: "owner_synthetic"}
}
