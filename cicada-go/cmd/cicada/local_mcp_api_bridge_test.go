package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		{"leave-group", "mcp_metadata_leave_group", "", http.MethodPost, "/v2/fabric/leave-group"},
		{"members", "mcp_metadata_members", "", http.MethodGet, "/v2/fabric/members?limit=200"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := localMCPMetadataRequest{Operation: test.operation, Query: test.query}
			if test.name == "members" {
				request.Limit = 200
			}
			method, path, body, err := request.route()
			if err != nil || method != test.wantMethod || path != test.wantPath {
				t.Fatalf("route = %q %q, err=%v", method, path, err)
			}
			if test.name == "find" || test.name == "resolve" || test.name == "inspect" {
				var input fabric.ResolveInput
				if err := decodeStrictJSON(body, &input); err != nil || input.Query != test.query {
					t.Fatalf("Directory body is invalid: %+v, %v", input, err)
				}
			} else if test.name == "leave-group" {
				if string(body) != `{"reason":""}` {
					t.Fatal("leave-group body was not fixed")
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
		{Operation: "mcp_metadata_leave_group", Reason: strings.Repeat("x", 1025)},
		{Operation: "mcp_metadata_leave_group", Reason: strings.Repeat("é", 513)},
		{Operation: "mcp_metadata_leave_group", Query: "unexpected"},
		{Operation: "mcp_metadata_members", Limit: 0},
		{Operation: "mcp_metadata_members", Limit: 201},
		{Operation: "mcp_metadata_members", Limit: 1, WorkspaceFilter: "unexpected"},
		{Operation: "mcp_metadata_whoami", Reason: "unexpected"},
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
		t.Fatal("members route without checked Node bridge did not fail closed")
	}
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/v2/fabric/leave-group", map[string]string{"reason": "synthetic"}},
		{http.MethodGet, "/v2/fabric/list", nil},
	} {
		if _, err := mcp.requestWithGroup(route.method, route.path, route.body, "CicadaSession cicada_session_synthetic", "group_synthetic"); err == nil || requests != 0 {
			t.Fatal("protected route fell back to unchecked HTTP")
		}
	}
}

func TestLocalMCPMembersFiltersRejectUnknownAndOversizedInputs(t *testing.T) {
	for _, path := range []string{
		"/v2/fabric/list", "/v2/fabric/members?path=/v2/fabric/leave",
		"/v2/fabric/members?limit=0", "/v2/fabric/members?limit=201",
		"/v2/fabric/members?limit=1&limit=2", "/v2/fabric/members?limit=bad",
		"/v2/fabric/members?status=" + strings.Repeat("x", 257),
		"/v2/fabric/members?node_id=" + strings.Repeat("x", 257),
		"/v2/fabric/members?harness=" + strings.Repeat("x", 257),
	} {
		t.Run(strconv.Itoa(len(path))+path[:min(len(path), 24)], func(t *testing.T) {
			var request localMCPMetadataRequest
			if request.membersQuery(path) == nil {
				t.Fatal("accepted unsupported members filter")
			}
		})
	}
	var request localMCPMetadataRequest
	if err := request.membersQuery("/v2/fabric/members?status=active&node_id=node_synthetic&harness=codex&limit=2"); err != nil {
		t.Fatal(err)
	}
	method, path, body, err := request.route()
	if err != nil || method != http.MethodGet || path != "/v2/fabric/members?harness=codex&limit=2&node_id=node_synthetic&status=active" || len(body) != 0 {
		t.Fatal("members filters did not round trip through fixed route")
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

func TestCheckedMCPMembersAndLeaveResultsAreScopedAndBounded(t *testing.T) {
	request := localMCPMetadataRequest{GroupID: "grp_synthetic", Limit: 1}
	for _, body := range []string{
		`{"endpoints":null}`, `{"endpoints":[] ,"secret":"unexpected"}`,
		`{"endpoints":[{"endpoint_id":"ep_one","group_id":"grp_foreign"}]}`,
		`{"endpoints":[{"endpoint_id":"ep_one","group_id":"grp_synthetic","native_session_id":"foreign"}]}`,
		`{"endpoints":[{"endpoint_id":"ep_one","group_id":"grp_synthetic"},{"endpoint_id":"ep_two","group_id":"grp_synthetic"}]}`,
		strings.Repeat("x", localMCPMetadataMaxBody+1),
	} {
		if _, err := checkedMCPMembersResult(request, json.RawMessage(body)); err == nil {
			t.Fatal("accepted invalid members result")
		}
	}
	if _, err := checkedMCPMembersResult(request, json.RawMessage(`{"endpoints":[{"endpoint_id":"ep_one","group_id":"grp_synthetic"}]}`)); err != nil {
		t.Fatal(err)
	}
	request.Limit = 2
	if _, err := checkedMCPMembersResult(request, json.RawMessage(`{"endpoints":[{"endpoint_id":"ep_one","group_id":"grp_synthetic"},{"endpoint_id":"ep_one","group_id":"grp_synthetic"}]}`)); err == nil {
		t.Fatal("accepted duplicate member")
	}
	for _, body := range []string{
		`{"status":"left","left_group_id":"grp_synthetic","remaining_group_id":""}`,
		`{"status":"left_group","left_group_id":"grp_foreign","remaining_group_id":""}`,
		`{"status":"left_group","left_group_id":"grp_synthetic","remaining_group_id":"grp_synthetic"}`,
		`{"status":"left_group","left_group_id":"grp_synthetic","remaining_group_id":"","token":"unexpected"}`,
	} {
		if _, err := checkedMCPLeaveGroupResult(request, json.RawMessage(body)); err == nil {
			t.Fatal("accepted invalid leave result")
		}
	}
	for _, remaining := range []string{"", "grp_second"} {
		body, _ := json.Marshal(map[string]string{"status": "left_group", "left_group_id": "grp_synthetic", "remaining_group_id": remaining})
		if _, err := checkedMCPLeaveGroupResult(request, body); err != nil {
			t.Fatal(err)
		}
	}
}
