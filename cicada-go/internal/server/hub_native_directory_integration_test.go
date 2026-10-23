package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
)

type nativeDirectoryExpected struct{ name, workspace, node string }

func assertNativeDirectoryStatus(t *testing.T, a *nativePairTCPActor, group, token string, status int) {
	t.Helper()
	for _, route := range []string{"members", "list"} {
		a.pairHTTP(t, http.MethodGet, "/v2/fabric/"+route, "CicadaSession "+token, group, nil, status)
	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		a.pairHTTP(t, http.MethodPost, "/v2/fabric/"+route, "CicadaSession "+token, group, fabric.ResolveInput{Query: "synthetic-private-peer"}, status)
	}
}

// Real Hub-Nodes-only TCP, current authentication and the existing Fabric
// directory projection. No synthetic SQL membership/grant bypass is used.
func assertNativeDirectoryHTTP(t *testing.T, a *nativePairTCPActor, group, token string, want map[string]nativeDirectoryExpected) {
	t.Helper()
	var caller fabric.NetworkCard
	if json.Unmarshal(a.pairHTTP(t, http.MethodGet, "/v2/fabric/whoami", "CicadaSession "+token, group, nil, http.StatusOK), &caller) != nil || caller.EndpointID == "" {
		t.Fatal("native directory caller is not authenticated")
	}
	for _, route := range []string{"members", "list"} {
		t.Run("directory-"+route, func(t *testing.T) {
			path := "/v2/fabric/" + route
			read := func(query string, count int) {
				t.Helper()
				raw := a.pairHTTP(t, http.MethodGet, path+query, "CicadaSession "+token, group, nil, http.StatusOK)
				var result struct {
					Endpoints []fabric.NetworkCard `json:"endpoints"`
				}
				if json.Unmarshal(raw, &result) != nil || len(result.Endpoints) != count || bytes.Contains(raw, []byte(token)) {
					t.Fatal("native directory count, shape or credential redaction failed")
				}
				seen := make(map[string]bool)
				for _, card := range result.Endpoints {
					expected, ok := want[card.EndpointID]
					if !ok || seen[card.EndpointID] || card.GroupID != group || card.Name != expected.name || card.Workspace != expected.workspace || card.NodeID != expected.node || card.NativeSessionID != "" {
						t.Fatal("native directory lost own name/cwd or exposed a foreign scope/native SID")
					}
					seen[card.EndpointID] = true
				}
			}
			read("", len(want))
			var node string
			for _, expected := range want {
				node = expected.node
				break
			}
			read("?node_id="+url.QueryEscape(node)+"&harness=codex&limit=1", 1)
			read("?node_id=synthetic-other-node", 0)
			a.pairHTTP(t, http.MethodGet, path, "", group, nil, http.StatusUnauthorized)
			a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, group, nil, http.StatusUnauthorized)
			a.pairHTTP(t, http.MethodGet, path, "CicadaSession "+token, "synthetic-other-group", nil, http.StatusForbidden)
			a.pairHTTP(t, http.MethodPost, path, "CicadaSession "+token, group, nil, http.StatusMethodNotAllowed)
			a.pairHTTP(t, http.MethodGet, path+"/extra", "CicadaSession "+token, group, nil, http.StatusNotFound)
		})
	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		t.Run("directory-"+route, func(t *testing.T) {
			path := "/v2/fabric/" + route
			for endpoint, expected := range want {
				// The legacy Pair resolver intentionally accepts only its other
				// exact peer, while WhoAmI remains the caller's identity endpoint.
				if endpoint == caller.EndpointID {
					continue
				}
				input := fabric.ResolveInput{Query: endpoint, NodeID: expected.node, Workspace: expected.workspace}
				raw := a.pairHTTP(t, http.MethodPost, path, "CicadaSession "+token, group, input, http.StatusOK)
				var card fabric.NetworkCard
				if json.Unmarshal(raw, &card) != nil || card.EndpointID != endpoint || card.GroupID != group || card.Name != expected.name || card.Workspace != expected.workspace || card.NodeID != expected.node || card.NativeSessionID != "" || bytes.Contains(raw, []byte(token)) {
					t.Fatal("native lookup alias lost its exact target or directory redaction")
				}
				input.Workspace = "/synthetic-other-workspace"
				a.pairHTTP(t, http.MethodPost, path, "CicadaSession "+token, group, input, http.StatusNotFound)
				input.Workspace, input.NodeID = expected.workspace, "synthetic-other-node"
				a.pairHTTP(t, http.MethodPost, path, "CicadaSession "+token, group, input, http.StatusNotFound)
			}
			input := fabric.ResolveInput{Query: "synthetic-peer"}
			a.pairHTTP(t, http.MethodPost, path, "", group, input, http.StatusUnauthorized)
			a.pairHTTP(t, http.MethodPost, path, "CicadaSession "+token, "synthetic-other-group", input, http.StatusForbidden)
			a.pairHTTP(t, http.MethodGet, path, "CicadaSession "+token, group, nil, http.StatusMethodNotAllowed)
			a.pairHTTP(t, http.MethodPost, path+"/extra", "CicadaSession "+token, group, input, http.StatusNotFound)
		})
	}
	var after fabric.NetworkCard
	if json.Unmarshal(a.pairHTTP(t, http.MethodGet, "/v2/fabric/whoami", "CicadaSession "+token, group, nil, http.StatusOK), &after) != nil || after.EndpointID != caller.EndpointID || after.NativeSessionID != caller.NativeSessionID || after.Workspace != caller.Workspace || after.NodeID != caller.NodeID || after.GroupID != caller.GroupID || after.BindingID != caller.BindingID || after.BindingEpoch != caller.BindingEpoch {
		t.Fatal("directory target filters changed the caller's current binding")
	}
}
