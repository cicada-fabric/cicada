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
}

// Real Hub-Nodes-only TCP, current authentication and the existing Fabric
// directory projection. No synthetic SQL membership/grant bypass is used.
func assertNativeDirectoryHTTP(t *testing.T, a *nativePairTCPActor, group, token string, want map[string]nativeDirectoryExpected) {
	t.Helper()
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
}
