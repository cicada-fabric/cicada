package server

import (
	"net/http"
	"testing"
)

func TestHubNodesExistingNetworkRoutesAreExactAndAuthenticated(t *testing.T) {
	f := newHubNodesTCPFixture(t)
	for _, item := range []struct{ method, path string }{
		{http.MethodGet, "/v2/fabric/networks/net_synthetic/whoami"},
		{http.MethodGet, "/v2/fabric/networks/net_synthetic/directory"},
		{http.MethodPost, "/v2/fabric/networks/net_synthetic/resolve"},
		{http.MethodPost, "/v2/fabric/networks/net_synthetic/direct/peer-key"},
		{http.MethodPost, "/v2/fabric/node/networks/renew"},
		{http.MethodPost, "/v2/fabric/node/networks/direct/send"},
		{http.MethodPost, "/v2/fabric/node/networks/direct/ask"},
	} {
		if !hubNodesExistingNetworkRoute(item.path, item.method) {
			t.Fatal("required route absent", item.path)
		}
		status, _ := n3HTTP(t, f, item.method, item.path, "", []byte(`{}`))
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Fatal("route did not retain authentication", item.path, status)
		}
		if hubNodesExistingNetworkRoute(item.path+"/extra", item.method) || hubNodesExistingNetworkRoute(item.path, http.MethodDelete) {
			t.Fatal("broad route or verb match", item.path)
		}
	}
	for _, path := range []string{"/v2/fabric/node/networks/join", "/v2/fabric/networks/net_synthetic/invitations", "/v2/fabric/networks/net_synthetic/tasks/list", "/v2/fabric/networks/net_synthetic/broadcasts/preview", "/v2/fabric/networks/net_synthetic/direct/collaboration-peer-key", "/v2/fabric/node/networks/direct/collaboration-send", "/v2/fabric/networks/../directory", "/v2/fabric/networks//directory"} {
		if hubNodesExistingNetworkRoute(path, http.MethodPost) || hubNodesExistingNetworkRoute(path, http.MethodGet) {
			t.Fatal("unreviewed Network surface exposed", path)
		}
	}
}
