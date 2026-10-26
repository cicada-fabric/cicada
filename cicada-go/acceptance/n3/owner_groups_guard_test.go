package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// The bounded Hub CLI deliberately omits Task/global routes. This additional
// task-owned listener uses the complete PRODUCTION Fabric router and the SAME
// original persistent Store, with Control absent. A 404/transport denial is not
// a permission test; positive whoami must first authenticate the actual actor.
func TestN3OwnerGroupsFabricRouterProcess(t *testing.T) {
	if os.Getenv("CICADA_N3_OWNER_GROUPS_FABRIC_CHILD") != "1" {
		t.Skip("owned production Fabric router child only")
	}
	root, marker := os.Getenv("CICADA_N3_FIXTURE"), os.Getenv("CICADA_N3_MARKER")
	var cfg fixtureConfig
	readJSON(t, filepath.Join(root, "synthetic-config.json"), &cfg)
	db := must(store.New(filepath.Join(root, "synthetic-hub", "cicada.sqlite3")))
	defer db.Close()
	setup := must(db.GetHubOwnerSetup())
	if setup == nil || setup.OwnerID != cfg.Material.OwnerID {
		t.Fatal("full Fabric router changed the original owned Hub identity")
	}
	service := must(fabric.NewService(db, setup.OwnerID, setup.OwnerID))
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	defer listener.Close()
	front := &http.Server{Handler: server.NewFabricHandler(service, ""), ReadHeaderTimeout: 5 * time.Second}
	writeJSON(t, marker, map[string]string{"origin": "http://" + listener.Addr().String(), "router": "PRODUCTION_FABRIC", "Control_inference": "DISABLED"})
	if err := front.Serve(listener); err != nil && err != http.ErrServerClosed {
		t.Fatal("owned production Fabric router stopped")
	}
}

type ownerGroupsFabricRouter struct {
	process *process
	origin  string
}

func startOwnerGroupsFabricRouter(t *testing.T, v *codexProductFixture) ownerGroupsFabricRouter {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "private-full-fabric-router.json")
	command := exec.Command(must(os.Executable()), "-test.run=^TestN3OwnerGroupsFabricRouterProcess$", "-test.timeout=30m")
	command.Env = append(os.Environ(), "CICADA_N3_OWNER_GROUPS_FABRIC_CHILD=1", "CICADA_N3_FIXTURE="+v.f.dir, "CICADA_N3_MARKER="+marker)
	process := startProcess(v.f.parent, command)
	awaitMarker(t, process, marker)
	var checkpoint map[string]string
	readJSON(t, marker, &checkpoint)
	loopback(t, checkpoint["origin"])
	if checkpoint["router"] != "PRODUCTION_FABRIC" || checkpoint["Control_inference"] != "DISABLED" {
		t.Fatal("full Fabric router lacks its explicit production/Control-free scope")
	}
	router := ownerGroupsFabricRouter{process: process, origin: checkpoint["origin"]}
	client := &http.Client{Timeout: 5 * time.Second}
	response := must(client.Get(router.origin + "/healthz"))
	defer response.Body.Close()
	var health struct {
		Status  string `json:"status"`
		Service string `json:"service"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&health) != nil || health.Status != "ok" || health.Service != "cicada-fabric" {
		t.Fatal("actual complete Fabric router did not start without Control")
	}
	return router
}

type ownerGroupsRESTCredential struct {
	token     string
	endpoint  string
	sid       string
	principal string
}

func originalOwnerGroupsRESTCredential(t *testing.T, v *codexProductFixture, identity ownerGroupsIdentity, selected string) ownerGroupsRESTCredential {
	t.Helper()
	paths := must(filepath.Glob(filepath.Join(filepath.Dir(v.mcpState), "scopes", "*.json")))
	var found []ownerGroupsRESTCredential
	for _, path := range paths {
		raw := readPrivate(t, path)
		var disk struct {
			Sessions []struct {
				Origin    string `json:"api_origin"`
				SID       string `json:"native_session_id"`
				Endpoint  string `json:"endpoint_id"`
				Node      string `json:"node_id"`
				Workspace string `json:"workspace"`
				Group     string `json:"group_id"`
				Binding   string `json:"binding_id"`
				Epoch     uint64 `json:"binding_epoch"`
				Token     string `json:"session_token"`
			} `json:"sessions"`
		}
		if json.Unmarshal(raw, &disk) != nil {
			clear(raw)
			t.Fatal("actual original MCP credential record is malformed")
		}
		clear(raw)
		for _, row := range disk.Sessions {
			if row.SID != identity.SID {
				continue
			}
			if row.Origin != v.f.cfg.Origin || row.Endpoint != identity.Endpoint || row.Node != identity.NodeID || row.Workspace != identity.Workspace ||
				row.Binding != identity.BindingID || row.Epoch != identity.BindingEpoch || row.Group != selected || row.Token == "" {
				t.Fatal("actual MCP credential changed its original actor or selected Group")
			}
			found = append(found, ownerGroupsRESTCredential{token: row.Token, endpoint: row.Endpoint, sid: row.SID, principal: identity.Principal})
		}
	}
	if len(found) != 1 {
		t.Fatal("original native SID lacks one exact protected MCP credential")
	}
	return found[0]
}

func (r ownerGroupsFabricRouter) request(t *testing.T, credential ownerGroupsRESTCredential, group, method, path string, body any) (int, []byte) {
	t.Helper()
	var encoded []byte
	if body != nil {
		encoded = must(json.Marshal(body))
		defer clear(encoded)
	}
	request := must(http.NewRequest(method, r.origin+path, bytes.NewReader(encoded)))
	request.Header.Set("Authorization", "CicadaSession "+credential.token)
	request.Header.Set("Cicada-Group-Scope", group)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response := must(client.Do(request))
	defer response.Body.Close()
	raw := must(io.ReadAll(io.LimitReader(response.Body, 128<<10+1)))
	if len(raw) > 128<<10 {
		clear(raw)
		t.Fatal("actual Fabric Guard response exceeded its private observation bound")
	}
	return response.StatusCode, raw
}

func (r ownerGroupsFabricRouter) requireActor(t *testing.T, credential ownerGroupsRESTCredential, group string) {
	t.Helper()
	status, raw := r.request(t, credential, group, http.MethodGet, "/v2/fabric/whoami", nil)
	defer clear(raw)
	var card fabric.NetworkCard
	if status != http.StatusOK || json.Unmarshal(raw, &card) != nil || card.EndpointID != credential.endpoint || card.GroupID != group || card.NativeSessionID != credential.sid {
		t.Fatal("actual Fabric router did not authenticate the original Endpoint and exact Group")
	}
}

func (r ownerGroupsFabricRouter) requireNetworkIdentity(t *testing.T, credential ownerGroupsRESTCredential, group, network string) {
	t.Helper()
	status, raw := r.request(t, credential, group, http.MethodGet, "/v2/fabric/networks/"+url.PathEscape(network)+"/whoami", nil)
	defer clear(raw)
	var identity map[string]string
	if status != http.StatusOK || json.Unmarshal(raw, &identity) != nil || len(identity) != 3 || identity["network_id"] != network || identity["endpoint_id"] != credential.endpoint || identity["principal_id"] != credential.principal {
		t.Fatal("actual managed token did not retain its exact Network self identity without business capabilities")
	}
}

func exerciseOwnerGroupsActorCeiling(t *testing.T, v *codexProductFixture, credential ownerGroupsRESTCredential, activeGroup, removedGroup, network string) {
	t.Helper()
	router := startOwnerGroupsFabricRouter(t, v)
	defer router.process.kill(t)
	originalNetwork := peerSharedAccessState(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"), network, credential.endpoint)
	router.requireActor(t, credential, activeGroup)
	router.requireNetworkIdentity(t, credential, activeGroup, network)
	status, raw := router.request(t, credential, removedGroup, http.MethodGet, "/v2/fabric/whoami", nil)
	clear(raw)
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatal("removed Group borrowed the surviving Group's actor authority")
	}
	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/v2/fabric/networks/" + url.PathEscape(network) + "/directory", nil},
		{http.MethodPost, "/v2/fabric/networks/" + url.PathEscape(network) + "/leave", map[string]string{"reason": "SYNTHETIC managed Group Actor has no Network business authority"}},
		{http.MethodGet, "/v2/fabric/tasks", nil},
		{http.MethodPost, "/v2/fabric/tasks/claim", fabric.TaskClaimInput{TaskID: "synthetic-owner-group-forbidden-task", ExpectedRevision: 1, IdempotencyKey: "synthetic-forbidden-claim", LeaseSeconds: 30}},
		{http.MethodPost, "/v2/fabric/tasks/release", fabric.TaskReleaseInput{TaskID: "synthetic-owner-group-forbidden-task", ExpectedRevision: 1, OwnerEpoch: 1}},
		{http.MethodPost, "/v2/fabric/tasks/renew", fabric.TaskRenewInput{TaskID: "synthetic-owner-group-forbidden-task", ExpectedRevision: 1, OwnerEpoch: 1, LeaseSeconds: 30}},
		{http.MethodPost, "/v2/fabric/leave-group", map[string]string{"reason": "SYNTHETIC managed Actor must not change Owner Group configuration"}},
		{http.MethodPost, "/v2/fabric/leave", map[string]string{"reason": "SYNTHETIC managed Actor must not globally leave the Endpoint"}},
	}
	for _, scenario := range cases {
		// Recheck current positive auth around each rejection. An expired token,
		// absent route or transport/authentication refusal is never this Guard.
		router.requireActor(t, credential, activeGroup)
		status, raw := router.request(t, credential, activeGroup, scenario.method, scenario.path, scenario.body)
		clear(raw)
		if status != http.StatusForbidden {
			t.Fatalf("actual five-right Actor Guard path=%s method=%s HTTP=%d expected=403", scenario.path, scenario.method, status)
		}
		router.requireActor(t, credential, activeGroup)
	}
	router.requireNetworkIdentity(t, credential, activeGroup, network)
	afterNetwork := peerSharedAccessState(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"), network, credential.endpoint)
	if afterNetwork != originalNetwork {
		t.Fatal("managed Group Actor changed shared Network authority through a forbidden route")
	}
}
