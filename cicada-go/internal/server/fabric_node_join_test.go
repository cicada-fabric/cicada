package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func newGuestNodeJoinFixture(t *testing.T) (*fabricpkg.Service, *store.Store, *store.Group, string, *store.NodeDeviceBinding) {
	t.Helper()
	persistence, err := store.New(filepath.Join(t.TempDir(), "guest-node-join.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })

	for _, principal := range []store.Principal{
		{ID: "manager", Kind: store.PrincipalKindHuman, OwnerID: "manager", TrustDomainID: "manager-domain", Name: "manager", Status: store.PrincipalStatusActive},
		{ID: "owner", Kind: store.PrincipalKindHuman, OwnerID: "owner", TrustDomainID: "guest-domain", Name: "guest owner", Status: store.PrincipalStatusActive},
		{ID: "other-owner", Kind: store.PrincipalKindHuman, OwnerID: "other-owner", TrustDomainID: "other-domain", Name: "other owner", Status: store.PrincipalStatusActive},
	} {
		if _, err := persistence.CreatePrincipal(principal); err != nil {
			t.Fatal(err)
		}
	}
	group, err := persistence.CreateGroup(store.Group{
		Name: "guest group", OwnerPrincipalID: "owner", TrustDomainID: "guest-domain",
		State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateGroup(store.Group{
		Name: "other group", OwnerPrincipalID: "other-owner", TrustDomainID: "other-domain",
		State: store.GroupStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, "manager", "manager-domain")
	if err != nil {
		t.Fatal(err)
	}
	token, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	binding := bindRelayNodeTestCredential(t, persistence, "guest-node", digest)
	return service, persistence, group, token, binding
}

func TestGuestOwnerNodeJoinDerivesOwnerAndNodeAndIsIdempotent(t *testing.T) {
	service, persistence, group, nodeToken, _ := newGuestNodeJoinFixture(t)
	handler := NewFabricHandler(service, "management-token")
	body, err := json.Marshal(map[string]any{
		"group_id": group.ID, "endpoint_name": "benchmark", "harness": "codex",
		"native_session_id": "native-guest-1", "workspace": "/work/bench",
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func() (*httptest.ResponseRecorder, fabricpkg.JoinResult) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v2/fabric/node/join", bytes.NewReader(body))
		request.Header.Set("Authorization", "CicadaNode "+nodeToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var result fabricpkg.JoinResult
		if response.Code == http.StatusCreated {
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return response, result
	}

	firstResponse, first := call()
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("guest Node join status=%d body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	if first.Endpoint.Owner != "owner" || first.Endpoint.MachineID != "guest-node" ||
		first.Endpoint.PrincipalID == "" || first.BindingID == "" || first.SessionToken == "" {
		t.Fatalf("join did not derive identity from Node binding: %#v", first)
	}
	principal, err := persistence.GetPrincipal(first.Endpoint.PrincipalID)
	if err != nil || principal.OwnerID != "owner" || principal.TrustDomainID != "guest-domain" {
		t.Fatalf("joined Agent Principal has wrong owner/domain: principal=%#v err=%v", principal, err)
	}
	binding, err := persistence.GetActiveSessionBinding(first.Endpoint.ID)
	if err != nil || binding.NodeID != "guest-node" || binding.PrincipalID != first.Endpoint.PrincipalID {
		t.Fatalf("SessionBinding did not retain authenticated Node scope: binding=%#v err=%v", binding, err)
	}

	secondResponse, second := call()
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("rejoin status=%d body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	if second.Endpoint.ID != first.Endpoint.ID || second.Endpoint.PrincipalID != first.Endpoint.PrincipalID ||
		second.BindingID != first.BindingID || second.BindingEpoch <= first.BindingEpoch || !second.Reused {
		t.Fatalf("rejoin changed stable identity or failed to fence prior binding: first=%#v second=%#v", first, second)
	}
}

func TestGuestOwnerNodeJoinRejectsForeignGroupAndForgedIdentityFields(t *testing.T) {
	service, persistence, guestGroup, nodeToken, _ := newGuestNodeJoinFixture(t)
	handler := NewFabricHandler(service, "")
	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v2/fabric/node/join", bytes.NewBufferString(body))
		request.Header.Set("Authorization", "CicadaNode "+nodeToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	foreignGroup, err := persistence.ListGroups(store.GroupFilter{Owner: "other-owner", Limit: 10})
	if err != nil || len(foreignGroup) != 1 {
		t.Fatalf("fixture other-owner Group missing: groups=%#v err=%v", foreignGroup, err)
	}
	foreign := call(`{"group_id":"` + foreignGroup[0].ID + `","harness":"codex","native_session_id":"native-forged"}`)
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("Node joined another owner's Group: status=%d body=%s", foreign.Code, foreign.Body.String())
	}
	spoofed := call(`{"group_id":"` + guestGroup.ID + `","harness":"codex","native_session_id":"native-forged","owner_id":"manager","node_id":"attacker-node"}`)
	if spoofed.Code != http.StatusBadRequest {
		t.Fatalf("request-supplied owner/node fields were not rejected: status=%d body=%s", spoofed.Code, spoofed.Body.String())
	}
	if endpoint, err := persistence.GetEndpointV2BySession("codex", "native-forged"); err != nil || endpoint != nil {
		t.Fatalf("rejected requests created an Endpoint: endpoint=%#v err=%v", endpoint, err)
	}
}

func TestGuestOwnerNodeJoinRejectsWrongAndRevokedCredential(t *testing.T) {
	service, persistence, group, nodeToken, binding := newGuestNodeJoinFixture(t)
	handler := NewFabricHandler(service, "")
	join := func(token string) (int, fabricpkg.JoinResult) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"group_id": group.ID, "harness": "codex", "native_session_id": "native-node-auth-test",
		})
		request := httptest.NewRequest(http.MethodPost, "/v2/fabric/node/join", bytes.NewReader(body))
		request.Header.Set("Authorization", "CicadaNode "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var result fabricpkg.JoinResult
		if response.Code == http.StatusCreated {
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return response.Code, result
	}
	wrongToken, _, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := join(wrongToken); status != http.StatusUnauthorized {
		t.Fatalf("wrong Node credential status=%d, want unauthorized", status)
	}
	status, joined := join(nodeToken)
	if status != http.StatusCreated {
		t.Fatalf("bound Node could not join before revocation: status=%d", status)
	}
	if _, err := service.Authenticate(joined.SessionToken); err != nil {
		t.Fatalf("fresh guest Session cannot authenticate: %v", err)
	}
	if _, err := persistence.RevokeNodeDeviceBinding("owner", binding.ID, binding.Version); err != nil {
		t.Fatal(err)
	}
	if status, _ := join(nodeToken); status != http.StatusUnauthorized {
		t.Fatalf("revoked Node credential status=%d, want unauthorized", status)
	}
	if _, err := service.Authenticate(joined.SessionToken); err == nil {
		t.Fatal("guest Fabric Session survived Node owner-binding revocation")
	}
}

func TestGuestOwnerNodeJoinCannotRebindSessionAcrossNode(t *testing.T) {
	service, persistence, group, firstToken, _ := newGuestNodeJoinFixture(t)
	secondToken, secondDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "guest-node-2", secondDigest)
	join := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"group_id": group.ID, "harness": "codex", "native_session_id": "same-native-session",
		})
		request := httptest.NewRequest(http.MethodPost, "/v2/fabric/node/join", bytes.NewReader(body))
		request.Header.Set("Authorization", "CicadaNode "+token)
		response := httptest.NewRecorder()
		NewFabricHandler(service, "").ServeHTTP(response, request)
		return response
	}
	first := join(firstToken)
	if first.Code != http.StatusCreated {
		t.Fatalf("first Node join status=%d body=%s", first.Code, first.Body.String())
	}
	second := join(secondToken)
	if second.Code != http.StatusForbidden {
		t.Fatalf("second Node rebound the same native Session: status=%d body=%s", second.Code, second.Body.String())
	}
	endpoint, err := persistence.GetEndpointV2BySession("codex", "same-native-session")
	if err != nil || endpoint == nil || endpoint.MachineID != "guest-node" || endpoint.Owner != "owner" {
		t.Fatalf("rejected cross-Node join mutated existing Endpoint: endpoint=%#v err=%v", endpoint, err)
	}
}
