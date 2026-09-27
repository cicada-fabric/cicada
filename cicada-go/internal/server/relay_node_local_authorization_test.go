package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestRelayNodeLocalAuthorizationRequiresNodeAndSessionHeadersAndStrictBody(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	nodeToken, nodeDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-local", nodeDigest)
	source, err := service.Join(fabricpkg.JoinInput{
		GroupID: group.ID, PrincipalName: "source", EndpointName: "source", Harness: "codex",
		NativeSessionID: "native-source-local", NodeID: "node-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.Join(fabricpkg.JoinInput{
		GroupID: group.ID, PrincipalName: "target", EndpointName: "target", Harness: "codex",
		NativeSessionID: "native-target-local", NodeID: "node-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	registerLocalAuthorizationEndpointKey(t, persistence, source.Endpoint.ID, source.BindingID, source.BindingEpoch)
	registerLocalAuthorizationEndpointKey(t, persistence, target.Endpoint.ID, target.BindingID, target.BindingEpoch)
	handler := NewFabricHandler(service, "management-token")
	path := "/v2/relay/nodes/node-local/local/authorize"
	call := func(nodePath, nodeAuthorization, sessionToken string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, nodePath, bytes.NewReader(body))
		if nodeAuthorization != "" {
			request.Header.Set("Authorization", nodeAuthorization)
		}
		if sessionToken != "" {
			request.Header.Set("X-Cicada-Session", sessionToken)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	body, err := json.Marshal(fabricpkg.LocalDeliveryAuthorizationInput{
		GroupID: group.ID, Target: "target", Action: "message.ask",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response := call(path, "Bearer "+nodeToken, source.SessionToken, body); response.Code != http.StatusUnauthorized {
		t.Fatalf("non-Node bearer read local authorization: %d %s", response.Code, response.Body.String())
	}
	if response := call("/v2/relay/nodes/other-node/local/authorize", "CicadaNode "+nodeToken, source.SessionToken, body); response.Code != http.StatusForbidden {
		t.Fatalf("Node credential crossed path Node scope: %d %s", response.Code, response.Body.String())
	}
	if response := call(path, "CicadaNode "+nodeToken, "", body); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing current Session header authorized local route: %d", response.Code)
	}
	forged := []byte(`{"group_id":"` + group.ID + `","target":"target","action":"message.ask","sender":"ep_forged","role":"owner","user_approved":true}`)
	if response := call(path, "CicadaNode "+nodeToken, source.SessionToken, forged); response.Code != http.StatusBadRequest {
		t.Fatalf("forged sender/role/approval fields were accepted: %d %s", response.Code, response.Body.String())
	}

	response := call(path, "CicadaNode "+nodeToken, source.SessionToken, body)
	if response.Code != http.StatusOK {
		t.Fatalf("valid local authorization failed: %d %s", response.Code, response.Body.String())
	}
	var authorization fabricpkg.LocalDeliveryAuthorization
	if err := json.Unmarshal(response.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	if authorization.Source.EndpointID != source.Endpoint.ID || authorization.Source.NativeSessionID != "" ||
		authorization.Target.EndpointID != target.Endpoint.ID || authorization.Target.NativeSessionID != target.Endpoint.NativeSessionID ||
		authorization.TargetKey.KeyID == "" || len(authorization.TargetKey.Proof) == 0 ||
		bytes.Contains(response.Body.Bytes(), []byte(source.SessionToken)) || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("route metadata crossed the intended bounds: %#v headers=%v", authorization, response.Header())
	}
}

func TestRelayNodeLocalRevalidationUsesOnlyExactCurrentRoute(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	nodeToken, nodeDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-local", nodeDigest)
	source, err := service.Join(fabricpkg.JoinInput{
		GroupID: group.ID, PrincipalName: "source", EndpointName: "source", Harness: "codex",
		NativeSessionID: "native-source-revalidate", NodeID: "node-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.Join(fabricpkg.JoinInput{
		GroupID: group.ID, PrincipalName: "target", EndpointName: "target", Harness: "codex",
		NativeSessionID: "native-target-revalidate", NodeID: "node-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	registerLocalAuthorizationEndpointKey(t, persistence, source.Endpoint.ID, source.BindingID, source.BindingEpoch)
	registerLocalAuthorizationEndpointKey(t, persistence, target.Endpoint.ID, target.BindingID, target.BindingEpoch)
	handler := NewFabricHandler(service, "management-token")
	path := "/v2/relay/nodes/node-local/local/revalidate"
	input := fabricpkg.LocalDeliveryRevalidationInput{
		GroupID: group.ID, SourceEndpointID: source.Endpoint.ID,
		SourceBindingID: source.BindingID, SourceBindingEpoch: source.BindingEpoch,
		TargetEndpointID: target.Endpoint.ID, Action: "message.ask",
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	call := func(payload []byte) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
		request.Header.Set("Authorization", "CicadaNode "+nodeToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := call(body)
	if response.Code != http.StatusOK {
		t.Fatalf("Node could not revalidate exact persisted route: %d %s", response.Code, response.Body.String())
	}
	var authorization fabricpkg.LocalDeliveryAuthorization
	if err := json.Unmarshal(response.Body.Bytes(), &authorization); err != nil || authorization.Target.NativeSessionID != target.Endpoint.NativeSessionID {
		t.Fatalf("revalidation did not return the current shared authorization DTO: %#v err=%v", authorization, err)
	}
	forged := []byte(`{"group_id":"` + group.ID + `","source_endpoint_id":"` + source.Endpoint.ID + `","source_binding_id":"` + source.BindingID + `","source_binding_epoch":1,"target_endpoint_id":"` + target.Endpoint.ID + `","action":"message.ask","sender":"forged","approved":true}`)
	if response := call(forged); response.Code != http.StatusBadRequest {
		t.Fatalf("revalidation accepted forged route authorization fields: %d %s", response.Code, response.Body.String())
	}
	if _, err := persistence.RevokeMembershipForPrincipalGroup(target.Endpoint.PrincipalID, group.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if response := call(body); response.Code != http.StatusNotFound {
		t.Fatalf("revoked target membership revalidated: %d %s", response.Code, response.Body.String())
	}
}

func TestRelayNodeLocalAuthorizationRejectsAmbiguousAndUnjoinedTargets(t *testing.T) {
	service, persistence, group := newRelayNodeTestService(t)
	nodeToken, nodeDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-local", nodeDigest)
	source, err := service.Join(fabricpkg.JoinInput{
		GroupID: group.ID, PrincipalName: "source", EndpointName: "source", Harness: "codex",
		NativeSessionID: "native-source-target-resolution", NodeID: "node-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, targetName := range []string{"target", "target"} {
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: group.ID, PrincipalName: targetName, EndpointName: targetName, Harness: "codex",
			NativeSessionID: "native-" + targetName + "-" + store.NewID("test"), NodeID: "node-local",
		})
		if err != nil {
			t.Fatal(err)
		}
		registerLocalAuthorizationEndpointKey(t, persistence, joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch)
	}
	if _, err := persistence.CreateGroup(store.Group{
		ID: "other-local-group", Name: "other", OwnerPrincipalID: "owner", TrustDomainID: "domain", State: store.GroupStateActive,
	}); err != nil {
		t.Fatal(err)
	}
	unjoined, err := service.Join(fabricpkg.JoinInput{
		GroupID: "other-local-group", PrincipalName: "unjoined", EndpointName: "unjoined", Harness: "codex",
		NativeSessionID: "native-unjoined-local", NodeID: "node-local",
	})
	if err != nil {
		t.Fatal(err)
	}
	registerLocalAuthorizationEndpointKey(t, persistence, source.Endpoint.ID, source.BindingID, source.BindingEpoch)
	handler := NewFabricHandler(service, "management-token")
	call := func(targetQuery string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(fabricpkg.LocalDeliveryAuthorizationInput{
			GroupID: group.ID, Target: targetQuery, Action: "message.send",
		})
		request := httptest.NewRequest(http.MethodPost, "/v2/relay/nodes/node-local/local/authorize", bytes.NewReader(body))
		request.Header.Set("Authorization", "CicadaNode "+nodeToken)
		request.Header.Set("X-Cicada-Session", source.SessionToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := call("target"); response.Code != http.StatusConflict {
		t.Fatalf("ambiguous target alias was guessed: %d %s", response.Code, response.Body.String())
	}
	if response := call(unjoined.Endpoint.ID); response.Code != http.StatusNotFound {
		t.Fatalf("unjoined target was disclosed/routed: %d %s", response.Code, response.Body.String())
	}
}

func registerLocalAuthorizationEndpointKey(t *testing.T, persistence *store.Store,
	endpointID, bindingID string, epoch uint64) {
	t.Helper()
	binding, err := persistence.GetSessionBinding(bindingID)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(endpointID, binding.PrincipalID,
		binding.NodeID, binding.ID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterEndpointKeyCandidate(endpointID, binding.PrincipalID, binding.ID, epoch, proof); err != nil {
		t.Fatal(err)
	}
}
