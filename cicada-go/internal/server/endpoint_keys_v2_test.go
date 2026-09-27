package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestEndpointKeyCandidateUsesSessionAndGroupBoundaryWithoutControl(t *testing.T) {
	persistence, err := store.New(filepath.Join(t.TempDir(), "hub.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreatePrincipal(store.Principal{ID: "owner", Kind: store.PrincipalKindHuman,
		OwnerID: "owner", TrustDomainID: "owner", Name: "owner", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	groupA, err := persistence.CreateGroup(store.Group{Name: "A", OwnerPrincipalID: owner.ID,
		TrustDomainID: "owner", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{Name: "B", OwnerPrincipalID: owner.ID,
		TrustDomainID: "owner", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(persistence, owner.ID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	a, err := service.Join(fabric.JoinInput{GroupID: groupA.ID, PrincipalName: "A1", EndpointName: "A1",
		Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := service.Join(fabric.JoinInput{GroupID: groupB.ID, PrincipalName: "B1", EndpointName: "B1",
		Harness: "codex", NativeSessionID: "native-b", NodeID: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(a.Endpoint.ID, a.Endpoint.PrincipalID,
		"node-a", a.BindingID, a.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewFabricHandler(service, "enroll-only-token")
	call := func(method, path, token string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(data))
		if token != "" {
			request.Header.Set("Authorization", "CicadaSession "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	body := map[string]any{"attestation": json.RawMessage(proof)}
	if result := call(http.MethodPost, "/v2/fabric/endpoint-keys", "", body); result.Code != http.StatusUnauthorized {
		t.Fatalf("missing session credential: %d", result.Code)
	}
	if result := call(http.MethodPost, "/v2/fabric/endpoint-keys", a.SessionToken,
		map[string]any{"attestation": json.RawMessage(proof), "owner_id": owner.ID}); result.Code != http.StatusBadRequest {
		t.Fatalf("body-supplied owner was accepted: %d", result.Code)
	}
	if result := call(http.MethodPost, "/v2/fabric/endpoint-keys", b.SessionToken, body); result.Code == http.StatusOK {
		t.Fatal("other bound Session registered A's key")
	}
	result := call(http.MethodPost, "/v2/fabric/endpoint-keys", a.SessionToken, body)
	if result.Code != http.StatusOK {
		t.Fatalf("candidate registration=%d body=%s", result.Code, result.Body.String())
	}
	if bytes.Contains(result.Body.Bytes(), []byte("private_identity")) || bytes.Contains(result.Body.Bytes(), []byte("kem_private")) {
		t.Fatal("candidate response leaked private-key fields")
	}
	if result := call(http.MethodGet, "/v2/fabric/endpoint-keys/"+a.Endpoint.ID, a.SessionToken, nil); result.Code != http.StatusOK {
		t.Fatalf("same-group candidate lookup=%d", result.Code)
	}
	if result := call(http.MethodGet, "/v2/fabric/endpoint-keys/"+a.Endpoint.ID, b.SessionToken, nil); result.Code != http.StatusNotFound {
		t.Fatalf("cross-group candidate lookup=%d", result.Code)
	}
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherProof, err := other.SignEndpointKeyAttestation(a.Endpoint.ID, a.Endpoint.PrincipalID,
		"node-a", a.BindingID, a.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if result := call(http.MethodPost, "/v2/fabric/endpoint-keys", a.SessionToken,
		map[string]any{"attestation": json.RawMessage(otherProof)}); result.Code != http.StatusConflict {
		t.Fatalf("silent key substitution status=%d body=%s", result.Code, result.Body.String())
	}
	rejoined, err := service.Join(fabric.JoinInput{GroupID: groupA.ID, PrincipalName: "A1", EndpointName: "A1",
		Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if rejoined.Endpoint.ID != a.Endpoint.ID || rejoined.BindingEpoch <= a.BindingEpoch {
		t.Fatal("rejoin did not retain Endpoint and rotate binding epoch")
	}
	if result := call(http.MethodGet, "/v2/fabric/endpoint-keys/"+a.Endpoint.ID, a.SessionToken, nil); result.Code != http.StatusUnauthorized {
		t.Fatalf("old session credential remained usable: %d", result.Code)
	}
	if result := call(http.MethodGet, "/v2/fabric/endpoint-keys/"+a.Endpoint.ID, rejoined.SessionToken, nil); result.Code != http.StatusNotFound {
		t.Fatalf("stale key attestation remained discoverable: %d", result.Code)
	}
	freshProof, err := identity.SignEndpointKeyAttestation(a.Endpoint.ID, a.Endpoint.PrincipalID,
		"node-a", rejoined.BindingID, rejoined.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if result := call(http.MethodPost, "/v2/fabric/endpoint-keys", rejoined.SessionToken,
		map[string]any{"attestation": json.RawMessage(freshProof)}); result.Code != http.StatusOK {
		t.Fatalf("same key failed to reattest new binding: %d body=%s", result.Code, result.Body.String())
	}
	if result := call(http.MethodGet, "/v2/fabric/endpoint-keys/"+a.Endpoint.ID, rejoined.SessionToken, nil); result.Code != http.StatusOK {
		t.Fatalf("reattested key unavailable: %d", result.Code)
	}
}
