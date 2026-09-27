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

func TestFabricJoinAndHistoricalReadsWorkWithoutControlBusinessService(t *testing.T) {
	persistence, err := store.New(filepath.Join(t.TempDir(), "fabric.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: "owner", Kind: store.PrincipalKindHuman, OwnerID: "owner",
		TrustDomainID: "domain", Name: "owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		Name: "group-a", OwnerPrincipalID: owner.ID, TrustDomainID: "domain",
		State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, owner.ID, "domain")
	if err != nil {
		t.Fatal(err)
	}
	// This handler has no *control.Control at all. Any accidental call into
	// planner/reporting/worker management would therefore panic or fail.
	handler := NewFabricHandler(service, "")
	joinBody := map[string]any{
		"group_id": group.ID, "principal_id": "forged-principal",
		"principal_name": "a", "endpoint_name": "a", "harness": "codex",
		"native_session_id": "native-a", "node_id": "node-a",
	}
	encoded, _ := json.Marshal(joinBody)
	join := httptest.NewRequest(http.MethodPost, "/v2/fabric/join", bytes.NewReader(encoded))
	join.Header.Set("Content-Type", "application/json")
	joinedResponse := httptest.NewRecorder()
	handler.ServeHTTP(joinedResponse, join)
	if joinedResponse.Code != http.StatusCreated {
		t.Fatalf("join status=%d body=%s", joinedResponse.Code, joinedResponse.Body.String())
	}
	var joined fabricpkg.JoinResult
	if err := json.Unmarshal(joinedResponse.Body.Bytes(), &joined); err != nil {
		t.Fatal(err)
	}
	if joined.Endpoint.PrincipalID == "forged-principal" || joined.SessionToken == "" {
		t.Fatalf("join trusted forged identity or omitted credential: %#v", joined)
	}

	whoami := httptest.NewRequest(http.MethodGet, "/v2/fabric/whoami", nil)
	whoami.Header.Set("Authorization", "CicadaSession "+joined.SessionToken)
	whoamiResponse := httptest.NewRecorder()
	handler.ServeHTTP(whoamiResponse, whoami)
	if whoamiResponse.Code != http.StatusOK {
		t.Fatalf("whoami status=%d body=%s", whoamiResponse.Code, whoamiResponse.Body.String())
	}

	wrongScheme := httptest.NewRequest(http.MethodGet, "/v2/fabric/whoami", nil)
	wrongScheme.Header.Set("Authorization", "Bearer "+joined.SessionToken)
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrongScheme)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("global bearer impersonated a session: status=%d body=%s", wrongResponse.Code, wrongResponse.Body.String())
	}

	joinBody["principal_name"] = "b"
	joinBody["endpoint_name"] = "benchmark"
	joinBody["native_session_id"] = "native-b"
	joinBody["node_id"] = "node-b"
	encoded, _ = json.Marshal(joinBody)
	joinB := httptest.NewRequest(http.MethodPost, "/v2/fabric/join", bytes.NewReader(encoded))
	joinB.Header.Set("Content-Type", "application/json")
	joinedBResponse := httptest.NewRecorder()
	handler.ServeHTTP(joinedBResponse, joinB)
	if joinedBResponse.Code != http.StatusCreated {
		t.Fatalf("join B status=%d body=%s", joinedBResponse.Code, joinedBResponse.Body.String())
	}
	var joinedB fabricpkg.JoinResult
	if err := json.Unmarshal(joinedBResponse.Body.Bytes(), &joinedB); err != nil {
		t.Fatal(err)
	}

	historical, err := persistence.CreateFabricRequest(store.FabricRequest{
		RequestID: "rq_historical", MessageID: "msg_historical_ask",
		SenderEndpointID: joined.Endpoint.ID, SenderPrincipalID: joined.Endpoint.PrincipalID,
		SenderGroupID: group.ID, SenderBindingID: joined.BindingID,
		SenderBindingEpoch: joined.BindingEpoch,
		ReceiverEndpointID: joinedB.Endpoint.ID, ReceiverPrincipalID: joinedB.Endpoint.PrincipalID,
		ReceiverGroupID: group.ID, ReceiverBindingID: joinedB.BindingID,
		ReceiverBindingEpoch: joinedB.BindingEpoch, Body: "historical question",
	})
	if err != nil {
		t.Fatalf("seed historical plaintext request: %v", err)
	}

	receiveB := httptest.NewRequest(http.MethodPost, "/v2/fabric/receive", bytes.NewReader([]byte(`{}`)))
	receiveB.Header.Set("Authorization", "CicadaSession "+joinedB.SessionToken)
	receiveB.Header.Set("Content-Type", "application/json")
	receiveBResponse := httptest.NewRecorder()
	handler.ServeHTTP(receiveBResponse, receiveB)
	if receiveBResponse.Code != http.StatusOK || !bytes.Contains(receiveBResponse.Body.Bytes(), []byte(historical.RequestID)) ||
		!bytes.Contains(receiveBResponse.Body.Bytes(), []byte("historical question")) {
		t.Fatalf("B receive status=%d body=%s", receiveBResponse.Code, receiveBResponse.Body.String())
	}

	if _, err := persistence.SubmitFabricReply(store.FabricReply{
		RequestID: historical.RequestID, ResponderEndpointID: joinedB.Endpoint.ID,
		ResponderPrincipalID: joinedB.Endpoint.PrincipalID, ResponderGroupID: group.ID,
		ReceiverBindingID: joined.BindingID, ReceiverBindingEpoch: joined.BindingEpoch,
		Body: "historical answer", IdempotencyKey: "historical-reply",
	}); err != nil {
		t.Fatalf("seed historical plaintext reply: %v", err)
	}

	receiveA := httptest.NewRequest(http.MethodPost, "/v2/fabric/receive", bytes.NewReader([]byte(`{}`)))
	receiveA.Header.Set("Authorization", "CicadaSession "+joined.SessionToken)
	receiveA.Header.Set("Content-Type", "application/json")
	receiveAResponse := httptest.NewRecorder()
	handler.ServeHTTP(receiveAResponse, receiveA)
	if receiveAResponse.Code != http.StatusOK || !bytes.Contains(receiveAResponse.Body.Bytes(), []byte(`"body":"historical answer"`)) {
		t.Fatalf("A receive status=%d body=%s", receiveAResponse.Code, receiveAResponse.Body.String())
	}
}

func TestFabricV2ResourceExhaustedUses429AndRetryAfter(t *testing.T) {
	response := httptest.NewRecorder()
	fabricV2Error(response, &fabricpkg.ResourceExhaustedError{
		Scope: "sender_group", Limit: 2, Pending: 2, RetryAfterSeconds: 4,
	})
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("RESOURCE_EXHAUSTED status=%d body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Retry-After"); got != "4" {
		t.Fatalf("Retry-After=%q want 4", got)
	}
	for _, expected := range []string{`"code":"RESOURCE_EXHAUSTED"`, `"scope":"sender_group"`, `"limit":2`, `"pending":2`, `"retry_after_seconds":4`} {
		if !bytes.Contains(response.Body.Bytes(), []byte(expected)) {
			t.Fatalf("error body missing %s: %s", expected, response.Body.String())
		}
	}
}

func TestFabricV2GroupScopeHeaderAndScopedLeave(t *testing.T) {
	persistence, err := store.New(filepath.Join(t.TempDir(), "groups.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: "owner", Kind: store.PrincipalKindHuman, OwnerID: "owner",
		TrustDomainID: "domain", Name: "owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	groupA, err := persistence.CreateGroup(store.Group{Name: "a", OwnerPrincipalID: owner.ID,
		TrustDomainID: "domain", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{Name: "b", OwnerPrincipalID: owner.ID,
		TrustDomainID: "domain", State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, owner.ID, "domain")
	if err != nil {
		t.Fatal(err)
	}
	a, err := service.Join(fabricpkg.JoinInput{GroupID: groupA.ID, PrincipalName: "a",
		EndpointName: "a", Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(store.Membership{
		PrincipalID: a.Endpoint.PrincipalID, GroupID: groupB.ID, Role: "member",
		Grants: []string{"directory.read", "message.send", "message.ask", "message.receive"},
	}); err != nil {
		t.Fatal(err)
	}
	a, err = service.Join(fabricpkg.JoinInput{GroupID: groupB.ID, EndpointID: a.Endpoint.ID,
		Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := service.Join(fabricpkg.JoinInput{GroupID: groupB.ID, PrincipalName: "b",
		EndpointName: "b", Harness: "codex", NativeSessionID: "native-b", NodeID: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	// No Control business service exists on this handler. Group selection is
	// checked against the native credential at every Fabric request.
	handler := NewFabricHandler(service, "")
	call := func(method, path, scope, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Authorization", "CicadaSession "+a.SessionToken)
		request.Header.Set("Cicada-Group-Scope", scope)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := call(http.MethodGet, "/v2/fabric/whoami", groupA.ID, ""); response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(groupA.ID)) {
		t.Fatalf("Group A scope: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/v2/fabric/whoami", groupB.ID, ""); response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(groupB.ID)) {
		t.Fatalf("Group B scope: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/v2/fabric/whoami", "forged-group", ""); response.Code != http.StatusForbidden {
		t.Fatalf("forged Group scope: status=%d body=%s", response.Code, response.Body.String())
	}
	ask := `{"target":"` + peer.Endpoint.ID + `","question":"scope test"}`
	if response := call(http.MethodPost, "/v2/fabric/ask", groupA.ID, ask); response.Code != http.StatusGone {
		t.Fatalf("retired ASK route returned %d for Group A scope: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/v2/fabric/ask", groupB.ID, ask); response.Code != http.StatusGone {
		t.Fatalf("retired ASK route returned %d for Group B scope: %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/v2/fabric/leave-group", groupB.ID, `{}`); response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(groupA.ID)) {
		t.Fatalf("scoped leave: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/v2/fabric/whoami", groupB.ID, ""); response.Code != http.StatusForbidden {
		t.Fatalf("left Group B still accessible: status=%d body=%s", response.Code, response.Body.String())
	}
	if response := call(http.MethodGet, "/v2/fabric/whoami", groupA.ID, ""); response.Code != http.StatusOK {
		t.Fatalf("scoped leave broke Group A: status=%d body=%s", response.Code, response.Body.String())
	}
}
