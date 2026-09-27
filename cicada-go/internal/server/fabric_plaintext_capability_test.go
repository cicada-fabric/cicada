package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

type readProbeBody struct {
	reader *strings.Reader
	reads  int
}

func (body *readProbeBody) Read(data []byte) (int, error) {
	body.reads++
	return body.reader.Read(data)
}

func (body *readProbeBody) Close() error { return nil }

var _ io.ReadCloser = (*readProbeBody)(nil)

func TestPlaintextFabricPeerWritesAreRetiredBeforeBodyRead(t *testing.T) {
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
		Name: "group", OwnerPrincipalID: owner.ID, TrustDomainID: "domain", State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, owner.ID, "domain")
	if err != nil {
		t.Fatal(err)
	}
	join := func(name string) *fabricpkg.JoinResult {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: group.ID, PrincipalName: name, EndpointName: name,
			Harness: "codex", NativeSessionID: "native-" + name, NodeID: "node-" + name,
		})
		if err != nil {
			t.Fatal(err)
		}
		return joined
	}
	a, b := join("a"), join("b")
	handler := NewFabricHandler(service, "")

	for _, test := range []struct {
		path  string
		token string
	}{
		{"/v2/fabric/send", a.SessionToken},
		{"/v2/fabric/ask", a.SessionToken},
		{"/v2/fabric/reply", b.SessionToken},
	} {
		requestBody := &readProbeBody{reader: strings.NewReader("not-json")}
		request := httptest.NewRequest(http.MethodPost, test.path, nil)
		request.Body = requestBody
		request.Header.Set("Authorization", "CicadaSession "+test.token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusGone || !strings.Contains(response.Body.String(),
			"plaintext Fabric peer writes are retired; use sealed Node delivery") {
			t.Fatalf("retired route %s returned %d %s", test.path, response.Code, response.Body.String())
		}
		if requestBody.reads != 0 {
			t.Fatalf("retired route %s read its request body %d times", test.path, requestBody.reads)
		}
	}

	// Authentication still runs before the retired-route response.
	unauthorizedBody := &readProbeBody{reader: strings.NewReader("not-json")}
	unauthorized := httptest.NewRequest(http.MethodPost, "/v2/fabric/ask", nil)
	unauthorized.Body = unauthorizedBody
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized || unauthorizedBody.reads != 0 {
		t.Fatalf("unauthenticated retired route returned %d after %d body reads: %s",
			unauthorizedResponse.Code, unauthorizedBody.reads, unauthorizedResponse.Body.String())
	}

	requests, err := persistence.ListRelayRequests(store.RelayRequestFilter{
		SenderPrincipalID: a.Endpoint.PrincipalID, SenderGroupID: group.ID, Limit: 10,
	})
	if err != nil || len(requests) != 0 {
		t.Fatalf("retired peer writes persisted an Ask: requests=%#v err=%v", requests, err)
	}
	for _, endpointID := range []string{a.Endpoint.ID, b.Endpoint.ID} {
		inbox, err := persistence.ListRelayInbox(endpointID, 0, 10)
		if err != nil || len(inbox) != 0 {
			t.Fatalf("retired peer writes persisted inbox rows for %s: inbox=%#v err=%v", endpointID, inbox, err)
		}
	}
}
