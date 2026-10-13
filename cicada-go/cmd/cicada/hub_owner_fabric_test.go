package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestHubOwnerConfiguredFabricHasNoControlAndUsesStableHuman(t *testing.T) {
	s, e := store.New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	setup, e := s.InitializeHubOwnerLocal("Synthetic Fabric owner", "https://synthetic.invalid", false)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	service, e := existingHubFabricService(s, identity.Public())
	if e != nil {
		t.Fatal(e)
	}
	group, e := s.CreateGroup(store.Group{OwnerPrincipalID: setup.OwnerID, TrustDomainID: setup.OwnerID, Name: "synthetic independent Fabric", State: store.GroupStateActive})
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(fabric.JoinInput{GroupID: group.ID, NativeSessionID: "synthetic-exact-native", NodeID: "synthetic-local-node", Harness: "codex", Workspace: "/synthetic/workspace", EndpointName: "synthetic endpoint"})
	handler := server.NewFabricHandler(service, "synthetic-local-manager-token")
	req := httptest.NewRequest(http.MethodPost, "/v2/fabric/join", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer synthetic-local-manager-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("configured Fabric Join status=%d", response.Code)
	}
	endpoints, e := s.ListEndpointsV2(store.EndpointV2Filter{OwnerID: setup.OwnerID})
	if e != nil || len(endpoints) != 1 {
		t.Fatalf("stable Owner endpoint not created: %v", e)
	}
	if endpoints[0].Owner != setup.OwnerID || endpoints[0].Owner == identity.Public().ID {
		t.Fatal("Fabric-only used Hub key as human owner")
	}
	management := httptest.NewRecorder()
	managementRequest := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	managementRequest.Header.Set("Authorization", "Bearer synthetic-local-manager-token")
	handler.ServeHTTP(management, managementRequest)
	if management.Code != http.StatusServiceUnavailable {
		t.Fatalf("Control business unexpectedly present: %d", management.Code)
	}
}

func TestHubOwnerFabricLegacyFallbackRequiresExactExistingHuman(t *testing.T) {
	s, e := store.New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	identity, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = existingHubFabricService(s, identity.Public()); e == nil {
		t.Fatal("Fabric-only created an Owner from a new key")
	}
	if e = s.EnsureLocalOwnerPrincipal("synthetic-guest"); e != nil {
		t.Fatal(e)
	}
	if _, e = existingHubFabricService(s, identity.Public()); e == nil {
		t.Fatal("Fabric-only selected a guest as manager")
	}
	if e = s.EnsureLocalOwnerPrincipal(identity.Public().ID); e != nil {
		t.Fatal(e)
	}
	if _, e = existingHubFabricService(s, identity.Public()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RevokePrincipal(identity.Public().ID, "synthetic revoked manager"); e != nil {
		t.Fatal(e)
	}
	if _, e = existingHubFabricService(s, identity.Public()); e == nil {
		t.Fatal("Fabric-only admitted revoked manager")
	}
}
