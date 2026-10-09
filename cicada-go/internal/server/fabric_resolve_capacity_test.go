package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestFabricV2ResolveUsesNameScopedCandidatesBeyondListPage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PUBLIC_SYNTHETIC.sqlite3")
	persistence, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: "PUBLIC_SYNTHETIC_resolve_owner", Kind: store.PrincipalKindHuman,
		OwnerID: "PUBLIC_SYNTHETIC_resolve_owner", TrustDomainID: "PUBLIC_SYNTHETIC_resolve_owner",
		Name: "PUBLIC_SYNTHETIC owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		ID: "PUBLIC_SYNTHETIC_resolve_group", Name: "PUBLIC_SYNTHETIC resolve group",
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.ID, State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabricpkg.NewService(persistence, owner.ID, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	callerJoin, err := service.Join(fabricpkg.JoinInput{
		GroupID: group.ID, PrincipalName: "PUBLIC_SYNTHETIC caller", EndpointName: "caller",
		Harness: "codex", NativeSessionID: "PUBLIC_SYNTHETIC_resolve_caller",
		NodeID: "PUBLIC_SYNTHETIC_caller_node",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedHTTPResolvePlaceholders(t, path, callerJoin.Endpoint.PrincipalID, group.ID)
	join := func(name, node string) *fabricpkg.JoinResult {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{
			GroupID: group.ID, PrincipalName: "PUBLIC_SYNTHETIC " + node, EndpointName: name,
			Harness: "codex", NativeSessionID: "PUBLIC_SYNTHETIC_resolve_" + node, NodeID: node,
		})
		if err != nil {
			t.Fatal(err)
		}
		return joined
	}
	join("tail-duplicate", "PUBLIC_SYNTHETIC_dup_a")
	join("tail-duplicate", "PUBLIC_SYNTHETIC_dup_b")
	unique := join("tail-unique", "PUBLIC_SYNTHETIC_unique")
	handler := NewFabricHandler(service, "PUBLIC_SYNTHETIC_manager_token")
	callResolve := func(query string) (int, fabricpkg.NetworkCard) {
		t.Helper()
		body, err := json.Marshal(fabricpkg.ResolveInput{Query: query})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v2/fabric/resolve", bytes.NewReader(body))
		request.Header.Set("Authorization", "CicadaSession "+callerJoin.SessionToken)
		request.Header.Set("Cicada-Group-Scope", group.ID)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var card fabricpkg.NetworkCard
		if response.Code == http.StatusOK {
			if err := json.Unmarshal(response.Body.Bytes(), &card); err != nil {
				t.Fatal("decode synthetic resolve response")
			}
		}
		return response.Code, card
	}
	if status, _ := callResolve("tail-duplicate"); status != http.StatusConflict {
		t.Fatalf("tail duplicate HTTP status=%d, want conflict", status)
	}
	if status, card := callResolve("tail-unique"); status != http.StatusOK || card.EndpointID != unique.Endpoint.ID {
		t.Fatalf("tail unique HTTP status=%d endpoint=%q, want 200/%q", status, card.EndpointID, unique.Endpoint.ID)
	}
	address := group.ID + "/" + unique.Endpoint.Name + "@public_synthetic_unique"
	if status, card := callResolve(address); status != http.StatusOK || card.EndpointID != unique.Endpoint.ID {
		t.Fatalf("tail address HTTP status=%d endpoint=%q, want 200/%q", status, card.EndpointID, unique.Endpoint.ID)
	}
}

func seedHTTPResolvePlaceholders(t *testing.T, path, principalID, groupID string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	endpointStmt, err := tx.Prepare(`INSERT INTO fabric_endpoints
(id,name,role,harness,native_session_id,machine_id,workspace,goal_id,status,
capabilities_json,tags_json,owner,visibility,joined_at,last_seen,created_at,updated_at,
principal_id,group_id,binding_id,migration_state)
VALUES(?,?,'worker','codex',?,'PUBLIC_SYNTHETIC_filler_node','','',?, '{}','[]',
'PUBLIC_SYNTHETIC_owner','private',?,'2040-01-01T00:00:00Z','2040-01-01T00:00:00Z',
'2040-01-01T00:00:00Z',?,?,?,'READY')`)
	if err != nil {
		t.Fatal(err)
	}
	defer endpointStmt.Close()
	groupStmt, err := tx.Prepare(`INSERT INTO endpoint_group_memberships
(endpoint_id,group_id,status,created_at,updated_at) VALUES(?,?,'active',?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer groupStmt.Close()
	bindingStmt, err := tx.Prepare(`INSERT INTO session_bindings
(id,endpoint_id,principal_id,group_id,native_session_id,node_id,epoch,status,created_at,updated_at)
VALUES(?,?,?,?,?,'PUBLIC_SYNTHETIC_filler_node',1,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer bindingStmt.Close()
	stamp := "2040-01-01T00:00:00Z"
	for i := 0; i < 1001; i++ {
		id := "PUBLIC_SYNTHETIC_filler_" + fmt.Sprintf("%04d", i)
		status, bindingStatus := "left", "active"
		if i == 0 {
			status = "online"
		} else if i%2 != 0 {
			status, bindingStatus = "online", "released"
		}
		bindingID, nativeID := "PUBLIC_SYNTHETIC_binding_"+id, "PUBLIC_SYNTHETIC_native_"+id
		if _, err := endpointStmt.Exec(id, "tail-duplicate", nativeID, status, stamp, principalID, groupID, bindingID); err != nil {
			t.Fatal(err)
		}
		if _, err := groupStmt.Exec(id, groupID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := bindingStmt.Exec(bindingID, id, principalID, groupID, nativeID, bindingStatus, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
