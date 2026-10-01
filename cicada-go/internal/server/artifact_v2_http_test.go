package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func artifactV2HTTPCall(t *testing.T, handler http.Handler, method, path, authorization string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func artifactV2HTTPJoin(t *testing.T, manager *control.Control, groupID, name string) *fabricpkg.JoinResult {
	t.Helper()
	joined, err := manager.Fabric().Join(fabricpkg.JoinInput{
		GroupID: groupID, PrincipalName: name, EndpointName: name, Harness: "codex",
		NativeSessionID: "artifact-http-" + name, NodeID: "node-" + name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return joined
}

func artifactV2HTTPPublish(t *testing.T, handler http.Handler, manager *control.Control, databasePath string, group *store.Group, joined *fabricpkg.JoinResult) (*store.Artifact, *store.ArtifactRefV2) {
	t.Helper()
	actor, err := manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	memberships, err := manager.GroupMembers(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	var membership *store.Membership
	for i := range memberships {
		if memberships[i].ID == actor.MembershipID {
			membership = &memberships[i]
			break
		}
	}
	if membership == nil {
		t.Fatal("publisher membership was not found")
	}
	if _, err := manager.BindMembershipRole(group.ID, membership.ID, "worker", membership.Version); err != nil {
		t.Fatal(err)
	}
	currentActor, err := manager.Fabric().Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Fabric().Authorize(currentActor, "artifact.publish"); err != nil {
		t.Fatalf("HTTP fixture has no current publication grant: %v", err)
	}
	content := []byte("private artifact fixture")
	digest := sha256.Sum256(content)
	digestHex := hex.EncodeToString(digest[:])
	// Seed a historical v1 row as a test fixture directly. The v1 HTTP route is
	// a legacy Manager surface and this test must not depend on anonymous access
	// to create its starting state.
	database, err := store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	legacy, createErr := database.CreateArtifact(store.Artifact{
		Name: "fixture.txt", Path: "fixture.txt", Kind: "evidence", Digest: digestHex, Evidence: "private artifact evidence",
	})
	if createErr != nil {
		_ = database.Close()
		t.Fatalf("seed historical artifact row: %v", createErr)
	}
	seed, seedErr := database.CreateArtifactRefV2(store.ArtifactRefV2Input{
		ArtifactID: legacy.ID, GroupID: group.ID, ProducerPrincipalID: actor.PrincipalID,
		ProducerEndpointID: actor.EndpointID, Scopes: []string{store.ArtifactRefV2ScopeMetadata},
	})
	closeErr := database.Close()
	if seedErr != nil || closeErr != nil {
		t.Fatalf("trusted legacy ref seed: ref=%#v create=%v close=%v", seed, seedErr, closeErr)
	}
	refResponse := artifactV2HTTPCall(t, handler, http.MethodPost, "/v2/artifacts", "CicadaSession "+joined.SessionToken, store.ArtifactRefV2Input{
		ArtifactID: legacy.ID, GroupID: group.ID, Version: 2, Digest: digestHex,
		Summary: "scoped evidence", Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeSummary, store.ArtifactRefV2ScopeDigest},
	})
	if refResponse.Code != http.StatusCreated {
		t.Fatalf("v2 artifact publication status=%d body=%s", refResponse.Code, refResponse.Body.String())
	}
	var ref store.ArtifactRefV2
	if err := json.Unmarshal(refResponse.Body.Bytes(), &ref); err != nil {
		t.Fatal(err)
	}
	if ref.ID == "" || ref.ID == seed.ID || ref.Version != 2 {
		t.Fatalf("HTTP did not publish a distinct scoped version: seed=%#v result=%#v", seed, ref)
	}
	return legacy, &ref
}

func TestLegacyArtifactHTTPFailsClosedAfterScopedArtifactRefExists(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "legacy-artifact-guard"})
	if err != nil {
		t.Fatal(err)
	}
	joined := artifactV2HTTPJoin(t, manager, group.ID, "publisher")
	_, ref := artifactV2HTTPPublish(t, handler, manager, filepath.Join(root, "state", "cicada.sqlite3"), group, joined)
	if ref.ID == "" {
		t.Fatal("scoped ArtifactRef was not created")
	}

	list := artifactV2HTTPCall(t, handler, http.MethodGet, "/v1/artifacts", "", nil)
	if list.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy artifact list exposed rows after scoped ref creation: status=%d body=%s", list.Code, list.Body.String())
	}
	create := artifactV2HTTPCall(t, handler, http.MethodPost, "/v1/artifacts", "", store.Artifact{
		Name: "legacy-after-v2.txt", Path: "legacy-after-v2.txt", Kind: "evidence", Evidence: "must not enter the legacy surface",
	})
	if create.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy artifact creation remained open after scoped ref creation: status=%d body=%s", create.Code, create.Body.String())
	}
}

func TestArtifactV2HTTPRejectsWrongGroupAndRevokedMembership(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	ownerGroup, err := manager.CreateGroup(control.GroupCreateInput{Name: "artifact-owner"})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := manager.CreateGroup(control.GroupCreateInput{Name: "artifact-other"})
	if err != nil {
		t.Fatal(err)
	}
	ownerSession := artifactV2HTTPJoin(t, manager, ownerGroup.ID, "owner-publisher")
	_, ref := artifactV2HTTPPublish(t, handler, manager, filepath.Join(root, "state", "cicada.sqlite3"), ownerGroup, ownerSession)
	otherSession := artifactV2HTTPJoin(t, manager, otherGroup.ID, "other-reader")
	readPath := "/v2/artifacts/" + ref.ID + "?scope=summary"
	wrongGroup := artifactV2HTTPCall(t, handler, http.MethodGet, readPath, "CicadaSession "+otherSession.SessionToken, nil)
	if wrongGroup.Code != http.StatusForbidden {
		t.Fatalf("wrong Group read succeeded: status=%d body=%s", wrongGroup.Code, wrongGroup.Body.String())
	}

	ownerActor, err := manager.Fabric().Authenticate(ownerSession.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RevokeGroupMember(ownerGroup.ID, ownerActor.MembershipID, "test membership revocation"); err != nil {
		t.Fatal(err)
	}
	revoked := artifactV2HTTPCall(t, handler, http.MethodGet, readPath, "CicadaSession "+ownerSession.SessionToken, nil)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked member retained ArtifactRef access: status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestConfiguredManagementBearerRetainsLegacyArtifactAccess(t *testing.T) {
	root := t.TempDir()
	manager, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "management-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())
	handler := NewHandler(manager)
	group, err := manager.CreateGroup(control.GroupCreateInput{Name: "authenticated-legacy-artifact"})
	if err != nil {
		t.Fatal(err)
	}
	joined := artifactV2HTTPJoin(t, manager, group.ID, "publisher")
	_, ref := artifactV2HTTPPublish(t, handler, manager, filepath.Join(root, "state", "cicada.sqlite3"), group, joined)

	unauthorized := artifactV2HTTPCall(t, handler, http.MethodGet, "/v1/artifacts", "", nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("legacy list without management bearer status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	managed := artifactV2HTTPCall(t, handler, http.MethodGet, "/v1/artifacts", "Bearer management-token", nil)
	if managed.Code != http.StatusOK || !bytes.Contains(managed.Body.Bytes(), []byte(ref.ArtifactID)) {
		t.Fatalf("authorized legacy list did not retain management access: status=%d body=%s", managed.Code, managed.Body.String())
	}
}
