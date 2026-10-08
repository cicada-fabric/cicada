package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// Synthetic Store and issued Fabric sessions, served by the production handler.
// There is no Control, Node process, installed Native Runtime or model here.
// Legacy Hub-backed plaintext Artifact fixtures test ACLs, not peer E2EE or Hub blindness.
type fabricG5PrivacyFixture struct {
	service               *fabricpkg.Service
	store                 *store.Store
	groupA, groupB        store.Group
	caller, peer, foreign *fabricpkg.JoinResult
	http                  *httptest.Server
}

func newFabricG5PrivacyFixture(t *testing.T, joinSecondGroup bool) *fabricG5PrivacyFixture {
	t.Helper()
	service, persistence, groupA := newRelayNodeTestService(t)
	groupB, err := persistence.CreateGroup(store.Group{ID: "grp_synthetic_g5_foreign",
		Name: "synthetic foreign group", OwnerPrincipalID: groupA.OwnerPrincipalID,
		TrustDomainID: groupA.TrustDomainID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal("create synthetic foreign Group")
	}
	join := func(groupID, name string) *fabricpkg.JoinResult {
		t.Helper()
		joined, err := service.Join(fabricpkg.JoinInput{GroupID: groupID, PrincipalName: name,
			EndpointName: name, Harness: "codex", NativeSessionID: "native_synthetic_g5_" + name,
			NodeID: "node_synthetic_g5_" + name})
		if err != nil {
			t.Fatal("issue synthetic Fabric session")
		}
		return joined
	}
	f := &fabricG5PrivacyFixture{service: service, store: persistence, groupA: groupA, groupB: *groupB,
		caller: join(groupA.ID, "caller"), peer: join(groupA.ID, "peer"), foreign: join(groupB.ID, "synthetic_g5_hidden_peer_name_7f93")}
	if joinSecondGroup {
		if _, err := persistence.CreateMembership(store.Membership{PrincipalID: f.caller.Endpoint.PrincipalID,
			GroupID: groupB.ID, Role: "member", Grants: []string{"directory.read"},
			Status: store.MembershipStatusActive}); err != nil {
			t.Fatal("authorize synthetic second Group directory only")
		}
		previous := f.caller
		f.caller, err = service.Join(fabricpkg.JoinInput{GroupID: groupB.ID, EndpointID: previous.Endpoint.ID,
			EndpointName: "caller", Harness: "codex", NativeSessionID: previous.Endpoint.NativeSessionID,
			NodeID: previous.Endpoint.MachineID})
		if err != nil {
			t.Fatal("join same synthetic Endpoint to second Group")
		}
		if f.caller.Endpoint.ID != previous.Endpoint.ID || f.caller.BindingID != previous.BindingID ||
			f.caller.Endpoint.NativeSessionID != previous.Endpoint.NativeSessionID {
			t.Fatal("second Join did not preserve exact synthetic Endpoint, binding and Native ID")
		}
	}
	f.http = httptest.NewServer(NewFabricHandler(service, "synthetic_g5_manager_token"))
	t.Cleanup(f.http.Close)
	return f
}

func (f *fabricG5PrivacyFixture) call(t *testing.T, method, path, group string, body any) (int, []byte) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal("encode synthetic HTTP request")
		}
	}
	request, err := http.NewRequest(method, f.http.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("construct synthetic HTTP request")
	}
	request.Header.Set("Authorization", "CicadaSession "+f.caller.SessionToken)
	request.Header.Set("Content-Type", "application/json")
	if group != "" {
		request.Header.Set("Cicada-Group-Scope", group)
	}
	client := f.http.Client()
	client.Timeout = 3 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("synthetic loopback HTTP request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		t.Fatal("synthetic HTTP response exceeds bound or failed read")
	}
	// Even failing assertions must not print credentials or complete responses.
	for _, joined := range []*fabricpkg.JoinResult{f.caller, f.peer, f.foreign} {
		if bytes.Contains(data, []byte(joined.SessionToken)) {
			t.Fatal("HTTP response disclosed a session credential")
		}
	}
	return response.StatusCode, data
}

func TestFabricG5DirectoryPrivacyHTTP(t *testing.T) {
	f := newFabricG5PrivacyFixture(t, false)
	checkCards := func(t *testing.T, data []byte, want int) {
		t.Helper()
		var result struct {
			Endpoints []fabricpkg.NetworkCard `json:"endpoints"`
		}
		if json.Unmarshal(data, &result) != nil || len(result.Endpoints) != want {
			t.Fatal("directory result count or wire shape mismatch")
		}
		for _, card := range result.Endpoints {
			if (card.EndpointID != f.caller.Endpoint.ID && card.EndpointID != f.peer.Endpoint.ID) ||
				card.GroupID != f.groupA.ID || card.NativeSessionID != "" {
				t.Fatal("directory disclosed foreign scope or Native ID")
			}
		}
		if bytes.Contains(data, []byte(f.foreign.Endpoint.ID)) || bytes.Contains(data, []byte("synthetic_g5_hidden_peer_name_7f93")) {
			t.Fatal("directory list disclosed hidden foreign peer metadata")
		}
		for _, joined := range []*fabricpkg.JoinResult{f.caller, f.peer, f.foreign} {
			if bytes.Contains(data, []byte(joined.Endpoint.NativeSessionID)) {
				t.Fatal("directory disclosed a Native ID")
			}
		}
	}
	for _, route := range []string{"members", "list"} {
		t.Run(route, func(t *testing.T) {
			for _, filter := range []struct {
				name, query string
				want        int
			}{
				{"all", "", 2},
				{"peer-node", "?node_id=" + url.QueryEscape(f.peer.Endpoint.MachineID), 1},
				{"foreign-node", "?node_id=" + url.QueryEscape(f.foreign.Endpoint.MachineID), 0},
				{"harness", "?harness=codex", 2},
				{"status", "?status=" + url.QueryEscape(f.peer.Endpoint.Status), 2},
				{"foreign-node-harness", "?node_id=" + url.QueryEscape(f.foreign.Endpoint.MachineID) + "&harness=codex", 0},
			} {
				t.Run(filter.name, func(t *testing.T) {
					code, data := f.call(t, http.MethodGet, "/v2/fabric/"+route+filter.query, "", nil)
					if code != http.StatusOK {
						t.Fatalf("directory HTTP status %d", code)
					}
					checkCards(t, data, filter.want)
				})
			}
			code, _ := f.call(t, http.MethodGet, "/v2/fabric/"+route, f.groupB.ID, nil)
			if code != http.StatusForbidden {
				t.Fatalf("unjoined Group header HTTP status %d", code)
			}
		})
	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		t.Run(route, func(t *testing.T) {
			code, data := f.call(t, http.MethodPost, "/v2/fabric/"+route, "", fabricpkg.ResolveInput{Query: f.peer.Endpoint.ID})
			var card fabricpkg.NetworkCard
			if code != http.StatusOK || json.Unmarshal(data, &card) != nil || card.EndpointID != f.peer.Endpoint.ID ||
				card.GroupID != f.groupA.ID || card.NativeSessionID != "" {
				t.Fatal("legitimate peer resolution failed or disclosed Native ID")
			}
			for _, joined := range []*fabricpkg.JoinResult{f.caller, f.peer, f.foreign} {
				if bytes.Contains(data, []byte(joined.Endpoint.NativeSessionID)) {
					t.Fatal("peer resolution disclosed a Native ID")
				}
			}
			code, data = f.call(t, http.MethodPost, "/v2/fabric/"+route, "", fabricpkg.ResolveInput{Query: f.foreign.Endpoint.ID})
			if code != http.StatusNotFound {
				t.Fatalf("foreign peer lookup HTTP status %d", code)
			}
			if bytes.Contains(data, []byte(f.foreign.Endpoint.NativeSessionID)) ||
				bytes.Contains(data, []byte("synthetic_g5_hidden_peer_name_7f93")) ||
				bytes.Contains(data, []byte(f.foreign.Endpoint.PrincipalID)) ||
				bytes.Contains(data, []byte(f.foreign.Endpoint.MachineID)) {
				t.Fatal("foreign lookup error disclosed unrequested hidden peer metadata")
			}
			code, _ = f.call(t, http.MethodPost, "/v2/fabric/"+route, f.groupB.ID, fabricpkg.ResolveInput{Query: f.foreign.Endpoint.ID})
			if code != http.StatusForbidden {
				t.Fatalf("forbidden Group header lookup HTTP status %d", code)
			}
		})
	}
}

func TestFabricG5ArtifactPrivacyHTTP(t *testing.T) {
	f := newFabricG5PrivacyFixture(t, true)
	actor, err := f.service.AuthenticateForGroup(f.caller.SessionToken, f.groupA.ID)
	if err != nil {
		t.Fatal("authenticate synthetic Artifact reader")
	}
	membership, err := f.store.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal("read synthetic Artifact reader membership")
	}
	grants := append(append([]string(nil), membership.Grants...), "artifact.read")
	if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, grants,
		membership.Authorization, membership.Version); err != nil {
		t.Fatal("grant synthetic Group A Artifact read")
	}
	root := t.TempDir()
	content := []byte("PUBLIC_SYNTHETIC_G5_ARTIFACT_CONTENT")
	if err := os.WriteFile(filepath.Join(root, "fixture.txt"), content, 0600); err != nil {
		t.Fatal("write synthetic Artifact fixture")
	}
	workspace, err := f.store.CreateWorkspace("workspace_synthetic_g5", "", root, "synthetic", "g5")
	if err != nil {
		t.Fatal("create synthetic Artifact workspace")
	}
	digest := sha256.Sum256(content)
	legacy, err := f.store.CreateArtifact(store.Artifact{ID: "artifact_synthetic_g5", WorkspaceID: workspace.ID,
		Name: "synthetic-private-name.txt", Path: "fixture.txt", Kind: "synthetic-private-kind",
		Digest: hex.EncodeToString(digest[:]), Evidence: "synthetic private summary", Status: "available"})
	if err != nil {
		t.Fatal("create synthetic legacy Artifact fixture")
	}
	createRef := func(id, group string, scopes []string) *store.ArtifactRefV2 {
		t.Helper()
		// Trusted fixture seeding, not a caller-controlled publication bypass.
		ref, err := f.store.CreateArtifactRefV2(store.ArtifactRefV2Input{ID: id, ArtifactID: legacy.ID,
			GroupID: group, WorkspaceID: workspace.ID, ProducerPrincipalID: actor.PrincipalID,
			ProducerEndpointID: actor.EndpointID, Digest: hex.EncodeToString(digest[:]),
			Summary: "synthetic private summary", RelativePath: "fixture.txt", Scopes: scopes})
		if err != nil {
			t.Fatal("seed synthetic scoped Artifact reference")
		}
		return ref
	}
	contentRef := createRef("ref_synthetic_g5_content", f.groupA.ID, []string{store.ArtifactRefV2ScopeContent})
	metadataRef := createRef("ref_synthetic_g5_metadata", f.groupA.ID, []string{store.ArtifactRefV2ScopeMetadata})
	foreignRef := createRef("ref_synthetic_g5_foreign", f.groupB.ID, []string{store.ArtifactRefV2ScopeMetadata})
	t.Run("authorized-content", func(t *testing.T) {
		code, data := f.call(t, http.MethodGet, "/v2/artifacts/"+contentRef.ID+"?scope=content", f.groupA.ID, nil)
		var result store.ArtifactRefV2Authorized
		if code != http.StatusOK || json.Unmarshal(data, &result) != nil || !bytes.Equal(result.Content, content) {
			t.Fatal("authorized synthetic content positive control failed")
		}
		if result.Ref.Name != "" || result.Ref.Kind != "" || result.Ref.WorkspaceID != "" || result.Ref.ProducerPrincipalID != "" ||
			result.Ref.ProducerEndpointID != "" || result.Ref.Summary != "" || result.Ref.Digest != "" {
			t.Fatal("content-only read disclosed forbidden metadata")
		}
	})
	t.Run("list-hides-foreign-and-redacts-content-only", func(t *testing.T) {
		code, data := f.call(t, http.MethodGet, "/v2/artifacts", f.groupA.ID, nil)
		var result struct {
			Refs []store.ArtifactRefV2 `json:"artifact_refs"`
		}
		if code != http.StatusOK || json.Unmarshal(data, &result) != nil || len(result.Refs) != 2 {
			t.Fatal("Artifact list status, shape or visible count mismatch")
		}
		seenContent, seenMetadata := false, false
		for _, ref := range result.Refs {
			switch ref.ID {
			case contentRef.ID:
				seenContent = true
				if ref.Name != "" || ref.Kind != "" || ref.WorkspaceID != "" || ref.ProducerPrincipalID != "" ||
					ref.ProducerEndpointID != "" || ref.Summary != "" || ref.Digest != "" || ref.Size != 0 || ref.MIMEType != "" {
					t.Fatal("content-only list entry disclosed forbidden metadata")
				}
			case metadataRef.ID:
				seenMetadata = true
				if ref.Name != legacy.Name || ref.Kind != legacy.Kind {
					t.Fatal("metadata-positive reference lost permitted fields")
				}
			default:
				t.Fatal("Artifact list disclosed a foreign or unexpected reference")
			}
		}
		if !seenContent || !seenMetadata || bytes.Contains(data, []byte(foreignRef.ID)) {
			t.Fatal("Artifact list visibility mismatch")
		}
	})
	t.Run("metadata-only-denies-content", func(t *testing.T) {
		code, _ := f.call(t, http.MethodGet, "/v2/artifacts/"+metadataRef.ID+"?scope=content", f.groupA.ID, nil)
		if code != http.StatusForbidden {
			t.Fatalf("metadata-only content HTTP status %d", code)
		}
	})
	t.Run("foreign-reference-denied", func(t *testing.T) {
		code, data := f.call(t, http.MethodGet, "/v2/artifacts/"+foreignRef.ID+"?scope=metadata", f.groupA.ID, nil)
		if code != http.StatusForbidden {
			t.Fatalf("foreign Artifact HTTP status %d", code)
		}
		if bytes.Contains(data, content) || bytes.Contains(data, []byte(legacy.Name)) ||
			bytes.Contains(data, []byte(legacy.Kind)) || bytes.Contains(data, []byte("synthetic private summary")) ||
			bytes.Contains(data, []byte(workspace.ID)) || bytes.Contains(data, []byte(hex.EncodeToString(digest[:]))) {
			t.Fatal("foreign Artifact denial disclosed hidden data")
		}
	})
	t.Run("same-native-endpoint-ungranted-group-denied", func(t *testing.T) {
		code, _ := f.call(t, http.MethodGet, "/v2/fabric/members", f.groupB.ID, nil)
		if code != http.StatusOK {
			t.Fatal("explicit second Group directory positive control failed")
		}
		for _, path := range []string{"/v2/artifacts", "/v2/artifacts/" + foreignRef.ID + "?scope=metadata", "/v2/artifacts/" + contentRef.ID + "?scope=content"} {
			code, _ = f.call(t, http.MethodGet, path, f.groupB.ID, nil)
			if code != http.StatusForbidden {
				t.Fatalf("ungranted second Group Artifact HTTP status %d", code)
			}
		}
	})
	t.Run("revoked-reader-denied", func(t *testing.T) {
		if _, err := f.store.RevokeMembership(actor.MembershipID, "synthetic g5 revoke"); err != nil {
			t.Fatal("revoke synthetic Artifact reader")
		}
		for _, path := range []string{"/v2/artifacts", "/v2/artifacts/" + contentRef.ID + "?scope=content"} {
			code, _ := f.call(t, http.MethodGet, path, f.groupA.ID, nil)
			if code != http.StatusUnauthorized && code != http.StatusForbidden {
				t.Fatalf("revoked reader Artifact HTTP status %d", code)
			}
		}
	})
}
