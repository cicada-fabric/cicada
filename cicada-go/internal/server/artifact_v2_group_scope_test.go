package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestArtifactV2HonorsExplicitGroupScopeForMultiGroupEndpoint(t *testing.T) {
	service, persistence, groupA := newRelayNodeTestService(t)
	owner, err := persistence.GetPrincipal("owner")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := persistence.CreateGroup(store.Group{ID: "group-artifact-scope-b",
		Name: "synthetic B", OwnerPrincipalID: owner.ID, TrustDomainID: "domain",
		State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	groupC, err := persistence.CreateGroup(store.Group{ID: "group-artifact-scope-c",
		Name: "synthetic C", OwnerPrincipalID: owner.ID, TrustDomainID: "domain",
		State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Join(fabric.JoinInput{GroupID: groupA.ID, PrincipalName: "multi-group-artifact",
		EndpointName: "multi-group-artifact", Harness: "codex", NativeSessionID: "synthetic-artifact-native",
		NodeID: "synthetic-artifact-node"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateMembership(store.Membership{PrincipalID: first.Endpoint.PrincipalID,
		GroupID: groupB.ID, Role: "member", Grants: []string{"directory.read", "artifact.read"},
		Status: store.MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	second, err := service.Join(fabric.JoinInput{GroupID: groupB.ID, EndpointID: first.Endpoint.ID,
		EndpointName: "multi-group-artifact", Harness: "codex", NativeSessionID: "synthetic-artifact-native",
		NodeID: "synthetic-artifact-node"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Endpoint.ID != first.Endpoint.ID {
		t.Fatalf("joining second Group replaced native Endpoint: first=%s second=%s", first.Endpoint.ID, second.Endpoint.ID)
	}

	createRef := func(groupID, suffix string) *store.ArtifactRefV2 {
		t.Helper()
		digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		legacy, err := persistence.CreateArtifact(store.Artifact{ID: "synthetic-artifact-" + suffix,
			Name: "synthetic " + suffix, Path: suffix + ".txt", Kind: "evidence", Digest: digest})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := persistence.CreateArtifactRefV2(store.ArtifactRefV2Input{
			ID: "synthetic-artifact-ref-" + suffix, ArtifactID: legacy.ID, GroupID: groupID,
			Digest: digest, Summary: "synthetic scoped metadata",
			Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeSummary},
		})
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	refA := createRef(groupA.ID, "a")
	refB := createRef(groupB.ID, "b")
	handler := NewFabricHandler(service, "synthetic-operator-token")
	call := func(path, groupScope string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "CicadaSession "+second.SessionToken)
		if groupScope != "" {
			request.Header.Set("Cicada-Group-Scope", groupScope)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	for _, test := range []struct {
		name, refID, groupID string
		want                 int
	}{
		{"implicit binding scope", refA.ID, "", http.StatusOK},
		{"explicit group A", refA.ID, groupA.ID, http.StatusOK},
		{"explicit group B", refB.ID, groupB.ID, http.StatusOK},
		{"cross group reference denied", refB.ID, groupA.ID, http.StatusForbidden},
		{"unjoined group denied", refA.ID, groupC.ID, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := "/v2/artifacts/" + test.refID + "?scope=summary"
			if got := call(path, test.groupID); got != test.want {
				t.Fatalf("ArtifactRef %s in Group %q status=%d want=%d", test.refID, test.groupID, got, test.want)
			}
		})
	}
}
