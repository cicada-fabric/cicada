package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestRelayNodeLinkAuthorizationRequiresCurrentBoundNodeCredential(t *testing.T) {
	service, persistence, _ := newRelayNodeTestService(t)
	nodeToken, nodeHash, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-b", nodeHash)
	handler := NewFabricHandler(service, "management-token")
	call := func(path, auth string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if auth != "" {
			request.Header.Set("Authorization", auth)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	path := "/v2/relay/nodes/node-b/links/unknown/authorization"
	if status := call(path, "Bearer management-token"); status != http.StatusUnauthorized {
		t.Fatalf("management bearer read Node Link material: status=%d", status)
	}
	if status := call(path, "CicadaNode "+nodeToken); status != http.StatusNotFound {
		t.Fatalf("nonexistent Link was disclosed to Node: status=%d", status)
	}
	if status := call("/v2/relay/nodes/other-node/links/unknown/authorization", "CicadaNode "+nodeToken); status != http.StatusForbidden {
		t.Fatalf("Node credential crossed Node scope: status=%d", status)
	}
	if status := call("/v2/relay/nodes/node-b/links/unknown/authorization/extra", "CicadaNode "+nodeToken); status != http.StatusNotFound {
		t.Fatalf("extra Link path segment accepted: status=%d", status)
	}
}

func TestRelayNodeLinkAuthorizationReturnsOnlyCurrentBilateralEvidence(t *testing.T) {
	service, persistence, groupA := newRelayNodeTestService(t)
	groupB, err := persistence.CreateGroup(store.Group{
		Name: "group B", OwnerPrincipalID: "owner", TrustDomainID: "domain",
		State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := service.Join(fabricpkg.JoinInput{GroupID: groupA.ID, PrincipalName: "A",
		EndpointName: "A", Harness: "codex", NativeSessionID: "native-a", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := service.Join(fabricpkg.JoinInput{GroupID: groupB.ID, PrincipalName: "B",
		EndpointName: "B", Harness: "codex", NativeSessionID: "native-b", NodeID: "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, joined := range []*fabricpkg.JoinResult{a, b} {
		identity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := identity.SignEndpointKeyAttestation(joined.Endpoint.ID,
			joined.Endpoint.PrincipalID, joined.Endpoint.MachineID, joined.BindingID, joined.BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.RegisterEndpointKeyCandidate(joined.Endpoint.ID,
			joined.Endpoint.PrincipalID, joined.BindingID, joined.BindingEpoch, proof); err != nil {
			t.Fatal(err)
		}
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	link, err := persistence.ProposeCommunicationLink(store.CommunicationLinkProposal{
		SourceEndpointID: a.Endpoint.ID, SourceGroupID: groupA.ID,
		TargetEndpointID: b.Endpoint.ID, TargetGroupID: groupB.ID,
		ActorOwnerID: "owner", Direction: "bidirectional",
		Actions: []string{"ask", "reply"}, DataScopes: []string{"benchmark.public_result"},
		TransportHubID: hubID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := persistence.GetCommunicationLinkKeyManifest(link.ID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		name string
		role e2ee.OwnerLinkGrantSide
	}{
		{store.CommunicationLinkGrantSource, e2ee.OwnerLinkGrantSideSource},
		{store.CommunicationLinkGrantTarget, e2ee.OwnerLinkGrantSideTarget},
	} {
		ownerKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.RegisterOwnerApprovalKeyLocal("owner", ownerKey.Public()); err != nil {
			t.Fatal(err)
		}
		proof, err := ownerKey.SignOwnerLinkKeyGrant("owner", link.ID, link.ContractDigest,
			manifest.Digest, uint64(link.Version), side.role,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(30*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := persistence.RecordCommunicationLinkKeyGrant("owner", link.ID,
			side.name, ownerKey.Public().ID, proof); err != nil {
			t.Fatal(err)
		}
	}
	tokenA, hashA, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-a", hashA)
	tokenB, hashB, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-b", hashB)
	tokenC, hashC, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	bindRelayNodeTestCredential(t, persistence, "node-c", hashC)
	handler := NewFabricHandler(service, "management-token")
	read := func(nodeID, token string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet,
			"/v2/relay/nodes/"+nodeID+"/links/"+link.ID+"/authorization", nil)
		request.Header.Set("Authorization", "CicadaNode "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for _, caller := range []struct{ nodeID, token string }{{"node-a", tokenA}, {"node-b", tokenB}} {
		response := read(caller.nodeID, caller.token)
		if response.Code != http.StatusOK {
			t.Fatalf("current endpoint Node %s could not read evidence: %d %s",
				caller.nodeID, response.Code, response.Body.String())
		}
		var bundle store.CommunicationLinkAuthorizationBundle
		if err := json.Unmarshal(response.Body.Bytes(), &bundle); err != nil ||
			bundle.Manifest.Digest != manifest.Digest || bundle.LinkState != store.CommunicationLinkProposed ||
			len(bundle.SourceGrant.SignedProof) == 0 || len(bundle.TargetGrant.SignedProof) == 0 {
			t.Fatalf("Node received incomplete current evidence: err=%v bundle=%#v", err, bundle)
		}
	}
	if response := read("node-c", tokenC); response.Code != http.StatusNotFound {
		t.Fatalf("unrelated bound Node learned Link material: %d", response.Code)
	}
	if _, err := persistence.RevokeCommunicationLink(link.ID, "owner", link.Version, "test"); err != nil {
		t.Fatal(err)
	}
	if response := read("node-a", tokenA); response.Code != http.StatusNotFound {
		t.Fatalf("revoked Link still provided current evidence: %d", response.Code)
	}
}
