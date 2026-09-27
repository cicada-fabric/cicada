package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestRelayNodeGroupBroadcastSnapshotIsOwnerBoundAndImmutable(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	grantSameGroupAuthorization(t, f.persistence, f.sourceEndpoint.PrincipalID, f.groupID, "message.broadcast")
	grantSameGroupAuthorization(t, f.persistence, f.targetEndpoint.PrincipalID, f.groupID, "message.receive")
	// Membership revisions are part of the owner-approved key manifests.
	// Refresh both proofs after making the broadcast and receive grants explicit.
	refreshSameGroupSealedTestEndpointKeyGrant(t, f.persistence, f.ownerID, f.groupID,
		f.ownerKeyID, f.ownerIdentity, f.sourceEndpoint)
	refreshSameGroupSealedTestEndpointKeyGrant(t, f.persistence, f.ownerID, f.groupID,
		f.ownerKeyID, f.ownerIdentity, f.targetEndpoint)

	fabricOnly, ok := f.handler.(*Handler)
	if !ok || fabricOnly.control != nil {
		t.Fatal("test handler must have Fabric enabled with Control business disabled")
	}

	path := "/v2/relay/nodes/" + f.sourceNodeID + "/group/broadcast/snapshot"
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
		f.handler.ServeHTTP(response, request)
		return response
	}
	body := func(groupID, broadcastID string) []byte {
		t.Helper()
		encoded, err := json.Marshal(map[string]string{
			"group_id": groupID, "broadcast_id": broadcastID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	if response := call(path, "Bearer invalid", f.sourceSessionToken, body(f.groupID, "bc_http_owner_bound")); response.Code != http.StatusUnauthorized || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("non-Node bearer reached broadcast snapshot: %d %s", response.Code, response.Body.String())
	}
	if response := call("/v2/relay/nodes/"+f.sourceNodeID+"/group/broadcast/snapshot",
		f.targetNodeAuth, f.sourceSessionToken, body(f.groupID, "bc_http_forged_node")); response.Code != http.StatusForbidden || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Node credential crossed path Node scope: %d %s", response.Code, response.Body.String())
	}
	if response := call(path, f.sourceNodeAuth, "", body(f.groupID, "bc_http_missing_session")); response.Code != http.StatusUnauthorized || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing Session credential authorized snapshot: %d %s", response.Code, response.Body.String())
	}
	if response := call(path, f.sourceNodeAuth, f.targetSessionToken, body(f.groupID, "bc_http_forged_sender")); response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("a Session bound to another Node was accepted or enumerated: %d %s headers=%v",
			response.Code, response.Body.String(), response.Header())
	}
	if response := call(path, f.sourceNodeAuth, f.sourceSessionToken,
		[]byte(`{"group_id":"`+f.groupID+`","broadcast_id":"bc_http_forged_sender","sender_endpoint_id":"`+f.targetEndpoint.ID+`"}`)); response.Code != http.StatusBadRequest {
		t.Fatalf("caller-supplied sender was accepted: %d %s", response.Code, response.Body.String())
	}
	if response := call(path, f.sourceNodeAuth, f.sourceSessionToken, body(f.otherGroupID, "bc_http_forged_group")); response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthorized Group was accepted or enumerated: %d %s headers=%v",
			response.Code, response.Body.String(), response.Header())
	}

	first := call(path, f.sourceNodeAuth, f.sourceSessionToken, body(f.groupID, "bc_http_immutable"))
	if first.Code != http.StatusOK || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("authorized snapshot failed: %d %s headers=%v", first.Code, first.Body.String(), first.Header())
	}
	type snapshotResponse struct {
		HubID    string                             `json:"hub_id"`
		Snapshot store.SameGroupBroadcastV2Snapshot `json:"snapshot"`
	}
	expectedHubID, err := f.persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	var firstResponse snapshotResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	initial := firstResponse.Snapshot
	if firstResponse.HubID != expectedHubID {
		t.Fatalf("snapshot did not carry the Store-pinned Hub identity: got=%q want=%q", firstResponse.HubID, expectedHubID)
	}
	if initial.BroadcastID != "bc_http_immutable" || initial.GroupID != f.groupID ||
		initial.Source.EndpointID != f.sourceEndpoint.ID || initial.Source.NativeSessionID == "" ||
		len(initial.Recipients) != 1 || initial.Recipients[0].EndpointID != f.targetEndpoint.ID ||
		bytes.Contains(first.Body.Bytes(), []byte(f.sourceSessionToken)) {
		t.Fatalf("snapshot did not preserve its derived source and exact roster: %#v", initial)
	}

	// Add a newly eligible Group member after capture. Reusing the same ID must
	// return the stored roster without expanding it to this new Endpoint.
	extra, err := f.service.Join(fabric.JoinInput{
		GroupID: f.groupID, PrincipalName: "same-group-late-recipient",
		EndpointName: "same-group-late-recipient", Harness: "codex",
		NativeSessionID: "native-same-group-late-recipient", NodeID: f.targetNodeID,
		LeaseOwner: "lease-same-group-late-recipient",
	})
	if err != nil {
		t.Fatal(err)
	}
	grantSameGroupAuthorization(t, f.persistence, extra.Endpoint.PrincipalID, f.groupID, "message.receive")
	addAndGrantSameGroupSealedTestEndpointKey(t, f.persistence, f.ownerID, f.groupID,
		f.ownerKeyID, f.ownerIdentity, extra.Endpoint)
	retry := call(path, f.sourceNodeAuth, f.sourceSessionToken, body(f.groupID, "bc_http_immutable"))
	if retry.Code != http.StatusOK {
		t.Fatalf("same BroadcastID retry failed: %d %s", retry.Code, retry.Body.String())
	}
	var retryResponse snapshotResponse
	if err := json.Unmarshal(retry.Body.Bytes(), &retryResponse); err != nil {
		t.Fatal(err)
	}
	repeated := retryResponse.Snapshot
	if retryResponse.HubID != expectedHubID {
		t.Fatalf("retry returned an unexpected Hub identity: got=%q want=%q", retryResponse.HubID, expectedHubID)
	}
	if repeated.SnapshotDigest != initial.SnapshotDigest || len(repeated.Recipients) != 1 ||
		repeated.Recipients[0].EndpointID != f.targetEndpoint.ID {
		t.Fatalf("same BroadcastID expanded or changed its persisted roster: initial=%#v retry=%#v", initial, repeated)
	}
}

func grantSameGroupAuthorization(t *testing.T, persistence *store.Store, principalID, groupID, action string) {
	t.Helper()
	membership, err := persistence.GetMembershipByPrincipalGroup(principalID, groupID)
	if err != nil {
		t.Fatal(err)
	}
	grants := append([]string(nil), membership.Grants...)
	for _, existing := range grants {
		if existing == action {
			return
		}
	}
	grants = append(grants, action)
	if _, err := persistence.UpdateMembershipAuthorization(membership.ID, membership.Roles,
		grants, membership.Authorization, membership.Version); err != nil {
		t.Fatal(err)
	}
}

func refreshSameGroupSealedTestEndpointKeyGrant(t *testing.T, persistence *store.Store,
	ownerID, groupID, ownerKeyID string, ownerIdentity *e2ee.Identity, endpoint store.Endpoint) {
	t.Helper()
	manifest, err := persistence.PreviewGroupEndpointKeyGrant(ownerID, groupID, endpoint.ID,
		ownerKeyID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerIdentity.SignOwnerLinkKeyGrant(ownerID,
		store.GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
		uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.AcceptGroupEndpointKeyGrant(ownerID, groupID, endpoint.ID,
		ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
}
