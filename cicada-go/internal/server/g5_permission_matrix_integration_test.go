package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// Seven deterministic permission categories through the production HTTP handler,
// issued Fabric/Node credentials and real SQLite Guards. Synthetic session IDs
// are protocol inputs, never claims of an installed Runtime or model consumption.
// Generic search/export, model memory, account and physical isolation are NOT_RUN.
func TestG5PermissionMatrixHTTP(t *testing.T) {
	t.Run("unjoined_u_hidden", g5MatrixUnjoinedU)
	t.Run("sender_group_link_forgery", g5MatrixForgery)
	t.Run("cross_group_artifact", g5MatrixCrossGroupArtifact)
	t.Run("revoked_pending_queue", g5MatrixRevokedPendingQueue)
	t.Run("revoked_read_surfaces", g5MatrixRevokedReads)
	// Reuse the existing complete enrollment/PQ packet/Monitor/Owner fixture:
	// authenticated Monitor cannot decide; pending row stays exact; Owner can.
	t.Run("monitor_not_user_approval", TestMonitorEndpointCannotMutateUserApprovalHTTP)
	t.Run("same_thread_group_selection_not_authority", g5MatrixMultiGroup)
}

func g5MatrixNoLeak(t *testing.T, data []byte, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		if marker != "" && bytes.Contains(data, []byte(marker)) {
			t.Fatal("denial or projection disclosed synthetic protected data")
		}
	}
}

func g5MatrixUnjoinedU(t *testing.T) {
	f := newFabricG5PrivacyFixture(t, false)
	uPrincipal, err := f.store.CreatePrincipal(store.Principal{ID: "principal_g5_matrix_unjoined",
		Kind: store.PrincipalKindAgent, OwnerID: f.groupA.OwnerPrincipalID,
		TrustDomainID: f.groupA.TrustDomainID, Name: "PUBLIC_SYNTHETIC_UNJOINED_U",
		Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal("create synthetic unjoined Principal")
	}
	// A retained migration-pending Endpoint has no Group association or binding.
	// This is stronger than querying an arbitrary nonexistent ID, but not live U.
	u, err := f.store.CreateEndpointV2(store.Endpoint{ID: "endpoint_g5_matrix_unjoined",
		Name: "PUBLIC_SYNTHETIC_UNJOINED_U", Harness: "codex", NativeSessionID: "native_g5_matrix_unjoined",
		MachineID: "node_g5_matrix_unjoined", Owner: f.groupA.OwnerPrincipalID,
		PrincipalID: uPrincipal.ID, Status: "online"})
	if err != nil || u == nil || u.MigrationState != store.EndpointMigrationPendingGroup {
		t.Fatal("unjoined migration fixture unavailable")
	}
	if _, err := f.store.GetMembershipByPrincipalGroup(uPrincipal.ID, f.groupA.ID); !errors.Is(err, store.ErrMembershipNotFound) {
		t.Fatal("U unexpectedly has a Group membership")
	}
	if _, err := f.store.GetActiveSessionBinding(u.ID); !errors.Is(err, store.ErrSessionBindingNotFound) {
		t.Fatal("U unexpectedly has a native binding")
	}
	for _, route := range []string{"members", "list"} {
		code, data := f.call(t, http.MethodGet, "/v2/fabric/"+route, f.groupA.ID, nil)
		var cards struct {
			Endpoints []fabricpkg.NetworkCard `json:"endpoints"`
		}
		if code != http.StatusOK || json.Unmarshal(data, &cards) != nil || len(cards.Endpoints) != 2 {
			t.Fatal("authorized Directory positive control failed")
		}
		g5MatrixNoLeak(t, data, u.ID, u.Name, u.NativeSessionID, u.MachineID)
	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		code, data := f.call(t, http.MethodPost, "/v2/fabric/"+route, f.groupA.ID,
			fabricpkg.ResolveInput{Query: f.peer.Endpoint.ID})
		var card fabricpkg.NetworkCard
		if code != http.StatusOK || json.Unmarshal(data, &card) != nil || card.EndpointID != f.peer.Endpoint.ID {
			t.Fatal("authorized lookup positive control failed")
		}
		for _, query := range []string{u.ID, u.NativeSessionID, u.Name} {
			code, data = f.call(t, http.MethodPost, "/v2/fabric/"+route, f.groupA.ID, fabricpkg.ResolveInput{Query: query})
			if code != http.StatusNotFound {
				t.Fatalf("unjoined lookup status=%d", code)
			}
			g5MatrixNoLeak(t, data, u.Name, u.NativeSessionID, u.MachineID, f.peer.Endpoint.NativeSessionID)
		}
	}
}

func g5MatrixPeerKey(t *testing.T, f *sameGroupSealedHTTPFixture) store.SameGroupSealedV1PeerKey {
	t.Helper()
	query := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.sourceEndpoint.ID},
		"target_endpoint_id": {f.targetEndpoint.ID}}
	response := f.call(t, http.MethodGet, "/v2/relay/nodes/"+f.sourceNodeID+"/group/sealed/peer-key?"+query.Encode(), f.sourceNodeAuth, nil)
	var peer store.SameGroupSealedV1PeerKey
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &peer) != nil ||
		peer.GroupID != f.groupID || peer.Sender.EndpointID != f.sourceEndpoint.ID || peer.Receiver.EndpointID != f.targetEndpoint.ID {
		t.Fatal("production Node credential and peer-key positive control failed")
	}
	return peer
}

func g5MatrixSend(t *testing.T, f *sameGroupSealedHTTPFixture, peer store.SameGroupSealedV1PeerKey, id string) map[string]any {
	t.Helper()
	return map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID,
		"target_endpoint_id": f.targetEndpoint.ID, "message_id": id,
		"data_scope": sameGroupSealedTestDataScope, "ciphertext": f.seal(t, peer, f.sourceKey, id, "SEND", "", "")}
}

func g5MatrixForgery(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	peer := g5MatrixPeerKey(t, f)
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/group/sealed/send"
	positiveID := "g5_matrix_authorized_send"
	positive := f.call(t, http.MethodPost, base, f.sourceNodeAuth, g5MatrixSend(t, f, peer, positiveID))
	persisted, err := f.persistence.GetRelaySealedV1(positiveID)
	if positive.Code != http.StatusAccepted || err != nil || persisted == nil || persisted.Route.SenderEndpointID != f.sourceEndpoint.ID ||
		persisted.Route.ReceiverEndpointID != f.targetEndpoint.ID || persisted.PayloadMode != store.RelayPayloadModeSealedV1 {
		t.Fatal("authorized SEND did not persist exact sealed route")
	}
	for _, test := range []struct {
		name, field, value string
		want               int
	}{
		{"sender", "source_endpoint_id", f.targetEndpoint.ID, http.StatusForbidden},
		{"group", "group_id", f.otherGroupID, http.StatusForbidden},
		{"extra_sender_claim", "sender_endpoint_id", f.targetEndpoint.ID, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := "g5_matrix_forged_" + test.name
			body := g5MatrixSend(t, f, peer, id)
			body[test.field] = test.value
			response := f.call(t, http.MethodPost, base, f.sourceNodeAuth, body)
			if response.Code != test.want {
				t.Fatalf("forgery status=%d want=%d", response.Code, test.want)
			}
			if row, err := f.persistence.GetRelaySealedV1(id); err == nil || row != nil {
				t.Fatal("rejected route left a durable sealed message")
			}
			g5MatrixNoLeak(t, response.Body.Bytes(), f.targetEndpoint.NativeSessionID, f.targetSessionToken)
		})
	}
	// A Node credential plus an arbitrary Link string is insufficient authority.
	id := "g5_matrix_unapproved_link"
	response := f.call(t, http.MethodPost, "/v2/relay/nodes/"+f.sourceNodeID+"/sealed/send", f.sourceNodeAuth,
		map[string]any{"link_id": "link_g5_matrix_unapproved", "message_id": id,
			"data_scope": sameGroupSealedTestDataScope, "ciphertext": []byte("PUBLIC_SYNTHETIC_OPAQUE_BYTES")})
	if response.Code != http.StatusForbidden {
		t.Fatalf("unapproved Link status=%d", response.Code)
	}
	if row, err := f.persistence.GetRelaySealedV1(id); err == nil || row != nil {
		t.Fatal("unapproved Link created a durable message")
	}
}

type g5MatrixArtifactFixture struct {
	f            *fabricG5PrivacyFixture
	membershipID string
	refA, refB   *store.ArtifactRefV2
	content      []byte
	digest       string
}

// Legacy Hub-backed plaintext Artifact fixtures prove ACLs, not peer E2EE or Hub blindness.
func newG5MatrixArtifactFixture(t *testing.T, multi bool) *g5MatrixArtifactFixture {
	t.Helper()
	f := newFabricG5PrivacyFixture(t, multi)
	actor, err := f.service.AuthenticateForGroup(f.caller.SessionToken, f.groupA.ID)
	if err != nil {
		t.Fatal("authenticate Artifact fixture")
	}
	membership, err := f.store.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal("read Artifact membership")
	}
	grants := append(append([]string(nil), membership.Grants...), "artifact.read")
	if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, grants, membership.Authorization, membership.Version); err != nil {
		t.Fatal("authorize Group A Artifact reader")
	}
	content := []byte("PUBLIC_SYNTHETIC_G5_MATRIX_ARTIFACT")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fixture.txt"), content, 0600); err != nil {
		t.Fatal("write public synthetic content")
	}
	workspace, err := f.store.CreateWorkspace("workspace_g5_matrix", "", root, "synthetic", "g5")
	if err != nil {
		t.Fatal("create Artifact workspace")
	}
	digest := sha256.Sum256(content)
	digestHex := hex.EncodeToString(digest[:])
	legacy, err := f.store.CreateArtifact(store.Artifact{ID: "artifact_g5_matrix", WorkspaceID: workspace.ID,
		Name: "PUBLIC_SYNTHETIC_G5_MATRIX_NAME", Path: "fixture.txt", Kind: "synthetic", Digest: digestHex, Status: "available"})
	if err != nil {
		t.Fatal("seed Artifact")
	}
	create := func(id, group string) *store.ArtifactRefV2 {
		t.Helper()
		ref, err := f.store.CreateArtifactRefV2(store.ArtifactRefV2Input{ID: id, ArtifactID: legacy.ID,
			GroupID: group, WorkspaceID: workspace.ID, ProducerPrincipalID: actor.PrincipalID,
			ProducerEndpointID: actor.EndpointID, Digest: digestHex, RelativePath: "fixture.txt",
			Summary: "PUBLIC_SYNTHETIC_G5_MATRIX_SUMMARY", Scopes: []string{store.ArtifactRefV2ScopeMetadata,
				store.ArtifactRefV2ScopeSummary, store.ArtifactRefV2ScopeDigest, store.ArtifactRefV2ScopeContent}})
		if err != nil {
			t.Fatal("seed scoped Artifact ref")
		}
		return ref
	}
	return &g5MatrixArtifactFixture{f: f, membershipID: actor.MembershipID,
		refA: create("ref_g5_matrix_a", f.groupA.ID), refB: create("ref_g5_matrix_b", f.groupB.ID), content: content, digest: digestHex}
}

func g5MatrixCrossGroupArtifact(t *testing.T) {
	a := newG5MatrixArtifactFixture(t, false)
	f := a.f
	code, data := f.call(t, http.MethodGet, "/v2/artifacts/"+a.refA.ID+"?scope=content", f.groupA.ID, nil)
	var authorized store.ArtifactRefV2Authorized
	if code != http.StatusOK || json.Unmarshal(data, &authorized) != nil || !bytes.Equal(authorized.Content, a.content) {
		t.Fatal("same-Group Artifact content positive control failed")
	}
	for _, scope := range []string{"metadata", "summary", "digest", "content"} {
		code, data := f.call(t, http.MethodGet, "/v2/artifacts/"+a.refB.ID+"?scope="+scope, f.groupA.ID, nil)
		if code != http.StatusForbidden {
			t.Fatalf("cross-Group Artifact scope %s status=%d", scope, code)
		}
		g5MatrixNoLeak(t, data, string(a.content), a.digest, "PUBLIC_SYNTHETIC_G5_MATRIX_NAME", "PUBLIC_SYNTHETIC_G5_MATRIX_SUMMARY")
	}
}

func g5MatrixRevokedPendingQueue(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	peer := g5MatrixPeerKey(t, f)
	id := "g5_matrix_pending_before_revoke"
	response := f.call(t, http.MethodPost, "/v2/relay/nodes/"+f.sourceNodeID+"/group/sealed/send", f.sourceNodeAuth, g5MatrixSend(t, f, peer, id))
	before, err := f.persistence.GetRelaySealedV1(id)
	if response.Code != http.StatusAccepted || err != nil || before == nil || before.Route.ReceiverEndpointID != f.targetEndpoint.ID ||
		before.Sequence <= 0 || before.OutboxState != store.RelayReceiptAccepted {
		t.Fatal("pre-revoke durable pending message missing")
	}
	// GetRelaySealedV1 reads the exact persisted inbox sequence and outbox state.
	// ListRelayInbox intentionally excludes sealed rows; no plaintext fallback.
	membership, err := f.persistence.GetMembershipByPrincipalGroup(f.targetEndpoint.PrincipalID, f.groupID)
	if err != nil {
		t.Fatal("read recipient membership")
	}
	if _, err := f.persistence.RevokeMembership(membership.ID, "synthetic G5 queue revoke"); err != nil {
		t.Fatal("revoke recipient")
	}
	response = f.call(t, http.MethodPost, "/v2/relay/nodes/"+f.targetNodeID+"/group/sealed/claim", f.targetNodeAuth,
		map[string]any{"consumer_id": "g5_matrix_after_revoke", "limit": 10})
	var claimed struct {
		Deliveries []store.RelaySealedV1DeliveryAttempt `json:"deliveries"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &claimed) != nil || len(claimed.Deliveries) != 0 {
		t.Fatal("revoked queued message remained deliverable")
	}
	g5MatrixNoLeak(t, response.Body.Bytes(), id, string(before.Ciphertext), f.targetEndpoint.NativeSessionID)
	after, err := f.persistence.GetRelaySealedV1(id)
	if err != nil || after == nil || !reflect.DeepEqual(before.Route, after.Route) || !bytes.Equal(before.Ciphertext, after.Ciphertext) {
		t.Fatal("revocation erased or rewrote original durable evidence")
	}
	receipts, err := f.persistence.ListRelayReceipts(id, 10)
	if err != nil {
		t.Fatal("read durable acceptance receipts")
	}
	for _, receipt := range receipts {
		if receipt.Layer == fabricpkg.ReceiptCodexQueueAccepted || receipt.Layer == fabricpkg.ReceiptNativeThreadResumed {
			t.Fatal("revoked pending row acquired a native acceptance receipt")
		}
	}
}

func g5MatrixRevokedReads(t *testing.T) {
	a := newG5MatrixArtifactFixture(t, false)
	f := a.f
	// Check each existing read alias is wired before revoke, not a route-404 test.
	paths := []string{"/v2/fabric/whoami", "/v2/fabric/members", "/v2/fabric/list?node_id=" + url.QueryEscape(f.peer.Endpoint.MachineID)}
	for _, prefix := range []string{"/v2/artifacts", "/v2/artifact-refs", "/v2/fabric/artifacts", "/v2/fabric/artifact-refs"} {
		paths = append(paths, prefix)
		for _, suffix := range []string{"", "/read"} {
			for _, scope := range []string{"metadata", "summary", "digest", "content"} {
				paths = append(paths, prefix+"/"+a.refA.ID+suffix+"?scope="+scope)
			}
		}
	}
	for _, path := range paths {
		code, _ := f.call(t, http.MethodGet, path, f.groupA.ID, nil)
		if code != http.StatusOK {
			t.Fatalf("read positive control status=%d", code)
		}
	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		code, data := f.call(t, http.MethodPost, "/v2/fabric/"+route, f.groupA.ID, fabricpkg.ResolveInput{Query: f.peer.Endpoint.ID})
		var card fabricpkg.NetworkCard
		if code != http.StatusOK || json.Unmarshal(data, &card) != nil || card.EndpointID != f.peer.Endpoint.ID {
			t.Fatal("pre-revoke lookup positive control failed")
		}
	}
	if _, err := f.store.RevokeMembership(a.membershipID, "synthetic G5 reads revoke"); err != nil {
		t.Fatal("revoke reader")
	}
	for _, path := range paths {
		code, data := f.call(t, http.MethodGet, path, f.groupA.ID, nil)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("revoked read status=%d", code)
		}
		g5MatrixNoLeak(t, data, string(a.content), a.digest, a.refA.ID, f.peer.Endpoint.NativeSessionID, "PUBLIC_SYNTHETIC_G5_MATRIX_SUMMARY")
	}
	for _, route := range []string{"find", "resolve", "inspect"} {
		code, data := f.call(t, http.MethodPost, "/v2/fabric/"+route, f.groupA.ID, fabricpkg.ResolveInput{Query: f.peer.Endpoint.ID})
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("revoked lookup status=%d", code)
		}
		g5MatrixNoLeak(t, data, f.peer.Endpoint.NativeSessionID, f.peer.Endpoint.MachineID)
	}
}

func g5MatrixMultiGroup(t *testing.T) {
	a := newG5MatrixArtifactFixture(t, true)
	f := a.f
	actorA, err := f.service.AuthenticateForGroup(f.caller.SessionToken, f.groupA.ID)
	if err != nil {
		t.Fatal("authenticate Group A")
	}
	actorB, err := f.service.AuthenticateForGroup(f.caller.SessionToken, f.groupB.ID)
	if err != nil || actorA.EndpointID != actorB.EndpointID || actorA.BindingID != actorB.BindingID ||
		actorA.BindingEpoch != actorB.BindingEpoch || actorA.GroupID == actorB.GroupID {
		t.Fatal("second Group did not preserve one exact synthetic SessionBinding")
	}
	code, _ := f.call(t, http.MethodGet, "/v2/fabric/members", f.groupB.ID, nil)
	if code != http.StatusOK {
		t.Fatal("joined second Group directory positive control failed")
	}
	for _, ref := range []*store.ArtifactRefV2{a.refA, a.refB} {
		code, data := f.call(t, http.MethodGet, "/v2/artifacts/"+ref.ID+"?scope=content", f.groupB.ID, nil)
		if code != http.StatusForbidden {
			t.Fatalf("Group header borrowed another Group grant: %d", code)
		}
		g5MatrixNoLeak(t, data, string(a.content), a.digest)
	}
	// Grant B its own Artifact read permission, then prove object scope still fences A.
	membershipB, err := f.store.GetMembership(actorB.MembershipID)
	if err != nil {
		t.Fatal("read second Group membership")
	}
	grantsB := append(append([]string(nil), membershipB.Grants...), "artifact.read")
	if _, err := f.store.UpdateMembershipAuthorization(membershipB.ID, membershipB.Roles, grantsB, membershipB.Authorization, membershipB.Version); err != nil {
		t.Fatal("authorize second Group Artifact positive control")
	}
	code, data := f.call(t, http.MethodGet, "/v2/artifacts/"+a.refB.ID+"?scope=content", f.groupB.ID, nil)
	var ownB store.ArtifactRefV2Authorized
	if code != http.StatusOK || json.Unmarshal(data, &ownB) != nil || !bytes.Equal(ownB.Content, a.content) {
		t.Fatal("second Group own Artifact positive control failed")
	}
	code, data = f.call(t, http.MethodGet, "/v2/artifacts/"+a.refA.ID+"?scope=content", f.groupB.ID, nil)
	if code != http.StatusForbidden {
		t.Fatal("second Group Artifact grant crossed object Group")
	}
	g5MatrixNoLeak(t, data, string(a.content), a.digest)
	code, data = f.call(t, http.MethodGet, "/v2/artifacts/"+a.refA.ID+"?scope=content", f.groupA.ID, nil)
	var result store.ArtifactRefV2Authorized
	if code != http.StatusOK || json.Unmarshal(data, &result) != nil || !bytes.Equal(result.Content, a.content) {
		t.Fatal("Group A grant lost its authorized positive control")
	}
}
