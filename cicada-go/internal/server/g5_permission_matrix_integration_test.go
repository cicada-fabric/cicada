package server

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// Eight deterministic permission categories through the production HTTP handler,
// issued Fabric/Node credentials and real SQLite Guards. Synthetic session IDs
// are protocol inputs, never claims of an installed Runtime or model consumption.
// Generic search/export, model memory, account and physical isolation are NOT_RUN.
func TestG5PermissionMatrixHTTP(t *testing.T) {
	t.Run("unjoined_u_hidden", g5MatrixUnjoinedU)
	t.Run("sender_group_link_forgery", g5MatrixForgery)
	t.Run("cross_group_artifact", g5MatrixCrossGroupArtifact)
	t.Run("revoked_pending_queue", g5MatrixRevokedPendingQueue)
	t.Run("revoked_bilateral_link_pending_request", g5MatrixRevokedBilateralLinkPendingRequest)
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

func g5MatrixBindNode(t *testing.T, f *reviewPolicyHTTPFixture, ownerID, deviceID, nodeID string) string {
	t.Helper()
	token, digest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal("create synthetic Node credential")
	}
	code := sha256.Sum256([]byte("PUBLIC_SYNTHETIC_G5_NODE_BINDING:" + nodeID))
	codeDigest := hex.EncodeToString(code[:])
	if _, err := f.store.CreatePendingNodeDeviceBinding(nodeID, nodeID, digest,
		codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal("create synthetic Node binding request")
	}
	if _, err := f.store.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal("confirm synthetic Node binding")
	}
	return token
}

func g5MatrixRegisterEndpointKey(t *testing.T, f *reviewPolicyHTTPFixture, endpointID string) *e2ee.Identity {
	t.Helper()
	binding, err := f.store.GetSessionBindingForEndpoint(endpointID)
	if err != nil {
		t.Fatal("read synthetic endpoint binding")
	}
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("create synthetic endpoint key")
	}
	attestation, err := key.SignEndpointKeyAttestation(endpointID, binding.PrincipalID,
		binding.NodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal("sign synthetic endpoint key")
	}
	if _, err := f.store.RegisterEndpointKeyCandidate(endpointID, binding.PrincipalID,
		binding.ID, binding.Epoch, attestation); err != nil {
		t.Fatal("register synthetic endpoint key")
	}
	return key
}

func g5MatrixLinkMessageContext(link *store.CommunicationLink,
	manifest *store.CommunicationLinkKeyManifest, messageID, kind, requestID, replyTo string,
	reverse bool) e2ee.EndpointMessageContext {
	sender, receiver := manifest.Source, manifest.Target
	senderRevision, receiverRevision := link.ScopeSnapshot.SourceMembershipRevision,
		link.ScopeSnapshot.TargetMembershipRevision
	if reverse {
		sender, receiver = receiver, sender
		senderRevision, receiverRevision = receiverRevision, senderRevision
	}
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		SenderEndpointID: sender.EndpointID, SenderPrincipalID: sender.PrincipalID,
		SenderOwnerID: sender.OwnerID, SenderGroupID: sender.GroupID,
		SenderMembershipRevision: senderRevision, SenderBindingEpoch: sender.BindingEpoch,
		SenderKeyID: sender.KeyID, ReceiverEndpointID: receiver.EndpointID,
		ReceiverPrincipalID: receiver.PrincipalID, ReceiverOwnerID: receiver.OwnerID,
		ReceiverGroupID: receiver.GroupID, ReceiverMembershipRevision: receiverRevision,
		ReceiverBindingEpoch: receiver.BindingEpoch, ReceiverKeyID: receiver.KeyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
}

func g5MatrixSealLinkMessage(t *testing.T, link *store.CommunicationLink,
	manifest *store.CommunicationLinkKeyManifest, sender *e2ee.Identity,
	recipient e2ee.PublicIdentity, messageID, kind, requestID, replyTo string,
	reverse bool) []byte {
	t.Helper()
	ciphertext, err := e2ee.SealEndpointMessage(sender, recipient,
		g5MatrixLinkMessageContext(link, manifest, messageID, kind, requestID, replyTo, reverse),
		[]byte("PUBLIC_SYNTHETIC_G5_LINK_PAYLOAD"), 1)
	if err != nil {
		t.Fatal("seal synthetic Link message")
	}
	return ciphertext
}

func g5MatrixNodeHTTP(t *testing.T, f *reviewPolicyHTTPFixture,
	method, path, token string, body any) (int, []byte) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal("encode synthetic Node request")
		}
	}
	request, err := http.NewRequest(method, f.server.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("construct synthetic Node request")
	}
	request.Header.Set("Authorization", "CicadaNode "+token)
	request.Header.Set("Content-Type", "application/json")
	client := f.server.Client()
	client.Timeout = 3 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("synthetic Node HTTP request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		t.Fatal("synthetic Node HTTP response exceeded its bound")
	}
	if bytes.Contains(data, []byte(token)) {
		t.Fatal("Node HTTP response disclosed a credential")
	}
	return response.StatusCode, data
}

func g5MatrixAssertNoRelayRows(t *testing.T, databasePath, messageID, requestID string) {
	t.Helper()
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(databasePath), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal("open read-only synthetic Relay database")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatal("connect to read-only synthetic Relay database")
	}
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal("mark synthetic Relay audit connection read-only")
	}
	for _, check := range []struct {
		table string
		query string
		args  []any
	}{
		{"fabric_messages", `SELECT COUNT(*) FROM fabric_messages WHERE id=?`, []any{messageID}},
		{"relay_v2_message_payloads", `SELECT COUNT(*) FROM relay_v2_message_payloads WHERE message_id=?`, []any{messageID}},
		{"relay_v2_message_security", `SELECT COUNT(*) FROM relay_v2_message_security WHERE message_id=?`, []any{messageID}},
		{"relay_v2_requests", `SELECT COUNT(*) FROM relay_v2_requests WHERE message_id=? OR request_id=?`, []any{messageID, requestID}},
		{"relay_v2_inbox", `SELECT COUNT(*) FROM relay_v2_inbox WHERE message_id=?`, []any{messageID}},
		{"relay_v2_outbox", `SELECT COUNT(*) FROM relay_v2_outbox WHERE message_id=?`, []any{messageID}},
		{"relay_v2_delivery_attempts", `SELECT COUNT(*) FROM relay_v2_delivery_attempts WHERE message_id=? OR request_id=?`, []any{messageID, requestID}},
		{"relay_v2_receipts", `SELECT COUNT(*) FROM relay_v2_receipts WHERE message_id=?`, []any{messageID}},
		{"relay_v2_request_events", `SELECT COUNT(*) FROM relay_v2_request_events WHERE request_id=?`, []any{requestID}},
	} {
		var count int
		if err := db.QueryRow(check.query, check.args...).Scan(&count); err != nil {
			t.Fatalf("read-only count in %s failed: %v", check.table, err)
		}
		if count != 0 {
			t.Fatalf("denied operation left %d durable rows in %s", count, check.table)
		}
	}
}

func g5MatrixRevokedBilateralLinkPendingRequest(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	link := f.link
	sourceToken := g5MatrixBindNode(t, f, f.source.ownerID, f.source.deviceID, link.SourceNodeID)
	targetToken := g5MatrixBindNode(t, f, f.target.ownerID, f.target.deviceID, link.TargetNodeID)
	foreignToken := g5MatrixBindNode(t, f, f.foreign.ownerID, f.foreign.deviceID, "node_review_foreign")
	sourceKey := g5MatrixRegisterEndpointKey(t, f, link.SourceEndpointID)
	targetKey := g5MatrixRegisterEndpointKey(t, f, link.TargetEndpointID)
	manifest, err := f.store.GetCommunicationLinkKeyManifest(link.ID, link.SourceOwnerID)
	if err != nil || manifest == nil || manifest.Source.EndpointID != link.SourceEndpointID ||
		manifest.Target.EndpointID != link.TargetEndpointID {
		t.Fatal("read exact synthetic bilateral Link manifest")
	}
	expiresAt, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		t.Fatal("parse synthetic Link expiry")
	}
	for _, approval := range []struct {
		actor *reviewPolicyHTTPActor
		side  e2ee.OwnerLinkGrantSide
		name  string
	}{
		{actor: f.source, side: e2ee.OwnerLinkGrantSideSource, name: store.CommunicationLinkGrantSource},
		{actor: f.target, side: e2ee.OwnerLinkGrantSideTarget, name: store.CommunicationLinkGrantTarget},
	} {
		proof, err := approval.actor.ownerKey.SignOwnerLinkKeyGrant(approval.actor.ownerID,
			link.ID, manifest.ContractDigest, manifest.Digest, uint64(link.Version), approval.side,
			time.Now().UTC().Add(-time.Minute), expiresAt)
		if err != nil {
			t.Fatal("sign independent synthetic Link approval")
		}
		if _, err := f.store.RecordCommunicationLinkKeyGrant(approval.actor.ownerID,
			link.ID, approval.name, approval.actor.ownerKey.Public().ID, proof); err != nil {
			t.Fatal("record independent synthetic Link approval")
		}
	}
	for _, node := range []struct{ id, token string }{{link.SourceNodeID, sourceToken}, {link.TargetNodeID, targetToken}} {
		path := "/v2/relay/nodes/" + node.id + "/links/" + link.ID + "/authorization"
		code, data := g5MatrixNodeHTTP(t, f, http.MethodGet, path, node.token, nil)
		var bundle store.CommunicationLinkAuthorizationBundle
		if code != http.StatusOK || json.Unmarshal(data, &bundle) != nil ||
			bundle.Manifest.Digest != manifest.Digest || bundle.LinkState != store.CommunicationLinkProposed ||
			bundle.SourceGrant.CurrentStatus != store.CommunicationLinkKeyGrantAccepted ||
			bundle.TargetGrant.CurrentStatus != store.CommunicationLinkKeyGrantAccepted {
			t.Fatal("both current endpoint Nodes did not receive exact bilateral Link evidence")
		}
	}

	const messageID = "g5_matrix_link_pending_ask"
	const requestID = "g5_matrix_link_pending_request"
	askCiphertext := g5MatrixSealLinkMessage(t, link, manifest, sourceKey,
		manifest.Target.PublicIdentity, messageID, "REQUEST", requestID, "", false)
	ask := fabricpkg.NodeSealedLinkAskInput{
		LinkID: link.ID, MessageID: messageID, RequestID: requestID,
		IdempotencyKey: "idem_" + messageID, DataScope: "thread.message",
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
		Ciphertext: askCiphertext,
	}
	askPath := "/v2/relay/nodes/" + link.SourceNodeID + "/sealed/ask"
	code, data := g5MatrixNodeHTTP(t, f, http.MethodPost, askPath, sourceToken, ask)
	var accepted struct {
		MessageID string `json:"message_id"`
		RequestID string `json:"request_id"`
		State     string `json:"state"`
	}
	if code != http.StatusAccepted || json.Unmarshal(data, &accepted) != nil ||
		accepted.MessageID != messageID || accepted.RequestID != requestID || accepted.State != store.FabricRequestOpen {
		t.Fatal("bilaterally approved Link did not accept exact pending ASK")
	}
	before, err := f.store.GetRelaySealedV1(messageID)
	if err != nil || before == nil || before.Route.RequestID != requestID ||
		before.Route.SenderEndpointID != link.SourceEndpointID || before.Route.ReceiverEndpointID != link.TargetEndpointID ||
		!bytes.Equal(before.Ciphertext, askCiphertext) || before.Sequence <= 0 ||
		before.OutboxState != store.RelayReceiptAccepted {
		t.Fatal("accepted Link ASK did not persist its exact durable route and ciphertext")
	}

	checkParticipantStatus := func(nodeID, token, wantState string, wantCancelledAt bool) {
		t.Helper()
		path := "/v2/relay/nodes/" + nodeID + "/sealed/requests/" + requestID
		code, data := g5MatrixNodeHTTP(t, f, http.MethodGet, path, token, nil)
		var current store.FabricRequest
		if code != http.StatusOK || json.Unmarshal(data, &current) != nil ||
			current.RequestID != requestID || current.MessageID != messageID ||
			current.SenderEndpointID != link.SourceEndpointID || current.ReceiverEndpointID != link.TargetEndpointID ||
			current.SenderBindingID != manifest.Source.BindingID || current.SenderBindingEpoch != manifest.Source.BindingEpoch ||
			current.ReceiverBindingID != manifest.Target.BindingID || current.ReceiverBindingEpoch != manifest.Target.BindingEpoch ||
			current.State != wantState || (current.CancelledAt != "") != wantCancelledAt || current.ReplyMessageID != "" ||
			current.LateResultMessageID != "" || current.Body != "" || current.Message != nil || current.Metadata != nil {
			t.Fatal("participant request status was missing or exposed non-status fields")
		}
		g5MatrixNoLeak(t, data, "PUBLIC_SYNTHETIC_G5_LINK_PAYLOAD",
			base64.StdEncoding.EncodeToString(askCiphertext))
	}
	checkParticipantStatus(link.SourceNodeID, sourceToken, store.FabricRequestOpen, false)
	checkParticipantStatus(link.TargetNodeID, targetToken, store.FabricRequestOpen, false)

	if _, err := f.store.RevokeCommunicationLink(link.ID, link.SourceOwnerID,
		link.Version, "synthetic G5 bilateral Link revocation"); err != nil {
		t.Fatal("revoke synthetic bilateral Link")
	}
	for _, node := range []struct{ id, token string }{{link.SourceNodeID, sourceToken}, {link.TargetNodeID, targetToken}} {
		path := "/v2/relay/nodes/" + node.id + "/links/" + link.ID + "/authorization"
		code, data := g5MatrixNodeHTTP(t, f, http.MethodGet, path, node.token, nil)
		if code != http.StatusNotFound {
			t.Fatal("revoked Link still exposed current bilateral authorization")
		}
		g5MatrixNoLeak(t, data, link.ID, manifest.Source.KeyFingerprint,
			manifest.Target.KeyFingerprint, base64.StdEncoding.EncodeToString(askCiphertext))
	}
	claimPath := "/v2/relay/nodes/" + link.TargetNodeID + "/sealed/claim"
	code, data = g5MatrixNodeHTTP(t, f, http.MethodPost, claimPath, targetToken,
		fabricpkg.NodeClaimInput{ConsumerID: "g5_matrix_after_link_revoke", Limit: 10})
	var claimed struct {
		Deliveries []fabricpkg.NodeSealedDelivery `json:"deliveries"`
	}
	if code != http.StatusOK || json.Unmarshal(data, &claimed) != nil || len(claimed.Deliveries) != 0 {
		t.Fatal("pending Link ASK remained claimable after bilateral Link revocation")
	}
	g5MatrixNoLeak(t, data, messageID, requestID, base64.StdEncoding.EncodeToString(askCiphertext))

	checkParticipantStatus(link.SourceNodeID, sourceToken, store.FabricRequestCancelled, true)
	checkParticipantStatus(link.TargetNodeID, targetToken, store.FabricRequestCancelled, true)
	foreignStatusPath := "/v2/relay/nodes/node_review_foreign/sealed/requests/" + requestID
	code, data = g5MatrixNodeHTTP(t, f, http.MethodGet, foreignStatusPath, foreignToken, nil)
	if code != http.StatusNotFound {
		t.Fatal("unrelated owner-bound Node read Link request status")
	}
	g5MatrixNoLeak(t, data, requestID, messageID, link.ID,
		"PUBLIC_SYNTHETIC_G5_LINK_PAYLOAD", base64.StdEncoding.EncodeToString(askCiphertext))
	replyID := "g5_matrix_link_revoked_reply"
	replyCiphertext := g5MatrixSealLinkMessage(t, link, manifest, targetKey,
		manifest.Source.PublicIdentity, replyID, "REPLY", requestID, messageID, true)
	replyPath := "/v2/relay/nodes/" + link.TargetNodeID + "/sealed/reply"
	code, data = g5MatrixNodeHTTP(t, f, http.MethodPost, replyPath, targetToken,
		fabricpkg.NodeSealedLinkReplyInput{RequestID: requestID, MessageID: replyID,
			IdempotencyKey: "idem_" + replyID, DataScope: "thread.message", Ciphertext: replyCiphertext})
	if code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatal("revoked Link accepted a correlated Reply")
	}
	g5MatrixAssertNoRelayRows(t, f.databasePath, replyID, replyID)

	newMessageID, newRequestID := "g5_matrix_link_revoked_ask", "g5_matrix_link_revoked_request"
	newCiphertext := g5MatrixSealLinkMessage(t, link, manifest, sourceKey,
		manifest.Target.PublicIdentity, newMessageID, "REQUEST", newRequestID, "", false)
	newAsk := ask
	newAsk.MessageID, newAsk.RequestID, newAsk.IdempotencyKey = newMessageID, newRequestID, "idem_"+newMessageID
	newAsk.Ciphertext = newCiphertext
	code, data = g5MatrixNodeHTTP(t, f, http.MethodPost, askPath, sourceToken, newAsk)
	if code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatal("revoked Link accepted a new ASK")
	}
	g5MatrixAssertNoRelayRows(t, f.databasePath, newMessageID, newRequestID)
	if _, err := f.store.GetCommunicationLinkSealedRequestForNodeCredential(
		fabricpkg.HashSessionCredential(sourceToken), newRequestID); !errors.Is(err, store.ErrRelayRequestNotFound) {
		t.Fatal("denied revoked-Link ASK left a durable request row")
	}

	after, err := f.store.GetRelaySealedV1(messageID)
	if err != nil || after == nil || !reflect.DeepEqual(before.Route, after.Route) ||
		!reflect.DeepEqual(before.Security, after.Security) || !bytes.Equal(before.Ciphertext, after.Ciphertext) ||
		after.OutboxState != store.RelayInboxFailed || after.Sequence != before.Sequence {
		t.Fatal("revocation changed immutable Link ASK evidence or failed to close delivery")
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
