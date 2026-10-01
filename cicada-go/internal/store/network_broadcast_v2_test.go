package store

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func enableNetworkBroadcastForTaskFixture(t *testing.T, f networkTaskFixture) {
	t.Helper()
	for _, endpoint := range []networkTaskTestEndpoint{f.publisher, f.reader, f.otherReader} {
		var grantsJSON string
		if err := f.s.db.QueryRow(`SELECT grants_json FROM network_memberships_v2
WHERE network_id=? AND principal_id=?`, endpoint.scope.NetworkID,
			endpoint.scope.PrincipalID).Scan(&grantsJSON); err != nil {
			t.Fatal(err)
		}
		var grants []string
		if err := json.Unmarshal([]byte(grantsJSON), &grants); err != nil {
			t.Fatal(err)
		}
		grants = append(grants, "broadcast.publish", "broadcast.receive")
		encoded, err := json.Marshal(grants)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`UPDATE network_memberships_v2 SET grants_json=?
WHERE network_id=? AND principal_id=?`, string(encoded), endpoint.scope.NetworkID,
			endpoint.scope.PrincipalID); err != nil {
			t.Fatal(err)
		}
		manifest, err := f.s.PreviewNetworkCollaborationKeyGrant("owner_a",
			endpoint.scope.NetworkID, endpoint.scope.EndpointID,
			e2ee.NetworkCollaborationPurposeBroadcast, f.owner.Public().ID)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := f.owner.SignOwnerNetworkCollaborationKeyGrant(
			e2ee.NetworkCollaborationPurposeBroadcast, manifest.Key.HubID,
			endpoint.scope.NetworkID, endpoint.scope.EndpointID, "owner_a", manifest.Digest,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.AcceptNetworkCollaborationKeyGrant("owner_a",
			endpoint.scope.NetworkID, endpoint.scope.EndpointID,
			e2ee.NetworkCollaborationPurposeBroadcast, proof); err != nil {
			t.Fatal(err)
		}
	}
}

func sendNetworkBroadcastFixture(t *testing.T, f networkTaskFixture,
	endpoint networkTaskTestEndpoint, messageID string, sequence uint64) {
	t.Helper()
	bundle, err := f.s.NetworkCollaborationPeerKey(f.publisher.scope,
		endpoint.scope.EndpointID, e2ee.NetworkCollaborationPurposeBroadcast)
	if err != nil {
		t.Fatal(err)
	}
	context, err := networkCollaborationContext(bundle, messageID)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := e2ee.SealNetworkCollaborationMessage(f.publisher.key,
		endpoint.key.Public(), *context, []byte("synthetic private broadcast body"), sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.EnqueueNetworkCollaborationSealedSend(NetworkCollaborationSendInput{
		Scope: f.publisher.scope, NodeCredentialDigest: f.credential,
		Purpose:          e2ee.NetworkCollaborationPurposeBroadcast,
		TargetEndpointID: endpoint.scope.EndpointID, MessageID: messageID,
		Ciphertext: ciphertext,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkBroadcastFixedSnapshotSealedFanoutAndPerReaderState(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	enableNetworkBroadcastForTaskFixture(t, f)
	const broadcastID = "nbroadcast_synthetic_team_001122334455"
	snapshot, err := f.s.PreviewNetworkBroadcastRecipients(f.publisher.scope)
	if err != nil || len(snapshot.Recipients) != 2 {
		t.Fatalf("fixed eligible recipient snapshot: %+v %v", snapshot, err)
	}
	if snapshot.Recipients[0].EndpointID == snapshot.Recipients[1].EndpointID {
		t.Fatalf("snapshot contains duplicate Endpoint: %+v", snapshot.Recipients)
	}
	endpoints := map[string]networkTaskTestEndpoint{
		f.reader.scope.EndpointID:      f.reader,
		f.otherReader.scope.EndpointID: f.otherReader,
	}
	input := NetworkBroadcastPublishInput{BroadcastID: broadcastID,
		SnapshotDigest: snapshot.SnapshotDigest,
		ExpiresAt:      time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
	for i, recipient := range snapshot.Recipients {
		messageID := broadcastID + ":reader:reader" + strconv.Itoa(i+1)
		sendNetworkBroadcastFixture(t, f, endpoints[recipient.EndpointID], messageID, uint64(i+1))
		input.Recipients = append(input.Recipients, NetworkBroadcastPublishRecipient{
			EndpointID: recipient.EndpointID, MessageID: messageID})
	}
	claim := NetworkDirectClaimInput{NodeID: "node_network_task",
		ConsumerID: "synthetic-broadcast-consumer", Limit: 10,
		CredentialDigest: f.credential}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claim)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("unregistered broadcast routes were consumed: %+v %v", deliveries, err)
	}
	for _, item := range input.Recipients {
		var state string
		var attempts, nodeReceived int
		if err := f.s.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`, item.MessageID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE message_id=?`, item.MessageID).Scan(&attempts); err != nil {
			t.Fatal(err)
		}
		if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE message_id=? AND layer=?`,
			item.MessageID, RelayReceiptNodeReceived).Scan(&nodeReceived); err != nil {
			t.Fatal(err)
		}
		if state != RelayInboxReady || attempts != 0 || nodeReceived != 0 {
			t.Fatalf("pre-metadata broadcast route consumed: state=%s attempts=%d receipt=%d",
				state, attempts, nodeReceived)
		}
	}
	published, err := f.s.PublishNetworkBroadcast(f.publisher.scope, input)
	if err != nil || published.Status != "PUBLISHED" || published.RecipientCount != 2 || len(published.Recipients) != 2 {
		t.Fatalf("broadcast metadata commit: %+v %v", published, err)
	}
	retry, err := f.s.PublishNetworkBroadcast(f.publisher.scope, input)
	if err != nil || retry.ID != broadcastID || len(retry.Recipients) != 2 {
		t.Fatalf("lost publish response retry: %+v %v", retry, err)
	}
	deliveries, err = f.s.ClaimNetworkDirectSealedInbox(claim)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("committed broadcast routes did not deliver: %+v %v", deliveries, err)
	}
	for _, delivery := range deliveries {
		authorization, err := f.s.AuthorizeClaimedNetworkDirectDelivery(
			f.credential, delivery.MessageID, delivery.AttemptID)
		if err != nil || authorization.NetworkBroadcast == nil ||
			authorization.NetworkBroadcast.BroadcastID != broadcastID ||
			authorization.CollaborationContext == nil ||
			authorization.CollaborationContext.Purpose != e2ee.NetworkCollaborationPurposeBroadcast ||
			authorization.NetworkTask != nil {
			t.Fatalf("fresh Broadcast delivery authorization: %+v %v", authorization, err)
		}
		if _, err := f.s.RecordNetworkDirectReceipt(f.credential, RelayReceipt{
			AttemptID: delivery.AttemptID, MessageID: delivery.MessageID, Digest: delivery.Digest,
			TargetEndpointID: delivery.RecipientEndpointID, BindingID: authorization.BindingID,
			BindingEpoch: authorization.BindingEpoch, Layer: RelayReceiptNodeReceived,
		}); err != nil {
			t.Fatalf("purpose-bound Broadcast receipt: %v", err)
		}
	}
	publisherView, err := f.s.GetNetworkBroadcast(f.publisher.scope, broadcastID)
	if err != nil || publisherView.RecipientCount != 2 || len(publisherView.Recipients) != 2 {
		t.Fatalf("publisher per-reader status view: %+v %v", publisherView, err)
	}
	readerView, err := f.s.GetNetworkBroadcast(f.reader.scope, broadcastID)
	if err != nil || readerView.Recipients != nil || readerView.RecipientCount != 0 || readerView.DeliveryState != RelayInboxClaimed {
		t.Fatalf("reader was shown the recipient roster or wrong state: %+v %v", readerView, err)
	}
}

func TestNetworkBroadcastSnapshotChangeRejectsMetadataCommit(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	enableNetworkBroadcastForTaskFixture(t, f)
	const broadcastID = "nbroadcast_synthetic_changed_001122334455"
	snapshot, err := f.s.PreviewNetworkBroadcastRecipients(f.publisher.scope)
	if err != nil || len(snapshot.Recipients) != 2 {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	endpoints := map[string]networkTaskTestEndpoint{
		f.reader.scope.EndpointID:      f.reader,
		f.otherReader.scope.EndpointID: f.otherReader,
	}
	input := NetworkBroadcastPublishInput{BroadcastID: broadcastID,
		SnapshotDigest: snapshot.SnapshotDigest,
		ExpiresAt:      time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
	for i, recipient := range snapshot.Recipients {
		messageID := broadcastID + ":reader:changed" + strconv.Itoa(i+1)
		sendNetworkBroadcastFixture(t, f, endpoints[recipient.EndpointID], messageID, uint64(i+1))
		input.Recipients = append(input.Recipients, NetworkBroadcastPublishRecipient{
			EndpointID: recipient.EndpointID, MessageID: messageID})
	}
	if err := f.s.LeaveEndpointNetwork("net_task", f.otherReader.scope.EndpointID,
		f.otherReader.scope.EndpointMembershipRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PublishNetworkBroadcast(f.publisher.scope, input); !errors.Is(err, ErrNetworkBroadcastSnapshotChanged) {
		t.Fatalf("metadata committed against changed recipient snapshot: %v", err)
	}
	var broadcasts, readyRoutes int
	if err := f.s.db.QueryRow(`SELECT count(*) FROM network_broadcasts_v2 WHERE id=?`, broadcastID).Scan(&broadcasts); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM network_direct_message_routes_v2 route
JOIN relay_v2_inbox inbox ON inbox.message_id=route.message_id
WHERE route.message_id LIKE ? AND inbox.state='READY'`, broadcastID+":reader:%").Scan(&readyRoutes); err != nil {
		t.Fatal(err)
	}
	if broadcasts != 0 || readyRoutes != 2 {
		t.Fatalf("rejected metadata changed existing SENDs: broadcasts=%d ready_routes=%d", broadcasts, readyRoutes)
	}
}

func TestNetworkBroadcastUnregisteredRouteExpiresAfterBound(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	enableNetworkBroadcastForTaskFixture(t, f)
	const broadcastID = "nbroadcast_synthetic_expired_001122334455"
	snapshot, err := f.s.PreviewNetworkBroadcastRecipients(f.publisher.scope)
	if err != nil || len(snapshot.Recipients) != 2 {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	messageID := broadcastID + ":reader:expired1"
	sendNetworkBroadcastFixture(t, f, f.reader, messageID, 1)
	if _, err := f.s.db.Exec(`UPDATE network_direct_message_routes_v2 SET created_at=? WHERE message_id=?`,
		time.Now().UTC().Add(-25*time.Hour).Format(time.RFC3339Nano), messageID); err != nil {
		t.Fatal(err)
	}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(NetworkDirectClaimInput{
		NodeID: "node_network_task", ConsumerID: "synthetic-broadcast-expiry", Limit: 10,
		CredentialDigest: f.credential})
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("expired unregistered broadcast route delivered: %+v %v", deliveries, err)
	}
	var state, failure string
	if err := f.s.db.QueryRow(`SELECT inbox.state,receipt.error
FROM relay_v2_inbox inbox JOIN relay_v2_receipts receipt
ON receipt.message_id=inbox.message_id WHERE inbox.message_id=? AND receipt.layer=?`,
		messageID, RelayReceiptFailed).Scan(&state, &failure); err != nil {
		t.Fatal(err)
	}
	if state != RelayInboxFailed || failure != "BROADCAST_EXPIRED" {
		t.Fatalf("expired broadcast route state=%s failure=%q", state, failure)
	}
}

func TestNetworkBroadcastOwnerGrantRevocationAndReapprovalDoNotReviveQueuedRoute(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	enableNetworkBroadcastForTaskFixture(t, f)
	const broadcastID = "nbroadcast_synthetic_revoke_001122334455"
	snapshot, err := f.s.PreviewNetworkBroadcastRecipients(f.publisher.scope)
	if err != nil || len(snapshot.Recipients) != 2 {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	endpoints := map[string]networkTaskTestEndpoint{
		f.reader.scope.EndpointID:      f.reader,
		f.otherReader.scope.EndpointID: f.otherReader,
	}
	input := NetworkBroadcastPublishInput{BroadcastID: broadcastID,
		SnapshotDigest: snapshot.SnapshotDigest,
		ExpiresAt:      time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)}
	messageByEndpoint := make(map[string]string, len(snapshot.Recipients))
	for i, recipient := range snapshot.Recipients {
		messageID := broadcastID + ":reader:revoke" + strconv.Itoa(i+1)
		sendNetworkBroadcastFixture(t, f, endpoints[recipient.EndpointID], messageID, uint64(i+1))
		input.Recipients = append(input.Recipients, NetworkBroadcastPublishRecipient{
			EndpointID: recipient.EndpointID, MessageID: messageID})
		messageByEndpoint[recipient.EndpointID] = messageID
	}
	if _, err := f.s.PublishNetworkBroadcast(f.publisher.scope, input); err != nil {
		t.Fatalf("publish: %v", err)
	}

	oldGrant, err := f.s.GetNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeBroadcast)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := f.s.RevokeNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeBroadcast, oldGrant.Revision)
	if err != nil || revoked.State != "revoked" {
		t.Fatalf("revoke receiver key grant: %+v %v", revoked, err)
	}
	manifest, err := f.s.PreviewNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeBroadcast, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.owner.SignOwnerNetworkCollaborationKeyGrant(
		e2ee.NetworkCollaborationPurposeBroadcast, manifest.Key.HubID, "net_task",
		f.reader.scope.EndpointID, "owner_a", manifest.Digest,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := f.s.AcceptNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeBroadcast, proof)
	if err != nil || newGrant.Revision <= revoked.Revision {
		t.Fatalf("fresh approval did not create a new fence: old=%+v new=%+v err=%v", revoked, newGrant, err)
	}
	tx, err := f.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	guardErr := networkGuardCollaborationMessageTx(tx, messageByEndpoint[f.reader.scope.EndpointID],
		"net_task", e2ee.NetworkCollaborationPurposeBroadcast, time.Now().UTC())
	_ = tx.Rollback()
	if !errors.Is(guardErr, ErrNetworkPermission) {
		t.Fatalf("fresh purpose approval revived old route: %v", guardErr)
	}

	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(NetworkDirectClaimInput{
		NodeID: "node_network_task", ConsumerID: "synthetic-broadcast-revocation", Limit: 10,
		CredentialDigest: f.credential})
	if err != nil {
		t.Fatal(err)
	}
	for _, delivery := range deliveries {
		if delivery.MessageID == messageByEndpoint[f.reader.scope.EndpointID] {
			t.Fatal("revoked-and-reapproved receiver got the stale sealed route")
		}
	}
	var state, failure string
	var attempts, receipts int
	if err := f.s.db.QueryRow(`SELECT inbox.state,COALESCE(receipt.error,'')
FROM relay_v2_inbox inbox LEFT JOIN relay_v2_receipts receipt
ON receipt.message_id=inbox.message_id AND receipt.layer=? WHERE inbox.message_id=?`,
		RelayReceiptFailed, messageByEndpoint[f.reader.scope.EndpointID]).Scan(&state, &failure); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE message_id=?`,
		messageByEndpoint[f.reader.scope.EndpointID]).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE message_id=? AND layer=?`,
		messageByEndpoint[f.reader.scope.EndpointID], RelayReceiptNodeReceived).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if state != RelayInboxFailed || failure == "" || attempts != 0 || receipts != 0 {
		t.Fatalf("stale route crossed preclaim gate: state=%s failure=%q attempts=%d NodeReceived=%d",
			state, failure, attempts, receipts)
	}
}

func TestNetworkBroadcastCandidateScanBudgetRejectsOverflowAndKeepsLastPage(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	enableNetworkBroadcastForTaskFixture(t, f)
	for _, endpoint := range []networkTaskTestEndpoint{f.publisher, f.otherReader} {
		var grantsJSON string
		if err := f.s.db.QueryRow(`SELECT grants_json FROM network_memberships_v2
WHERE network_id=? AND principal_id=?`, endpoint.scope.NetworkID,
			endpoint.scope.PrincipalID).Scan(&grantsJSON); err != nil {
			t.Fatal(err)
		}
		var grants []string
		if err := json.Unmarshal([]byte(grantsJSON), &grants); err != nil {
			t.Fatal(err)
		}
		filtered := make([]string, 0, len(grants))
		for _, grant := range grants {
			if grant != "broadcast.receive" {
				filtered = append(filtered, grant)
			}
		}
		encoded, err := json.Marshal(filtered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.db.Exec(`UPDATE network_memberships_v2 SET grants_json=?
WHERE network_id=? AND principal_id=?`, string(encoded), endpoint.scope.NetworkID,
			endpoint.scope.PrincipalID); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < networkBroadcastMaxCandidates-1; i++ {
		endpointID := "00broadcast_candidate_" + strconv.Itoa(i)
		insertClientNetworkDirectoryEndpoint(t, f.s, "net_task", endpointID,
			"owner_a", "candidate-"+strconv.Itoa(i), true, "online", false)
		if _, err := f.s.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["broadcast.receive"]'
WHERE network_id='net_task' AND principal_id=?`, "principal_"+endpointID); err != nil {
			t.Fatal(err)
		}
	}
	exactBoundary, err := f.s.PreviewNetworkBroadcastRecipients(f.publisher.scope)
	if err != nil || len(exactBoundary.Recipients) != 1 ||
		exactBoundary.Recipients[0].EndpointID != f.reader.scope.EndpointID {
		t.Fatalf("last valid reader was silently omitted at candidate budget: %+v %v", exactBoundary, err)
	}
	endpointID := "00broadcast_candidate_overflow"
	insertClientNetworkDirectoryEndpoint(t, f.s, "net_task", endpointID,
		"owner_a", "overflow-candidate", true, "online", false)
	if _, err := f.s.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["broadcast.receive"]'
WHERE network_id='net_task' AND principal_id=?`, "principal_"+endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PreviewNetworkBroadcastRecipients(f.publisher.scope); !errors.Is(err, ErrNetworkBroadcastCandidateLimit) {
		t.Fatalf("candidate scan beyond hard budget did not fail explicitly: %v", err)
	}
}
