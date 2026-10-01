package store

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type networkTaskTestEndpoint struct {
	scope NetworkAccessScope
	key   *e2ee.Identity
}

type networkTaskFixture struct {
	s           *Store
	owner       *e2ee.Identity
	publisher   networkTaskTestEndpoint
	reader      networkTaskTestEndpoint
	otherReader networkTaskTestEndpoint
	credential  string
}

func newNetworkTaskFixture(t *testing.T) networkTaskFixture {
	t.Helper()
	s, owner, _, device := newClientDeviceFixture(t)
	if _, err := s.db.Exec(`UPDATE principals SET trust_domain_id='domain' WHERE id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	const nodeID, networkID = "node_network_task", "net_task"
	credential := nodeBindingTestCredentialDigest("synthetic-network-task-token")
	codeDigest := nodeBindingTestCodeDigest("synthetic-network-task-code")
	bound, err := s.CreatePendingNodeDeviceBinding(nodeID, nodeID, credential, codeDigest, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateNetwork(Network{ID: networkID, HubID: bound.HubID, Name: "Synthetic task network", OwnerID: "owner_a"}); err != nil {
		t.Fatal(err)
	}
	grants := []string{"task.offer.accept", "task.offer.claim", "task.offer.list", "task.offer.publish", "task.offer.result"}
	join := func(label string) networkTaskTestEndpoint {
		invitation := "synthetic-network-task-invitation-" + label + "-aaaaaaaaaaaaaaaaaaaa"
		if err := s.IssueNetworkInvitation(networkID, "owner_a", "owner_a", invitation, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := owner.SignOwnerNetworkJoinGrant("owner_a", bound.HubID, networkID, nodeID, "native_task_"+label, NetworkInvitationDigest(invitation), owner.Public().ID, grants, false, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Nonce     string `json:"nonce"`
			ExpiresAt string `json:"expires_at"`
		}
		if err = json.Unmarshal(proof, &claims); err != nil {
			t.Fatal(err)
		}
		joined, err := s.AcceptNetworkJoin(AcceptNetworkJoinInput{NetworkID: networkID, OwnerID: "owner_a", TrustDomainID: "domain", NodeID: nodeID, NativeSessionID: "native_task_" + label, Harness: "codex", EndpointName: "task-" + label, InvitationToken: invitation, ProofNonce: claims.Nonce, ProofDigest: NetworkInvitationDigest(string(proof)), ProofExpiresAt: claims.ExpiresAt, OwnerKeyID: owner.Public().ID, OwnerJoinProof: string(proof), NodeCredentialHash: credential, Grants: grants, CredentialHash: "task-access-" + label, LeaseOwner: "task-lease-" + label, LeaseExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		scope := NetworkAccessScope{NetworkID: networkID, PrincipalID: joined.PrincipalID, EndpointID: joined.EndpointID, AccessSessionID: joined.AccessSessionID, AccessEpoch: joined.AccessSessionEpoch, LeaseOwner: "task-lease-" + label, MembershipID: joined.MembershipID, MembershipRevision: joined.MembershipRevision, EndpointMembershipRevision: joined.EndpointRevision}
		binding, err := s.EnsureNetworkDirectNativeBinding(scope)
		if err != nil {
			t.Fatal(err)
		}
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := key.SignNetworkDirectKeyAttestation(bound.HubID, networkID, joined.EndpointID, joined.PrincipalID, nodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.RegisterNetworkDirectKeyCandidate(scope, attestation); err != nil {
			t.Fatal(err)
		}
		manifest, err := s.PreviewNetworkCollaborationKeyGrant("owner_a", networkID,
			joined.EndpointID, e2ee.NetworkCollaborationPurposeTask, owner.Public().ID)
		if err != nil {
			t.Fatal(err)
		}
		ownerProof, err := owner.SignOwnerNetworkCollaborationKeyGrant(
			e2ee.NetworkCollaborationPurposeTask, bound.HubID, networkID,
			joined.EndpointID, "owner_a", manifest.Digest,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.AcceptNetworkCollaborationKeyGrant("owner_a", networkID,
			joined.EndpointID, e2ee.NetworkCollaborationPurposeTask, ownerProof); err != nil {
			t.Fatal(err)
		}
		return networkTaskTestEndpoint{scope: scope, key: key}
	}
	return networkTaskFixture{s: s, owner: owner, publisher: join("publisher"), reader: join("reader"),
		otherReader: join("other_reader"), credential: credential}
}

func (f networkTaskFixture) send(t *testing.T, sender, receiver networkTaskTestEndpoint, messageID string, payload string, sequence uint64) {
	t.Helper()
	bundle, err := f.s.NetworkCollaborationPeerKey(sender.scope, receiver.scope.EndpointID,
		e2ee.NetworkCollaborationPurposeTask)
	if err != nil {
		t.Fatal(err)
	}
	context, err := networkCollaborationContext(bundle, messageID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := e2ee.SealNetworkCollaborationMessage(sender.key, receiver.key.Public(),
		*context, []byte(payload), sequence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.EnqueueNetworkCollaborationSealedSend(NetworkCollaborationSendInput{
		Scope: sender.scope, NodeCredentialDigest: f.credential,
		Purpose: e2ee.NetworkCollaborationPurposeTask, TargetEndpointID: receiver.scope.EndpointID,
		MessageID: messageID, Ciphertext: sealed}); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkTaskSealedOfferClaimResultAcceptance(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	for _, endpoint := range []networkTaskTestEndpoint{f.publisher, f.reader} {
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
		for _, grant := range grants {
			if grant == "direct.send" || grant == "direct.receive" {
				t.Fatalf("Task route unexpectedly depends on Direct grant %q", grant)
			}
		}
	}
	const taskID = "ntask_synthetic_aabbccddeeff00112233"
	offerID := taskID + ":offer:reader"
	resultID := taskID + ":result:1:publisher"
	f.send(t, f.publisher, f.reader, offerID, "synthetic private title and acceptance", 1)
	input := NetworkTaskOfferInput{TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), OfferMessageIDs: []string{offerID}}
	task, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, input)
	if err != nil || task.Status != SharedTaskReady || task.RecipientCount != 1 {
		t.Fatalf("publish %#v %v", task, err)
	}
	retry, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, input)
	if err != nil || retry.ID != task.ID || retry.RecipientCount != 1 {
		t.Fatalf("publish retry %#v %v", retry, err)
	}
	listed, err := f.s.ListNetworkTaskOffers(f.reader.scope, 10)
	if err != nil || len(listed) != 1 || listed[0].OfferMessageID != offerID {
		t.Fatalf("recipient list %#v %v", listed, err)
	}
	if _, err = f.s.PublishNetworkTaskOffer(f.reader.scope, input); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("recipient published foreign message: %v", err)
	}
	claimed, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, task.Revision, "claim-1", 300)
	if err != nil || claimed.OwnerEpoch != 1 || claimed.Status != SharedTaskClaimed {
		t.Fatalf("claim %#v %v", claimed, err)
	}
	claimRetry, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, task.Revision, "claim-1", 300)
	if err != nil || claimRetry.Revision != claimed.Revision {
		t.Fatalf("claim retry %#v %v", claimRetry, err)
	}
	if _, err = f.s.AcceptNetworkTaskResult(f.publisher.scope, taskID, "unknown", claimed.Revision); !errors.Is(err, ErrSharedTaskResultNotFound) {
		t.Fatalf("claim treated complete: %v", err)
	}
	f.send(t, f.reader, f.publisher, resultID, "synthetic private result with evidence", 1)
	result, err := f.s.SubmitNetworkTaskResult(f.reader.scope, NetworkTaskResultInput{TaskID: taskID, ExpectedRevision: claimed.Revision, OwnerEpoch: claimed.OwnerEpoch, ResultMessageID: resultID})
	if err != nil || result.Authority != "PENDING" {
		t.Fatalf("submit %#v %v", result, err)
	}
	resultRetry, err := f.s.SubmitNetworkTaskResult(f.reader.scope, NetworkTaskResultInput{TaskID: taskID, ExpectedRevision: claimed.Revision, OwnerEpoch: claimed.OwnerEpoch, ResultMessageID: resultID})
	if err != nil || resultRetry.ID != result.ID {
		t.Fatalf("submit retry %#v %v", resultRetry, err)
	}
	pending, err := f.s.GetNetworkTaskOffer(f.publisher.scope, taskID)
	if err != nil || pending.PendingResultID != result.ID || pending.PendingResultMessageID != resultID ||
		pending.Status != SharedTaskResultSubmitted || pending.OwnerEpoch != claimed.OwnerEpoch {
		t.Fatalf("publisher cannot discover exact pending result: %+v %v", pending, err)
	}
	readerView, err := f.s.GetNetworkTaskOffer(f.reader.scope, taskID)
	if err != nil || readerView.PendingResultID != "" || readerView.PendingResultMessageID != "" || readerView.AcceptedResultID != "" {
		t.Fatalf("result metadata leaked to task reader: %+v %v", readerView, err)
	}
	var publisherGrantsJSON string
	if err = f.s.db.QueryRow(`SELECT grants_json FROM network_memberships_v2 WHERE network_id=? AND principal_id=?`,
		task.NetworkID, f.publisher.scope.PrincipalID).Scan(&publisherGrantsJSON); err != nil {
		t.Fatal(err)
	}
	var publisherGrants []string
	if err = json.Unmarshal([]byte(publisherGrantsJSON), &publisherGrants); err != nil {
		t.Fatal(err)
	}
	withoutAccept := make([]string, 0, len(publisherGrants))
	for _, grant := range publisherGrants {
		if grant != "task.offer.accept" {
			withoutAccept = append(withoutAccept, grant)
		}
	}
	withoutAcceptJSON, err := json.Marshal(withoutAccept)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec(`UPDATE network_memberships_v2 SET grants_json=? WHERE network_id=? AND principal_id=?`,
		string(withoutAcceptJSON), task.NetworkID, f.publisher.scope.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.GetNetworkTaskOffer(f.publisher.scope, taskID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("publisher read result after accept grant revocation: %v", err)
	}
	if _, err = f.s.db.Exec(`UPDATE network_memberships_v2 SET grants_json=? WHERE network_id=? AND principal_id=?`,
		publisherGrantsJSON, task.NetworkID, f.publisher.scope.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec(`UPDATE network_task_results_v2 SET owner_epoch=owner_epoch+1 WHERE id=?`, result.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.GetNetworkTaskOffer(f.publisher.scope, taskID); !errors.Is(err, ErrSharedTaskConflict) {
		t.Fatalf("publisher read result metadata after owner epoch mismatch: %v", err)
	}
	if _, err = f.s.db.Exec(`UPDATE network_task_results_v2 SET owner_epoch=? WHERE id=?`, claimed.OwnerEpoch, result.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AcceptNetworkTaskResult(f.reader.scope, taskID, result.ID, claimed.Revision+1); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("claimant self-accepted: %v", err)
	}
	completed, err := f.s.AcceptNetworkTaskResult(f.publisher.scope, taskID, result.ID, claimed.Revision+1)
	if err != nil || completed.Status != SharedTaskCompleted || completed.AcceptedResultID != result.ID {
		t.Fatalf("accept %#v %v", completed, err)
	}
	completeRetry, err := f.s.AcceptNetworkTaskResult(f.publisher.scope, taskID, result.ID, claimed.Revision+1)
	if err != nil || completeRetry.Revision != completed.Revision {
		t.Fatalf("accept retry %#v %v", completeRetry, err)
	}
	completedView, err := f.s.GetNetworkTaskOffer(f.publisher.scope, taskID)
	if err != nil || completedView.AcceptedResultID != result.ID || completedView.PendingResultID != "" {
		t.Fatalf("publisher completed-result view %#v %v", completedView, err)
	}
	readerView, err = f.s.GetNetworkTaskOffer(f.reader.scope, taskID)
	if err != nil || readerView.AcceptedResultID != "" {
		t.Fatalf("accepted result metadata leaked to task reader: %+v %v", readerView, err)
	}
	var objective, criteria, summary int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM network_task_offers_v2 WHERE id=? AND (status LIKE '%private%' OR network_id LIKE '%private%')`, taskID).Scan(&objective); err != nil {
		t.Fatal(err)
	}
	if err = f.s.db.QueryRow(`SELECT count(*) FROM network_task_results_v2 WHERE id=? AND message_id LIKE '%private%'`, result.ID).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if err = f.s.db.QueryRow(`SELECT count(*) FROM shared_tasks_v2 WHERE id=?`, taskID).Scan(&criteria); err != nil {
		t.Fatal(err)
	}
	if objective != 0 || summary != 0 || criteria != 0 {
		t.Fatal("task plaintext or fictitious Group row")
	}
}

func TestNetworkTaskRejectsStaleEpochAndRevokedReader(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_11223344556677889900"
	offerID := taskID + ":offer:reader"
	f.send(t, f.publisher, f.reader, offerID, "private synthetic offer", 1)
	task, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), OfferMessageIDs: []string{offerID}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, task.Revision, "first", 300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.db.Exec(`UPDATE network_task_offers_v2 SET lease_expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), taskID); err != nil {
		t.Fatal(err)
	}
	second, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, first.Revision, "second", 300)
	if err != nil || second.OwnerEpoch != first.OwnerEpoch+1 {
		t.Fatalf("reclaim %#v %v", second, err)
	}
	staleID := taskID + ":result:1:publisher"
	f.send(t, f.reader, f.publisher, staleID, "stale result", 1)
	if _, err = f.s.SubmitNetworkTaskResult(f.reader.scope, NetworkTaskResultInput{TaskID: taskID, ExpectedRevision: first.Revision, OwnerEpoch: first.OwnerEpoch, ResultMessageID: staleID}); !errors.Is(err, ErrSharedTaskStaleOwner) {
		t.Fatalf("stale epoch accepted %v", err)
	}
	if err = f.s.LeaveEndpointNetwork("net_task", f.reader.scope.EndpointID, f.reader.scope.EndpointMembershipRevision); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.GetNetworkTaskOffer(f.reader.scope, taskID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked reader listed: %v", err)
	}
	if _, err = f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, second.Revision, "third", 300); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked reader claimed: %v", err)
	}
	var count int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM network_task_results_v2 WHERE task_id=?`, taskID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale result persisted %d %v", count, err)
	}
}

func TestNetworkTaskOfferRejectsPlaintextAndWrongRoute(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_ffeeddccbbaa00998877"
	wrongID := taskID + ":result:1:wrong"
	f.send(t, f.publisher, f.reader, wrongID, "private synthetic offer", 1)
	_, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), OfferMessageIDs: []string{wrongID}})
	if !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("wrong AAD purpose accepted: %v", err)
	}
	var count int
	if err = f.s.db.QueryRow(`SELECT count(*) FROM network_task_offers_v2 WHERE id=?`, taskID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial task persisted %d %v", count, err)
	}
	if strings.Contains(wrongID, "private") {
		t.Fatal("test setup leaked title in route")
	}
}

func TestNetworkTaskEarlyOfferSendRemainsQueuedUntilPublish(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_offer_race_0123456789"
	messageID := taskID + ":offer:synthetic-reader-op"
	f.send(t, f.publisher, f.reader, messageID, "synthetic sealed offer", 1)
	claimInput := NetworkDirectClaimInput{NodeID: "node_network_task", ConsumerID: "synthetic-node-consumer",
		Limit: 10, CredentialDigest: f.credential}
	if deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput); err != nil || len(deliveries) != 0 {
		t.Fatalf("pre-publish claim must remain empty: %d %v", len(deliveries), err)
	}
	var inboxState string
	var attempts, nodeReceipts int
	if err := f.s.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`, messageID).Scan(&inboxState); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE message_id=?`, messageID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_receipts WHERE message_id=? AND layer=?`, messageID, RelayReceiptNodeReceived).Scan(&nodeReceipts); err != nil {
		t.Fatal(err)
	}
	if inboxState != RelayInboxReady || attempts != 0 || nodeReceipts != 0 {
		t.Fatalf("pre-publish SEND was consumed: inbox=%s attempts=%d node_received=%d", inboxState, attempts, nodeReceipts)
	}
	deadline := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	published, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{
		TaskID: taskID, ExpiresAt: deadline, OfferMessageIDs: []string{messageID}})
	if err != nil || len(published.NotifyEndpointIDs) != 1 || published.NotifyEndpointIDs[0] != f.reader.scope.EndpointID {
		t.Fatalf("publish metadata/wake route: %+v %v", published, err)
	}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput)
	if err != nil || len(deliveries) != 1 || deliveries[0].MessageID != messageID {
		t.Fatalf("post-publish claim: %+v %v", deliveries, err)
	}
	authorization, err := f.s.AuthorizeClaimedNetworkDirectDelivery(f.credential, messageID, deliveries[0].AttemptID)
	if err != nil || authorization.NetworkTask == nil || authorization.NetworkTask.TaskID != taskID ||
		authorization.NetworkTask.Kind != "offer" || authorization.NetworkTask.Status != SharedTaskReady ||
		authorization.NetworkTask.ReceiverEndpointID != f.reader.scope.EndpointID {
		t.Fatalf("fresh task authorization: %+v %v", authorization, err)
	}
	if _, err := f.s.RecordNetworkDirectReceipt(f.credential, RelayReceipt{
		AttemptID: deliveries[0].AttemptID, MessageID: messageID, Digest: deliveries[0].Digest,
		TargetEndpointID: f.reader.scope.EndpointID, BindingID: authorization.BindingID,
		BindingEpoch: authorization.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatalf("typed Task NodeReceived receipt: %v", err)
	}
}

func TestNetworkTaskEarlyResultSendRemainsQueuedUntilResultMetadata(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_result_race_0123456789"
	offerID := taskID + ":offer:synthetic-reader-op"
	f.send(t, f.publisher, f.reader, offerID, "synthetic sealed offer", 1)
	task, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{
		TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		OfferMessageIDs: []string{offerID}})
	if err != nil {
		t.Fatal(err)
	}
	claimInput := NetworkDirectClaimInput{NodeID: "node_network_task", ConsumerID: "synthetic-node-consumer",
		Limit: 10, CredentialDigest: f.credential}
	if deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput); err != nil || len(deliveries) != 1 || deliveries[0].MessageID != offerID {
		t.Fatalf("claim offer before Task claim: %+v %v", deliveries, err)
	}
	claimed, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, task.Revision, "result-race-claim", 300)
	if err != nil {
		t.Fatal(err)
	}
	resultID := taskID + ":result:" + strconv.FormatInt(claimed.OwnerEpoch, 10) + ":synthetic-publisher-op"
	f.send(t, f.reader, f.publisher, resultID, "synthetic sealed result", 1)
	if deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput); err != nil || len(deliveries) != 0 {
		t.Fatalf("pre-result-metadata claim must remain empty: %+v %v", deliveries, err)
	}
	var inboxState string
	var attempts int
	if err := f.s.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`, resultID).Scan(&inboxState); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE message_id=?`, resultID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if inboxState != RelayInboxReady || attempts != 0 {
		t.Fatalf("pre-result-metadata SEND was consumed: inbox=%s attempts=%d", inboxState, attempts)
	}
	result, err := f.s.SubmitNetworkTaskResult(f.reader.scope, NetworkTaskResultInput{
		TaskID: taskID, ExpectedRevision: claimed.Revision, OwnerEpoch: claimed.OwnerEpoch,
		ResultMessageID: resultID})
	if err != nil || result.Authority != "PENDING" || result.NotifyEndpointID != f.publisher.scope.EndpointID {
		t.Fatalf("result metadata/wake: %+v %v", result, err)
	}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput)
	if err != nil || len(deliveries) != 1 || deliveries[0].MessageID != resultID {
		t.Fatalf("post-result-metadata claim: %+v %v", deliveries, err)
	}
	authorization, err := f.s.AuthorizeClaimedNetworkDirectDelivery(f.credential, resultID, deliveries[0].AttemptID)
	if err != nil || authorization.NetworkTask == nil || authorization.NetworkTask.TaskID != taskID ||
		authorization.NetworkTask.Kind != "result" || authorization.NetworkTask.OwnerEpoch != claimed.OwnerEpoch ||
		authorization.NetworkTask.Status != SharedTaskResultSubmitted {
		t.Fatalf("fresh result authorization: %+v %v", authorization, err)
	}
}

func TestNetworkTaskConcurrentClaimHasSingleWinnerAndIsNetworkScoped(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_claim_race_0123456789"
	offerID := taskID + ":offer:synthetic-reader-op"
	f.send(t, f.publisher, f.reader, offerID, "synthetic sealed offer", 1)
	task, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{
		TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		OfferMessageIDs: []string{offerID}})
	if err != nil {
		t.Fatal(err)
	}
	otherNetwork := f.reader.scope
	otherNetwork.NetworkID = "net_other_task"
	if tasks, err := f.s.ListNetworkTaskOffers(otherNetwork, 10); !errors.Is(err, ErrNetworkPermission) || len(tasks) != 0 {
		t.Fatalf("cross-Network task listing: %+v %v", tasks, err)
	}
	const claimants = 8
	type outcome struct {
		task *NetworkTaskOffer
		err  error
	}
	outcomes := make(chan outcome, claimants)
	var group sync.WaitGroup
	for i := 0; i < claimants; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			task, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, task.Revision,
				"claim-race-"+strconv.Itoa(index), 300)
			outcomes <- outcome{task: task, err: err}
		}(i)
	}
	group.Wait()
	close(outcomes)
	winners, conflicts := 0, 0
	for result := range outcomes {
		if result.err == nil {
			winners++
			if result.task.OwnerEpoch != 1 || result.task.OwnerEndpointID != f.reader.scope.EndpointID {
				t.Fatalf("winner has wrong owner epoch: %+v", result.task)
			}
		} else if errors.Is(result.err, ErrSharedTaskConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent claim error: %v", result.err)
		}
	}
	if winners != 1 || conflicts != claimants-1 {
		t.Fatalf("claim winners=%d conflicts=%d", winners, conflicts)
	}
}

func TestNetworkTaskExpiredPendingRouteFailsWithoutDelivery(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_expired_offer_012345"
	messageID := taskID + ":offer:synthetic-reader-op"
	f.send(t, f.publisher, f.reader, messageID, "synthetic sealed offer", 1)
	if _, err := f.s.db.Exec(`UPDATE network_direct_message_routes_v2 SET created_at=? WHERE message_id=?`,
		time.Now().UTC().Add(-25*time.Hour).Format(time.RFC3339Nano), messageID); err != nil {
		t.Fatal(err)
	}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(NetworkDirectClaimInput{
		NodeID: "node_network_task", ConsumerID: "synthetic-node-consumer", Limit: 10,
		CredentialDigest: f.credential})
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("expired unregistered task was returned: %+v %v", deliveries, err)
	}
	var state, failure string
	if err := f.s.db.QueryRow(`SELECT i.state,r.error FROM relay_v2_inbox i JOIN relay_v2_receipts r
ON r.message_id=i.message_id WHERE i.message_id=? AND r.layer=?`, messageID, RelayReceiptFailed).Scan(&state, &failure); err != nil {
		t.Fatal(err)
	}
	if state != RelayInboxFailed || failure != "TASK_EXPIRED" {
		t.Fatalf("expired route state=%s reason=%q", state, failure)
	}
}

func TestNetworkTaskFanoutWinnerGetsOfferAndOtherQueuedReadersTerminate(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_fanout_winner_0123456789"
	readerOffer := taskID + ":offer:synthetic-reader-op"
	otherOffer := taskID + ":offer:synthetic-other-reader-op"
	f.send(t, f.publisher, f.reader, readerOffer, "synthetic sealed offer", 1)
	f.send(t, f.publisher, f.otherReader, otherOffer, "synthetic sealed offer", 2)
	task, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{
		TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		OfferMessageIDs: []string{readerOffer, otherOffer}})
	if err != nil {
		t.Fatal(err)
	}
	claimInput := NetworkDirectClaimInput{NodeID: "node_network_task", ConsumerID: "synthetic-node-consumer",
		Limit: 10, CredentialDigest: f.credential}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("fanout deliveries: %+v %v", deliveries, err)
	}
	byMessage := map[string]NetworkDirectClaimedDelivery{}
	for _, delivery := range deliveries {
		byMessage[delivery.MessageID] = delivery
	}
	readerDelivery, readerOK := byMessage[readerOffer]
	otherDelivery, otherOK := byMessage[otherOffer]
	if !readerOK || !otherOK {
		t.Fatalf("fanout claims missing exact routes: %+v", deliveries)
	}
	claimed, err := f.s.ClaimNetworkTaskOffer(f.reader.scope, taskID, task.Revision,
		"fanout-winner-claim", 300)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := f.s.AuthorizeClaimedNetworkDirectDelivery(f.credential,
		readerOffer, readerDelivery.AttemptID)
	if err != nil || authorization.NetworkTask == nil ||
		authorization.NetworkTask.Status != SharedTaskClaimed ||
		authorization.NetworkTask.OwnerEndpointID != f.reader.scope.EndpointID ||
		authorization.NetworkTask.OwnerEpoch != claimed.OwnerEpoch {
		t.Fatalf("winner's queued offer was not authorized: %+v %v", authorization, err)
	}
	if _, err := f.s.db.Exec(`UPDATE network_task_offers_v2 SET lease_expires_at=? WHERE id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.AuthorizeClaimedNetworkDirectDelivery(f.credential,
		readerOffer, readerDelivery.AttemptID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("expired winner lease retained delivery authority: %v", err)
	}
	var winnerState, winnerFailure string
	if err := f.s.db.QueryRow(`SELECT i.state,r.error FROM relay_v2_inbox i JOIN relay_v2_receipts r
ON r.message_id=i.message_id WHERE i.message_id=? AND r.layer=?`, readerOffer, RelayReceiptFailed).Scan(&winnerState, &winnerFailure); err != nil {
		t.Fatal(err)
	}
	if winnerState != RelayInboxFailed || winnerFailure != "TASK_LEASE_EXPIRED" {
		t.Fatalf("expired winner route state=%s reason=%q", winnerState, winnerFailure)
	}
	if _, err := f.s.AuthorizeClaimedNetworkDirectDelivery(f.credential,
		otherOffer, otherDelivery.AttemptID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("late non-winner offer was not denied: %v", err)
	}
	var state, failure string
	if err := f.s.db.QueryRow(`SELECT i.state,r.error FROM relay_v2_inbox i JOIN relay_v2_receipts r
ON r.message_id=i.message_id WHERE i.message_id=? AND r.layer=?`, otherOffer, RelayReceiptFailed).Scan(&state, &failure); err != nil {
		t.Fatal(err)
	}
	if state != RelayInboxFailed || failure != "TASK_ALREADY_CLAIMED" {
		t.Fatalf("losing offer state=%s reason=%q", state, failure)
	}
}

func TestNetworkTaskLegacyAndTamperedPurposeRoutesStayUndeliverable(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	claimInput := NetworkDirectClaimInput{NodeID: "node_network_task",
		ConsumerID: "synthetic-purpose-guard", Limit: 10, CredentialDigest: f.credential}
	for _, test := range []struct {
		name    string
		purpose string
		failure string
	}{
		{name: "legacy direct", purpose: "DIRECT", failure: "TASK_MIGRATION_BLOCKED"},
		{name: "purpose substitution", purpose: e2ee.NetworkCollaborationPurposeBroadcast,
			failure: "Network direct enrollment or route is no longer current"},
	} {
		t.Run(test.name, func(t *testing.T) {
			taskID := "ntask_synthetic_" + strings.ReplaceAll(strings.ToLower(test.name), " ", "_") + "_0123456789"
			messageID := taskID + ":offer:synthetic-reader-op"
			f.send(t, f.publisher, f.reader, messageID, "synthetic sealed offer", 1)
			if _, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{
				TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
				OfferMessageIDs: []string{messageID}}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.db.Exec(`UPDATE network_direct_message_routes_v2
SET key_purpose=? WHERE message_id=?`, test.purpose, messageID); err != nil {
				t.Fatal(err)
			}
			deliveries, err := f.s.ClaimNetworkDirectSealedInbox(claimInput)
			if err != nil || len(deliveries) != 0 {
				t.Fatalf("tampered purpose route delivered: %+v %v", deliveries, err)
			}
			var inboxState, failure string
			if err := f.s.db.QueryRow(`SELECT inbox.state,receipt.error
FROM relay_v2_inbox inbox JOIN relay_v2_receipts receipt
ON receipt.message_id=inbox.message_id WHERE inbox.message_id=? AND receipt.layer=?`,
				messageID, RelayReceiptFailed).Scan(&inboxState, &failure); err != nil {
				t.Fatal(err)
			}
			if inboxState != RelayInboxFailed || failure != test.failure {
				t.Fatalf("purpose route terminal state=%s reason=%q", inboxState, failure)
			}
			var retainedTask, ciphertextLength int
			if err := f.s.db.QueryRow(`SELECT count(*) FROM network_task_offers_v2 WHERE id=?`, taskID).Scan(&retainedTask); err != nil {
				t.Fatal(err)
			}
			if err := f.s.db.QueryRow(`SELECT length(ciphertext) FROM relay_v2_message_payloads WHERE message_id=?`,
				messageID).Scan(&ciphertextLength); err != nil {
				t.Fatal(err)
			}
			view, err := f.s.GetNetworkTaskOffer(f.publisher.scope, taskID)
			if err != nil || view.DeliveryState != "MIGRATION_BLOCKED" || retainedTask != 1 || ciphertextLength == 0 {
				t.Fatalf("historical metadata/ciphertext not retained: view=%+v rows=%d cipher=%d err=%v",
					view, retainedTask, ciphertextLength, err)
			}
		})
	}
}

func TestNetworkTaskPurposeRevocationAndFreshRegrantDoNotReviveRoute(t *testing.T) {
	f := newNetworkTaskFixture(t)
	defer f.s.Close()
	const taskID = "ntask_synthetic_typed_revoke_0123456789"
	messageID := taskID + ":offer:synthetic-reader-op"
	f.send(t, f.publisher, f.reader, messageID, "synthetic sealed offer", 1)
	if _, err := f.s.PublishNetworkTaskOffer(f.publisher.scope, NetworkTaskOfferInput{
		TaskID: taskID, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		OfferMessageIDs: []string{messageID}}); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.s.RevokeNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeTask, 1)
	if err != nil || revoked.State != "revoked" || revoked.Revision != 2 {
		t.Fatalf("revoke typed key grant: %+v %v", revoked, err)
	}
	retry, err := f.s.RevokeNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeTask, 1)
	if err != nil || retry.State != "revoked" || retry.Revision != revoked.Revision {
		t.Fatalf("lost revoke response did not recover: %+v %v", retry, err)
	}
	deliveries, err := f.s.ClaimNetworkDirectSealedInbox(NetworkDirectClaimInput{
		NodeID: "node_network_task", ConsumerID: "synthetic-revoked-key", Limit: 10,
		CredentialDigest: f.credential})
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("revoked purpose route delivered: %+v %v", deliveries, err)
	}
	manifest, err := f.s.PreviewNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeTask, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.owner.SignOwnerNetworkCollaborationKeyGrant(
		e2ee.NetworkCollaborationPurposeTask, manifest.Key.HubID, "net_task",
		f.reader.scope.EndpointID, "owner_a", manifest.Digest,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	reapproved, err := f.s.AcceptNetworkCollaborationKeyGrant("owner_a", "net_task",
		f.reader.scope.EndpointID, e2ee.NetworkCollaborationPurposeTask, proof)
	if err != nil || reapproved.State != "active" || reapproved.Revision != 3 {
		t.Fatalf("fresh purpose approval: %+v %v", reapproved, err)
	}
	tx, err := f.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := networkGuardStoredSealedMessageTx(tx, messageID, "net_task", time.Now().UTC()); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("fresh purpose grant revived old queued route: %v", err)
	}
}
