package store

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type communicationLinkReviewTestActor struct {
	scope NativeActorScope
}

func addCommunicationLinkReviewer(t *testing.T, s *Store, endpointID, ownerID, groupID string,
	grants []string) communicationLinkReviewTestActor {
	t.Helper()
	principal, err := s.CreatePrincipal(Principal{ID: "pr_" + endpointID, Kind: PrincipalKindAgent,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: endpointID, Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := s.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: groupID,
		Role: "member", Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := s.UpsertEndpointV2(Endpoint{ID: endpointID, Name: endpointID,
		Harness: "codex", NativeSessionID: "native_" + endpointID, MachineID: "node_" + endpointID,
		Owner: ownerID, Status: "online", PrincipalID: principal.ID, GroupID: groupID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
		PrincipalID: principal.ID, GroupID: groupID, NativeSessionID: endpoint.NativeSessionID,
		NodeID: endpoint.MachineID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = s.AcquireSessionBindingLease(binding.ID, "lease_"+endpointID, binding.Epoch,
		time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	return communicationLinkReviewTestActor{scope: NativeActorScope{
		PrincipalID: principal.ID, EndpointID: endpoint.ID, GroupID: groupID,
		MembershipID: membership.ID, MembershipRevision: membership.Revision,
		BindingID: binding.ID, BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner,
	}}
}

func recordCommunicationLinkReviewPolicy(t *testing.T, f *linkSealedSendTestFixture,
	policy CommunicationLinkReviewPolicy, expectedVersion int64) *CommunicationLinkReviewPolicyStatus {
	t.Helper()
	_, _, policyDigest, err := normalizeCommunicationLinkReviewPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, f.link.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	version := uint64(expectedVersion + 1)
	now := time.Now().UTC()
	sourceProof, err := f.sourceOwner.identity.SignOwnerLinkReviewPolicy(f.link.SourceOwnerID,
		f.link.ID, f.link.ContractDigest, policyDigest, uint64(f.link.Version), version,
		e2ee.OwnerLinkGrantSideSource, now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	targetProof, err := f.targetOwner.identity.SignOwnerLinkReviewPolicy(f.link.TargetOwnerID,
		f.link.ID, f.link.ContractDigest, policyDigest, uint64(f.link.Version), version,
		e2ee.OwnerLinkGrantSideTarget, now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID,
		CommunicationLinkGrantSource, f.sourceOwner.ownerKeyID, expectedVersion, policy, sourceProof)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current {
		t.Fatal("single Owner proof activated bilateral review policy")
	}
	status, err = f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID,
		CommunicationLinkGrantTarget, f.targetOwner.ownerKeyID, expectedVersion, policy, targetProof)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Current || status.PolicyVersion != int64(version) || len(status.AcceptedSides) != 2 {
		t.Fatalf("bilateral policy did not activate: %+v", status)
	}
	// Recover a lost response from the exact second-owner submission.
	retry, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID,
		CommunicationLinkGrantTarget, f.targetOwner.ownerKeyID, expectedVersion, policy, targetProof)
	if err != nil || !retry.Current || retry.PolicyDigest != status.PolicyDigest || retry.PolicyVersion != status.PolicyVersion {
		t.Fatalf("identical second-owner policy submission did not recover the committed head: status=%+v err=%v", retry, err)
	}
	return status
}

func TestCommunicationLinkReviewPolicyBilateralQueueFailoverAndDecision(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	first := addCommunicationLinkReviewer(t, f.base.store, "ep_review_a", f.link.SourceOwnerID,
		f.link.SourceGroupID, []string{"link.review"})
	second := addCommunicationLinkReviewer(t, f.base.store, "ep_review_b", f.link.TargetOwnerID,
		f.link.TargetGroupID, []string{"link.review"})
	policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewMetadata,
		Reviewers: []CommunicationLinkReviewer{
			{EndpointID: first.scope.EndpointID, GroupID: first.scope.GroupID},
			{EndpointID: second.scope.EndpointID, GroupID: second.scope.GroupID},
		}, MaxFailovers: 1, ReviewerLeaseSeconds: 30, MaxReviewAgeSeconds: 600}
	recordCommunicationLinkReviewPolicy(t, f, policy, 0)

	f.messageID = "msg_link_review_waiting"
	f.ciphertext = f.seal(t)
	record, err := f.base.store.EnqueueCommunicationLinkSealedSend(CommunicationLinkSealedSend{
		NodeCredentialDigest: f.sourceOwner.nodeCredential, LinkID: f.link.ID,
		MessageID: f.messageID, DataScope: f.dataScope, Ciphertext: f.ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		staleID := fmt.Sprintf("0000-review-stale-%04d", i)
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := f.base.store.db.Exec(`INSERT INTO fabric_messages
(id,from_endpoint_id,to_endpoint_id,kind,body,created_at) VALUES(?,?,?,?,?,?)`,
			staleID, f.link.SourceEndpointID, f.link.TargetEndpointID, "send", "", stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.db.Exec(`INSERT INTO communication_link_message_reviews_v2
SELECT ?,link_id,link_version,policy_version,policy_digest,route_kind,request_id,
sender_endpoint_id,sender_group_id,receiver_endpoint_id,receiver_group_id,message_digest,
reviewers_json,reviewer_index,owner_epoch,lease_expires_at,expires_at,status,version,created_at,updated_at,decided_at
FROM communication_link_message_reviews_v2 WHERE message_id=?`, staleID, f.messageID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.db.Exec(`INSERT INTO communication_link_message_review_candidates_v2
(message_id,reviewer_endpoint_id,reviewer_group_id,reviewer_index) VALUES(?,?,?,0)`,
			staleID, first.scope.EndpointID, first.scope.GroupID); err != nil {
			t.Fatal(err)
		}
	}
	var relayBytes []byte
	if err := f.base.store.db.QueryRow(`SELECT ciphertext FROM relay_v2_message_payloads WHERE message_id=?`, f.messageID).Scan(&relayBytes); err != nil {
		t.Fatal(err)
	}
	if len(relayBytes) == 0 {
		t.Fatal("review queue unexpectedly removed sealed ciphertext")
	}
	var plaintextCount int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM communication_link_message_reviews_v2 WHERE message_id=? AND message_digest=?`,
		f.messageID, record.Security.Digest).Scan(&plaintextCount); err != nil || plaintextCount != 1 {
		t.Fatalf("metadata-only review row missing or not digest-bound: count=%d err=%v", plaintextCount, err)
	}
	binding, err := f.base.store.GetSessionBindingForEndpoint(f.link.TargetEndpointID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "node_review_target",
		BindingID: binding.ID, BindingEpoch: binding.Epoch, Limit: 10,
	})
	if err != nil || len(claim) != 0 {
		t.Fatalf("WAITING_REVIEW message was claimable: count=%d err=%v", len(claim), err)
	}
	rows, err := f.base.store.ListCommunicationLinkMessageReviewsForActor(first.scope, 10)
	if err != nil || len(rows) != 1 || rows[0].MessageID != f.messageID || rows[0].Status != CommunicationLinkReviewWaiting {
		t.Fatalf("assigned reviewer metadata listing mismatch: rows=%+v err=%v", rows, err)
	}
	// More than a thousand unrelated reviewer-index entries must not consume
	// this actor's bounded page or hide its exact assigned review.
	for i := 0; i < 1001; i++ {
		endpointID := fmt.Sprintf("unrelated-reviewer-%04d", i)
		if _, err := f.base.store.db.Exec(`INSERT INTO communication_link_message_review_candidates_v2
(message_id,reviewer_endpoint_id,reviewer_group_id,reviewer_index) VALUES(?,?,?,?)`,
			f.messageID, endpointID, "unrelated-group", i+10); err != nil {
			t.Fatal(err)
		}
	}
	page, err := f.base.store.ListCommunicationLinkMessageReviewsPageForActor(first.scope, "", 1)
	if err != nil || len(page.Items) != 0 || page.NextCursor == "" {
		t.Fatalf("bounded scan did not advance over stale lookahead rows: page=%+v err=%v", page, err)
	}
	page, err = f.base.store.ListCommunicationLinkMessageReviewsPageForActor(first.scope, page.NextCursor, 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].MessageID != f.messageID {
		t.Fatalf("bounded cursor skipped a live row behind stale rows: page=%+v err=%v", page, err)
	}
	if _, err := f.base.store.GetCommunicationLinkMessageReviewForActor(second.scope, f.messageID); err != nil {
		t.Fatalf("explicit next reviewer could not read metadata needed for bounded failover: %v", err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE communication_link_message_reviews_v2 SET lease_expires_at=? WHERE message_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), f.messageID); err != nil {
		t.Fatal(err)
	}
	claimedReview, err := f.base.store.ClaimNextCommunicationLinkReviewForActor(second.scope,
		f.messageID, 1, 1)
	if err != nil || claimedReview.ReviewerEndpointID != second.scope.EndpointID ||
		claimedReview.OwnerEpoch != 2 || claimedReview.Version != 2 {
		t.Fatalf("bounded failover did not advance reviewer epoch/version: review=%+v err=%v", claimedReview, err)
	}
	if _, err := f.base.store.DecideCommunicationLinkMessageReviewForActor(first.scope,
		f.messageID, 1, 1, CommunicationLinkReviewApproved); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale reviewer epoch made a decision: %v", err)
	}
	approved, err := f.base.store.DecideCommunicationLinkMessageReviewForActor(second.scope,
		f.messageID, claimedReview.Version, claimedReview.OwnerEpoch, CommunicationLinkReviewApproved)
	if err != nil || approved.Status != CommunicationLinkReviewApproved {
		t.Fatalf("metadata reviewer could not approve the exact live epoch: review=%+v err=%v", approved, err)
	}
	retried, err := f.base.store.DecideCommunicationLinkMessageReviewForActor(second.scope,
		f.messageID, claimedReview.Version, claimedReview.OwnerEpoch, CommunicationLinkReviewApproved)
	if err != nil || retried.Status != CommunicationLinkReviewApproved || retried.Version != approved.Version {
		t.Fatalf("identical reviewer decision did not recover the committed outcome: review=%+v err=%v", retried, err)
	}
	if _, err := f.base.store.DecideCommunicationLinkMessageReviewForActor(second.scope,
		f.messageID, claimedReview.Version, claimedReview.OwnerEpoch, CommunicationLinkReviewRejected); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("opposite reviewer decision replay did not conflict: %v", err)
	}
	terminal, err := f.base.store.GetCommunicationLinkMessageReviewForActor(second.scope, f.messageID)
	if err != nil || terminal.Status != CommunicationLinkReviewApproved {
		t.Fatalf("authorized reviewer could not recover terminal review metadata: review=%+v err=%v", terminal, err)
	}
	claim, err = f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "node_review_target",
		BindingID: binding.ID, BindingEpoch: binding.Epoch, Limit: 10,
	})
	if err != nil || len(claim) != 1 || claim[0].MessageID != f.messageID {
		t.Fatalf("approved message did not return to Relay claim path: count=%d err=%v", len(claim), err)
	}
}

func TestCommunicationLinkReviewExpiryUsesOwnerProofDeadlineAndRecoversQueue(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	reviewer := addCommunicationLinkReviewer(t, f.base.store, "ep_review_expiry", f.link.SourceOwnerID,
		f.link.SourceGroupID, []string{"link.review"})
	policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewMetadata,
		Reviewers:            []CommunicationLinkReviewer{{EndpointID: reviewer.scope.EndpointID, GroupID: reviewer.scope.GroupID}},
		ReviewerLeaseSeconds: 30, MaxReviewAgeSeconds: 600}
	_, _, digest, err := normalizeCommunicationLinkReviewPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proofExpiry := now.Add(1500 * time.Millisecond)
	for _, side := range []struct {
		name string
		key  string
		id   string
		who  e2ee.OwnerLinkGrantSide
	}{
		{name: CommunicationLinkGrantSource, key: f.sourceOwner.ownerKeyID, id: f.link.SourceOwnerID, who: e2ee.OwnerLinkGrantSideSource},
		{name: CommunicationLinkGrantTarget, key: f.targetOwner.ownerKeyID, id: f.link.TargetOwnerID, who: e2ee.OwnerLinkGrantSideTarget},
	} {
		var identity *e2ee.Identity
		if side.name == CommunicationLinkGrantSource {
			identity = f.sourceOwner.identity
		} else {
			identity = f.targetOwner.identity
		}
		proof, err := identity.SignOwnerLinkReviewPolicy(side.id, f.link.ID, f.link.ContractDigest,
			digest, uint64(f.link.Version), 1, side.who, now.Add(-time.Second), proofExpiry)
		if err != nil {
			t.Fatal(err)
		}
		status, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID,
			side.name, side.key, 0, policy, proof)
		if err != nil {
			t.Fatal(err)
		}
		if side.name == CommunicationLinkGrantTarget && !status.Current {
			t.Fatal("short-lived bilateral policy did not activate")
		}
	}
	f.messageID = "msg_link_review_proof_expiry"
	f.ciphertext = f.seal(t)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(CommunicationLinkSealedSend{
		NodeCredentialDigest: f.sourceOwner.nodeCredential, LinkID: f.link.ID,
		MessageID: f.messageID, DataScope: f.dataScope, Ciphertext: f.ciphertext,
	}); err != nil {
		t.Fatal(err)
	}
	var rawExpiry string
	if err := f.base.store.db.QueryRow(`SELECT expires_at FROM communication_link_message_reviews_v2 WHERE message_id=?`, f.messageID).Scan(&rawExpiry); err != nil {
		t.Fatal(err)
	}
	reviewExpiry, err := time.Parse(time.RFC3339Nano, rawExpiry)
	if err != nil || reviewExpiry.After(proofExpiry.Add(100*time.Millisecond)) || reviewExpiry.Before(proofExpiry.Add(-100*time.Millisecond)) {
		t.Fatalf("review lifetime did not stop at the shortest owner proof: expiry=%v proofExpiry=%v err=%v", reviewExpiry, proofExpiry, err)
	}
	time.Sleep(time.Until(proofExpiry) + 50*time.Millisecond)
	page, err := f.base.store.ListCommunicationLinkMessageReviewsPageForActor(reviewer.scope, "", 10)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("expired review remained visible: page=%+v err=%v", page, err)
	}
	var status, inboxState string
	if err := f.base.store.db.QueryRow(`SELECT r.status,i.state FROM communication_link_message_reviews_v2 r
JOIN relay_v2_inbox i ON i.message_id=r.message_id WHERE r.message_id=?`, f.messageID).Scan(&status, &inboxState); err != nil {
		t.Fatal(err)
	}
	if status != CommunicationLinkReviewExpiredStatus || inboxState != RelayInboxFailed {
		t.Fatalf("proof expiry did not persist terminal cleanup: review=%q inbox=%q", status, inboxState)
	}
	// An expired pending row must not pin Link policy updates indefinitely.
	recordCommunicationLinkReviewPolicy(t, f, policy, 1)
}

func TestCommunicationLinkReviewPolicyRejectsPolicyMismatchAndStaleCAS(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	first := addCommunicationLinkReviewer(t, f.base.store, "ep_review_policy", f.link.SourceOwnerID,
		f.link.SourceGroupID, []string{"link.review"})
	policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewMetadata,
		Reviewers:            []CommunicationLinkReviewer{{EndpointID: first.scope.EndpointID, GroupID: first.scope.GroupID}},
		ReviewerLeaseSeconds: 30, MaxReviewAgeSeconds: 600}
	active := recordCommunicationLinkReviewPolicy(t, f, policy, 0)
	if _, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID,
		CommunicationLinkGrantSource, f.sourceOwner.ownerKeyID, 0, policy, []byte("synthetic stale proof")); !errors.Is(err, ErrCommunicationLinkReviewConflict) {
		t.Fatalf("stale policy CAS was not rejected: %v", err)
	}
	got, err := f.base.store.GetCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.TargetOwnerID)
	if err != nil || got.PolicyVersion != active.PolicyVersion || got.PolicyDigest != active.PolicyDigest {
		t.Fatalf("policy owner read differs from active version: got=%+v err=%v", got, err)
	}
	bad := policy
	bad.MaxReviewAgeSeconds++
	_, _, badDigest, err := normalizeCommunicationLinkReviewPolicy(bad)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires, _ := time.Parse(time.RFC3339, f.link.ExpiresAt)
	proof, err := f.sourceOwner.identity.SignOwnerLinkReviewPolicy(f.link.SourceOwnerID,
		f.link.ID, f.link.ContractDigest, badDigest, uint64(f.link.Version), uint64(active.PolicyVersion+1),
		e2ee.OwnerLinkGrantSideSource, now.Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID,
		CommunicationLinkGrantSource, f.sourceOwner.ownerKeyID, active.PolicyVersion, bad, proof)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current {
		t.Fatal("one side's mismatching next policy changed the active head")
	}
	got, err = f.base.store.GetCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID)
	if err != nil || got.PolicyVersion != active.PolicyVersion || got.PolicyDigest != active.PolicyDigest {
		t.Fatalf("incomplete policy proposal replaced the current head: got=%+v err=%v", got, err)
	}
}

func TestCommunicationLinkReviewPolicyRejectsCASOverflowAndPermitsFinalVersion(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, false)
	policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewNone, Reviewers: []CommunicationLinkReviewer{}}
	if _, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID, CommunicationLinkGrantSource, f.sourceOwner.ownerKeyID, math.MaxInt64, policy, []byte("synthetic overflow proof")); !errors.Is(err, ErrCommunicationLinkReviewPolicy) {
		t.Fatalf("overflow was not rejected as invalid input: %v", err)
	}
	recordCommunicationLinkReviewPolicy(t, f, policy, 0)
	// Fixture-only boundary setup: production transitions still use signed proofs.
	if _, err := f.base.store.db.Exec(`UPDATE communication_link_review_policy_heads_v2 SET policy_version=? WHERE link_id=?`, int64(math.MaxInt64-1), f.link.ID); err != nil {
		t.Fatal(err)
	}
	preview, err := f.base.store.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy)
	if err != nil || preview.ExpectedPolicyVersion != math.MaxInt64-1 || preview.PolicyVersion != math.MaxInt64 {
		t.Fatalf("final representable preview: %v", err)
	}
	active := recordCommunicationLinkReviewPolicy(t, f, policy, math.MaxInt64-1)
	if active.PolicyVersion != math.MaxInt64 {
		t.Fatal("final valid policy version refused")
	}
	if _, err := f.base.store.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy); !errors.Is(err, ErrCommunicationLinkReviewConflict) {
		t.Fatalf("exhausted version preview overflowed: %v", err)
	}
}

// Candidate eligibility must use the same current native actor authority as
// actual review. Preview never promises eligibility for a later transaction.
func TestCommunicationLinkReviewPolicyCurrentReviewerQualification(t *testing.T) {
	for _, test := range []struct {
		name   string
		grants []string
		mutate func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, policy *CommunicationLinkReviewPolicy)
	}{
		{name: "no review grant", grants: []string{"message.ask"}},
		{name: "grant removed after preview", grants: []string{"link.review"}, mutate: func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, _ *CommunicationLinkReviewPolicy) {
			if _, err := s.db.Exec(`UPDATE memberships SET grants_json='["message.ask"]',revision=revision+1 WHERE id=?`, actor.scope.MembershipID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "membership revoked after preview", grants: []string{"link.review"}, mutate: func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, _ *CommunicationLinkReviewPolicy) {
			if _, err := s.db.Exec(`UPDATE memberships SET status='revoked',revision=revision+1 WHERE id=?`, actor.scope.MembershipID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "binding expired after preview", grants: []string{"link.review"}, mutate: func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, _ *CommunicationLinkReviewPolicy) {
			if _, err := s.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), actor.scope.BindingID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "binding released after preview", grants: []string{"link.review"}, mutate: func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, _ *CommunicationLinkReviewPolicy) {
			if _, err := s.ReleaseSessionBindingLease(actor.scope.BindingID, actor.scope.LeaseOwner, actor.scope.BindingEpoch); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "binding pointer replaced after preview", grants: []string{"link.review"}, mutate: func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, _ *CommunicationLinkReviewPolicy) {
			if _, err := s.db.Exec(`UPDATE fabric_endpoints SET binding_id='synthetic_missing_reviewer_binding' WHERE id=?`, actor.scope.EndpointID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "native session replaced after preview", grants: []string{"link.review"}, mutate: func(t *testing.T, s *Store, actor communicationLinkReviewTestActor, _ *CommunicationLinkReviewPolicy) {
			if _, err := s.db.Exec(`UPDATE fabric_endpoints SET native_session_id='synthetic_replaced_reviewer_session' WHERE id=?`, actor.scope.EndpointID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong group after preview", grants: []string{"link.review"}, mutate: func(_ *testing.T, _ *Store, _ communicationLinkReviewTestActor, policy *CommunicationLinkReviewPolicy) {
			policy.Reviewers[0].GroupID = "synthetic_unrelated_group"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkSealedSendTestFixture(t, true)
			actor := addCommunicationLinkReviewer(t, f.base.store, "ep_review_eligibility", f.link.SourceOwnerID,
				f.link.SourceGroupID, test.grants)
			policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewMetadata,
				Reviewers:            []CommunicationLinkReviewer{{EndpointID: actor.scope.EndpointID, GroupID: actor.scope.GroupID}},
				ReviewerLeaseSeconds: 30, MaxReviewAgeSeconds: 600}
			if test.mutate != nil {
				if _, err := f.base.store.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy); err != nil {
					t.Fatalf("qualified initial preview: %v", err)
				}
				test.mutate(t, f.base.store, actor, &policy)
			}
			_, _, digest, err := normalizeCommunicationLinkReviewPolicy(policy)
			if err != nil {
				t.Fatal(err)
			}
			expires, err := time.Parse(time.RFC3339, f.link.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := f.sourceOwner.identity.SignOwnerLinkReviewPolicy(f.link.SourceOwnerID,
				f.link.ID, f.link.ContractDigest, digest, uint64(f.link.Version), 1,
				e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), expires)
			if err != nil {
				t.Fatal(err)
			}
			if p, err := f.base.store.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy); !errors.Is(err, ErrCommunicationLinkReviewPolicy) || p != nil {
				t.Fatalf("unqualified reviewer preview not generically rejected: result=%v err=%v", p, err)
			}
			if p, err := f.base.store.RecordCommunicationLinkReviewPolicyForOwner(f.link.ID, CommunicationLinkGrantSource,
				f.sourceOwner.ownerKeyID, 0, policy, proof); !errors.Is(err, ErrCommunicationLinkReviewPolicy) || p != nil {
				t.Fatalf("unqualified reviewer grant not generically rejected: result=%v err=%v", p, err)
			}
			var accepted int
			if err := f.base.store.db.QueryRow(`SELECT count(*) FROM communication_link_review_policy_grants_v2 WHERE link_id=?`, f.link.ID).Scan(&accepted); err != nil || accepted != 0 {
				t.Fatalf("rejection persisted Owner consent: count=%d err=%v", accepted, err)
			}
		})
	}
}

func TestCommunicationLinkReviewPolicyQualifiedCurrentReviewer(t *testing.T) {
	for _, test := range []struct {
		name   string
		grants []string
		renew  bool
	}{
		{name: "explicit review grant", grants: []string{"link.review"}},
		{name: "existing wildcard grant", grants: []string{"*"}},
		{name: "fresh current binding epoch", grants: []string{"link.review"}, renew: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLinkSealedSendTestFixture(t, true)
			actor := addCommunicationLinkReviewer(t, f.base.store, "ep_review_current", f.link.SourceOwnerID,
				f.link.SourceGroupID, test.grants)
			policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewMetadata,
				Reviewers:            []CommunicationLinkReviewer{{EndpointID: actor.scope.EndpointID, GroupID: actor.scope.GroupID}},
				ReviewerLeaseSeconds: 30, MaxReviewAgeSeconds: 600}
			if test.renew {
				released, err := f.base.store.ReleaseSessionBindingLease(actor.scope.BindingID, actor.scope.LeaseOwner, actor.scope.BindingEpoch)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.base.store.AcquireSessionBindingLease(released.ID, actor.scope.LeaseOwner, released.Epoch,
					time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			for _, ownerID := range []string{f.link.SourceOwnerID, f.link.TargetOwnerID} {
				p, err := f.base.store.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, ownerID, policy)
				if err != nil || p == nil || len(p.Policy.Reviewers) != 1 {
					t.Fatalf("qualified preview: %v", err)
				}
			}
			if p, err := f.base.store.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, "synthetic_unrelated_owner", policy); !errors.Is(err, ErrCommunicationLinkNotFound) || p != nil {
				t.Fatalf("third Owner received reviewer policy: result=%v err=%v", p, err)
			}
			recordCommunicationLinkReviewPolicy(t, f, policy, 0)
		})
	}
}
