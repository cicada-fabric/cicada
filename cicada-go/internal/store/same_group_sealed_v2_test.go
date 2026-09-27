package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type sameGroupSealedV1EndpointFixture struct {
	id        string
	nodeID    string
	principal string
	binding   *SessionBinding
	identity  *e2ee.Identity
}

type sameGroupSealedV1Fixture struct {
	store      *Store
	dbPath     string
	ownerID    string
	groupID    string
	source     sameGroupSealedV1EndpointFixture
	target     sameGroupSealedV1EndpointFixture
	sameNode   sameGroupSealedV1EndpointFixture
	sourceNode linkSealedSendTestOwner
	targetNode linkSealedSendTestOwner
	owner      *e2ee.Identity
	ownerKeyID string
}

func newSameGroupSealedV1Fixture(t *testing.T) *sameGroupSealedV1Fixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "same-group-sealed.sqlite3")
	s, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ownerID, groupID := "owner_same_group_sealed", "grp_same_group_sealed"
	ownerPrincipal, err := s.CreatePrincipal(Principal{ID: ownerID, Kind: PrincipalKindHuman,
		OwnerID: ownerID, TrustDomainID: ownerID, Name: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(Group{ID: groupID, OwnerPrincipalID: ownerPrincipal.ID,
		TrustDomainID: ownerID, Name: groupID, State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	createEndpoint := func(endpointID, nodeID string) sameGroupSealedV1EndpointFixture {
		t.Helper()
		principalID := "pr_" + endpointID
		principal, err := s.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
			OwnerID: ownerID, TrustDomainID: ownerID, Name: endpointID,
			Status: PrincipalStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateMembership(Membership{PrincipalID: principal.ID,
			GroupID: groupID, Role: "member"}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := s.UpsertEndpointV2(Endpoint{ID: endpointID, Name: endpointID,
			Harness: "codex", NativeSessionID: "native_" + endpointID,
			MachineID: nodeID, Owner: ownerID, Status: "online",
			PrincipalID: principal.ID, GroupID: groupID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := s.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
			PrincipalID: principal.ID, GroupID: groupID,
			NativeSessionID: endpoint.NativeSessionID, NodeID: nodeID})
		if err != nil {
			t.Fatal(err)
		}
		binding, err = s.AcquireSessionBindingLease(binding.ID, "lease_"+endpointID,
			binding.Epoch, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		identity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := identity.SignEndpointKeyAttestation(endpointID,
			principal.ID, nodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RegisterEndpointKeyCandidate(endpointID, principal.ID,
			binding.ID, binding.Epoch, attestation); err != nil {
			t.Fatal(err)
		}
		return sameGroupSealedV1EndpointFixture{id: endpointID, nodeID: nodeID,
			principal: principal.ID, binding: binding, identity: identity}
	}
	source := createEndpoint("ep_sgs_source", "node_sgs_source")
	target := createEndpoint("ep_sgs_target", "node_sgs_target")
	sameNode := createEndpoint("ep_sgs_same_node", source.nodeID)

	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal(ownerID, owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	sourceNode := bindLinkSealedSendTestNode(t, s, ownerID, source.nodeID)
	targetNode := bindLinkSealedSendTestNode(t, s, ownerID, target.nodeID)
	f := &sameGroupSealedV1Fixture{store: s, dbPath: dbPath, ownerID: ownerID, groupID: groupID,
		source: source, target: target, sameNode: sameNode,
		sourceNode: sourceNode, targetNode: targetNode,
		owner: owner, ownerKeyID: ownerKey.KeyID}
	for _, endpointID := range []string{source.id, target.id, sameNode.id} {
		f.grant(t, endpointID)
	}
	return f
}

func (f *sameGroupSealedV1Fixture) grant(t *testing.T, endpointID string) {
	t.Helper()
	issuedAt := time.Now().UTC().Add(-time.Minute)
	expiresAt := time.Now().UTC().Add(time.Hour)
	manifest, err := f.store.PreviewGroupEndpointKeyGrant(f.ownerID,
		f.groupID, endpointID, f.ownerKeyID, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err = time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err = time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.owner.SignOwnerLinkKeyGrant(manifest.OwnerID,
		GroupEndpointKeyGrantOperation, manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AcceptGroupEndpointKeyGrant(f.ownerID, f.groupID,
		endpointID, f.ownerKeyID, proof); err != nil {
		t.Fatal(err)
	}
}

func (f *sameGroupSealedV1Fixture) peer(t *testing.T, sender, receiver sameGroupSealedV1EndpointFixture,
	credential string) (*SameGroupSealedV1PeerKey, sameGroupEndpointPair) {
	t.Helper()
	peer, err := f.store.GetSameGroupSealedV1PeerKey(credential,
		f.groupID, sender.id, receiver.id)
	if err != nil {
		t.Fatal(err)
	}
	return peer, sameGroupEndpointPair{hubID: peer.HubID, groupID: peer.GroupID,
		sender: peer.Sender, receiver: peer.Receiver}
}

func (f *sameGroupSealedV1Fixture) seal(t *testing.T,
	sender, receiver sameGroupSealedV1EndpointFixture, credential,
	messageID, kind, requestID, replyTo string) []byte {
	t.Helper()
	_, pair := f.peer(t, sender, receiver, credential)
	context := sameGroupSealedV1Context(pair, messageID, kind, requestID, replyTo)
	wire, err := e2ee.SealEndpointMessage(sender.identity, receiver.identity.Public(),
		context, []byte("opaque application payload"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func sameGroupSealedV1ClaimInput(receiver sameGroupSealedV1EndpointFixture,
	consumer string) RelayClaimInput {
	return RelayClaimInput{RecipientEndpointID: receiver.id, ConsumerID: consumer,
		BindingID: receiver.binding.ID, BindingEpoch: receiver.binding.Epoch, Limit: 10}
}

func TestSameGroupSealedV1SendRequiresCurrentOwnerNodeAndCrossNodeGrant(t *testing.T) {
	f := newSameGroupSealedV1Fixture(t)
	peer, _ := f.peer(t, f.source, f.target, f.sourceNode.nodeCredential)
	if peer.Receiver.NativeSessionID != "" {
		t.Fatal("peer-key response exposed the target native Session ID")
	}
	if peer.Sender.NativeSessionID == "" {
		t.Fatal("peer-key response omitted the source Node's own Session ID")
	}
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		"msg_sgs_send", "SEND", "", "")
	input := SameGroupSealedV1Send{NodeCredentialDigest: f.sourceNode.nodeCredential,
		GroupID: f.groupID, SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
		MessageID: "msg_sgs_send", IdempotencyKey: "idem_sgs_send",
		DataScope: SameGroupSealedV1DataScope, Ciphertext: wire}
	if _, err := f.store.EnqueueSameGroupSealedV1Send(input); err != nil {
		t.Fatalf("current same-Group cross-Node SEND was denied: %v", err)
	}
	retry, err := f.store.EnqueueSameGroupSealedV1Send(input)
	if err != nil || retry.Route.MessageID != input.MessageID {
		t.Fatalf("exact SEND retry was not idempotent: record=%#v err=%v", retry, err)
	}
	forged := input
	forged.NodeCredentialDigest = f.targetNode.nodeCredential
	forged.MessageID = "msg_sgs_forged_sender"
	forged.Ciphertext = f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		forged.MessageID, "SEND", "", "")
	if _, err := f.store.EnqueueSameGroupSealedV1Send(forged); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("another Node credential forged the source Endpoint: %v", err)
	}
	wrongScope := input
	wrongScope.MessageID = "msg_sgs_wrong_scope"
	wrongScope.DataScope = "thread.private_history"
	if _, err := f.store.EnqueueSameGroupSealedV1Send(wrongScope); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("caller widened the fixed same-Group scope: %v", err)
	}
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		f.groupID, f.source.id, f.sameNode.id); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("same-Node route was not refused: %v", err)
	}
	otherGroup := "grp_sgs_other"
	ownerPrincipal, err := f.store.GetPrincipal(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateGroup(Group{ID: otherGroup, OwnerPrincipalID: ownerPrincipal.ID,
		TrustDomainID: f.ownerID, Name: otherGroup, State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateMembership(Membership{PrincipalID: f.target.principal,
		GroupID: otherGroup, Role: "member"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.JoinEndpointGroup(f.target.id, otherGroup); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PreviewGroupEndpointKeyGrant(f.ownerID, otherGroup,
		f.target.id, f.ownerKeyID, time.Now().UTC().Add(-time.Minute),
		time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetSameGroupSealedV1PeerKey(f.sourceNode.nodeCredential,
		otherGroup, f.source.id, f.target.id); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("Endpoints without a common Group were routed together: %v", err)
	}
}

func TestSameGroupSealedV1ClaimAndAskReplyRecheckExactAttempt(t *testing.T) {
	f := newSameGroupSealedV1Fixture(t)
	messageID, requestID := "msg_sgs_ask", "rq_sgs_ask"
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		messageID, "REQUEST", requestID, "")
	expiresAt := time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano)
	input := SameGroupSealedV1Ask{NodeCredentialDigest: f.sourceNode.nodeCredential,
		GroupID: f.groupID, SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
		MessageID: messageID, RequestID: requestID, IdempotencyKey: "idem_sgs_ask",
		DataScope: SameGroupSealedV1DataScope, ExpiresAt: expiresAt, Ciphertext: wire}
	request, err := f.store.EnqueueSameGroupSealedV1Ask(input)
	if err != nil || request.State != FabricRequestOpen {
		t.Fatalf("valid same-Group ASK was denied: request=%#v err=%v", request, err)
	}
	retry, err := f.store.EnqueueSameGroupSealedV1Ask(input)
	if err != nil || retry.RequestID != request.RequestID || retry.MessageID != request.MessageID {
		t.Fatalf("exact ASK retry was not idempotent: request=%#v err=%v", retry, err)
	}
	if _, err := f.store.GetSameGroupSealedV1RequestStatus(f.targetNode.nodeCredential,
		requestID); err != nil {
		t.Fatalf("target Node could not read its request status: %v", err)
	}
	claimInput := sameGroupSealedV1ClaimInput(f.target, "consumer_sgs_target")
	generic, err := f.store.ClaimRelaySealedV1Inbox(claimInput)
	if err != nil || len(generic) != 0 {
		t.Fatalf("generic sealed claim bypassed same-Group authorization: attempts=%#v err=%v", generic, err)
	}
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential, claimInput)
	if err != nil || len(claims) != 1 || claims[0].MessageID != messageID {
		t.Fatalf("specialized claim did not deliver the queued ASK: attempts=%#v err=%v", claims, err)
	}
	if _, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		f.sourceNode.nodeCredential, messageID, claims[0].AttemptID); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("wrong Node credential authorized pre-injection: %v", err)
	}
	authorization, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		f.targetNode.nodeCredential, messageID, claims[0].AttemptID)
	if err != nil || authorization.EndpointID != f.target.id ||
		authorization.NativeSessionID != "native_"+f.target.id ||
		authorization.Sender.NativeSessionID != "" ||
		authorization.Receiver.NativeSessionID != "native_"+f.target.id {
		t.Fatalf("exact receiver pre-injection authorization failed or leaked a remote session: authorization=%#v err=%v", authorization, err)
	}
	wrongReceipt, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: claims[0].AttemptID, MessageID: claims[0].MessageID,
		Digest: claims[0].Digest, TargetEndpointID: f.target.id,
		BindingID: "binding_forged", BindingEpoch: claims[0].BindingEpoch,
		Layer: RelayReceiptNodeReceived,
	})
	if err == nil || wrongReceipt != nil {
		t.Fatalf("wrong binding receipt changed the attempt: receipt=%#v err=%v", wrongReceipt, err)
	}
	if _, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: claims[0].AttemptID, MessageID: claims[0].MessageID,
		Digest: claims[0].Digest, TargetEndpointID: f.target.id,
		BindingID: claims[0].BindingID, BindingEpoch: claims[0].BindingEpoch,
		Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		f.targetNode.nodeCredential, messageID, claims[0].AttemptID); err != nil {
		t.Fatalf("NODE_RECEIVED evidence incorrectly blocked pre-injection authorization: %v", err)
	}
	if _, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: claims[0].AttemptID, MessageID: claims[0].MessageID,
		Digest: claims[0].Digest, TargetEndpointID: f.target.id,
		BindingID: claims[0].BindingID, BindingEpoch: claims[0].BindingEpoch,
		Layer: RelayReceiptRuntimeInjected,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		f.targetNode.nodeCredential, messageID, claims[0].AttemptID); !errors.Is(err, ErrSameGroupSealedV1Denied) {
		t.Fatalf("pre-injection authorization was allowed after runtime injection: %v", err)
	}

	// The original responder's credential supplies the reverse route. A caller
	// cannot choose a different Group, requester, or destination for a reply.
	_, reverse := f.peer(t, f.target, f.source, f.targetNode.nodeCredential)
	replyID := "msg_sgs_reply"
	replyWire, err := e2ee.SealEndpointMessage(f.target.identity,
		f.source.identity.Public(), sameGroupSealedV1Context(reverse, replyID,
			"REPLY", requestID, messageID), []byte("opaque reply"), 1)
	if err != nil {
		t.Fatal(err)
	}
	replyInput := SameGroupSealedV1Reply{NodeCredentialDigest: f.targetNode.nodeCredential,
		RequestID: requestID, MessageID: replyID, Ciphertext: replyWire}
	replied, err := f.store.EnqueueSameGroupSealedV1Reply(replyInput)
	if err != nil || replied.State != FabricRequestReplied || replied.ReplyMessageID != replyID {
		t.Fatalf("current responder could not create correlated reverse reply: request=%#v err=%v", replied, err)
	}
	replyRetry, err := f.store.EnqueueSameGroupSealedV1Reply(replyInput)
	if err != nil || replyRetry.State != FabricRequestReplied || replyRetry.ReplyMessageID != replyID {
		t.Fatalf("exact reply retry was not idempotent: request=%#v err=%v", replyRetry, err)
	}
	sourceClaims, err := f.store.ClaimSameGroupSealedV1Inbox(f.sourceNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.source, "consumer_sgs_source"))
	if err != nil || len(sourceClaims) != 1 || sourceClaims[0].MessageID != replyID {
		t.Fatalf("original requester did not receive its correlated reply: attempts=%#v err=%v", sourceClaims, err)
	}
	sourceAuthorization, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		f.sourceNode.nodeCredential, replyID, sourceClaims[0].AttemptID)
	if err != nil || sourceAuthorization.EndpointID != f.source.id ||
		sourceAuthorization.NativeSessionID != "native_"+f.source.id ||
		sourceAuthorization.Sender.NativeSessionID != "" {
		t.Fatalf("reverse pre-injection authorization failed: authorization=%#v err=%v", sourceAuthorization, err)
	}
}

func TestSameGroupSealedV1RevocationFailsClaimAndPreInjection(t *testing.T) {
	t.Run("queued", func(t *testing.T) {
		f := newSameGroupSealedV1Fixture(t)
		messageID := "msg_sgs_revoked_before_claim"
		wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
			messageID, "SEND", "", "")
		if _, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
			NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
			SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
			MessageID: messageID, DataScope: SameGroupSealedV1DataScope, Ciphertext: wire,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.db.Exec(`UPDATE memberships SET status=?,revision=revision+1
WHERE principal_id=? AND group_id=?`, MembershipStatusRevoked, f.target.principal, f.groupID); err != nil {
			t.Fatal(err)
		}
		claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
			sameGroupSealedV1ClaimInput(f.target, "consumer_sgs_stale"))
		if err != nil || len(claims) != 0 {
			t.Fatalf("revoked Group grant reached the receiver: attempts=%#v err=%v", claims, err)
		}
		var state string
		if err := f.store.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`,
			messageID).Scan(&state); err != nil || state != RelayInboxFailed {
			t.Fatalf("stale queued row was not made terminal: state=%q err=%v", state, err)
		}
	})
	t.Run("before injection", func(t *testing.T) {
		f := newSameGroupSealedV1Fixture(t)
		messageID := "msg_sgs_revoked_before_injection"
		wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
			messageID, "SEND", "", "")
		if _, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
			NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
			SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
			MessageID: messageID, DataScope: SameGroupSealedV1DataScope, Ciphertext: wire,
		}); err != nil {
			t.Fatal(err)
		}
		claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
			sameGroupSealedV1ClaimInput(f.target, "consumer_sgs_before_injection"))
		if err != nil || len(claims) != 1 {
			t.Fatalf("current message was not claimed: attempts=%#v err=%v", claims, err)
		}
		if _, err := f.store.db.Exec(`UPDATE memberships SET status=?,revision=revision+1
WHERE principal_id=? AND group_id=?`, MembershipStatusRevoked, f.target.principal, f.groupID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
			f.targetNode.nodeCredential, messageID, claims[0].AttemptID); !errors.Is(err, ErrSameGroupSealedV1Denied) {
			t.Fatalf("grant revocation between claim and injection was ignored: %v", err)
		}
		var attemptState string
		if err := f.store.db.QueryRow(`SELECT state FROM relay_v2_delivery_attempts WHERE attempt_id=?`,
			claims[0].AttemptID).Scan(&attemptState); err != nil || attemptState != RelayAttemptFailed {
			t.Fatalf("stale pre-injection attempt was not fenced: state=%q err=%v", attemptState, err)
		}
	})
}

func TestSameGroupSealedV1StaleBindingCancelsAskAndReleasesQuota(t *testing.T) {
	queueAsk := func(t *testing.T, f *sameGroupSealedV1Fixture, suffix string) string {
		t.Helper()
		messageID, requestID := "msg_sgs_stale_binding_"+suffix, "rq_sgs_stale_binding_"+suffix
		wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
			messageID, "REQUEST", requestID, "")
		_, err := f.store.EnqueueSameGroupSealedV1Ask(SameGroupSealedV1Ask{
			NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
			SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
			MessageID: messageID, RequestID: requestID, DataScope: SameGroupSealedV1DataScope,
			ExpiresAt:  time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
			Ciphertext: wire,
		})
		if err != nil {
			t.Fatal(err)
		}
		return requestID
	}
	assertCancelledAndQuotaReleased := func(t *testing.T, f *sameGroupSealedV1Fixture,
		requestID string) {
		t.Helper()
		var requestState string
		if err := f.store.db.QueryRow(`SELECT state FROM relay_v2_requests WHERE request_id=?`,
			requestID).Scan(&requestState); err != nil || requestState != FabricRequestCancelled {
			t.Fatalf("stale binding left Ask active: state=%q err=%v", requestState, err)
		}
		tx, err := f.store.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		pending, err := relayPendingAskCountTx(tx,
			RelayAdmissionScopeReceiver, "", "", f.target.id,
			time.Now().UTC().Format(time.RFC3339Nano))
		_ = tx.Rollback()
		if err != nil || pending != 0 {
			t.Fatalf("cancelled stale Ask still consumes receiver quota: pending=%d err=%v", pending, err)
		}
	}

	t.Run("expired lease", func(t *testing.T) {
		f := newSameGroupSealedV1Fixture(t)
		requestID := queueAsk(t, f, "expired")
		if _, err := f.store.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`,
			time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), f.target.binding.ID); err != nil {
			t.Fatal(err)
		}
		claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
			sameGroupSealedV1ClaimInput(f.target, "consumer_sgs_expired_binding"))
		if err != nil || len(claims) != 0 {
			t.Fatalf("expired binding received a same-Group Ask: claims=%#v err=%v", claims, err)
		}
		assertCancelledAndQuotaReleased(t, f, requestID)
	})

	t.Run("binding replaced", func(t *testing.T) {
		f := newSameGroupSealedV1Fixture(t)
		requestID := queueAsk(t, f, "replaced")
		if _, err := f.store.RevokeSessionBinding(f.target.binding.ID,
			f.target.binding.Epoch, "test binding rotation"); err != nil {
			t.Fatal(err)
		}
		replacement, err := f.store.CreateSessionBinding(SessionBinding{
			ID: "binding_sgs_target_replacement", EndpointID: f.target.id,
			PrincipalID: f.target.principal, GroupID: f.groupID,
			NativeSessionID: "native_" + f.target.id, NodeID: f.target.nodeID,
			ReplacesBindingID: f.target.binding.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		replacement, err = f.store.AcquireSessionBindingLease(replacement.ID,
			"lease_sgs_target_replacement", replacement.Epoch,
			time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
			RelayClaimInput{RecipientEndpointID: f.target.id, ConsumerID: "consumer_sgs_replaced_binding",
				BindingID: replacement.ID, BindingEpoch: replacement.Epoch, Limit: 10})
		if err != nil || len(claims) != 0 {
			t.Fatalf("replaced binding received an old same-Group Ask: claims=%#v err=%v", claims, err)
		}
		assertCancelledAndQuotaReleased(t, f, requestID)
	})
}

func TestSameGroupSealedV1CancellationAllowsOnlyLateEncryptedResult(t *testing.T) {
	f := newSameGroupSealedV1Fixture(t)
	messageID, requestID := "msg_sgs_cancel_ask", "rq_sgs_cancel_ask"
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		messageID, "REQUEST", requestID, "")
	request, err := f.store.EnqueueSameGroupSealedV1Ask(SameGroupSealedV1Ask{
		NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
		SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
		MessageID: messageID, RequestID: requestID, DataScope: SameGroupSealedV1DataScope,
		ExpiresAt:  time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
		Ciphertext: wire,
	})
	if err != nil || request.State != FabricRequestOpen {
		t.Fatalf("enqueue ASK: request=%#v err=%v", request, err)
	}
	cancelled, err := f.store.CancelSameGroupSealedV1Request(f.sourceNode.nodeCredential, requestID)
	if err != nil || cancelled.State != FabricRequestCancelRequested {
		t.Fatalf("source Node could not cancel its request: request=%#v err=%v", cancelled, err)
	}
	if _, err := f.store.CancelSameGroupSealedV1Request(f.targetNode.nodeCredential, requestID); !errors.Is(err, ErrSameGroupSealedV1NotFound) {
		t.Fatalf("responder Node cancelled the source request: %v", err)
	}
	_, reverse := f.peer(t, f.target, f.source, f.targetNode.nodeCredential)
	replyID := "msg_sgs_late_reply"
	replyWire, err := e2ee.SealEndpointMessage(f.target.identity, f.source.identity.Public(),
		sameGroupSealedV1Context(reverse, replyID, "REPLY", requestID, messageID),
		[]byte("encrypted late result"), 1)
	if err != nil {
		t.Fatal(err)
	}
	late, err := f.store.EnqueueSameGroupSealedV1Reply(SameGroupSealedV1Reply{
		NodeCredentialDigest: f.targetNode.nodeCredential, RequestID: requestID,
		MessageID: replyID, Ciphertext: replyWire,
	})
	if err != nil || late.State != FabricRequestLateResult || late.LateResultMessageID != replyID {
		t.Fatalf("late ciphertext was not retained with terminal request state: request=%#v err=%v", late, err)
	}
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.sourceNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.source, "consumer_sgs_late"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("late result was offered for injection into the cancelled thread: attempts=%#v err=%v", claims, err)
	}
}

func TestSameGroupSealedV1StaleBindingCannotBeClaimed(t *testing.T) {
	f := newSameGroupSealedV1Fixture(t)
	messageID := "msg_sgs_binding_revoked"
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		messageID, "SEND", "", "")
	if _, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
		NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
		SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
		MessageID: messageID, DataScope: SameGroupSealedV1DataScope, Ciphertext: wire,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE session_bindings SET status=? WHERE id=?`,
		SessionBindingStatusRevoked, f.target.binding.ID); err != nil {
		t.Fatal(err)
	}
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.target, "consumer_sgs_revoked_binding"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("revoked binding allowed claim: attempts=%#v err=%v", claims, err)
	}
	var state string
	if err := f.store.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`,
		messageID).Scan(&state); err != nil || state != RelayInboxFailed {
		t.Fatalf("revoked binding queue row was not terminal: state=%q err=%v", state, err)
	}
}
