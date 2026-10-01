package store

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

func newRelayV2TestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.initializeRelayV2Schema(); err != nil {
		store.Close()
		t.Fatal(err)
	}
	preparingRelaySealedSenderFixture(t, store)
	preparingNetworkActorFixture(t, store, "group-a", "principal-b", "ep-b")
	return store
}

func relayTestAsk(requestID, messageID, digest, key, body string) FabricRequest {
	return FabricRequest{
		RequestID: requestID, MessageID: messageID,
		SenderEndpointID: "ep-a", SenderPrincipalID: "principal-a", SenderGroupID: "group-a",
		ReceiverEndpointID: "ep-b", ReceiverPrincipalID: "principal-b", ReceiverGroupID: "group-a",
		ReceiverBindingID: "binding-b", ReceiverBindingEpoch: 7,
		Digest: digest, IdempotencyKey: key, Body: body,
	}
}

func relayTestSealedV1(messageID, idempotencyKey string, ciphertext []byte) RelaySealedV1Input {
	return RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: messageID, SenderEndpointID: "ep-a",
			ReceiverEndpointID: "ep-b", Kind: "send"},
		Security: RelayMessageSecurity{SenderEndpointID: "ep-a", SenderPrincipalID: "principal-a",
			SenderGroupID: "group-a", ReceiverEndpointID: "ep-b", ReceiverPrincipalID: "principal-b",
			ReceiverGroupID: "group-a", ReceiverBindingID: "binding-b", ReceiverBindingEpoch: 1,
			VisibilityPolicyRef: "visible-to-recipient", AuthorizationRef: "link-grant-v1"},
		Ciphertext: ciphertext, IdempotencyKey: idempotencyKey,
	}
}

func setupRelaySealedGroup(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.CreateGroup(Group{ID: "group-a", Name: "group-a", State: GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	preparingRelaySealedSenderFixture(t, store)
}

func setupRelaySealedReceiver(t *testing.T, store *Store, endpointID, principalID, bindingID string) *SessionBinding {
	t.Helper()
	principal, err := store.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent, Name: principalID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: "group-a", Grants: []string{"message.receive"}}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := store.UpsertEndpoint(Endpoint{ID: endpointID, Name: endpointID, Harness: "codex",
		NativeSessionID: "native-" + endpointID, MachineID: "node-" + endpointID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := store.CreateSessionBinding(SessionBinding{ID: bindingID, EndpointID: endpoint.ID,
		PrincipalID: principal.ID, GroupID: "group-a", NativeSessionID: endpoint.NativeSessionID,
		NodeID: "node-" + endpointID})
	if err != nil {
		t.Fatal(err)
	}
	// Sealed claims require a current native lease. Preserve the fixture's epoch
	// while supplying its explicit, parseable deadline.
	if _, err := store.db.Exec(`UPDATE session_bindings SET lease_expires_at = ? WHERE id = ?`,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), binding.ID); err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestRelaySealedV1PayloadIsOpaqueAndLegacyReadsFailClosed(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	setupRelaySealedGroup(t, store)
	setupRelaySealedReceiver(t, store, "ep-b", "principal-b", "binding-b")
	ciphertext := []byte{0x00, 0xff, 0x10, 0x00, 0x7f, 0x80}
	input := relayTestSealedV1("msg-sealed-read", "sealed-operation", ciphertext)
	created, err := store.EnqueueRelaySealedV1(input)
	if err != nil {
		t.Fatal(err)
	}
	if created.PayloadMode != RelayPayloadModeSealedV1 || !bytes.Equal(created.Ciphertext, ciphertext) || created.Sequence != 1 {
		t.Fatalf("sealed enqueue did not return the durable opaque payload: %#v", created)
	}
	if created.Security.Digest != relayCiphertextDigest(ciphertext) {
		t.Fatalf("ciphertext digest does not bind the stored bytes: %q", created.Security.Digest)
	}
	var body, payloadMode, blobType string
	var persisted []byte
	if err := store.db.QueryRow(`SELECT f.body, p.payload_mode, p.ciphertext, typeof(p.ciphertext)
FROM fabric_messages f JOIN relay_v2_message_payloads p ON p.message_id = f.id
WHERE f.id = ?`, created.Route.MessageID).Scan(&body, &payloadMode, &persisted, &blobType); err != nil {
		t.Fatal(err)
	}
	if body != "" || payloadMode != RelayPayloadModeSealedV1 || blobType != "blob" || !bytes.Equal(persisted, ciphertext) {
		t.Fatalf("sealed bytes were not isolated in their own BLOB: body=%q mode=%q type=%q bytes=%v", body, payloadMode, blobType, persisted)
	}

	read, err := store.ReceiveRelayInbox("ep-b", "legacy-reader", "", 10)
	if err != nil || len(read.Messages) != 0 {
		t.Fatalf("legacy Receive exposed a sealed row: %#v err=%v", read, err)
	}
	legacyClaim, err := store.ClaimRelayInbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "legacy-claim", BindingID: "binding-b", BindingEpoch: 1, Limit: 10})
	if err != nil || len(legacyClaim) != 0 {
		t.Fatalf("legacy Claim exposed a sealed row: %#v err=%v", legacyClaim, err)
	}
	listed, err := store.ListRelayInbox("ep-b", 0, 10)
	if err != nil || len(listed) != 0 {
		t.Fatalf("legacy inbox history exposed a sealed placeholder: %#v err=%v", listed, err)
	}
	if _, err := store.GetRelayInboxItem("ep-b", created.Sequence); !errors.Is(err, ErrRelayDeliveryNotFound) {
		t.Fatalf("legacy inbox lookup exposed a sealed placeholder: %v", err)
	}
	if _, err := store.GetRelayMessage(created.Route.MessageID); !errors.Is(err, ErrRelayPayloadModeMismatch) {
		t.Fatalf("legacy message lookup did not fail closed: %v", err)
	}
	if _, err := store.GetRelayMessageSecurity(created.Route.MessageID); !errors.Is(err, ErrRelayMessageNotFound) {
		t.Fatalf("legacy security lookup exposed a sealed route: %v", err)
	}
	if message, err := store.GetFabricMessage(created.Route.MessageID); err != nil || message != nil {
		t.Fatalf("legacy Fabric read returned a placeholder body: %#v err=%v", message, err)
	}

	sealed, err := store.GetRelaySealedV1(created.Route.MessageID)
	if err != nil || !bytes.Equal(sealed.Ciphertext, ciphertext) || sealed.Route.ReceiverEndpointID != "ep-b" || sealed.Security.AuthorizationRef != "link-grant-v1" {
		t.Fatalf("dedicated read did not return ciphertext and route metadata: %#v err=%v", sealed, err)
	}

	retry := input
	retry.Route.MessageID = "msg-sealed-retry"
	retried, err := store.EnqueueRelaySealedV1(retry)
	if err != nil || retried.Route.MessageID != created.Route.MessageID || retried.Sequence != created.Sequence {
		t.Fatalf("same ciphertext idempotency retry did not return the original row: %#v err=%v", retried, err)
	}
	conflict := input
	conflict.Route.MessageID = "msg-sealed-conflict"
	conflict.Ciphertext = []byte("different ciphertext")
	if _, err := store.EnqueueRelaySealedV1(conflict); !errors.Is(err, ErrRelayIdempotencyConflict) {
		t.Fatalf("changed ciphertext reused an idempotency key: %v", err)
	}
	if _, err := store.EnqueueRelaySealedV1(RelaySealedV1Input{Route: input.Route, Security: input.Security}); err == nil {
		t.Fatal("empty ciphertext silently downgraded or entered the queue")
	}
	unsupportedRequest := input
	unsupportedRequest.Route.MessageID = "msg-sealed-ask"
	unsupportedRequest.Route.Kind = "ask"
	unsupportedRequest.Route.RequestID = "rq-sealed-ask"
	if _, err := store.EnqueueRelaySealedV1(unsupportedRequest); err == nil {
		t.Fatal("SEALED_V1 accepted an Ask without its request/quota lifecycle")
	}

	claimed, err := store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "sealed-node", BindingID: "binding-b", BindingEpoch: 1, Limit: 1})
	if err != nil || len(claimed) != 1 || claimed[0].PayloadMode != RelayPayloadModeSealedV1 || !bytes.Equal(claimed[0].Ciphertext, ciphertext) || claimed[0].Route.MessageID != created.Route.MessageID {
		t.Fatalf("dedicated claim did not return complete sealed delivery: %#v err=%v", claimed, err)
	}
}

func TestRelaySealedV1RetryAckCrashRecoveryAndRestart(t *testing.T) {
	path := t.TempDir() + "/state/cicada.sqlite3"
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	setupRelaySealedGroup(t, store)
	setupRelaySealedReceiver(t, store, "ep-b", "principal-b", "binding-b")
	firstBytes := []byte{0x01, 0x02, 0x00, 0xfe}
	secondBytes := []byte{0x9a, 0xbc, 0x00, 0x10}
	first, err := store.EnqueueRelaySealedV1(relayTestSealedV1("msg-sealed-retry-window", "sealed-retry-window", firstBytes))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.EnqueueRelaySealedV1(relayTestSealedV1("msg-sealed-uncertain-window", "sealed-uncertain-window", secondBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	restored, err := store.GetRelaySealedV1(first.Route.MessageID)
	if err != nil || !bytes.Equal(restored.Ciphertext, firstBytes) {
		t.Fatalf("sealed BLOB did not survive Store restart: %#v err=%v", restored, err)
	}
	claimed, err := store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "node-b", BindingID: "binding-b", BindingEpoch: 1, Limit: 1})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != first.Route.MessageID || !bytes.Equal(claimed[0].Ciphertext, firstBytes) {
		t.Fatalf("initial sealed claim failed: %#v err=%v", claimed, err)
	}
	beforeNode, uncertain, err := store.RecoverStaleRelayClaims(time.Now().UTC().Add(time.Minute))
	if err != nil || beforeNode != 1 || uncertain != 0 {
		t.Fatalf("claim-before-node crash was not safely requeued: requeued=%d uncertain=%d err=%v", beforeNode, uncertain, err)
	}
	retry, err := store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "node-b-retry", BindingID: "binding-b", BindingEpoch: 1, Limit: 1})
	if err != nil || len(retry) != 1 || retry[0].AttemptID == claimed[0].AttemptID || !bytes.Equal(retry[0].Ciphertext, firstBytes) {
		t.Fatalf("sealed delivery did not retry with the original bytes and a fresh attempt: %#v err=%v", retry, err)
	}
	ack, err := store.RecordRelayReceipt(RelayReceipt{AttemptID: retry[0].AttemptID, MessageID: retry[0].MessageID,
		Digest: retry[0].Digest, TargetEndpointID: retry[0].RecipientEndpointID,
		BindingID: retry[0].BindingID, BindingEpoch: retry[0].BindingEpoch, Layer: RelayReceiptApplicationAck})
	if err != nil || ack.Layer != RelayReceiptApplicationAck {
		t.Fatalf("sealed application ACK was not durably accepted: %#v err=%v", ack, err)
	}

	uncertainClaim, err := store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "node-b", BindingID: "binding-b", BindingEpoch: 1, Limit: 1})
	if err != nil || len(uncertainClaim) != 1 || uncertainClaim[0].MessageID != second.Route.MessageID || !bytes.Equal(uncertainClaim[0].Ciphertext, secondBytes) {
		t.Fatalf("next sealed row was not claimable: %#v err=%v", uncertainClaim, err)
	}
	if _, err := store.RecordRelayReceipt(RelayReceipt{AttemptID: uncertainClaim[0].AttemptID, MessageID: uncertainClaim[0].MessageID,
		Digest: uncertainClaim[0].Digest, TargetEndpointID: uncertainClaim[0].RecipientEndpointID,
		BindingID: uncertainClaim[0].BindingID, BindingEpoch: uncertainClaim[0].BindingEpoch, Layer: RelayReceiptNodeReceived}); err != nil {
		t.Fatal(err)
	}
	beforeNode, uncertain, err = store.RecoverStaleRelayClaims(time.Now().UTC().Add(time.Minute))
	if err != nil || beforeNode != 0 || uncertain != 1 {
		t.Fatalf("post-node crash was not quarantined as uncertain: requeued=%d uncertain=%d err=%v", beforeNode, uncertain, err)
	}
	noDuplicate, err := store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "other-node", BindingID: "binding-b", BindingEpoch: 1, Limit: 10})
	if err != nil || len(noDuplicate) != 0 {
		t.Fatalf("node-received uncertain delivery was blindly retried: %#v err=%v", noDuplicate, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for messageID, expected := range map[string][]byte{first.Route.MessageID: firstBytes, second.Route.MessageID: secondBytes} {
		record, err := store.GetRelaySealedV1(messageID)
		if err != nil || !bytes.Equal(record.Ciphertext, expected) {
			t.Fatalf("sealed bytes did not survive recovery restart for %s: %#v err=%v", messageID, record, err)
		}
	}
}

func TestRelaySealedV1ClaimRequiresReadyJoinAndActivePermission(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	setupRelaySealedGroup(t, store)

	unjoinedPrincipal, err := store.CreatePrincipal(Principal{ID: "principal-unjoined", Kind: PrincipalKindAgent, Name: "unjoined"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateMembership(Membership{PrincipalID: unjoinedPrincipal.ID, GroupID: "group-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertEndpoint(Endpoint{ID: "ep-unjoined", Name: "unjoined", Harness: "codex", NativeSessionID: "native-unjoined"}); err != nil {
		t.Fatal(err)
	}
	unjoined := relayTestSealedV1("msg-unjoined", "sealed-unjoined", []byte{0x11, 0x22})
	unjoined.Route.ReceiverEndpointID = "ep-unjoined"
	unjoined.Security.ReceiverEndpointID = "ep-unjoined"
	unjoined.Security.ReceiverPrincipalID = unjoinedPrincipal.ID
	unjoined.Security.ReceiverBindingID = "binding-unjoined"
	if _, err := store.EnqueueRelaySealedV1(unjoined); err != nil {
		t.Fatal(err)
	}
	claim, err := store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-unjoined", ConsumerID: "unjoined", BindingID: "binding-unjoined", BindingEpoch: 1, Limit: 10})
	if err != nil || len(claim) != 0 {
		t.Fatalf("unjoined endpoint claimed SEALED_V1 delivery: %#v err=%v", claim, err)
	}

	setupRelaySealedReceiver(t, store, "ep-revoked", "principal-revoked", "binding-revoked")
	revoked := relayTestSealedV1("msg-revoked", "sealed-revoked", []byte{0x33, 0x44})
	revoked.Route.ReceiverEndpointID = "ep-revoked"
	revoked.Security.ReceiverEndpointID = "ep-revoked"
	revoked.Security.ReceiverPrincipalID = "principal-revoked"
	revoked.Security.ReceiverBindingID = "binding-revoked"
	if _, err := store.EnqueueRelaySealedV1(revoked); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeMembershipForPrincipalGroup("principal-revoked", "group-a", "access revoked"); err != nil {
		t.Fatal(err)
	}
	claim, err = store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-revoked", ConsumerID: "revoked", BindingID: "binding-revoked", BindingEpoch: 1, Limit: 10})
	if err != nil || len(claim) != 0 {
		t.Fatalf("revoked membership claimed SEALED_V1 delivery: %#v err=%v", claim, err)
	}

	binding := setupRelaySealedReceiver(t, store, "ep-binding-revoked", "principal-binding-revoked", "binding-revoked-2")
	stale := relayTestSealedV1("msg-binding-revoked", "sealed-binding-revoked", []byte{0x55, 0x66})
	stale.Route.ReceiverEndpointID = "ep-binding-revoked"
	stale.Security.ReceiverEndpointID = "ep-binding-revoked"
	stale.Security.ReceiverPrincipalID = "principal-binding-revoked"
	stale.Security.ReceiverBindingID = binding.ID
	stale.Security.ReceiverBindingEpoch = binding.Epoch
	if _, err := store.EnqueueRelaySealedV1(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeSessionBinding(binding.ID, binding.Epoch, "binding revoked"); err != nil {
		t.Fatal(err)
	}
	claim, err = store.ClaimRelaySealedV1Inbox(RelayClaimInput{RecipientEndpointID: "ep-binding-revoked", ConsumerID: "binding-revoked", BindingID: binding.ID, BindingEpoch: binding.Epoch, Limit: 10})
	if err != nil || len(claim) != 0 {
		t.Fatalf("revoked binding claimed SEALED_V1 delivery: %#v err=%v", claim, err)
	}
}

func enqueueSecondaryGroupSealedRelay(t *testing.T, f *localDeliveryAuthorizationFixture, messageID string) {
	t.Helper()
	groupID := "group_other"
	input := RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: messageID,
			SenderEndpointID: f.source.ID, ReceiverEndpointID: f.target.ID, Kind: "send"},
		Security: RelayMessageSecurity{
			SenderEndpointID: f.source.ID, SenderPrincipalID: f.source.PrincipalID,
			SenderGroupID: f.group.ID, SenderBindingID: f.sourceBinding.ID,
			SenderBindingEpoch: f.sourceBinding.Epoch,
			ReceiverEndpointID: f.target.ID, ReceiverPrincipalID: f.target.PrincipalID,
			ReceiverGroupID: groupID, ReceiverBindingID: f.targetBinding.ID,
			ReceiverBindingEpoch: f.targetBinding.Epoch,
			VisibilityPolicyRef:  "visible-to-recipient", AuthorizationRef: "link-grant-v1",
		},
		Ciphertext: []byte("synthetic sealed secondary-group payload"), IdempotencyKey: messageID,
	}
	if _, err := f.store.EnqueueRelaySealedV1(input); err != nil {
		t.Fatal(err)
	}
}

func TestRelaySealedV1ClaimSupportsSecondaryGroupsAndRetainsGuards(t *testing.T) {
	t.Run("active secondary Group join", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreateMembership(Membership{PrincipalID: f.target.PrincipalID,
			GroupID: "group_other", Role: "member", Grants: []string{"message.receive"},
			Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JoinEndpointGroup(f.target.ID, "group_other"); err != nil {
			t.Fatal(err)
		}
		enqueueSecondaryGroupSealedRelay(t, f, "msg-secondary-group-claim")
		claimed, err := f.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.target.ID, ConsumerID: "secondary-group-node",
			BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
		})
		if err != nil || len(claimed) != 1 || claimed[0].ReceiverGroupID != "group_other" ||
			claimed[0].BindingID != f.targetBinding.ID || claimed[0].BindingEpoch != f.targetBinding.Epoch {
			t.Fatalf("active secondary-Group delivery was not claimable on its current binding: %#v err=%v", claimed, err)
		}
	})

	t.Run("missing endpoint Group join", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreateMembership(Membership{PrincipalID: f.target.PrincipalID,
			GroupID: "group_other", Role: "member", Grants: []string{"message.receive"},
			Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		enqueueSecondaryGroupSealedRelay(t, f, "msg-secondary-group-unjoined")
		claimed, err := f.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.target.ID, ConsumerID: "unjoined-secondary-group-node",
			BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("unjoined secondary Group claimed sealed delivery: %#v err=%v", claimed, err)
		}
	})

	t.Run("revoked principal membership", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreateMembership(Membership{PrincipalID: f.target.PrincipalID,
			GroupID: "group_other", Role: "member", Grants: []string{"message.receive"},
			Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JoinEndpointGroup(f.target.ID, "group_other"); err != nil {
			t.Fatal(err)
		}
		enqueueSecondaryGroupSealedRelay(t, f, "msg-secondary-group-revoked")
		if _, err := f.store.RevokeMembershipForPrincipalGroup(f.target.PrincipalID,
			"group_other", "test revocation"); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.target.ID, ConsumerID: "revoked-secondary-group-node",
			BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("revoked secondary-Group membership claimed sealed delivery: %#v err=%v", claimed, err)
		}
	})

	t.Run("revoked endpoint Group join", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreateMembership(Membership{PrincipalID: f.target.PrincipalID,
			GroupID: "group_other", Role: "member", Grants: []string{"message.receive"},
			Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JoinEndpointGroup(f.target.ID, "group_other"); err != nil {
			t.Fatal(err)
		}
		enqueueSecondaryGroupSealedRelay(t, f, "msg-secondary-group-left")
		if _, err := f.store.LeaveEndpointGroup(f.target.ID, "group_other", f.targetBinding.ID,
			f.targetBinding.Epoch, "test leave"); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.target.ID, ConsumerID: "left-secondary-group-node",
			BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("endpoint with revoked secondary-Group join claimed sealed delivery: %#v err=%v", claimed, err)
		}
	})

	t.Run("stale binding epoch", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		if _, err := f.store.CreateMembership(Membership{PrincipalID: f.target.PrincipalID,
			GroupID: "group_other", Role: "member", Grants: []string{"message.receive"},
			Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.JoinEndpointGroup(f.target.ID, "group_other"); err != nil {
			t.Fatal(err)
		}
		enqueueSecondaryGroupSealedRelay(t, f, "msg-secondary-group-stale-epoch")
		if _, err := f.store.RotateSessionBindingCredential(f.targetBinding.ID, f.targetBinding.Epoch,
			localDeliveryDigest("rotated target credential"), f.targetBinding.LeaseOwner,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.target.ID, ConsumerID: "stale-secondary-group-node",
			BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("old binding epoch claimed sealed delivery: %#v err=%v", claimed, err)
		}
	})
}

func TestRelayV2SchemaMigrationKeepsLegacyEnvelope(t *testing.T) {
	path := t.TempDir() + "/state/cicada.sqlite3"
	first, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := first.CreateFabricMessage(FabricMessage{
		ID: "legacy-message", FromEndpointID: "ep-old-a", ToEndpointID: "ep-old-b",
		Kind: "notice", Body: "legacy body", Metadata: map[string]any{"v": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ID != "legacy-message" {
		t.Fatalf("unexpected legacy id: %s", legacy.ID)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.initializeRelayV2Schema(); err != nil {
		t.Fatal(err)
	}
	got, err := second.GetFabricMessage("legacy-message")
	if err != nil || got == nil || got.Body != "legacy body" {
		t.Fatalf("legacy envelope changed during additive migration: %#v err=%v", got, err)
	}
	var tables int
	if err := second.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('relay_v2_requests', 'relay_v2_inbox', 'relay_v2_receipts')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 3 {
		t.Fatalf("relay tables were not created: %d", tables)
	}
}

func TestRelayV2IdempotencyUsesSenderScopeAndDigest(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()

	firstInput := relayTestAsk("rq-one", "msg-one", "digest-one", "operation-1", "first body")
	firstInput.RequestID = ""
	first, err := createPreparingRelayRequestFixture(t, store, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	retry := relayTestAsk("rq-retry", "msg-retry", "digest-one", "operation-1", "first body")
	retry.RequestID = ""
	second, err := createPreparingRelayRequestFixture(t, store, retry)
	if err != nil {
		t.Fatal(err)
	}
	if second.RequestID != first.RequestID || second.MessageID != first.MessageID {
		t.Fatalf("same scoped key/digest did not return original row: first=%#v second=%#v", first, second)
	}
	conflict := relayTestAsk("rq-conflict", "msg-conflict", "digest-two", "operation-1", "changed body")
	if _, err := createPreparingRelayRequestFixture(t, store, conflict); !errors.Is(err, ErrRelayIdempotencyConflict) {
		t.Fatalf("different digest did not conflict: %v", err)
	}

	differentScope := retry
	differentScope.RequestID = "rq-other-scope"
	differentScope.MessageID = "msg-other-scope"
	differentScope.SenderPrincipalID = "principal-other"
	differentScope.SenderEndpointID = "ep-other"
	created, err := createPreparingRelayRequestFixture(t, store, differentScope)
	if err != nil {
		t.Fatal(err)
	}
	if created.RequestID == first.RequestID {
		t.Fatal("same key in a different sender scope was incorrectly deduplicated")
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM fabric_messages WHERE kind = 'ask'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("unexpected authoritative envelope count: %d", count)
	}
}

func TestRelayV2ConcurrentIdempotentCreateAndSingleClaim(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	input := relayTestAsk("rq-concurrent", "msg-concurrent", "digest-concurrent", "operation-concurrent", "body")
	const workers = 16
	results := make([]*FabricRequest, workers)
	errorsSeen := make([]error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index], errorsSeen[index] = createPreparingRelayRequestFixture(t, store, input)
		}(index)
	}
	group.Wait()
	for index := range results {
		if errorsSeen[index] != nil {
			t.Fatalf("concurrent create %d failed: %v", index, errorsSeen[index])
		}
		if results[index].RequestID != input.RequestID || results[index].MessageID != input.MessageID {
			t.Fatalf("concurrent create %d returned another row: %#v", index, results[index])
		}
	}
	claimed, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "node-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 10,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("expected one claim after concurrent create: %#v err=%v", claimed, err)
	}
	claimedAgain, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "node-b-2", BindingID: "binding-b", BindingEpoch: 7, Limit: 10,
	})
	if err != nil || len(claimedAgain) != 0 {
		t.Fatalf("delivery was claimed twice: %#v err=%v", claimedAgain, err)
	}
}

func TestRelayV2CursorSurvivesReadDisconnectAndRestart(t *testing.T) {
	path := t.TempDir() + "/state/cicada.sqlite3"
	store, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.initializeRelayV2Schema(); err != nil {
		t.Fatal(err)
	}
	request, err := createPreparingRelayRequestFixture(t, store, relayTestAsk("rq-cursor", "msg-cursor", "digest-cursor", "operation-cursor", "body"))
	if err != nil {
		t.Fatal(err)
	}
	read, err := store.ReceiveRelayInbox("ep-b", "consumer-b", "", 1)
	if err != nil || len(read.Messages) != 1 || read.Messages[0].MessageID != request.MessageID {
		t.Fatalf("initial receive failed: %#v err=%v", read, err)
	}
	// Simulate the connection dying after receive but before claim/ack.  The
	// same opaque cursor must still expose the unacknowledged row.
	reconnected, err := store.ReceiveRelayInbox("ep-b", "consumer-b", read.NextCursor, 1)
	if err != nil || len(reconnected.Messages) != 1 {
		t.Fatalf("unacknowledged row was lost after reconnect: %#v err=%v", reconnected, err)
	}
	claimed, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "consumer-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim failed: %#v err=%v", claimed, err)
	}
	attempt := claimed[0]
	if _, err := store.RecordRelayReceipt(RelayReceipt{
		AttemptID: attempt.AttemptID, MessageID: attempt.MessageID, Digest: attempt.Digest,
		TargetEndpointID: attempt.RecipientEndpointID, BindingID: attempt.BindingID,
		BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptApplicationAck,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.initializeRelayV2Schema(); err != nil {
		t.Fatal(err)
	}
	cursor, err := restarted.GetRelayCursor("ep-b", "consumer-b", "binding-b")
	if err != nil || cursor.Sequence != 1 {
		t.Fatalf("durable cursor not restored: %#v err=%v", cursor, err)
	}
	readAfterAck, err := restarted.ReceiveRelayInbox("ep-b", "consumer-b", "", 10)
	if err != nil || len(readAfterAck.Messages) != 0 {
		t.Fatalf("acked inbox row was replayed after restart: %#v err=%v", readAfterAck, err)
	}
}

func TestRelayV2ForgedAckRejectedAndFailureRequeues(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	_, err := createPreparingRelayRequestFixture(t, store, relayTestAsk("rq-ack", "msg-ack", "digest-ack", "operation-ack", "body"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "consumer-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim failed: %#v err=%v", claimed, err)
	}
	attempt := claimed[0]
	forged := RelayReceipt{AttemptID: attempt.AttemptID, MessageID: attempt.MessageID,
		Digest: "wrong-digest", TargetEndpointID: attempt.RecipientEndpointID,
		BindingID: attempt.BindingID, BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptApplicationAck}
	if _, err := store.RecordRelayReceipt(forged); !errors.Is(err, ErrRelayInvalidReceipt) {
		t.Fatalf("forged digest ACK was accepted: %v", err)
	}
	forged = RelayReceipt{AttemptID: attempt.AttemptID, MessageID: attempt.MessageID,
		Digest: attempt.Digest, TargetEndpointID: "ep-attacker", BindingID: attempt.BindingID,
		BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptApplicationAck}
	if _, err := store.RecordRelayReceipt(forged); !errors.Is(err, ErrRelayInvalidReceipt) {
		t.Fatalf("forged target ACK was accepted: %v", err)
	}
	stillClaimed, err := store.GetRelayDeliveryAttempt(attempt.AttemptID)
	if err != nil || stillClaimed.State != RelayAttemptClaimed {
		t.Fatalf("forged ACK changed attempt state: %#v err=%v", stillClaimed, err)
	}
	if _, err := store.RequeueRelayDelivery(attempt.AttemptID, "temporary runtime failure"); err != nil {
		t.Fatal(err)
	}
	retry, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "consumer-b-retry", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(retry) != 1 || retry[0].AttemptID == attempt.AttemptID {
		t.Fatalf("failed delivery was not requeued as a new attempt: %#v err=%v", retry, err)
	}
}

func TestRelayV2RebindsOnlyPendingRowsForExactEndpoint(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	for _, endpoint := range []string{"ep-a", "ep-b"} {
		if _, err := store.UpsertEndpoint(Endpoint{ID: endpoint, Name: endpoint, Harness: "codex", NativeSessionID: endpoint + "-native"}); err != nil {
			t.Fatal(err)
		}
	}
	request := relayTestAsk("rq-rebind", "msg-rebind", "digest-rebind", "operation-rebind", "body")
	if _, err := createPreparingRelayRequestFixture(t, store, request); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RebindPendingRelayInbox("ep-a", "binding-b", 7, "binding-a-new", 8); !errors.Is(err, ErrRelayBindingMismatch) {
		t.Fatalf("wrong endpoint was allowed to rebind: %v", err)
	}
	count, err := store.RebindPendingRelayInbox("ep-b", "binding-b", 7, "binding-b-new", 8)
	if err != nil || count != 1 {
		t.Fatalf("pending row was not rebound: count=%d err=%v", count, err)
	}
	if _, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "consumer-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	}); !errors.Is(err, ErrRelayBindingMismatch) {
		t.Fatalf("old binding was still able to claim rebound row: %v", err)
	}
	claimed, err := store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "consumer-b", BindingID: "binding-b-new", BindingEpoch: 8, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("new binding could not claim rebound row: %#v err=%v", claimed, err)
	}
}

func TestRelayV2ExpiryCancelAndLateReplyAreAtomic(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	requestInput := relayTestAsk("rq-late", "msg-late", "digest-late", "operation-late", "body")
	requestInput.SenderBindingID = "binding-a"
	requestInput.SenderBindingEpoch = 11
	requestInput.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	request, err := createPreparingRelayRequestFixture(t, store, requestInput)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.ExpireFabricRequest(request.RequestID, "deadline reached")
	if err != nil || expired.State != FabricRequestExpired {
		t.Fatalf("request did not expire: %#v err=%v", expired, err)
	}
	lateInput := FabricReply{
		RequestID: request.RequestID, ResponderEndpointID: "ep-b", ResponderPrincipalID: "principal-b",
		ResponderGroupID: "group-a", ReceiverBindingID: "binding-a", ReceiverBindingEpoch: 11,
		Body: "late answer", Digest: "digest-late-reply", IdempotencyKey: "late-reply-key",
	}
	late, err := store.SubmitFabricReply(lateInput)
	if err != nil {
		t.Fatal(err)
	}
	if late.State != FabricRequestLateResult || late.LateResultMessageID == "" || late.ReplyMessageID != "" {
		t.Fatalf("late result reopened or completed request: %#v", late)
	}
	retried, err := store.SubmitFabricReply(lateInput)
	if err != nil || retried.LateResultMessageID != late.LateResultMessageID {
		t.Fatalf("late-result retry was not idempotent: %#v err=%v", retried, err)
	}
	changed := lateInput
	changed.Body = "different late answer"
	if _, err := store.SubmitFabricReply(changed); !errors.Is(err, ErrRelayIdempotencyConflict) {
		t.Fatalf("changed late result reused a key: %v", err)
	}
	if _, err := store.SubmitFabricReply(FabricReply{
		RequestID: request.RequestID, ResponderEndpointID: "ep-a", ResponderPrincipalID: "principal-a",
		ResponderGroupID: "group-a", ReceiverBindingID: "binding-a", ReceiverBindingEpoch: 11,
		Body: "forged responder", Digest: "digest-forged",
	}); !errors.Is(err, ErrRelayInvalidReceipt) {
		t.Fatalf("wrong responder was accepted after late result: %v", err)
	}
	if _, err := store.SubmitFabricReply(FabricReply{
		RequestID: request.RequestID, ResponderEndpointID: "ep-b", ResponderPrincipalID: "principal-b",
		ResponderGroupID: "group-a", ReceiverBindingID: "binding-a", ReceiverBindingEpoch: 10,
		Body: "stale binding", Digest: "digest-stale-binding",
	}); !errors.Is(err, ErrRelayBindingMismatch) {
		t.Fatalf("stale sender binding was accepted: %v", err)
	}
	var eventType, fromState, toState string
	if err := store.db.QueryRow(`SELECT event_type, from_state, to_state FROM relay_v2_request_events
WHERE request_id = ? ORDER BY event_id DESC LIMIT 1`, request.RequestID).Scan(&eventType, &fromState, &toState); err != nil {
		t.Fatal(err)
	}
	if eventType != "LATE_RESULT" || fromState != FabricRequestExpired || toState != FabricRequestLateResult {
		t.Fatalf("late transition event was not durable: %s %s -> %s", eventType, fromState, toState)
	}

	cancelInput := relayTestAsk("rq-cancel", "msg-cancel", "digest-cancel", "operation-cancel", "cancel body")
	cancelled, err := createPreparingRelayRequestFixture(t, store, cancelInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RequestFabricRequestCancellation(cancelled.RequestID, "operator requested stop"); err != nil {
		t.Fatal(err)
	}
	cancelled, err = store.CancelFabricRequest(cancelled.RequestID, "runtime stopped")
	if err != nil || cancelled.State != FabricRequestCancelled {
		t.Fatalf("cancel transition failed: %#v err=%v", cancelled, err)
	}
}

func TestRelayV2RecoversStaleClaimByReceiptBoundary(t *testing.T) {
	store := newRelayV2TestStore(t)
	defer store.Close()
	for _, endpoint := range []string{"ep-a", "ep-b"} {
		if _, err := store.UpsertEndpoint(Endpoint{ID: endpoint, Name: endpoint, Harness: "codex", NativeSessionID: endpoint + "-native"}); err != nil {
			t.Fatal(err)
		}
	}
	first := relayTestAsk("rq-stale-before-node", "msg-stale-before-node", "digest-before-node", "stale-before-node", "body")
	if _, err := createPreparingRelayRequestFixture(t, store, first); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRelayInbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "node", BindingID: "binding-b", BindingEpoch: 7, Limit: 1})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("initial claim=%#v err=%v", claimed, err)
	}
	requeued, uncertain, err := store.RecoverStaleRelayClaims(time.Now().UTC().Add(time.Minute))
	if err != nil || requeued != 1 || uncertain != 0 {
		t.Fatalf("pre-node claim recovery requeued=%d uncertain=%d err=%v", requeued, uncertain, err)
	}
	retry, err := store.ClaimRelayInbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "node-retry", BindingID: "binding-b", BindingEpoch: 7, Limit: 1})
	if err != nil || len(retry) != 1 || retry[0].AttemptID == claimed[0].AttemptID {
		t.Fatalf("safe retry was not assigned with a new attempt: %#v err=%v", retry, err)
	}
	if _, err := store.RecordRelayReceipt(RelayReceipt{
		AttemptID: retry[0].AttemptID, MessageID: retry[0].MessageID, Digest: retry[0].Digest,
		TargetEndpointID: retry[0].RecipientEndpointID, BindingID: retry[0].BindingID,
		BindingEpoch: retry[0].BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	requeued, uncertain, err = store.RecoverStaleRelayClaims(time.Now().UTC().Add(time.Minute))
	if err != nil || requeued != 0 || uncertain != 1 {
		t.Fatalf("post-node recovery requeued=%d uncertain=%d err=%v", requeued, uncertain, err)
	}
	if _, err := store.ClaimRelayInbox(RelayClaimInput{RecipientEndpointID: "ep-b", ConsumerID: "other", BindingID: "binding-b", BindingEpoch: 7, Limit: 1}); err != nil {
		t.Fatal(err)
	}
	item, err := store.GetRelayInboxItem("ep-b", retry[0].Sequence)
	if err != nil || item.State != RelayInboxUncertain {
		t.Fatalf("node-received stale claim was not quarantined: %#v err=%v", item, err)
	}
}

func TestRelayV2ReceiptCannotRegressAfterRuntimeOrApplicationAck(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	if _, err := createPreparingRelayRequestFixture(t, persistence, relayTestAsk("rq-monotonic", "msg-monotonic", "digest-monotonic", "operation-monotonic", "body")); err != nil {
		t.Fatal(err)
	}
	claimed, err := persistence.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "node-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
	attempt := claimed[0]
	receipt := func(layer string) RelayReceipt {
		return RelayReceipt{AttemptID: attempt.AttemptID, MessageID: attempt.MessageID,
			Digest: attempt.Digest, TargetEndpointID: attempt.RecipientEndpointID,
			BindingID: attempt.BindingID, BindingEpoch: attempt.BindingEpoch, Layer: layer}
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptRuntimeInjected)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptNodeReceived)); !errors.Is(err, ErrRelayStaleReceipt) {
		t.Fatalf("runtime receipt regressed to NODE_RECEIVED: %v", err)
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptApplicationAck)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptResultAccepted)); err != nil {
		t.Fatalf("business result receipt after transport ACK was rejected: %v", err)
	}
	// An exact duplicate of an already persisted receipt remains idempotent and
	// must not mutate state.
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptRuntimeInjected)); err != nil {
		t.Fatalf("exact duplicate runtime receipt was not idempotent: %v", err)
	}
	for _, layer := range []string{RelayReceiptNodeReceived, RelayReceiptFailed} {
		if _, err := persistence.RecordRelayReceipt(receipt(layer)); !errors.Is(err, ErrRelayStaleReceipt) {
			t.Fatalf("ACKED attempt accepted regressive %s receipt: %v", layer, err)
		}
	}
	item, err := persistence.GetRelayInboxItem("ep-b", attempt.Sequence)
	if err != nil || item.State != RelayInboxAcked {
		t.Fatalf("regressive receipt changed inbox: %#v err=%v", item, err)
	}
	cursor, err := persistence.GetRelayCursor("ep-b", "node-b", "binding-b")
	if err != nil || cursor.Sequence != attempt.Sequence {
		t.Fatalf("RESULT_ACCEPTED regressed or advanced ACK cursor: %#v err=%v", cursor, err)
	}
}

func TestRelayV2CodexRecoveryStagesAreDurableWithoutDeliveryProgress(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	if _, err := createPreparingRelayRequestFixture(t, persistence, relayTestAsk("rq-codex-stages", "msg-codex-stages", "digest-codex-stages", "operation-codex-stages", "body")); err != nil {
		t.Fatal(err)
	}
	claimed, err := persistence.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "node-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
	attempt := claimed[0]
	receipt := func(layer string) RelayReceipt {
		return RelayReceipt{AttemptID: attempt.AttemptID, MessageID: attempt.MessageID,
			Digest: attempt.Digest, TargetEndpointID: attempt.RecipientEndpointID,
			BindingID: attempt.BindingID, BindingEpoch: attempt.BindingEpoch, Layer: layer}
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptCodexQueueAccepted)); !errors.Is(err, ErrRelayStaleReceipt) {
		t.Fatalf("queue acceptance without durable Node receipt was accepted: %v", err)
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptNodeReceived)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptNativeThreadResumed)); !errors.Is(err, ErrRelayStaleReceipt) {
		t.Fatalf("native resume without queued submission was accepted: %v", err)
	}
	for _, layer := range []string{RelayReceiptCodexQueueAccepted, RelayReceiptNativeThreadResumed} {
		if _, err := persistence.RecordRelayReceipt(receipt(layer)); err != nil {
			t.Fatalf("could not persist %s: %v", layer, err)
		}
	}
	state, err := persistence.GetRelayDeliveryAttempt(attempt.AttemptID)
	if err != nil || state.State != RelayAttemptClaimed {
		t.Fatalf("operational stages advanced attempt state: %#v err=%v", state, err)
	}
	item, err := persistence.GetRelayInboxItem("ep-b", attempt.Sequence)
	if err != nil || item.State != RelayInboxClaimed || item.AttemptID != attempt.AttemptID {
		t.Fatalf("operational stages changed inbox ownership: %#v err=%v", item, err)
	}
	cursor, err := persistence.GetRelayCursor("ep-b", "node-b", "binding-b")
	if err != nil || cursor.Sequence != 0 {
		t.Fatalf("operational stages advanced consumer cursor: %#v err=%v", cursor, err)
	}
	if _, err := persistence.RecordRelayReceipt(receipt(RelayReceiptRuntimeInjected)); err != nil {
		t.Fatalf("runtime start acceptance was not recorded: %v", err)
	}
}

func TestRelayV2StaleAttemptCannotOverwriteNewInboxClaim(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	if _, err := createPreparingRelayRequestFixture(t, persistence, relayTestAsk("rq-attempt-fence", "msg-attempt-fence", "digest-attempt-fence", "operation-attempt-fence", "body")); err != nil {
		t.Fatal(err)
	}
	first, err := persistence.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "node-b", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim=%#v err=%v", first, err)
	}
	old := first[0]
	oldReceipt := RelayReceipt{AttemptID: old.AttemptID, MessageID: old.MessageID, Digest: old.Digest,
		TargetEndpointID: old.RecipientEndpointID, BindingID: old.BindingID, BindingEpoch: old.BindingEpoch,
		Layer: RelayReceiptNodeReceived}
	if _, err := persistence.RecordRelayReceipt(oldReceipt); err != nil {
		t.Fatal(err)
	}
	// Exercise the race invariant directly: simulate recovery/reconciliation
	// making a newer claim current while the previous uncertain attempt remains
	// addressable for a delayed receipt.
	if _, err := persistence.db.Exec(`UPDATE relay_v2_inbox SET state = ?, attempt_id = ''
WHERE recipient_endpoint_id = ? AND sequence = ?`, RelayInboxReady, "ep-b", old.Sequence); err != nil {
		t.Fatal(err)
	}
	second, err := persistence.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: "ep-b", ConsumerID: "node-b-next", BindingID: "binding-b", BindingEpoch: 7, Limit: 1,
	})
	if err != nil || len(second) != 1 || second[0].AttemptID == old.AttemptID {
		t.Fatalf("second claim=%#v err=%v", second, err)
	}
	late := oldReceipt
	late.Layer = RelayReceiptRuntimeInjected
	if _, err := persistence.RecordRelayReceipt(late); !errors.Is(err, ErrRelayStaleReceipt) {
		t.Fatalf("old attempt receipt was not fenced: %v", err)
	}
	item, err := persistence.GetRelayInboxItem("ep-b", old.Sequence)
	if err != nil || item.State != RelayInboxClaimed || item.AttemptID != second[0].AttemptID {
		t.Fatalf("old receipt overwrote newer inbox owner: %#v err=%v", item, err)
	}
	newAttempt, err := persistence.GetRelayDeliveryAttempt(second[0].AttemptID)
	if err != nil || newAttempt.State != RelayAttemptClaimed {
		t.Fatalf("old receipt changed new attempt state: %#v err=%v", newAttempt, err)
	}
	cursor, err := persistence.GetRelayCursor("ep-b", "node-b-next", "binding-b")
	if err != nil || cursor.Sequence != 0 {
		t.Fatalf("old receipt advanced new owner's cursor: %#v err=%v", cursor, err)
	}
}
