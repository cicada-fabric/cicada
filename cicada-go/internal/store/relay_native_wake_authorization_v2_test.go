package store

import (
	"errors"
	"testing"
	"time"
)

func enqueueAndClaimNativeWakeTest(t *testing.T, f *localDeliveryAuthorizationFixture) RelayDeliveryAttempt {
	t.Helper()
	messageID := "msg-native-wake"
	_, err := f.store.EnqueueRelayMessage(RelayMessageInput{
		Message: FabricMessage{ID: messageID, FromEndpointID: f.source.ID,
			ToEndpointID: f.target.ID, Kind: "send", Body: "synthetic wake test"},
		Security: RelayMessageSecurity{
			SenderEndpointID: f.source.ID, SenderPrincipalID: f.source.PrincipalID,
			SenderGroupID: f.group.ID, SenderBindingID: f.sourceBinding.ID,
			SenderBindingEpoch: f.sourceBinding.Epoch, ReceiverEndpointID: f.target.ID,
			ReceiverPrincipalID: f.target.PrincipalID, ReceiverGroupID: f.group.ID,
			ReceiverBindingID: f.targetBinding.ID, ReceiverBindingEpoch: f.targetBinding.Epoch,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: f.target.ID, ConsumerID: "native-wake-test",
		BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim native wake test delivery: %#v err=%v", claimed, err)
	}
	attempt := claimed[0]
	if _, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: attempt.AttemptID, MessageID: attempt.MessageID, Digest: attempt.Digest,
		TargetEndpointID: attempt.RecipientEndpointID, BindingID: attempt.BindingID,
		BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	return attempt
}

func TestRelayNativeWakeAuthorizationBindsCurrentNodeAttemptAndBinding(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	attempt := enqueueAndClaimNativeWakeTest(t, f)
	authorization, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if authorization.NodeID != f.nodeID || authorization.MessageID != attempt.MessageID ||
		authorization.AttemptID != attempt.AttemptID || authorization.Digest != attempt.Digest ||
		authorization.EndpointID != f.target.ID || authorization.BindingID != f.targetBinding.ID ||
		authorization.BindingEpoch != f.targetBinding.Epoch || authorization.NativeSessionID != f.target.NativeSessionID ||
		authorization.LeaseOwner != f.targetBinding.LeaseOwner || authorization.Harness != "codex" {
		t.Fatalf("authorization did not return exact current route: %#v", authorization)
	}
	if authorization.Mode != "" && authorization.Mode != f.targetBinding.Mode {
		t.Fatalf("authorization mode = %q, want current binding mode %q", authorization.Mode, f.targetBinding.Mode)
	}

	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, "other-node",
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("wrong Node identity authorized native wake: %v", err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(localDeliveryDigest("different Node credential"), f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("wrong Node credential authorized native wake: %v", err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: "wrong-attempt"}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("wrong attempt authorized native wake: %v", err)
	}

	if _, err := f.store.RevokeSessionBinding(f.targetBinding.ID, f.targetBinding.Epoch, "test revocation"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("revoked binding retained native wake authorization: %v", err)
	}
}

func TestRelayNativeWakeAuthorizationUsesCurrentEndpointGroupJoin(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	otherGroup, err := f.store.CreateGroup(Group{ID: "group_native_wake_second", Name: "second",
		OwnerPrincipalID: "owner_local", TrustDomainID: "domain_local", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	for _, principalID := range []string{f.source.PrincipalID, f.target.PrincipalID} {
		if _, err := f.store.CreateMembership(Membership{PrincipalID: principalID, GroupID: otherGroup.ID,
			Role: "member", Grants: []string{"message.send", "message.receive"}, Status: MembershipStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	for _, endpointID := range []string{f.source.ID, f.target.ID} {
		if _, err := f.store.JoinEndpointGroup(endpointID, otherGroup.ID); err != nil {
			t.Fatal(err)
		}
	}
	messageID := "msg-native-wake-second-group"
	if _, err := f.store.EnqueueRelayMessage(RelayMessageInput{
		Message: FabricMessage{ID: messageID, FromEndpointID: f.source.ID,
			ToEndpointID: f.target.ID, Kind: "send", Body: "synthetic multi-group wake"},
		Security: RelayMessageSecurity{
			SenderEndpointID: f.source.ID, SenderPrincipalID: f.source.PrincipalID,
			SenderGroupID: otherGroup.ID, SenderBindingID: f.sourceBinding.ID,
			SenderBindingEpoch: f.sourceBinding.Epoch, ReceiverEndpointID: f.target.ID,
			ReceiverPrincipalID: f.target.PrincipalID, ReceiverGroupID: otherGroup.ID,
			ReceiverBindingID: f.targetBinding.ID, ReceiverBindingEpoch: f.targetBinding.Epoch,
		},
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: f.target.ID, ConsumerID: "native-wake-second-group",
		BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim multi-Group delivery: %#v err=%v", claimed, err)
	}
	attempt := claimed[0]
	if _, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: attempt.AttemptID, MessageID: attempt.MessageID, Digest: attempt.Digest,
		TargetEndpointID: attempt.RecipientEndpointID, BindingID: attempt.BindingID,
		BindingEpoch: attempt.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	authorization, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID})
	if err != nil || authorization.GroupID != otherGroup.ID {
		t.Fatalf("authorization did not use the current multi-Group join: %#v err=%v", authorization, err)
	}
}

func TestRelayNativeWakeAuthorizationRequiresSecurityBindingToMatchAttempt(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	attempt := enqueueAndClaimNativeWakeTest(t, f)
	if _, err := f.store.db.Exec(`UPDATE relay_v2_message_security
SET receiver_binding_epoch=receiver_binding_epoch+1 WHERE message_id=?`, attempt.MessageID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("wake authorization accepted mismatched security binding epoch: %v", err)
	}
}

func TestRelayNativeWakeAuthorizationRequiresNodeReceivedAndLiveLease(t *testing.T) {
	t.Run("sealed payload requires separate Link and grant authorization", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		attempt := enqueueAndClaimNativeWakeTest(t, f)
		if _, err := f.store.db.Exec(`UPDATE relay_v2_message_payloads
SET payload_mode='SEALED_V1',ciphertext=? WHERE message_id=?`, []byte("synthetic opaque ciphertext"), attempt.MessageID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
			RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
			t.Fatalf("basic native wake auth accepted a sealed payload without Link/Grant recheck: %v", err)
		}
	})
	t.Run("receipt missing", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		attempt := enqueueAndClaimNativeWakeTest(t, f)
		if _, err := f.store.db.Exec(`DELETE FROM relay_v2_receipts WHERE attempt_id=? AND layer=?`,
			attempt.AttemptID, RelayReceiptNodeReceived); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
			RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
			t.Fatalf("native wake authorized before durable NODE_RECEIVED: %v", err)
		}
	})
	t.Run("expired lease", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		attempt := enqueueAndClaimNativeWakeTest(t, f)
		if _, err := f.store.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`,
			time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), f.targetBinding.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
			RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
			t.Fatalf("expired session lease retained native wake authorization: %v", err)
		}
	})
}

func TestRelayNativeWakeAuthorizationRejectsStaleEpochAndRejoinedGroup(t *testing.T) {
	t.Run("same binding ID with a new epoch", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		attempt := enqueueAndClaimNativeWakeTest(t, f)
		if _, err := f.store.RotateSessionBindingCredential(f.targetBinding.ID, f.targetBinding.Epoch,
			localDeliveryDigest("rotated native session token"), f.targetBinding.LeaseOwner,
			time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
			RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
			t.Fatalf("old attempt survived same-ID epoch rotation: %v", err)
		}
	})
	t.Run("active group rejoin after message acceptance", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		attempt := enqueueAndClaimNativeWakeTest(t, f)
		updatedAt := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
		if _, err := f.store.db.Exec(`UPDATE endpoint_group_memberships SET status='active',
revision=revision+2,updated_at=? WHERE endpoint_id=? AND group_id=?`,
			updatedAt, f.target.ID, f.group.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
			RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
			t.Fatalf("old message was revived by active Group rejoin: %v", err)
		}
	})
	t.Run("active membership rejoin after message acceptance", func(t *testing.T) {
		f := newLocalDeliveryAuthorizationFixture(t)
		attempt := enqueueAndClaimNativeWakeTest(t, f)
		updatedAt := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
		if _, err := f.store.db.Exec(`UPDATE memberships SET status='active',
revision=revision+2,updated_at=? WHERE principal_id=? AND group_id=?`,
			updatedAt, f.target.PrincipalID, f.group.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
			RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
			t.Fatalf("old message was revived by active membership rejoin: %v", err)
		}
	})
}
