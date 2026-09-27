package store

import (
	"errors"
	"testing"
	"time"
)

func claimLinkSealedSendForAuthorizationTest(t *testing.T, f *linkSealedSendTestFixture) RelaySealedV1DeliveryAttempt {
	t.Helper()
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim sealed SEND: deliveries=%d err=%v", len(claimed), err)
	}
	return claimed[0]
}

func TestClaimedSealedSendAuthorizationFencesRecoveredAttempt(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	first := claimLinkSealedSendForAuthorizationTest(t, f)
	requeued, uncertain, err := f.base.store.RecoverStaleRelayClaims(time.Now().UTC().Add(time.Minute))
	if err != nil || requeued != 1 || uncertain != 0 {
		t.Fatalf("first claim was not safely requeued: requeued=%d uncertain=%d err=%v",
			requeued, uncertain, err)
	}
	second, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node-retry",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
	})
	if err != nil || len(second) != 1 || second[0].AttemptID == first.AttemptID {
		t.Fatalf("retry did not issue a new claim: %#v err=%v", second, err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, first.MessageID, first.AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("old recovered attempt authorized injection: %v", err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, second[0].MessageID, second[0].AttemptID); err != nil {
		t.Fatalf("new exact attempt was refused: %v", err)
	}
}

func TestClaimedSealedSendAuthorizationBindsCurrentAttemptAndNativeSession(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	claim := claimLinkSealedSendForAuthorizationTest(t, f)
	got, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, claim.MessageID, claim.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AttemptID != claim.AttemptID || got.MessageID != claim.MessageID ||
		got.Digest != claim.Digest || got.EndpointID != f.link.TargetEndpointID ||
		got.BindingID != claim.BindingID || got.BindingEpoch != claim.BindingEpoch ||
		got.NativeSessionID != "native_"+f.base.target.endpointID ||
		got.DataScope != f.dataScope || got.Route != claim.Route ||
		got.Bundle.Manifest.Digest != f.manifest.Digest ||
		len(got.Bundle.SourceGrant.SignedProof) == 0 || len(got.Bundle.TargetGrant.SignedProof) == 0 {
		t.Fatalf("pre-injection authorization did not match claimed route and current native binding: %#v", got)
	}
	for _, input := range []struct{ credential, message, attempt string }{
		{f.sourceOwner.nodeCredential, claim.MessageID, claim.AttemptID},
		{f.targetOwner.nodeCredential, "other-message", claim.AttemptID},
		{f.targetOwner.nodeCredential, claim.MessageID, "other-attempt"},
		{"invalid-digest", claim.MessageID, claim.AttemptID},
	} {
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			input.credential, input.message, input.attempt); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("wrong Node or delivery coordinates authorized: %v", err)
		}
	}
	if _, err := f.base.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: claim.AttemptID, MessageID: claim.MessageID, Digest: claim.Digest,
		TargetEndpointID: claim.RecipientEndpointID, BindingID: claim.BindingID,
		BindingEpoch: claim.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, claim.MessageID, claim.AttemptID); err != nil {
		t.Fatalf("durable Node receipt prematurely disabled injection preflight: %v", err)
	}
	if _, err := f.base.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: claim.AttemptID, MessageID: claim.MessageID, Digest: claim.Digest,
		TargetEndpointID: claim.RecipientEndpointID, BindingID: claim.BindingID,
		BindingEpoch: claim.BindingEpoch, Layer: RelayReceiptRuntimeInjected,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, claim.MessageID, claim.AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("already injected delivery authorized for a second injection: %v", err)
	}
}

func TestClaimedSealedSendAuthorizationFailsClosedAfterClaim(t *testing.T) {
	t.Run("link revoked", func(t *testing.T) {
		f := newLinkSealedSendTestFixture(t, true)
		claim := claimLinkSealedSendForAuthorizationTest(t, f)
		if _, err := f.base.store.RevokeCommunicationLink(f.link.ID, f.link.SourceOwnerID,
			f.link.Version, "revoked after claim"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.targetOwner.nodeCredential, claim.MessageID, claim.AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("revoked Link authorized native injection: %v", err)
		}
	})
	t.Run("owner key revoked", func(t *testing.T) {
		f := newLinkSealedSendTestFixture(t, true)
		claim := claimLinkSealedSendForAuthorizationTest(t, f)
		if _, err := f.base.store.RevokeOwnerApprovalKeyLocal(f.link.SourceOwnerID,
			f.sourceOwner.ownerKeyID, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.targetOwner.nodeCredential, claim.MessageID, claim.AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("revoked Owner key authorized native injection: %v", err)
		}
	})
	t.Run("binding epoch changed", func(t *testing.T) {
		f := newLinkSealedSendTestFixture(t, true)
		claim := claimLinkSealedSendForAuthorizationTest(t, f)
		if _, err := f.base.store.ReleaseSessionBindingLease(f.base.target.bindingID,
			"lease_ep_target", f.manifest.Target.BindingEpoch); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.targetOwner.nodeCredential, claim.MessageID, claim.AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("stale native binding authorized injection: %v", err)
		}
	})
}
