package store

import (
	"errors"
	"testing"
	"time"
)

func TestCommunicationLinkSealedAskStatusAndCancellationRequireBoundNode(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
	input := sealedAskInputForFixture(t, f)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.GetFabricRequestV2(input.RequestID); !errors.Is(err, ErrRelayRequestNotFound) {
		t.Fatalf("plaintext request reader exposed sealed Ask: %v", err)
	}
	for _, credential := range []string{f.sourceOwner.nodeCredential, f.targetOwner.nodeCredential} {
		status, err := f.base.store.GetCommunicationLinkSealedRequestForNodeCredential(
			credential, input.RequestID)
		if err != nil || status.State != FabricRequestOpen || status.MessageID != input.MessageID {
			t.Fatalf("participant Node could not see opaque Ask status: %#v err=%v", status, err)
		}
	}
	if _, err := f.base.store.GetCommunicationLinkSealedRequestForNodeCredential(
		"invalid credential", input.RequestID); !errors.Is(err, ErrRelayRequestNotFound) {
		t.Fatalf("unbound Node read sealed Ask status: %v", err)
	}
	if _, err := f.base.store.RequestCommunicationLinkSealedAskCancellation(
		f.targetOwner.nodeCredential, input.RequestID, "not the requester"); !errors.Is(err, ErrRelayRequestNotFound) {
		t.Fatalf("responder cancelled another Endpoint's Ask: %v", err)
	}
	cancelled, err := f.base.store.RequestCommunicationLinkSealedAskCancellation(
		f.sourceOwner.nodeCredential, input.RequestID, "requester changed plans")
	if err != nil || cancelled.State != FabricRequestCancelRequested {
		t.Fatalf("source Node could not request cancellation: %#v err=%v", cancelled, err)
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-consumer",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch,
		Limit: 1,
	})
	if err != nil || len(claimed) != 0 {
		t.Fatalf("cancel-requested Ask remained deliverable: %#v err=%v", claimed, err)
	}
	if _, err := f.base.store.RevokeCommunicationLink(f.link.ID, f.link.SourceOwnerID,
		f.link.Version, "owner revoked Link"); err != nil {
		t.Fatal(err)
	}
	status, err := f.base.store.GetCommunicationLinkSealedRequestForNodeCredential(
		f.sourceOwner.nodeCredential, input.RequestID)
	if err != nil || status.State != FabricRequestCancelRequested {
		t.Fatalf("revocation hid original request lifecycle: %#v err=%v", status, err)
	}
}

func TestCommunicationLinkSealedAskCancellationAfterDeadlineReportsExpired(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
	input := sealedAskInputForFixture(t, f)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), input.RequestID); err != nil {
		t.Fatal(err)
	}
	status, err := f.base.store.RequestCommunicationLinkSealedAskCancellation(
		f.sourceOwner.nodeCredential, input.RequestID, "too late")
	if err != nil || status.State != FabricRequestExpired {
		t.Fatalf("deadline was not persisted instead of a false cancellation: %#v err=%v", status, err)
	}
}

func TestCommunicationLinkSealedAskStatusExpiresWithoutRelayClaim(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
	input := sealedAskInputForFixture(t, f)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), input.RequestID); err != nil {
		t.Fatal(err)
	}
	status, err := f.base.store.GetCommunicationLinkSealedRequestForNodeCredential(
		f.sourceOwner.nodeCredential, input.RequestID)
	if err != nil || status.State != FabricRequestExpired {
		t.Fatalf("status remained falsely OPEN after deadline: %#v err=%v", status, err)
	}
	var inboxState string
	if err := f.base.store.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`,
		input.MessageID).Scan(&inboxState); err != nil || inboxState != RelayInboxExpired {
		t.Fatalf("status read did not persist request/inbox expiry together: %s err=%v", inboxState, err)
	}
}
