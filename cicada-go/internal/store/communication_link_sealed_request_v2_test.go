package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func sealedAskInputForFixture(t *testing.T, f *linkSealedSendTestFixture) CommunicationLinkSealedAsk {
	return sealedAskInputForFixtureWithIDs(t, f, "msg_link_ask_test", "rq_link_ask_test")
}

func sealedAskInputForFixtureWithIDs(t *testing.T, f *linkSealedSendTestFixture,
	messageID, requestID string) CommunicationLinkSealedAsk {
	return sealedAskInputForDirectionWithIDs(t, f, messageID, requestID, "", false)
}

func sealedAskInputForDirectionWithIDs(t *testing.T, f *linkSealedSendTestFixture,
	messageID, requestID, parentRequestID string, reverse bool) CommunicationLinkSealedAsk {
	t.Helper()
	route := sealedLinkAskEndpointContext(f.link, f.manifest,
		messageID, requestID, parentRequestID, reverse)
	signer, recipient := f.sourceEndpointKey, f.manifest.Target.PublicIdentity
	credential := f.sourceOwner.nodeCredential
	if reverse {
		signer, recipient = f.targetEndpointKey, f.manifest.Source.PublicIdentity
		credential = f.targetOwner.nodeCredential
	}
	wire, err := e2ee.SealEndpointMessage(signer,
		recipient, route, []byte("private question"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return CommunicationLinkSealedAsk{
		NodeCredentialDigest: credential,
		LinkID:               f.link.ID, MessageID: messageID, RequestID: requestID,
		ParentRequestID: parentRequestID,
		IdempotencyKey:  "idem_" + messageID, DataScope: f.dataScope,
		ExpiresAt:  time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
		Ciphertext: wire,
	}
}

func TestCommunicationLinkSealedAskEnforcesSharedRelayQuota(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
	if err := f.base.store.ConfigureRelayAdmissionLimits(RelayAdmissionLimits{
		PerSenderPrincipal: 1, PerSenderGroup: 1, PerReceiver: 1,
		Global: 1, RetryAfterSeconds: 1,
	}); err != nil {
		t.Fatal(err)
	}
	first := sealedAskInputForFixtureWithIDs(t, f, "msg_ask_quota_one", "rq_ask_quota_one")
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(first); err != nil {
		t.Fatal(err)
	}
	second := sealedAskInputForFixtureWithIDs(t, f, "msg_ask_quota_two", "rq_ask_quota_two")
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(second); !errors.Is(err, ErrRelayResourceExhausted) {
		t.Fatalf("second pending sealed Ask exceeded quota: %v", err)
	}
	var messages, requests int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM fabric_messages WHERE id=?`, second.MessageID).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_requests WHERE request_id=?`, second.RequestID).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if messages != 0 || requests != 0 {
		t.Fatalf("quota rejection left partial records: messages=%d requests=%d", messages, requests)
	}
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(first); err != nil {
		t.Fatalf("idempotent retry was rejected while quota was full: %v", err)
	}
}

func TestCommunicationLinkBidirectionalAskReplyUsesAuthenticatedReverseDirection(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
		[]string{"ask", "reply"}, "cross", []string{"direct.receive", "direct.send"},
		[]string{"direct.receive", "direct.send"}, "bidirectional")
	ask := sealedAskInputForDirectionWithIDs(t, f,
		"msg_link_reverse_ask", "rq_link_reverse_ask", "", true)
	request, err := f.base.store.EnqueueCommunicationLinkSealedAsk(ask)
	if err != nil {
		t.Fatalf("target Node's bidirectional reverse Ask was denied: %v", err)
	}
	if request.SenderEndpointID != f.link.TargetEndpointID ||
		request.ReceiverEndpointID != f.link.SourceEndpointID ||
		request.SenderBindingID != f.manifest.Target.BindingID ||
		request.ReceiverBindingID != f.manifest.Source.BindingID {
		t.Fatalf("reverse Ask route was not derived from authenticated target Node: %#v", request)
	}
	claimedAsk, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "reverse-ask-source",
		BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 1,
	})
	if err != nil || len(claimedAsk) != 1 || claimedAsk[0].MessageID != ask.MessageID {
		t.Fatalf("reverse Ask was not claimable by Link source: %#v err=%v", claimedAsk, err)
	}
	askAuthorization, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.sourceOwner.nodeCredential, ask.MessageID, claimedAsk[0].AttemptID)
	if err != nil || askAuthorization.ParentRequestID != "" {
		t.Fatalf("fresh source-side reverse Ask authorization failed: %v", err)
	}
	if _, err := f.base.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: claimedAsk[0].AttemptID, MessageID: ask.MessageID, Digest: claimedAsk[0].Digest,
		TargetEndpointID: f.link.SourceEndpointID, BindingID: f.manifest.Source.BindingID,
		BindingEpoch: f.manifest.Source.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatalf("record exact receiver receipt for reverse Ask: %v", err)
	}
	reply := sealedReplyInputForFixture(t, f, ask, "msg_link_reverse_reply")
	accepted, err := f.base.store.EnqueueCommunicationLinkSealedReply(reply)
	if err != nil || accepted.State != FabricRequestReplied || accepted.ReplyMessageID != reply.MessageID {
		t.Fatalf("reverse Ask's source-side Reply was denied: %#v err=%v", accepted, err)
	}
	record, err := f.base.store.GetRelaySealedV1(reply.MessageID)
	if err != nil || record.Route.SenderEndpointID != f.link.SourceEndpointID ||
		record.Route.ReceiverEndpointID != f.link.TargetEndpointID || record.Route.ReplyTo != ask.MessageID {
		t.Fatalf("Reply did not reverse the stored reverse Ask direction: %#v err=%v", record, err)
	}
	claimedReply, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "reverse-reply-target",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
	})
	if err != nil || len(claimedReply) != 1 || claimedReply[0].MessageID != reply.MessageID {
		t.Fatalf("reverse Ask Reply was not claimable by original sender: %#v err=%v", claimedReply, err)
	}
	replyAuthorization, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, reply.MessageID, claimedReply[0].AttemptID)
	if err != nil || replyAuthorization.ParentRequestID != "" {
		t.Fatalf("fresh target-side Reply authorization failed: %v", err)
	}
}

func TestCommunicationLinkReverseAskRequiresBidirectionalAndRejectsCausalCycle(t *testing.T) {
	t.Run("forward-only Link rejects target initiated Ask", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"ask", "reply"}, "cross", []string{"direct.receive", "direct.send"},
			[]string{"direct.receive", "direct.send"}, "forward")
		reverse := sealedAskInputForDirectionWithIDs(t, f,
			"msg_link_forward_only_reverse", "rq_link_forward_only_reverse", "", true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(reverse); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("forward-only Link accepted target-initiated Ask: %v", err)
		}
	})
	t.Run("A to B to A cycle is rejected", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"ask", "reply"}, "cross", []string{"direct.receive", "direct.send"},
			[]string{"direct.receive", "direct.send"}, "bidirectional")
		rootAsk := sealedAskInputForDirectionWithIDs(t, f,
			"msg_link_cycle_root", "rq_link_cycle_root", "", false)
		rootRequest, err := f.base.store.EnqueueCommunicationLinkSealedAsk(rootAsk)
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "cycle-target",
			BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
		})
		if err != nil || len(claimed) != 1 {
			t.Fatalf("cycle root Ask was not claimable: %#v err=%v", claimed, err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.targetOwner.nodeCredential, rootAsk.MessageID, claimed[0].AttemptID); err != nil {
			t.Fatalf("cycle root Ask was not freshly authorized: %v", err)
		}
		if _, err := f.base.store.RecordRelayReceipt(RelayReceipt{
			AttemptID: claimed[0].AttemptID, MessageID: rootAsk.MessageID, Digest: claimed[0].Digest,
			TargetEndpointID: f.link.TargetEndpointID, BindingID: f.manifest.Target.BindingID,
			BindingEpoch: f.manifest.Target.BindingEpoch, Layer: RelayReceiptNodeReceived,
		}); err != nil {
			t.Fatal(err)
		}
		cycle := sealedAskInputForDirectionWithIDs(t, f,
			"msg_link_cycle_back", "rq_link_cycle_back", rootRequest.RequestID, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(cycle); !errors.Is(err, ErrRelayCausalCycle) {
			t.Fatalf("A→B→A causal cycle was not rejected at admission: %v", err)
		}
	})
}

func TestCommunicationLinkSealedAskPersistsRequestAndCiphertextAtomically(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"send", "ask"})
	input := sealedAskInputForFixture(t, f)
	accepted, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input)
	if err != nil || accepted.RequestID != input.RequestID || accepted.MessageID != input.MessageID ||
		accepted.State != FabricRequestOpen || accepted.Digest == "" {
		t.Fatalf("sealed Ask was not durably accepted: %#v err=%v", accepted, err)
	}
	record, err := f.base.store.GetRelaySealedV1(input.MessageID)
	if err != nil || record.Route.Kind != "ask" || record.Route.RequestID != input.RequestID ||
		!bytes.Equal(record.Ciphertext, input.Ciphertext) || record.Sequence <= 0 {
		t.Fatalf("sealed Ask route/payload was not stored exactly: %#v err=%v", record, err)
	}
	if exposed, err := f.base.store.GetFabricMessage(input.MessageID); err != nil || exposed != nil {
		t.Fatalf("legacy Fabric read exposed a sealed Ask: %#v err=%v", exposed, err)
	}
	retried, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input)
	if err != nil || retried.MessageID != accepted.MessageID || retried.RequestID != accepted.RequestID {
		t.Fatalf("exact Ask retry did not return the original request: %#v err=%v", retried, err)
	}
	var count int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_requests WHERE request_id=?`, input.RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retry duplicated the request: count=%d err=%v", count, err)
	}
	attempts, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-consumer",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch,
		Limit: 1,
	})
	if err != nil || len(attempts) != 1 || attempts[0].RequestID != input.RequestID ||
		attempts[0].Route.Kind != "ask" || !bytes.Equal(attempts[0].Ciphertext, input.Ciphertext) {
		t.Fatalf("sealed Ask was not claimed with exact correlation: %#v err=%v", attempts, err)
	}
	claim := attempts[0]
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, input.MessageID, "attempt_wrong"); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("wrong attempt authorized request injection: %v", err)
	}
	authorization, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, input.MessageID, claim.AttemptID)
	if err != nil || authorization.Route.RequestID != input.RequestID ||
		authorization.Route.Kind != "ask" || authorization.DataScope != input.DataScope ||
		authorization.ParentRequestID != "" ||
		authorization.NativeSessionID == "" {
		t.Fatalf("claimed Ask did not receive exact current authorization: %#v err=%v", authorization, err)
	}
	if _, err := f.base.store.CancelFabricRequest(input.RequestID, "sender cancelled"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, input.MessageID, claim.AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("cancelled request still authorized native injection: %v", err)
	}
	changed := input
	changed.RequestID = "rq_link_ask_other"
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(changed); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("changed request correlation reused ciphertext: %v", err)
	}
	changed = input
	changed.MessageID = "msg_link_ask_other"
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(changed); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("changed message ID reused ciphertext: %v", err)
	}
	changed = input
	changed.Ciphertext = append([]byte(nil), input.Ciphertext...)
	changed.Ciphertext[len(changed.Ciphertext)-2] ^= 1
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(changed); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("changed ciphertext under same request was accepted: %v", err)
	}
}

func TestCommunicationLinkSealedAskRequiresAskGrantAndCurrentNode(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	input := sealedAskInputForFixture(t, f)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("SEND-only Link authorized Ask: %v", err)
	}
	f = newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
	input = sealedAskInputForFixture(t, f)
	wrongNode := input
	wrongNode.NodeCredentialDigest = f.targetOwner.nodeCredential
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(wrongNode); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("receiver Node impersonated Ask sender: %v", err)
	}
	tooLate := input
	tooLate.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(tooLate); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("Ask outlived its Link: %v", err)
	}
	if _, err := f.base.store.EnqueueRelaySealedV1(RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: input.MessageID, RequestID: input.RequestID,
			SenderEndpointID:   f.link.SourceEndpointID,
			ReceiverEndpointID: f.link.TargetEndpointID, Kind: "ask"},
		Security: RelayMessageSecurity{SenderPrincipalID: f.link.SourcePrincipalID,
			SenderGroupID: f.link.SourceGroupID, ReceiverGroupID: f.link.TargetGroupID},
		Ciphertext: input.Ciphertext,
	}); err == nil {
		t.Fatal("raw sealed message API created an orphan Ask")
	}
	var count int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_requests WHERE request_id=?`, input.RequestID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied Ask left a request row: count=%d err=%v", count, err)
	}
}

func TestCommunicationLinkSealedAskQueuedFailureClosesRequest(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		requestState string
		inboxState   string
	}{
		{"deadline reached", FabricRequestExpired, RelayInboxExpired},
		{"link revoked", FabricRequestCancelled, RelayInboxCancelled},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
			input := sealedAskInputForFixture(t, f)
			if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input); err != nil {
				t.Fatal(err)
			}
			if scenario.requestState == FabricRequestExpired {
				// Advance only the stored deadline so the claim observes an expired
				// request without a wall-clock sleep or changing its signed route.
				if _, err := f.base.store.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
					time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), input.RequestID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.base.store.RevokeCommunicationLink(f.link.ID,
				f.link.SourceOwnerID, f.link.Version, "revoked before claim"); err != nil {
				t.Fatal(err)
			}
			claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
				RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-consumer",
				BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch,
				Limit: 1,
			})
			if err != nil || len(claimed) != 0 {
				t.Fatalf("stale Ask remained deliverable: %#v err=%v", claimed, err)
			}
			// The legacy plaintext request reader deliberately hides sealed
			// requests; inspect the internal lifecycle row directly here.
			var requestState, inboxState, outboxState string
			if err := f.base.store.db.QueryRow(`SELECT state FROM relay_v2_requests WHERE request_id=?`,
				input.RequestID).Scan(&requestState); err != nil {
				t.Fatal(err)
			}
			if err := f.base.store.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`,
				input.MessageID).Scan(&inboxState); err != nil {
				t.Fatal(err)
			}
			if err := f.base.store.db.QueryRow(`SELECT state FROM relay_v2_outbox WHERE message_id=?`,
				input.MessageID).Scan(&outboxState); err != nil {
				t.Fatal(err)
			}
			if requestState != scenario.requestState || inboxState != scenario.inboxState ||
				outboxState != RelayInboxFailed {
				t.Fatalf("queued Ask states disagreed: request=%s inbox=%s outbox=%s",
					requestState, inboxState, outboxState)
			}
		})
	}
}
