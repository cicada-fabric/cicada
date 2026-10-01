package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func sealedReplyInputForFixture(t *testing.T, f *linkSealedSendTestFixture,
	ask CommunicationLinkSealedAsk, messageID string) CommunicationLinkSealedReply {
	t.Helper()
	reverseAsk := ask.NodeCredentialDigest == f.targetOwner.nodeCredential
	askSender, askReceiver := communicationLinkAskRoles(f.link, f.manifest, reverseAsk)
	request := &FabricRequest{
		RequestID: ask.RequestID, MessageID: ask.MessageID,
		SenderEndpointID: askSender.endpointID, SenderPrincipalID: askSender.principalID,
		SenderGroupID: askSender.groupID, SenderBindingID: askSender.bindingID,
		SenderBindingEpoch: askSender.bindingEpoch,
		ReceiverEndpointID: askReceiver.endpointID, ReceiverPrincipalID: askReceiver.principalID,
		ReceiverGroupID: askReceiver.groupID, ReceiverBindingID: askReceiver.bindingID,
		ReceiverBindingEpoch: askReceiver.bindingEpoch,
	}
	context := sealedLinkReplyEndpointContext(f.link, f.manifest, request, messageID)
	return sealedReplyInputWithContext(t, f, ask, messageID, context, replyEndpointKeyForContext(f, context))
}

func sealedReplyInputWithContext(t *testing.T, f *linkSealedSendTestFixture,
	ask CommunicationLinkSealedAsk, messageID string, context e2ee.EndpointMessageContext,
	signer *e2ee.Identity) CommunicationLinkSealedReply {
	t.Helper()
	recipient := f.manifest.Source.PublicIdentity
	credential := f.targetOwner.nodeCredential
	if context.ReceiverEndpointID == f.link.TargetEndpointID {
		recipient = f.manifest.Target.PublicIdentity
	}
	if context.SenderEndpointID == f.link.SourceEndpointID {
		credential = f.sourceOwner.nodeCredential
	}
	wire, err := e2ee.SealEndpointMessage(signer, recipient,
		context, []byte("private answer"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return CommunicationLinkSealedReply{
		NodeCredentialDigest: credential,
		RequestID:            ask.RequestID,
		MessageID:            messageID,
		IdempotencyKey:       "idem_" + messageID,
		DataScope:            f.dataScope,
		Ciphertext:           wire,
	}
}

func replyEndpointKeyForContext(f *linkSealedSendTestFixture,
	context e2ee.EndpointMessageContext) *e2ee.Identity {
	if context.SenderEndpointID == f.link.SourceEndpointID {
		return f.sourceEndpointKey
	}
	return f.targetEndpointKey
}

func enqueueSealedAskForReply(t *testing.T, f *linkSealedSendTestFixture) CommunicationLinkSealedAsk {
	t.Helper()
	ask := sealedAskInputForFixture(t, f)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(ask); err != nil {
		t.Fatal(err)
	}
	return ask
}

func TestCommunicationLinkSealedReplyPersistsReverseRouteAndClaimsExactly(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
	ask := enqueueSealedAskForReply(t, f)
	input := sealedReplyInputForFixture(t, f, ask, "msg_link_reply_test")
	accepted, err := f.base.store.EnqueueCommunicationLinkSealedReply(input)
	if err != nil || accepted.RequestID != ask.RequestID || accepted.State != FabricRequestReplied ||
		accepted.ReplyMessageID != input.MessageID || accepted.LateResultMessageID != "" {
		t.Fatalf("sealed Reply did not atomically finish its request: %#v err=%v", accepted, err)
	}
	record, err := f.base.store.GetRelaySealedV1(input.MessageID)
	if err != nil || record.Route.Kind != "reply" || record.Route.RequestID != ask.RequestID ||
		record.Route.ReplyTo != ask.MessageID || record.Route.SenderEndpointID != f.link.TargetEndpointID ||
		record.Route.ReceiverEndpointID != f.link.SourceEndpointID ||
		record.Security.SenderBindingID != f.manifest.Target.BindingID ||
		record.Security.ReceiverBindingID != f.manifest.Source.BindingID ||
		!bytes.Equal(record.Ciphertext, input.Ciphertext) {
		t.Fatalf("sealed Reply did not preserve its exact reverse route and ciphertext: %#v err=%v", record, err)
	}
	if exposed, err := f.base.store.GetFabricMessage(input.MessageID); err != nil || exposed != nil {
		t.Fatalf("legacy Fabric read exposed a sealed Reply: %#v err=%v", exposed, err)
	}
	// The requester can stay offline until the original Ask deadline passes;
	// an already committed REPLIED result remains claimable without reopening
	// or re-expiring the request.
	if _, err := f.base.store.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), ask.RequestID); err != nil {
		t.Fatal(err)
	}
	var readyCount int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox
WHERE message_id=? AND recipient_endpoint_id=? AND state='READY'`, input.MessageID,
		f.link.SourceEndpointID).Scan(&readyCount); err != nil || readyCount != 1 {
		t.Fatalf("offline requester did not retain one durable reverse inbox row: count=%d err=%v", readyCount, err)
	}
	if _, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "wrong-binding-consumer",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
	}); !errors.Is(err, ErrRelayBindingMismatch) {
		t.Fatalf("reverse Reply was claimable under the responder's binding: %v", err)
	}

	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "source-consumer",
		BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 1,
	})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != input.MessageID ||
		claimed[0].RequestID != ask.RequestID || claimed[0].Route.ReplyTo != ask.MessageID ||
		!bytes.Equal(claimed[0].Ciphertext, input.Ciphertext) {
		t.Fatalf("reverse Link Reply was not claimable by the original requester: %#v err=%v", claimed, err)
	}
	if _, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-consumer",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
	}); err != nil {
		t.Fatal(err)
	}
	authorization, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.sourceOwner.nodeCredential, input.MessageID, claimed[0].AttemptID)
	if err != nil || authorization.Route.Kind != "reply" || authorization.EndpointID != f.link.SourceEndpointID ||
		authorization.BindingID != f.manifest.Source.BindingID || authorization.NativeSessionID == "" {
		t.Fatalf("original requester Node did not receive exact reverse authorization: %#v err=%v", authorization, err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, input.MessageID, claimed[0].AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("responder Node was authorized to inject its own reverse reply: %v", err)
	}

	retried, err := f.base.store.EnqueueCommunicationLinkSealedReply(input)
	if err != nil || retried.State != FabricRequestReplied || retried.ReplyMessageID != input.MessageID {
		t.Fatalf("exact reply retry was not idempotent: %#v err=%v", retried, err)
	}
	different := sealedReplyInputForFixture(t, f, ask, "msg_link_reply_second")
	if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(different); !errors.Is(err, ErrRelayRequestTerminal) {
		t.Fatalf("a second distinct reply did not conflict with the completed request: %v", err)
	}
	differentCiphertext := input
	differentCiphertext.Ciphertext = append([]byte(nil), input.Ciphertext...)
	differentCiphertext.Ciphertext[len(differentCiphertext.Ciphertext)-1] ^= 1
	if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(differentCiphertext); !errors.Is(err, ErrRelayIdempotencyConflict) {
		t.Fatalf("same reply ID with different ciphertext was not an idempotency conflict: %v", err)
	}
}

func TestCommunicationLinkSealedReplyKeepsConcurrentRequestsSeparate(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
	first := sealedAskInputForFixtureWithIDs(t, f, "msg_parallel_ask_one", "rq_parallel_ask_one")
	second := sealedAskInputForFixtureWithIDs(t, f, "msg_parallel_ask_two", "rq_parallel_ask_two")
	for _, ask := range []CommunicationLinkSealedAsk{first, second} {
		if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(ask); err != nil {
			t.Fatal(err)
		}
	}
	wrongRoute := sealedLinkReverseEndpointContext(f.link, f.manifest,
		"msg_parallel_wrong", first.RequestID, second.MessageID)
	wrong := sealedReplyInputWithContext(t, f, first, "msg_parallel_wrong", wrongRoute, f.targetEndpointKey)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(wrong); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("reply crossed two pending request correlations: %v", err)
	}
	// Deliberately complete the second request first. Matching must use the
	// immutable request ID and reply_to, never whichever Ask was most recent.
	for _, pair := range []struct {
		ask     CommunicationLinkSealedAsk
		replyID string
	}{{second, "msg_parallel_reply_two"}, {first, "msg_parallel_reply_one"}} {
		input := sealedReplyInputForFixture(t, f, pair.ask, pair.replyID)
		accepted, err := f.base.store.EnqueueCommunicationLinkSealedReply(input)
		if err != nil || accepted.RequestID != pair.ask.RequestID ||
			accepted.ReplyMessageID != pair.replyID || accepted.State != FabricRequestReplied {
			t.Fatalf("reply crossed pending request states: %#v err=%v", accepted, err)
		}
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "parallel-source",
		BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 2,
	})
	if err != nil || len(claimed) != 2 {
		t.Fatalf("parallel replies not separately claimable: %#v err=%v", claimed, err)
	}
	want := map[string]string{first.RequestID: first.MessageID, second.RequestID: second.MessageID}
	for _, delivery := range claimed {
		if want[delivery.RequestID] != delivery.Route.ReplyTo || delivery.Route.Kind != "reply" {
			t.Fatalf("reply had mismatched original request: %#v", delivery)
		}
		delete(want, delivery.RequestID)
	}
	if len(want) != 0 {
		t.Fatalf("missing correlated replies: %#v", want)
	}
}

func TestCommunicationLinkSealedReplyRequiresActionResponderAndExactCorrelation(t *testing.T) {
	t.Run("missing reply action", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask"})
		ask := enqueueSealedAskForReply(t, f)
		input := sealedReplyInputForFixture(t, f, ask, "msg_reply_without_action")
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("ask-only Link accepted a reverse Reply: %v", err)
		}
	})
	t.Run("forged responder Node", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
		ask := enqueueSealedAskForReply(t, f)
		input := sealedReplyInputForFixture(t, f, ask, "msg_reply_wrong_node")
		input.NodeCredentialDigest = f.sourceOwner.nodeCredential
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("original requester Node impersonated the responder: %v", err)
		}
	})
	t.Run("forged endpoint signature", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
		ask := enqueueSealedAskForReply(t, f)
		input := sealedReplyInputForFixture(t, f, ask, "msg_reply_wrong_signature")
		var envelope e2ee.EndpointMessageEnvelope
		if err := json.Unmarshal(input.Ciphertext, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Signature[0] ^= 1
		forged, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		input.Ciphertext = forged
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("reply with a forged responder signature was accepted: %v", err)
		}
	})
	t.Run("wrong request and reply-to", func(t *testing.T) {
		for _, field := range []string{"request_id", "reply_to"} {
			t.Run(field, func(t *testing.T) {
				f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
				ask := enqueueSealedAskForReply(t, f)
				context := sealedLinkReverseEndpointContext(f.link, f.manifest,
					"msg_reply_wrong_correlation", ask.RequestID, ask.MessageID)
				if field == "request_id" {
					context.RequestID = "rq_forged_request"
				} else {
					context.ReplyTo = "msg_forged_parent"
				}
				input := sealedReplyInputWithContext(t, f, ask, context.MessageID, context, f.targetEndpointKey)
				if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
					t.Fatalf("reply with uncorrelated %s was accepted: %v", field, err)
				}
			})
		}
	})
	t.Run("raw sealed enqueue cannot create orphan reply", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
		if _, err := f.base.store.EnqueueRelaySealedV1(RelaySealedV1Input{
			Route: RelaySealedV1Route{MessageID: "msg_orphan_reply", RequestID: "rq_missing",
				ReplyTo: "msg_missing", SenderEndpointID: f.link.TargetEndpointID,
				ReceiverEndpointID: f.link.SourceEndpointID, Kind: "reply"},
			Security: RelayMessageSecurity{MessageID: "msg_orphan_reply",
				SenderEndpointID: f.link.TargetEndpointID, SenderPrincipalID: f.link.TargetPrincipalID,
				SenderGroupID: f.link.TargetGroupID, ReceiverEndpointID: f.link.SourceEndpointID,
				ReceiverPrincipalID: f.link.SourcePrincipalID, ReceiverGroupID: f.link.SourceGroupID},
			Ciphertext: []byte("opaque"),
		}); err == nil {
			t.Fatal("raw sealed enqueue created an orphan reverse reply")
		}
	})
}

func TestCommunicationLinkSealedReplyRechecksRevocationAtClaimAndPreflight(t *testing.T) {
	t.Run("revoked before claim", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
		ask := enqueueSealedAskForReply(t, f)
		input := sealedReplyInputForFixture(t, f, ask, "msg_reply_revoke_before_claim")
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(input); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.RevokeCommunicationLink(f.link.ID, f.link.SourceOwnerID,
			f.link.Version, "revoked before reverse claim"); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "source-consumer",
			BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 1,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("revoked reverse route remained claimable: %#v err=%v", claimed, err)
		}
	})
	t.Run("revoked after claim", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
		ask := enqueueSealedAskForReply(t, f)
		input := sealedReplyInputForFixture(t, f, ask, "msg_reply_revoke_after_claim")
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(input); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "source-consumer",
			BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 1,
		})
		if err != nil || len(claimed) != 1 {
			t.Fatalf("expected reverse reply claim before revocation: %#v err=%v", claimed, err)
		}
		if _, err := f.base.store.RevokeCommunicationLink(f.link.ID, f.link.SourceOwnerID,
			f.link.Version, "revoked after reverse claim"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.sourceOwner.nodeCredential, input.MessageID, claimed[0].AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("revoked reverse reply passed exact-attempt preflight: %v", err)
		}
	})
}

func TestCommunicationLinkSealedReplyAfterDeadlineOrCancellationIsLateAndNotClaimed(t *testing.T) {
	for _, terminal := range []string{"deadline", "cancelled"} {
		t.Run(terminal, func(t *testing.T) {
			f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"ask", "reply"})
			ask := enqueueSealedAskForReply(t, f)
			if terminal == "deadline" {
				if _, err := f.base.store.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
					time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), ask.RequestID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.base.store.CancelFabricRequest(ask.RequestID, "cancelled by requester"); err != nil {
				t.Fatal(err)
			}
			input := sealedReplyInputForFixture(t, f, ask, "msg_reply_late_"+terminal)
			accepted, err := f.base.store.EnqueueCommunicationLinkSealedReply(input)
			if err != nil || accepted.State != FabricRequestLateResult ||
				accepted.ReplyMessageID != "" || accepted.LateResultMessageID != input.MessageID {
				t.Fatalf("late response reopened or replaced the request outcome: %#v err=%v", accepted, err)
			}
			if terminal == "deadline" && accepted.ExpiredAt == "" {
				t.Fatalf("deadline transition was not durably recorded: %#v", accepted)
			}
			record, err := f.base.store.GetRelaySealedV1(input.MessageID)
			if err != nil || record.Route.Kind != "reply" || record.Route.RequestID != ask.RequestID ||
				record.Route.ReplyTo != ask.MessageID || !bytes.Equal(record.Ciphertext, input.Ciphertext) {
				t.Fatalf("late encrypted evidence was not retained exactly: %#v err=%v", record, err)
			}
			var inboxState, outboxState string
			if err := f.base.store.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`,
				input.MessageID).Scan(&inboxState); err != nil {
				t.Fatal(err)
			}
			if err := f.base.store.db.QueryRow(`SELECT state FROM relay_v2_outbox WHERE message_id=?`,
				input.MessageID).Scan(&outboxState); err != nil {
				t.Fatal(err)
			}
			if inboxState != RelayInboxExpired || outboxState != RelayInboxExpired {
				t.Fatalf("late reply remained queued for automatic delivery: inbox=%s outbox=%s", inboxState, outboxState)
			}
			claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
				RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "source-consumer",
				BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 1,
			})
			if err != nil || len(claimed) != 0 {
				t.Fatalf("late result was automatically delivered to the original native Thread: %#v err=%v", claimed, err)
			}
			state, err := f.base.store.GetCommunicationLinkSealedRequestForNodeCredential(
				f.sourceOwner.nodeCredential, ask.RequestID)
			if err != nil || state.State != FabricRequestLateResult || state.LateResultMessageID != input.MessageID {
				t.Fatalf("late-result claim reopened request state: %#v err=%v", state, err)
			}
		})
	}
}
