//go:build linux

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// This workload leaves messages unclaimed while producers run, then drains
// exact receiver backlogs and verifies every RequestID/ReplyTo correlation.
// It measures the durable Store Relay path, not a live Node or model Runtime.
func TestStressConcurrentLinkSendAskReplyAndBacklogIsolation(t *testing.T) {
	const asks = DefaultRelayPendingAsksPerSenderEndpoint
	const sends = 32
	f := newLinkSealedSendTestFixtureWithActions(t, true, []string{"send", "ask", "reply"})
	baseAsks := make([]CommunicationLinkSealedAsk, asks/2)
	for i := range baseAsks {
		baseAsks[i] = sealedAskInputForFixtureWithIDs(t, f,
			fmt.Sprintf("msg_stress_base_ask_%03d", i), fmt.Sprintf("rq_stress_base_%03d", i))
		if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(baseAsks[i]); err != nil {
			t.Fatalf("seed Ask %d for concurrent replies: %v", i, err)
		}
	}

	newAsks := make([]CommunicationLinkSealedAsk, asks/2)
	for i := range newAsks {
		newAsks[i] = sealedAskInputForFixtureWithIDs(t, f,
			fmt.Sprintf("msg_stress_ask_%03d", i), fmt.Sprintf("rq_stress_ask_%03d", i))
	}
	sendInputs := make([]CommunicationLinkSealedSend, sends)
	for i := range sendInputs {
		messageID := fmt.Sprintf("msg_stress_send_%03d", i)
		context := sealedLinkEndpointContext(f.link, f.manifest, messageID, "SEND", "", "", "", false)
		wire, err := e2ee.SealEndpointMessage(f.sourceEndpointKey,
			f.manifest.Target.PublicIdentity, context, []byte("PUBLIC_SYNTHETIC stress send"), 1)
		if err != nil {
			t.Fatalf("seal synthetic Send %d: %v", i, err)
		}
		sendInputs[i] = CommunicationLinkSealedSend{
			NodeCredentialDigest: f.sourceOwner.nodeCredential, LinkID: f.link.ID,
			MessageID: messageID, IdempotencyKey: "idem_" + messageID,
			DataScope: f.dataScope, Ciphertext: wire,
		}
	}

	concurrentStart := time.Now()
	type enqueueResult struct {
		kind    string
		id      string
		elapsed time.Duration
		err     error
	}
	results := make(chan enqueueResult, len(newAsks)+len(sendInputs))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i, input := range newAsks {
		wait.Add(1)
		go func(index int, input CommunicationLinkSealedAsk) {
			defer wait.Done()
			<-start
			started := time.Now()
			_, err := f.base.store.EnqueueCommunicationLinkSealedAsk(input)
			results <- enqueueResult{kind: "ask", id: input.RequestID, elapsed: time.Since(started), err: err}
		}(i, input)
	}
	for i, input := range sendInputs {
		wait.Add(1)
		go func(index int, input CommunicationLinkSealedSend) {
			defer wait.Done()
			<-start
			started := time.Now()
			_, err := f.base.store.EnqueueCommunicationLinkSealedSend(input)
			results <- enqueueResult{kind: "send", id: input.MessageID, elapsed: time.Since(started), err: err}
		}(i, input)
	}
	close(start)
	wait.Wait()
	close(results)
	concurrentLatencies := make([]time.Duration, 0, len(newAsks)+len(sendInputs))
	for result := range results {
		concurrentLatencies = append(concurrentLatencies, result.elapsed)
		if result.err != nil {
			t.Fatalf("concurrent %s %s failed: %v", result.kind, result.id, result.err)
		}
	}
	concurrentElapsed := time.Since(concurrentStart)

	// Duplicate retries use the same exact idempotency identities. They must
	// return the stored rows and must not create extra receiver backlog.
	if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(newAsks[0]); err != nil {
		t.Fatalf("exact Ask retry: %v", err)
	}
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(sendInputs[0]); err != nil {
		t.Fatalf("exact Send retry: %v", err)
	}

	var targetReady int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox
WHERE recipient_endpoint_id=? AND state='READY'`, f.link.TargetEndpointID).Scan(&targetReady); err != nil {
		t.Fatal(err)
	}
	wantTargetBacklog := sends + asks
	if targetReady != wantTargetBacklog {
		t.Fatalf("target durable backlog=%d, want %d distinct SEND/ASK rows", targetReady, wantTargetBacklog)
	}

	claimStarted := time.Now()
	claimedTarget, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "stress-target-drain",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch,
		Limit: wantTargetBacklog,
	})
	claimElapsed := time.Since(claimStarted)
	if err != nil || len(claimedTarget) != wantTargetBacklog {
		t.Fatalf("target backlog claim count=%d err=%v, want %d", len(claimedTarget), err, wantTargetBacklog)
	}
	seenTarget := make(map[string]struct{}, wantTargetBacklog)
	for _, item := range claimedTarget {
		if item.RecipientEndpointID != f.link.TargetEndpointID || item.Route.ReceiverEndpointID != f.link.TargetEndpointID {
			t.Fatalf("target claim crossed receiver: %s", item.RecipientEndpointID)
		}
		if _, duplicate := seenTarget[item.MessageID]; duplicate {
			t.Fatalf("duplicate message in target backlog: %s", item.MessageID)
		}
		seenTarget[item.MessageID] = struct{}{}
		if item.Route.Kind == "ask" {
			if item.RequestID == "" || item.Route.RequestID != item.RequestID {
				t.Fatalf("ASK claim lost request correlation: %#v", item.Route)
			}
		} else if item.Route.Kind != "send" || item.RequestID != "" {
			t.Fatalf("unexpected target backlog route: kind=%s request=%s", item.Route.Kind, item.RequestID)
		}
	}
	if len(seenTarget) != wantTargetBacklog {
		t.Fatalf("target backlog unique messages=%d, want=%d", len(seenTarget), wantTargetBacklog)
	}
	if len(claimedTarget) == 0 {
		t.Fatal("target backlog unexpectedly empty")
	}
	firstAttempt := claimedTarget[0]
	if _, err := f.base.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: "attempt_stress_wrong_ack", MessageID: firstAttempt.MessageID,
		Digest: firstAttempt.Digest, TargetEndpointID: firstAttempt.RecipientEndpointID,
		BindingID: firstAttempt.BindingID, BindingEpoch: firstAttempt.BindingEpoch,
		Layer: RelayReceiptApplicationAck,
	}); !errors.Is(err, ErrRelayDeliveryNotFound) {
		t.Fatalf("wrong attempt ACK error=%v, want closed not-found", err)
	}
	requireSealedRelayAttemptState(t, f.base.store, firstAttempt, RelayAttemptClaimed)

	// The 17th Ask from this source Endpoint must fail at the per-sender cap
	// and leave no partial payload or request row.
	overLimitAsk := sealedAskInputForFixtureWithIDs(t, f,
		"msg_stress_over_quota", "rq_stress_over_quota")
	_, err = f.base.store.EnqueueCommunicationLinkSealedAsk(overLimitAsk)
	assertRelayAdmissionError(t, err, RelayAdmissionScopeSenderEndpoint,
		DefaultRelayPendingAsksPerSenderEndpoint,
		DefaultRelayPendingAsksPerSenderEndpoint, DefaultRelayAdmissionRetryAfterSec)
	var overLimitPayloads, overLimitRequests int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_message_payloads WHERE message_id=?`,
		overLimitAsk.MessageID).Scan(&overLimitPayloads); err != nil {
		t.Fatal(err)
	}
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_requests WHERE request_id=?`,
		overLimitAsk.RequestID).Scan(&overLimitRequests); err != nil {
		t.Fatal(err)
	}
	if overLimitPayloads != 0 || overLimitRequests != 0 {
		t.Fatalf("sender over-limit ASK left partial durable state: payloads=%d requests=%d",
			overLimitPayloads, overLimitRequests)
	}

	allAsks := append(append([]CommunicationLinkSealedAsk(nil), baseAsks...), newAsks...)
	replyInputs := make([]CommunicationLinkSealedReply, len(allAsks))
	for i, ask := range allAsks {
		replyInputs[i] = sealedReplyInputForFixture(t, f, ask, fmt.Sprintf("msg_stress_reply_%03d", i))
	}
	wrongReply := replyInputs[0]
	wrongReply.RequestID = replyInputs[1].RequestID
	wrongReply.MessageID = "msg_stress_wrong_request_reply"
	wrongReply.IdempotencyKey = "idem_" + wrongReply.MessageID
	if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(wrongReply); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("cross-request Reply error=%v, want closed authorization denial", err)
	}
	replyStarted := time.Now()
	replyResults := make(chan enqueueResult, len(replyInputs))
	start = make(chan struct{})
	replyOrder := make([]int, len(replyInputs))
	for i := range replyOrder {
		replyOrder[i] = i
	}
	rand.New(rand.NewSource(20261009)).Shuffle(len(replyOrder), func(i, j int) {
		replyOrder[i], replyOrder[j] = replyOrder[j], replyOrder[i]
	})
	for _, index := range replyOrder {
		input := replyInputs[index]
		wait.Add(1)
		go func(input CommunicationLinkSealedReply) {
			defer wait.Done()
			<-start
			started := time.Now()
			accepted, err := f.base.store.EnqueueCommunicationLinkSealedReply(input)
			if err == nil && (accepted.RequestID != input.RequestID || accepted.ReplyMessageID != input.MessageID || accepted.State != FabricRequestReplied) {
				err = fmt.Errorf("reply lifecycle result did not match exact RequestID")
			}
			replyResults <- enqueueResult{kind: "reply", id: input.RequestID, elapsed: time.Since(started), err: err}
		}(input)
	}
	close(start)
	wait.Wait()
	close(replyResults)
	replyLatencies := make([]time.Duration, 0, len(replyInputs))
	for result := range replyResults {
		replyLatencies = append(replyLatencies, result.elapsed)
		if result.err != nil {
			t.Fatalf("concurrent %s for %s failed: %v", result.kind, result.id, result.err)
		}
	}
	replyElapsed := time.Since(replyStarted)
	if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(replyInputs[0]); err != nil {
		t.Fatalf("exact Reply retry: %v", err)
	}

	var sourceReady int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox
WHERE recipient_endpoint_id=? AND state='READY'`, f.link.SourceEndpointID).Scan(&sourceReady); err != nil {
		t.Fatal(err)
	}
	if sourceReady != len(replyInputs) {
		t.Fatalf("source durable Reply backlog=%d, want=%d", sourceReady, len(replyInputs))
	}
	claimRepliesStarted := time.Now()
	claimedReplies, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "stress-source-drain",
		BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch,
		Limit: len(replyInputs),
	})
	claimRepliesElapsed := time.Since(claimRepliesStarted)
	if err != nil || len(claimedReplies) != len(replyInputs) {
		t.Fatalf("source reply backlog claim count=%d err=%v, want=%d", len(claimedReplies), err, len(replyInputs))
	}
	wantByRequest := make(map[string]string, len(allAsks))
	for i, ask := range allAsks {
		wantByRequest[ask.RequestID] = ask.MessageID
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(replyInputs[i]); err != nil {
			t.Fatalf("idempotent Reply retry %d: %v", i, err)
		}
	}
	for _, item := range claimedReplies {
		if item.RecipientEndpointID != f.link.SourceEndpointID || item.Route.ReceiverEndpointID != f.link.SourceEndpointID || item.Route.Kind != "reply" ||
			wantByRequest[item.RequestID] != item.Route.ReplyTo {
			t.Fatalf("reply crossed receiver/request/message: receiver=%s request=%s reply_to=%s",
				item.RecipientEndpointID, item.RequestID, item.Route.ReplyTo)
		}
		delete(wantByRequest, item.RequestID)
	}
	if len(wantByRequest) != 0 {
		t.Fatalf("missing correlated replies: %d", len(wantByRequest))
	}
	var acceptedPayloads, inboxRows, claimedAttempts int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_message_payloads`).Scan(&acceptedPayloads); err != nil {
		t.Fatal(err)
	}
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox`).Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE state='CLAIMED'`).Scan(&claimedAttempts); err != nil {
		t.Fatal(err)
	}
	if acceptedPayloads != sends+asks+len(replyInputs) || inboxRows != acceptedPayloads || claimedAttempts != inboxRows {
		t.Fatalf("durable accepted conservation failed: payloads=%d inbox=%d claimed_attempts=%d want=%d",
			acceptedPayloads, inboxRows, claimedAttempts, sends+asks+len(replyInputs))
	}
	emitRelayStressMetric(t, "relay_concurrent_send_ask", map[string]any{
		"send_count": sends, "new_ask_count": len(newAsks), "prerequisite_open_asks": len(baseAsks),
		"receiver_pending_limit": DefaultRelayPendingAsksPerReceiver,
		"target_backlog_rows":    targetReady, "samples": sends + len(newAsks),
		"elapsed_ms":       concurrentElapsed.Milliseconds(),
		"throughput_ops_s": relayRatePerSecond(int64(sends+len(newAsks)), concurrentElapsed),
		"latency_p50_ms":   percentileStress(concurrentLatencies, 0.50),
		"latency_p95_ms":   percentileStress(concurrentLatencies, 0.95),
		"claim_elapsed_ms": claimElapsed.Milliseconds(),
	})
	emitRelayStressMetric(t, "relay_concurrent_reply", map[string]any{
		"reply_count": len(replyInputs), "source_backlog_rows": sourceReady,
		"samples": len(replyInputs), "elapsed_ms": replyElapsed.Milliseconds(),
		"throughput_ops_s":            relayRatePerSecond(int64(len(replyInputs)), replyElapsed),
		"latency_p50_ms":              percentileStress(replyLatencies, 0.50),
		"latency_p95_ms":              percentileStress(replyLatencies, 0.95),
		"claim_elapsed_ms":            claimRepliesElapsed.Milliseconds(),
		"unique_request_correlations": len(allAsks),
		"wrong_ack_rejected":          true, "cross_request_reply_rejected": true,
		"sender_over_limit_rejected": true,
		"sender_endpoint_limit":      DefaultRelayPendingAsksPerSenderEndpoint,
		"durable_conservation_rows":  acceptedPayloads,
	})
}

// This workload drives the production Store authorization and relay entry
// points from four distinct source Endpoints into one exact receiver. It
// verifies Store correlation and durable backlog only; ciphertext is synthetic
// and this does not exercise Node replay counters, decryption, or Runtime
// consumption.
func TestStressFourSendersSixteenAsksEachAndShuffledReplies(t *testing.T) {
	const senders, asksPerSender = 4, 16
	const total = senders * asksPerSender
	base := newExternalThreadInviteTestFixture(t)
	sourceOwner := bindLinkSealedSendTestNode(t, base.store, base.source.ownerID, "node_source")
	targetOwner := bindLinkSealedSendTestNode(t, base.store, base.target.ownerID, "node_target")
	targetKey := registerLinkSealedSendEndpointKey(t, base.store, base.target.endpointID)
	targetBinding, err := base.store.GetSessionBindingForEndpoint(base.target.endpointID)
	if err != nil {
		t.Fatal(err)
	}

	type sender struct {
		endpoint externalThreadInviteTestEndpoint
		link     *CommunicationLink
		manifest *CommunicationLinkKeyManifest
		fixture  *linkSealedSendTestFixture
	}
	// Four senders fill the receiver's 64-request cap. A fifth independently
	// authorized sender with no prior asks attempts request 65, isolating the
	// receiver cap from each sender's own 16-request limit.
	senderSet := make([]sender, senders+1)
	for i := range senderSet {
		source := base.source
		if i > 0 {
			source = stressCreateAdditionalSourceEndpoint(t, base, i)
		}
		sourceKey := registerLinkSealedSendEndpointKey(t, base.store, source.endpointID)
		invite, err := base.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
			OwnerID: source.ownerID, SourceEndpointID: source.endpointID,
			SourceGroupID: source.groupID, HubID: base.hubID,
			Direction: "forward", Actions: []string{"ask", "reply"},
			DataScopes: []string{"thread.message"},
			ExpiresAt:  time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
		})
		if err != nil {
			t.Fatalf("create sender %d invite: %v", i, err)
		}
		accepted, err := base.store.AcceptExternalThreadInvite(invite.Token,
			base.target.ownerID, base.target.endpointID, base.target.groupID)
		if err != nil {
			t.Fatalf("accept sender %d invite: %v", i, err)
		}
		link, err := base.store.GetCommunicationLinkForOwner(accepted.LinkID, source.ownerID)
		if err != nil {
			t.Fatalf("read sender %d Link: %v", i, err)
		}
		manifest, err := base.store.GetCommunicationLinkKeyManifest(link.ID, source.ownerID)
		if err != nil {
			t.Fatalf("read sender %d key manifest: %v", i, err)
		}
		for _, grant := range []struct {
			ownerID, keyID string
			identity       *e2ee.Identity
			side           e2ee.OwnerLinkGrantSide
		}{
			{link.SourceOwnerID, sourceOwner.ownerKeyID, sourceOwner.identity, e2ee.OwnerLinkGrantSideSource},
			{link.TargetOwnerID, targetOwner.ownerKeyID, targetOwner.identity, e2ee.OwnerLinkGrantSideTarget},
		} {
			linkExpiry, parseErr := time.Parse(time.RFC3339, link.ExpiresAt)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			proof, signErr := grant.identity.SignOwnerLinkKeyGrant(grant.ownerID, link.ID,
				link.ContractDigest, manifest.Digest, uint64(link.Version), grant.side,
				time.Now().UTC().Add(-time.Minute), linkExpiry)
			if signErr != nil {
				t.Fatalf("sign sender %d owner grant: %v", i, signErr)
			}
			if _, err := base.store.RecordCommunicationLinkKeyGrant(grant.ownerID,
				link.ID, string(grant.side), grant.keyID, proof); err != nil {
				t.Fatalf("record sender %d owner grant: %v", i, err)
			}
		}
		fixture := &linkSealedSendTestFixture{
			base: base, link: link, sourceOwner: sourceOwner, targetOwner: targetOwner,
			sourceEndpointKey: sourceKey, targetEndpointKey: targetKey,
			manifest: manifest, dataScope: "thread.message",
		}
		senderSet[i] = sender{endpoint: source, link: link, manifest: manifest, fixture: fixture}
	}

	asks := make([]CommunicationLinkSealedAsk, total)
	wantByRequest := make(map[string]sender, total)
	for senderIndex, entry := range senderSet[:senders] {
		for perSender := 0; perSender < asksPerSender; perSender++ {
			index := senderIndex*asksPerSender + perSender
			messageID := fmt.Sprintf("msg_stress_multi_%02d_%02d", senderIndex, perSender)
			requestID := fmt.Sprintf("rq_stress_multi_%02d_%02d", senderIndex, perSender)
			ask := sealedAskInputForFixtureWithIDs(t, entry.fixture, messageID, requestID)
			asks[index] = ask
			wantByRequest[requestID] = entry
		}
	}
	askByRequest := make(map[string]CommunicationLinkSealedAsk, total)
	for _, ask := range asks {
		askByRequest[ask.RequestID] = ask
	}

	type result struct {
		request string
		latency time.Duration
		err     error
	}
	results := make(chan result, total)
	start := make(chan struct{})
	var workers sync.WaitGroup
	started := time.Now()
	for _, task := range asks {
		workers.Add(1)
		go func(task CommunicationLinkSealedAsk) {
			defer workers.Done()
			<-start
			callStarted := time.Now()
			_, err := base.store.EnqueueCommunicationLinkSealedAsk(task)
			results <- result{request: task.RequestID, latency: time.Since(callStarted), err: err}
		}(task)
	}
	close(start)
	workers.Wait()
	close(results)
	askLatencies := make([]time.Duration, 0, total)
	for outcome := range results {
		askLatencies = append(askLatencies, outcome.latency)
		if outcome.err != nil {
			t.Fatalf("concurrent Ask %s failed: %v", outcome.request, outcome.err)
		}
	}
	askElapsed := time.Since(started)

	var ready int
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox WHERE recipient_endpoint_id=? AND state='READY'`, base.target.endpointID).Scan(&ready); err != nil || ready != total {
		t.Fatalf("durable target backlog=%d err=%v, want=%d", ready, err, total)
	}
	// Retry exact ciphertext/message/request identities while the receiver is
	// offline; the idempotent rows must not create extra backlog.
	for _, task := range []CommunicationLinkSealedAsk{asks[0], asks[asksPerSender], asks[2*asksPerSender], asks[3*asksPerSender]} {
		if _, err := base.store.EnqueueCommunicationLinkSealedAsk(task); err != nil {
			t.Fatalf("exact Ask retry %s: %v", task.RequestID, err)
		}
	}
	var retriedReady int
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox WHERE recipient_endpoint_id=? AND state='READY'`, base.target.endpointID).Scan(&retriedReady); err != nil || retriedReady != total {
		t.Fatalf("exact retries changed backlog to %d err=%v, want=%d", retriedReady, err, total)
	}

	quotaFixture := senderSet[senders].fixture
	overQuota := sealedAskInputForFixtureWithIDs(t, quotaFixture, "msg_stress_multi_overquota", "rq_stress_multi_overquota")
	_, err = base.store.EnqueueCommunicationLinkSealedAsk(overQuota)
	assertRelayAdmissionError(t, err, RelayAdmissionScopeReceiver,
		DefaultRelayPendingAsksPerReceiver,
		DefaultRelayPendingAsksPerReceiver, DefaultRelayAdmissionRetryAfterSec)
	var overQuotaPayloads, overQuotaRequests int
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_message_payloads WHERE message_id=?`, overQuota.MessageID).Scan(&overQuotaPayloads); err != nil {
		t.Fatal(err)
	}
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_requests WHERE request_id=?`, overQuota.RequestID).Scan(&overQuotaRequests); err != nil {
		t.Fatal(err)
	}
	if overQuotaPayloads != 0 || overQuotaRequests != 0 {
		t.Fatalf("over-quota Ask left partial durable state: payloads=%d requests=%d", overQuotaPayloads, overQuotaRequests)
	}

	claimed, err := base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: base.target.endpointID, ConsumerID: "stress-multi-target",
		BindingID: targetBinding.ID, BindingEpoch: targetBinding.Epoch, Limit: total,
	})
	if err != nil || len(claimed) != total {
		t.Fatalf("claim target asks=%d err=%v, want=%d", len(claimed), err, total)
	}
	seenRequest := make(map[string]struct{}, total)
	for _, attempt := range claimed {
		want, ok := wantByRequest[attempt.RequestID]
		if !ok || attempt.RecipientEndpointID != base.target.endpointID || attempt.Route.ReceiverEndpointID != base.target.endpointID ||
			attempt.Route.SenderEndpointID != want.endpoint.endpointID || attempt.Route.Kind != "ask" || attempt.Route.RequestID != attempt.RequestID {
			t.Fatalf("claim correlation crossed sender/receiver/request: request=%s sender=%s receiver=%s", attempt.RequestID, attempt.Route.SenderEndpointID, attempt.RecipientEndpointID)
		}
		if _, duplicate := seenRequest[attempt.RequestID]; duplicate {
			t.Fatalf("duplicate target request claim %s", attempt.RequestID)
		}
		seenRequest[attempt.RequestID] = struct{}{}
	}
	if len(seenRequest) != total {
		t.Fatalf("unique target requests=%d, want=%d", len(seenRequest), total)
	}
	if _, err := base.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: "attempt_stress_multi_wrong", MessageID: claimed[0].MessageID,
		Digest: claimed[0].Digest, TargetEndpointID: base.target.endpointID,
		BindingID: targetBinding.ID, BindingEpoch: targetBinding.Epoch,
		Layer: RelayReceiptApplicationAck,
	}); !errors.Is(err, ErrRelayDeliveryNotFound) {
		t.Fatalf("wrong attempt ACK returned %v, want closed not-found", err)
	}
	requireSealedRelayAttemptState(t, base.store, claimed[0], RelayAttemptClaimed)

	replies := make([]CommunicationLinkSealedReply, total)
	for i, task := range asks {
		entry := wantByRequest[task.RequestID]
		replies[i] = sealedReplyInputForFixture(t, entry.fixture, task, fmt.Sprintf("msg_stress_multi_reply_%03d", i))
	}
	replyOrder := make([]int, total)
	for i := range replyOrder {
		replyOrder[i] = i
	}
	rand.New(rand.NewSource(20261009)).Shuffle(len(replyOrder), func(i, j int) {
		replyOrder[i], replyOrder[j] = replyOrder[j], replyOrder[i]
	})
	replyResults := make(chan result, total)
	start = make(chan struct{})
	workers = sync.WaitGroup{}
	replyStarted := time.Now()
	for _, index := range replyOrder {
		task, reply := asks[index], replies[index]
		workers.Add(1)
		go func(task CommunicationLinkSealedAsk, reply CommunicationLinkSealedReply) {
			defer workers.Done()
			<-start
			callStarted := time.Now()
			accepted, err := base.store.EnqueueCommunicationLinkSealedReply(reply)
			if err == nil && (accepted.RequestID != task.RequestID || accepted.ReplyMessageID != reply.MessageID || accepted.State != FabricRequestReplied) {
				err = fmt.Errorf("Reply lifecycle crossed RequestID")
			}
			replyResults <- result{request: task.RequestID, latency: time.Since(callStarted), err: err}
		}(task, reply)
	}
	close(start)
	workers.Wait()
	close(replyResults)
	replyLatencies := make([]time.Duration, 0, total)
	for outcome := range replyResults {
		replyLatencies = append(replyLatencies, outcome.latency)
		if outcome.err != nil {
			t.Fatalf("Reply for %s failed: %v", outcome.request, outcome.err)
		}
	}
	replyElapsed := time.Since(replyStarted)

	// The requester endpoints are separate; drain each exact 16-message
	// backlog under its own binding and verify the original RequestID and ASK.
	for _, entry := range senderSet[:senders] {
		claimedReplies, err := base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: entry.endpoint.endpointID, ConsumerID: "stress-multi-source-" + entry.endpoint.endpointID,
			BindingID: entry.manifest.Source.BindingID, BindingEpoch: entry.manifest.Source.BindingEpoch,
			Limit: asksPerSender,
		})
		if err != nil || len(claimedReplies) != asksPerSender {
			t.Fatalf("source %s Reply backlog=%d err=%v, want=%d", entry.endpoint.endpointID, len(claimedReplies), err, asksPerSender)
		}
		seenReplies := make(map[string]struct{}, asksPerSender)
		for _, item := range claimedReplies {
			askSender := wantByRequest[item.RequestID]
			originalAsk, ok := askByRequest[item.RequestID]
			if !ok || askSender.endpoint.endpointID != entry.endpoint.endpointID || item.RecipientEndpointID != entry.endpoint.endpointID || item.Route.ReceiverEndpointID != entry.endpoint.endpointID ||
				item.Route.Kind != "reply" || item.Route.RequestID != originalAsk.RequestID || item.Route.ReplyTo != originalAsk.MessageID {
				t.Fatalf("Reply crossed original endpoint/request: endpoint=%s request=%s reply_to=%s", entry.endpoint.endpointID, item.RequestID, item.Route.ReplyTo)
			}
			if _, duplicate := seenReplies[item.RequestID]; duplicate {
				t.Fatalf("duplicate Reply correlation for %s", item.RequestID)
			}
			seenReplies[item.RequestID] = struct{}{}
		}
		if len(seenReplies) != asksPerSender {
			t.Fatalf("source %s has %d unique correlated replies, want=%d", entry.endpoint.endpointID, len(seenReplies), asksPerSender)
		}
	}
	var payloads, inboxRows, claimedAttempts, repliedRequests int
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_message_payloads`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_inbox`).Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_delivery_attempts WHERE state='CLAIMED'`).Scan(&claimedAttempts); err != nil {
		t.Fatal(err)
	}
	if err := base.store.db.QueryRow(`SELECT count(*) FROM relay_v2_requests WHERE state=? AND reply_message_id<>''`, FabricRequestReplied).Scan(&repliedRequests); err != nil {
		t.Fatal(err)
	}
	if payloads != total*2 || inboxRows != payloads || claimedAttempts != inboxRows || repliedRequests != total {
		t.Fatalf("durable accepted/correlation conservation failed: payloads=%d inbox=%d claimed=%d replied_requests=%d want payloads=%d requests=%d",
			payloads, inboxRows, claimedAttempts, repliedRequests, total*2, total)
	}

	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		t.Fatal(err)
	}
	t.Logf("stress metrics: senders=%d asks_per_sender=%d total_asks=%d receiver_cap_probe_extra_authorized_sender=true receiver_cap_probe_attempts=1 receiver_pending_limit=%d ask_wall=%s ask_throughput=%.1f/s ask_p50_ms=%.3f ask_p95_ms=%.3f shuffled_reply_wall=%s reply_throughput=%.1f/s reply_p50_ms=%.3f reply_p95_ms=%.3f process_user_cpu=%v process_system_cpu=%v process_maxrss_kib=%d durable_payloads=%d durable_inbox=%d claimed_attempts=%d replied_requests=%d crypto_scope=store-only-no-node-replay-or-decrypt",
		senders, asksPerSender, total, DefaultRelayPendingAsksPerReceiver, askElapsed, float64(total)/askElapsed.Seconds(), percentileStress(askLatencies, .50), percentileStress(askLatencies, .95),
		replyElapsed, float64(total)/replyElapsed.Seconds(), percentileStress(replyLatencies, .50), percentileStress(replyLatencies, .95),
		rusage.Utime, rusage.Stime, rusage.Maxrss,
		payloads, inboxRows, claimedAttempts, repliedRequests)
}

func requireSealedRelayAttemptState(t *testing.T, s *Store,
	attempt RelaySealedV1DeliveryAttempt, want string) {
	t.Helper()
	var state string
	err := s.db.QueryRow(`SELECT state FROM relay_v2_delivery_attempts
WHERE attempt_id=? AND message_id=? AND recipient_endpoint_id=? AND binding_id=? AND binding_epoch=?`,
		attempt.AttemptID, attempt.MessageID, attempt.RecipientEndpointID,
		attempt.BindingID, attempt.BindingEpoch).Scan(&state)
	if err != nil || state != want {
		t.Fatalf("sealed attempt state=%q err=%v, want=%q for exact attempt coordinates", state, err, want)
	}
}

func stressCreateAdditionalSourceEndpoint(t *testing.T, base *externalThreadInviteTestFixture, index int) externalThreadInviteTestEndpoint {
	t.Helper()
	endpointID := fmt.Sprintf("ep_source_stress_%d", index)
	principalID := "pr_" + endpointID
	principal, err := base.store.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
		OwnerID: base.source.ownerID, TrustDomainID: base.source.ownerID, Name: endpointID})
	if err != nil {
		t.Fatalf("create stress source principal %d: %v", index, err)
	}
	if _, err := base.store.CreateMembership(Membership{PrincipalID: principal.ID, GroupID: base.source.groupID,
		Role: "member", Grants: []string{"message.ask"}}); err != nil {
		t.Fatalf("join stress source principal %d: %v", index, err)
	}
	nativeSessionID := "native_" + endpointID
	endpoint, err := base.store.UpsertEndpoint(Endpoint{ID: endpointID, Name: "Thread " + endpointID,
		Harness: "codex", NativeSessionID: nativeSessionID, MachineID: "node_source", Status: "online"})
	if err != nil {
		t.Fatalf("create stress source Endpoint %d: %v", index, err)
	}
	binding, err := base.store.CreateSessionBinding(SessionBinding{EndpointID: endpoint.ID,
		PrincipalID: principal.ID, GroupID: base.source.groupID, NativeSessionID: nativeSessionID, NodeID: "node_source"})
	if err != nil {
		t.Fatalf("bind stress source Endpoint %d: %v", index, err)
	}
	if _, err := base.store.AcquireSessionBindingLease(binding.ID, "lease_"+endpointID,
		binding.Epoch, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("lease stress source Endpoint %d: %v", index, err)
	}
	return externalThreadInviteTestEndpoint{ownerID: base.source.ownerID, groupID: base.source.groupID,
		endpointID: endpoint.ID, bindingID: binding.ID}
}

func emitRelayStressMetric(t *testing.T, stage string, fields map[string]any) {
	t.Helper()
	fields["schema"] = "cicada.v01.stress.metric.v1"
	fields["stage"] = stage
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err == nil {
		fields["process_peak_rss_kib"] = usage.Maxrss
		fields["process_user_cpu_ms"] = usage.Utime.Sec*1000 + usage.Utime.Usec/1000
		fields["process_system_cpu_ms"] = usage.Stime.Sec*1000 + usage.Stime.Usec/1000
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encode stress metric: %v", err)
	}
	t.Logf("CICADA_STRESS_METRIC %s", encoded)
}

func relayRatePerSecond(count int64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
}

func percentileStress(samples []time.Duration, percentile float64) float64 {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return float64(ordered[index].Microseconds()) / 1000
}
