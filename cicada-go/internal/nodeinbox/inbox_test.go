package nodeinbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenRequiresPrivateDirectoryAndProtectsPlaintextDatabase(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "node")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inbox.sqlite3")
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("plaintext inbox opened in a directory readable by other users")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	inbox, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if _, _, err := inbox.Save(context.Background(), testMessage("msg-private", "digest-private")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %v; want 0600", info.Mode().Perm())
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if sidecar, err := os.Stat(path + suffix); err == nil && sidecar.Mode().Perm()&0o077 != 0 {
			t.Fatalf("SQLite %s sidecar is readable by other users", suffix)
		}
	}
}

func TestSaveIsIdempotentAndRejectsDigestConflict(t *testing.T) {
	inbox := openTestInbox(t)
	message := testMessage("msg-idempotent", "digest-a")
	first, created, err := inbox.Save(context.Background(), message)
	if err != nil {
		t.Fatalf("save first message: %v", err)
	}
	if !created || first.State != NODE_RECEIVED {
		t.Fatalf("first save did not create NODE_RECEIVED delivery: created=%t state=%s", created, first.State)
	}
	message.Payload = []byte("a different local copy does not change the digest key")
	second, created, err := inbox.Save(context.Background(), message)
	if err != nil {
		t.Fatalf("save duplicate message: %v", err)
	}
	if created || second.MessageID != first.MessageID || second.State != NODE_RECEIVED {
		t.Fatalf("duplicate save was not idempotent: created=%t state=%s", created, second.State)
	}
	if string(second.Payload) != "sensitive test body" {
		t.Fatalf("duplicate save replaced durable payload")
	}

	conflict := message
	conflict.Digest = "digest-b"
	conflict.Payload = []byte("sensitive conflict body")
	_, _, err = inbox.Save(context.Background(), conflict)
	if !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("same ID with another digest error = %v, want ErrMessageConflict", err)
	}
	if strings.Contains(err.Error(), "sensitive conflict body") || strings.Contains(err.Error(), "sensitive test body") {
		t.Fatalf("conflict error leaked payload")
	}
	stored, err := inbox.Get(context.Background(), message.MessageID)
	if err != nil {
		t.Fatalf("get original after conflict: %v", err)
	}
	if stored.Digest != "digest-a" || stored.State != NODE_RECEIVED {
		t.Fatalf("conflict changed stored delivery: digest=%s state=%s", stored.Digest, stored.State)
	}
}

func TestAbandonClaimBeforeInjectionAllowsRetryButNotAfterInjection(t *testing.T) {
	inbox := openTestInbox(t)
	ctx := context.Background()
	message := testMessage("msg-local-guard-outage", "digest-local-guard-outage")
	if _, _, err := inbox.Save(ctx, message); err != nil {
		t.Fatal(err)
	}
	first, err := inbox.Claim(ctx, "local-consumer")
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.AbandonClaim(ctx, first.AttemptID); err != nil {
		t.Fatalf("release before injection: %v", err)
	}
	if err := inbox.AbandonClaim(ctx, first.AttemptID); !errors.Is(err, ErrStaleReceipt) {
		t.Fatalf("reusing abandoned attempt: %v", err)
	}
	second, err := inbox.Claim(ctx, "local-consumer")
	if err != nil || second.MessageID != first.MessageID || second.AttemptID == first.AttemptID {
		t.Fatalf("retry after Guard recovery: claim=%+v err=%v", second, err)
	}
	if _, err := inbox.BeginInjection(ctx, second.AttemptID); err != nil {
		t.Fatal(err)
	}
	if err := inbox.AbandonClaim(ctx, second.AttemptID); !errors.Is(err, ErrStaleReceipt) {
		t.Fatalf("injecting attempt must not be released: %v", err)
	}
	if _, err := inbox.Claim(ctx, "another-consumer"); !errors.Is(err, ErrNoDelivery) {
		t.Fatalf("injecting message was re-claimed: %v", err)
	}
}

func TestRejectBeforeInjectionFencesRevokedLocalDelivery(t *testing.T) {
	inbox := openTestInbox(t)
	ctx := context.Background()
	message := testMessage("msg-local-revoked", "digest-local-revoked")
	if _, _, err := inbox.Save(ctx, message); err != nil {
		t.Fatal(err)
	}
	claim, err := inbox.Claim(ctx, "local-consumer")
	if err != nil {
		t.Fatal(err)
	}
	forged := *claim
	forged.BindingEpoch++
	if err := inbox.RejectBeforeInjection(ctx, forged, "authorization revoked"); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("forged route could reject delivery: %v", err)
	}
	assertState(t, inbox, message.MessageID, NODE_RECEIVED)
	if err := inbox.RejectBeforeInjection(ctx, *claim, "authorization revoked"); err != nil {
		t.Fatal(err)
	}
	assertState(t, inbox, message.MessageID, FAILED)
	if _, err := inbox.Claim(ctx, "other-consumer"); !errors.Is(err, ErrNoDelivery) {
		t.Fatalf("revoked delivery was re-claimed: %v", err)
	}
}

func TestReceiptValidationAndLayeredStates(t *testing.T) {
	inbox := openTestInbox(t)
	message := testMessage("msg-receipt", "digest-receipt")
	if _, _, err := inbox.Save(context.Background(), message); err != nil {
		t.Fatalf("save: %v", err)
	}
	claim, err := inbox.Claim(context.Background(), "consumer-a")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claim.State != NODE_RECEIVED || claim.EndpointID != message.EndpointID || claim.SessionID != message.SessionID || claim.BindingEpoch != message.BindingEpoch || claim.AttemptID == "" {
		t.Fatalf("claim lost immutable routing or attempt metadata: state=%s endpoint=%s session=%s epoch=%d attempt=%s", claim.State, claim.EndpointID, claim.SessionID, claim.BindingEpoch, claim.AttemptID)
	}
	if _, err := inbox.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatalf("begin injection: %v", err)
	}
	assertState(t, inbox, message.MessageID, INJECTING)

	wrong := receiptFrom(claim, RUNTIME_INJECTED)
	wrong.EndpointID = "endpoint-other"
	if _, err := inbox.Acknowledge(context.Background(), wrong); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("wrong endpoint receipt error = %v, want ErrInvalidReceipt", err)
	}
	assertState(t, inbox, message.MessageID, INJECTING)
	wrong = receiptFrom(claim, RUNTIME_INJECTED)
	wrong.Digest = "digest-other"
	if _, err := inbox.Acknowledge(context.Background(), wrong); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("wrong digest receipt error = %v, want ErrInvalidReceipt", err)
	}
	assertState(t, inbox, message.MessageID, INJECTING)
	wrong = receiptFrom(claim, RUNTIME_INJECTED)
	wrong.BindingEpoch++
	if _, err := inbox.Acknowledge(context.Background(), wrong); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("wrong epoch receipt error = %v, want ErrInvalidReceipt", err)
	}
	assertState(t, inbox, message.MessageID, INJECTING)
	wrong = receiptFrom(claim, RUNTIME_INJECTED)
	wrong.AttemptID = "attempt-stale"
	if _, err := inbox.Acknowledge(context.Background(), wrong); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("wrong attempt receipt error = %v, want ErrInvalidReceipt", err)
	}
	assertState(t, inbox, message.MessageID, INJECTING)

	if _, err := inbox.RecordRuntimeInjected(context.Background(), receiptFrom(claim, RUNTIME_INJECTED)); err != nil {
		t.Fatalf("record runtime injection: %v", err)
	}
	assertState(t, inbox, message.MessageID, RUNTIME_INJECTED)
	if _, err := inbox.RecordConsumptionUnconfirmed(context.Background(), receiptFrom(claim, CONSUMPTION_UNCONFIRMED)); err != nil {
		t.Fatalf("record unconfirmed consumption: %v", err)
	}
	assertState(t, inbox, message.MessageID, CONSUMPTION_UNCONFIRMED)
	if _, err := inbox.RecordRuntimeInjected(context.Background(), receiptFrom(claim, RUNTIME_INJECTED)); !errors.Is(err, ErrStaleReceipt) {
		t.Fatalf("late runtime receipt error = %v, want ErrStaleReceipt", err)
	}
	assertState(t, inbox, message.MessageID, CONSUMPTION_UNCONFIRMED)
	// Repeating the receipt at the current layer is idempotent.
	if _, err := inbox.RecordConsumptionUnconfirmed(context.Background(), receiptFrom(claim, CONSUMPTION_UNCONFIRMED)); err != nil {
		t.Fatalf("repeat unconfirmed receipt: %v", err)
	}
}

func TestCodexQueueAcceptedDoesNotClaimRuntimeInjection(t *testing.T) {
	inbox := openTestInbox(t)
	message := testMessage("msg-codex-queue-accepted", "digest-codex-queue-accepted")
	if _, _, err := inbox.Save(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	claim, err := inbox.Claim(context.Background(), "codex-queue-consumer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	queued, err := inbox.RecordCodexQueueAccepted(context.Background(), receiptFrom(claim, CONSUMPTION_UNCONFIRMED))
	if err != nil {
		t.Fatal(err)
	}
	if queued.State != CONSUMPTION_UNCONFIRMED || queued.State == RUNTIME_INJECTED {
		t.Fatalf("queue acceptance state = %s, must remain consumption-unconfirmed", queued.State)
	}
}

func TestFailedReceiptIsTerminal(t *testing.T) {
	inbox := openTestInbox(t)
	message := testMessage("msg-failed", "digest-failed")
	if _, _, err := inbox.Save(context.Background(), message); err != nil {
		t.Fatalf("save: %v", err)
	}
	claim, err := inbox.Claim(context.Background(), "consumer-failed")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := inbox.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatalf("begin injection: %v", err)
	}
	if _, err := inbox.RecordFailed(context.Background(), receiptFrom(claim, FAILED), "runtime unavailable"); err != nil {
		t.Fatalf("record failed receipt: %v", err)
	}
	assertState(t, inbox, message.MessageID, FAILED)
	if _, err := inbox.RecordRuntimeInjected(context.Background(), receiptFrom(claim, RUNTIME_INJECTED)); !errors.Is(err, ErrStaleReceipt) {
		t.Fatalf("late runtime receipt after failure = %v, want ErrStaleReceipt", err)
	}
}

func TestClaimIsSingleConsumer(t *testing.T) {
	inbox := openTestInbox(t)
	if _, _, err := inbox.Save(context.Background(), testMessage("msg-concurrent", "digest-concurrent")); err != nil {
		t.Fatalf("save: %v", err)
	}

	const consumers = 32
	var wg sync.WaitGroup
	claims := make(chan *Claim, consumers)
	errorsCh := make(chan error, consumers)
	for n := 0; n < consumers; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			claim, err := inbox.Claim(context.Background(), "consumer-"+string(rune('a'+n)))
			if err != nil {
				errorsCh <- err
				return
			}
			claims <- claim
		}(n)
	}
	wg.Wait()
	close(claims)
	close(errorsCh)

	var got []*Claim
	for claim := range claims {
		got = append(got, claim)
	}
	if len(got) != 1 {
		t.Fatalf("concurrent claim winners = %d, want 1", len(got))
	}
	for err := range errorsCh {
		if !errors.Is(err, ErrNoDelivery) {
			t.Fatalf("losing claim error = %v, want ErrNoDelivery", err)
		}
	}
	assertState(t, inbox, "msg-concurrent", NODE_RECEIVED)
}

func TestClaimIsSingleConsumerAcrossInboxHandles(t *testing.T) {
	path := privateTestInboxPath(t)
	producer, err := Open(path)
	if err != nil {
		t.Fatalf("open producer inbox: %v", err)
	}
	defer producer.Close()
	if _, _, err := producer.Save(context.Background(), testMessage("msg-cross-handle", "digest-cross-handle")); err != nil {
		t.Fatalf("save: %v", err)
	}
	left, err := Open(path)
	if err != nil {
		t.Fatalf("open left inbox: %v", err)
	}
	defer left.Close()
	right, err := Open(path)
	if err != nil {
		t.Fatalf("open right inbox: %v", err)
	}
	defer right.Close()

	var wg sync.WaitGroup
	claims := make(chan *Claim, 2)
	errorsCh := make(chan error, 2)
	for n, inbox := range []*Inbox{left, right} {
		wg.Add(1)
		go func(n int, inbox *Inbox) {
			defer wg.Done()
			claim, err := inbox.Claim(context.Background(), "cross-consumer-"+string(rune('a'+n)))
			if err != nil {
				errorsCh <- err
				return
			}
			claims <- claim
		}(n, inbox)
	}
	wg.Wait()
	close(claims)
	close(errorsCh)
	var winnerCount int
	for range claims {
		winnerCount++
	}
	if winnerCount != 1 {
		t.Fatalf("cross-handle claim winners = %d, want 1", winnerCount)
	}
	for err := range errorsCh {
		if !errors.Is(err, ErrNoDelivery) {
			t.Fatalf("cross-handle losing claim error = %v, want ErrNoDelivery", err)
		}
	}
}

func TestRecoveryMarksInjectionUncertainAndDoesNotRetry(t *testing.T) {
	path := privateTestInboxPath(t)
	first, err := Open(path)
	if err != nil {
		t.Fatalf("open first inbox: %v", err)
	}
	message := testMessage("msg-restart", "digest-restart")
	if _, _, err := first.Save(context.Background(), message); err != nil {
		t.Fatalf("save: %v", err)
	}
	claim, err := first.Claim(context.Background(), "consumer-restart")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := first.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatalf("begin injection: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first inbox: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen inbox: %v", err)
	}
	delivery, err := second.Get(context.Background(), message.MessageID)
	if err != nil {
		t.Fatalf("get after recovery: %v", err)
	}
	if delivery.State != INJECTION_UNCERTAIN {
		t.Fatalf("recovered state = %s, want INJECTION_UNCERTAIN", delivery.State)
	}
	if _, err := second.Claim(context.Background(), "consumer-after-restart"); !errors.Is(err, ErrNoDelivery) {
		t.Fatalf("uncertain delivery claim error = %v, want ErrNoDelivery", err)
	}
	if _, err := second.BeginInjection(context.Background(), claim.AttemptID); !errors.Is(err, ErrInjectionUncertain) {
		t.Fatalf("uncertain attempt begin error = %v, want ErrInjectionUncertain", err)
	}

	// A native idempotency receipt can reconcile the uncertain window without
	// invoking the runtime a second time.
	reconciled, err := second.RecordRuntimeInjected(context.Background(), receiptFrom(claim, RUNTIME_INJECTED))
	if err != nil {
		t.Fatalf("reconcile native receipt: %v", err)
	}
	if reconciled.State != RUNTIME_INJECTED {
		t.Fatalf("reconciled state = %s, want RUNTIME_INJECTED", reconciled.State)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second inbox: %v", err)
	}
}

func TestRecoveryReleasesClaimBeforeInjection(t *testing.T) {
	path := privateTestInboxPath(t)
	first, err := Open(path)
	if err != nil {
		t.Fatalf("open first inbox: %v", err)
	}
	message := testMessage("msg-claim-restart", "digest-claim-restart")
	if _, _, err := first.Save(context.Background(), message); err != nil {
		t.Fatalf("save: %v", err)
	}
	claim, err := first.Claim(context.Background(), "consumer-crashed-before-begin")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first inbox: %v", err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen inbox: %v", err)
	}
	reclaimed, err := second.Claim(context.Background(), "consumer-after-claim-crash")
	if err != nil {
		t.Fatalf("reclaim delivery: %v", err)
	}
	if reclaimed.AttemptID == claim.AttemptID {
		t.Fatalf("recovery reused abandoned attempt ID")
	}
	if _, err := second.BeginInjection(context.Background(), claim.AttemptID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("abandoned attempt begin error = %v, want ErrNotFound", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second inbox: %v", err)
	}
}

func openTestInbox(t *testing.T) *Inbox {
	t.Helper()
	path := privateTestInboxPath(t)
	inbox, err := Open(path)
	if err != nil {
		t.Fatalf("open inbox: %v", err)
	}
	t.Cleanup(func() { _ = inbox.Close() })
	return inbox
}

func privateTestInboxPath(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "node.sqlite3")
}

func testMessage(messageID, digest string) Message {
	return Message{
		MessageID:    messageID,
		Digest:       digest,
		EndpointID:   "endpoint-target",
		SessionID:    "native-session-target",
		BindingEpoch: 7,
		Payload:      []byte("sensitive test body"),
	}
}

func receiptFrom(claim *Claim, state State) Receipt {
	return Receipt{
		MessageID:    claim.MessageID,
		Digest:       claim.Digest,
		EndpointID:   claim.EndpointID,
		SessionID:    claim.SessionID,
		BindingEpoch: claim.BindingEpoch,
		AttemptID:    claim.AttemptID,
		State:        state,
	}
}

func assertState(t *testing.T, inbox *Inbox, messageID string, want State) {
	t.Helper()
	delivery, err := inbox.Get(context.Background(), messageID)
	if err != nil {
		t.Fatalf("get %s: %v", messageID, err)
	}
	if delivery.State != want {
		t.Fatalf("delivery %s state = %s, want %s", messageID, delivery.State, want)
	}
}
