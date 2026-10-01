package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func relayAdmissionAsk(id, senderPrincipal, senderGroup, receiver, receiverGroup, key, body string) FabricRequest {
	return FabricRequest{
		RequestID: id, MessageID: "message-" + id,
		SenderEndpointID: "sender-" + senderPrincipal, SenderPrincipalID: senderPrincipal,
		SenderGroupID: senderGroup, ReceiverEndpointID: receiver,
		ReceiverPrincipalID: "receiver-principal", ReceiverGroupID: receiverGroup,
		IdempotencyKey: key, Body: body,
	}
}

func onePerScopeAdmissionLimits() RelayAdmissionLimits {
	return RelayAdmissionLimits{
		PerSenderPrincipal: 100,
		PerSenderGroup:     100,
		PerReceiver:        100,
		Global:             100,
		RetryAfterSeconds:  3,
	}
}

func mustConfigureAdmission(t *testing.T, persistence *Store, limits RelayAdmissionLimits) {
	t.Helper()
	if err := persistence.ConfigureRelayAdmissionLimits(limits); err != nil {
		t.Fatal(err)
	}
}

func TestRelayAdmissionRejectsEachPendingAskScopeWithRetryAfter(t *testing.T) {
	t.Run("sender principal", func(t *testing.T) {
		persistence := newRelayV2TestStore(t)
		defer persistence.Close()
		limits := onePerScopeAdmissionLimits()
		limits.PerSenderPrincipal = 2
		mustConfigureAdmission(t, persistence, limits)
		for i := 0; i < 2; i++ {
			if _, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk(
				"principal-"+string(rune('a'+i)), "principal", "group-a", "receiver-"+string(rune('a'+i)),
				"receiver-group", "principal-key-"+string(rune('a'+i)), "question")); err != nil {
				t.Fatal(err)
			}
		}
		_, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("principal-c", "principal", "group-a", "receiver-c", "receiver-group", "principal-key-c", "question"))
		assertRelayAdmissionError(t, err, RelayAdmissionScopeSenderPrincipal, 2, 2, 3)
	})

	t.Run("sender group", func(t *testing.T) {
		persistence := newRelayV2TestStore(t)
		defer persistence.Close()
		limits := onePerScopeAdmissionLimits()
		limits.PerSenderGroup = 2
		mustConfigureAdmission(t, persistence, limits)
		for i, principal := range []string{"principal-a", "principal-b"} {
			if _, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk(
				"group-"+string(rune('a'+i)), principal, "group", "receiver-"+string(rune('a'+i)),
				"receiver-group", "group-key-"+string(rune('a'+i)), "question")); err != nil {
				t.Fatal(err)
			}
		}
		_, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("group-c", "principal-c", "group", "receiver-c", "receiver-group", "group-key-c", "question"))
		assertRelayAdmissionError(t, err, RelayAdmissionScopeSenderGroup, 2, 2, 3)
	})

	t.Run("receiver endpoint", func(t *testing.T) {
		persistence := newRelayV2TestStore(t)
		defer persistence.Close()
		limits := onePerScopeAdmissionLimits()
		limits.PerReceiver = 2
		mustConfigureAdmission(t, persistence, limits)
		for i, principal := range []string{"principal-a", "principal-b"} {
			if _, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk(
				"receiver-"+string(rune('a'+i)), principal, "group-"+string(rune('a'+i)), "receiver", "receiver-group",
				"receiver-key-"+string(rune('a'+i)), "question")); err != nil {
				t.Fatal(err)
			}
		}
		_, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("receiver-c", "principal-c", "group-c", "receiver", "receiver-group", "receiver-key-c", "question"))
		assertRelayAdmissionError(t, err, RelayAdmissionScopeReceiver, 2, 2, 3)
	})

	t.Run("global", func(t *testing.T) {
		persistence := newRelayV2TestStore(t)
		defer persistence.Close()
		limits := onePerScopeAdmissionLimits()
		limits.Global = 2
		mustConfigureAdmission(t, persistence, limits)
		for i := 0; i < 2; i++ {
			if _, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk(
				"global-"+string(rune('a'+i)), "principal-"+string(rune('a'+i)), "group-"+string(rune('a'+i)),
				"receiver-"+string(rune('a'+i)), "receiver-group-"+string(rune('a'+i)), "global-key-"+string(rune('a'+i)), "question")); err != nil {
				t.Fatal(err)
			}
		}
		_, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("global-c", "principal-c", "group-c", "receiver-c", "receiver-group-c", "global-key-c", "question"))
		assertRelayAdmissionError(t, err, RelayAdmissionScopeGlobal, 2, 2, 3)
	})
}

func assertRelayAdmissionError(t *testing.T, err error, scope string, limit, pending, retryAfterSeconds int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected RESOURCE_EXHAUSTED")
	}
	if !errors.Is(err, ErrRelayResourceExhausted) {
		t.Fatalf("error=%v does not unwrap to RESOURCE_EXHAUSTED", err)
	}
	var admission *RelayAdmissionError
	if !errors.As(err, &admission) {
		t.Fatalf("error=%v did not expose RelayAdmissionError", err)
	}
	if admission.Scope != scope || admission.Limit != limit || admission.Pending != pending {
		t.Fatalf("admission=%#v want scope=%q limit=%d pending=%d", admission, scope, limit, pending)
	}
	if admission.RetryAfterDuration().Seconds() != float64(retryAfterSeconds) || admission.RetryAfterSeconds != retryAfterSeconds {
		t.Fatalf("retry metadata=%#v want %ds", admission, retryAfterSeconds)
	}
}

func TestRelayAdmissionIdempotentRetrySucceedsAtQuota(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	mustConfigureAdmission(t, persistence, RelayAdmissionLimits{
		PerSenderPrincipal: 1, PerSenderGroup: 1, PerReceiver: 1, Global: 1, RetryAfterSeconds: 2,
	})
	firstInput := relayAdmissionAsk("request-first", "principal", "group", "receiver", "receiver-group", "same-key", "same question")
	firstInput.RequestID = ""
	first, err := createPreparingRelayRequestFixture(t, persistence, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	retry := relayAdmissionAsk("request-retry", "principal", "group", "receiver", "receiver-group", "same-key", "same question")
	retry.RequestID = ""
	second, err := createPreparingRelayRequestFixture(t, persistence, retry)
	if err != nil {
		t.Fatalf("idempotent retry was quota rejected: %v", err)
	}
	if second.RequestID != first.RequestID || second.MessageID != first.MessageID {
		t.Fatalf("retry returned a new request: first=%#v retry=%#v", first, second)
	}
	var requestCount, messageCount int
	if err := persistence.db.QueryRow(`SELECT count(*) FROM relay_v2_requests`).Scan(&requestCount); err != nil {
		t.Fatal(err)
	}
	if err := persistence.db.QueryRow(`SELECT count(*) FROM relay_v2_message_security`).Scan(&messageCount); err != nil {
		t.Fatal(err)
	}
	if requestCount != 1 || messageCount != 1 {
		t.Fatalf("idempotent retry created extra rows: requests=%d messages=%d", requestCount, messageCount)
	}
}

func TestRelayRequestIdentityKeepsExplicitIDsAndNewKeysDistinct(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	mustConfigureAdmission(t, persistence, RelayAdmissionLimits{
		PerSenderPrincipal: 10, PerSenderGroup: 10, PerReceiver: 10, Global: 10, RetryAfterSeconds: 1,
	})
	first, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk(
		"explicit-request", "principal", "group", "receiver", "receiver-group", "", "original question"))
	if err != nil {
		t.Fatal(err)
	}
	changedBody := relayAdmissionAsk(
		first.RequestID, "principal", "group", "receiver", "receiver-group", "", "changed question")
	if _, err := createPreparingRelayRequestFixture(t, persistence, changedBody); !errors.Is(err, ErrRelayMessageConflict) {
		t.Fatalf("same explicit request ID accepted changed body: %v", err)
	}
	changedTarget := relayAdmissionAsk(
		first.RequestID, "principal", "group", "other-receiver", "receiver-group", "", "original question")
	if _, err := createPreparingRelayRequestFixture(t, persistence, changedTarget); !errors.Is(err, ErrRelayMessageConflict) {
		t.Fatalf("same explicit request ID accepted changed target: %v", err)
	}

	explicitDifferentID := relayAdmissionAsk(
		"different-explicit-request", "principal", "group", "receiver", "receiver-group", "", "original question")
	explicitDifferentID.IdempotencyKey = "same-key"
	firstWithKey := relayAdmissionAsk(
		"keyed-request", "principal-keyed", "group-keyed", "receiver-keyed", "receiver-group", "same-key", "keyed question")
	if _, err := createPreparingRelayRequestFixture(t, persistence, firstWithKey); err != nil {
		t.Fatal(err)
	}
	explicitDifferentID.SenderEndpointID = firstWithKey.SenderEndpointID
	explicitDifferentID.SenderPrincipalID = firstWithKey.SenderPrincipalID
	explicitDifferentID.SenderGroupID = firstWithKey.SenderGroupID
	explicitDifferentID.ReceiverEndpointID = firstWithKey.ReceiverEndpointID
	explicitDifferentID.ReceiverGroupID = firstWithKey.ReceiverGroupID
	explicitDifferentID.Body = firstWithKey.Body
	explicitDifferentID.Digest = firstWithKey.Digest
	if _, err := createPreparingRelayRequestFixture(t, persistence, explicitDifferentID); !errors.Is(err, ErrRelayIdempotencyConflict) {
		t.Fatalf("caller-provided different request ID reused idempotency key: %v", err)
	}

	newKey := relayAdmissionAsk(
		"new-key-request", "principal-keyed", "group-keyed", "receiver-keyed", "receiver-group", "new-key", "new question")
	if _, err := createPreparingRelayRequestFixture(t, persistence, newKey); err != nil {
		t.Fatalf("new key with changed question was rejected: %v", err)
	}
}

func TestRelayReplyAndCancellationProgressWhenAskQuotaIsFull(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	mustConfigureAdmission(t, persistence, RelayAdmissionLimits{
		PerSenderPrincipal: 1, PerSenderGroup: 1, PerReceiver: 1, Global: 1, RetryAfterSeconds: 1,
	})
	first, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("request-reply", "principal", "group", "receiver", "receiver-group", "reply-key", "question"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.SubmitFabricReply(FabricReply{
		RequestID: first.RequestID, ResponderEndpointID: first.ReceiverEndpointID,
		ResponderPrincipalID: first.ReceiverPrincipalID, ResponderGroupID: first.ReceiverGroupID,
		Body: "answer",
	}); err != nil {
		t.Fatalf("reply was starved by full Ask quota: %v", err)
	}
	second, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("request-after-reply", "principal", "group", "receiver", "receiver-group", "reply-key-2", "question"))
	if err != nil {
		t.Fatalf("quota was not released after reply: %v", err)
	}
	if _, err := persistence.SubmitFabricReply(FabricReply{
		RequestID: second.RequestID, ResponderEndpointID: second.ReceiverEndpointID,
		ResponderPrincipalID: second.ReceiverPrincipalID, ResponderGroupID: second.ReceiverGroupID,
		Body: "second answer",
	}); err != nil {
		t.Fatal(err)
	}

	cancelled, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("request-cancel", "principal-2", "group-2", "receiver-2", "receiver-group-2", "cancel-key", "question"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RequestFabricRequestCancellation(cancelled.RequestID, "stop"); err != nil {
		t.Fatalf("cancellation request was starved by full Ask quota: %v", err)
	}
	if _, err := persistence.CancelFabricRequest(cancelled.RequestID, "stopped"); err != nil {
		t.Fatal(err)
	}
	if _, err := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk("request-after-cancel", "principal-2", "group-2", "receiver-2", "receiver-group-2", "cancel-key-2", "question")); err != nil {
		t.Fatalf("quota was not released after cancellation: %v", err)
	}
}

func TestRelayAdmissionSerializesIndependentStoreHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	first, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	mustConfigureAdmission(t, first, RelayAdmissionLimits{
		PerSenderPrincipal: 10, PerSenderGroup: 10, PerReceiver: 10, Global: 1, RetryAfterSeconds: 1,
	})

	stores := []*Store{first, second}
	errs := make(chan error, len(stores))
	var wait sync.WaitGroup
	wait.Add(len(stores))
	for i, persistence := range stores {
		go func(index int, persistence *Store) {
			defer wait.Done()
			_, createErr := createPreparingRelayRequestFixture(t, persistence, relayAdmissionAsk(
				"concurrent-"+string(rune('a'+index)), "principal-"+string(rune('a'+index)),
				"group-"+string(rune('a'+index)), "receiver-"+string(rune('a'+index)),
				"receiver-group-"+string(rune('a'+index)), "concurrent-key-"+string(rune('a'+index)), "question"))
			errs <- createErr
		}(i, persistence)
	}
	wait.Wait()
	close(errs)
	accepted, rejected := 0, 0
	for createErr := range errs {
		if createErr == nil {
			accepted++
			continue
		}
		if errors.Is(createErr, ErrRelayResourceExhausted) {
			rejected++
			continue
		}
		t.Fatalf("unexpected concurrent admission error: %v", createErr)
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent quota was not atomic: accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestRelayAdmissionBoundsMutualAskWaitsBySenderSession(t *testing.T) {
	persistence := newRelayV2TestStore(t)
	defer persistence.Close()
	mustConfigureAdmission(t, persistence, RelayAdmissionLimits{
		PerSenderPrincipal: 100, PerSenderGroup: 100, PerReceiver: 100,
		Global: 1000, RetryAfterSeconds: 2,
	})
	deadline := time.Now().UTC().Add(DefaultRelayAskLifetime).Format(time.RFC3339Nano)
	for i := 0; i < DefaultRelayPendingAsksPerSenderEndpoint; i++ {
		askA := relayAdmissionAsk(fmt.Sprintf("cycle-a-%02d", i), "principal-a", "group-a",
			"endpoint-b", "group-b", fmt.Sprintf("cycle-a-key-%02d", i), "synthetic A waits for B")
		askA.SenderEndpointID = "session-a"
		askA.ExpiresAt = deadline
		if _, err := createPreparingRelayRequestFixture(t, persistence, askA); err != nil {
			t.Fatalf("A->B ask %d rejected before its session budget: %v", i, err)
		}
		askB := relayAdmissionAsk(fmt.Sprintf("cycle-b-%02d", i), "principal-b", "group-b",
			"endpoint-a", "group-a", fmt.Sprintf("cycle-b-key-%02d", i), "synthetic B waits for A")
		askB.SenderEndpointID = "session-b"
		askB.ExpiresAt = deadline
		if _, err := createPreparingRelayRequestFixture(t, persistence, askB); err != nil {
			t.Fatalf("B->A ask %d rejected before its session budget: %v", i, err)
		}
	}

	for _, test := range []struct {
		id, principal, group, receiver, receiverGroup, key string
	}{
		{"cycle-a-over", "principal-a", "group-a", "endpoint-b", "group-b", "cycle-a-over-key"},
		{"cycle-b-over", "principal-b", "group-b", "endpoint-a", "group-a", "cycle-b-over-key"},
	} {
		ask := relayAdmissionAsk(test.id, test.principal, test.group, test.receiver,
			test.receiverGroup, test.key, "synthetic repeated wait")
		ask.SenderEndpointID = "session-" + test.principal[len("principal-"):]
		ask.ExpiresAt = deadline
		_, err := createPreparingRelayRequestFixture(t, persistence, ask)
		assertRelayAdmissionError(t, err, RelayAdmissionScopeSenderEndpoint,
			DefaultRelayPendingAsksPerSenderEndpoint, DefaultRelayPendingAsksPerSenderEndpoint, 2)
	}

	if _, err := persistence.db.Exec(`UPDATE relay_v2_requests SET expires_at=? WHERE request_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), "cycle-a-00"); err != nil {
		t.Fatal(err)
	}
	freed := relayAdmissionAsk("cycle-a-after-expiry", "principal-a", "group-a", "endpoint-b",
		"group-b", "cycle-a-after-expiry-key", "synthetic A retries after expiry")
	freed.SenderEndpointID = "session-a"
	freed.ExpiresAt = time.Now().UTC().Add(DefaultRelayAskLifetime).Format(time.RFC3339Nano)
	if _, err := createPreparingRelayRequestFixture(t, persistence, freed); err != nil {
		t.Fatalf("expired pending Ask kept its sender session budget: %v", err)
	}
}

func TestRelayAdmissionMigrationV4ToV5InstallsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	persistence, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.db.Exec(`DROP TABLE relay_v2_admission_config; DROP TABLE relay_v2_admission_guard;
DELETE FROM schema_migrations_v2 WHERE version = 5`); err != nil {
		persistence.Close()
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	limits, err := reopened.GetRelayAdmissionLimits()
	if err != nil {
		t.Fatal(err)
	}
	if limits != DefaultRelayAdmissionLimits() {
		t.Fatalf("migration did not restore defaults: got=%#v want=%#v", limits, DefaultRelayAdmissionLimits())
	}
	var state string
	if err := reopened.db.QueryRow(`SELECT state FROM schema_migrations_v2 WHERE version = 5`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != v2MigrationApplied {
		t.Fatalf("admission migration state=%q", state)
	}
}
