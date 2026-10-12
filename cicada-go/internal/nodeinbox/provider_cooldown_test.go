package nodeinbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func cooldownRequest(id string) ProviderAdmissionRequest {
	return ProviderAdmissionRequest{ExecutionID: id, ProviderID: "synthetic-codex",
		AdmissionIntent: providerAdmissionTestIntent(id)}
}

func cooldownTestPath(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "synthetic-provider.sqlite3")
}

func TestProviderCooldownInboxConstructorAndBoundedGrowth(t *testing.T) {
	ctx := context.Background()
	inbox, err := Open(cooldownTestPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	for i := 0; i < 10; i++ {
		request := cooldownRequest(string(rune('a' + i)))
		if _, err := inbox.db.Exec("UPDATE node_provider_cooldowns_v1 SET next_admission_at_ms=0 WHERE provider_id=?", request.ProviderID); err != nil {
			t.Fatal(err)
		}
		decision, err := inbox.AdmitProviderAttempt(ctx, request)
		if err != nil || !decision.Admitted {
			t.Fatalf("legitimate Inbox constructor failed admission: %#v %v", decision, err)
		}
		if _, err := inbox.RecordProviderAdmissionOutcome(ctx, ProviderAdmissionOutcome{
			ExecutionID: request.ExecutionID, ProviderID: request.ProviderID, Attempt: 1,
			Class: ProviderOutcomeInjectionUncertain, PostSubmissionRateLimited: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var rows, failures int
	if err := inbox.db.QueryRow("SELECT count(*),max(failures) FROM node_provider_cooldowns_v1").Scan(&rows, &failures); err != nil ||
		rows != 1 || failures != providerAdmissionMaxAttempts {
		t.Fatalf("observations produced unbounded provider metadata: rows=%d failures=%d err=%v", rows, failures, err)
	}
	next, err := inbox.AdmitProviderAttempt(ctx, cooldownRequest("synthetic-delayed"))
	if err != nil || !next.CoolingDown || next.Admitted || !next.Retryable {
		t.Fatalf("saturated observation counter lost its scheduling fence: %#v %v", next, err)
	}
}

func TestProviderCooldownDifferentExecutionPersistsWithoutReplay(t *testing.T) {
	ctx := context.Background()
	path := cooldownTestPath(t)
	first := openProviderAdmissionTestLedger(t, path)
	second := openProviderAdmissionTestLedger(t, path)
	original := cooldownRequest("synthetic-original")
	admitted, err := first.AdmitProviderAttempt(ctx, original)
	if err != nil || !admitted.Admitted {
		t.Fatalf("original admission: %v", err)
	}
	outcome := ProviderAdmissionOutcome{ExecutionID: original.ExecutionID, ProviderID: original.ProviderID,
		Attempt: admitted.Attempt, Class: ProviderOutcomeInjectionUncertain, PostSubmissionRateLimited: true}
	closed, err := first.RecordProviderAdmissionOutcome(ctx, outcome)
	if err != nil || closed.State != ProviderAdmissionInjectionUncertain || closed.Retryable {
		t.Fatalf("post-submission 429 changed original authority: %#v %v", closed, err)
	}
	var until, failures int64
	read := func() (int64, int64) {
		t.Helper()
		var deadline, count int64
		if err := first.inbox.db.QueryRow("SELECT next_admission_at_ms,failures FROM node_provider_cooldowns_v1 WHERE provider_id=?", original.ProviderID).Scan(&deadline, &count); err != nil {
			t.Fatal(err)
		}
		return deadline, count
	}
	until, failures = read()
	var wait sync.WaitGroup
	errorsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := second.RecordProviderAdmissionOutcome(ctx, outcome)
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if after, count := read(); after != until || count != failures || count != 1 {
		t.Fatal("idempotent/concurrent repeated outcome extended the cooldown")
	}
	next := cooldownRequest("synthetic-next")
	held, err := second.AdmitProviderAttempt(ctx, next)
	if err != nil || held.Admitted || !held.CoolingDown || !held.Retryable || held.Attempt != 0 || held.NextRetryAt == "" {
		t.Fatalf("different execution did not wait: %#v %v", held, err)
	}
	if _, err := second.InspectProviderAttempt(ctx, next); !errors.Is(err, ErrProviderAdmissionUnknown) {
		t.Fatalf("held execution acquired a durable attempt: %v", err)
	}
	other := cooldownRequest("synthetic-other-provider")
	other.ProviderID = "synthetic-independent-provider"
	if result, err := second.AdmitProviderAttempt(ctx, other); err != nil || !result.Admitted {
		t.Fatalf("unrelated provider was held: %#v %v", result, err)
	}
	if _, err := first.inbox.db.Exec("UPDATE node_provider_cooldowns_v1 SET next_admission_at_ms=0 WHERE provider_id=?", original.ProviderID); err != nil {
		t.Fatal(err)
	}
	// Changing only the synthetic scheduling clock must never release the old
	// execution; a genuinely distinct execution can now acquire attempt 1.
	replayed, err := second.AdmitProviderAttempt(ctx, original)
	if err != nil || replayed.Admitted || replayed.State != ProviderAdmissionInjectionUncertain {
		t.Fatalf("cooldown expiry replayed the original: %#v %v", replayed, err)
	}
	if ready, err := second.AdmitProviderAttempt(ctx, next); err != nil || !ready.Admitted || ready.Attempt != 1 {
		t.Fatalf("distinct execution remained blocked after expiry: %#v %v", ready, err)
	}
}

func TestProviderCooldownStaleAndInvalidOutcomeCannotSchedule(t *testing.T) {
	ctx := context.Background()
	ledger := openProviderAdmissionTestLedger(t, cooldownTestPath(t))
	request := cooldownRequest("synthetic-stale")
	if _, err := ledger.AdmitProviderAttempt(ctx, request); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name    string
		outcome ProviderAdmissionOutcome
	}{
		{"stale-attempt", ProviderAdmissionOutcome{ExecutionID: request.ExecutionID, ProviderID: request.ProviderID, Attempt: 2, Class: ProviderOutcomeInjectionUncertain, PostSubmissionRateLimited: true}},
		{"completed-is-not-uncertain", ProviderAdmissionOutcome{ExecutionID: request.ExecutionID, ProviderID: request.ProviderID, Attempt: 1, Class: ProviderOutcomeCompleted, PostSubmissionRateLimited: true}},
		{"negative-minimum", ProviderAdmissionOutcome{ExecutionID: request.ExecutionID, ProviderID: request.ProviderID, Attempt: 1, Class: ProviderOutcomeInjectionUncertain, PostSubmissionRateLimited: true, RetryAfter: -time.Second}},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := ledger.RecordProviderAdmissionOutcome(ctx, item.outcome); err == nil {
				t.Fatal("invalid authority changed scheduling")
			}
			var count int
			if err := ledger.inbox.db.QueryRow("SELECT count(*) FROM node_provider_cooldowns_v1").Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid event left a cooldown: count=%d err=%v", count, err)
			}
		})
	}
}

func TestProviderCooldownTrustedMinimumNeverShortened(t *testing.T) {
	for _, item := range []struct {
		name    string
		post    bool
		minimum time.Duration
		blocked bool
	}{
		{"pre-submission-finite", false, 3 * time.Second, false},
		{"pre-submission-oversized", false, providerAdmissionMaxBackoff + time.Second, true},
		{"post-submission-finite", true, 3 * time.Second, false},
		{"post-submission-oversized", true, providerAdmissionMaxBackoff + time.Second, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			ctx := context.Background()
			path := cooldownTestPath(t)
			ledger := openProviderAdmissionTestLedger(t, path)
			request := cooldownRequest("synthetic-minimum")
			if _, err := ledger.AdmitProviderAttempt(ctx, request); err != nil {
				t.Fatal(err)
			}
			class := ProviderOutcomeRateLimitedNotInjected
			if item.post {
				class = ProviderOutcomeInjectionUncertain
			}
			before := time.Now().Add(item.minimum)
			outcome := ProviderAdmissionOutcome{ExecutionID: request.ExecutionID, ProviderID: request.ProviderID,
				Attempt: 1, Class: class, RetryAfter: item.minimum, PostSubmissionRateLimited: item.post}
			decision, err := ledger.RecordProviderAdmissionOutcome(ctx, outcome)
			if err != nil {
				t.Fatal(err)
			}
			if item.post {
				reopened := openProviderAdmissionTestLedger(t, path)
				decision, err = reopened.AdmitProviderAttempt(ctx, cooldownRequest("synthetic-new"))
				if err != nil || !decision.CoolingDown || decision.Admitted {
					t.Fatalf("provider fence lost across reopen: %#v %v", decision, err)
				}
			}
			if item.blocked {
				if decision.State != ProviderAdmissionExhausted || decision.Retryable || decision.NextRetryAt != "" {
					t.Fatalf("oversized minimum was shortened: %#v", decision)
				}
			} else {
				until, err := time.Parse(time.RFC3339Nano, decision.NextRetryAt)
				if err != nil || until.Before(before) {
					t.Fatalf("trusted minimum was shortened: until=%v minimum=%v err=%v", until, before, err)
				}
			}
		})
	}
}
