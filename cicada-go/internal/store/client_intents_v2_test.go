package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestClientIntentAcceptanceIsIdempotentAndRejectsChangedInput(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	input := []byte(`{"text":"idea: compare caches","kind":"idea","goal":{"objective":""}}`)
	first, created, err := s.AcceptClientIntent("request-a", "idea: compare caches", "idea", "", nil, input)
	if err != nil || !created || first.Status != "pending" {
		t.Fatalf("first Client acceptance = %#v created=%v err=%v", first, created, err)
	}
	retry, created, err := s.AcceptClientIntent("request-a", "idea: compare caches", "idea", "", nil, input)
	if err != nil || created || retry.ID != first.ID {
		t.Fatalf("exact Client retry did not recover accepted Intent: %#v created=%v err=%v", retry, created, err)
	}
	if _, _, err := s.AcceptClientIntent("request-a", "idea: a different request", "idea", "", nil,
		[]byte(`{"text":"idea: a different request","kind":"idea"}`)); !errors.Is(err, ErrClientIntentConflict) {
		t.Fatalf("changed input reused the same request ID: %v", err)
	}
	job, err := s.GetClientIntent(first.ID)
	if err != nil || job == nil || job.State != ClientIntentQueued || string(job.Input) != string(input) {
		t.Fatalf("full input was not durably retained: %#v err=%v", job, err)
	}
}

func TestOwnerAttributedClientIntentCannotBeRetriedAcrossOwners(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	input := []byte(`{"text":"goal","owner_id":"owner_b"}`)
	intent, created, err := s.AcceptClientIntentForOwner("owner_a", "same-client-request", "goal", "goal", "", nil, input)
	if err != nil || !created || intent == nil {
		t.Fatalf("accept owner-attributed Client intent: intent=%#v created=%v err=%v", intent, created, err)
	}
	job, err := s.GetClientIntent(intent.ID)
	if err != nil || job.OwnerID != "owner_a" {
		t.Fatalf("owner was not persisted from the authenticated caller: job=%#v err=%v", job, err)
	}
	if _, created, err := s.AcceptClientIntentForOwner("owner_a", "same-client-request", "goal", "goal", "", nil, input); err != nil || created {
		t.Fatalf("same-owner retry was not idempotent: created=%v err=%v", created, err)
	}
	if _, _, err := s.AcceptClientIntentForOwner("owner_b", "same-client-request", "goal", "goal", "", nil, input); !errors.Is(err, ErrClientIntentConflict) {
		t.Fatalf("foreign owner reused another owner's Client request ID: %v", err)
	}
}

func TestClientIntentRecoveryPreservesQueuedAndFencesRunningCrashWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"text":"idea: recover me","kind":"idea"}`)
	queued, _, err := s.AcceptClientIntent("request-queued", "idea: queued", "idea", "", nil, input)
	if err != nil {
		t.Fatal(err)
	}
	startedButPending, _, err := s.AcceptClientIntent("request-running", "idea: running", "idea", "", nil, input)
	if err != nil {
		t.Fatal(err)
	}
	startedAndResolved, _, err := s.AcceptClientIntent("request-resolved", "idea: resolved", "idea", "", nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := s.ClaimClientIntent(startedButPending.ID); err != nil || !claimed {
		t.Fatalf("claim pending crash-window intent: claimed=%v err=%v", claimed, err)
	}
	if _, claimed, err := s.ClaimClientIntent(startedAndResolved.ID); err != nil || !claimed {
		t.Fatalf("claim resolved crash-window intent: claimed=%v err=%v", claimed, err)
	}
	if _, err := s.ResolveIntent(startedAndResolved.ID, "idea", "resolved", map[string]any{"type": "idea"}, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	queuedJobs, err := restarted.RecoverClientIntents()
	if err != nil || len(queuedJobs) != 1 || queuedJobs[0].IntentID != queued.ID {
		t.Fatalf("restart did not return only unstarted QUEUED work: %#v err=%v", queuedJobs, err)
	}
	for intentID, want := range map[string]string{
		queued.ID:             ClientIntentQueued,
		startedButPending.ID:  ClientIntentUncertain,
		startedAndResolved.ID: ClientIntentDone,
	} {
		got, err := restarted.GetClientIntent(intentID)
		if err != nil || got.State != want {
			t.Fatalf("recovered state for %s = %#v, want %s (err=%v)", intentID, got, want, err)
		}
	}
	if _, claimed, err := restarted.ClaimClientIntent(startedButPending.ID); err != nil || claimed {
		t.Fatalf("UNCERTAIN intent was blindly replayed: claimed=%v err=%v", claimed, err)
	}
}

func TestClientIntentClaimAllowsOnlyOneConcurrentDispatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	intent, _, err := s.AcceptClientIntent("request-concurrent", "idea: one owner", "idea", "", nil,
		[]byte(`{"text":"idea: one owner","kind":"idea"}`))
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 24
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	claimedCount := 0
	errList := make([]error, 0)
	start := make(chan struct{})
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			claimer := s
			if index%2 == 1 {
				claimer = second
			}
			_, claimed, claimErr := claimer.ClaimClientIntent(intent.ID)
			resultMu.Lock()
			defer resultMu.Unlock()
			if claimErr != nil {
				errList = append(errList, claimErr)
			}
			if claimed {
				claimedCount++
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if len(errList) != 0 || claimedCount != 1 {
		t.Fatalf("concurrent claim results: claimed=%d errors=%v", claimedCount, errList)
	}
	if err := s.CompleteClientIntent(intent.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteClientIntent(intent.ID); !errors.Is(err, ErrClientIntentState) {
		t.Fatalf("terminal Client intent was transitioned twice: %v", err)
	}
}

func TestClientIntentV19MigrationPreservesLegacyIntentRows(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	legacy, err := s.CreateIntent("legacy request remains", "idea", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptedLegacy, err := s.CreateIntent("legacy accepted Client request", "idea", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Recreate the v18 schema boundary while leaving all existing Intent rows
	// intact, then run only the additive v19 migration as an upgrade would.
	s.mu.Lock()
	_, err = s.db.Exec(`DROP TABLE client_control_intents_v2;
DELETE FROM schema_migrations_v2 WHERE version >= 19`)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.initializeClientControlIntentsV2Schema(); err != nil {
		t.Fatal(err)
	}
	stamp := now()
	if _, err := s.db.Exec(`INSERT INTO client_control_intents_v2
(client_request_id, intent_id, input_json, state, error, created_at, updated_at)
VALUES ('legacy-client-request', ?, ?, 'QUEUED', '', ?, ?)`, acceptedLegacy.ID, []byte(`{"text":"legacy request"}`), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := s.initializeV2Migrations(); err != nil {
		t.Fatalf("apply v19 migration to existing database: %v", err)
	}
	got, err := s.GetIntent(legacy.ID)
	if err != nil || got == nil || got.Text != legacy.Text || got.Status != legacy.Status {
		t.Fatalf("additive migration changed legacy Intent: before=%#v after=%#v err=%v", legacy, got, err)
	}
	entry, err := s.readV2Migration(19)
	if err != nil || entry == nil || entry.State != v2MigrationApplied {
		t.Fatalf("v19 migration ledger = %#v err=%v", entry, err)
	}
	var legacyOwner string
	if err := s.db.QueryRow(`SELECT owner_id FROM client_control_intents_v2 WHERE client_request_id='legacy-client-request'`).Scan(&legacyOwner); err != nil {
		t.Fatal(err)
	}
	if legacyOwner != "" {
		t.Fatalf("v23 inferred owner for legacy accepted Client intent: %q", legacyOwner)
	}
}
