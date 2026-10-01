package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func claimSideEffectTask(t *testing.T, s *Store, groupID, principalID, endpointID string) *SharedTask {
	t.Helper()
	task := createTask(t, s, groupID, "apply one external change")
	ready, err := s.ReadySharedTask(task.ID, task.Revision, "manager")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := claimPreparingSharedTaskFixture(t, s, task.ID, ready.Revision, principalID, endpointID, "claim-"+principalID, 300)
	if err != nil {
		t.Fatal(err)
	}
	return claimed
}

func sideEffectIntent(task *SharedTask, key, digest string) SharedTaskSideEffectIntent {
	return SharedTaskSideEffectIntent{
		TaskID: task.ID, Key: key, Digest: digest, Intent: "publish report revision 4",
		ResourceID: "workspace/kernel/write", PrincipalID: task.OwnerPrincipalID,
		EndpointID: task.OwnerEndpointID, OwnerEpoch: task.OwnerEpoch,
	}
}

func TestSharedTaskSideEffectIntentIdempotencyAndReconciliation(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := claimSideEffectTask(t, s, groupID, "principal-a", "endpoint-a")
	input := sideEffectIntent(task, "publish:report:v4", "sha256:operation-a")

	intent, err := s.RecordSharedTaskSideEffectIntent(input)
	if err != nil || intent.State != SharedTaskSideEffectIntended || intent.OwnerEpoch != task.OwnerEpoch {
		t.Fatalf("intent=%#v err=%v", intent, err)
	}
	retry := input
	retry.Intent = "different description, same operation digest"
	retry.ResourceID = "workspace/other/write"
	repeated, err := s.RecordSharedTaskSideEffectIntent(retry)
	if err != nil || repeated.ID != intent.ID || repeated.Intent != input.Intent || repeated.ResourceID != input.ResourceID {
		t.Fatalf("same-key same-digest retry changed intent: %#v err=%v", repeated, err)
	}
	conflict := input
	conflict.Digest = "sha256:different-operation"
	if _, err = s.RecordSharedTaskSideEffectIntent(conflict); !errors.Is(err, ErrSharedTaskSideEffectConflict) {
		t.Fatalf("same key with different digest was accepted: %v", err)
	}

	started, err := s.MarkSharedTaskSideEffectStarted(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch)
	if err != nil || started.State != SharedTaskSideEffectStarted || started.StartedAt == "" {
		t.Fatalf("started=%#v err=%v", started, err)
	}
	if _, err = s.MarkSharedTaskSideEffectStarted(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch); !errors.Is(err, ErrSharedTaskSideEffectAlreadyStarted) {
		t.Fatalf("repeated start was not fenced: %v", err)
	}
	uncertain, err := s.MarkSharedTaskSideEffectUncertain(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, "process exited after request write")
	if err != nil || uncertain.State != SharedTaskSideEffectUncertain || uncertain.UncertainAt == "" {
		t.Fatalf("uncertain=%#v err=%v", uncertain, err)
	}
	required, err := s.RequireSharedTaskSideEffectReconciliation(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, "remote receipt not observed")
	if err != nil || required.State != SharedTaskSideEffectReconciliationRequired || required.ReconciliationAt == "" {
		t.Fatalf("reconciliation required=%#v err=%v", required, err)
	}
	if _, err = s.ReconcileSharedTaskSideEffect(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, "UNKNOWN", "still no receipt"); !errors.Is(err, ErrSharedTaskSideEffectConflict) {
		t.Fatalf("unknown outcome incorrectly resolved: %v", err)
	}
	reconciled, err := s.ReconcileSharedTaskSideEffect(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, SharedTaskSideEffectOutcomeApplied, "receipt:remote-981")
	if err != nil || reconciled.State != SharedTaskSideEffectReconciled || reconciled.ReconciliationOutcome != SharedTaskSideEffectOutcomeApplied {
		t.Fatalf("reconciled=%#v err=%v", reconciled, err)
	}
	if _, err = s.ReconcileSharedTaskSideEffect(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, SharedTaskSideEffectOutcomeNotApplied, "contradictory evidence"); !errors.Is(err, ErrSharedTaskSideEffectConflict) {
		t.Fatalf("conflicting reconciliation overwrote evidence: %v", err)
	}
	unconfirmed, err := s.ListUnconfirmedSharedTaskSideEffects(task.ID)
	if err != nil || len(unconfirmed) != 0 {
		t.Fatalf("resolved operation remained unconfirmed: %#v err=%v", unconfirmed, err)
	}
	events, err := s.ListSharedTaskSideEffectEvents(task.ID, input.Key)
	if err != nil || len(events) != 5 {
		t.Fatalf("transition audit events=%#v err=%v", events, err)
	}
	if events[0].Kind != "INTENT_RECORDED" || events[1].Kind != "STARTED" || events[4].Kind != "RECONCILED" {
		t.Fatalf("unexpected event sequence: %#v", events)
	}
}

func TestSharedTaskSideEffectCompletionAndHandoffReconciliationView(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	oldTask := claimSideEffectTask(t, s, groupID, "principal-old-effect", "endpoint-old-effect")
	input := sideEffectIntent(oldTask, "deployment:prod:release-8", "sha256:release-8")
	if _, err := s.RecordSharedTaskSideEffectIntent(input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkSharedTaskSideEffectStarted(oldTask.ID, input.Key, input.Digest, oldTask.OwnerPrincipalID, oldTask.OwnerEndpointID, oldTask.OwnerEpoch); err != nil {
		t.Fatal(err)
	}

	proposal, err := proposePreparingSharedTaskHandoffFixture(t, s, SharedTaskHandoff{
		TaskID: oldTask.ID, GroupID: groupID, FromPrincipalID: oldTask.OwnerPrincipalID, FromEndpointID: oldTask.OwnerEndpointID,
		ToPrincipalID: "principal-new-effect", ToEndpointID: "endpoint-new-effect", FromOwnerEpoch: oldTask.OwnerEpoch,
		TaskRevision: oldTask.Revision, PendingWork: "check remote deployment receipt", WorkspaceState: "clean",
		SideEffects:     []string{"deployment request may have reached the remote service"},
		NoRepeatActions: []string{input.Key},
	})
	if err != nil {
		t.Fatal(err)
	}
	newTask, err := s.AcceptSharedTaskHandoff(proposal.ID, "principal-new-effect", "endpoint-new-effect", 300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.MarkSharedTaskSideEffectUncertain(oldTask.ID, input.Key, input.Digest, oldTask.OwnerPrincipalID, oldTask.OwnerEndpointID, oldTask.OwnerEpoch, "old owner observed timeout"); !errors.Is(err, ErrSharedTaskStaleOwner) {
		t.Fatalf("old owner changed post-handoff side-effect state: %v", err)
	}

	ledger, err := s.GetSharedTaskHandoffSideEffectLedger(proposal.ID)
	if err != nil || ledger.Handoff == nil || len(ledger.NoRepeatActions) != 1 || ledger.NoRepeatActions[0] != input.Key ||
		len(ledger.SideEffects) != 1 || len(ledger.UnconfirmedSideEffects) != 1 || ledger.UnconfirmedSideEffects[0].State != SharedTaskSideEffectStarted {
		t.Fatalf("handoff reconciliation view=%#v err=%v", ledger, err)
	}
	uncertain, err := s.MarkSharedTaskSideEffectUncertain(oldTask.ID, input.Key, input.Digest, newTask.OwnerPrincipalID, newTask.OwnerEndpointID, newTask.OwnerEpoch, "receiver cannot confirm by local receipt")
	if err != nil || uncertain.OwnerEpoch != oldTask.OwnerEpoch || uncertain.State != SharedTaskSideEffectUncertain {
		t.Fatalf("new owner uncertainty record=%#v err=%v", uncertain, err)
	}
	if _, err = s.RequireSharedTaskSideEffectReconciliation(oldTask.ID, input.Key, input.Digest, newTask.OwnerPrincipalID, newTask.OwnerEndpointID, newTask.OwnerEpoch, "query deployment service"); err != nil {
		t.Fatal(err)
	}
	completed, err := s.ReconcileSharedTaskSideEffect(oldTask.ID, input.Key, input.Digest, newTask.OwnerPrincipalID, newTask.OwnerEndpointID, newTask.OwnerEpoch, SharedTaskSideEffectOutcomeApplied, "remote:release-8:active")
	if err != nil || completed.State != SharedTaskSideEffectReconciled || completed.OwnerEpoch != oldTask.OwnerEpoch {
		t.Fatalf("new-owner reconciliation rewrote initiating epoch: %#v err=%v", completed, err)
	}
	events, err := s.ListSharedTaskSideEffectEvents(oldTask.ID, input.Key)
	if err != nil || len(events) != 5 {
		t.Fatalf("handoff events=%#v err=%v", events, err)
	}
	if events[1].OwnerEpoch != oldTask.OwnerEpoch || events[2].OwnerEpoch != newTask.OwnerEpoch || events[4].OwnerEpoch != newTask.OwnerEpoch {
		t.Fatalf("event history lost the owner epochs: %#v", events)
	}
	ledger, err = s.GetSharedTaskHandoffSideEffectLedger(proposal.ID)
	if err != nil || len(ledger.NoRepeatActions) != 1 || len(ledger.UnconfirmedSideEffects) != 0 || len(ledger.SideEffects) != 1 {
		t.Fatalf("resolved handoff ledger=%#v err=%v", ledger, err)
	}
}

func TestSharedTaskSideEffectRetryRequiresProvenNotAppliedOutcome(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	oldTask := claimSideEffectTask(t, s, groupID, "principal-prior-attempt", "endpoint-prior-attempt")
	input := sideEffectIntent(oldTask, "external:sync:item-42", "sha256:item-42")
	if _, err := s.RecordSharedTaskSideEffectIntent(input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkSharedTaskSideEffectStarted(oldTask.ID, input.Key, input.Digest, oldTask.OwnerPrincipalID, oldTask.OwnerEndpointID, oldTask.OwnerEpoch); err != nil {
		t.Fatal(err)
	}
	proposal, err := proposePreparingSharedTaskHandoffFixture(t, s, SharedTaskHandoff{
		TaskID: oldTask.ID, GroupID: groupID, FromPrincipalID: oldTask.OwnerPrincipalID, FromEndpointID: oldTask.OwnerEndpointID,
		ToPrincipalID: "principal-retry-owner", ToEndpointID: "endpoint-retry-owner", FromOwnerEpoch: oldTask.OwnerEpoch,
		TaskRevision: oldTask.Revision, PendingWork: "inspect remote state before retry", WorkspaceState: "clean",
		NoRepeatActions: []string{"do not retry until absence is verified"},
	})
	if err != nil {
		t.Fatal(err)
	}
	newTask, err := s.AcceptSharedTaskHandoff(proposal.ID, "principal-retry-owner", "endpoint-retry-owner", 300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RequireSharedTaskSideEffectReconciliation(oldTask.ID, input.Key, input.Digest, newTask.OwnerPrincipalID, newTask.OwnerEndpointID, newTask.OwnerEpoch, "look up item 42 by operation key"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReconcileSharedTaskSideEffect(oldTask.ID, input.Key, input.Digest, newTask.OwnerPrincipalID, newTask.OwnerEndpointID, newTask.OwnerEpoch, SharedTaskSideEffectOutcomeNotApplied, "remote audit: operation key absent"); err != nil {
		t.Fatal(err)
	}
	started, err := s.MarkSharedTaskSideEffectStarted(oldTask.ID, input.Key, input.Digest, newTask.OwnerPrincipalID, newTask.OwnerEndpointID, newTask.OwnerEpoch)
	if err != nil || started.State != SharedTaskSideEffectStarted || started.OwnerEpoch != newTask.OwnerEpoch {
		t.Fatalf("verified retry did not adopt the new epoch: %#v err=%v", started, err)
	}
	if _, err = s.MarkSharedTaskSideEffectStarted(oldTask.ID, input.Key, input.Digest, oldTask.OwnerPrincipalID, oldTask.OwnerEndpointID, oldTask.OwnerEpoch); !errors.Is(err, ErrSharedTaskStaleOwner) {
		t.Fatalf("stale epoch authorized retry after transfer: %v", err)
	}
	ledger, err := s.GetSharedTaskHandoffSideEffectLedger(proposal.ID)
	if err != nil || len(ledger.NoRepeatActions) != 1 || len(ledger.UnconfirmedSideEffects) != 1 || ledger.UnconfirmedSideEffects[0].OwnerEpoch != newTask.OwnerEpoch {
		t.Fatalf("retry handoff ledger=%#v err=%v", ledger, err)
	}
}

func TestSharedTaskSideEffectCompletedIsDurable(t *testing.T) {
	s, groupID := newSharedTaskTestStore(t)
	defer s.Close()
	task := claimSideEffectTask(t, s, groupID, "principal-complete", "endpoint-complete")
	input := sideEffectIntent(task, "artifact:publish:v2", "sha256:artifact-v2")
	if _, err := s.RecordSharedTaskSideEffectIntent(input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkSharedTaskSideEffectStarted(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch); err != nil {
		t.Fatal(err)
	}
	completed, err := s.CompleteSharedTaskSideEffect(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, "receipt:artifact-v2")
	if err != nil || completed.State != SharedTaskSideEffectCompleted || completed.CompletedAt == "" || completed.CompletionEvidence == "" {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	retry, err := s.CompleteSharedTaskSideEffect(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, "receipt:artifact-v2")
	if err != nil || retry.ID != completed.ID {
		t.Fatalf("completion retry=%#v err=%v", retry, err)
	}
	if _, err := s.CompleteSharedTaskSideEffect(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch, "different receipt"); !errors.Is(err, ErrSharedTaskSideEffectConflict) {
		t.Fatalf("conflicting completion evidence was accepted: %v", err)
	}
}

func TestSharedTaskSideEffectIntentSurvivesStoreRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.CreatePrincipal(Principal{Kind: PrincipalKindHuman, Name: "restart-owner", Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateGroup(Group{Name: "side-effect-restart", OwnerPrincipalID: owner.ID, State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	task := claimSideEffectTask(t, s, group.ID, "principal-restart", "endpoint-restart")
	input := sideEffectIntent(task, "connector:send:request-17", "sha256:request-17")
	if _, err = s.RecordSharedTaskSideEffectIntent(input); err != nil {
		t.Fatal(err)
	}
	if _, err = s.MarkSharedTaskSideEffectStarted(task.ID, input.Key, input.Digest, task.OwnerPrincipalID, task.OwnerEndpointID, task.OwnerEpoch); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stored, err := reopened.GetSharedTaskSideEffect(task.ID, input.Key)
	if err != nil || stored.State != SharedTaskSideEffectStarted || stored.Digest != input.Digest || stored.ResourceID != input.ResourceID {
		t.Fatalf("restart lost started side effect: %#v err=%v", stored, err)
	}
	unconfirmed, err := reopened.ListUnconfirmedSharedTaskSideEffects(task.ID)
	if err != nil || len(unconfirmed) != 1 || unconfirmed[0].ID != stored.ID {
		t.Fatalf("restart lost unresolved query: %#v err=%v", unconfirmed, err)
	}
	events, err := reopened.ListSharedTaskSideEffectEvents(task.ID, input.Key)
	if err != nil || len(events) != 2 || events[1].Kind != "STARTED" {
		t.Fatalf("restart lost ordered event history: %#v err=%v", events, err)
	}
}
