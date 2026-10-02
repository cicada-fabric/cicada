package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSharedTaskPeerPlaintextDenialPreservesTaskResultsAndEvents(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	task := sealedTaskHandoffTask(t, f, source)
	snapshot := func() string {
		t.Helper()
		var resultCount, eventCount int
		var touched string
		if err := f.store.db.QueryRow(`SELECT COUNT(*) FROM shared_task_v2_results`).Scan(&resultCount); err != nil {
			t.Fatal(err)
		}
		if err := f.store.db.QueryRow(`SELECT COUNT(*) FROM shared_task_v2_events`).Scan(&eventCount); err != nil {
			t.Fatal(err)
		}
		if err := f.store.db.QueryRow(`SELECT touched_at FROM shared_task_v2_guard WHERE id=1`).Scan(&touched); err != nil {
			t.Fatal(err)
		}
		current, err := f.store.GetSharedTask(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal([]any{current, resultCount, eventCount, touched})
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	before := snapshot()
	for _, epoch := range []int64{task.OwnerEpoch, task.OwnerEpoch - 1} {
		result, err := f.store.SubmitSharedTaskResultForActor(source, task.ID, epoch,
			task.Revision, "synthetic private peer summary", []string{"synthetic evidence"})
		want := ErrSharedTaskPeerPlaintext
		if epoch != task.OwnerEpoch {
			want = ErrSharedTaskStaleOwner
		}
		if result != nil || !errors.Is(err, want) {
			t.Fatalf("plaintext denial: result=%#v err=%v", result, err)
		}
		if after := snapshot(); after != before {
			t.Fatal("rejected plaintext changed Task/result/event/guard state")
		}
	}
	encoded, err := json.Marshal(ProjectSharedTaskPeer(task))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{task.Objective, task.AcceptanceCriteria, "objective", "acceptance_criteria", "summary", "evidence", "claim_key"} {
		if strings.Contains(string(encoded), value) {
			t.Fatalf("peer projection exposes %q", value)
		}
	}
}

func privacyVerifier(t *testing.T, f *sameGroupSealedV1Fixture, networkID string) NativeActorScope {
	t.Helper()
	actor := sealedTaskHandoffActor(t, f, networkID, f.target, true)
	member, err := f.store.GetMembershipByPrincipalGroup(actor.PrincipalID, actor.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	member, err = f.store.UpdateMembershipAuthorization(member.ID, member.Roles, append(member.Grants, "task.verify"), member.Authorization, member.Version)
	if err != nil {
		t.Fatal(err)
	}
	f.grant(t, f.target.id)
	actor.MembershipRevision = member.Revision
	return actor
}
func privacySend(t *testing.T, f *sameGroupSealedV1Fixture, sender, reader sameGroupSealedV1EndpointFixture, credential, body string) *RelaySealedV1Record {
	t.Helper()
	id := NewID("privacy_send")
	_, pair := f.peer(t, sender, reader, credential)
	wire, err := e2ee.SealEndpointMessage(sender.identity, reader.identity.Public(), sameGroupSealedV1Context(pair, id, "SEND", "", ""), []byte(body), 1)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{NodeCredentialDigest: credential, GroupID: f.groupID, SourceEndpointID: sender.id, TargetEndpointID: reader.id, MessageID: id, IdempotencyKey: id, DataScope: SameGroupSealedV1DataScope, Ciphertext: wire})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
func privacyState(t *testing.T, s *Store, taskID string) string {
	t.Helper()
	task, err := s.GetSharedTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	var results, events, refs int
	var touched string
	for _, item := range []struct {
		table string
		count *int
	}{{"shared_task_v2_results", &results}, {"shared_task_v2_events", &events}, {"shared_task_peer_refs_v57", &refs}} {
		if err = s.db.QueryRow("SELECT COUNT(*) FROM " + item.table).Scan(item.count); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.db.QueryRow(`SELECT touched_at FROM shared_task_v2_guard WHERE id=1`).Scan(&touched); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal([]any{task, results, events, refs, touched})
	return string(encoded)
}
func TestSharedTaskPeerSealedReferenceLifecycleAndImmutableRetry(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	worker := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	verifier := privacyVerifier(t, f, networkID)
	task, err := f.store.CreateSharedTaskPeerShell(f.groupID, "synthetic-manager-bearer", SharedTaskPeerShellInput{PublisherEndpointID: f.target.id, ResultRecipientEndpointID: f.target.id})
	if err != nil {
		t.Fatal(err)
	}
	if task.Objective != "" || task.AcceptanceCriteria != "" {
		t.Fatal("metadata shell contains prose")
	}
	body := "synthetic private definition sentinel"
	record := privacySend(t, f, f.target, f.source, f.targetNode.nodeCredential, body)
	before := privacyState(t, f.store, task.ID)
	// A generic sealed SEND has normal peer delivery only, no Task ref/result/CAS.
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.sourceNode.nodeCredential, sameGroupSealedV1ClaimInput(f.source, "consumer_privacy_candidate"))
	if err != nil || len(claims) != 1 {
		t.Fatalf("candidate ordinary SEND unavailable: %d %v", len(claims), err)
	}
	if privacyState(t, f.store, task.ID) != before {
		t.Fatal("candidate delivery changed Task business authority")
	}
	input := SharedTaskSealedRefInput{TaskID: task.ID, Purpose: SharedTaskDefinitionPurpose, AssignmentVersion: 1, ContentVersion: 1, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch, MessageID: record.Route.MessageID, MessageDigest: record.Security.Digest}
	ref, err := f.store.RegisterSharedTaskSealedRefForActor(verifier, input)
	if err != nil || ref.ReaderEndpointID != worker.EndpointID {
		t.Fatalf("register definition: %+v %v", ref, err)
	}
	view, err := f.store.GetSharedTaskPeerForActor(worker, task.ID, "task.read")
	if err != nil || view.DefinitionStatus != "REGISTERED" || len(view.DefinitionRefs) != 1 {
		t.Fatalf("authorized definition: %+v %v", view, err)
	}
	view, err = f.store.GetSharedTaskPeerForActor(verifier, task.ID, "task.read")
	if err != nil || len(view.DefinitionRefs) != 0 {
		t.Fatalf("definition leaked to nonreader: %+v %v", view, err)
	}
	frozen := privacyState(t, f.store, task.ID)
	retry, err := f.store.RegisterSharedTaskSealedRefForActor(verifier, input)
	if err != nil || !reflect.DeepEqual(retry, ref) || privacyState(t, f.store, task.ID) != frozen {
		t.Fatalf("immutable definition retry changed state: %v", err)
	}
	other := privacySend(t, f, f.target, f.source, f.targetNode.nodeCredential, "different encrypted definition")
	transplant := input
	transplant.MessageID = other.Route.MessageID
	transplant.MessageDigest = other.Security.Digest
	if _, err = f.store.RegisterSharedTaskSealedRefForActor(verifier, transplant); err == nil || privacyState(t, f.store, task.ID) != frozen {
		t.Fatal("same content version replaced definition")
	}
	for _, change := range []func(*SharedTaskSealedRefInput){func(i *SharedTaskSealedRefInput) { i.Purpose = SharedTaskResultPurpose }, func(i *SharedTaskSealedRefInput) { i.ContentVersion++ }, func(i *SharedTaskSealedRefInput) { i.AssignmentVersion++ }, func(i *SharedTaskSealedRefInput) { i.OwnerEpoch++ }, func(i *SharedTaskSealedRefInput) { i.ExpectedRevision++ }, func(i *SharedTaskSealedRefInput) { i.MessageDigest = strings.Repeat("0", 64) }} {
		bad := input
		change(&bad)
		if _, err = f.store.RegisterSharedTaskSealedRefForActor(verifier, bad); err == nil || privacyState(t, f.store, task.ID) != frozen {
			t.Fatal("reference transplant changed Task state")
		}
	}
	task, err = f.store.ReadySharedTask(task.ID, task.Revision, "synthetic-manager-bearer")
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ClaimSharedTaskForActor(worker, task.ID, task.Revision, "privacy-owner", 600)
	if err != nil {
		t.Fatal(err)
	}
	artifact := createHandoffArtifactRef(t, f, NewID("artifact"), NewID("ref"), strings.Repeat("b", 64))
	evidence := []SharedTaskArtifactRef{{ArtifactRefID: artifact.ID, Version: artifact.Version, Digest: artifact.Digest, Scopes: []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeDigest}}}
	resultRecord := privacySend(t, f, f.source, f.target, f.sourceNode.nodeCredential, "synthetic private result sentinel")
	frozen = privacyState(t, f.store, task.ID)
	resultInput := SharedTaskSealedRefInput{TaskID: task.ID, Purpose: SharedTaskResultPurpose, AssignmentVersion: 1, ContentVersion: 1, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch, MessageID: resultRecord.Route.MessageID, MessageDigest: resultRecord.Security.Digest, ArtifactRefs: evidence}
	stale := resultInput
	stale.OwnerEpoch--
	if _, err = f.store.RegisterSharedTaskSealedRefForActor(worker, stale); err == nil || privacyState(t, f.store, task.ID) != frozen {
		t.Fatal("stale sealed result created a candidate or changed CAS")
	}
	result, err := f.store.RegisterSharedTaskSealedRefForActor(worker, resultInput)
	if err != nil || result.ResultID == "" {
		t.Fatalf("register result: %+v %v", result, err)
	}
	current, err := f.store.GetSharedTask(task.ID)
	if err != nil || current.Status != SharedTaskResultSubmitted || current.Revision != task.Revision+1 {
		t.Fatalf("result CAS: %+v %v", current, err)
	}
	frozen = privacyState(t, f.store, task.ID)
	again, err := f.store.RegisterSharedTaskSealedRefForActor(worker, resultInput)
	if err != nil || !reflect.DeepEqual(result, again) || privacyState(t, f.store, task.ID) != frozen {
		t.Fatalf("lost registration reply retry changed authority: %v", err)
	}
	var summary, evidenceJSON string
	if err = f.store.db.QueryRow(`SELECT summary,evidence_json FROM shared_task_v2_results WHERE id=?`, result.ResultID).Scan(&summary, &evidenceJSON); err != nil || summary != "" || evidenceJSON != "[]" {
		t.Fatal("sealed result persisted plaintext")
	}
	completed, err := f.store.AcceptSharedTaskResultForActor(task.ID, result.ResultID, current.Revision, verifier)
	if err != nil || completed.Status != SharedTaskCompleted {
		t.Fatalf("accept current registered result: %+v %v", completed, err)
	}
	// Neither message ciphertext nor peer DTO contains the new private sentinel.
	projection, _ := json.Marshal(view)
	if strings.Contains(string(resultRecord.Ciphertext), "synthetic private result sentinel") || strings.Contains(string(record.Ciphertext), body) || strings.Contains(string(projection), body) {
		t.Fatal("private Task body crossed Hub projection")
	}
}

func TestSharedTaskPeerSealedReferenceCurrentRevocationIsFailClosed(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	worker := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	verifier := privacyVerifier(t, f, networkID)
	task, err := f.store.CreateSharedTaskPeerShell(f.groupID, "synthetic-manager-bearer", SharedTaskPeerShellInput{PublisherEndpointID: f.target.id, ResultRecipientEndpointID: f.target.id})
	if err != nil {
		t.Fatal(err)
	}
	record := privacySend(t, f, f.target, f.source, f.targetNode.nodeCredential, "synthetic private definition")
	input := SharedTaskSealedRefInput{TaskID: task.ID, Purpose: SharedTaskDefinitionPurpose, AssignmentVersion: 1, ContentVersion: 1, ExpectedRevision: 1, OwnerEpoch: 0, MessageID: record.Route.MessageID, MessageDigest: record.Security.Digest}
	if _, err = f.store.RegisterSharedTaskSealedRefForActor(verifier, input); err != nil {
		t.Fatal(err)
	}
	before := privacyState(t, f.store, task.ID)
	revokeSealedFixtureNetwork(t, f, networkID)
	if _, err = f.store.RegisterSharedTaskSealedRefForActor(verifier, input); err == nil {
		t.Fatal("revoked current assignment revived reference")
	}
	view, readErr := f.store.GetSharedTaskPeerForActor(worker, task.ID, "task.read")
	if readErr != nil || view.DefinitionStatus == "REGISTERED" || len(view.DefinitionRefs) != 0 || view.Assignment != nil {
		t.Fatal("revoked publisher retained a current definition")
	}
	if _, err = f.store.GetSharedTaskPeerForActor(verifier, task.ID, "task.read"); err == nil {
		t.Fatal("revoked actor read Task metadata")
	}
	if privacyState(t, f.store, task.ID) != before {
		t.Fatal("revoked reference changed Task business state")
	}
	rejoinSealedFixtureNetwork(t, f, networkID)
	if _, err = f.store.RegisterSharedTaskSealedRefForActor(verifier, input); err == nil {
		t.Fatal("rejoin revived old enrolled ciphertext reference")
	}
	if privacyState(t, f.store, task.ID) != before {
		t.Fatal("rejoin failure changed Task authority")
	}
}

func preparePrivacyPendingResult(t *testing.T) (*sameGroupSealedV1Fixture, NativeActorScope, NativeActorScope, *SharedTask, *SharedTaskSealedRef) {
	t.Helper()
	f, networkID := mappedSealedFixture(t)
	worker := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	verifier := privacyVerifier(t, f, networkID)
	task, err := f.store.CreateSharedTaskPeerShell(f.groupID, "synthetic-manager-bearer", SharedTaskPeerShellInput{PublisherEndpointID: f.target.id, ResultRecipientEndpointID: f.target.id})
	if err != nil {
		t.Fatal(err)
	}
	definition := privacySend(t, f, f.target, f.source, f.targetNode.nodeCredential, "synthetic private definition")
	if _, err = f.store.RegisterSharedTaskSealedRefForActor(verifier, SharedTaskSealedRefInput{TaskID: task.ID, Purpose: SharedTaskDefinitionPurpose, AssignmentVersion: 1, ContentVersion: 1, ExpectedRevision: 1, OwnerEpoch: 0, MessageID: definition.Route.MessageID, MessageDigest: definition.Security.Digest}); err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ReadySharedTask(task.ID, 1, "synthetic-manager-bearer")
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ClaimSharedTaskForActor(worker, task.ID, task.Revision, "privacy-claim", 600)
	if err != nil {
		t.Fatal(err)
	}
	artifact := createHandoffArtifactRef(t, f, NewID("artifact"), NewID("ref"), strings.Repeat("b", 64))
	record := privacySend(t, f, f.source, f.target, f.sourceNode.nodeCredential, "synthetic private result")
	ref, err := f.store.RegisterSharedTaskSealedRefForActor(worker, SharedTaskSealedRefInput{TaskID: task.ID, Purpose: SharedTaskResultPurpose, AssignmentVersion: 1, ContentVersion: 1, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch, MessageID: record.Route.MessageID, MessageDigest: record.Security.Digest, ArtifactRefs: []SharedTaskArtifactRef{{ArtifactRefID: artifact.ID, Version: artifact.Version, Digest: artifact.Digest, Scopes: []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeDigest}}}})
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f, worker, verifier, task, ref
}
func TestSharedTaskPeerAcceptanceRepeatsCurrentAssignmentRouteAndArtifactGuard(t *testing.T) {
	for _, fault := range []string{"source-submit-revoked", "artifact-read-revoked", "artifact-latest-version", "assignment-replaced", "owner-key-revoked", "stale-owner-epoch", "wrong-authorized-recipient"} {
		t.Run(fault, func(t *testing.T) {
			f, worker, verifier, task, ref := preparePrivacyPendingResult(t)
			scope := verifier
			switch fault {
			case "source-submit-revoked", "artifact-read-revoked":
				membership, err := f.store.GetMembershipByPrincipalGroup(worker.PrincipalID, f.groupID)
				if err != nil {
					t.Fatal(err)
				}
				denied := "task.submit"
				if fault == "artifact-read-revoked" {
					denied = "artifact.read"
				}
				grants := []string{}
				for _, grant := range membership.Grants {
					if grant != denied {
						grants = append(grants, grant)
					}
				}
				if _, err = f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, grants, membership.Authorization, membership.Version); err != nil {
					t.Fatal(err)
				}
				f.grant(t, worker.EndpointID)
			case "artifact-latest-version":
				old, err := f.store.GetArtifactRefV2(ref.ArtifactRefs[0].ArtifactRefID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.store.CreateArtifactRefV2(ArtifactRefV2Input{ID: NewID("ref"), ArtifactID: old.ArtifactID, GroupID: f.groupID, Digest: strings.Repeat("c", 64), Scopes: old.Scopes}); err != nil {
					t.Fatal(err)
				}
			case "assignment-replaced":
				if _, err := f.store.AssignSharedTaskPeerBody(f.groupID, task.ID, "synthetic-manager-bearer", SharedTaskPeerAssignmentInput{ExpectedRevision: task.Revision, ExpectedAssignmentVersion: 1, PublisherEndpointID: f.target.id, ResultRecipientEndpointID: f.target.id}); err != nil {
					t.Fatal(err)
				}
			case "owner-key-revoked":
				key, err := f.store.GetOwnerApprovalKey(f.ownerID, f.ownerKeyID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.store.RevokeOwnerApprovalKeyLocal(f.ownerID, f.ownerKeyID, key.Version); err != nil {
					t.Fatal(err)
				}
			case "stale-owner-epoch":
				// Isolated negative fixture corruption never resets or repairs the
				// original responsibility epoch to make an old result authoritative.
				if _, err := f.store.db.Exec(`UPDATE shared_tasks_v2 SET owner_epoch=owner_epoch+1 WHERE id=?`, task.ID); err != nil {
					t.Fatal(err)
				}
			case "wrong-authorized-recipient":
				third := sealedTaskHandoffActor(t, f, worker.NetworkID, f.sameNode, true)
				membership, err := f.store.GetMembershipByPrincipalGroup(third.PrincipalID, f.groupID)
				if err != nil {
					t.Fatal(err)
				}
				membership, err = f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles, append(membership.Grants, "task.verify"), membership.Authorization, membership.Version)
				if err != nil {
					t.Fatal(err)
				}
				f.grant(t, f.sameNode.id)
				third.MembershipRevision = membership.Revision
				scope = third
			}
			before := privacyState(t, f.store, task.ID)
			if _, err := f.store.AcceptSharedTaskResultForActor(task.ID, ref.ResultID, task.Revision, scope); err == nil {
				t.Fatal("changed authority accepted registered result")
			}
			if after := privacyState(t, f.store, task.ID); before != after {
				t.Fatal("failed acceptance changed Task/result/event/guard")
			}
		})
	}
}
func TestSharedTaskPeerLegacyManagementResultCannotAcquirePeerAuthority(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	worker := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	verifier := privacyVerifier(t, f, networkID)
	task := sealedTaskHandoffTask(t, f, worker)
	result, err := f.store.SubmitSharedTaskResult(task.ID, worker.PrincipalID, worker.EndpointID, task.OwnerEpoch, task.Revision, "synthetic legal management history", []string{"synthetic management evidence"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.GetSharedTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := privacyState(t, f.store, task.ID)
	if _, err = f.store.AcceptSharedTaskResultForActor(task.ID, result.ID, task.Revision, verifier); err == nil || privacyState(t, f.store, task.ID) != before {
		t.Fatal("unclassified legacy result acquired peer authority")
	}
	view, err := f.store.GetSharedTaskPeerForActor(verifier, task.ID, "task.read")
	if err != nil || view.DefinitionStatus != "MANAGEMENT_ONLY" || len(view.ResultRefs) != 0 {
		t.Fatal("legacy result was guessed safely sealed")
	}
	rows, err := f.store.ListSharedTaskResults(f.groupID, 100)
	if err != nil || len(rows) != 1 || rows[0].Summary != "synthetic legal management history" {
		t.Fatal("legacy management history was rewritten")
	}
}
func TestSharedTaskPeerMigration57InterruptionRetains56AndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("synthetic v57 interruption")
	failed, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.task.peer_sealed_references" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatal("v57 interruption was not reported", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var before56 string
	if err = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'shared_task_peer_%v57'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("interrupted v57 left schema objects")
	}
	if err = db.QueryRow(`SELECT checksum FROM schema_migrations_v2 WHERE version=56 AND state='applied'`).Scan(&before56); err != nil {
		t.Fatal("v56 changed or was missing", err)
	}
	db.Close()
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	assertLegacyStatePreserved(t, reopened)
	entry, err := reopened.readV2Migration(57)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatal("v57 retry ledger incorrect", err)
	}
	entry56, err := reopened.readV2Migration(56)
	if err != nil || entry56.Checksum != before56 || entry56.Attempts != 1 {
		t.Fatal("v57 changed v56")
	}
	reopened.Close()
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	assertLegacyStatePreserved(t, restarted)
	entry, err = restarted.readV2Migration(57)
	if err != nil || entry.Attempts != 2 {
		t.Fatal("repeat open reapplied v57")
	}
	entry56, err = restarted.readV2Migration(56)
	if err != nil || entry56.Checksum != before56 || entry56.Attempts != 1 {
		t.Fatal("repeat open changed v56")
	}
}

func TestSharedTaskPeerActual55UpgradePreservesManagementTaskResultAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	halted := errors.New("synthetic stop at applied schema55")
	_, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.node.tls_authority" && phase == "before_apply" {
			return halted
		}
		return nil
	})
	if !errors.Is(err, halted) {
		t.Fatal("could not create actual applied55 ledger", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	old := &Store{db: db}
	var applied int
	if err = db.QueryRow(`SELECT max(version) FROM schema_migrations_v2 WHERE state='applied'`).Scan(&applied); err != nil || applied != 55 {
		t.Fatal("fixture is not an applied55 schema")
	}
	owner, err := old.CreatePrincipal(Principal{Kind: PrincipalKindHuman, Name: "synthetic upgrade owner", Status: PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := old.CreateGroup(Group{Name: "synthetic upgrade group", OwnerPrincipalID: owner.ID, State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	preparingNetworkActorFixture(t, old, group.ID, "synthetic-upgrade-worker", "synthetic-upgrade-endpoint")
	task, err := old.CreateSharedTask(SharedTask{GroupID: group.ID, Objective: "synthetic legacy management objective", AcceptanceCriteria: "synthetic legacy management criteria"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = old.ReadySharedTask(task.ID, task.Revision, "synthetic-manager")
	if err != nil {
		t.Fatal(err)
	}
	task, err = old.ClaimSharedTask(task.ID, task.Revision, "synthetic-upgrade-worker", "synthetic-upgrade-endpoint", "synthetic-claim", 600)
	if err != nil {
		t.Fatal(err)
	}
	result, err := old.SubmitSharedTaskResult(task.ID, "synthetic-upgrade-worker", "synthetic-upgrade-endpoint", task.OwnerEpoch, task.Revision, "synthetic legacy management summary", []string{"synthetic management evidence"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func(s *Store) string {
		t.Helper()
		task, err := s.GetSharedTask(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		results, err := s.ListSharedTaskResults(group.ID, 100)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := s.db.Query(`SELECT id,task_id,kind,actor_principal_id,owner_epoch,revision,data_json,created_at FROM shared_task_v2_events WHERE task_id=? ORDER BY id`, task.ID)
		if err != nil {
			t.Fatal(err)
		}
		events := []any{}
		for rows.Next() {
			var id, taskID, kind, actor, data, stamp string
			var epoch, revision int64
			if err = rows.Scan(&id, &taskID, &kind, &actor, &epoch, &revision, &data, &stamp); err != nil {
				t.Fatal(err)
			}
			events = append(events, []any{id, taskID, kind, actor, epoch, revision, data, stamp})
		}
		rows.Close()
		encoded, _ := json.Marshal([]any{task, results, events})
		return string(encoded)
	}
	baseline := snapshot(old)
	if result.Summary == "" {
		t.Fatal("management fixture missing summary")
	}
	old.Close()
	interrupted := errors.New("synthetic v57 interrupted upgrade")
	_, err = openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.task.peer_sealed_references" && phase == "after_apply" {
			return interrupted
		}
		return nil
	})
	if !errors.Is(err, interrupted) {
		t.Fatal("55 to57 interrupted upgrade was not reported", err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	checking := &Store{db: check}
	if snapshot(checking) != baseline {
		t.Fatal("interrupted upgrade changed management rows/history")
	}
	entry56, err := checking.readV2Migration(56)
	if err != nil || entry56.State != v2MigrationApplied {
		t.Fatal("56 did not remain committed before failed57", err)
	}
	before56 := *entry56
	var objects int
	if err = check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'shared_task_peer_%v57'`).Scan(&objects); err != nil || objects != 0 {
		t.Fatal("failed57 left partial sidecars")
	}
	checking.Close()
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot(reopened) != baseline {
		t.Fatal("55 to57 reopen changed management prose/history/epochs")
	}
	after56, err := reopened.readV2Migration(56)
	if err != nil || !reflect.DeepEqual(before56, *after56) {
		t.Fatal("privacy migration rewrote D1 ledger56")
	}
	entry57, err := reopened.readV2Migration(57)
	if err != nil || entry57.State != v2MigrationApplied || entry57.Attempts != 2 {
		t.Fatal("privacy upgrade retry/checksum incorrect", err)
	}
	reopened.Close()
	repeat, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repeat.Close()
	if snapshot(repeat) != baseline {
		t.Fatal("repeat open changed management rows/history")
	}
	after56, err = repeat.readV2Migration(56)
	if err != nil || !reflect.DeepEqual(before56, *after56) {
		t.Fatal("repeat open changed D1 ledger56")
	}
}
