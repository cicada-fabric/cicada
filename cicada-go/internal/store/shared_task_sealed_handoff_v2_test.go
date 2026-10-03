package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sealedTaskHandoffActor(t *testing.T, f *sameGroupSealedV1Fixture,
	networkID string, endpoint sameGroupSealedV1EndpointFixture, artifactRead bool) NativeActorScope {
	t.Helper()
	membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.principal, f.groupID)
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{"task.read", "task.claim", "task.submit"}
	if artifactRead {
		grants = append(grants, "artifact.read")
	}
	membership, err = f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles,
		grants, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	// Membership revision is part of the endpoint key-grant proof. Refresh the
	// synthetic proof after changing the Task grants used by this Actor.
	f.grant(t, endpoint.id)
	binding, err := f.store.GetSessionBinding(endpoint.binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	return NativeActorScope{PrincipalID: endpoint.principal, EndpointID: endpoint.id,
		GroupID: f.groupID, NetworkID: networkID, MembershipID: membership.ID,
		MembershipRevision: membership.Revision, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner}
}

func sealedTaskHandoffTask(t *testing.T, f *sameGroupSealedV1Fixture,
	owner NativeActorScope) *SharedTask {
	t.Helper()
	task, err := f.store.CreateSharedTask(SharedTask{ID: NewID("handoff_task"), GroupID: f.groupID,
		Objective: "synthetic private task objective", AcceptanceCriteria: "synthetic private criteria"})
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ReadySharedTask(task.ID, task.Revision, "synthetic-control")
	if err != nil {
		t.Fatal(err)
	}
	task, err = f.store.ClaimSharedTaskForActor(owner, task.ID, task.Revision, NewID("claim"), 600)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func enqueueSealedTaskHandoffSend(t *testing.T, f *sameGroupSealedV1Fixture,
	lease time.Duration) (string, string, string) {
	t.Helper()
	expires := time.UnixMilli(time.Now().UTC().Add(lease).UnixMilli()).UTC()
	id := NewID("handoff")
	messageID := sealedTaskHandoffMessageID(expires, id)
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential,
		messageID, "SEND", "", "")
	record, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
		NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
		SourceEndpointID: f.source.id, TargetEndpointID: f.target.id,
		MessageID: messageID, IdempotencyKey: NewID("handoff_send"),
		DataScope: SameGroupSealedV1DataScope, Ciphertext: wire,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, messageID, record.Security.Digest
}

func proposeSealedTaskHandoff(t *testing.T, f *sameGroupSealedV1Fixture,
	source NativeActorScope, task *SharedTask, handoffID, messageID, digest string,
	refs []SealedTaskHandoffArtifactRef) *SealedSharedTaskHandoff {
	t.Helper()
	parsedID, expires, ok := parseSealedTaskHandoffMessageID(messageID)
	if !ok || parsedID != handoffID {
		t.Fatalf("invalid fixture route id %q", messageID)
	}
	handoff, err := f.store.ProposeSealedSharedTaskHandoffForActor(source,
		SealedSharedTaskHandoffProposal{HandoffID: handoffID, TaskID: task.ID,
			ExpectedTargetEndpointID: f.target.id, ExpectedRevision: task.Revision,
			OwnerEpoch: task.OwnerEpoch, MessageID: messageID, MessageDigest: digest,
			ExpiresAt: expires.Format(time.RFC3339Nano), RequiredArtifactRefs: refs})
	if err != nil {
		t.Fatal(err)
	}
	return handoff
}

func createHandoffArtifactRef(t *testing.T, f *sameGroupSealedV1Fixture,
	artifactID, refID, digest string) *ArtifactRefV2 {
	t.Helper()
	legacy, err := f.store.CreateArtifact(Artifact{ID: artifactID, Name: "synthetic evidence",
		Path: "synthetic/evidence", Kind: "evidence", Digest: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.store.CreateArtifactRefV2(ArtifactRefV2Input{ID: refID,
		ArtifactID: legacy.ID, GroupID: f.groupID, Digest: digest,
		Scopes: []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeSummary, ArtifactRefV2ScopeDigest}})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestSealedSharedTaskHandoffPreclaimGateAndAtomicTransfer(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	target := sealedTaskHandoffActor(t, f, networkID, f.target, true)
	task := sealedTaskHandoffTask(t, f, source)
	handoffID, messageID, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)

	// Relay may wake the target as soon as SEND persists, before the owner has
	// committed its Task metadata. The reservation remains READY and unclaimed.
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.target, "consumer_handoff_precommit"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("pre-metadata handoff was claimable: %#v err=%v", claims, err)
	}
	var state, attemptID string
	if err := f.store.db.QueryRow(`SELECT state,attempt_id FROM relay_v2_inbox
WHERE message_id=? AND recipient_endpoint_id=?`, messageID, f.target.id).Scan(&state, &attemptID); err != nil {
		t.Fatal(err)
	}
	if state != RelayInboxReady || attemptID != "" {
		t.Fatalf("pre-metadata Relay row changed state=%q attempt=%q", state, attemptID)
	}

	handoff := proposeSealedTaskHandoff(t, f, source, task, handoffID, messageID, digest, nil)
	if handoff.Status != SealedTaskHandoffProposed || handoff.Version != 1 ||
		handoff.NotifyNodeID != f.target.nodeID || len(handoff.RequiredArtifactRefs) != 0 {
		t.Fatalf("unexpected metadata-only proposal: %+v", handoff)
	}
	claims, err = f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.target, "consumer_handoff_aftercommit"))
	if err != nil || len(claims) != 1 || claims[0].MessageID != messageID {
		t.Fatalf("committed handoff SEND was not claimable: %#v err=%v", claims, err)
	}
	authorization, err := f.store.AuthorizeClaimedSameGroupSealedV1Delivery(
		f.targetNode.nodeCredential, messageID, claims[0].AttemptID)
	if err != nil || authorization.TaskHandoff == nil ||
		authorization.TaskHandoff.HandoffID != handoffID ||
		authorization.TaskHandoff.TaskRevision != task.Revision ||
		authorization.TaskHandoff.FromOwnerEpoch != task.OwnerEpoch {
		t.Fatalf("delivery metadata did not bind the claim: %+v err=%v", authorization, err)
	}
	if strings.Contains(string(claims[0].Ciphertext), "synthetic private task objective") {
		t.Fatal("Hub metadata path contains task prose")
	}

	transferred, err := f.store.AcceptSealedSharedTaskHandoffForActor(target,
		handoffID, handoff.Version, 300)
	if err != nil || transferred.OwnerEndpointID != target.EndpointID ||
		transferred.OwnerEpoch != task.OwnerEpoch+1 || transferred.Revision != task.Revision+1 {
		t.Fatalf("atomic transfer failed: %+v err=%v", transferred, err)
	}
	// The client can recover a lost Accept response by retrying the exact
	// expected metadata version while the transferred owner remains current.
	retry, err := f.store.AcceptSealedSharedTaskHandoffForActor(target,
		handoffID, handoff.Version, 300)
	if err != nil || retry.OwnerEpoch != transferred.OwnerEpoch || retry.Revision != transferred.Revision {
		t.Fatalf("lost-response Accept retry was not idempotent: %+v err=%v", retry, err)
	}
	stored, err := f.store.GetSealedSharedTaskHandoffForActor(target, handoffID, "task.read")
	if err != nil || stored.Status != SealedTaskHandoffTransferred || stored.Version != handoff.Version+1 ||
		stored.AcceptedAt == "" || stored.TransferredAt == "" || stored.TaskID != task.ID {
		t.Fatalf("transfer status was not recoverable: %+v err=%v", stored, err)
	}
	if _, err := f.store.SubmitSharedTaskResultForActor(source, task.ID, task.OwnerEpoch,
		task.Revision, "stale old-owner prose", []string{"synthetic"}); !errors.Is(err, ErrSharedTaskStaleOwner) {
		t.Fatalf("old owner was not fenced after transfer: %v", err)
	}
}

func TestSealedSharedTaskHandoffAcceptRechecksArtifactACLAndVersion(t *testing.T) {
	for _, tc := range []struct {
		name          string
		revoke        bool
		rotateVersion bool
		targetGrant   bool
	}{
		{name: "receiver lacks artifact grant", targetGrant: false},
		{name: "reference revoked", revoke: true, targetGrant: true},
		{name: "newer immutable version", rotateVersion: true, targetGrant: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, networkID := mappedSealedFixture(t)
			source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
			target := sealedTaskHandoffActor(t, f, networkID, f.target, tc.targetGrant)
			task := sealedTaskHandoffTask(t, f, source)
			ref := createHandoffArtifactRef(t, f, NewID("legacy_handoff_artifact"),
				NewID("artifact_ref"), strings.Repeat("b", 64))
			handoffID, messageID, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)
			handoff := proposeSealedTaskHandoff(t, f, source, task, handoffID, messageID, digest,
				[]SealedTaskHandoffArtifactRef{{ArtifactRefID: ref.ID, Version: ref.Version, Digest: ref.Digest}})
			if tc.revoke {
				if _, err := f.store.RevokeArtifactRefV2(ref.ID, "synthetic revoke"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.rotateVersion {
				if _, err := f.store.CreateArtifactRefV2(ArtifactRefV2Input{
					ArtifactID: ref.ArtifactID, GroupID: f.groupID, Digest: strings.Repeat("c", 64),
					Scopes: []string{ArtifactRefV2ScopeMetadata, ArtifactRefV2ScopeSummary, ArtifactRefV2ScopeDigest},
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target,
				handoff.ID, handoff.Version, 300); !errors.Is(err, ErrSealedTaskHandoffMissingArtifact) {
				t.Fatalf("direct actor Accept bypassed current Artifact ACL/version: %v", err)
			}
			unchanged, err := f.store.GetSharedTask(task.ID)
			if err != nil || unchanged.OwnerEndpointID != source.EndpointID ||
				unchanged.OwnerEpoch != task.OwnerEpoch || unchanged.Revision != task.Revision {
				t.Fatalf("failed Artifact check transferred task: %+v err=%v", unchanged, err)
			}
		})
	}
}

func TestSealedSharedTaskHandoffDirectAcceptRechecksCurrentRoutePair(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(*testing.T, *sameGroupSealedV1Fixture, string)
	}{
		{name: "sender Network membership revoked", revoke: func(t *testing.T, f *sameGroupSealedV1Fixture, networkID string) {
			membership, err := f.store.GetNetworkMembership(networkID, f.source.principal)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.RevokeNetworkMembership(networkID, f.source.principal, membership.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "receiver Endpoint Network membership revoked", revoke: func(t *testing.T, f *sameGroupSealedV1Fixture, networkID string) {
			membership, err := f.store.GetEndpointNetworkMembership(networkID, f.target.id)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.LeaveEndpointNetwork(networkID, f.target.id, membership.Revision); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "Network paused", revoke: func(t *testing.T, f *sameGroupSealedV1Fixture, networkID string) {
			if _, err := f.store.db.Exec(`UPDATE networks_v2 SET state=?,version=version+1 WHERE id=?`,
				NetworkStatePaused, networkID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, networkID := mappedSealedFixture(t)
			source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
			target := sealedTaskHandoffActor(t, f, networkID, f.target, true)
			task := sealedTaskHandoffTask(t, f, source)
			handoffID, messageID, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)
			handoff := proposeSealedTaskHandoff(t, f, source, task, handoffID, messageID, digest, nil)
			tc.revoke(t, f, networkID)
			if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target,
				handoff.ID, handoff.Version, 300); err == nil {
				t.Fatalf("direct Accept transferred after current route authorization was revoked: %v", err)
			}
			unchanged, err := f.store.GetSharedTask(task.ID)
			if err != nil || unchanged.OwnerEndpointID != source.EndpointID || unchanged.OwnerEpoch != task.OwnerEpoch ||
				unchanged.Revision != task.Revision {
				t.Fatalf("revoked route changed Task ownership: %+v err=%v", unchanged, err)
			}
		})
	}
}

func TestSealedSharedTaskHandoffExpiryFencesUnregisteredRelaySend(t *testing.T) {
	f, _ := mappedSealedFixture(t)
	deadline := time.UnixMilli(time.Now().UTC().Add(-time.Minute).UnixMilli()).UTC()
	id := NewID("expired_handoff")
	messageID := sealedTaskHandoffMessageID(deadline, id)
	wire := f.seal(t, f.source, f.target, f.sourceNode.nodeCredential, messageID, "SEND", "", "")
	if _, err := f.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
		NodeCredentialDigest: f.sourceNode.nodeCredential, GroupID: f.groupID,
		SourceEndpointID: f.source.id, TargetEndpointID: f.target.id, MessageID: messageID,
		DataScope: SameGroupSealedV1DataScope, Ciphertext: wire,
	}); err != nil {
		t.Fatal(err)
	}
	claims, err := f.store.ClaimSameGroupSealedV1Inbox(f.targetNode.nodeCredential,
		sameGroupSealedV1ClaimInput(f.target, "consumer_handoff_expired"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("expired unregistered SEND became deliverable: %#v err=%v", claims, err)
	}
	var state string
	if err := f.store.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`, messageID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != RelayInboxFailed {
		t.Fatalf("expired unregistered SEND remained queued: %s", state)
	}
}

func TestSealedSharedTaskHandoffMigrationInterruptionPreservesLegacyHandoff(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	task := sealedTaskHandoffTask(t, f, source)
	const legacyID = "legacy_plaintext_handoff_preserved"
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.store.db.Exec(`INSERT INTO shared_task_v2_handoffs
(id,task_id,group_id,from_principal_id,from_endpoint_id,to_principal_id,to_endpoint_id,
from_owner_epoch,task_revision,pending_work,workspace_state,evidence_refs_json,artifact_refs_json,
missing_artifact_refs_json,side_effects_json,no_repeat_actions_json,status,accepted_at,transferred_at,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		legacyID, task.ID, f.groupID, source.PrincipalID, source.EndpointID,
		"legacy_receiver", "legacy_receiver_endpoint", task.OwnerEpoch, task.Revision,
		"synthetic retained legacy work", "synthetic retained workspace", "[]", "[]", "[]", "[]", "[]",
		HandoffProposed, "", "", stamp, stamp); err != nil {
		t.Fatal(err)
	}
	path := f.dbPath
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := check.Exec(`DROP TABLE shared_task_sealed_handoffs_v2`); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if _, err := check.Exec(`DELETE FROM schema_migrations_v2 WHERE version=45`); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("simulated v45 process interruption")
	if _, err := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v2.fabric.sealed_shared_task_handoff" && phase == "after_apply" {
			return injected
		}
		return nil
	}); !errors.Is(err, injected) {
		t.Fatalf("expected v45 interruption, got %v", err)
	}
	check, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var tableCount int
	if err := check.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='shared_task_sealed_handoffs_v2'`).Scan(&tableCount); err != nil {
		check.Close()
		t.Fatal(err)
	}
	var pendingWork, migrationState string
	var attempts int
	if err := check.QueryRow(`SELECT pending_work FROM shared_task_v2_handoffs WHERE id=?`, legacyID).Scan(&pendingWork); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT state,attempts FROM schema_migrations_v2 WHERE version=45`).Scan(&migrationState, &attempts); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if err := check.Close(); err != nil {
		t.Fatal(err)
	}
	if tableCount != 0 || pendingWork != "synthetic retained legacy work" || migrationState != v2MigrationFailed || attempts != 1 {
		t.Fatalf("failed v45 migration did not roll back cleanly: table=%d legacy=%q state=%q attempts=%d",
			tableCount, pendingWork, migrationState, attempts)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var preserved string
	if err := reopened.db.QueryRow(`SELECT pending_work FROM shared_task_v2_handoffs WHERE id=?`, legacyID).Scan(&preserved); err != nil || preserved != "synthetic retained legacy work" {
		t.Fatalf("old plaintext handoff history was lost on retry: value=%q err=%v", preserved, err)
	}
	entry, err := reopened.readV2Migration(45)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("v45 migration did not recover on restart: entry=%+v err=%v", entry, err)
	}
}

// The shared guard timestamp is a real write: exact receipt/history reads must
// preserve it as well as the Task, handoff and audit event count.
func sealedHandoffSnapshot(t *testing.T, f *sameGroupSealedV1Fixture, taskID, handoffID string) string {
	t.Helper()
	task, err := f.store.GetSharedTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	var guard string
	var events int
	if err := f.store.db.QueryRow(`SELECT touched_at FROM shared_task_v2_guard WHERE id=1`).Scan(&guard); err != nil {
		t.Fatal(err)
	}
	if err := f.store.db.QueryRow(`SELECT count(*) FROM shared_task_v2_events WHERE task_id=?`, taskID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	handoff, err := scanSealedSharedTaskHandoff(f.store.db.QueryRow(`SELECT `+sealedSharedTaskHandoffColumns+` FROM shared_task_sealed_handoffs_v2 WHERE id=?`, handoffID))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal([]any{task, handoff, guard, events})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSealedSharedTaskHandoffSameNodeExactHistoryAndLease(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	thirdEndpoint := f.target
	f.target, f.targetNode = f.sameNode, f.sourceNode
	source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	target := sealedTaskHandoffActor(t, f, networkID, f.target, true)
	third := sealedTaskHandoffActor(t, f, networkID, thirdEndpoint, true)
	task := sealedTaskHandoffTask(t, f, source)
	id, message, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)
	handoff := proposeSealedTaskHandoff(t, f, source, task, id, message, digest, nil)
	_, expiry, _ := parseSealedTaskHandoffMessageID(message)
	proposal := SealedSharedTaskHandoffProposal{HandoffID: id, TaskID: task.ID, ExpectedTargetEndpointID: target.EndpointID, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch, MessageID: message, MessageDigest: digest, ExpiresAt: expiry.Format(time.RFC3339Nano)}
	before := sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.ProposeSealedSharedTaskHandoffForActor(source, proposal); err != nil {
		t.Fatal(err)
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("exact proposal retry wrote state")
	}
	transferred, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, handoff.Version, 300)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.OwnerEpoch != task.OwnerEpoch+1 || transferred.Revision != task.Revision+1 {
		t.Fatal("non-atomic transfer")
	}
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.ProposeSealedSharedTaskHandoffForActor(source, proposal); err != nil {
		t.Fatal("proposal response lost after transfer", err)
	}
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, handoff.Version, 300); err != nil {
		t.Fatal(err)
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("exact transferred recovery wrote state")
	}
	for _, lease := range []int{-1, 301, 3601} {
		if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, handoff.Version, lease); err == nil {
			t.Fatalf("changed/invalid lease accepted: %d", lease)
		}
	}
	stale := proposal
	stale.ExpectedRevision++
	if _, err := f.store.ProposeSealedSharedTaskHandoffForActor(source, stale); err == nil {
		t.Fatal("changed proposal accepted")
	}
	tx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := guardNativeActorTx(tx, third, "task.read", time.Now().UTC()); err != nil {
		tx.Rollback()
		t.Fatal("third Actor fixture is not authorized", err)
	}
	tx.Rollback()
	if _, err := f.store.GetSealedSharedTaskHandoffForActor(third, id, "task.read"); err == nil {
		t.Fatal("valid third Endpoint read history")
	}
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(third, id, handoff.Version, 300); err == nil {
		t.Fatal("valid third Endpoint accepted handoff")
	}
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(source, id, handoff.Version, 300); err == nil {
		t.Fatal("old owner accepted receiver receipt")
	}
	rebound := target
	rebound.BindingEpoch++
	if _, err := f.store.GetSealedSharedTaskHandoffForActor(rebound, id, "task.read"); err == nil {
		t.Fatal("rebound actor read historical receipt")
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("denied recovery wrote state")
	}
}

func TestSealedSharedTaskHandoffReceiptRevocationAndACL(t *testing.T) {
	for _, kind := range []string{"artifact", "grant", "binding", "revision"} {
		t.Run(kind, func(t *testing.T) {
			f, net := mappedSealedFixture(t)
			source := sealedTaskHandoffActor(t, f, net, f.source, true)
			target := sealedTaskHandoffActor(t, f, net, f.target, true)
			task := sealedTaskHandoffTask(t, f, source)
			ref := createHandoffArtifactRef(t, f, NewID("synthetic_artifact"), NewID("synthetic_ref"), strings.Repeat("b", 64))
			id, msg, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)
			h := proposeSealedTaskHandoff(t, f, source, task, id, msg, digest, []SealedTaskHandoffArtifactRef{{ArtifactRefID: ref.ID, Version: ref.Version, Digest: ref.Digest}})
			if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, h.Version, 300); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "artifact":
				if _, err := f.store.RevokeArtifactRefV2(ref.ID, "synthetic revoke"); err != nil {
					t.Fatal(err)
				}
			case "grant":
				m, err := f.store.GetNetworkMembership(net, f.target.principal)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.store.RevokeNetworkMembership(net, f.target.principal, m.Revision); err != nil {
					t.Fatal(err)
				}
			case "binding":
				binding, err := f.store.RotateSessionBindingCredential(target.BindingID, target.BindingEpoch, "synthetic-new-credential-digest", target.LeaseOwner, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
				if err != nil {
					t.Fatal(err)
				}
				proof, err := f.target.identity.SignEndpointKeyAttestation(f.target.id, f.target.principal, f.target.nodeID, binding.ID, binding.Epoch)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.RegisterEndpointKeyCandidate(f.target.id, f.target.principal, binding.ID, binding.Epoch, proof); err != nil {
					t.Fatal(err)
				}
				f.grant(t, f.target.id)
				target.BindingID, target.BindingEpoch = binding.ID, binding.Epoch
				tx, err := f.store.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				if err := guardNativeActorTx(tx, target, "task.claim", time.Now().UTC()); err != nil {
					tx.Rollback()
					t.Fatal("fresh rebound actor is not currently authorized", err)
				}
				tx.Rollback()
				if _, err := f.store.GetSealedSharedTaskHandoffForActor(target, id, "task.read"); err == nil {
					t.Fatal("new valid binding read old receipt")
				}
			case "revision":
				if _, err := f.store.db.Exec(`UPDATE shared_tasks_v2 SET revision=revision+1 WHERE id=?`, task.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := sealedHandoffSnapshot(t, f, task.ID, id)
			if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, h.Version, 300); err == nil {
				t.Fatal("revoked/evolved receipt recovered")
			}
			if before != sealedHandoffSnapshot(t, f, task.ID, id) {
				t.Fatal("denied exact receipt changed state")
			}
		})
	}
}

func TestSealedSharedTaskHandoffCASAndExpiredRevokedActor(t *testing.T) {
	f, net := mappedSealedFixture(t)
	source := sealedTaskHandoffActor(t, f, net, f.source, true)
	target := sealedTaskHandoffActor(t, f, net, f.target, true)
	task := sealedTaskHandoffTask(t, f, source)
	id, msg, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)
	h := proposeSealedTaskHandoff(t, f, source, task, id, msg, digest, nil)
	before := sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, h.Version+1, 300); err == nil {
		t.Fatal("wrong CAS accepted")
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("CAS denial wrote state")
	}
	if _, err := f.store.db.Exec(`UPDATE shared_task_sealed_handoffs_v2 SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	m, err := f.store.GetNetworkMembership(net, f.target.principal)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeNetworkMembership(net, f.target.principal, m.Revision); err != nil {
		t.Fatal(err)
	}
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, h.Version, 300); err == nil {
		t.Fatal("revoked expired acceptance allowed")
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("revoked actor marked handoff expired")
	}
}

func TestSealedSharedTaskHandoffLegacyLocalHistoryNeverTransfers(t *testing.T) {
	f, networkID := mappedSealedFixture(t)
	f.target, f.targetNode = f.sameNode, f.sourceNode
	source := sealedTaskHandoffActor(t, f, networkID, f.source, true)
	target := sealedTaskHandoffActor(t, f, networkID, f.target, true)
	task := sealedTaskHandoffTask(t, f, source)
	id, message, digest := enqueueSealedTaskHandoffSend(t, f, time.Hour)
	ref := createHandoffArtifactRef(t, f, NewID("synthetic_legacy_artifact"), NewID("synthetic_legacy_ref"), strings.Repeat("b", 64))
	h := proposeSealedTaskHandoff(t, f, source, task, id, message, digest, []SealedTaskHandoffArtifactRef{{ArtifactRefID: ref.ID, Version: ref.Version, Digest: ref.Digest}})
	input := LocalSealedSharedTaskHandoffProposal{HandoffID: id, TaskID: task.ID, TargetEndpointID: target.EndpointID, ExpectedRevision: task.Revision, OwnerEpoch: task.OwnerEpoch, MessageID: message, MessageDigest: digest, ExpiresAt: h.ExpiresAt, RequiredArtifactRefs: h.RequiredArtifactRefs}
	// Seed authentic synthetic v54 evidence, not a new production local handoff.
	// Existing signed identities, immutable metadata and proof match the old format.
	tx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	from, err := readLocalDeliveryEndpointByIDTx(tx, f.groupID, source.EndpointID, now.Format(time.RFC3339Nano))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	to, err := readLocalDeliveryEndpointByIDTx(tx, f.groupID, target.EndpointID, now.Format(time.RFC3339Nano))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	fromKey, err := readCurrentLocalDeliveryKeyTx(tx, from)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	toKey, err := readCurrentLocalDeliveryKeyTx(tx, to)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var hub string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hub); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	refsDigest, err := SealedTaskHandoffArtifactRefsDigest(h.RequiredArtifactRefs)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	claims := localTaskHandoffProofClaims(input, h.ExpiresAt, refsDigest, hub, f.groupID, task, from, to, fromKey, toKey)
	claims.IssuedAt = now.Format(time.RFC3339Nano)
	proof, err := f.source.identity.SignLocalTaskHandoffProof(claims)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	input.SenderProof = proof
	proofDigest := sha256.Sum256(proof)
	if _, err := tx.Exec(`INSERT INTO shared_task_local_handoff_routes_v54(handoff_id,node_id,from_binding_id,from_binding_epoch,from_membership_revision,from_join_revision,from_key_id,from_key_version,to_binding_id,to_binding_epoch,to_membership_revision,to_join_revision,to_key_id,to_key_version,sender_proof_digest,sender_proof,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, from.NodeID, from.BindingID, from.BindingEpoch, from.MembershipRevision, from.GroupJoinRevision, fromKey.KeyID, fromKey.Version, to.BindingID, to.BindingEpoch, to.MembershipRevision, to.GroupJoinRevision, toKey.KeyID, toKey.Version, hex.EncodeToString(proofDigest[:]), proof, now.Format(time.RFC3339Nano)); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before := sealedHandoffSnapshot(t, f, task.ID, id)
	recovered, err := f.store.ProposeLocalSealedSharedTaskHandoffForActor(source, input)
	if err != nil || recovered.Transport != "LOCAL_NODE" {
		t.Fatal("authentic existing local history rejected", err)
	}
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, h.Version, 300); err == nil {
		t.Fatal("old PROPOSED local history transferred responsibility")
	}
	if _, err := authorizeLocalSealedTaskHandoffDeliveryTx(nil, LocalDeliveryRevalidationInput{}, from, to, fromKey, toKey, now); err == nil {
		t.Fatal("old local history authorized delivery")
	}
	missing := input
	missing.HandoffID = "synthetic_absent_local_handoff"
	if _, err := f.store.ProposeLocalSealedSharedTaskHandoffForActor(source, missing); err == nil {
		t.Fatal("absent local history was manufactured")
	}
	changed := input
	changed.SenderProof = []byte("visibly synthetic invalid proof")
	if _, err := f.store.ProposeLocalSealedSharedTaskHandoffForActor(source, changed); err == nil {
		t.Fatal("changed legacy proof accepted")
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("legacy history/denials changed state")
	}
	// Deadline freshness governs new operations; authentic history is still read
	// after expiry and does not mark or transfer the old proposal.
	if _, err := f.store.db.Exec(`UPDATE shared_task_sealed_handoffs_v2 SET expires_at=? WHERE id=?`, now.Add(-time.Hour).Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	history, err := f.store.GetSealedSharedTaskHandoffForActor(source, id, "task.read")
	if err != nil || history.Status != SealedTaskHandoffProposed {
		t.Fatal("expired history mutated or unavailable", err)
	}
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, h.Version, 300); err == nil {
		t.Fatal("old expired local handoff accepted")
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("legacy expired acceptance wrote state")
	}
	// The only allowed legacy acceptance result is a genuine prior transfer.
	// These synthetic SQL rows are fixture setup; production never creates them.
	stamp := time.Now().UTC()
	if _, err := f.store.db.Exec(`UPDATE shared_tasks_v2 SET owner_principal_id=?,owner_endpoint_id=?,owner_epoch=?,revision=?,claim_key=?,lease_expires_at=?,status=? WHERE id=?`, target.PrincipalID, target.EndpointID, task.OwnerEpoch+1, task.Revision+1, "sealed-handoff:"+id, stamp.Add(300*time.Second).Format(time.RFC3339Nano), SharedTaskClaimed, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE shared_task_sealed_handoffs_v2 SET status=?,version=2,expires_at=?,accepted_at=?,transferred_at=? WHERE id=?`, SealedTaskHandoffTransferred, h.ExpiresAt, stamp.Format(time.RFC3339Nano), stamp.Format(time.RFC3339Nano), id); err != nil {
		t.Fatal(err)
	}
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if recovered, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, 1, 300); err != nil || recovered.OwnerEndpointID != target.EndpointID {
		t.Fatal("authentic prior legacy acceptance receipt rejected", err)
	}
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, 1, 301); err == nil {
		t.Fatal("legacy changed-lease replay accepted")
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("legacy transfer receipt replay wrote state")
	}
	// Isolate current source-pair authorization while the receiver and receipt
	// remain valid. Fixture-only status changes do not run revocation cascades.
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET status='revoked' WHERE network_id=? AND principal_id=?`, networkID, source.PrincipalID); err != nil {
		t.Fatal(err)
	}
	pairTx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := guardNativeActorTx(pairTx, target, "task.claim", time.Now().UTC()); err != nil {
		pairTx.Rollback()
		t.Fatal("receiver Guard was not independently valid", err)
	}
	pairTx.Rollback()
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, 1, 300); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("legacy receipt ignored current source pair revocation", err)
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("legacy pair denial wrote state")
	}
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET status='active' WHERE network_id=? AND principal_id=?`, networkID, source.PrincipalID); err != nil {
		t.Fatal(err)
	}
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, 1, 300); err != nil {
		t.Fatal("restored exact fixture receipt no longer valid", err)
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("restored legacy exact receipt wrote state")
	}
	if _, err := f.store.RevokeArtifactRefV2(ref.ID, "synthetic legacy ACL revoke"); err != nil {
		t.Fatal(err)
	}
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, 1, 300); !errors.Is(err, ErrSealedTaskHandoffMissingArtifact) {
		t.Fatal("legacy receipt ignored current Artifact ACL", err)
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("legacy ACL denial wrote state")
	}
	binding, err := f.store.RotateSessionBindingCredential(target.BindingID, target.BindingEpoch, "synthetic-legacy-new-credential", target.LeaseOwner, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	keyProof, err := f.target.identity.SignEndpointKeyAttestation(f.target.id, f.target.principal, f.target.nodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RegisterEndpointKeyCandidate(f.target.id, f.target.principal, binding.ID, binding.Epoch, keyProof); err != nil {
		t.Fatal(err)
	}
	f.grant(t, f.target.id)
	target.BindingID, target.BindingEpoch = binding.ID, binding.Epoch
	guardTx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := guardNativeActorTx(guardTx, target, "task.claim", time.Now().UTC()); err != nil {
		guardTx.Rollback()
		t.Fatal("legacy rebound current actor not authorized", err)
	}
	guardTx.Rollback()
	before = sealedHandoffSnapshot(t, f, task.ID, id)
	if _, err := f.store.AcceptSealedSharedTaskHandoffForActor(target, id, 1, 300); !errors.Is(err, ErrSealedTaskHandoffConflict) {
		t.Fatal("legacy new binding inherited old receipt", err)
	}
	if before != sealedHandoffSnapshot(t, f, task.ID, id) {
		t.Fatal("legacy rebound denial wrote state")
	}
}
