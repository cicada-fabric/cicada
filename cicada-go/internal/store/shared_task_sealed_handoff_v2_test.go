package store

import (
	"database/sql"
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
