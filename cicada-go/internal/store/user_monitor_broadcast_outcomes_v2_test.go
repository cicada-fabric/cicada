package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func authorizeUserMonitorOutcomeFixture(t *testing.T) (*userMonitorBroadcastFixture, *UserMonitorBroadcastV2, []byte) {
	t.Helper()
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic Monitor broadcast used only by outcome tests")
	prepared, _ := f.prepare(t, body)
	approved, _ := f.confirm(t, prepared, body, 1)
	authorized, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2(f.consumeInput(approved))
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Status != UserMonitorBroadcastV2DispatchAuthorized || authorized.Snapshot == nil ||
		len(authorized.Snapshot.Recipients) != 2 {
		t.Fatalf("fixture did not reserve its exact two-recipient dispatch: %+v", authorized)
	}
	return f, authorized, body
}

func userMonitorOutcomeResult(t *testing.T, r *UserMonitorBroadcastV2, ordinal int, state, evidence, failure string) UserMonitorBroadcastV2RecipientReport {
	t.Helper()
	if r.Snapshot == nil || ordinal < 0 || ordinal >= len(r.Snapshot.Recipients) {
		t.Fatalf("outcome fixture has no recipient ordinal %d", ordinal)
	}
	recipient := r.Snapshot.Recipients[ordinal]
	childID, messageID, err := UserMonitorBroadcastV2ChildIDs(r.BroadcastID, recipient.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	return UserMonitorBroadcastV2RecipientReport{Ordinal: ordinal, EndpointID: recipient.EndpointID,
		ChildOperationID: childID, MessageID: messageID, State: state, Evidence: evidence, FailureCode: failure}
}

func userMonitorOutcomeInput(f *userMonitorBroadcastFixture, r *UserMonitorBroadcastV2,
	results ...UserMonitorBroadcastV2RecipientReport) UserMonitorBroadcastV2OutcomeReportInput {
	return UserMonitorBroadcastV2OutcomeReportInput{
		NodeCredentialDigest:    f.sealed.sourceNode.nodeCredential,
		SessionCredentialDigest: sameGroupBroadcastV2CredentialDigest(f.sessionToken),
		PreviewID:               r.PreviewID, BroadcastID: r.BroadcastID, OperationID: r.OperationID,
		SnapshotDigest: r.SnapshotDigest, Results: results,
	}
}

func TestUserMonitorBroadcastV2OutcomeReportsAreExactAndMonotone(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	status, err := f.sealed.store.GetUserMonitorBroadcastV2OutcomeStatus(r.confirmRequestID, r.PreviewID)
	if err != nil || status.ApprovalStatus != UserMonitorBroadcastV2DispatchAuthorized ||
		status.BroadcastID != r.BroadcastID || status.GroupID != r.GroupID || len(status.Recipients) != 2 {
		t.Fatalf("status did not expose the exact reserved snapshot: %+v %v", status, err)
	}
	for i, outcome := range status.Recipients {
		if outcome.Ordinal != i || outcome.EndpointID != r.Snapshot.Recipients[i].EndpointID ||
			outcome.State != UserMonitorBroadcastV2OutcomePending || outcome.MessageID != "" {
			t.Fatalf("initial outcome was not the exact pending snapshot slot: %+v", outcome)
		}
	}

	failed := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED")
	got, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, failed))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeFailed || got[0].FailureCode != "DELIVERY_REJECTED" {
		t.Fatalf("FAILED report did not persist: %+v %v", got, err)
	}
	unknown := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeUnknown, "", "DELIVERY_OUTCOME_UNKNOWN")
	got, err = f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, unknown))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeUnknown {
		t.Fatalf("UNKNOWN did not advance FAILED: %+v %v", got, err)
	}
	got, err = f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, failed))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeUnknown {
		t.Fatalf("stale FAILED report regressed UNKNOWN: %+v %v", got, err)
	}
	accepted := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeAccepted,
		UserMonitorBroadcastV2EvidenceNode, "")
	got, err = f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, accepted))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeAccepted || got[0].Evidence != UserMonitorBroadcastV2EvidenceNode ||
		got[0].MessageID != accepted.MessageID || got[0].ReportedAt == "" {
		t.Fatalf("local NODE_REPORTED acceptance did not advance UNKNOWN: %+v %v", got, err)
	}
	got, err = f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, unknown))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeAccepted || got[0].Evidence != UserMonitorBroadcastV2EvidenceNode ||
		got[0].MessageID != accepted.MessageID {
		t.Fatalf("stale UNKNOWN report regressed ACCEPTED: %+v %v", got, err)
	}
	got, err = f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, accepted))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeAccepted {
		t.Fatalf("exact ACCEPTED retry was not idempotent: %+v %v", got, err)
	}
}

func TestUserMonitorBroadcastV2RemoteAcceptedNeedsPersistedRelayChild(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	remote := userMonitorOutcomeResult(t, r, 1, UserMonitorBroadcastV2OutcomeAccepted,
		UserMonitorBroadcastV2EvidenceRelay, "")
	input := userMonitorOutcomeInput(f, r, remote)
	if _, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("unpersisted remote Relay acceptance was trusted: %v", err)
	}
	if states := readOutcomeStatesForTest(t, f.sealed.store, r.PreviewID); states[1] != UserMonitorBroadcastV2OutcomePending {
		t.Fatalf("denied remote acceptance changed durable state: %v", states)
	}

	peerCiphertext := f.sealed.seal(t, f.sealed.source, f.sealed.target, f.sealed.sourceNode.nodeCredential,
		remote.MessageID, "SEND", "", "")
	if _, err := f.sealed.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{
		NodeCredentialDigest: f.sealed.sourceNode.nodeCredential, GroupID: r.GroupID,
		SourceEndpointID: f.sealed.source.id, TargetEndpointID: f.sealed.target.id,
		MessageID: remote.MessageID, IdempotencyKey: remote.ChildOperationID,
		DataScope: SameGroupSealedV1DataScope, Ciphertext: peerCiphertext,
	}); err != nil {
		t.Fatalf("could not persist synthetic Relay child: %v", err)
	}
	got, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(input)
	if err != nil || got[1].State != UserMonitorBroadcastV2OutcomeAccepted ||
		got[1].Evidence != UserMonitorBroadcastV2EvidenceRelay || got[1].MessageID != remote.MessageID {
		t.Fatalf("persisted remote Relay child did not support acceptance: %+v %v", got, err)
	}
}

func TestUserMonitorBroadcastV2OutcomeRejectsMismatchesAtomically(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*userMonitorBroadcastFixture, *UserMonitorBroadcastV2, *UserMonitorBroadcastV2OutcomeReportInput)
		wantErr error
	}{
		{name: "wrong Node", mutate: func(f *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.NodeCredentialDigest = f.sealed.targetNode.nodeCredential
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "wrong Session", mutate: func(_ *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.SessionCredentialDigest = sameGroupBroadcastV2CredentialDigest("synthetic wrong Session")
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "wrong source binding", mutate: func(f *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, _ *UserMonitorBroadcastV2OutcomeReportInput) {
			if _, err := f.sealed.store.RevokeSessionBinding(f.sealed.source.binding.ID, f.sealed.source.binding.Epoch, "synthetic test fence"); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "wrong recipient", mutate: func(_ *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.Results[0].EndpointID = "ep_synthetic_wrong_recipient"
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "wrong child operation", mutate: func(_ *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.Results[0].ChildOperationID = "op_00000000000000000000000000000000"
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "wrong message", mutate: func(_ *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.Results[0].MessageID = "msg_00000000000000000000000000000000"
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "wrong snapshot digest", mutate: func(_ *userMonitorBroadcastFixture, _ *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.SnapshotDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		}, wantErr: ErrUserMonitorBroadcastV2Denied},
		{name: "duplicate ordinal", mutate: func(_ *userMonitorBroadcastFixture, r *UserMonitorBroadcastV2, in *UserMonitorBroadcastV2OutcomeReportInput) {
			in.Results = append(in.Results, userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeUnknown, "", "DELIVERY_OUTCOME_UNKNOWN"))
		}, wantErr: ErrUserMonitorBroadcastV2Conflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, r, _ := authorizeUserMonitorOutcomeFixture(t)
			first := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED")
			if tt.name == "duplicate ordinal" {
				first = userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED")
			}
			in := userMonitorOutcomeInput(f, r, first)
			tt.mutate(f, r, &in)
			_, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("report mismatch returned %v, want %v", err, tt.wantErr)
			}
			states := readOutcomeStatesForTest(t, f.sealed.store, r.PreviewID)
			if states[0] != UserMonitorBroadcastV2OutcomePending || states[1] != UserMonitorBroadcastV2OutcomePending {
				t.Fatalf("rejected batch partially changed outcomes: %v", states)
			}
		})
	}

	t.Run("valid row before invalid row rolls back", func(t *testing.T) {
		f, r, _ := authorizeUserMonitorOutcomeFixture(t)
		first := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED")
		second := userMonitorOutcomeResult(t, r, 1, UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED")
		second.MessageID = "msg_00000000000000000000000000000000"
		if _, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, first, second)); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
			t.Fatalf("batch with a mismatched second row returned %v", err)
		}
		states := readOutcomeStatesForTest(t, f.sealed.store, r.PreviewID)
		if states[0] != UserMonitorBroadcastV2OutcomePending || states[1] != UserMonitorBroadcastV2OutcomePending {
			t.Fatalf("invalid second row did not roll back first row: %v", states)
		}
	})
}

func TestUserMonitorBroadcastV2OutcomeStatusIsBoundToOriginalCurrentClientDevice(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	if _, err := f.sealed.store.GetUserMonitorBroadcastV2OutcomeStatus(r.confirmRequestID, r.PreviewID); err != nil {
		t.Fatalf("original active Client device could not read status: %v", err)
	}

	otherIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.sealed.owner.SignOwnerDeviceGrant(f.sealed.ownerID, "phone_outcome_synthetic", otherIdentity.Public(),
		hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: f.sealed.ownerID, OwnerKeyID: f.sealed.ownerKeyID, DeviceID: "phone_outcome_synthetic",
		DevicePublic: otherIdentity.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	requestCiphertextHash := sha256.Sum256([]byte("synthetic other-device request"))
	requestDigest := hex.EncodeToString(requestCiphertextHash[:])
	request, err := f.sealed.store.AcceptClientRequest(AcceptClientRequestInput{
		OwnerID: f.sealed.ownerID, DeviceID: "phone_outcome_synthetic", SessionEpoch: 1, Sequence: 1,
		OperationID: "outcome_other_device_request", CiphertextDigest: requestDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.GetUserMonitorBroadcastV2OutcomeStatus(request.Request.ID, r.PreviewID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("different accepted Client device read another device's outcomes: %v", err)
	}

	if _, err := f.sealed.store.RevokeClientDevice(r.OwnerID, r.DeviceID, f.deviceRecord.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.GetUserMonitorBroadcastV2OutcomeStatus(r.confirmRequestID, r.PreviewID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("revoked original Client device retained outcome access: %v", err)
	}
}

func TestUserMonitorBroadcastV2ExpiryAllowsFactualReportButNotSend(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE preview_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), r.PreviewID); err != nil {
		t.Fatal(err)
	}
	accepted := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeAccepted,
		UserMonitorBroadcastV2EvidenceNode, "")
	got, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, accepted))
	if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeAccepted {
		t.Fatalf("expiry erased or denied a factual Node report: %+v %v", got, err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2(f.consumeInput(r)); !errors.Is(err, ErrUserMonitorBroadcastV2Expired) {
		t.Fatalf("expired approval authorized a child send: %v", err)
	}
}

func TestUserMonitorBroadcastV2OutcomeMigrationBackfillsV32Dispatch(t *testing.T) {
	f, authorized, _ := authorizeUserMonitorOutcomeFixture(t)
	store := f.sealed.store
	before := *authorized
	before.SealedPayload = bytes.Clone(authorized.SealedPayload)
	beforeSnapshot, err := readBroadcastSnapshotForTest(t, store, authorized.BroadcastID)
	if err != nil {
		t.Fatal(err)
	}
	before.Snapshot = beforeSnapshot

	if _, err := store.db.Exec(`DROP TABLE user_monitor_broadcast_v2_recipient_outcomes`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM schema_migrations_v2 WHERE version=33`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })

	entry, err := reopened.readV2Migration(33)
	if err != nil || entry == nil || entry.State != v2MigrationApplied {
		t.Fatalf("v33 outcome migration did not apply after v32-style downgrade: %+v %v", entry, err)
	}
	after, err := readUserMonitorBroadcastTxForTest(reopened, authorized.PreviewID)
	if err != nil {
		t.Fatal(err)
	}
	after.Snapshot, err = readBroadcastSnapshotForTest(t, reopened, authorized.BroadcastID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != UserMonitorBroadcastV2DispatchAuthorized || before.PreviewID != after.PreviewID ||
		before.BroadcastID != after.BroadcastID || before.OperationID != after.OperationID ||
		before.SnapshotDigest != after.SnapshotDigest || before.BodyDigest != after.BodyDigest ||
		before.SealedPayloadDigest != after.SealedPayloadDigest || before.SealedSequence != after.SealedSequence ||
		!bytes.Equal(before.SealedPayload, after.SealedPayload) || !reflect.DeepEqual(before.Snapshot, after.Snapshot) {
		t.Fatalf("v33 backfill changed the v32 dispatch or immutable snapshot: before=%+v after=%+v", before, after)
	}
	outcomes, err := readOutcomeRowsForTest(reopened, authorized.PreviewID)
	if err != nil || len(outcomes) != len(before.Snapshot.Recipients) {
		t.Fatalf("v33 backfill did not restore all recipient slots: %+v %v", outcomes, err)
	}
	for ordinal, outcome := range outcomes {
		recipient := before.Snapshot.Recipients[ordinal]
		childID, messageID, err := UserMonitorBroadcastV2ChildIDs(before.BroadcastID, recipient.EndpointID)
		if err != nil || outcome.Ordinal != ordinal || outcome.EndpointID != recipient.EndpointID ||
			outcome.State != UserMonitorBroadcastV2OutcomePending || outcome.ChildOperationID != childID || outcome.ExpectedMessageID != messageID {
			t.Fatalf("backfilled slot %d lost original child identity: %+v err=%v", ordinal, outcome, err)
		}
	}
}

func TestUserMonitorBroadcastV2OutcomeReportsAreIdempotentAcrossStoreHandles(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	otherStore, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	result := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED")
	input := userMonitorOutcomeInput(f, r, result)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*Store{f.sealed.store, otherStore} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			<-start
			_, err := store.ReportUserMonitorBroadcastV2RecipientOutcomes(input)
			results <- err
		}(store)
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent exact outcome report failed: %v", err)
		}
	}
	for _, store := range []*Store{f.sealed.store, otherStore} {
		got, err := store.ReportUserMonitorBroadcastV2RecipientOutcomes(input)
		if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeFailed || got[0].FailureCode != "DELIVERY_REJECTED" {
			t.Fatalf("exact report retry did not read back the same durable outcome: %+v %v", got, err)
		}
	}
	if err := otherStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	status, err := reopened.GetUserMonitorBroadcastV2OutcomeStatus(r.confirmRequestID, r.PreviewID)
	if err != nil || status.Recipients[0].State != UserMonitorBroadcastV2OutcomeFailed ||
		status.Recipients[0].FailureCode != "DELIVERY_REJECTED" {
		t.Fatalf("outcome did not survive Store restart: %+v %v", status, err)
	}
}

type userMonitorOutcomeRowForTest struct {
	Ordinal           int
	EndpointID        string
	NodeID            string
	ChildOperationID  string
	ExpectedMessageID string
	State             string
	Evidence          string
	FailureCode       string
	ReportedAt        string
}

func readOutcomeRowsForTest(s *Store, previewID string) ([]userMonitorOutcomeRowForTest, error) {
	rows, err := s.db.Query(`SELECT ordinal,endpoint_id,node_id,child_operation_id,expected_message_id,state,evidence,failure_code,reported_at
FROM user_monitor_broadcast_v2_recipient_outcomes WHERE preview_id=? ORDER BY ordinal`, previewID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]userMonitorOutcomeRowForTest, 0, SameGroupBroadcastV2MaxRecipients)
	for rows.Next() {
		var r userMonitorOutcomeRowForTest
		if err := rows.Scan(&r.Ordinal, &r.EndpointID, &r.NodeID, &r.ChildOperationID, &r.ExpectedMessageID,
			&r.State, &r.Evidence, &r.FailureCode, &r.ReportedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func readOutcomeStatesForTest(t *testing.T, s *Store, previewID string) map[int]string {
	t.Helper()
	rows, err := readOutcomeRowsForTest(s, previewID)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[int]string, len(rows))
	for _, row := range rows {
		out[row.Ordinal] = row.State
	}
	return out
}

func readBroadcastSnapshotForTest(t *testing.T, s *Store, broadcastID string) (*SameGroupBroadcastV2Snapshot, error) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return readSameGroupBroadcastV2SnapshotTx(tx, broadcastID)
}

func TestUserMonitorBroadcastV2OutcomeReportBindingEpochReplacementDenied(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	oldBinding := f.sealed.source.binding
	released, err := f.sealed.store.ReleaseSessionBindingLease(oldBinding.ID, oldBinding.LeaseOwner, oldBinding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.AcquireSessionBindingLease(released.ID, "lease_synthetic_replacement", released.Epoch,
		time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	accepted := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeAccepted,
		UserMonitorBroadcastV2EvidenceNode, "")
	if _, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, accepted)); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("old dispatch reported against a replacement source binding epoch: %v", err)
	}
	if states := readOutcomeStatesForTest(t, f.sealed.store, r.PreviewID); states[0] != UserMonitorBroadcastV2OutcomePending {
		t.Fatalf("replacement binding denial changed outcome state: %v", states)
	}
}

func TestUserMonitorBroadcastV2OutcomeReportBoundsBatch(t *testing.T) {
	f, r, _ := authorizeUserMonitorOutcomeFixture(t)
	input := userMonitorOutcomeInput(f, r)
	if _, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("empty outcome batch was accepted: %v", err)
	}
	for i := 0; i < 9; i++ {
		input.Results = append(input.Results, userMonitorOutcomeResult(t, r, 0,
			UserMonitorBroadcastV2OutcomeFailed, "", "DELIVERY_REJECTED"))
	}
	if _, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("oversized outcome batch was accepted: %v", err)
	}
	if rows, err := readOutcomeRowsForTest(f.sealed.store, r.PreviewID); err != nil || len(rows) != 2 {
		t.Fatalf("batch bound failure changed seeded outcomes: rows=%d err=%v", len(rows), err)
	}
}

func TestUserMonitorBroadcastV2SameNodeRelayEvidenceRequiresExactPersistence(t *testing.T) {
	for _, scenario := range []string{"exact", "not persisted", "missing payload", "corrupt payload", "missing outbox", "wrong binding", "wrong envelope"} {
		t.Run(scenario, func(t *testing.T) {
			f, r, _ := authorizeUserMonitorOutcomeFixture(t)
			report := userMonitorOutcomeResult(t, r, 0, UserMonitorBroadcastV2OutcomeAccepted, UserMonitorBroadcastV2EvidenceRelay, "")
			if report.EndpointID != f.sealed.sameNode.id {
				t.Fatal("fixture ordinal0 is not sameNode recipient")
			}
			if scenario != "not persisted" {
				ciphertext := f.sealed.seal(t, f.sealed.source, f.sealed.sameNode, f.sealed.sourceNode.nodeCredential, report.MessageID, "SEND", "", "")
				if _, err := f.sealed.store.EnqueueSameGroupSealedV1Send(SameGroupSealedV1Send{NodeCredentialDigest: f.sealed.sourceNode.nodeCredential, GroupID: r.GroupID,
					SourceEndpointID: f.sealed.source.id, TargetEndpointID: f.sealed.sameNode.id, MessageID: report.MessageID, IdempotencyKey: report.ChildOperationID,
					DataScope: SameGroupSealedV1DataScope, Ciphertext: ciphertext}); err != nil {
					t.Fatal(err)
				}
			}
			var query string
			switch scenario {
			case "missing payload":
				query = "DELETE FROM relay_v2_message_payloads WHERE message_id=?"
			case "corrupt payload":
				query = "UPDATE relay_v2_message_payloads SET ciphertext=X'00' WHERE message_id=?"
			case "missing outbox":
				query = "DELETE FROM relay_v2_outbox WHERE message_id=?"
			case "wrong binding":
				query = "UPDATE relay_v2_message_security SET receiver_binding_epoch=receiver_binding_epoch+1 WHERE message_id=?"
			case "wrong envelope":
				query = "UPDATE fabric_messages SET kind='reply' WHERE id=?"
			}
			if query != "" {
				if _, err := f.sealed.store.db.Exec(query, report.MessageID); err != nil {
					t.Fatal(err)
				}
			}
			before, err := f.sealed.store.GetUserMonitorBroadcastV2OutcomeStatus(r.confirmRequestID, r.PreviewID)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.sealed.store.ReportUserMonitorBroadcastV2RecipientOutcomes(userMonitorOutcomeInput(f, r, report))
			if scenario == "exact" {
				if err != nil || got[0].State != UserMonitorBroadcastV2OutcomeAccepted || got[0].Evidence != UserMonitorBroadcastV2EvidenceRelay {
					t.Fatalf("sameNode persisted Relay was not authoritative: %+v %v", got, err)
				}
			} else {
				if !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
					t.Fatalf("inexact Relay evidence accepted: %v", err)
				}
				after, err := f.sealed.store.GetUserMonitorBroadcastV2OutcomeStatus(r.confirmRequestID, r.PreviewID)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("denied Relay evidence changed durable outcome")
				}
			}
		})
	}
}
