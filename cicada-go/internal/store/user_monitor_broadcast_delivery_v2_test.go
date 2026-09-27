package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func approvedUserMonitorDeliveryFixture(t *testing.T) (*userMonitorBroadcastFixture, *UserMonitorBroadcastV2) {
	t.Helper()
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("visibly synthetic Monitor delivery body")
	r, _ := f.prepare(t, body)
	approved, _ := f.confirm(t, r, body, 1)
	return f, approved
}

func storedSyntheticEnrollmentProof(t *testing.T, f *userMonitorBroadcastFixture) []byte {
	t.Helper()
	var proof []byte
	if err := f.sealed.store.db.QueryRow(`SELECT grant_bytes FROM client_device_enrollment_proofs_v2
WHERE owner_id=? AND device_id=?`, f.sealed.ownerID, f.deviceRecord.DeviceID).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestUserMonitorBroadcastV2DeliveryCarriesVerifiedOriginalEnrollment(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	input := f.consumeInput(r)
	delivery, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.OperationID != input.OperationID || delivery.Context.ApprovalID != r.PreviewID ||
		delivery.Context.BroadcastID != r.BroadcastID || delivery.Context.BodySHA256 != r.BodyDigest ||
		delivery.Context.RecipientSnapshotSHA256 != r.SnapshotDigest ||
		delivery.Snapshot.BroadcastID != r.BroadcastID || delivery.OwnerKeyID != f.sealed.ownerKeyID ||
		!reflect.DeepEqual(delivery.ClientPublic, f.device.Public()) ||
		!bytes.Equal(delivery.OwnerDeviceGrant, storedSyntheticEnrollmentProof(t, f)) {
		t.Fatalf("delivery evidence did not bind original enrollment or operation: %+v", delivery.Context)
	}
	enrolledAt, err := time.Parse(time.RFC3339Nano, delivery.EnrolledAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerDeviceGrant(delivery.OwnerDeviceGrant, f.sealed.owner.Public(),
		delivery.ClientPublic, r.OwnerID, delivery.OwnerKeyID, r.DeviceID, delivery.Context.HubID,
		e2ee.OwnerDevicePurposeControl, enrolledAt); err != nil {
		t.Fatalf("Node could not verify original owner proof: %v", err)
	}
	if seq, err := e2ee.VerifyMonitorBroadcast(delivery.SealedPayload, delivery.ClientPublic,
		delivery.Snapshot.Source.PublicKey, delivery.Context); err != nil || seq != delivery.SealedSequence {
		t.Fatalf("delivery envelope no longer verifies: seq=%d err=%v", seq, err)
	}
	if len(delivery.SealedPayload) == 0 || bytes.Contains(delivery.SealedPayload, []byte("visibly synthetic Monitor delivery body")) {
		t.Fatal("delivery is empty or contains plaintext")
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); err != nil {
		t.Fatalf("exact bundle retry failed: %v", err)
	}
}

type userMonitorBroadcastReviewState struct {
	status, operationID, authorizedAt, approvedAt            string
	expiresAt, sealedDigest, confirmRequestID, confirmStatus string
	consumeNodeID, consumeBindingID                          string
	consumeBindingEpoch, sealedSequence                      int64
	outcomes, noticeReceipts                                 int64
	relayRequests, relayOutbox, relayInbox, relayReceipts    int64
	outcomeRows                                              []UserMonitorBroadcastV2RecipientOutcome
}

func captureUserMonitorBroadcastReviewState(t *testing.T, f *userMonitorBroadcastFixture,
	r *UserMonitorBroadcastV2) userMonitorBroadcastReviewState {
	t.Helper()
	var state userMonitorBroadcastReviewState
	err := f.sealed.store.db.QueryRow(`SELECT status,operation_id,dispatch_authorized_at,approved_at,expires_at,
sealed_payload_digest,sealed_sequence,COALESCE(confirm_request_id,''),consume_node_id,consume_binding_id,
consume_binding_epoch
FROM user_monitor_broadcast_v2 WHERE preview_id=?`, r.PreviewID).Scan(
		&state.status, &state.operationID, &state.authorizedAt, &state.approvedAt, &state.expiresAt,
		&state.sealedDigest, &state.sealedSequence, &state.confirmRequestID, &state.consumeNodeID,
		&state.consumeBindingID, &state.consumeBindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.db.QueryRow(`SELECT request.status FROM client_device_requests_v2 request
JOIN user_monitor_broadcast_v2 approval ON approval.confirm_request_id=request.id
WHERE approval.preview_id=?`, r.PreviewID).
		Scan(&state.confirmStatus); err != nil {
		t.Fatal(err)
	}
	for table, target := range map[string]*int64{
		"user_monitor_broadcast_v2_recipient_outcomes": &state.outcomes,
		"user_monitor_broadcast_v2_notice_receipts":    &state.noticeReceipts,
		"relay_v2_requests":                            &state.relayRequests,
		"relay_v2_outbox":                              &state.relayOutbox,
		"relay_v2_inbox":                               &state.relayInbox,
		"relay_v2_receipts":                            &state.relayReceipts,
	} {
		if err := f.sealed.store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(target); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
	}
	tx, err := f.sealed.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	state.outcomeRows, err = readUserMonitorOutcomesTx(tx, r.PreviewID)
	if rollbackErr := tx.Rollback(); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func previewUserMonitorBroadcastInput(input AuthorizeUserMonitorBroadcastV2Input) PreviewUserMonitorBroadcastV2Input {
	return PreviewUserMonitorBroadcastV2Input{NodeCredentialDigest: input.NodeCredentialDigest,
		SessionCredentialDigest: input.SessionCredentialDigest, PreviewID: input.PreviewID}
}

func TestUserMonitorBroadcastV2ReviewDoesNotConsumeApprovalOrMutateDeliveryLedgers(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	input := f.consumeInput(r)
	previewInput := previewUserMonitorBroadcastInput(input)
	before := captureUserMonitorBroadcastReviewState(t, f, r)
	if before.status != UserMonitorBroadcastV2Approved || before.outcomes != 0 || before.noticeReceipts != 0 ||
		before.relayRequests != 0 || before.relayOutbox != 0 || before.relayInbox != 0 || before.relayReceipts != 0 {
		t.Fatalf("fixture was not an unconsumed approval: %+v", before)
	}
	first, err := f.sealed.store.PreviewUserMonitorBroadcastV2Delivery(previewInput)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.sealed.store.PreviewUserMonitorBroadcastV2Delivery(previewInput)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated review changed evidence: err=%v", err)
	}
	if bytes.Contains(first.SealedPayload, []byte("visibly synthetic Monitor delivery body")) ||
		first.OperationID != input.OperationID || first.Context.ApprovalID != r.PreviewID ||
		first.Context.BroadcastID != r.BroadcastID || first.Snapshot.SnapshotDigest != r.SnapshotDigest {
		t.Fatal("review did not return only the exact opaque approval evidence")
	}
	if after := captureUserMonitorBroadcastReviewState(t, f, r); !reflect.DeepEqual(before, after) {
		t.Fatalf("review mutated approval, Client replay status, relay, receipt, or outcome ledger: before=%+v after=%+v", before, after)
	}
	authorized, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input)
	if err != nil || !reflect.DeepEqual(first, authorized) {
		t.Fatalf("review consumed or changed the exact approval before dispatch: err=%v", err)
	}
	dispatched := captureUserMonitorBroadcastReviewState(t, f, r)
	if dispatched.status != UserMonitorBroadcastV2DispatchAuthorized || dispatched.operationID != input.OperationID ||
		dispatched.outcomes != int64(len(first.Snapshot.Recipients)) {
		t.Fatalf("expected dispatch to reserve outcomes exactly once: %+v", dispatched)
	}
	afterDispatch, err := f.sealed.store.PreviewUserMonitorBroadcastV2Delivery(previewInput)
	if err != nil || !reflect.DeepEqual(first, afterDispatch) {
		t.Fatalf("read-only review could not recover exact authorized evidence: err=%v", err)
	}
	if after := captureUserMonitorBroadcastReviewState(t, f, r); !reflect.DeepEqual(dispatched, after) {
		t.Fatalf("post-dispatch review rewrote delivery ledger: before=%+v after=%+v", dispatched, after)
	}
}

func TestUserMonitorBroadcastV2ReviewRequiresCurrentGuard(t *testing.T) {
	for _, scenario := range []string{"wrong Node", "wrong Session", "expired preview", "revoked device", "source role revoked", "recipient revoked", "recipient key proof changed", "snapshot digest changed"} {
		t.Run(scenario, func(t *testing.T) {
			f, r := approvedUserMonitorDeliveryFixture(t)
			input := previewUserMonitorBroadcastInput(f.consumeInput(r))
			switch scenario {
			case "wrong Node":
				input.NodeCredentialDigest = f.sealed.targetNode.nodeCredential
			case "wrong Session":
				input.SessionCredentialDigest = sameGroupBroadcastV2CredentialDigest("session_foreign")
			case "expired preview":
				if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE preview_id=?`,
					time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), r.PreviewID); err != nil {
					t.Fatal(err)
				}
			case "revoked device":
				if _, err := f.sealed.store.RevokeClientDevice(r.OwnerID, r.DeviceID, f.deviceRecord.Version); err != nil {
					t.Fatal(err)
				}
			case "source role revoked":
				membership, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, r.GroupID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.sealed.store.UpdateMembershipAuthorization(membership.ID,
					[]string{"worker"}, membership.Grants, membership.Authorization, membership.Version); err != nil {
					t.Fatal(err)
				}
			case "recipient revoked":
				if _, err := f.sealed.store.RevokeMembershipForPrincipalGroup(f.sealed.target.principal,
					r.GroupID, "synthetic review recipient revocation"); err != nil {
					t.Fatal(err)
				}
			case "recipient key proof changed":
				tampered := []byte("synthetic-invalid-owner-proof")
				if _, err := f.sealed.store.db.Exec(`UPDATE group_endpoint_key_grants_v2 SET signed_proof=?
WHERE owner_id=? AND group_id=? AND endpoint_id=?`, tampered, r.OwnerID, r.GroupID, f.sealed.target.id); err != nil {
					t.Fatal(err)
				}
			case "snapshot digest changed":
				if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET snapshot_digest=? WHERE preview_id=?`,
					strings.Repeat("0", 64), r.PreviewID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.sealed.store.PreviewUserMonitorBroadcastV2Delivery(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) &&
				!errors.Is(err, ErrUserMonitorBroadcastV2Expired) {
				t.Fatalf("stale or foreign current Guard received evidence: %v", err)
			}
		})
	}
}

func TestUserMonitorBroadcastV2ReviewThenSessionFenceBlocksDispatch(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	authorizeInput := f.consumeInput(r)
	preview, err := f.sealed.store.PreviewUserMonitorBroadcastV2Delivery(previewUserMonitorBroadcastInput(authorizeInput))
	if err != nil || preview.OperationID != authorizeInput.OperationID {
		t.Fatalf("initial current review failed: delivery=%#v err=%v", preview, err)
	}
	if _, err := f.sealed.store.FenceSessionBinding(f.sealed.source.binding.ID,
		f.sealed.source.binding.Epoch, SessionBindingStatusSuperseded); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(authorizeInput); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("dispatch ignored the Monitor Session fence after preview: %v", err)
	}
}

func TestUserMonitorBroadcastV2HistoricalMissingProofFailsClosedUntilExactRetry(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	proof := storedSyntheticEnrollmentProof(t, f)
	if _, err := f.sealed.store.db.Exec(`DELETE FROM client_device_enrollment_proofs_v2 WHERE owner_id=? AND device_id=?`,
		r.OwnerID, r.DeviceID); err != nil {
		t.Fatal(err)
	}
	input := f.consumeInput(r)
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("historical device without proof received delivery: %v", err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("legacy authorization method bypassed missing proof: %v", err)
	}
	if list, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(input.NodeCredentialDigest, 16); err != nil || len(list) != 0 {
		t.Fatalf("historical missing proof produced Node notification: count=%d err=%v", len(list), err)
	}
	tampered := append([]byte(nil), proof...)
	tampered[len(tampered)-1] ^= 1
	if _, err := f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: r.OwnerID, OwnerKeyID: f.sealed.ownerKeyID, DeviceID: r.DeviceID,
		DevicePublic: f.device.Public(), OwnerDeviceGrant: tampered}); err == nil {
		t.Fatal("tampered retry recovered missing proof")
	}
	if _, err := f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: r.OwnerID, OwnerKeyID: f.sealed.ownerKeyID, DeviceID: r.DeviceID,
		DevicePublic: f.device.Public(), OwnerDeviceGrant: proof}); err != nil {
		t.Fatalf("exact old signed grant did not recover evidence: %v", err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); err != nil {
		t.Fatalf("recovered proof did not authorize delivery: %v", err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE client_device_enrollment_proofs_v2 SET grant_bytes=? WHERE owner_id=? AND device_id=?`,
		tampered, r.OwnerID, r.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("tampered persisted proof authorized delivery: %v", err)
	}
}

func TestUserMonitorBroadcastV2NodeNoticeScopeAndReceipts(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	input := f.consumeInput(r)
	notices, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(input.NodeCredentialDigest, 100)
	if err != nil || len(notices) != 1 {
		t.Fatalf("approved Node notice missing: count=%d err=%v", len(notices), err)
	}
	n := notices[0]
	if n.HubID == "" || n.PreviewID != r.PreviewID || n.BroadcastID != r.BroadcastID ||
		n.NodeID != f.sealed.source.nodeID || n.NativeSessionID != f.sealed.source.binding.NativeSessionID ||
		n.BindingID != f.sealed.source.binding.ID || n.BindingEpoch != f.sealed.source.binding.Epoch ||
		n.ReceiptState != UserMonitorBroadcastV2NoticePending {
		t.Fatalf("notice lacks exact route: %+v", n)
	}
	other, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(f.sealed.targetNode.nodeCredential, 16)
	if err != nil || len(other) != 0 {
		t.Fatalf("wrong Node enumerated notice: count=%d err=%v", len(other), err)
	}
	if _, err := f.sealed.store.GetUserMonitorBroadcastV2Notification(f.sealed.targetNode.nodeCredential, r.PreviewID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("wrong Node read notice: %v", err)
	}
	receipt := UserMonitorBroadcastV2NotificationReceiptInput{NodeCredentialDigest: input.NodeCredentialDigest,
		PreviewID: r.PreviewID, BroadcastID: r.BroadcastID, SnapshotDigest: r.SnapshotDigest,
		BindingID: n.BindingID, BindingEpoch: n.BindingEpoch, State: UserMonitorBroadcastV2NoticeNodeAccepted}
	bad := receipt
	bad.BindingEpoch++
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(bad); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("stale binding receipt persisted: %v", err)
	}
	bad = receipt
	bad.NodeCredentialDigest = f.sealed.targetNode.nodeCredential
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(bad); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("wrong Node receipt persisted: %v", err)
	}
	if got, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); err != nil || got.ReceiptState != UserMonitorBroadcastV2NoticeNodeAccepted {
		t.Fatalf("Node receipt failed: %+v %v", got, err)
	}
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); err != nil {
		t.Fatalf("duplicate Node receipt failed: %v", err)
	}
	receipt.State = UserMonitorBroadcastV2NoticeQueueAccepted
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); err != nil {
		t.Fatalf("queue receipt failed: %v", err)
	}
	receipt.State = UserMonitorBroadcastV2NoticeNodeAccepted
	if got, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); err != nil || got.ReceiptState != UserMonitorBroadcastV2NoticeQueueAccepted {
		t.Fatalf("late lower receipt regressed status: %+v %v", got, err)
	}
	if notices, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(input.NodeCredentialDigest, 16); err != nil || len(notices) != 0 {
		t.Fatalf("terminal queue notice relisted: count=%d err=%v", len(notices), err)
	}
	got, err := f.sealed.store.GetUserMonitorBroadcastV2Notification(input.NodeCredentialDigest, r.PreviewID)
	if err != nil || got.ReceiptState != UserMonitorBroadcastV2NoticeQueueAccepted {
		t.Fatalf("terminal notice not queryable: %+v %v", got, err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); err != nil {
		t.Fatalf("queue receipt incorrectly blocked MCP approval: %v", err)
	}
	receipt.State = UserMonitorBroadcastV2NoticeInjectionUncertain
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); !errors.Is(err, ErrUserMonitorBroadcastV2Conflict) {
		t.Fatalf("terminal queue receipt replaced: %v", err)
	}
}

func TestUserMonitorBroadcastV2NoticeRejectsStaleAuthAndExpires(t *testing.T) {
	for _, scenario := range []string{"recipient revoked", "device revoked", "expiry", "Node revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f, r := approvedUserMonitorDeliveryFixture(t)
			input := f.consumeInput(r)
			switch scenario {
			case "recipient revoked":
				if _, err := f.sealed.store.RevokeMembershipForPrincipalGroup(f.sealed.target.principal, r.GroupID, "synthetic"); err != nil {
					t.Fatal(err)
				}
			case "device revoked":
				if _, err := f.sealed.store.RevokeClientDevice(r.OwnerID, r.DeviceID, f.deviceRecord.Version); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE preview_id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), r.PreviewID); err != nil {
					t.Fatal(err)
				}
			case "Node revoked":
				if _, err := f.sealed.store.db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED' WHERE node_id=?`, f.sealed.source.nodeID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.sealed.store.GetUserMonitorBroadcastV2Notification(input.NodeCredentialDigest, r.PreviewID); err == nil {
				t.Fatal("stale notice remained available")
			}
			if notices, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(input.NodeCredentialDigest, 16); scenario != "Node revoked" && (err != nil || len(notices) != 0) {
				t.Fatalf("stale notice listed: count=%d err=%v", len(notices), err)
			}
			if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); err == nil {
				t.Fatal("stale bundle authorized")
			}
		})
	}
}

func TestUserMonitorBroadcastV2FailedNoticeIsTerminalButNotApproval(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	input := f.consumeInput(r)
	notice, err := f.sealed.store.GetUserMonitorBroadcastV2Notification(input.NodeCredentialDigest, r.PreviewID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := UserMonitorBroadcastV2NotificationReceiptInput{NodeCredentialDigest: input.NodeCredentialDigest,
		PreviewID: r.PreviewID, BroadcastID: r.BroadcastID, SnapshotDigest: r.SnapshotDigest,
		BindingID: notice.BindingID, BindingEpoch: notice.BindingEpoch, State: UserMonitorBroadcastV2NoticeNodeAccepted}
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	receipt.State = UserMonitorBroadcastV2NoticeFailed
	got, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt)
	if err != nil || got.ReceiptState != UserMonitorBroadcastV2NoticeFailed {
		t.Fatalf("definitely-not-started receipt failed: %+v %v", got, err)
	}
	if list, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(input.NodeCredentialDigest, 16); err != nil || len(list) != 0 {
		t.Fatalf("FAILED notice requeued: count=%d err=%v", len(list), err)
	}
	if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); err != nil {
		t.Fatalf("FAILED notification revoked independent approved MCP action: %v", err)
	}
	receipt.State = UserMonitorBroadcastV2NoticeQueueAccepted
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); !errors.Is(err, ErrUserMonitorBroadcastV2Conflict) {
		t.Fatalf("FAILED receipt changed to queue accepted: %v", err)
	}
}

func TestUserMonitorBroadcastV2ReceiptRejectsStaleSessionEpoch(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	input := f.consumeInput(r)
	notice, err := f.sealed.store.GetUserMonitorBroadcastV2Notification(input.NodeCredentialDigest, r.PreviewID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := UserMonitorBroadcastV2NotificationReceiptInput{NodeCredentialDigest: input.NodeCredentialDigest,
		PreviewID: r.PreviewID, BroadcastID: r.BroadcastID, SnapshotDigest: r.SnapshotDigest,
		BindingID: notice.BindingID, BindingEpoch: notice.BindingEpoch, State: UserMonitorBroadcastV2NoticeNodeAccepted}
	if _, err := f.sealed.store.RotateSessionBindingCredential(notice.BindingID, notice.BindingEpoch,
		sameGroupBroadcastV2CredentialDigest("synthetic_new_monitor_session"),
		"lease_"+f.sealed.source.id, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.RecordUserMonitorBroadcastV2NotificationReceipt(receipt); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("stale native owner wrote receipt after epoch rotation: %v", err)
	}
	var count int
	if err := f.sealed.store.db.QueryRow(`SELECT count(*) FROM user_monitor_broadcast_v2_notice_receipts WHERE preview_id=?`, r.PreviewID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale receipt persisted %d rows", count)
	}
}

func TestUserMonitorBroadcastV2Migration31To32PreservesDeviceAndFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v31.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrincipal(Principal{ID: "synthetic_v31_owner", Kind: PrincipalKindHuman,
		OwnerID: "synthetic_v31_owner", Name: "synthetic_v31_owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE user_monitor_broadcast_v2_notice_receipts`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE client_device_enrollment_proofs_v2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations_v2 WHERE version=32`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entry, err := reopened.readV2Migration(32)
	if err != nil || entry == nil || entry.State != v2MigrationApplied {
		t.Fatalf("schema32 not applied from 31: %+v %v", entry, err)
	}
	var ownerCount, proofCount int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM principals WHERE id='synthetic_v31_owner'`).Scan(&ownerCount); err != nil {
		t.Fatal(err)
	}
	if err := reopened.db.QueryRow(`SELECT count(*) FROM client_device_enrollment_proofs_v2`).Scan(&proofCount); err != nil {
		t.Fatal(err)
	}
	if ownerCount != 1 || proofCount != 0 {
		t.Fatalf("additive migration changed old state or fabricated proofs: owner=%d proofs=%d", ownerCount, proofCount)
	}
}

func TestUserMonitorBroadcastV2DeliveryConcurrentHandlesAndRestart(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	other, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	input := f.consumeInput(r)
	start := make(chan struct{})
	results := make(chan *UserMonitorBroadcastV2Delivery, 2)
	errorsSeen := make(chan error, 2)
	var wg sync.WaitGroup
	for _, s := range []*Store{f.sealed.store, other} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start
			d, err := s.AuthorizeUserMonitorBroadcastV2Delivery(input)
			results <- d
			errorsSeen <- err
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsSeen)
	successes := 0
	for err := range errorsSeen {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("concurrent Store handles both failed to authorize")
	}
	for d := range results {
		if d != nil && d.OperationID != input.OperationID {
			t.Fatalf("concurrent handle minted different operation: %s", d.OperationID)
		}
	}
	if err := f.sealed.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = restarted
	d, err := restarted.AuthorizeUserMonitorBroadcastV2Delivery(input)
	if err != nil || d.OperationID != input.OperationID {
		t.Fatalf("restart did not recover exact operation: %+v %v", d, err)
	}
}
