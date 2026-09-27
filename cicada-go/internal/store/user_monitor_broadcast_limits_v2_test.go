package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func sha256Digest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestUserMonitorBroadcastV2IntakeLimitRetryAndExpiry(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("visibly synthetic bounded intake")
	var last *UserMonitorBroadcastV2
	var lastRequestID string
	for i := 0; i < userMonitorBroadcastV2MaxLivePreviewsPerDevice; i++ {
		last, lastRequestID = f.prepare(t, body)
	}

	// Exact idempotent retries resolve before admission, even when the device
	// has reached its live limit.
	h := sha256Digest(body)
	retry, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: lastRequestID, GroupID: f.sealed.groupID,
		MonitorEndpointID: f.sealed.source.id, BodyDigest: h,
	})
	if err != nil || retry.PreviewID != last.PreviewID {
		t.Fatalf("exact retry consumed admission capacity: preview=%+v err=%v", retry, err)
	}
	before := countUserMonitorBroadcastSnapshots(t, f)
	requestID := f.acceptedRequest(t)
	if _, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: requestID, GroupID: f.sealed.groupID,
		MonitorEndpointID: f.sealed.source.id, BodyDigest: h,
	}); !errors.Is(err, ErrUserMonitorBroadcastV2Backpressure) {
		t.Fatalf("device intake limit did not return generic backpressure: %v", err)
	}
	if after := countUserMonitorBroadcastSnapshots(t, f); after != before {
		t.Fatalf("backpressured request created a recipient snapshot: before=%d after=%d", before, after)
	}

	if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE preview_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), last.PreviewID); err != nil {
		t.Fatal(err)
	}
	requestID = f.acceptedRequest(t)
	if _, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: requestID, GroupID: f.sealed.groupID,
		MonitorEndpointID: f.sealed.source.id, BodyDigest: h,
	}); err != nil {
		t.Fatalf("expired preview continued consuming live capacity: %v", err)
	}
}

func TestUserMonitorBroadcastV2OwnerLimitCountsRevokedDevicesUntilExpiry(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	base, _ := f.prepare(t, []byte("visibly synthetic owner intake seed"))
	devices := []*ClientDevice{f.deviceRecord}
	for i := 0; i < 3; i++ {
		deviceID := fmt.Sprintf("phone_synthetic_limit_%d", i)
		devices = append(devices, registerSyntheticMonitorDevice(t, f, deviceID))
	}
	if len(devices) != 4 {
		t.Fatal("expected four synthetic intake devices")
	}
	// The first actual preview uses one slot. Seed the remaining rows as
	// PREPARED ledger reservations to exercise owner-wide admission without
	// spending time sealing 63 synthetic payloads.
	if err := seedPreparedMonitorPreviews(f, base, devices[0], userMonitorBroadcastV2MaxLivePreviewsPerDevice-1); err != nil {
		t.Fatal(err)
	}
	for _, device := range devices[1:] {
		if err := seedPreparedMonitorPreviews(f, base, device, userMonitorBroadcastV2MaxLivePreviewsPerDevice); err != nil {
			t.Fatal(err)
		}
	}
	otherDevice := registerSyntheticMonitorDevice(t, f, "phone_synthetic_limit_other")
	if err := checkMonitorIntake(f, otherDevice.DeviceID, time.Now().UTC()); !errors.Is(err, ErrUserMonitorBroadcastV2Backpressure) {
		t.Fatalf("owner-wide intake cap did not block a fifth device: %v", err)
	}
	if _, err := f.sealed.store.RevokeClientDevice(f.sealed.ownerID, devices[0].DeviceID, devices[0].Version); err != nil {
		t.Fatal(err)
	}
	if err := checkMonitorIntake(f, otherDevice.DeviceID, time.Now().UTC()); !errors.Is(err, ErrUserMonitorBroadcastV2Backpressure) {
		t.Fatalf("revoking a device freed unexpired intake slots: %v", err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE owner_id=? AND device_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), f.sealed.ownerID, devices[0].DeviceID); err != nil {
		t.Fatal(err)
	}
	if err := checkMonitorIntake(f, otherDevice.DeviceID, time.Now().UTC()); err != nil {
		t.Fatalf("expired reservations continued consuming owner capacity: %v", err)
	}
}

func TestUserMonitorBroadcastV2NoticeCursorPagesLegacyRowsAndSurvivesRestart(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("visibly synthetic rotating notice")
	base, _ := f.prepare(t, body)
	approved, _ := f.confirm(t, base, body, 1)
	if err := seedTerminalMonitorNotices(f, approved, userMonitorBroadcastV2NoticeScanPage*2); err != nil {
		t.Fatal(err)
	}

	list := func() []UserMonitorBroadcastV2Notification {
		t.Helper()
		notices, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(f.sealed.sourceNode.nodeCredential, 16)
		if err != nil {
			t.Fatal(err)
		}
		return notices
	}
	assertCursorProgress := func(want int) {
		t.Helper()
		var cursor userMonitorBroadcastV2NoticeCursor
		if err := f.sealed.store.db.QueryRow(`SELECT owner_id,last_expiry_julian,last_preview_id
FROM user_monitor_broadcast_v2_notice_cursors WHERE node_id=?`, f.sealed.source.nodeID).
			Scan(&cursor.ownerID, &cursor.expiryJulian, &cursor.previewID); err != nil {
			t.Fatal(err)
		}
		var count int
		err := f.sealed.store.db.QueryRow(`SELECT count(*) FROM user_monitor_broadcast_v2
WHERE owner_id=? AND status IN ('APPROVED','DISPATCH_AUTHORIZED')
 AND julianday(expires_at)>julianday(?)
 AND (julianday(expires_at),preview_id)<=(?,?)`, f.sealed.ownerID,
			time.Now().UTC().Format(time.RFC3339Nano), cursor.expiryJulian, cursor.previewID).Scan(&count)
		if err != nil || count != want {
			t.Fatalf("cursor moved across %d active candidates, want %d: err=%v", count, want, err)
		}
	}
	if got := list(); len(got) != 0 {
		t.Fatalf("terminal legacy rows produced notices: %+v", got)
	}
	assertCursorProgress(userMonitorBroadcastV2NoticeScanPage)

	oldStore := f.sealed.store
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	if got := list(); len(got) != 0 {
		t.Fatalf("second legacy page produced terminal notices: %+v", got)
	}
	assertCursorProgress(userMonitorBroadcastV2NoticeScanPage * 2)
	got := list()
	if len(got) != 1 || got[0].PreviewID != approved.PreviewID {
		t.Fatalf("valid notice beyond terminal legacy pages was starved: %+v", got)
	}
}

func TestUserMonitorBroadcastV2PendingCursorEntryRepeatsAcrossCallsAndRestart(t *testing.T) {
	f, r := approvedUserMonitorDeliveryFixture(t)
	list := func() []UserMonitorBroadcastV2Notification {
		t.Helper()
		notices, err := f.sealed.store.ListUserMonitorBroadcastV2Notifications(f.sealed.sourceNode.nodeCredential, 16)
		if err != nil {
			t.Fatal(err)
		}
		return notices
	}
	for i := 0; i < 2; i++ {
		if notices := list(); len(notices) != 1 || notices[0].PreviewID != r.PreviewID {
			t.Fatalf("pending cursor record disappeared on call %d: %+v", i+1, notices)
		}
	}
	oldStore := f.sealed.store
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	if notices := list(); len(notices) != 1 || notices[0].PreviewID != r.PreviewID {
		t.Fatalf("restart turned a scheduling cursor into a lost notification: %+v", notices)
	}
}

func TestUserMonitorBroadcastV2LimitsMigration34PreservesLedger(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	r, _ := f.prepare(t, []byte("visibly synthetic migration preservation"))
	oldStore := f.sealed.store
	if err := oldStore.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DELETE FROM schema_migrations_v2 WHERE version=34`,
		`DROP TABLE user_monitor_broadcast_v2_notice_cursors`,
		`DROP INDEX user_monitor_broadcast_v2_live_device_expiry_idx`,
		`DROP INDEX user_monitor_broadcast_v2_live_owner_expiry_idx`,
		`DROP INDEX user_monitor_broadcast_v2_notice_scan_idx`,
		`ALTER TABLE user_monitor_broadcast_v2 DROP COLUMN preview_json`,
		`ALTER TABLE user_monitor_broadcast_v2 DROP COLUMN consent_digest`,
		`CREATE INDEX user_monitor_broadcast_v2_active_notice_idx ON user_monitor_broadcast_v2(owner_id,status,julianday(expires_at),approved_at,preview_id) WHERE status IN ('APPROVED','DISPATCH_AUTHORIZED')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatalf("prepare synthetic v33 database with %q: %v", statement, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	var status string
	if err := reopened.db.QueryRow(`SELECT status FROM user_monitor_broadcast_v2 WHERE preview_id=?`, r.PreviewID).Scan(&status); err != nil || status != UserMonitorBroadcastV2Prepared {
		t.Fatalf("v34 migration lost an existing Monitor preview: status=%q err=%v", status, err)
	}
	if columns, err := existingColumns(reopened.db, "user_monitor_broadcast_v2", []string{"consent_digest", "preview_json"}); err != nil || len(columns) != 2 {
		t.Fatalf("v34 migration did not restore additive consent columns: %v %v", columns, err)
	}
	for _, index := range []string{"user_monitor_broadcast_v2_live_device_expiry_idx", "user_monitor_broadcast_v2_live_owner_expiry_idx", "user_monitor_broadcast_v2_notice_scan_idx"} {
		var count int
		if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&count); err != nil || count != 1 {
			t.Fatalf("v34 index %q was not installed: count=%d err=%v", index, count, err)
		}
	}
	var oldIndexCount int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='user_monitor_broadcast_v2_active_notice_idx'`).Scan(&oldIndexCount); err != nil || oldIndexCount != 0 {
		t.Fatalf("migration retained redundant notice index: count=%d err=%v", oldIndexCount, err)
	}
}

func countUserMonitorBroadcastSnapshots(t *testing.T, f *userMonitorBroadcastFixture) int {
	t.Helper()
	var count int
	if err := f.sealed.store.db.QueryRow(`SELECT count(*) FROM group_broadcast_v2_snapshots`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func registerSyntheticMonitorDevice(t *testing.T, f *userMonitorBroadcastFixture, deviceID string) *ClientDevice {
	t.Helper()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.sealed.owner.SignOwnerDeviceGrant(f.sealed.ownerID, deviceID,
		identity.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: f.sealed.ownerID, OwnerKeyID: f.sealed.ownerKeyID, DeviceID: deviceID,
		DevicePublic: identity.Public(), OwnerDeviceGrant: grant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func checkMonitorIntake(f *userMonitorBroadcastFixture, deviceID string, nowTime time.Time) error {
	tx, err := f.sealed.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return checkUserMonitorBroadcastV2IntakeTx(tx, f.sealed.ownerID, deviceID, nowTime)
}

func seedPreparedMonitorPreviews(f *userMonitorBroadcastFixture, base *UserMonitorBroadcastV2,
	device *ClientDevice, count int) error {
	tx, err := f.sealed.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := 0; i < count; i++ {
		broadcastID, previewID, requestID := NewID("bcast"), NewID("umbprev"), NewID("clientreq")
		sequence := int64(1000 + i + len(device.DeviceID)*100)
		if _, err := tx.Exec(`INSERT INTO client_device_requests_v2
(id,owner_id,device_id,session_epoch,sequence,operation_id,ciphertext_digest,status,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,'PROCESSING',?,?)`, requestID, device.OwnerID, device.DeviceID, device.SessionEpoch,
			sequence, NewID("op"), strings.Repeat("a", 64), time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		snapshot := *base.Snapshot
		snapshot.BroadcastID = broadcastID
		if err := insertSameGroupBroadcastV2SnapshotTx(tx, &snapshot); err != nil {
			return err
		}
		expiresAt := time.Now().UTC().Add(UserMonitorBroadcastV2TTL).Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO user_monitor_broadcast_v2
(preview_id,broadcast_id,prepare_request_id,owner_id,device_id,session_epoch,client_key_version,group_id,
monitor_endpoint_id,monitor_key_id,body_digest,snapshot_digest,expires_at,status)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'PREPARED')`, previewID, broadcastID, requestID, device.OwnerID,
			device.DeviceID, device.SessionEpoch, device.KeyVersion, base.GroupID, base.MonitorEndpointID,
			base.MonitorKeyID, base.BodyDigest, snapshot.SnapshotDigest, expiresAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func seedTerminalMonitorNotices(f *userMonitorBroadcastFixture, base *UserMonitorBroadcastV2, count int) error {
	tx, err := f.sealed.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := 0; i < count; i++ {
		broadcastID, previewID := NewID("bcast"), NewID("umbprev")
		prepareRequestID, confirmRequestID := NewID("clientreq"), NewID("clientreq")
		for j, requestID := range []string{prepareRequestID, confirmRequestID} {
			sequence := int64(2000 + i*2 + j)
			if _, err := tx.Exec(`INSERT INTO client_device_requests_v2
(id,owner_id,device_id,session_epoch,sequence,operation_id,ciphertext_digest,status,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,'PROCESSING',?,?)`, requestID, base.OwnerID, base.DeviceID, base.SessionEpoch,
				sequence, NewID("op"), strings.Repeat("b", 64), time.Now().UTC().Format(time.RFC3339Nano),
				time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				return err
			}
		}
		snapshot := *base.Snapshot
		snapshot.BroadcastID = broadcastID
		// Alternate synthetic legacy rows route to a foreign Node. They are
		// in the same owner ledger page but must not be exposed to this Node.
		if i%2 == 0 {
			snapshot.Source.NodeID = "node_synthetic_foreign"
		}
		if err := insertSameGroupBroadcastV2SnapshotTx(tx, &snapshot); err != nil {
			return err
		}
		expiresAt := time.Now().UTC().Add(2*time.Minute + time.Duration(i)*time.Second).Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO user_monitor_broadcast_v2
(preview_id,broadcast_id,prepare_request_id,confirm_request_id,owner_id,device_id,session_epoch,
client_key_version,group_id,monitor_endpoint_id,monitor_key_id,body_digest,snapshot_digest,expires_at,
status,approved_at,sealed_payload,sealed_payload_digest,sealed_sequence)
SELECT ?,?,?,?,owner_id,device_id,session_epoch,client_key_version,group_id,monitor_endpoint_id,monitor_key_id,
body_digest,snapshot_digest,?,'APPROVED',approved_at,sealed_payload,sealed_payload_digest,0
FROM user_monitor_broadcast_v2 WHERE preview_id=?`, previewID, broadcastID, prepareRequestID,
			confirmRequestID, expiresAt, base.PreviewID); err != nil {
			return err
		}
		source := snapshot.Source
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO user_monitor_broadcast_v2_notice_receipts
(preview_id,node_id,binding_id,binding_epoch,snapshot_digest,receipt_state,first_reported_at,updated_at)
VALUES(?,?,?,?,?,'FAILED',?,?)`, previewID, source.NodeID, source.BindingID, source.BindingEpoch,
			base.SnapshotDigest, stamp, stamp); err != nil {
			return err
		}
	}
	return tx.Commit()
}
