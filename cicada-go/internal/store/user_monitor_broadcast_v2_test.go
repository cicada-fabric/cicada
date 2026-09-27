package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type userMonitorBroadcastFixture struct {
	*sameGroupBroadcastV2Fixture
	device          *e2ee.Identity
	deviceRecord    *ClientDevice
	requestSequence uint64
}

func newUserMonitorBroadcastFixture(t *testing.T) *userMonitorBroadcastFixture {
	t.Helper()
	b := newSameGroupBroadcastV2Fixture(t)
	m, err := b.sealed.store.GetMembershipByPrincipalGroup(b.sealed.source.principal, b.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"monitor"},
		[]string{"message.receive", "message.send", "message.broadcast"}, m.Authorization, m.Version)
	if err != nil {
		t.Fatal(err)
	}
	b.sealed.grant(t, b.sealed.source.id)
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := b.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := b.sealed.owner.SignOwnerDeviceGrant(b.sealed.ownerID, "phone_synthetic",
		device.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute),
		time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := b.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: b.sealed.ownerID, OwnerKeyID: b.sealed.ownerKeyID, DeviceID: "phone_synthetic",
		DevicePublic: device.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	return &userMonitorBroadcastFixture{sameGroupBroadcastV2Fixture: b, device: device, deviceRecord: registered}
}

func (f *userMonitorBroadcastFixture) acceptedRequest(t *testing.T) string {
	t.Helper()
	f.requestSequence++
	h := sha256.Sum256([]byte(NewID("synthetic_rpc_ciphertext")))
	a, err := f.sealed.store.AcceptClientRequest(AcceptClientRequestInput{
		OwnerID: f.sealed.ownerID, DeviceID: f.deviceRecord.DeviceID,
		SessionEpoch: f.deviceRecord.SessionEpoch, Sequence: f.requestSequence,
		OperationID: NewID("synthetic_rpc"), CiphertextDigest: hex.EncodeToString(h[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a.Request.ID
}

func (f *userMonitorBroadcastFixture) prepare(t *testing.T, body []byte) (*UserMonitorBroadcastV2, string) {
	t.Helper()
	h := sha256.Sum256(body)
	id := f.acceptedRequest(t)
	r, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: id, GroupID: f.sealed.groupID, MonitorEndpointID: f.sealed.source.id,
		BodyDigest: hex.EncodeToString(h[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Existing v1 tests exercise historical rows. New consent-bound rows have
	// their own tests below; an upgrade must keep old signed bytes readable.
	if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET consent_digest='',preview_json='' WHERE preview_id=?`, r.PreviewID); err != nil {
		t.Fatal(err)
	}
	return r, id
}

func (f *userMonitorBroadcastFixture) seal(t *testing.T, r *UserMonitorBroadcastV2, body []byte, sequence uint64) []byte {
	t.Helper()
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	ctx := e2ee.MonitorBroadcastContext{HubID: hubID, OwnerID: r.OwnerID,
		ClientDeviceID: r.DeviceID, ClientSessionEpoch: r.SessionEpoch, ClientKeyVersion: r.ClientKeyVersion,
		ApprovalID: r.PreviewID, BroadcastID: r.BroadcastID, GroupID: r.GroupID,
		MonitorEndpointID: r.MonitorEndpointID, MonitorKeyID: r.Snapshot.Source.KeyID,
		MonitorBindingID:    r.Snapshot.Source.BindingID,
		MonitorBindingEpoch: r.Snapshot.Source.BindingEpoch, BodySHA256: r.BodyDigest,
		RecipientSnapshotSHA256: r.SnapshotDigest, ExpiresAt: r.ExpiresAt}
	payload, err := e2ee.SealMonitorBroadcast(f.device, f.sealed.source.identity.Public(), ctx, body, sequence)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func (f *userMonitorBroadcastFixture) confirm(t *testing.T, r *UserMonitorBroadcastV2, body []byte, sequence uint64) (*UserMonitorBroadcastV2, string) {
	t.Helper()
	id := f.acceptedRequest(t)
	confirmed, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: id, PreviewID: r.PreviewID, SnapshotDigest: r.SnapshotDigest,
		BodyDigest: r.BodyDigest, SealedPayload: f.seal(t, r, body, sequence),
	})
	if err != nil {
		t.Fatal(err)
	}
	return confirmed, id
}

func (f *userMonitorBroadcastFixture) consumeInput(r *UserMonitorBroadcastV2) AuthorizeUserMonitorBroadcastV2Input {
	return AuthorizeUserMonitorBroadcastV2Input{NodeCredentialDigest: f.sealed.sourceNode.nodeCredential,
		SessionCredentialDigest: sameGroupBroadcastV2CredentialDigest(f.sessionToken), PreviewID: r.PreviewID,
		BroadcastID: r.BroadcastID, OperationID: "op_" + r.BroadcastID[3:], BodyDigest: r.BodyDigest,
		SnapshotDigest: r.SnapshotDigest}
}

func TestUserMonitorBroadcastV2RequiresMonitorRoleAndAcceptedClientRequest(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	m, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"worker"}, m.Grants, m.Authorization, m.Version)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("synthetic body"))
	in := PrepareUserMonitorBroadcastV2Input{ClientRequestID: f.acceptedRequest(t), GroupID: f.sealed.groupID,
		MonitorEndpointID: f.sealed.source.id, BodyDigest: hex.EncodeToString(h[:])}
	if _, err = f.sealed.store.PrepareUserMonitorBroadcastV2(in); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("worker prepared user broadcast: %v", err)
	}
	in.ClientRequestID = "forged_client_request"
	if _, err = f.sealed.store.PrepareUserMonitorBroadcastV2(in); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("unaccepted request prepared user broadcast: %v", err)
	}
}

func TestUserMonitorBroadcastV2ConfirmBindsDevicePayloadAndImmutableSnapshot(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic broadcast content")
	r, prepareID := f.prepare(t, body)
	if r.Snapshot.Source.EndpointID != f.sealed.source.id || len(r.Snapshot.Recipients) != 2 ||
		r.OwnerID != f.sealed.ownerID || r.DeviceID != f.deviceRecord.DeviceID {
		t.Fatalf("incorrect preview provenance: %+v", r)
	}
	retry, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: prepareID, GroupID: r.GroupID, MonitorEndpointID: r.MonitorEndpointID, BodyDigest: r.BodyDigest})
	if err != nil || retry.PreviewID != r.PreviewID {
		t.Fatalf("prepare retry changed identity: %+v %v", retry, err)
	}
	bad := f.seal(t, r, body, 1)
	bad[len(bad)-1] ^= 1
	confirmID := f.acceptedRequest(t)
	input := ConfirmUserMonitorBroadcastV2Input{ClientRequestID: confirmID, PreviewID: r.PreviewID,
		SnapshotDigest: r.SnapshotDigest, BodyDigest: r.BodyDigest, SealedPayload: bad}
	if _, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("tampered envelope confirmed: %v", err)
	}
	input.SealedPayload = f.seal(t, r, body, 1)
	confirmed, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input)
	if err != nil || confirmed.Status != UserMonitorBroadcastV2Approved || confirmed.SealedPayloadDigest == "" {
		t.Fatalf("confirm failed: %+v %v", confirmed, err)
	}
	if _, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input); err != nil {
		t.Fatalf("exact confirm retry failed: %v", err)
	}
	input.BodyDigest = hex.EncodeToString(sha256.New().Sum(nil))
	if _, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Conflict) {
		t.Fatalf("changed body digest accepted: %v", err)
	}
	status, err := f.sealed.store.GetUserMonitorBroadcastV2Status(f.acceptedRequest(t), r.PreviewID)
	if err != nil || status.SealedPayload != nil || status.Status != UserMonitorBroadcastV2Approved {
		t.Fatalf("status leaked payload or lost state: %+v %v", status, err)
	}
}

func TestUserMonitorBroadcastV2RejectsExpiryRevocationAndRecipientChange(t *testing.T) {
	for _, scenario := range []string{"expiry", "device revoked", "recipient revoked", "monitor role revoked", "key changed"} {
		t.Run(scenario, func(t *testing.T) {
			f := newUserMonitorBroadcastFixture(t)
			body := []byte("synthetic body")
			r, _ := f.prepare(t, body)
			id := f.acceptedRequest(t)
			switch scenario {
			case "expiry":
				_, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE preview_id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), r.PreviewID)
				if err != nil {
					t.Fatal(err)
				}
			case "device revoked":
				if _, err := f.sealed.store.RevokeClientDevice(r.OwnerID, r.DeviceID, f.deviceRecord.Version); err != nil {
					t.Fatal(err)
				}
			case "recipient revoked":
				if _, err := f.sealed.store.RevokeMembershipForPrincipalGroup(f.sealed.target.principal, r.GroupID, "synthetic revoke"); err != nil {
					t.Fatal(err)
				}
			case "monitor role revoked":
				m, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, r.GroupID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"worker"}, m.Grants, m.Authorization, m.Version); err != nil {
					t.Fatal(err)
				}
			case "key changed":
				_, err := f.sealed.store.db.Exec(`UPDATE endpoint_key_candidates_v2 SET version=version+1 WHERE endpoint_id=?`, f.sealed.source.id)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(ConfirmUserMonitorBroadcastV2Input{
				ClientRequestID: id, PreviewID: r.PreviewID, SnapshotDigest: r.SnapshotDigest,
				BodyDigest: r.BodyDigest, SealedPayload: f.seal(t, r, body, 1)})
			if err == nil {
				t.Fatal("stale preview confirmed")
			}
		})
	}
}

func TestUserMonitorBroadcastV2ConsumeIsSingleUseAndDurable(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic body")
	r, _ := f.prepare(t, body)
	confirmed, _ := f.confirm(t, r, body, 1)
	input := f.consumeInput(confirmed)
	consumed, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2(input)
	if err != nil || consumed.Status != UserMonitorBroadcastV2DispatchAuthorized || len(consumed.SealedPayload) == 0 {
		t.Fatalf("authorize failed: %+v %v", consumed, err)
	}
	if err := f.sealed.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	retry, err := reopened.AuthorizeUserMonitorBroadcastV2(input)
	if err != nil || retry.OperationID != input.OperationID || retry.BroadcastID != r.BroadcastID {
		t.Fatalf("restart retry minted another operation: %+v %v", retry, err)
	}
	input.OperationID = "op_00000000000000000000000000000000"
	if _, err := reopened.AuthorizeUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Conflict) {
		t.Fatalf("other operation reused approval: %v", err)
	}
	input = f.consumeInput(confirmed)
	input.NodeCredentialDigest = f.sealed.targetNode.nodeCredential
	if _, err := reopened.AuthorizeUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("wrong Node recovered payload: %v", err)
	}
	input = f.consumeInput(confirmed)
	if _, err := reopened.db.Exec(`UPDATE user_monitor_broadcast_v2 SET expires_at=? WHERE preview_id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), r.PreviewID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.AuthorizeUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Expired) {
		t.Fatalf("expired retry recovered dispatch permission: %v", err)
	}
}

func TestUserMonitorBroadcastV2RejectsDifferentAcceptedClientDevice(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic body")
	r, _ := f.prepare(t, body)
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.sealed.owner.SignOwnerDeviceGrant(f.sealed.ownerID, "phone_other_synthetic", other.Public(),
		hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: f.sealed.ownerID, OwnerKeyID: f.sealed.ownerKeyID, DeviceID: "phone_other_synthetic",
		DevicePublic: other.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("other synthetic request"))
	a, err := f.sealed.store.AcceptClientRequest(AcceptClientRequestInput{
		OwnerID: f.sealed.ownerID, DeviceID: "phone_other_synthetic", SessionEpoch: 1, Sequence: 1,
		OperationID: "other_device_confirm", CiphertextDigest: hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.sealed.store.ConfirmUserMonitorBroadcastV2(ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: a.Request.ID, PreviewID: r.PreviewID, SnapshotDigest: r.SnapshotDigest,
		BodyDigest: r.BodyDigest, SealedPayload: f.seal(t, r, body, 1)})
	if !errors.Is(err, ErrUserMonitorBroadcastV2Conflict) {
		t.Fatalf("different authenticated device confirmed preview: %v", err)
	}
	if _, err := f.sealed.store.GetUserMonitorBroadcastV2Status(a.Request.ID, r.PreviewID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("different device read preview status: %v", err)
	}
}

func TestUserMonitorBroadcastV2DispatchRechecksCurrentGuard(t *testing.T) {
	for _, scenario := range []string{"source binding revoked", "recipient revoked", "Monitor role revoked", "Node binding revoked", "Client epoch rotated"} {
		t.Run(scenario, func(t *testing.T) {
			f := newUserMonitorBroadcastFixture(t)
			body := []byte("synthetic body")
			r, _ := f.prepare(t, body)
			approved, _ := f.confirm(t, r, body, 1)
			switch scenario {
			case "source binding revoked":
				_, err := f.sealed.store.RevokeSessionBinding(f.sealed.source.binding.ID, f.sealed.source.binding.Epoch, "synthetic revoke")
				if err != nil {
					t.Fatal(err)
				}
			case "recipient revoked":
				_, err := f.sealed.store.RevokeMembershipForPrincipalGroup(f.sealed.target.principal, r.GroupID, "synthetic revoke")
				if err != nil {
					t.Fatal(err)
				}
			case "Monitor role revoked":
				m, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.source.principal, r.GroupID)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.sealed.store.UpdateMembershipAuthorization(m.ID, []string{"worker"}, m.Grants, m.Authorization, m.Version)
				if err != nil {
					t.Fatal(err)
				}
			case "Node binding revoked":
				_, err := f.sealed.store.db.Exec(`UPDATE node_owner_bindings_v2 SET state='REVOKED' WHERE node_id=?`, f.sealed.source.nodeID)
				if err != nil {
					t.Fatal(err)
				}
			case "Client epoch rotated":
				_, err := f.sealed.store.AdvanceClientDeviceSessionEpoch(r.OwnerID, r.DeviceID, r.SessionEpoch)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2(f.consumeInput(approved)); err == nil {
				t.Fatal("stale Guard state authorized dispatch")
			}
		})
	}
}

func TestUserMonitorBroadcastV2MigrationFrom30PreservesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration.sqlite3")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrincipal(Principal{ID: "synthetic_migration_owner", Kind: PrincipalKindHuman,
		OwnerID: "synthetic_migration_owner", Name: "synthetic_migration_owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE user_monitor_broadcast_v2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations_v2 WHERE version BETWEEN 31 AND 34`); err != nil {
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
	entry, err := reopened.readV2Migration(31)
	if err != nil || entry == nil || entry.State != v2MigrationApplied {
		t.Fatalf("v31 migration did not apply: %+v %v", entry, err)
	}
	var count int
	if err := reopened.db.QueryRow(`SELECT count(*) FROM principals WHERE id='synthetic_migration_owner'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("v30 state changed across additive migration: count=%d err=%v", count, err)
	}
}

func TestUserMonitorBroadcastV2ConcurrentStoreAuthorizationKeepsOneOperation(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic concurrent body")
	r, _ := f.prepare(t, body)
	approved, _ := f.confirm(t, r, body, 1)
	otherStore, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	input := f.consumeInput(approved)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, s := range []*Store{f.sealed.store, otherStore} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start
			_, err := s.AuthorizeUserMonitorBroadcastV2(input)
			results <- err
		}(s)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("neither Store handle authorized dispatch")
	}
	row, err := readUserMonitorBroadcastTxForTest(f.sealed.store, r.PreviewID)
	if err != nil || row.Status != UserMonitorBroadcastV2DispatchAuthorized || row.OperationID != input.OperationID ||
		row.BroadcastID != input.BroadcastID {
		t.Fatalf("concurrent authorization changed operation: %+v %v", row, err)
	}
	if _, err := otherStore.AuthorizeUserMonitorBroadcastV2(input); err != nil {
		t.Fatalf("second Store could not recover exact operation: %v", err)
	}
}

func TestUserMonitorBroadcastV2ConcurrentStoreConfirmKeepsOneEnvelope(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic concurrent approval")
	r, _ := f.prepare(t, body)
	otherStore, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	inputs := []ConfirmUserMonitorBroadcastV2Input{
		{ClientRequestID: f.acceptedRequest(t), PreviewID: r.PreviewID, SnapshotDigest: r.SnapshotDigest,
			BodyDigest: r.BodyDigest, SealedPayload: f.seal(t, r, body, 1)},
		{ClientRequestID: f.acceptedRequest(t), PreviewID: r.PreviewID, SnapshotDigest: r.SnapshotDigest,
			BodyDigest: r.BodyDigest, SealedPayload: f.seal(t, r, body, 2)},
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, s := range []*Store{f.sealed.store, otherStore} {
		wg.Add(1)
		go func(s *Store, input ConfirmUserMonitorBroadcastV2Input) {
			defer wg.Done()
			<-start
			_, err := s.ConfirmUserMonitorBroadcastV2(input)
			results <- err
		}(s, inputs[i])
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent distinct confirmations returned %d successes", successes)
	}
	row, err := readUserMonitorBroadcastTxForTest(f.sealed.store, r.PreviewID)
	if err != nil || row.Status != UserMonitorBroadcastV2Approved || row.SealedSequence == 0 ||
		(row.confirmRequestID != inputs[0].ClientRequestID && row.confirmRequestID != inputs[1].ClientRequestID) {
		t.Fatalf("concurrent confirm did not retain one exact envelope: %+v %v", row, err)
	}
}

func readUserMonitorBroadcastTxForTest(s *Store, previewID string) (*UserMonitorBroadcastV2, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return readUserMonitorBroadcastTx(tx, previewID)
}

func TestUserMonitorBroadcastV2RejectsUnstorableSealedSequence(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic high sequence body")
	r, _ := f.prepare(t, body)
	sequence := uint64(^uint64(0)>>1) + 1
	_, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: f.acceptedRequest(t), PreviewID: r.PreviewID, SnapshotDigest: r.SnapshotDigest,
		BodyDigest: r.BodyDigest, SealedPayload: f.seal(t, r, body, sequence)})
	if !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("unstorable sealed sequence accepted: %v", err)
	}
}
