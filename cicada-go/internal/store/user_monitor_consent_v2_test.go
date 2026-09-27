package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func prepareConsentMonitor(t *testing.T, f *userMonitorBroadcastFixture, body []byte) (*UserMonitorBroadcastV2, string) {
	t.Helper()
	requestID := f.acceptedRequest(t)
	sum := sha256.Sum256(body)
	r, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: requestID, GroupID: f.sealed.groupID,
		MonitorEndpointID: f.sealed.source.id, BodyDigest: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	return r, requestID
}

func TestUserMonitorConsentPreviewVerifiesAndRecoversOriginalOperation(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	r, prepareID := prepareConsentMonitor(t, f, []byte("synthetic consent body"))
	if r.Preview == nil || r.Preview.ConsentSHA256 != r.consentDigest || len(r.Preview.ConsentScope.Recipients) != 2 {
		t.Fatal("new prepare omitted bounded consent evidence")
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 64*1024 || bytes.Contains(encoded, []byte("native_session_id")) ||
		bytes.Contains(encoded, []byte("workspace")) || bytes.Contains(encoded, []byte(`"snapshot":`)) {
		t.Fatalf("preview exceeded Client budget or exposed internal locator (%d bytes)", len(encoded))
	}
	scope := r.Preview.ConsentScope
	digest, err := e2ee.MonitorBroadcastConsentDigest(scope)
	if err != nil || digest != r.Preview.ConsentSHA256 {
		t.Fatal("Client cannot recompute consent digest", err)
	}
	manifest := r.Preview.MonitorGrantManifest
	attested, err := e2ee.VerifyEndpointKeyAttestation(manifest.CandidateAttestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID, manifest.BindingID, manifest.BindingEpoch)
	if err != nil || attested.ID != r.Snapshot.Source.KeyID {
		t.Fatal("Monitor possession proof invalid", err)
	}
	var signed e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(r.Preview.MonitorGrantSignedProof, &signed); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, signed.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(r.Preview.MonitorGrantSignedProof, f.sealed.owner.Public(),
		manifest.OwnerID, GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
		uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, at); err != nil {
		t.Fatal("Owner grant proof invalid", err)
	}
	var originalOperation string
	if err := f.sealed.store.db.QueryRow(`SELECT operation_id FROM client_device_requests_v2 WHERE id=?`, prepareID).Scan(&originalOperation); err != nil {
		t.Fatal(err)
	}
	recoveryID := f.acceptedRequest(t)
	recovered, err := f.sealed.store.RecoverUserMonitorBroadcastV2(recoveryID, originalOperation)
	if err != nil || recovered.PreviewID != r.PreviewID || recovered.Preview.ConsentSHA256 != digest {
		t.Fatalf("lost prepare response did not recover same consent: %+v %v", recovered, err)
	}
	if _, err := f.sealed.store.RecoverUserMonitorBroadcastV2(recoveryID, "foreign_operation"); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("foreign operation recovered")
	}
	tamperedPreview := *r.Preview
	tamperedPreview.MonitorGrantSignedProof = append([]byte(nil), r.Preview.MonitorGrantSignedProof...)
	tamperedPreview.MonitorGrantSignedProof[len(tamperedPreview.MonitorGrantSignedProof)-1] ^= 1
	tamperedJSON, err := json.Marshal(tamperedPreview)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE user_monitor_broadcast_v2 SET preview_json=? WHERE preview_id=?`, string(tamperedJSON), r.PreviewID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.RecoverUserMonitorBroadcastV2(recoveryID, originalOperation); err == nil {
		t.Fatal("tampered proof recovered")
	}
}

func TestUserMonitorConsentConfirmBindsOuterSequence(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic v2 body")
	r, _ := prepareConsentMonitor(t, f, body)
	confirmID := f.acceptedRequest(t)
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	req := userMonitorClientRequest{hubID: hubID, sequence: f.requestSequence}
	context := userMonitorBroadcastContext(req, r)
	if context.ConsentSHA256 != r.Preview.ConsentSHA256 || context.ConfirmRequestSequence != f.requestSequence {
		t.Fatal("context omitted consent or outer sequence")
	}
	legacy := context
	legacy.ConsentSHA256, legacy.ConfirmRequestSequence = "", 0
	v1, err := e2ee.SealMonitorBroadcast(f.device, r.Snapshot.Source.PublicKey, legacy, body, 1)
	if err != nil {
		t.Fatal(err)
	}
	input := ConfirmUserMonitorBroadcastV2Input{ClientRequestID: confirmID, PreviewID: r.PreviewID,
		SnapshotDigest: r.SnapshotDigest, BodyDigest: r.BodyDigest, SealedPayload: v1}
	if _, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("v1 public envelope accepted", err)
	}
	wrong := context
	wrong.ConsentSHA256 = strings.Repeat("0", 64)
	tampered, err := e2ee.SealMonitorBroadcast(f.device, r.Snapshot.Source.PublicKey, wrong, body, f.requestSequence)
	if err != nil {
		t.Fatal(err)
	}
	input.SealedPayload = tampered
	if _, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("wrong consent digest accepted", err)
	}
	sealed, err := e2ee.SealMonitorBroadcast(f.device, r.Snapshot.Source.PublicKey, context, body, f.requestSequence)
	if err != nil {
		t.Fatal(err)
	}
	input.SealedPayload = sealed
	confirmed, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input)
	if err != nil || confirmed.SealedSequence != f.requestSequence {
		t.Fatalf("v2 confirm failed: %+v %v", confirmed, err)
	}
	input.SealedPayload = v1
	if _, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(input); !errors.Is(err, ErrUserMonitorBroadcastV2Conflict) {
		t.Fatal("confirmed operation changed ciphertext", err)
	}
}

func TestUserMonitorConsentShortOwnerGrantExpiresBeforePreviewAndRevalidationDenies(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	grantExpiry := time.Now().UTC().Add(90 * time.Second)
	manifest, err := f.sealed.store.PreviewGroupEndpointKeyGrant(f.sealed.ownerID,
		f.sealed.groupID, f.sealed.source.id, f.sealed.ownerKeyID,
		time.Now().UTC().Add(-time.Minute), grantExpiry)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	grantExpiry, err = time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.sealed.owner.SignOwnerLinkKeyGrant(manifest.OwnerID,
		GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest,
		uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issuedAt, grantExpiry)
	if err != nil {
		t.Fatal(err)
	}
	shortGrant, err := f.sealed.store.AcceptGroupEndpointKeyGrant(f.sealed.ownerID,
		f.sealed.groupID, f.sealed.source.id, f.sealed.ownerKeyID, proof)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic short-grant consent body")
	prepared, _ := prepareConsentMonitor(t, f, body)
	previewExpiry, err := time.Parse(time.RFC3339Nano, prepared.ExpiresAt)
	if err != nil || !grantExpiry.Before(previewExpiry) || prepared.Preview == nil ||
		prepared.Preview.MonitorGrantManifest.Digest != manifest.Digest ||
		!bytes.Equal(prepared.Preview.MonitorGrantSignedProof, proof) {
		t.Fatal("short signed Owner grant was not projected into the longer Client preview")
	}
	confirmID := f.acceptedRequest(t)
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	context := userMonitorBroadcastContext(userMonitorClientRequest{hubID: hubID,
		sequence: f.requestSequence}, prepared)
	sealed, err := e2ee.SealMonitorBroadcast(f.device, prepared.Snapshot.Source.PublicKey,
		context, body, f.requestSequence)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: confirmID, PreviewID: prepared.PreviewID,
		SnapshotDigest: prepared.SnapshotDigest, BodyDigest: prepared.BodyDigest,
		SealedPayload: sealed})
	if err != nil || approved.Status != UserMonitorBroadcastV2Approved {
		t.Fatalf("currently valid short Owner grant could not confirm consent: %v", err)
	}

	// Move only the predicate's explicit evaluation time. The signed proof and
	// persisted preview remain intact; no production clock or TTL is changed.
	afterGrantExpiry := grantExpiry.Add(time.Second)
	if !afterGrantExpiry.Before(previewExpiry) || userMonitorExpiry(approved, afterGrantExpiry) != nil {
		t.Fatal("test did not isolate a still-live preview after Owner grant expiry")
	}
	tx, err := f.sealed.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	latest, err := readLatestGroupEndpointKeyGrant(tx, f.sealed.ownerID,
		f.sealed.groupID, f.sealed.source.id)
	if err != nil || latest.ID != shortGrant.ID ||
		evaluateGroupEndpointKeyGrant(tx, latest, afterGrantExpiry) != GroupEndpointKeyGrantExpired {
		t.Fatal("actual signed source grant did not become expired at evaluation time")
	}
	if _, err := currentUserMonitorSourceTx(tx, approved.GroupID, approved.MonitorEndpointID,
		approved.OwnerID, afterGrantExpiry); err != nil {
		t.Fatalf("unrelated Monitor source guard expired first: %v", err)
	}
	for _, recipient := range prepared.Snapshot.Recipients {
		grant, err := readLatestGroupEndpointKeyGrant(tx, f.sealed.ownerID,
			f.sealed.groupID, recipient.EndpointID)
		if err != nil || evaluateGroupEndpointKeyGrant(tx, grant, afterGrantExpiry) != GroupEndpointKeyGrantCurrent {
			t.Fatalf("unrelated recipient grant expired first: %v", err)
		}
	}
	if err := currentUserMonitorSnapshotTx(tx, approved, afterGrantExpiry); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatalf("expired Owner grant passed the production snapshot revalidation guard: %v", err)
	}
}

func TestUserMonitorConsentPreviewMaxRosterFitsClientBudget(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	r, _ := prepareConsentMonitor(t, f, []byte("synthetic size measurement"))
	scope := r.Preview.ConsentScope
	scope.Recipients = make([]e2ee.MonitorBroadcastConsentEndpoint, 0, 32)
	for i := 0; i < 32; i++ {
		identity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		card := r.Preview.ConsentScope.Recipients[0]
		card.EndpointID = fmt.Sprintf("endpoint_synthetic_%02d_%032x", i, i)
		card.PrincipalID = fmt.Sprintf("principal_synthetic_%02d_%032x", i, i)
		card.BindingID = fmt.Sprintf("binding_synthetic_%02d_%032x", i, i)
		card.KeyID = identity.Public().ID
		card.KeyFingerprint, err = nodekeys.PeerKeyFingerprint(identity.Public())
		if err != nil {
			t.Fatal(err)
		}
		scope.Recipients = append(scope.Recipients, card)
	}
	digest, err := e2ee.MonitorBroadcastConsentDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	projection := *r.Preview
	projection.ConsentScope, projection.ConsentSHA256 = scope, digest
	if _, err := encodedUserMonitorPreview(&projection); err != nil {
		t.Fatal("32 recipients exceed Store projection cap", err)
	}
	copy := *r
	copy.Preview = &projection
	encoded, err := json.Marshal(struct {
		RequestID   string                 `json:"request_id"`
		OperationID string                 `json:"operation_id"`
		OK          bool                   `json:"ok"`
		Result      UserMonitorBroadcastV2 `json:"result"`
	}{RequestID: strings.Repeat("r", 256), OperationID: strings.Repeat("o", 256), OK: true, Result: copy})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 64*1024 || bytes.Contains(encoded, []byte("native_session_id")) || bytes.Contains(encoded, []byte("workspace")) {
		t.Fatalf("32-recipient public response exceeded plaintext budget or leaked locator: %d bytes", len(encoded))
	}
}

func TestUserMonitorConsentPrepareRequiresEnrollmentProof(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	if _, err := f.sealed.store.db.Exec(`DELETE FROM client_device_enrollment_proofs_v2 WHERE owner_id=? AND device_id=?`,
		f.sealed.ownerID, f.deviceRecord.DeviceID); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("synthetic absent proof"))
	_, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: f.acceptedRequest(t), GroupID: f.sealed.groupID,
		MonitorEndpointID: f.sealed.source.id, BodyDigest: hex.EncodeToString(h[:])})
	if !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("missing enrollment proof prepared", err)
	}
}

func TestUserMonitorConsentRecoveryFencesDeviceEpochAndKey(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	r, prepareID := prepareConsentMonitor(t, f, []byte("synthetic recovered once"))
	var operationID string
	if err := f.sealed.store.db.QueryRow(`SELECT operation_id FROM client_device_requests_v2 WHERE id=?`, prepareID).Scan(&operationID); err != nil {
		t.Fatal(err)
	}
	other, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.sealed.owner.SignOwnerDeviceGrant(f.sealed.ownerID, "phone_other_recovery_synthetic",
		other.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.sealed.store.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: f.sealed.ownerID, OwnerKeyID: f.sealed.ownerKeyID,
		DeviceID: "phone_other_recovery_synthetic", DevicePublic: other.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("synthetic foreign recovery"))
	foreign, err := f.sealed.store.AcceptClientRequest(AcceptClientRequestInput{
		OwnerID: f.sealed.ownerID, DeviceID: "phone_other_recovery_synthetic",
		SessionEpoch: 1, Sequence: 1, OperationID: "foreign_recovery_synthetic",
		CiphertextDigest: hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.RecoverUserMonitorBroadcastV2(foreign.Request.ID, operationID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("other device recovered consent", err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE client_devices_v2 SET key_version=key_version+1 WHERE owner_id=? AND device_id=?`,
		f.sealed.ownerID, f.deviceRecord.DeviceID); err != nil {
		t.Fatal(err)
	}
	keyRotatedID := f.acceptedRequest(t)
	if _, err := f.sealed.store.RecoverUserMonitorBroadcastV2(keyRotatedID, operationID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("new key version recovered old consent", err)
	}
	if _, err := f.sealed.store.GetUserMonitorBroadcastV2Status(keyRotatedID, r.PreviewID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("new key version read old preview", err)
	}
	advanced, err := f.sealed.store.AdvanceClientDeviceSessionEpoch(f.sealed.ownerID, f.deviceRecord.DeviceID, f.deviceRecord.SessionEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.RecoverUserMonitorBroadcastV2(keyRotatedID, operationID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("stale session recovered old consent", err)
	}
	if _, err := f.sealed.store.RevokeClientDevice(f.sealed.ownerID, f.deviceRecord.DeviceID, advanced.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.RecoverUserMonitorBroadcastV2(keyRotatedID, operationID); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("revoked device recovered old consent", err)
	}
}

func TestUserMonitorConsentMigrationPreservesApprovedV1Dispatch(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic historical v1 approved body")
	prepared, _ := f.prepare(t, body)
	approved, _ := f.confirm(t, prepared, body, 1)
	for _, ddl := range []string{
		`ALTER TABLE user_monitor_broadcast_v2 DROP COLUMN consent_digest`,
		`ALTER TABLE user_monitor_broadcast_v2 DROP COLUMN preview_json`,
		`DELETE FROM schema_migrations_v2 WHERE version=34`,
	} {
		if _, err := f.sealed.store.db.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.sealed.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.sealed.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.sealed.store = reopened
	delivery, err := reopened.AuthorizeUserMonitorBroadcastV2Delivery(f.consumeInput(approved))
	if err != nil || delivery.Context.ConsentSHA256 != "" || delivery.Context.ConfirmRequestSequence != 0 {
		t.Fatalf("v33 approved envelope could not dispatch after v34 migration: %+v %v", delivery, err)
	}
	if sequence, err := e2ee.VerifyMonitorBroadcast(delivery.SealedPayload, delivery.ClientPublic,
		delivery.Snapshot.Source.PublicKey, delivery.Context); err != nil || sequence != 1 {
		t.Fatalf("historical signed bytes changed: sequence=%d err=%v", sequence, err)
	}
}

func TestUserMonitorConsentApprovedDispatchSurvivesUncertainConfirmResponse(t *testing.T) {
	f := newUserMonitorBroadcastFixture(t)
	body := []byte("synthetic approved before lost response")
	prepared, _ := prepareConsentMonitor(t, f, body)
	confirmID := f.acceptedRequest(t)
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	context := userMonitorBroadcastContext(userMonitorClientRequest{hubID: hubID,
		sequence: f.requestSequence}, prepared)
	sealed, err := e2ee.SealMonitorBroadcast(f.device, prepared.Snapshot.Source.PublicKey,
		context, body, f.requestSequence)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := f.sealed.store.ConfirmUserMonitorBroadcastV2(ConfirmUserMonitorBroadcastV2Input{
		ClientRequestID: confirmID, PreviewID: prepared.PreviewID,
		SnapshotDigest: prepared.SnapshotDigest, BodyDigest: prepared.BodyDigest,
		SealedPayload: sealed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE client_device_requests_v2 SET status='UNCERTAIN' WHERE id=?`, confirmID); err != nil {
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
	if _, err := reopened.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
		ClientRequestID: confirmID, GroupID: prepared.GroupID,
		MonitorEndpointID: prepared.MonitorEndpointID, BodyDigest: prepared.BodyDigest}); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
		t.Fatal("uncertain confirm request created a fresh preview", err)
	}
	notice, err := reopened.GetUserMonitorBroadcastV2Notification(f.sealed.sourceNode.nodeCredential, approved.PreviewID)
	if err != nil || notice.BroadcastID != approved.BroadcastID {
		t.Fatalf("approved notice lost after uncertain outer response: %+v %v", notice, err)
	}
	delivery, err := reopened.AuthorizeUserMonitorBroadcastV2Delivery(f.consumeInput(approved))
	if err != nil || delivery.Context.ConsentSHA256 != prepared.Preview.ConsentSHA256 ||
		delivery.Context.ConfirmRequestSequence != context.ConfirmRequestSequence ||
		delivery.SealedSequence != context.ConfirmRequestSequence {
		t.Fatalf("durable approved delivery lost after uncertain outer response: %+v %v", delivery, err)
	}
}
