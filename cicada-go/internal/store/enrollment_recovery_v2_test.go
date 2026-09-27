package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestClientDeviceEnrollmentExactAcceptedGrantRetrySurvivesExpiryAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	current, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if current != nil {
			_ = current.Close()
		}
	})
	if _, err := current.CreatePrincipal(Principal{
		ID: "owner_a", Kind: PrincipalKindHuman, OwnerID: "owner_a",
		Name: "owner_a", Status: PrincipalStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := current.RegisterOwnerApprovalKeyLocal("owner_a", owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := current.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(1500 * time.Millisecond)
	acceptedGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, issuedAt, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	input := RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: ownerKey.KeyID, DeviceID: "phone_a",
		DevicePublic: device.Public(), OwnerDeviceGrant: acceptedGrant,
	}
	initial, err := current.RegisterClientDeviceFromOwnerGrant(input)
	if err != nil || initial.SessionEpoch != 1 || initial.KeyVersion != 1 {
		t.Fatalf("initial enrollment failed: device=%+v err=%v", initial, err)
	}
	// v31 stored only whole seconds. The original signed grant may have been
	// issued later inside that same accepted second; v32 must recover its exact
	// bytes without pretending the old timestamp had finer precision.
	legacyCreatedAt := issuedAt.Truncate(time.Second).Format(time.RFC3339)
	if _, err := current.db.Exec(`UPDATE client_devices_v2 SET created_at=? WHERE owner_id=? AND device_id=?`,
		legacyCreatedAt, input.OwnerID, input.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := current.db.Exec(`DELETE FROM client_device_enrollment_proofs_v2 WHERE owner_id=? AND device_id=?`,
		input.OwnerID, input.DeviceID); err != nil {
		t.Fatal(err)
	}

	// An independently authorized epoch advance must be reflected by recovery;
	// replaying the enrollment grant must never recreate its original epoch.
	advanced, err := current.AdvanceClientDeviceSessionEpoch("owner_a", "phone_a", 1)
	if err != nil || advanced.SessionEpoch != 2 {
		t.Fatalf("advance enrollment fixture epoch: device=%+v err=%v", advanced, err)
	}
	if delay := time.Until(expiresAt.Add(20 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	current = nil
	current, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := current.RegisterClientDeviceFromOwnerGrant(input)
	if err != nil {
		t.Fatalf("exact accepted grant retry failed after expiry/restart: %v", err)
	}
	if recovered.OwnerID != initial.OwnerID || recovered.DeviceID != initial.DeviceID ||
		recovered.KeyID != initial.KeyID || recovered.KeyFingerprint != initial.KeyFingerprint ||
		recovered.SessionEpoch != 2 || recovered.KeyVersion != 1 || recovered.Version != advanced.Version {
		t.Fatalf("retry did not return the current persisted device binding: initial=%+v recovered=%+v", initial, recovered)
	}
	var recoveredEnrollmentAt string
	if err := current.db.QueryRow(`SELECT enrolled_at FROM client_device_enrollment_proofs_v2
WHERE owner_id=? AND device_id=?`, input.OwnerID, input.DeviceID).Scan(&recoveredEnrollmentAt); err != nil {
		t.Fatal(err)
	}
	if recoveredEnrollmentAt != legacyCreatedAt {
		t.Fatalf("legacy enrollment timestamp changed on proof recovery: got %q want %q", recoveredEnrollmentAt, legacyCreatedAt)
	}

	var nonceCount int
	if err := current.db.QueryRow(`SELECT count(*) FROM client_device_grant_nonces_v2
WHERE owner_id = ? AND owner_key_id = ? AND device_id = ?`, "owner_a", ownerKey.KeyID, "phone_a").Scan(&nonceCount); err != nil {
		t.Fatal(err)
	}
	if nonceCount != 1 {
		t.Fatalf("retry consumed another nonce record: count=%d", nonceCount)
	}

	changedSignature := append([]byte(nil), acceptedGrant...)
	var decoded e2ee.OwnerDeviceGrant
	if err := json.Unmarshal(changedSignature, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Signature[0] ^= 0xff
	changedSignature, err = json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	changedInput := input
	changedInput.OwnerDeviceGrant = changedSignature
	if _, err := current.RegisterClientDeviceFromOwnerGrant(changedInput); !errors.Is(err, ErrClientDeviceGrantReplay) {
		t.Fatalf("changed grant bytes reusing the accepted nonce were not rejected as replay: %v", err)
	}

	otherDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	changedIdentity := input
	changedIdentity.DevicePublic = otherDevice.Public()
	if _, err := current.RegisterClientDeviceFromOwnerGrant(changedIdentity); !errors.Is(err, ErrClientDeviceConflict) {
		t.Fatalf("changed device key was accepted for the existing ID: %v", err)
	}
	newGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	changedGrant := input
	changedGrant.OwnerDeviceGrant = newGrant
	if _, err := current.RegisterClientDeviceFromOwnerGrant(changedGrant); !errors.Is(err, ErrClientDeviceConflict) {
		t.Fatalf("different grant was accepted as recovery: %v", err)
	}
	wrongHubGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(), "different_hub",
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	changedHub := input
	changedHub.OwnerDeviceGrant = wrongHubGrant
	if _, err := current.RegisterClientDeviceFromOwnerGrant(changedHub); !errors.Is(err, ErrClientDeviceConflict) {
		t.Fatalf("grant bound to another Hub was accepted as recovery: %v", err)
	}
	wrongDeviceID := input
	wrongDeviceID.DeviceID = "phone_b"
	if _, err := current.RegisterClientDeviceFromOwnerGrant(wrongDeviceID); err == nil {
		t.Fatal("accepted grant was replayed under a different device ID")
	}
	crossOwner := input
	crossOwner.OwnerID = "owner_b"
	if _, err := current.RegisterClientDeviceFromOwnerGrant(crossOwner); err == nil {
		t.Fatal("accepted grant was replayed under another owner")
	}
	expiredDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	expiredGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_expired", expiredDevice.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-2*time.Hour), time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: "owner_a", OwnerKeyID: ownerKey.KeyID, DeviceID: "phone_expired",
		DevicePublic: expiredDevice.Public(), OwnerDeviceGrant: expiredGrant,
	}); err == nil {
		t.Fatal("expired grant was accepted for a new device enrollment")
	}

	if _, err := current.RevokeClientDevice("owner_a", "phone_a", recovered.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := current.RegisterClientDeviceFromOwnerGrant(input); !errors.Is(err, ErrClientDeviceRevoked) {
		t.Fatalf("revoked device recovered through its old grant: %v", err)
	}

	secondDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secondGrant, err := owner.SignOwnerDeviceGrant("owner_a", "phone_c", secondDevice.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	secondInput := RegisterClientDeviceInput{OwnerID: "owner_a", OwnerKeyID: ownerKey.KeyID,
		DeviceID: "phone_c", DevicePublic: secondDevice.Public(), OwnerDeviceGrant: secondGrant}
	if _, err := current.RegisterClientDeviceFromOwnerGrant(secondInput); err != nil {
		t.Fatal(err)
	}
	if _, err := current.RevokeOwnerApprovalKeyLocal("owner_a", ownerKey.KeyID, ownerKey.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := current.RegisterClientDeviceFromOwnerGrant(secondInput); !errors.Is(err, ErrOwnerApprovalKeyConflict) {
		t.Fatalf("device recovered after its owner key was revoked: %v", err)
	}

}
