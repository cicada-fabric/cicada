package e2ee

import (
	"testing"
	"time"
)

func TestOwnerDeviceGrantRecordedEnrollmentSecond(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recordedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	issuedAt := recordedAt.Add(400 * time.Millisecond)
	proof := signOwnerDeviceGrantForTest(t, owner, device, issuedAt, recordedAt.Add(700*time.Millisecond))
	verify := func(data []byte, at time.Time) error {
		_, err := VerifyOwnerDeviceGrantAtRecordedEnrollment(data, owner.Public(), device.Public(),
			"owner_a", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl, at)
		return err
	}
	if err := verify(proof, recordedAt); err != nil {
		t.Fatalf("valid proof issued later in recorded second was rejected: %v", err)
	}
	if err := verify(proof, recordedAt.Add(time.Nanosecond)); err == nil {
		t.Fatal("subsecond enrollment accepted a grant issued after exact time")
	}
	if err := verify(proof, recordedAt.Add(-time.Second)); err == nil {
		t.Fatal("proof issued outside recorded second was accepted")
	}
	if err := verify(proof, recordedAt.Add(time.Second)); err == nil {
		t.Fatal("expired proof was accepted in a later recorded second")
	}
	tampered := append([]byte(nil), proof...)
	tampered[len(tampered)-2] ^= 1
	if err := verify(tampered, recordedAt); err == nil {
		t.Fatal("tampered historical grant was accepted")
	}
}
