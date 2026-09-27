package e2ee

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signOwnerDeviceGrantForTest(t *testing.T, owner, device *Identity, issued, expires time.Time) []byte {
	t.Helper()
	proof, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(),
		"hub_stable", OwnerDevicePurposeControl, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestOwnerDeviceGrantVerifiesExactTrustedEnrollment(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	proof := signOwnerDeviceGrantForTest(t, owner, device, now.Add(-time.Minute), now.Add(time.Hour))
	grant, err := VerifyOwnerDeviceGrant(proof, owner.Public(), device.Public(),
		"owner_a", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl, now)
	if err != nil {
		t.Fatalf("valid device grant rejected: %v", err)
	}
	fingerprint, err := OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	if grant.Version != OwnerDeviceGrantVersion || grant.OwnerID != "owner_a" ||
		grant.OwnerKeyID != owner.Public().ID || grant.DeviceID != "phone_a" ||
		grant.DeviceKeyID != device.Public().ID || grant.DeviceKeyFingerprint != fingerprint ||
		grant.HubID != "hub_stable" || grant.Purpose != OwnerDevicePurposeControl ||
		len(grant.Nonce) != 64 || len(grant.Signature) == 0 {
		t.Fatalf("verified grant has unexpected claims: %+v", grant)
	}
	if len(fingerprint) != 64 || strings.ToLower(fingerprint) != fingerprint {
		t.Fatalf("fingerprint is not full lower-case SHA-256 hex: %q", fingerprint)
	}

	otherOwner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherDevice, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string]struct {
		trusted    PublicIdentity
		device     PublicIdentity
		ownerID    string
		ownerKeyID string
		deviceID   string
		hubID      string
		purpose    string
	}{
		"untrusted signer":     {otherOwner.Public(), device.Public(), "owner_a", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl},
		"different device key": {owner.Public(), otherDevice.Public(), "owner_a", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl},
		"owner":                {owner.Public(), device.Public(), "owner_b", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl},
		"owner key":            {owner.Public(), device.Public(), "owner_a", otherOwner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl},
		"device id":            {owner.Public(), device.Public(), "owner_a", owner.Public().ID, "tablet_a", "hub_stable", OwnerDevicePurposeControl},
		"hub":                  {owner.Public(), device.Public(), "owner_a", owner.Public().ID, "phone_a", "hub_other", OwnerDevicePurposeControl},
		"purpose":              {owner.Public(), device.Public(), "owner_a", owner.Public().ID, "phone_a", "hub_stable", "ADMIN"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyOwnerDeviceGrant(proof, args.trusted, args.device,
				args.ownerID, args.ownerKeyID, args.deviceID, args.hubID, args.purpose, now); err == nil {
				t.Fatal("grant verified outside its precise enrollment scope")
			}
		})
	}
}

func TestOwnerDeviceGrantRejectsTamperingNoncanonicalAndInvalidTime(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	proof := signOwnerDeviceGrantForTest(t, owner, device, now.Add(-time.Minute), now.Add(time.Hour))
	var grant OwnerDeviceGrant
	if err := json.Unmarshal(proof, &grant); err != nil {
		t.Fatal(err)
	}
	grant.HubID = "hub_other"
	tampered, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerDeviceGrant(tampered, owner.Public(), device.Public(),
		"owner_a", owner.Public().ID, "phone_a", "hub_other", OwnerDevicePurposeControl, now); err == nil {
		t.Fatal("grant accepted tampered hub claim")
	}

	for name, data := range map[string][]byte{
		"leading whitespace": append([]byte(" "), proof...),
		"trailing object":    append(append([]byte(nil), proof...), []byte(" {}")...),
		"unknown field":      append([]byte(strings.TrimSuffix(string(proof), "}")), []byte(`,"unknown":true}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyOwnerDeviceGrant(data, owner.Public(), device.Public(),
				"owner_a", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl, now); err == nil {
				t.Fatal("noncanonical or extended grant wire was accepted")
			}
		})
	}

	for name, bounds := range map[string]struct{ issued, expires time.Time }{
		"expired":         {now.Add(-2 * time.Hour), now.Add(-time.Second)},
		"future issuance": {now.Add(time.Second), now.Add(time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := signOwnerDeviceGrantForTest(t, owner, device, bounds.issued, bounds.expires)
			if _, err := VerifyOwnerDeviceGrant(invalid, owner.Public(), device.Public(),
				"owner_a", owner.Public().ID, "phone_a", "hub_stable", OwnerDevicePurposeControl, now); err == nil {
				t.Fatal("grant accepted outside its validity period")
			}
		})
	}
	if _, err := owner.SignOwnerDeviceGrant("owner_a", "phone_a", device.Public(),
		"hub_stable", "ADMIN", now, now.Add(time.Hour)); err == nil {
		t.Fatal("signer accepted unsupported device purpose")
	}
}

func TestOwnerDeviceGrantNoncesAreRandom(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	first := signOwnerDeviceGrantForTest(t, owner, device, now, now.Add(time.Hour))
	second := signOwnerDeviceGrantForTest(t, owner, device, now, now.Add(time.Hour))
	var a, b OwnerDeviceGrant
	if err := json.Unmarshal(first, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second, &b); err != nil {
		t.Fatal(err)
	}
	if a.Nonce == b.Nonce {
		t.Fatal("separate device grants reused a nonce")
	}
}
