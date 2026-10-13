package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestOwnerDeviceExternalSignerUsesExistingCanonicalClaims(t *testing.T) {
	owner, _ := NewIdentity()
	device, _ := NewIdentity()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	var received []byte
	proof, err := SignOwnerDeviceGrantWithSigner(owner.Public(), "owner_synthetic", "device_synthetic",
		device.Public(), "hub_synthetic", OwnerDevicePurposeControl, now, now.Add(time.Hour),
		func(message []byte) ([]byte, error) {
			received = append([]byte(nil), message...)
			sig := make([]byte, mldsa65.SignatureSize)
			return sig, mldsa65.SignTo(owner.signingPrivate, message, nil, false, sig)
		})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := VerifyOwnerDeviceGrant(proof, owner.Public(), device.Public(),
		"owner_synthetic", owner.Public().ID, "device_synthetic", "hub_synthetic", OwnerDevicePurposeControl, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(grant.claims())
	if !bytes.Equal(received, append([]byte("cicada/client/owner-device-grant/v1\x00"), claims...)) {
		t.Fatal("external callback did not receive the existing domain and ordered claims")
	}
	legacy, err := owner.SignOwnerDeviceGrant("owner_synthetic", "device_synthetic", device.Public(),
		"hub_synthetic", OwnerDevicePurposeControl, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var prior OwnerDeviceGrant
	if err := json.Unmarshal(legacy, &prior); err != nil {
		t.Fatal(err)
	}
	prior.Nonce, prior.Signature = grant.Nonce, grant.Signature
	if !reflect.DeepEqual(prior, grant) {
		t.Fatal("native and external signer claims differ")
	}
}

func TestOwnerDeviceExternalSignerRejectsBadSignatureAndInputBeforeCallback(t *testing.T) {
	owner, _ := NewIdentity()
	other, _ := NewIdentity()
	device, _ := NewIdentity()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for name, sign := range map[string]func([]byte) ([]byte, error){
		"nil":              nil,
		"callback failure": func([]byte) ([]byte, error) { return nil, errors.New("synthetic failure") },
		"short signature":  func([]byte) ([]byte, error) { return []byte{1}, nil },
		"wrong key": func(message []byte) ([]byte, error) {
			sig := make([]byte, mldsa65.SignatureSize)
			return sig, mldsa65.SignTo(other.signingPrivate, message, nil, false, sig)
		},
		"mutated claims": func(message []byte) ([]byte, error) {
			message[0] ^= 1
			sig := make([]byte, mldsa65.SignatureSize)
			return sig, mldsa65.SignTo(owner.signingPrivate, message, nil, false, sig)
		},
	} {
		t.Run(name, func(t *testing.T) {
			proof, err := SignOwnerDeviceGrantWithSigner(owner.Public(), "owner_synthetic", "device_synthetic",
				device.Public(), "hub_synthetic", OwnerDevicePurposeControl, now, now.Add(time.Hour), sign)
			if err == nil || proof != nil {
				t.Fatal("invalid external signature produced a grant")
			}
		})
	}
	called := false
	proof, err := SignOwnerDeviceGrantWithSigner(owner.Public(), "owner_synthetic", "device_synthetic",
		device.Public(), "hub_synthetic", "ADMIN", now, now.Add(time.Hour), func([]byte) ([]byte, error) { called = true; return nil, nil })
	if err == nil || proof != nil || called {
		t.Fatal("invalid scope reached the external signer")
	}
}

func TestNewPublicIdentityPreservesExistingIDAndCopiesInputs(t *testing.T) {
	identity, _ := NewIdentity()
	original := identity.Public()
	public, err := NewPublicIdentity(original.KEMPublic, original.SigningPublic)
	if err != nil || !reflect.DeepEqual(original, public) {
		t.Fatal("public constructor changed existing identity")
	}
	original.KEMPublic[0] ^= 1
	original.SigningPublic[0] ^= 1
	if err := ValidatePublicIdentity(public); err != nil {
		t.Fatal("public constructor aliases caller key bytes")
	}
	if _, err := NewPublicIdentity(public.KEMPublic[:1], public.SigningPublic); err == nil {
		t.Fatal("short KEM key accepted")
	}
	if _, err := NewPublicIdentity(public.KEMPublic, public.SigningPublic[:1]); err == nil {
		t.Fatal("short signing key accepted")
	}
}
