package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// This opt-in gate uses actual OpenSSL, never a signer stub or deployment key.
func TestExternalOwnerOpenSSLRealSignatureInterop(t *testing.T) {
	openssl := os.Getenv("CICADA_TEST_OWNER_OPENSSL")
	if openssl == "" {
		t.Skip("set CICADA_TEST_OWNER_OPENSSL to an independently verified OpenSSL 3.5.9 executable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(input string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(openssl, args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("synthetic OpenSSL operation %s failed: %v", args[0], err)
		}
		return out
	}
	if version := string(run("", "version")); !strings.Contains(version, "OpenSSL 3.5.9 ") {
		t.Fatal("this interoperability gate requires actual OpenSSL 3.5.9")
	}
	const password = "SYNTHETIC-EPHEMERAL-TEST-ONLY-no-deployment\n"
	public := PublicIdentity{}
	for _, key := range []struct {
		algorithm, file, oid string
		size                 int
	}{
		{"ML-KEM-768", "synthetic-kem", "2.16.840.1.101.3.4.4.2", 1184},
		{"ML-DSA-65", "synthetic-signing", "2.16.840.1.101.3.4.3.18", 1952},
	} {
		private := filepath.Join(dir, key.file+".pem")
		der := filepath.Join(dir, key.file+".der")
		run(password, "genpkey", "-algorithm", key.algorithm, "-aes-256-cbc", "-pass", "stdin", "-out", private)
		pem, err := os.ReadFile(private)
		if err != nil || !bytes.HasPrefix(pem, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
			t.Fatal("OpenSSL fixture private key is not encrypted PKCS8 PEM")
		}
		if err := os.Chmod(private, 0600); err != nil {
			t.Fatal(err)
		}
		run(password, "pkey", "-in", private, "-passin", "stdin", "-pubout", "-outform", "DER", "-out", der)
		data, err := os.ReadFile(der)
		if err != nil {
			t.Fatal(err)
		}
		var spki struct {
			Algorithm struct {
				OID        asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			Public asn1.BitString
		}
		rest, err := asn1.Unmarshal(data, &spki)
		if err != nil || len(rest) != 0 || spki.Algorithm.OID.String() != key.oid || len(spki.Algorithm.Parameters.FullBytes) != 0 || spki.Public.BitLength != key.size*8 {
			t.Fatal("OpenSSL SPKI has unexpected algorithm, parameters or raw key length")
		}
		if key.algorithm == "ML-KEM-768" {
			public.KEMPublic = spki.Public.Bytes
		} else {
			public.SigningPublic = spki.Public.Bytes
		}
	}
	public.ID = identityID(public.KEMPublic, public.SigningPublic)
	if err := ValidatePublicIdentity(public); err != nil {
		t.Fatal(err)
	}
	device, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	nonce := sha256.Sum256([]byte("SYNTHETIC-EPHEMERAL-OWNER-GRANT-ONLY"))
	grant := OwnerDeviceGrant{Version: 1, OwnerID: "synthetic-openssl-owner", OwnerKeyID: public.ID, DeviceID: "synthetic-openssl-phone", DeviceKeyID: device.Public().ID, DeviceKeyFingerprint: fingerprint, HubID: "synthetic-openssl-hub", Purpose: OwnerDevicePurposeControl, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce[:])}
	signed, err := ownerDeviceGrantSignedBytes(grant)
	if err != nil {
		t.Fatal(err)
	}
	message := filepath.Join(dir, "synthetic-grant-message.bin")
	signature := filepath.Join(dir, "synthetic-signature.bin")
	if err := os.WriteFile(message, signed, 0600); err != nil {
		t.Fatal(err)
	}
	run(password, "pkeyutl", "-sign", "-rawin", "-inkey", filepath.Join(dir, "synthetic-signing.pem"), "-passin", "stdin", "-in", message, "-out", signature)
	grant.Signature, err = os.ReadFile(signature)
	if err != nil {
		t.Fatal(err)
	}
	pk := new(mldsa65.PublicKey)
	if err := pk.UnmarshalBinary(public.SigningPublic); err != nil {
		t.Fatal(err)
	}
	if !mldsa65.Verify(pk, signed, nil, grant.Signature) {
		t.Fatal("actual OpenSSL pure MLDSA signature did not verify with unchanged CIRCL FIPS204 encoding")
	}
	wire, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(data []byte, owner string, publicDevice PublicIdentity) error {
		_, err := VerifyOwnerDeviceGrant(data, public, publicDevice, owner, public.ID, grant.DeviceID, grant.HubID, grant.Purpose, now)
		return err
	}
	if err := verify(wire, grant.OwnerID, device.Public()); err != nil {
		t.Fatal(err)
	}
	t.Run("WrongOwnerBinding", func(t *testing.T) {
		if verify(wire, "synthetic-other-owner", device.Public()) == nil {
			t.Fatal("wrong owner accepted")
		}
	})
	t.Run("WrongDeviceKey", func(t *testing.T) {
		other, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if verify(wire, grant.OwnerID, other.Public()) == nil {
			t.Fatal("wrong device accepted")
		}
	})
	t.Run("ChangedSignedPayload", func(t *testing.T) {
		changed := grant
		changed.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano)
		tampered, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if verify(tampered, grant.OwnerID, device.Public()) == nil {
			t.Fatal("changed payload accepted")
		}
	})
	t.Log("actual OpenSSL3.5.9 encrypted PKCS8 keygen, strict MLKEM768/MLDSA65 SPKI OIDs, pure MLDSA signature and unchanged CIRCL OwnerDeviceGrant verification passed")
}
