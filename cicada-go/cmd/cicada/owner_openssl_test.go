package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Visibly synthetic deterministic keys are test-only, never deployment inputs.
func syntheticAdapterPublicIdentity(t *testing.T, tag byte) (e2ee.PublicIdentity, *mldsa65.PrivateKey) {
	t.Helper()
	kem, _ := mlkem768.NewKeyFromSeed(bytes.Repeat([]byte{tag}, mlkem768.KeySeedSize))
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], bytes.Repeat([]byte{tag}, len(seed)))
	signing, private := mldsa65.NewKeyFromSeed(&seed)
	kemBytes, _ := kem.MarshalBinary()
	signingBytes, _ := signing.MarshalBinary()
	public, err := e2ee.NewPublicIdentity(kemBytes, signingBytes)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func syntheticOwnerSPKI(t *testing.T, oid asn1.ObjectIdentifier, raw []byte) []byte {
	t.Helper()
	info := ownerPublicKeyInfo{}
	info.Algorithm.OID = oid
	info.PublicKey = asn1.BitString{Bytes: raw, BitLength: len(raw) * 8}
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestOwnerOpenSSLPublicParserRefusesWrongVariantAndAmbiguousEncoding(t *testing.T) {
	public, _ := syntheticAdapterPublicIdentity(t, 11)
	valid := syntheticOwnerSPKI(t, ownerMLDSA65OID, public.SigningPublic)
	got, err := parseOwnerOpenSSLPublic(valid, ownerMLDSA65OID, mldsa65.PublicKeySize)
	if err != nil || !bytes.Equal(got, public.SigningPublic) {
		t.Fatal("valid synthetic SPKI rejected")
	}
	withParams := ownerPublicKeyInfo{}
	withParams.Algorithm.OID = ownerMLDSA65OID
	withParams.Algorithm.Parameters = asn1.RawValue{Tag: 5}
	withParams.PublicKey = asn1.BitString{Bytes: public.SigningPublic, BitLength: len(public.SigningPublic) * 8}
	paramsDER, _ := asn1.Marshal(withParams)
	block, _ := pem.Decode(valid)
	validInfo := ownerPublicKeyInfo{}
	validInfo.Algorithm.OID = ownerMLDSA65OID
	validInfo.PublicKey = withParams.PublicKey
	algorithmDER, _ := asn1.Marshal(validInfo.Algorithm)
	extraDER, _ := asn1.Marshal(struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
		Extra     asn1.RawValue
	}{asn1.RawValue{FullBytes: algorithmDER}, validInfo.PublicKey, asn1.RawValue{Tag: 5}})
	validInfo.PublicKey = asn1.BitString{Bytes: append([]byte(nil), public.SigningPublic...), BitLength: len(public.SigningPublic)*8 - 1}
	validInfo.PublicKey.Bytes[len(validInfo.PublicKey.Bytes)-1] &= 0xfe
	unalignedDER, _ := asn1.Marshal(validInfo)
	for name, data := range map[string][]byte{
		"ML-DSA-44 OID":         syntheticOwnerSPKI(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, public.SigningPublic),
		"ML-KEM-512 OID":        syntheticOwnerSPKI(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}, public.SigningPublic),
		"ML-KEM-1024 OID":       syntheticOwnerSPKI(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}, public.SigningPublic),
		"wrong key length":      syntheticOwnerSPKI(t, ownerMLDSA65OID, public.SigningPublic[:10]),
		"NULL parameters":       pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: paramsDER}),
		"extra sequence field":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: extraDER}),
		"unaligned public bits": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: unalignedDER}),
		"truncated DER":         pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes[:len(block.Bytes)-1]}),
		"trailing DER":          pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: append(append([]byte(nil), block.Bytes...), 0)}),
		"extra PEM":             append(append([]byte(nil), valid...), valid...),
		"trailing text":         append(append([]byte(nil), valid...), []byte("unexpected")...),
		"leading text":          append([]byte("unexpected\n"), valid...),
		"private PEM":           pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block.Bytes}),
		"PEM headers":           pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes, Headers: map[string]string{"Comment": "synthetic"}}),
		"oversize":              bytes.Repeat([]byte{'a'}, 16*1024+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOwnerOpenSSLPublic(data, ownerMLDSA65OID, mldsa65.PublicKeySize); err == nil {
				t.Fatal("invalid SPKI accepted")
			}
		})
	}
	for _, oid := range []asn1.ObjectIdentifier{
		{2, 16, 840, 1, 101, 3, 4, 4, 1}, {2, 16, 840, 1, 101, 3, 4, 4, 3},
	} {
		if _, err := parseOwnerOpenSSLPublic(syntheticOwnerSPKI(t, oid, public.KEMPublic), ownerMLKEM768OID, mlkem768.PublicKeySize); err == nil {
			t.Fatal("wrong ML-KEM variant accepted with matching raw length")
		}
	}
}

func TestOwnerKeyFromOpenSSLIsPublicOnlyAndDoesNotOverwrite(t *testing.T) {
	public, _ := syntheticAdapterPublicIdentity(t, 12)
	dir := t.TempDir()
	kemPath, signingPath, outputPath := filepath.Join(dir, "kem.pem"), filepath.Join(dir, "signing.pem"), filepath.Join(dir, "public.json")
	if err := os.WriteFile(kemPath, syntheticOwnerSPKI(t, ownerMLKEM768OID, public.KEMPublic), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signingPath, syntheticOwnerSPKI(t, ownerMLDSA65OID, public.SigningPublic), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--kem-public", kemPath, "--signing-public", signingPath, "--output", outputPath}
	var output bytes.Buffer
	if err := ownerKeyFromOpenSSLCommand(args, &output); err != nil {
		t.Fatal(err)
	}
	got, err := readOfflineOwnerIdentity(outputPath)
	if err != nil || !reflect.DeepEqual(got, public) {
		t.Fatal("SPKI conversion changed public identity or ID")
	}
	before, _ := os.ReadFile(outputPath)
	if err := ownerKeyFromOpenSSLCommand(args, &output); err == nil {
		t.Fatal("public output overwritten")
	}
	after, _ := os.ReadFile(outputPath)
	if !bytes.Equal(before, after) {
		t.Fatal("failed conversion changed public output")
	}
}

func TestOwnerOpenSSLPrepareAndSignReviewedTuple(t *testing.T) {
	owner, private := syntheticAdapterPublicIdentity(t, 13)
	device, _ := syntheticAdapterPublicIdentity(t, 14)
	dir := t.TempDir()
	ownerPath, devicePath := filepath.Join(dir, "owner.json"), filepath.Join(dir, "device.json")
	for path, public := range map[string]e2ee.PublicIdentity{ownerPath: owner, devicePath: device} {
		data, _ := json.Marshal(public)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath, grantPath := filepath.Join(dir, "manifest.json"), filepath.Join(dir, "grant.json")
	var output bytes.Buffer
	prepare := []string{"--device-public", devicePath, "--owner-public", ownerPath, "--owner-id", "owner-synthetic",
		"--hub-id", "hub-pinned-synthetic", "--device-id", "browser-synthetic", "--output", manifestPath}
	if err := ownerDeviceEnrollmentPrepareCommand(prepare, &output); err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if !strings.Contains(output.String(), fingerprint) {
		t.Fatal("preparation did not display full device fingerprint")
	}
	if err := ownerDeviceEnrollmentPrepareCommand(prepare, &output); err == nil {
		t.Fatal("manifest overwritten")
	}
	args := ownerDeviceSignTestArgs("unused", manifestPath, grantPath, owner.ID, device.ID, fingerprint, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	args[0] = "--signing-private"
	args = append(args, "--owner-public", ownerPath, "--openssl", filepath.Join(dir, "synthetic-openssl"))
	called := 0
	signer := func(executable, privatePath string, message []byte) ([]byte, error) {
		called++
		if privatePath != "unused" || executable != filepath.Join(dir, "synthetic-openssl") {
			t.Fatal("external signer coordinate changed")
		}
		sig := make([]byte, mldsa65.SignatureSize)
		return sig, mldsa65.SignTo(private, message, nil, false, sig)
	}
	if err := ownerDeviceGrantSignOpenSSL(args, &output, signer); err != nil {
		t.Fatal(err)
	}
	proof, _ := os.ReadFile(grantPath)
	if _, err := e2ee.VerifyOwnerDeviceGrant(proof, owner, device, "owner-synthetic", owner.ID, "browser-synthetic",
		"hub-pinned-synthetic", e2ee.OwnerDevicePurposeControl, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(grantPath)
		if info.Mode().Perm() != 0o600 {
			t.Fatal("grant file does not have private Unix permissions")
		}
	}
	if err := ownerDeviceGrantSignOpenSSL(args, &output, signer); err == nil || called != 1 {
		t.Fatal("existing output reached signer")
	}
	for name, flagValue := range map[string][2]string{
		"wrong owner":         {"--expect-owner-id", "other"},
		"wrong owner key":     {"--expect-owner-key-id", device.ID},
		"wrong device":        {"--expect-device-id", "other"},
		"wrong device key":    {"--expect-device-key-id", owner.ID},
		"wrong hub":           {"--expect-hub-id", "other"},
		"wrong fingerprint":   {"--expect-device-fingerprint", strings.Repeat("0", 64)},
		"expired":             {"--expires-at", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)},
		"too late":            {"--expires-at", time.Now().UTC().Add(25 * time.Hour).Format(time.RFC3339Nano)},
		"non UTC":             {"--expires-at", "2026-10-13T12:00:00+01:00"},
		"relative executable": {"--openssl", "openssl"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]string(nil), args...)
			replaceArg(bad, "--output", filepath.Join(dir, "refused.json"))
			replaceArg(bad, flagValue[0], flagValue[1])
			if err := ownerDeviceGrantSignOpenSSL(bad, &output, signer); err == nil || called != 1 {
				t.Fatal("unreviewed tuple reached signer")
			}
		})
	}
	for name, sign := range map[string]func(string, string, []byte) ([]byte, error){
		"bad signature":    func(string, string, []byte) ([]byte, error) { return make([]byte, mldsa65.SignatureSize), nil },
		"external failure": func(string, string, []byte) ([]byte, error) { return nil, errors.New("synthetic external failure") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]string(nil), args...)
			path := filepath.Join(dir, name+".json")
			replaceArg(bad, "--output", path)
			if err := ownerDeviceGrantSignOpenSSL(bad, &output, sign); err == nil {
				t.Fatal("failed signer wrote grant")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed signer left output")
			}
		})
	}
}
