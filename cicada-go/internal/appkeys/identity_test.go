package appkeys

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/publicidentity"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type testPKIXPublicKey struct {
	Algorithm struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

func TestImportOwnerPKCS8BothSeedAndExpanded(t *testing.T) {
	fixture := makeSyntheticOwnerPEM(t)
	identity, err := ImportOwner(fixture)
	if err != nil {
		t.Fatalf("import canonical synthetic PKCS#8: %v", err)
	}
	defer identity.Close()
	want, err := publicidentity.ParseOpenSSLIdentity(fixture.KEMPublicSPKI, fixture.SigningPublicSPKI)
	if err != nil {
		t.Fatal(err)
	}
	got := identity.Public()
	if got.ID != want.ID || !bytes.Equal(got.KEMPublic, want.KEMPublic) || !bytes.Equal(got.SigningPublic, want.SigningPublic) {
		t.Fatal("imported private identity does not match the supplied public identity")
	}
}

func TestImportOwnerRejectsMismatchesAndMalformedPEM(t *testing.T) {
	fixture := makeSyntheticOwnerPEM(t)
	second := makeSyntheticOwnerPEMWithSeeds(t, 0x56, 0x78)
	tests := []struct {
		name string
		edit func(*ImportOwnerPEM)
	}{
		{name: "different kem public key", edit: func(p *ImportOwnerPEM) { p.KEMPublicSPKI = second.KEMPublicSPKI }},
		{name: "different signing public key", edit: func(p *ImportOwnerPEM) { p.SigningPublicSPKI = second.SigningPublicSPKI }},
		{name: "trailing pem text", edit: func(p *ImportOwnerPEM) {
			p.KEMPrivatePKCS8 = append(append([]byte(nil), p.KEMPrivatePKCS8...), []byte("extra")...)
		}},
		{name: "duplicate pem block", edit: func(p *ImportOwnerPEM) {
			p.SigningPrivatePKCS8 = append(append([]byte(nil), p.SigningPrivatePKCS8...), p.SigningPrivatePKCS8...)
		}},
		{name: "encrypted pem", edit: func(p *ImportOwnerPEM) {
			p.KEMPrivatePKCS8 = []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := fixture
			input.KEMPrivatePKCS8 = append([]byte(nil), fixture.KEMPrivatePKCS8...)
			input.SigningPrivatePKCS8 = append([]byte(nil), fixture.SigningPrivatePKCS8...)
			input.KEMPublicSPKI = append([]byte(nil), fixture.KEMPublicSPKI...)
			input.SigningPublicSPKI = append([]byte(nil), fixture.SigningPublicSPKI...)
			test.edit(&input)
			identity, err := ImportOwner(input)
			if identity != nil {
				identity.Close()
			}
			if err == nil {
				t.Fatal("invalid import unexpectedly succeeded")
			}
		})
	}
	after, err := ImportOwner(fixture)
	if err != nil {
		t.Fatalf("valid synthetic import after rejection tests: %v", err)
	}
	after.Close()
}

// This opt-in test validates the exact private PEM encoding emitted by the
// accepted OpenSSL 3.5 build. The test reads only a caller-created synthetic
// fixture directory, never deployment material.
func TestImportSyntheticOpenSSLGeneratedPEMsWhenConfigured(t *testing.T) {
	dir := os.Getenv("CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR")
	if dir == "" {
		t.Skip("set CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR to a synthetic OpenSSL fixture directory")
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read synthetic fixture %s: %v", name, err)
		}
		return data
	}
	identity, err := ImportOwner(ImportOwnerPEM{
		KEMPrivatePKCS8:     read("kem-private.pem"),
		SigningPrivatePKCS8: read("signing-private.pem"),
		KEMPublicSPKI:       read("kem-public.pem"),
		SigningPublicSPKI:   read("signing-public.pem"),
	})
	if err != nil {
		t.Fatalf("import OpenSSL-generated synthetic keys: %v", err)
	}
	identity.Close()
}

func TestGenerateAndMarshalRoundTrip(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := first.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	want := first.Public()
	second, err := ParseIdentity(encoded)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	defer second.Close()
	got := second.Public()
	if got.ID != want.ID || !bytes.Equal(got.KEMPublic, want.KEMPublic) || !bytes.Equal(got.SigningPublic, want.SigningPublic) {
		t.Fatal("round-tripped identity public keys changed")
	}
	if _, err := ParseIdentity(append(append([]byte(nil), encoded...), ' ')); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("trailing identity bytes error = %v", err)
	}
}

func makeSyntheticOwnerPEM(t *testing.T) ImportOwnerPEM {
	t.Helper()
	return makeSyntheticOwnerPEMWithSeeds(t, 0x12, 0x34)
}

func makeSyntheticOwnerPEMWithSeeds(t *testing.T, kemByte, signingByte byte) ImportOwnerPEM {
	t.Helper()
	kemSeed := bytes.Repeat([]byte{kemByte}, mlkem768.KeySeedSize)
	kemPublic, kemPrivate := mlkem768.NewKeyFromSeed(kemSeed)
	kemExpanded, err := kemPrivate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	kemPrivateChoice, err := asn1.Marshal(struct {
		Seed     []byte
		Expanded []byte
	}{kemSeed, kemExpanded})
	if err != nil {
		t.Fatal(err)
	}
	kemPrivatePKCS8 := marshalTestPrivatePEM(t, mlkem768OID, kemPrivateChoice)
	kemPublicBytes, err := kemPublic.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	kemPublicSPKI := marshalTestPublicPEM(t, mlkem768OID, kemPublicBytes)

	signingSeed := bytes.Repeat([]byte{signingByte}, mldsa65.SeedSize)
	signingPublic, signingPrivate := mldsa65.Scheme().DeriveKey(signingSeed)
	signingExpanded, err := signingPrivate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signingChoice, err := asn1.Marshal(struct {
		Seed     []byte
		Expanded []byte
	}{signingSeed, signingExpanded})
	if err != nil {
		t.Fatal(err)
	}
	signingPrivatePKCS8 := marshalTestPrivatePEM(t, mldsa65OID, signingChoice)
	signingPublicSPKI, err := pki.MarshalPEMPublicKey(signingPublic)
	if err != nil {
		t.Fatal(err)
	}
	return ImportOwnerPEM{
		KEMPrivatePKCS8:     kemPrivatePKCS8,
		SigningPrivatePKCS8: signingPrivatePKCS8,
		KEMPublicSPKI:       kemPublicSPKI,
		SigningPublicSPKI:   signingPublicSPKI,
	}
}

func marshalTestPrivatePEM(t *testing.T, oid asn1.ObjectIdentifier, private []byte) []byte {
	t.Helper()
	var info privateKeyInfo
	info.Version = 0
	info.Algorithm.OID = oid
	info.PrivateKey = private
	encoded, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func marshalTestPublicPEM(t *testing.T, oid asn1.ObjectIdentifier, public []byte) []byte {
	t.Helper()
	var info testPKIXPublicKey
	info.Algorithm.OID = oid
	info.PublicKey = asn1.BitString{Bytes: public, BitLength: len(public) * 8}
	encoded, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
}
