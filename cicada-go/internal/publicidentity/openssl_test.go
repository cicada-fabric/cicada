package publicidentity

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type testSPKI struct {
	Algorithm struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

func TestParseOpenSSLSPKIPublicStrictlyAcceptsSupportedPublicKeys(t *testing.T) {
	kemBytes := bytes.Repeat([]byte{0x31}, mlkem768.PublicKeySize)
	signingBytes := bytes.Repeat([]byte{0x72}, mldsa65.PublicKeySize)
	kemPEM := testSPKIPEM(t, mlkem768OID, kemBytes, nil)
	signingPEM := testSPKIPEM(t, mldsa65OID, signingBytes, nil)
	gotKEM, err := ParseOpenSSLSPKIPublic(kemPEM, MLKEM768)
	if err != nil || !bytes.Equal(gotKEM, kemBytes) {
		t.Fatalf("Parse ML-KEM SPKI = %x, %v", gotKEM, err)
	}
	gotSigning, err := ParseOpenSSLSPKIPublic(signingPEM, MLDSA65)
	if err != nil || !bytes.Equal(gotSigning, signingBytes) {
		t.Fatalf("Parse ML-DSA SPKI = %x, %v", gotSigning, err)
	}
	identity, err := ParseOpenSSLIdentity(kemPEM, signingPEM)
	if err != nil || e2ee.ValidatePublicIdentity(identity) != nil {
		t.Fatalf("ParseOpenSSLIdentity = %q, %v", identity.ID, err)
	}
}

func TestParseOpenSSLSPKIPublicRejectsWrongAlgorithmParametersSizeAndTrailingPEM(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, mlkem768.PublicKeySize)
	valid := testSPKIPEM(t, mlkem768OID, key, nil)
	wrongOID := testSPKIPEM(t, mldsa65OID, key, nil)
	withParameters := testSPKIPEM(t, mlkem768OID, key, []byte{0x05, 0x00})
	wrongSize := testSPKIPEM(t, mlkem768OID, key[:len(key)-1], nil)
	for name, input := range map[string][]byte{
		"wrong algorithm":       wrongOID,
		"parameters present":    withParameters,
		"wrong public-key size": wrongSize,
		"second PEM block":      append(bytes.Clone(valid), valid...),
		"trailing data":         append(bytes.Clone(valid), []byte("unexpected\n")...),
		"wrong PEM label":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOpenSSLSPKIPublic(input, MLKEM768); err == nil {
				t.Fatal("invalid SPKI accepted")
			}
		})
	}
	if _, err := ParseOpenSSLSPKIPublic(valid, Algorithm("unknown")); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}
}

func testSPKIPEM(t *testing.T, oid asn1.ObjectIdentifier, key []byte, parameters []byte) []byte {
	t.Helper()
	var info testSPKI
	info.Algorithm.OID = oid
	if parameters != nil {
		info.Algorithm.Parameters = asn1.RawValue{FullBytes: bytes.Clone(parameters)}
	}
	info.PublicKey = asn1.BitString{Bytes: bytes.Clone(key), BitLength: len(key) * 8}
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
