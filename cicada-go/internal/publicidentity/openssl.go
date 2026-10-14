// Package publicidentity parses public-key formats emitted by OpenSSL. It
// never reads private keys and adds no cryptographic implementation.
package publicidentity

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type Algorithm string

const (
	MLKEM768        Algorithm = "ML-KEM-768"
	MLDSA65         Algorithm = "ML-DSA-65"
	maxSPKIPemBytes           = 16 * 1024
)

var (
	ErrInvalidSPKI = errors.New("invalid OpenSSL SPKI public key")
	mlkem768OID    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	mldsa65OID     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
)

type publicKeyInfo struct {
	Algorithm struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

// ParseOpenSSLSPKIPublic accepts one canonical PEM SubjectPublicKeyInfo for
// exactly one supported algorithm, with absent parameters and exact key size.
func ParseOpenSSLSPKIPublic(data []byte, algorithm Algorithm) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var size int
	switch algorithm {
	case MLKEM768:
		oid, size = mlkem768OID, mlkem768.PublicKeySize
	case MLDSA65:
		oid, size = mldsa65OID, mldsa65.PublicKeySize
	default:
		return nil, ErrInvalidSPKI
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || len(data) > maxSPKIPemBytes || !bytes.HasPrefix(data, []byte("-----BEGIN PUBLIC KEY-----")) ||
		bytes.Count(data, []byte("-----BEGIN ")) != 1 || bytes.Count(data, []byte("-----END ")) != 1 {
		return nil, ErrInvalidSPKI
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidSPKI
	}
	var info publicKeyInfo
	rest, err := asn1.Unmarshal(block.Bytes, &info)
	if err != nil || len(rest) != 0 || !info.Algorithm.OID.Equal(oid) || len(info.Algorithm.Parameters.FullBytes) != 0 ||
		len(info.PublicKey.Bytes) != size || info.PublicKey.BitLength != size*8 {
		return nil, ErrInvalidSPKI
	}
	canonical, err := asn1.Marshal(info)
	if err != nil || !bytes.Equal(canonical, block.Bytes) {
		return nil, ErrInvalidSPKI
	}
	return append([]byte(nil), info.PublicKey.Bytes...), nil
}

// ParseOpenSSLIdentity combines public SPKI files into an existing Cicada
// identity. The caller must keep each private key outside this parser.
func ParseOpenSSLIdentity(kemSPKI, signingSPKI []byte) (e2ee.PublicIdentity, error) {
	kem, err := ParseOpenSSLSPKIPublic(kemSPKI, MLKEM768)
	if err != nil {
		return e2ee.PublicIdentity{}, err
	}
	signing, err := ParseOpenSSLSPKIPublic(signingSPKI, MLDSA65)
	if err != nil {
		return e2ee.PublicIdentity{}, err
	}
	identity, err := e2ee.NewPublicIdentity(kem, signing)
	if err != nil {
		return e2ee.PublicIdentity{}, ErrInvalidSPKI
	}
	return identity, nil
}
