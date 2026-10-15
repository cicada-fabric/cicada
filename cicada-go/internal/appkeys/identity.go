// Package appkeys provides the native application's in-process identities.
// It wraps Cicada's existing E2EE implementation and adds strict OpenSSL
// PKCS#8/SPKI import without implementing cryptographic primitives.
package appkeys

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/publicidentity"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	maxPrivatePEMBytes = 1 << 20
	maxPublicPEMBytes  = 16 << 10
	identityVersion    = 1
)

var (
	ErrInvalidIdentity         = errors.New("invalid application identity")
	ErrEncryptedPEMUnsupported = errors.New("encrypted Owner PKCS#8 PEM import is unsupported by the native application")
)

// Identity is an opaque handle to Cicada's existing E2EE identity. Go cannot
// guarantee that compiler/runtime copies of private-key material are zeroized.
type Identity struct {
	inner *e2ee.Identity
}

// ImportOwnerPEM contains the existing Owner identity's PKCS#8 private PEMs
// and matching OpenSSL SPKI public PEMs. Private PEM bytes stay in-process.
// This checkpoint supports unencrypted PKCS#8 only; encrypted PEM is rejected
// without modifying, externally decrypting, or replacing the supplied keys.
type ImportOwnerPEM struct {
	KEMPrivatePKCS8     []byte
	SigningPrivatePKCS8 []byte
	KEMPublicSPKI       []byte
	SigningPublicSPKI   []byte
}

type privateKeyInfo struct {
	Version   int
	Algorithm struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PrivateKey []byte
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
}

type identityDisk struct {
	Version        int    `json:"version"`
	KEMPrivate     []byte `json:"kem_private"`
	SigningPrivate []byte `json:"signing_private"`
}

var mlkem768OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
var mldsa65OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

// Generate creates a new ordinary App-device identity using the existing
// ML-KEM-768 and ML-DSA-65 implementation.
func Generate() (*Identity, error) {
	inner, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	return &Identity{inner: inner}, nil
}

// ImportOwner imports the exact supplied Owner identity. It never derives a
// replacement key and verifies both public components and the stable ID.
func ImportOwner(p ImportOwnerPEM) (*Identity, error) {
	if len(p.KEMPrivatePKCS8) == 0 || len(p.KEMPrivatePKCS8) > maxPrivatePEMBytes ||
		len(p.SigningPrivatePKCS8) == 0 || len(p.SigningPrivatePKCS8) > maxPrivatePEMBytes ||
		len(p.KEMPublicSPKI) == 0 || len(p.KEMPublicSPKI) > maxPublicPEMBytes ||
		len(p.SigningPublicSPKI) == 0 || len(p.SigningPublicSPKI) > maxPublicPEMBytes {
		return nil, ErrInvalidIdentity
	}
	wantPublic, err := publicidentity.ParseOpenSSLIdentity(p.KEMPublicSPKI, p.SigningPublicSPKI)
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	kemPrivate, kemPublic, err := parseMLKEMPrivatePEM(p.KEMPrivatePKCS8)
	if err != nil {
		return nil, err
	}
	signingPrivate, signingPublic, err := parseMLDSAPrivatePEM(p.SigningPrivatePKCS8)
	if err != nil {
		clear(kemPrivate)
		return nil, err
	}
	defer clear(kemPrivate)
	defer clear(signingPrivate)
	if !bytes.Equal(kemPublic, wantPublic.KEMPublic) || !bytes.Equal(signingPublic, wantPublic.SigningPublic) {
		return nil, ErrInvalidIdentity
	}
	derived, err := e2ee.NewPublicIdentity(kemPublic, signingPublic)
	if err != nil || derived.ID != wantPublic.ID {
		return nil, ErrInvalidIdentity
	}
	privateBlob, err := json.Marshal(identityDisk{Version: identityVersion, KEMPrivate: kemPrivate, SigningPrivate: signingPrivate})
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	defer clear(privateBlob)
	inner, err := e2ee.UnmarshalIdentity(privateBlob)
	if err != nil || !samePublic(inner, wantPublic) {
		return nil, ErrInvalidIdentity
	}
	return &Identity{inner: inner}, nil
}

// ParseIdentity restores the existing Cicada identity serialization. Callers
// must obtain this data from an authenticated encrypted vault.
func ParseIdentity(data []byte) (*Identity, error) {
	if len(data) == 0 || len(data) > 64<<10 {
		return nil, ErrInvalidIdentity
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var disk identityDisk
	if err := decoder.Decode(&disk); err != nil {
		return nil, ErrInvalidIdentity
	}
	if err := decoder.Decode(new(any)); err != io.EOF || disk.Version != identityVersion ||
		len(disk.KEMPrivate) != mlkem768.PrivateKeySize || len(disk.SigningPrivate) != mldsa65.PrivateKeySize {
		clear(disk.KEMPrivate)
		clear(disk.SigningPrivate)
		return nil, ErrInvalidIdentity
	}
	canonical, err := json.Marshal(disk)
	if err != nil || !bytes.Equal(canonical, data) {
		clear(canonical)
		clear(disk.KEMPrivate)
		clear(disk.SigningPrivate)
		return nil, ErrInvalidIdentity
	}
	clear(canonical)
	clear(disk.KEMPrivate)
	clear(disk.SigningPrivate)
	inner, err := e2ee.UnmarshalIdentity(data)
	if err != nil {
		return nil, ErrInvalidIdentity
	}
	return &Identity{inner: inner}, nil
}

// Public returns a detached copy of the full public identity.
func (i *Identity) Public() e2ee.PublicIdentity {
	if i == nil || i.inner == nil {
		return e2ee.PublicIdentity{}
	}
	return i.inner.Public()
}

// E2EE returns the existing crypto handle for immediate in-process Cicada
// operations. It exposes no private byte representation; only MarshalBinary
// can serialize the identity, for encrypted appvault persistence.
func (i *Identity) E2EE() (*e2ee.Identity, error) {
	if i == nil || i.inner == nil {
		return nil, ErrInvalidIdentity
	}
	return i.inner, nil
}

// MarshalBinary returns the existing e2ee identity serialization. The caller
// must keep the returned bytes secret and clear them when no longer needed.
func (i *Identity) MarshalBinary() ([]byte, error) {
	if i == nil || i.inner == nil {
		return nil, ErrInvalidIdentity
	}
	return i.inner.MarshalBinary()
}

// Close drops this handle. It cannot promise runtime-level zeroization.
func (i *Identity) Close() {
	if i != nil {
		i.inner = nil
	}
}

func parseMLKEMPrivatePEM(data []byte) ([]byte, []byte, error) {
	block, err := decodeOnePrivatePEM(data)
	if err != nil {
		return nil, nil, err
	}
	defer clear(block.Bytes)
	var info privateKeyInfo
	if err := decodePrivateKeyInfo(block.Bytes, mlkem768OID, &info); err != nil {
		return nil, nil, ErrInvalidIdentity
	}
	defer clear(info.PrivateKey)
	private, err := parseMLKEMPrivateChoice(info.PrivateKey)
	if err != nil {
		return nil, nil, ErrInvalidIdentity
	}
	privateBytes, err := private.MarshalBinary()
	if err != nil {
		return nil, nil, ErrInvalidIdentity
	}
	public, err := private.Public().MarshalBinary()
	if err != nil {
		clear(privateBytes)
		return nil, nil, ErrInvalidIdentity
	}
	return privateBytes, public, nil
}

func parseMLDSAPrivatePEM(data []byte) ([]byte, []byte, error) {
	block, err := decodeOnePrivatePEM(data)
	if err != nil {
		return nil, nil, err
	}
	defer clear(block.Bytes)
	var info privateKeyInfo
	if err := decodePrivateKeyInfo(block.Bytes, mldsa65OID, &info); err != nil {
		return nil, nil, ErrInvalidIdentity
	}
	defer clear(info.PrivateKey)
	private, err := pki.UnmarshalPKIXPrivateKey(block.Bytes)
	if err != nil || private.Scheme().Name() != mldsa65.Scheme().Name() {
		return nil, nil, ErrInvalidIdentity
	}
	privateBytes, err := private.MarshalBinary()
	if err != nil {
		return nil, nil, ErrInvalidIdentity
	}
	public, ok := private.Public().(*mldsa65.PublicKey)
	if !ok {
		clear(privateBytes)
		return nil, nil, ErrInvalidIdentity
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		clear(privateBytes)
		return nil, nil, ErrInvalidIdentity
	}
	return privateBytes, publicBytes, nil
}

func decodeOnePrivatePEM(data []byte) (*pem.Block, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || len(trimmed) > maxPrivatePEMBytes ||
		!bytes.HasPrefix(trimmed, []byte("-----BEGIN PRIVATE KEY-----")) ||
		bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		if bytes.HasPrefix(trimmed, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
			return nil, ErrEncryptedPEMUnsupported
		}
		return nil, ErrInvalidIdentity
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidIdentity
	}
	return block, nil
}

func decodePrivateKeyInfo(encoded []byte, wantOID asn1.ObjectIdentifier, info *privateKeyInfo) error {
	rest, err := asn1.Unmarshal(encoded, info)
	if err != nil || len(rest) != 0 || info.Version != 0 || !info.Algorithm.OID.Equal(wantOID) ||
		len(info.Algorithm.Parameters.FullBytes) != 0 || len(info.Attributes.FullBytes) != 0 {
		return ErrInvalidIdentity
	}
	canonical, err := asn1.Marshal(*info)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidIdentity
	}
	return nil
}

// OpenSSL's ML-KEM-768 PKCS#8 output uses the RFC private-key choice holding
// both the 64-byte seed and expanded encoding. We also accept the canonical
// seed-only and expanded-only choices. When both are present, derive from the
// seed and require an exact match before accepting the expanded key.
func parseMLKEMPrivateChoice(encoded []byte) (kem.PrivateKey, error) {
	var choice asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &choice)
	if err != nil || len(rest) != 0 || len(choice.FullBytes) != len(encoded) || !bytes.Equal(choice.FullBytes, encoded) {
		return nil, ErrInvalidIdentity
	}
	switch {
	case choice.Class == 0 && choice.Tag == 4 && !choice.IsCompound:
		var raw []byte
		trailing, decodeErr := asn1.Unmarshal(encoded, &raw)
		if decodeErr != nil || len(trailing) != 0 {
			return nil, ErrInvalidIdentity
		}
		defer clear(raw)
		if len(raw) == mlkem768.KeySeedSize {
			_, private := mlkem768.NewKeyFromSeed(raw)
			return private, nil
		}
		if len(raw) == mlkem768.PrivateKeySize {
			return mlkem768.Scheme().UnmarshalBinaryPrivateKey(raw)
		}
		return nil, ErrInvalidIdentity
	case choice.Class == 0 && choice.Tag == 16 && choice.IsCompound:
		var both struct {
			Seed     []byte
			Expanded []byte
		}
		trailing, decodeErr := asn1.Unmarshal(encoded, &both)
		if decodeErr != nil || len(trailing) != 0 {
			clear(both.Seed)
			clear(both.Expanded)
			return nil, ErrInvalidIdentity
		}
		defer clear(both.Seed)
		defer clear(both.Expanded)
		canonical, marshalErr := asn1.Marshal(both)
		if marshalErr != nil || !bytes.Equal(canonical, encoded) || len(both.Seed) != mlkem768.KeySeedSize || len(both.Expanded) != mlkem768.PrivateKeySize {
			return nil, ErrInvalidIdentity
		}
		_, fromSeed := mlkem768.NewKeyFromSeed(both.Seed)
		fromExpanded, decodeErr := mlkem768.Scheme().UnmarshalBinaryPrivateKey(both.Expanded)
		if decodeErr != nil || !fromSeed.Equal(fromExpanded) {
			return nil, ErrInvalidIdentity
		}
		return fromSeed, nil
	default:
		return nil, ErrInvalidIdentity
	}
}

func samePublic(identity *e2ee.Identity, expected e2ee.PublicIdentity) bool {
	if identity == nil {
		return false
	}
	actual := identity.Public()
	return actual.ID == expected.ID && bytes.Equal(actual.KEMPublic, expected.KEMPublic) && bytes.Equal(actual.SigningPublic, expected.SigningPublic)
}
