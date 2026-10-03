package pqtls

import (
	"crypto/sha256"
	"time"
)

const (
	// MaxTLSApplicationSigningPublicKeys bounds the complete trusted inventory.
	// The authority layer must fail closed when its inventory exceeds this cap;
	// it must not truncate, omit retired keys, or accept a bundle-provided list.
	MaxTLSApplicationSigningPublicKeys = 1024
	tlsApplicationSigningPublicBytes   = 1952 // FIPS 204 ML-DSA-65 public key
)

var ErrTLSApplicationKeyReuse = &Error{Kind: "tls_application_key_reuse"}

// Profile revalidates the actual opaque issuer handle and returns only its
// public tuple. It uses the existing strict C issuer import operation under
// the same state lock as IssueTLSLeaf and Destroy; no private key is exported.
// A caller-edited TLSIssuerProfile cannot substitute for this check before
// passing the handle to an exact Owner-approved signer.
func (s TLSIssuer) Profile(at time.Time) (TLSIssuerProfile, error) {
	if err := Available(); err != nil {
		return TLSIssuerProfile{}, err
	}
	if !certificateTime(at) {
		return TLSIssuerProfile{}, ErrConfig
	}
	if s.state == nil {
		return TLSIssuerProfile{}, ErrIssuer
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if len(s.state.keyPEM) == 0 || (s.state.role != "node" && s.state.role != "hub") {
		return TLSIssuerProfile{}, ErrIssuer
	}
	chain, root, issuer, err := certificateChain(s.state.chainPEM, s.state.trustPEM)
	if err != nil {
		return TLSIssuerProfile{}, err
	}
	key, err := issuerKeyDER(s.state.keyPEM)
	if err != nil {
		return TLSIssuerProfile{}, err
	}
	defer clear(key)
	info, err := runTLSCertificate(1, chain, root, key, nil, TLSLeafParameters{TLSCSRParameters: TLSCSRParameters{Role: s.state.role}}, at)
	if err != nil {
		return TLSIssuerProfile{}, err
	}
	return TLSIssuerProfile{Role: s.state.role, CertificateDERHash: sha256.Sum256(issuer), SPKIDERHash: info.SPKIHash,
		TrustAnchorDERHash: sha256.Sum256(root), VerifiedNotBefore: info.NotBefore, VerifiedNotAfter: info.NotAfter}, nil
}

// TLSIssuerSigningSPKIHash derives the actual first certificate's ML-DSA-65
// signing-key SPKI hash. Caller-supplied TLSIssuerProfile fields are not proof
// of that key. The bounded, header-free certificate PEM envelope is checked;
// this helper does not validate the issuer's CA status, chain, trust, purpose,
// signatures or time. ImportTLSIssuer/InspectTLSLeaf must still perform those
// independent checks. It accepts one through four public certificates.
func TLSIssuerSigningSPKIHash(chainPEM []byte) ([32]byte, error) {
	if err := Available(); err != nil {
		return [32]byte{}, err
	}
	blocks, err := certificatePEMBlocks(chainPEM, "CERTIFICATE", MaxTLSIssuerChainLength)
	if err != nil {
		return [32]byte{}, ErrIssuer
	}
	spki, err := tlsIssuerSigningSPKIDER(blocks[0])
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(spki), nil
}

// CheckTLSCSRApplicationKeySeparation rejects a strict TLS CSR that reuses any
// application signing public key in the independently trusted complete known
// inventory. Entries are raw FIPS 204 ML-DSA-65 public keys, including retained
// retired/revoked keys. This function does not find unknown or lost keys, attest
// inventory completeness, authorize a CSR, or import application private keys.
// OpenSSL performs public-key decoding, normalization and actual key comparison.
// Errors contain no inventory identity, public-key bytes or matching position.
func CheckTLSCSRApplicationKeySeparation(csrPEM []byte, expected TLSCSRParameters, knownSigningPublic [][]byte) error {
	if err := Available(); err != nil {
		return err
	}
	if len(knownSigningPublic) == 0 || len(knownSigningPublic) > MaxTLSApplicationSigningPublicKeys {
		return ErrConfig
	}
	flat := make([]byte, len(knownSigningPublic)*tlsApplicationSigningPublicBytes)
	for i, public := range knownSigningPublic {
		if len(public) != tlsApplicationSigningPublicBytes {
			return ErrConfig
		}
		copy(flat[i*tlsApplicationSigningPublicBytes:], public)
	}
	profile, err := InspectTLSCSR(csrPEM, expected)
	if err != nil {
		return err
	}
	public, err := tlsApplicationSigningPublicFromSPKI(profile.SPKIDER)
	if err != nil {
		return err
	}
	return checkTLSApplicationSigningPublicSeparation(public, flat)
}
