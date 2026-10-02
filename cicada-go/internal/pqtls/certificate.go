package pqtls

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"sync"
	"time"
)

const (
	MaxTLSCertificatePEMBytes = 32 << 10
	MaxTLSIssuerChainLength   = 4
	MaxTLSLeafLifetime        = 24 * time.Hour
)

var (
	ErrIssuer      = &Error{Kind: "invalid_tls_issuer"}
	ErrCertificate = &Error{Kind: "invalid_tls_certificate"}
)

// TLSLeafParameters are exact caller-supplied expectations, not Owner approval.
// Serial represents a positive, nonzero 128-bit integer. Callers, not these
// stateless primitives, must reserve unique serials and verify authorization.
type TLSLeafParameters struct {
	TLSCSRParameters
	Serial           [16]byte
	NotBefore        time.Time
	NotAfter         time.Time
	ExpectedSPKIHash [32]byte
}

type TLSIssuerProfile struct {
	Role               string
	CertificateDERHash [32]byte
	SPKIDERHash        [32]byte
	TrustAnchorDERHash [32]byte
	VerifiedNotBefore  time.Time
	VerifiedNotAfter   time.Time
}

// TLSLeafProfile reports verified public material. DER hashes cover the exact
// accepted/generated certificate bytes, not an assertion of canonical input.
// CSRDERHash is populated only by IssueTLSLeaf, which actually inspected a CSR.
type TLSLeafProfile struct {
	Parameters            TLSLeafParameters
	CertificatePEM        []byte
	CertificateDERHash    [32]byte
	SPKIDERHash           [32]byte
	CSRDERHash            [32]byte
	IssuerCertificateHash [32]byte
	TrustAnchorDERHash    [32]byte
	VerifiedNotBefore     time.Time
	VerifiedNotAfter      time.Time
}

type tlsIssuerState struct {
	mu                         sync.Mutex
	keyPEM, chainPEM, trustPEM []byte
	role                       string
}

// TLSIssuer retains only an explicitly imported local key and public chain.
// It grants no Owner rights, file access, enrollment or automatic rotation.
// Aliases share the same lock and destruction state; private export is absent.
type TLSIssuer struct{ state *tlsIssuerState }

func (TLSIssuer) String() string               { return "pqtls.TLSIssuer[redacted]" }
func (TLSIssuer) GoString() string             { return "pqtls.TLSIssuer[redacted]" }
func (TLSIssuer) MarshalJSON() ([]byte, error) { return nil, ErrConfig }
func (s TLSIssuer) Destroy() {
	if s.state == nil {
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	clear(s.state.keyPEM)
	s.state.keyPEM = nil
}

func certificateTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Nanosecond() == 0 && t.Year() >= 1970 && t.Year() <= 9999
}
func validLeafParameters(p TLSLeafParameters, at time.Time) bool {
	return validTLSCSRParameters(p.TLSCSRParameters) && p.Serial != [16]byte{} && p.ExpectedSPKIHash != [32]byte{} &&
		certificateTime(at) && certificateTime(p.NotBefore) && certificateTime(p.NotAfter) &&
		p.NotBefore.Before(p.NotAfter) && p.NotAfter.Sub(p.NotBefore) <= MaxTLSLeafLifetime
}

// Strict PEM envelopes cannot silently skip malformed blocks. Chain material is
// public. Private PKCS#8 DER callers must clear the returned buffer themselves.
func certificatePEMBlocks(input []byte, kind string, limit int) ([][]byte, error) {
	if len(input) == 0 || len(input) > limit*MaxTLSCertificatePEMBytes {
		return nil, ErrCertificate
	}
	input = bytes.Trim(input, " \t\r\n")
	begin := []byte("-----BEGIN " + kind + "-----")
	if !bytes.HasPrefix(input, begin) {
		return nil, ErrCertificate
	}
	count := bytes.Count(input, []byte("-----BEGIN "))
	if count < 1 || count > limit || bytes.Count(input, []byte("-----END ")) != count {
		return nil, ErrCertificate
	}
	var blocks [][]byte
	success := false
	defer func() {
		if kind == "PRIVATE KEY" && !success {
			for _, block := range blocks {
				clear(block)
			}
		}
	}()
	for len(input) > 0 {
		if !bytes.HasPrefix(input, begin) {
			return nil, ErrCertificate
		}
		b, rest := pem.Decode(input)
		if b == nil || b.Type != kind || len(b.Headers) != 0 || len(b.Bytes) == 0 || len(b.Bytes) > MaxTLSCertificatePEMBytes {
			if b != nil && kind == "PRIVATE KEY" {
				clear(b.Bytes)
			}
			return nil, ErrCertificate
		}
		blocks = append(blocks, b.Bytes)
		input = bytes.Trim(rest, " \t\r\n")
	}
	if len(blocks) != count {
		return nil, ErrCertificate
	}
	success = true
	return blocks, nil
}

func certificateChain(chainPEM, trustPEM []byte) ([]byte, []byte, []byte, error) {
	chain, err := certificatePEMBlocks(chainPEM, "CERTIFICATE", MaxTLSIssuerChainLength)
	if err != nil || len(chain) < 2 {
		return nil, nil, nil, ErrIssuer
	}
	root, err := certificatePEMBlocks(trustPEM, "CERTIFICATE", 1)
	if err != nil || !bytes.Equal(chain[len(chain)-1], root[0]) {
		return nil, nil, nil, ErrIssuer
	}
	return bytes.Join(chain, nil), root[0], chain[0], nil
}

func issuerKeyDER(keyPEM []byte) ([]byte, error) {
	if len(keyPEM) > 16<<10 {
		return nil, ErrIssuer
	}
	key, err := certificatePEMBlocks(keyPEM, "PRIVATE KEY", 1)
	if err != nil {
		return nil, ErrIssuer
	}
	return key[0], nil
}

// ImportTLSIssuer validates a dedicated pathLen=0 issuing CA, its distinct
// explicitly trusted root chain, and the matching ML-DSA-65 PKCS#8 key. There is
// no system-root lookup, self-signed leaf trust, CA generation or filesystem IO.
// Input keyPEM remains caller-owned and must be secured/cleared by its caller.
func ImportTLSIssuer(chainPEM, keyPEM, trustPEM []byte, role string, at time.Time) (TLSIssuer, TLSIssuerProfile, error) {
	if err := Available(); err != nil {
		return TLSIssuer{}, TLSIssuerProfile{}, err
	}
	if (role != "node" && role != "hub") || !certificateTime(at) {
		return TLSIssuer{}, TLSIssuerProfile{}, ErrConfig
	}
	chain, root, issuer, err := certificateChain(chainPEM, trustPEM)
	if err != nil {
		return TLSIssuer{}, TLSIssuerProfile{}, err
	}
	key, err := issuerKeyDER(keyPEM)
	if err != nil {
		return TLSIssuer{}, TLSIssuerProfile{}, err
	}
	defer clear(key)
	info, err := runTLSCertificate(1, chain, root, key, nil, TLSLeafParameters{TLSCSRParameters: TLSCSRParameters{Role: role}}, at)
	if err != nil {
		return TLSIssuer{}, TLSIssuerProfile{}, err
	}
	profile := TLSIssuerProfile{Role: role, CertificateDERHash: sha256.Sum256(issuer), SPKIDERHash: info.SPKIHash,
		TrustAnchorDERHash: sha256.Sum256(root), VerifiedNotBefore: info.NotBefore, VerifiedNotAfter: info.NotAfter}
	return TLSIssuer{state: &tlsIssuerState{keyPEM: bytes.Clone(keyPEM), chainPEM: bytes.Clone(chainPEM), trustPEM: bytes.Clone(trustPEM), role: role}}, profile, nil
}

// IssueTLSLeaf requires strict CSR possession/profile and the expected public
// key. It revalidates the imported issuer at the supplied verification time,
// builds fixed leaf extensions, and signs with the imported key. Signing is not
// Owner approval. Issue and Destroy serialize; no private key leaves this API.
func (s TLSIssuer) IssueTLSLeaf(csrPEM []byte, p TLSLeafParameters, at time.Time) (TLSLeafProfile, error) {
	if err := Available(); err != nil {
		return TLSLeafProfile{}, err
	}
	if !validLeafParameters(p, at) {
		return TLSLeafProfile{}, ErrConfig
	}
	csr, err := InspectTLSCSR(csrPEM, p.TLSCSRParameters)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	if csr.SPKIDERHash != p.ExpectedSPKIHash {
		return TLSLeafProfile{}, ErrProfile
	}
	if s.state == nil {
		return TLSLeafProfile{}, ErrIssuer
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if len(s.state.keyPEM) == 0 || s.state.role != p.Role {
		return TLSLeafProfile{}, ErrIssuer
	}
	chain, root, issuer, err := certificateChain(s.state.chainPEM, s.state.trustPEM)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	key, err := issuerKeyDER(s.state.keyPEM)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	defer clear(key)
	block, _ := pem.Decode(csr.CSRPEM)
	info, err := runTLSCertificate(2, chain, root, key, block.Bytes, p, at)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	info.IssuerHash = sha256.Sum256(issuer)
	profile := leafProfile(info.CertificateDER, root, p, info)
	profile.CSRDERHash = csr.CSRDERHash
	return profile, nil
}

// InspectTLSLeaf verifies one leaf against only the supplied public chain and
// independent explicit trust, plus every exact expectation. A successful result
// proves public certificate properties, never current Owner/device authorization.
func InspectTLSLeaf(leafPEM, chainPEM, trustPEM []byte, p TLSLeafParameters, at time.Time) (TLSLeafProfile, error) {
	if err := Available(); err != nil {
		return TLSLeafProfile{}, err
	}
	if !validLeafParameters(p, at) {
		return TLSLeafProfile{}, ErrConfig
	}
	leaf, err := certificatePEMBlocks(leafPEM, "CERTIFICATE", 1)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	chain, root, issuer, err := certificateChain(chainPEM, trustPEM)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	info, err := runTLSCertificate(3, chain, root, nil, leaf[0], p, at)
	if err != nil {
		return TLSLeafProfile{}, err
	}
	info.IssuerHash = sha256.Sum256(issuer)
	return leafProfile(leaf[0], root, p, info), nil
}

type tlsCertificateResult struct {
	CertificateDER       []byte
	SPKIHash, IssuerHash [32]byte
	NotBefore, NotAfter  time.Time
}

func leafProfile(der, root []byte, p TLSLeafParameters, v tlsCertificateResult) TLSLeafProfile {
	return TLSLeafProfile{Parameters: p, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CertificateDERHash: sha256.Sum256(der), SPKIDERHash: v.SPKIHash, IssuerCertificateHash: v.IssuerHash,
		TrustAnchorDERHash: sha256.Sum256(root), VerifiedNotBefore: v.NotBefore, VerifiedNotAfter: v.NotAfter}
}
