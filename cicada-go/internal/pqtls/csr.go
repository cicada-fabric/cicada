package pqtls

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"sync"
)

const MaxTLSCSRPEMBytes = 32 << 10

var ErrCSR = &Error{Kind: "invalid_tls_csr"}

// TLSCSRParameters request one TLS leaf purpose and one exact DNS SAN. They
// contain no Owner approval, Hub/Node binding, issuer permission or TLS epoch.
type TLSCSRParameters struct {
	Role    string // node requests clientAuth; hub requests serverAuth
	DNSName string // lowercase DNS, without wildcard, IP or CN fallback
}

// TLSCSRProfile describes a verified CSR, not an approved certificate request.
// CSRDERHash covers exact accepted CSR DER bytes, independent of PEM wrapping;
// SPKIDERHash covers the public key DER exported by OpenSSL. Inspection does not
// assert canonicalization of the complete input CSR DER.
type TLSCSRProfile struct {
	Parameters         TLSCSRParameters
	KeyAlgorithm       string
	SignatureAlgorithm string
	CSRPEM             []byte
	SPKIDER            []byte
	CSRDERHash         [32]byte
	SPKIDERHash        [32]byte
}

type tlsPrivateKeyState struct {
	mu  sync.Mutex
	pem []byte
}

// TLSPrivateKey is an opaque, independently generated TLS key. Only ExportPEM
// returns private material. Copies share the same Destroy state; neither fmt
// nor JSON serializes the key. Callers must clear any exported copies themselves.
type TLSPrivateKey struct{ state *tlsPrivateKeyState }

func (TLSPrivateKey) String() string               { return "pqtls.TLSPrivateKey[redacted]" }
func (TLSPrivateKey) GoString() string             { return "pqtls.TLSPrivateKey[redacted]" }
func (TLSPrivateKey) MarshalJSON() ([]byte, error) { return nil, ErrConfig }

func (k TLSPrivateKey) ExportPEM() ([]byte, error) {
	if k.state == nil {
		return nil, ErrConfig
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	if len(k.state.pem) == 0 {
		return nil, ErrConfig
	}
	return bytes.Clone(k.state.pem), nil
}

// Destroy clears this handle's retained Go buffer. It does not promise locked
// memory, protection from a malicious host, or erasure of caller-owned copies.
func (k TLSPrivateKey) Destroy() {
	if k.state == nil {
		return
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	clear(k.state.pem)
	k.state.pem = nil
}

func validTLSCSRParameters(p TLSCSRParameters) bool {
	return (p.Role == "node" || p.Role == "hub") &&
		validIdentity(Identity{Kind: "hub", HubID: "csr-profile", DNSName: p.DNSName})
}

func tlsCSRProfile(p TLSCSRParameters, csrDER, spkiDER []byte) TLSCSRProfile {
	return TLSCSRProfile{Parameters: p, KeyAlgorithm: "ML-DSA-65", SignatureAlgorithm: "ML-DSA-65",
		CSRPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		SPKIDER: spkiDER, CSRDERHash: sha256.Sum256(csrDER), SPKIDERHash: sha256.Sum256(spkiDER)}
}

// GenerateTLSCSR uses the pinned OpenSSL provider to generate a new key and
// self-signed PKCS#10 request. It neither loads existing keys nor writes files.
// The CSR proves TLS key possession; it never grants Owner or business rights.
func GenerateTLSCSR(p TLSCSRParameters) (TLSPrivateKey, TLSCSRProfile, error) {
	if err := Available(); err != nil {
		return TLSPrivateKey{}, TLSCSRProfile{}, err
	}
	if !validTLSCSRParameters(p) {
		return TLSPrivateKey{}, TLSCSRProfile{}, ErrConfig
	}
	key, csr, spki, err := generateTLSCSR(p)
	if err != nil {
		clear(key)
		return TLSPrivateKey{}, TLSCSRProfile{}, err
	}
	return TLSPrivateKey{state: &tlsPrivateKeyState{pem: key}}, tlsCSRProfile(p, csr, spki), nil
}

// InspectTLSCSR verifies possession and the exact fixed leaf profile. Exactly
// one header-free CERTIFICATE REQUEST PEM block is accepted, with ASCII space
// allowed only around it. OpenSSL checks the entire DER and all attributes and
// extensions; callers cannot ask this function to copy arbitrary extensions.
func InspectTLSCSR(input []byte, expected TLSCSRParameters) (TLSCSRProfile, error) {
	if err := Available(); err != nil {
		return TLSCSRProfile{}, err
	}
	if !validTLSCSRParameters(expected) {
		return TLSCSRProfile{}, ErrConfig
	}
	if len(input) == 0 || len(input) > MaxTLSCSRPEMBytes {
		return TLSCSRProfile{}, ErrCSR
	}
	input = bytes.Trim(input, " \t\r\n")
	if !bytes.HasPrefix(input, []byte("-----BEGIN CERTIFICATE REQUEST-----")) ||
		bytes.Count(input, []byte("-----BEGIN ")) != 1 || bytes.Count(input, []byte("-----END ")) != 1 {
		return TLSCSRProfile{}, ErrCSR
	}
	block, rest := pem.Decode(input)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 ||
		len(bytes.Trim(rest, " \t\r\n")) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > MaxTLSCSRPEMBytes {
		return TLSCSRProfile{}, ErrCSR
	}
	spki, err := inspectTLSCSR(block.Bytes, expected)
	if err != nil {
		return TLSCSRProfile{}, err
	}
	return tlsCSRProfile(expected, block.Bytes, spki), nil
}
