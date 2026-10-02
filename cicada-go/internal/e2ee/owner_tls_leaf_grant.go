package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	ownerTLSLeafDomain         = "cicada/node/tls-leaf-grant/v1\x00"
	nodeTLSInstallDomain       = "cicada/node/tls-install-ack/v1\x00"
	nodeTLSActivationDomain    = "cicada/hub/tls-activation/v1\x00"
	MaxNodeTLSProofBytes       = 32 << 10
	NodeTLSApplicationProtocol = "cicada/node-control/v1"
	NodeTLSPQProfile           = "TLS1.3/ML-KEM-768/ML-DSA-65/AES-256-GCM"
)

// OwnerTLSLeafGrantClaims is one exact human approval. None of the public key
// hashes, a CSR possession proof, or a bearer credential is approval by itself.
// Serial and TLS epoch are reserved before the independently held Owner signs.
type OwnerTLSLeafGrantClaims struct {
	Version                   int    `json:"version"`
	RequestID                 string `json:"request_id"`
	HubID                     string `json:"hub_id"`
	NodeID                    string `json:"node_id"`
	OwnerID                   string `json:"owner_id"`
	OwnerKeyID                string `json:"owner_key_id"`
	OwnerKeyVersion           uint64 `json:"owner_key_version"`
	ClientDeviceID            string `json:"client_device_id"`
	ClientDeviceVersion       uint64 `json:"client_device_version"`
	OwnerBindingID            string `json:"owner_binding_id"`
	OwnerBindingVersion       uint64 `json:"owner_binding_version"`
	CredentialDigest          string `json:"credential_digest"`
	CredentialVersion         uint64 `json:"credential_version"`
	NodeControlKeyID          string `json:"node_control_key_id"`
	NodeControlKeyVersion     uint64 `json:"node_control_key_version"`
	NodeControlKeyEpoch       uint64 `json:"node_control_key_epoch"`
	NodeControlBindingVersion uint64 `json:"node_control_binding_version"`
	HubControlKeyID           string `json:"hub_control_key_id"`
	HubControlKeyVersion      uint64 `json:"hub_control_key_version"`
	CSRDERHash                string `json:"csr_der_hash"`
	SPKIDERHash               string `json:"spki_der_hash"`
	IssuerSPKIHash            string `json:"issuer_spki_hash"`
	IssuerDERHash             string `json:"issuer_der_hash"`
	RootDERHash               string `json:"root_der_hash"`
	IssuerGeneration          string `json:"issuer_generation"`
	Role                      string `json:"role"`
	DNSName                   string `json:"dns_name"`
	Serial                    string `json:"serial"`
	ExpectedTLSEpochFloor     uint64 `json:"expected_tls_epoch_floor"`
	TLSEpoch                  uint64 `json:"tls_epoch"`
	NotBefore                 string `json:"not_before"`
	NotAfter                  string `json:"not_after"`
	HubSPKIHash               string `json:"hub_spki_hash"`
	HubTrustAnchorDERHash     string `json:"hub_trust_anchor_der_hash"`
	HubPQOrigin               string `json:"hub_pq_origin"`
	ApplicationOrigin         string `json:"application_origin"`
	ApplicationProtocol       string `json:"application_protocol"`
	PQProfile                 string `json:"pq_profile"`
	IssuedAt                  string `json:"issued_at"`
	ExpiresAt                 string `json:"expires_at"`
	Nonce                     string `json:"nonce"`
}

type OwnerTLSLeafGrant struct {
	Claims    OwnerTLSLeafGrantClaims `json:"claims"`
	Signature []byte                  `json:"signature"`
}

// Acknowledgement is signed by the independently approved NodeControl key,
// never by the TLS private key. It claims completed, verified local staging.
type NodeTLSInstallAckClaims struct {
	Version            int                     `json:"version"`
	GrantClaims        OwnerTLSLeafGrantClaims `json:"grant_claims"`
	GrantDigest        string                  `json:"grant_digest"`
	ReservationVersion uint64                  `json:"reservation_version"`
	LeafDERHash        string                  `json:"leaf_der_hash"`
	IssuedAt           string                  `json:"issued_at"`
	ExpiresAt          string                  `json:"expires_at"`
	Nonce              string                  `json:"nonce"`
}

type NodeTLSInstallAck struct {
	Claims    NodeTLSInstallAckClaims `json:"claims"`
	Signature []byte                  `json:"signature"`
}

// Activation is signed by the independently approved HubControl key. Its
// signature does not mutate Store state; the activation CAS must also succeed.
type NodeTLSActivationClaims struct {
	Version           int                     `json:"version"`
	InstallAckClaims  NodeTLSInstallAckClaims `json:"install_ack_claims"`
	InstallAckDigest  string                  `json:"install_ack_digest"`
	ActivationVersion uint64                  `json:"activation_version"`
	IssuedAt          string                  `json:"issued_at"`
	ExpiresAt         string                  `json:"expires_at"`
	Nonce             string                  `json:"nonce"`
}

type NodeTLSActivation struct {
	Claims    NodeTLSActivationClaims `json:"claims"`
	Signature []byte                  `json:"signature"`
}

// NodeTLSAuthorityDigest covers exact canonical wire bytes including signature.
func NodeTLSAuthorityDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func tlsGrantToken(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func tlsGrantDNS(s string) bool {
	if len(s) == 0 || len(s) > 253 || s != strings.ToLower(s) || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func tlsGrantSecondTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.IsZero() || t.Year() < 1970 || t.Year() > 9999 || t.Nanosecond() != 0 || t.UTC().Format(time.RFC3339) != s {
		return time.Time{}, ErrInvalidEnvelope
	}
	return t.UTC(), nil
}

func tlsGrantWindow(issued, expires string, limit time.Duration) bool {
	i, err := tlsGrantSecondTime(issued)
	if err != nil {
		return false
	}
	e, err := tlsGrantSecondTime(expires)
	return err == nil && e.After(i) && e.Sub(i) <= limit
}

func tlsGrantDigest(s string) bool { return canonicalSHA256Hex(s) && s != strings.Repeat("0", 64) }

// ValidateOwnerTLSLeafGrantClaims checks fixed structure without trusting an
// identity or authorizing issuance. Store and Node must separately check live
// binding, independently registered trust, exact candidate and public crypto.
func ValidateOwnerTLSLeafGrantClaims(c OwnerTLSLeafGrantClaims) error {
	if c.Version != 1 || c.Role != "node" || c.ApplicationProtocol != NodeTLSApplicationProtocol || c.PQProfile != NodeTLSPQProfile || !tlsGrantDNS(c.DNSName) {
		return ErrInvalidEnvelope
	}
	for _, s := range []string{c.RequestID, c.HubID, c.NodeID, c.OwnerID, c.OwnerKeyID, c.ClientDeviceID, c.OwnerBindingID, c.NodeControlKeyID, c.HubControlKeyID, c.IssuerGeneration, c.CredentialDigest} {
		if !tlsGrantToken(s) {
			return ErrInvalidEnvelope
		}
	}
	for _, v := range []uint64{c.OwnerKeyVersion, c.ClientDeviceVersion, c.OwnerBindingVersion, c.CredentialVersion, c.NodeControlKeyVersion, c.NodeControlKeyEpoch, c.NodeControlBindingVersion, c.HubControlKeyVersion, c.TLSEpoch} {
		if v == 0 || v > math.MaxInt64 {
			return ErrInvalidEnvelope
		}
	}
	if c.ExpectedTLSEpochFloor >= math.MaxInt64 || c.TLSEpoch != c.ExpectedTLSEpochFloor+1 {
		return ErrInvalidEnvelope
	}
	for _, s := range []string{c.CSRDERHash, c.SPKIDERHash, c.IssuerSPKIHash, c.IssuerDERHash, c.RootDERHash, c.HubSPKIHash, c.HubTrustAnchorDERHash, c.Nonce} {
		if !tlsGrantDigest(s) {
			return ErrInvalidEnvelope
		}
	}
	serial, err := hex.DecodeString(c.Serial)
	if err != nil || len(serial) != 16 || hex.EncodeToString(serial) != c.Serial || bytes.Equal(serial, make([]byte, 16)) {
		return ErrInvalidEnvelope
	}
	if !tlsGrantWindow(c.NotBefore, c.NotAfter, 24*time.Hour) || !tlsGrantWindow(c.IssuedAt, c.ExpiresAt, 24*time.Hour) {
		return ErrInvalidEnvelope
	}
	na, _ := tlsGrantSecondTime(c.NotAfter)
	exp, _ := tlsGrantSecondTime(c.ExpiresAt)
	if exp.After(na) {
		return ErrInvalidEnvelope
	}
	u, err := url.Parse(c.HubPQOrigin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" || !tlsGrantDNS(u.Hostname()) || u.String() != c.HubPQOrigin {
		return ErrInvalidEnvelope
	}
	a, err := url.Parse(c.ApplicationOrigin)
	if err != nil || (a.Scheme != "http" && a.Scheme != "https") || a.Host == "" || a.User != nil || a.RawQuery != "" || a.ForceQuery || a.Opaque != "" || a.Fragment != "" || a.Path != "" || a.RawPath != "" || a.String() != c.ApplicationOrigin {
		return ErrInvalidEnvelope
	}
	if a.Scheme == "http" && a.Hostname() != "localhost" {
		ip := net.ParseIP(a.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func validateTLSAck(c NodeTLSInstallAckClaims) error {
	if c.Version != 1 || ValidateOwnerTLSLeafGrantClaims(c.GrantClaims) != nil || !tlsGrantDigest(c.GrantDigest) || !tlsGrantDigest(c.LeafDERHash) || !tlsGrantDigest(c.Nonce) || c.ReservationVersion == 0 || c.ReservationVersion > math.MaxInt64 || !tlsGrantWindow(c.IssuedAt, c.ExpiresAt, 24*time.Hour) {
		return ErrInvalidEnvelope
	}
	e, _ := tlsGrantSecondTime(c.ExpiresAt)
	ge, _ := tlsGrantSecondTime(c.GrantClaims.ExpiresAt)
	if e.After(ge) {
		return ErrInvalidEnvelope
	}
	return nil
}

func validateTLSActivation(c NodeTLSActivationClaims) error {
	if c.Version != 1 || validateTLSAck(c.InstallAckClaims) != nil || !tlsGrantDigest(c.InstallAckDigest) || !tlsGrantDigest(c.Nonce) || c.ActivationVersion == 0 || c.ActivationVersion > math.MaxInt64 || !tlsGrantWindow(c.IssuedAt, c.ExpiresAt, 24*time.Hour) {
		return ErrInvalidEnvelope
	}
	e, _ := tlsGrantSecondTime(c.ExpiresAt)
	ae, _ := tlsGrantSecondTime(c.InstallAckClaims.ExpiresAt)
	if e.After(ae) {
		return ErrInvalidEnvelope
	}
	return nil
}

func tlsProofSignature(identity *Identity, signerID, domain string, claims any) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil || identity.Public().ID != signerID {
		return nil, ErrInvalidEnvelope
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err = mldsa65.SignTo(identity.signingPrivate, append([]byte(domain), data...), nil, true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

func tlsProofRead(wire []byte, target any) error {
	if len(wire) == 0 || len(wire) > MaxNodeTLSProofBytes {
		return ErrInvalidEnvelope
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrInvalidEnvelope
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(wire, canonical) {
		return ErrInvalidEnvelope
	}
	return nil
}

func tlsProofVerify(trusted PublicIdentity, signerID, domain string, claims any, signature []byte, issued, expires string, at time.Time) error {
	if at.IsZero() || ValidatePublicIdentity(trusted) != nil || trusted.ID != signerID || len(signature) != mldsa65.SignatureSize {
		return ErrInvalidEnvelope
	}
	i, err := tlsGrantSecondTime(issued)
	if err != nil {
		return ErrInvalidEnvelope
	}
	e, err := tlsGrantSecondTime(expires)
	if err != nil || i.After(at) || !at.Before(e) {
		return ErrInvalidEnvelope
	}
	_, public, err := validatePublic(trusted)
	if err != nil {
		return ErrInvalidEnvelope
	}
	data, err := json.Marshal(claims)
	if err != nil || !mldsa65.Verify(public, append([]byte(domain), data...), nil, signature) {
		return ErrInvalidEnvelope
	}
	return nil
}

func SignOwnerTLSLeafGrant(identity *Identity, claims OwnerTLSLeafGrantClaims) ([]byte, error) {
	if err := ValidateOwnerTLSLeafGrantClaims(claims); err != nil {
		return nil, err
	}
	sig, err := tlsProofSignature(identity, claims.OwnerKeyID, ownerTLSLeafDomain, claims)
	if err != nil {
		return nil, err
	}
	return json.Marshal(OwnerTLSLeafGrant{claims, sig})
}
func VerifyOwnerTLSLeafGrant(trusted PublicIdentity, at time.Time, wire []byte) (OwnerTLSLeafGrantClaims, error) {
	var p OwnerTLSLeafGrant
	if tlsProofRead(wire, &p) != nil || ValidateOwnerTLSLeafGrantClaims(p.Claims) != nil {
		return OwnerTLSLeafGrantClaims{}, ErrInvalidEnvelope
	}
	if err := tlsProofVerify(trusted, p.Claims.OwnerKeyID, ownerTLSLeafDomain, p.Claims, p.Signature, p.Claims.IssuedAt, p.Claims.ExpiresAt, at); err != nil {
		return OwnerTLSLeafGrantClaims{}, err
	}
	return p.Claims, nil
}
func SignNodeTLSInstallAck(identity *Identity, claims NodeTLSInstallAckClaims) ([]byte, error) {
	if err := validateTLSAck(claims); err != nil {
		return nil, err
	}
	sig, err := tlsProofSignature(identity, claims.GrantClaims.NodeControlKeyID, nodeTLSInstallDomain, claims)
	if err != nil {
		return nil, err
	}
	return json.Marshal(NodeTLSInstallAck{claims, sig})
}
func VerifyNodeTLSInstallAck(trusted PublicIdentity, at time.Time, wire []byte) (NodeTLSInstallAckClaims, error) {
	var p NodeTLSInstallAck
	if tlsProofRead(wire, &p) != nil || validateTLSAck(p.Claims) != nil {
		return NodeTLSInstallAckClaims{}, ErrInvalidEnvelope
	}
	if err := tlsProofVerify(trusted, p.Claims.GrantClaims.NodeControlKeyID, nodeTLSInstallDomain, p.Claims, p.Signature, p.Claims.IssuedAt, p.Claims.ExpiresAt, at); err != nil {
		return NodeTLSInstallAckClaims{}, err
	}
	return p.Claims, nil
}
func SignNodeTLSActivation(identity *Identity, claims NodeTLSActivationClaims) ([]byte, error) {
	if err := validateTLSActivation(claims); err != nil {
		return nil, err
	}
	sig, err := tlsProofSignature(identity, claims.InstallAckClaims.GrantClaims.HubControlKeyID, nodeTLSActivationDomain, claims)
	if err != nil {
		return nil, err
	}
	return json.Marshal(NodeTLSActivation{claims, sig})
}
func VerifyNodeTLSActivation(trusted PublicIdentity, at time.Time, wire []byte) (NodeTLSActivationClaims, error) {
	var p NodeTLSActivation
	if tlsProofRead(wire, &p) != nil || validateTLSActivation(p.Claims) != nil {
		return NodeTLSActivationClaims{}, ErrInvalidEnvelope
	}
	if err := tlsProofVerify(trusted, p.Claims.InstallAckClaims.GrantClaims.HubControlKeyID, nodeTLSActivationDomain, p.Claims, p.Signature, p.Claims.IssuedAt, p.Claims.ExpiresAt, at); err != nil {
		return NodeTLSActivationClaims{}, err
	}
	return p.Claims, nil
}
