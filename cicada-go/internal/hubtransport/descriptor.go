// Package hubtransport binds an independently supplied Hub connection descriptor
// to verified standard TLS. Numeric reachability is separate from application
// origin and identity. No descriptor is an account or business authorization.
package hubtransport

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

const (
	DescriptorFormat        = "cicada.hub-transport.v1"
	DescriptorPrefix        = "cicada-hub-transport-v1:"
	BootstrapFormat         = "cicada.hub-bootstrap.v1"
	BootstrapPrefix         = "cicada-hub-bootstrap-v1:"
	Version                 = 1
	MaxDescriptorBytes      = 32 * 1024
	MaxBootstrapBytes       = 64 * 1024
	MaxRootCertificateBytes = 8 * 1024
	MaxDescriptorText       = len(DescriptorPrefix) + (MaxDescriptorBytes*8+5)/6
	MaxBootstrapText        = len(BootstrapPrefix) + (MaxBootstrapBytes*8+5)/6
)

var ErrInvalid = errors.New("invalid Hub connection material")
var ErrOrigin = errors.New("Hub transport origin rejected")

// Claims contains public installation data only. Its signature binds the two
// retained PQ identities to one exact logical origin and native TLS profile.
// DialAddress is deliberately absent: changing reachability grants no rights.
type Claims struct {
	Format                string              `json:"format"`
	Version               int                 `json:"version"`
	Origin                string              `json:"origin"`
	Hub                   wire.HubIdentity    `json:"hub"`
	HubFingerprint        string              `json:"hub_fingerprint"`
	NodeControl           e2ee.PublicIdentity `json:"node_control"`
	NodeControlKeyVersion uint64              `json:"node_control_key_version"`
	TransportEpoch        uint64              `json:"transport_epoch"`
	ServerName            string              `json:"server_name"`
	RootCertificateDER    []byte              `json:"root_certificate_der"`
	ServerSPKISHA256      string              `json:"server_spki_sha256"`
}

type Descriptor struct {
	Claims    Claims `json:"claims"`
	Signature []byte `json:"signature"`
}

// Bootstrap carries the unchanged activation-v1 text, including its one-use
// secret. Never log or publish this wrapper. Descriptor alone is public.
type Bootstrap struct {
	Format         string     `json:"format"`
	Version        int        `json:"version"`
	Descriptor     Descriptor `json:"descriptor"`
	ActivationCode string     `json:"activation_code"`
}

func (Bootstrap) String() string   { return "hubtransport.Bootstrap[redacted]" }
func (Bootstrap) GoString() string { return "hubtransport.Bootstrap[redacted]" }

// DefaultOrigin is for a pristine setup only. Existing READY origins remain
// immutable. The 54-character DNS label never requires a DNS lookup.
func DefaultOrigin(hubID string) (string, error) {
	if !validID(hubID) {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte("cicada/hub/logical-origin/v1\x00" + hubID))
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
	return "https://h-" + label + ".cicada.invalid", nil
}

func validID(v string) bool {
	if v == "" || len(v) > 128 || !utf8.ValidString(v) || strings.ContainsAny(v, "/\\") {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func claimsDigest(c Claims) [32]byte {
	raw, _ := json.Marshal(c)
	return sha256.Sum256(append([]byte("cicada/hub/connection-claims/v1\x00"), raw...))
}

func SignDescriptor(hub *e2ee.Identity, c Claims) (Descriptor, error) {
	if hub == nil || !reflect.DeepEqual(hub.Public(), c.Hub.Public) || validateClaims(c, time.Time{}) != nil {
		return Descriptor{}, ErrInvalid
	}
	signature, err := e2ee.SignHubTransportBinding(hub, claimsDigest(c))
	if err != nil {
		return Descriptor{}, ErrInvalid
	}
	return Descriptor{Claims: c, Signature: signature}, nil
}

// ValidateDescriptor verifies structure and the internal binding, not external
// trust. The caller must obtain this descriptor via a trusted local channel or
// match an already independently retained complete Hub fingerprint. A zero at
// skips CA time checks only, for parsing retained historical connection data.
func ValidateDescriptor(d Descriptor, at time.Time) error {
	if validateClaims(d.Claims, at) != nil || e2ee.VerifyHubTransportBinding(d.Claims.Hub.Public, claimsDigest(d.Claims), d.Signature) != nil {
		return ErrInvalid
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > MaxDescriptorBytes {
		return ErrInvalid
	}
	return nil
}

func validateClaims(c Claims, at time.Time) error {
	fp, err := wire.HubFingerprint(c.Hub)
	if err != nil || c.Format != DescriptorFormat || c.Version != Version || !validID(c.Hub.HubID) || fp != c.HubFingerprint ||
		e2ee.ValidatePublicIdentity(c.NodeControl) != nil || c.NodeControl.ID == c.Hub.Public.ID || c.NodeControlKeyVersion != 1 ||
		c.TransportEpoch == 0 || c.TransportEpoch > math.MaxInt64 || !canonicalHash(c.ServerSPKISHA256) {
		return ErrInvalid
	}
	origin, err := ownerbootstrap.CanonicalOrigin(c.Origin, false)
	u, parseErr := url.Parse(c.Origin)
	if err != nil || parseErr != nil || origin != c.Origin || len(origin) > 2048 || c.ServerName == "" || c.ServerName != u.Hostname() {
		return ErrInvalid
	}
	if len(c.RootCertificateDER) == 0 || len(c.RootCertificateDER) > MaxRootCertificateBytes {
		return ErrInvalid
	}
	root, err := x509.ParseCertificate(c.RootCertificateDER)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 ||
		root.CheckSignatureFrom(root) != nil || (!at.IsZero() && (at.Before(root.NotBefore) || !at.Before(root.NotAfter))) {
		return ErrInvalid
	}
	return nil
}

func canonicalHash(v string) bool {
	raw, err := hex.DecodeString(v)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == v
}

// MatchNodeControl checks metadata fetched only through verified TLS against
// the Node-Control identity bound by the independently supplied descriptor.
func MatchNodeControl(d Descriptor, hubID string, public e2ee.PublicIdentity, keyVersion uint64, fingerprint string) error {
	if ValidateDescriptor(d, time.Time{}) != nil || hubID != d.Claims.Hub.HubID || keyVersion != d.Claims.NodeControlKeyVersion ||
		!reflect.DeepEqual(public, d.Claims.NodeControl) || fingerprint != nodewire.IdentityFingerprint(public) {
		return ErrInvalid
	}
	return nil
}

func ValidateBootstrap(b Bootstrap, at time.Time) (wire.ActivationMaterial, error) {
	if b.Format != BootstrapFormat || b.Version != Version || ValidateDescriptor(b.Descriptor, at) != nil {
		return wire.ActivationMaterial{}, ErrInvalid
	}
	m, err := wire.DecodeActivationCode(b.ActivationCode)
	if err != nil || wire.ValidateActivationHub(m, b.Descriptor.Claims.Hub, at) != nil || m.Origin != b.Descriptor.Claims.Origin {
		return wire.ActivationMaterial{}, ErrInvalid
	}
	return m, nil
}
