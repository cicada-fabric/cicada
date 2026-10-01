// Package pqtls is an optional, fail-closed OpenSSL transport experiment.
// It does not authorize CICADA requests or replace application-layer E2EE.
package pqtls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	OpenSSLVersion      = "3.5.9"
	OpenSSLSourceSHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
)

// Error has stable classification without including keys or peer payloads.
type Error struct{ Kind string }

func (e *Error) Error() string { return "pqtls: " + e.Kind }

var (
	ErrUnavailable = &Error{Kind: "unavailable"}
	ErrProfile     = &Error{Kind: "profile_mismatch"}
	ErrIdentity    = &Error{Kind: "identity_mismatch"}
	ErrConfig      = &Error{Kind: "invalid_configuration"}
	ErrHTTPState   = &Error{Kind: "unsupported_http_tls_state"}
)

// Identity is a certificate's explicitly approved connection identity.
// BindingEpoch is informational: the eventual route owner must recheck it.
type Identity struct {
	Kind         string // "hub" or "node"
	HubID        string
	NodeID       string
	BindingEpoch uint64
	DNSName      string // exact SAN DNS service identity, without wildcards
}
type Pin struct {
	Kind   string // "certificate-sha256" or "spki-sha256"
	SHA256 [32]byte
}
type Peer struct {
	Identity Identity
	Pin      Pin
}
type Config struct {
	CertificateFile      string // separate ML-DSA-65 TLS chain; never E2EE keys
	PrivateKeyFile       string
	TrustFile            string // explicit trust anchors, never OS defaults/TOFU
	LocalIdentity        Identity
	Peers                []Peer // client: one hub; server: explicit approved node list
	HandshakeTimeout     time.Duration
	MaxPendingHandshakes int // server only; includes verified, unaccepted peers
}
type State struct {
	TLSVersion         string
	Group              string
	CipherSuite        string
	PeerSignature      string
	ALPN               string
	VerificationResult int64
	HostnameVerified   bool
	Peer               Identity
	CertificateSHA256  [32]byte
	SPKISHA256         [32]byte
}

func validIdentity(v Identity) bool {
	if v.HubID == "" || len(v.HubID) > 256 || v.DNSName == "" || len(v.DNSName) > 253 {
		return false
	}
	if v.Kind == "hub" {
		if v.NodeID != "" || v.BindingEpoch != 0 {
			return false
		}
	} else if v.Kind == "node" {
		if v.NodeID == "" || len(v.NodeID) > 256 || v.BindingEpoch == 0 {
			return false
		}
	} else {
		return false
	}
	if net.ParseIP(v.DNSName) != nil {
		return false
	}
	for _, label := range strings.Split(v.DNSName, ".") {
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
func normalizeConfig(cfg Config, server bool) (Config, error) {
	for _, path := range []string{cfg.CertificateFile, cfg.PrivateKeyFile, cfg.TrustFile} {
		if path == "" || len(path) > 4096 || strings.IndexByte(path, 0) >= 0 {
			return Config{}, ErrConfig
		}
	}
	if cfg.CertificateFile == "" || cfg.PrivateKeyFile == "" || cfg.TrustFile == "" || !validIdentity(cfg.LocalIdentity) || len(cfg.Peers) == 0 || len(cfg.Peers) > 64 {
		return Config{}, ErrConfig
	}
	if server != (cfg.LocalIdentity.Kind == "hub") || !server && len(cfg.Peers) != 1 {
		return Config{}, ErrConfig
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.HandshakeTimeout < 0 || cfg.HandshakeTimeout > time.Minute {
		return Config{}, ErrConfig
	}
	if server {
		if cfg.MaxPendingHandshakes == 0 {
			cfg.MaxPendingHandshakes = 16
		}
		if cfg.MaxPendingHandshakes < 1 || cfg.MaxPendingHandshakes > 64 {
			return Config{}, ErrConfig
		}
	} else if cfg.MaxPendingHandshakes != 0 {
		return Config{}, ErrConfig
	}
	seen := make(map[Pin]bool)
	for _, p := range cfg.Peers {
		if !validIdentity(p.Identity) || p.Identity.Kind == cfg.LocalIdentity.Kind || p.Identity.HubID != cfg.LocalIdentity.HubID || p.Pin.SHA256 == [32]byte{} || p.Pin.Kind != "certificate-sha256" && p.Pin.Kind != "spki-sha256" || seen[p.Pin] {
			return Config{}, ErrConfig
		}
		seen[p.Pin] = true
	}
	cfg.Peers = append([]Peer(nil), cfg.Peers...)
	return cfg, nil
}

type Client struct{ cfg Config }

func NewClient(cfg Config) (*Client, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	cfg, err := normalizeConfig(cfg, false)
	if err != nil {
		return nil, err
	}
	if err = checkMaterial(cfg); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c == nil || len(c.cfg.Peers) != 1 {
		return nil, ErrConfig
	}
	if ctx == nil || network != "tcp" {
		return nil, ErrConfig
	}
	return dial(ctx, address, c.cfg)
}
func Listen(network, address string, cfg Config) (net.Listener, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	cfg, err := normalizeConfig(cfg, true)
	if err != nil {
		return nil, err
	}
	if network != "tcp" {
		return nil, ErrConfig
	}
	if err = checkMaterial(cfg); err != nil {
		return nil, err
	}
	return listen(address, cfg)
}

// HTTPTransport restricts HTTPS to one preapproved origin and HTTP/1.1.
// A caller's http.Client should also reject redirects. Plain HTTP is rejected.
func (c *Client) HTTPTransport(address string) (*http.Transport, error) {
	if c == nil || len(c.cfg.Peers) != 1 {
		return nil, ErrConfig
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, ErrConfig
	}
	return &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DialContext:  func(context.Context, string, string) (net.Conn, error) { return nil, ErrProfile },
		DialTLSContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != address {
				return nil, ErrIdentity
			}
			return c.DialContext(ctx, network, target)
		},
	}, nil
}

type stateConn interface{ PQTLSState() State }
type stateKey struct{}

// HTTPConnContext is suitable for http.Server.ConnContext. Request.TLS remains
// nil because this connection is not crypto/tls.Conn; use StateFromContext.
func HTTPConnContext(ctx context.Context, conn net.Conn) context.Context {
	if c, ok := conn.(stateConn); ok {
		return context.WithValue(ctx, stateKey{}, c.PQTLSState())
	}
	return ctx
}
func StateFromContext(ctx context.Context) (State, error) {
	v, ok := ctx.Value(stateKey{}).(State)
	if !ok {
		return State{}, ErrHTTPState
	}
	return v, nil
}

// RequireGoTLSState always fails: synthesized crypto/tls state cannot represent
// these OpenSSL peer certificates or prove Go HTTP/2 compatibility.
func RequireGoTLSState(net.Conn) (tls.ConnectionState, error) {
	return tls.ConnectionState{}, ErrHTTPState
}

func failure(kind error, operation string) error { return fmt.Errorf("pqtls %s: %w", operation, kind) }
func isClosed(err error) bool                    { return errors.Is(err, net.ErrClosed) }
