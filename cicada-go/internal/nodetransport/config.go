// Package nodetransport defines private, operator-approved Node TLS coordinates.
// These approvals narrow existing Store authority; they never enroll a Node.
package nodetransport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/pqtls"
)

var ErrConfiguration = errors.New("invalid private Node PQ transport configuration")

type Identity struct {
	Kind     string `json:"kind"`
	HubID    string `json:"hub_id"`
	NodeID   string `json:"node_id,omitempty"`
	TLSEpoch uint64 `json:"tls_epoch,omitempty"`
	DNSName  string `json:"dns_name"`
}

func (v Identity) TLSIdentity() pqtls.Identity {
	return pqtls.Identity{Kind: v.Kind, HubID: v.HubID, NodeID: v.NodeID, BindingEpoch: v.TLSEpoch, DNSName: v.DNSName}
}

type Approval struct {
	Identity          Identity `json:"identity"`
	PinKind           string   `json:"pin_kind"`
	PinSHA256         string   `json:"pin_sha256"`
	OwnerID           string   `json:"owner_id,omitempty"`
	OwnerKeyID        string   `json:"owner_key_id,omitempty"`
	BindingID         string   `json:"binding_id,omitempty"`
	BindingVersion    int64    `json:"binding_version,omitempty"`
	CredentialVersion int64    `json:"credential_version,omitempty"`
}
type Config struct {
	Version           int        `json:"version"`
	Role              string     `json:"role"`
	Listen            string     `json:"listen,omitempty"`
	Origin            string     `json:"origin,omitempty"`
	ApplicationOrigin string     `json:"application_origin,omitempty"`
	CertificateFile   string     `json:"certificate_file"`
	PrivateKeyFile    string     `json:"private_key_file"`
	TrustFile         string     `json:"trust_file"`
	Identity          Identity   `json:"identity"`
	Peers             []Approval `json:"peers"`
}

// Load refuses public/symlink configuration and keys and unknown/trailing JSON.
// Paths are resolved relative to the private configuration file, not cwd.
func Load(path, role string) (*Config, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 128<<10 {
		return nil, ErrConfiguration
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, (128<<10)+1))
	d.DisallowUnknownFields()
	var cfg Config
	if d.Decode(&cfg) != nil {
		return nil, ErrConfiguration
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return nil, ErrConfiguration
	}
	for _, target := range []*string{&cfg.CertificateFile, &cfg.PrivateKeyFile, &cfg.TrustFile} {
		if *target == "" {
			return nil, ErrConfiguration
		}
		if !filepath.IsAbs(*target) {
			*target = filepath.Join(filepath.Dir(path), *target)
		}
		info, err := os.Lstat(*target)
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrConfiguration
		}
	}
	keyInfo, err := os.Lstat(cfg.PrivateKeyFile)
	if err != nil || keyInfo.Mode().Perm()&0077 != 0 {
		return nil, ErrConfiguration
	}
	if err := cfg.Validate(role); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate(role string) error {
	if c == nil || c.Version != 1 || c.Role != role || c.Identity.Kind != role || c.Identity.HubID == "" || c.Identity.DNSName == "" || len(c.Peers) < 1 || len(c.Peers) > 64 {
		return ErrConfiguration
	}
	if role == "hub" {
		if c.Identity.NodeID != "" || c.Identity.TLSEpoch != 0 || c.Origin != "" || c.ApplicationOrigin != "" {
			return ErrConfiguration
		}
		if _, _, err := net.SplitHostPort(c.Listen); err != nil {
			return ErrConfiguration
		}
	} else if role == "node" {
		if c.Identity.NodeID == "" || c.Identity.TLSEpoch == 0 || c.Listen != "" || len(c.Peers) != 1 {
			return ErrConfiguration
		}
		if _, err := ParseOrigin(c.Origin); err != nil {
			return err
		}
		if err := validateApplicationOrigin(c.LogicalOrigin()); err != nil {
			return err
		}
	} else {
		return ErrConfiguration
	}
	seenNode, seenPin := map[string]bool{}, map[string]bool{}
	for _, p := range c.Peers {
		bytes, err := hex.DecodeString(p.PinSHA256)
		if err != nil || len(bytes) != 32 || p.PinSHA256 != strings.ToLower(p.PinSHA256) || p.PinSHA256 == strings.Repeat("0", 64) || (p.PinKind != "certificate-sha256" && p.PinKind != "spki-sha256") || seenPin[p.PinSHA256] || p.Identity.HubID != c.Identity.HubID {
			return ErrConfiguration
		}
		seenPin[p.PinSHA256] = true
		if role == "hub" {
			if p.Identity.Kind != "node" || p.Identity.NodeID == "" || p.Identity.TLSEpoch == 0 || seenNode[p.Identity.NodeID] || p.OwnerID == "" || p.OwnerKeyID == "" || p.BindingID == "" || p.BindingVersion < 1 || p.CredentialVersion < 1 {
				return ErrConfiguration
			}
			seenNode[p.Identity.NodeID] = true
		} else if p.Identity.Kind != "hub" || p.Identity.NodeID != "" || p.Identity.TLSEpoch != 0 || p.BindingID != "" || p.BindingVersion != 0 || p.CredentialVersion != 0 || p.OwnerID != "" || p.OwnerKeyID != "" {
			return ErrConfiguration
		}
	}
	return nil
}

func (c *Config) TLSConfig() pqtls.Config {
	cfg := pqtls.Config{CertificateFile: c.CertificateFile, PrivateKeyFile: c.PrivateKeyFile, TrustFile: c.TrustFile, LocalIdentity: c.Identity.TLSIdentity()}
	for _, p := range c.Peers {
		var hash [32]byte
		raw, _ := hex.DecodeString(p.PinSHA256)
		copy(hash[:], raw)
		cfg.Peers = append(cfg.Peers, pqtls.Peer{Identity: p.Identity.TLSIdentity(), Pin: pqtls.Pin{Kind: p.PinKind, SHA256: hash}})
	}
	return cfg
}

func ParseOrigin(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrConfiguration
	}
	return u, nil
}

func (c *Config) LogicalOrigin() string {
	if c.ApplicationOrigin != "" {
		return c.ApplicationOrigin
	}
	return c.Origin
}

func validateApplicationOrigin(origin string) error {
	if _, err := ParseOrigin(origin); err == nil {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return ErrConfiguration
	}
	// Existing isolated loopback fixtures may retain their original logical
	// origin. Every enrolled request still goes to the explicit HTTPS PQ origin.
	if u.Hostname() != "localhost" {
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return ErrConfiguration
		}
	}
	return nil
}

// IsEnrolledNodePath is shared by the destination selector and BOTH Hub
// listener Guards. Public Client/bootstrap paths are deliberately excluded.
func IsEnrolledNodePath(path string) bool {
	if path == "/v2/node/control/rpc" || path == "/v2/node/control/key-upgrade" || strings.HasPrefix(path, "/v2/relay/") || path == "/v2/fabric" || strings.HasPrefix(path, "/v2/fabric/") {
		return true
	}
	for _, prefix := range []string{"/v2/artifacts", "/v2/artifact-refs", "/v2/fabric/artifacts", "/v2/fabric/artifact-refs"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

type originTransport struct {
	origin        string
	logicalOrigin string
	destination   *url.URL
	base          *http.Transport
	bootstrap     http.RoundTripper
}

func (t *originTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.logicalOrigin || r.URL.User != nil || r.URL.Fragment != "" || (r.Host != "" && r.Host != r.URL.Host) {
		return nil, pqtls.ErrIdentity
	}
	if t.logicalOrigin != t.origin {
		if !IsEnrolledNodePath(r.URL.Path) {
			return t.bootstrap.RoundTrip(r)
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = t.destination.Scheme, t.destination.Host
		r.Host = t.destination.Host
	}
	return t.base.RoundTrip(r)
}
func (t *originTransport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
	if transport, ok := t.bootstrap.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

// NewTransport never falls back to Go TLS or plaintext, including unavailable builds.
func NewTransport(c *Config) (http.RoundTripper, error) {
	if err := c.Validate("node"); err != nil {
		return nil, err
	}
	u, err := ParseOrigin(c.Origin)
	if err != nil {
		return nil, err
	}
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "443")
	}
	client, err := pqtls.NewClient(c.TLSConfig())
	if err != nil {
		return nil, err
	}
	base, err := client.HTTPTransport(address)
	if err != nil {
		return nil, err
	}
	base.MaxIdleConnsPerHost = 4
	base.MaxConnsPerHost = 8
	base.IdleConnTimeout = 60 * time.Second
	base.ResponseHeaderTimeout = 30 * time.Second
	var bootstrap http.RoundTripper
	if c.LogicalOrigin() != c.Origin {
		// Separate frontdoor selection is made before dialing; an error from
		// the PQ transport is always returned and never enters this branch.
		if transport, ok := http.DefaultTransport.(*http.Transport); ok {
			bootstrap = transport.Clone()
		} else {
			return nil, ErrConfiguration
		}
	}
	return &originTransport{origin: c.Origin, logicalOrigin: c.LogicalOrigin(), destination: u, base: base, bootstrap: bootstrap}, nil
}
