package hubtransport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cicada-ai/cicada/internal/pqtls"
)

// Transport owns one immutable Hub origin, TLS identity and numeric locator.
// Construct a new transport and close the old idle pool when the user changes
// locator. It does not change any application scope, packet or authorization.
type Transport struct {
	base   *http.Transport
	origin string
	host   string
}

func NewTransport(d Descriptor, dialAddress string) (*Transport, error) {
	if ValidateDescriptor(d, time.Now()) != nil || pqtls.ValidateIPDialAddress(dialAddress) != nil {
		return nil, ErrInvalid
	}
	u, err := url.Parse(d.Claims.Origin)
	if err != nil {
		return nil, ErrInvalid
	}
	root, err := x509.ParseCertificate(d.Claims.RootCertificateDER)
	if err != nil {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	pin, _ := hex.DecodeString(d.Claims.ServerSPKISHA256)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	logicalAddress := net.JoinHostPort(u.Hostname(), port)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	base := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != logicalAddress {
				return nil, ErrOrigin
			}
			return dialer.DialContext(ctx, "tcp", dialAddress)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: d.Claims.ServerName,
			// Standard chain/name/time verification runs first, on the live
			// clock. VerifyConnection also checks resumed connections.
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
					return ErrInvalid
				}
				digest := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(digest[:], pin) != 1 {
					return ErrInvalid
				}
				return nil
			},
		},
		MaxIdleConns: 8, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
	}
	return &Transport{base: base, origin: d.Claims.Origin, host: u.Host}, nil
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t == nil || r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Fragment != "" ||
		r.URL.Scheme+"://"+r.URL.Host != t.origin || (r.Host != "" && r.Host != t.host) ||
		(r.Header.Get("Origin") != "" && r.Header.Get("Origin") != t.origin) {
		return nil, ErrOrigin
	}
	return t.base.RoundTrip(r)
}

func (t *Transport) CloseIdleConnections() {
	if t != nil && t.base != nil {
		t.base.CloseIdleConnections()
	}
}

// A zero timeout supports streaming Node requests. Individual requests still
// carry cancellation; handshake and response-header waits remain bounded.
func NewHTTPClient(d Descriptor, dialAddress string, timeout time.Duration) (*http.Client, error) {
	if timeout < 0 {
		return nil, ErrInvalid
	}
	transport, err := NewTransport(d, dialAddress)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
