package hubtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

// DiscoveryCandidate is public, untrusted external identity data. It offers no
// Doer/client or Trusted bit. Only an independently pinned App plus the local
// Node pairing S/E/ACK ceremony can authorize its first durable pin.
type DiscoveryCandidate struct {
	Descriptor                  Descriptor
	DescriptorText, DialAddress string
}

// DiscoverCandidate reads public material from one numeric socket. The first
// handshake intentionally fails verification with an empty trust pool; its
// exposed certificate chain is data only. The second handshake verifies that
// same candidate CA/name/SPKI and can send exactly one public GET. Neither
// handshake disables verification, supplies a token, or opens a business path.
func DiscoverCandidate(parent context.Context, dial string) (DiscoveryCandidate, error) {
	var zero DiscoveryCandidate
	if parent == nil || pqtls.ValidateIPDialAddress(dial) != nil {
		return zero, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	ip, _, e := net.SplitHostPort(dial)
	if e != nil {
		return zero, ErrInvalid
	}
	probe := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ip, RootCAs: x509.NewCertPool()}}
	conn, err := probe.DialContext(ctx, "tcp", dial)
	if conn != nil {
		conn.Close()
	}
	var verification *tls.CertificateVerificationError
	if err == nil || !errors.As(err, &verification) || len(verification.UnverifiedCertificates) != 2 {
		return zero, ErrInvalid
	}
	leaf, root := verification.UnverifiedCertificates[0], verification.UnverifiedCertificates[1]
	if len(root.Raw) > MaxRootCertificateBytes || len(leaf.Raw) > MaxRootCertificateBytes || !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return zero, ErrInvalid
	}
	name := ""
	if len(leaf.DNSNames) == 1 && len(leaf.IPAddresses) == 0 {
		name = leaf.DNSNames[0]
	} else if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 1 {
		name = leaf.IPAddresses[0].String()
	} else {
		return zero, ErrInvalid
	}
	u, err := url.Parse("https://" + net.JoinHostPort(name, "443"))
	if err != nil || u.Hostname() != name || u.User != nil || u.Path != "" || len(name) > 253 {
		return zero, ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo) != spki {
			return ErrInvalid
		}
		return nil
	}}, DisableKeepAlives: true, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 8 << 10}
	tr.DialContext = func(c context.Context, network, address string) (net.Conn, error) {
		if address != dial || network != "tcp" {
			return nil, ErrInvalid
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c, "tcp", dial)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+dial+wire.NodePairTrustDescriptorPath, nil)
	if err != nil {
		return zero, ErrInvalid
	}
	request.Header.Set("Accept", "text/plain")
	response, err := client.Do(request)
	if err != nil {
		return zero, ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil {
		return zero, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(MaxDescriptorText)+1))
	if err != nil || len(raw) > MaxDescriptorText {
		return zero, ErrInvalid
	}
	d, err := DecodeDescriptor(string(raw))
	if err != nil || ValidateDescriptor(d, time.Now()) != nil || d.Claims.ServerName != name || !bytes.Equal(d.Claims.RootCertificateDER, root.Raw) {
		return zero, ErrInvalid
	}
	live := response.TLS.PeerCertificates[0]
	if !bytes.Equal(live.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		return zero, ErrInvalid
	}
	// Constructor validation repeats the signed SPKI comparison without
	// producing a reusable discovery transport for the caller.
	if d.Claims.ServerSPKISHA256 != hex.EncodeToString(spki[:]) {
		return zero, ErrInvalid
	}
	return DiscoveryCandidate{d, string(raw), dial}, nil
}
