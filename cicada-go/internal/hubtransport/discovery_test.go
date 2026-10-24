package hubtransport

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func discoveryFixture(t *testing.T) (fixture, tls.Certificate, string) {
	t.Helper()
	f := newFixture(t)
	cert := f.leaf
	cert.Certificate = append(append([][]byte(nil), cert.Certificate...), f.ca.Raw)
	text, err := EncodeDescriptor(f.d)
	if err != nil {
		t.Fatal(err)
	}
	return f, cert, text
}

func TestNodePairDiscoveryCandidateUsesOnlyPublicGETAndNeverGlobalTrust(t *testing.T) {
	f, cert, text := discoveryFixture(t)
	var public, business atomic.Int32
	s := serveFixture(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wire.NodePairTrustDescriptorPath {
			business.Add(1)
			w.WriteHeader(403)
			return
		}
		public.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 || r.URL.RawQuery != "" {
			t.Error("public probe carried credentials/body/parameters")
		}
		_, _ = io.WriteString(w, text)
	}))
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	c, err := DiscoverCandidate(context.Background(), s.Listener.Addr().String())
	if err != nil || c.DescriptorText != text || c.DialAddress != s.Listener.Addr().String() {
		t.Fatal("public numeric candidate discovery", err)
	}
	if public.Load() != 1 || business.Load() != 0 {
		t.Fatal("discovery leaked beyond one public GET")
	}
	// The ordinary independently pinned transport is still explicit and works
	// without any changed process-global trust state.
	client, err := NewHTTPClient(f.d, c.DialAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	r, err := client.Get(f.d.Claims.Origin + wire.NodePairTrustDescriptorPath)
	if err != nil {
		t.Fatal("original verified transport after public discovery", err)
	}
	r.Body.Close()
	other := newFixture(t)
	wrong, err := NewHTTPClient(other.d, c.DialAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.CloseIdleConnections()
	if r, err = wrong.Get(other.d.Claims.Origin + "/must-not-run"); err == nil {
		r.Body.Close()
		t.Fatal("candidate discovery changed global/pinned trust")
	}
	if business.Load() != 0 {
		t.Fatal("wrong pin sent business")
	}
}

func TestNodePairDiscoveryRejectsChainDescriptorAndRedirectConfusion(t *testing.T) {
	f, cert, text := discoveryFixture(t)
	other := newFixture(t)
	for _, kind := range []string{"no-root", "wrong-root", "wrong-SAN", "wrong-SPKI", "expired", "foreign-descriptor", "tampered-descriptor", "oversize", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			chain := cert
			body := text
			status := http.StatusOK
			switch kind {
			case "no-root":
				chain.Certificate = chain.Certificate[:1]
			case "wrong-root":
				chain.Certificate = [][]byte{f.leaf.Certificate[0], other.ca.Raw}
			case "wrong-SAN":
				chain = f.makeLeaf(t, "other.synthetic.invalid", f.ca.NotBefore, f.ca.NotAfter)
				chain.Certificate = append(chain.Certificate, f.ca.Raw)
			case "wrong-SPKI":
				chain = f.makeLeaf(t, f.d.Claims.ServerName, f.ca.NotBefore, f.ca.NotAfter)
				chain.Certificate = append(chain.Certificate, f.ca.Raw)
			case "expired":
				chain = f.makeLeaf(t, f.d.Claims.ServerName, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
				chain.Certificate = append(chain.Certificate, f.ca.Raw)
			case "foreign-descriptor":
				var err error
				body, err = EncodeDescriptor(other.d)
				if err != nil {
					t.Fatal(err)
				}
			case "tampered-descriptor":
				body = text[:len(text)-3] + "AAA"
			case "oversize":
				body = strings.Repeat("a", MaxDescriptorText+1)
			case "redirect":
				status = http.StatusTemporaryRedirect
			}
			var requests atomic.Int32
			s := serveFixture(t, chain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", "https://127.0.0.1:1/must-not-follow")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			if _, err := DiscoverCandidate(context.Background(), s.Listener.Addr().String()); err == nil {
				t.Fatal("invalid candidate accepted")
			}
			if requests.Load() > 1 {
				t.Fatal("discovery followed redirect or retried HTTP")
			}
			if (kind == "no-root" || kind == "wrong-root" || kind == "expired") && requests.Load() != 0 {
				t.Fatal("bad candidate chain reached HTTP")
			}
		})
	}
}

func TestNodePairDiscoveryRejectsNonNumericAndHonorsCancellation(t *testing.T) {
	for _, s := range []string{"synthetic.invalid:443", "https://127.0.0.1:443", "127.0.0.1:0443", "[fe80::1%lo]:443"} {
		if _, err := DiscoverCandidate(context.Background(), s); err == nil {
			t.Fatal("invalid locator accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := DiscoverCandidate(ctx, "127.0.0.1:443"); err == nil || time.Since(start) > time.Second {
		t.Fatal("cancelled public probe did not stop")
	}
}

func TestNodePairDiscoveryNativeProfilePublishesRetainedPublicRoot(t *testing.T) {
	_, _, p := createTestProfile(t)
	d, err := DecodeDescriptor(p.DescriptorText())
	if err != nil {
		t.Fatal(err)
	}
	s := serveFixture(t, tlsCertificateForDiscovery(t, p), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, p.DescriptorText()) }))
	c, err := DiscoverCandidate(context.Background(), s.Listener.Addr().String())
	if err != nil || c.Descriptor.Claims.HubFingerprint != d.Claims.HubFingerprint {
		t.Fatal("persisted native profile did not support public discovery", err)
	}
}
func tlsCertificateForDiscovery(t *testing.T, p *Profile) tls.Certificate {
	t.Helper()
	certificate, err := p.TLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 2 {
		t.Fatal("native leaf/root chain missing")
	}
	return *certificate
}
