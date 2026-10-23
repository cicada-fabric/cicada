package hubtransport

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serveFixture(t *testing.T, cert tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestNativeTLSNumericDialRetainsLogicalOrigin(t *testing.T) {
	f := newFixture(t)
	var calls atomic.Int32
	s := serveFixture(t, f.leaf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || "https://"+r.Host != f.d.Claims.Origin || r.Header.Get("Origin") != f.d.Claims.Origin {
			t.Error("request lost TLS or logical origin")
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://foreign.synthetic.invalid/secret")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "synthetic-ok")
	}))
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client, err := NewHTTPClient(f.d, s.Listener.Addr().String(), time.Second*5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	r, err := http.NewRequest(http.MethodPost, f.d.Claims.Origin+"/probe", strings.NewReader("CICADA SYNTHETIC TEST BODY ONLY"))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", f.d.Claims.Origin)
	response, err := client.Do(r)
	if err != nil {
		t.Fatal("verified numeric dial failed:", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "synthetic-ok" || calls.Load() != 1 {
		t.Fatal("unexpected Hub response")
	}
	r, err = http.NewRequest(http.MethodGet, f.d.Claims.Origin+"/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", f.d.Claims.Origin)
	response, err = client.Do(r)
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatal("redirect handling changed")
	}
	response.Body.Close()
	if calls.Load() != 2 {
		t.Fatal("redirect was followed")
	}
	transport := client.Transport.(*Transport)
	if transport.base.TLSClientConfig.InsecureSkipVerify || transport.base.TLSClientConfig.Time != nil || transport.base.Proxy != nil {
		t.Fatal("TLS verification or proxy policy bypassed")
	}
}

func TestNativeTLSWrongTrustFailsBeforeHTTP(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	cases := []struct {
		name       string
		descriptor Descriptor
		cert       tls.Certificate
	}{
		{"wrong-pin", copyDescriptor(t, f.d), f.leaf},
		{"wrong-root", copyDescriptor(t, f.d), f.leaf},
		{"wrong-san", copyDescriptor(t, f.d), f.makeLeaf(t, "foreign.synthetic.invalid", f.ca.NotBefore, f.ca.NotAfter)},
		{"expired-leaf", copyDescriptor(t, f.d), f.makeLeaf(t, f.d.Claims.ServerName, f.ca.NotBefore, f.ca.NotBefore.Add(time.Hour))},
	}
	cases[0].descriptor.Claims.ServerSPKISHA256 = strings.Repeat("0", 64)
	cases[1].descriptor.Claims.RootCertificateDER = other.ca.Raw
	for i := 2; i < len(cases); i++ {
		leaf, err := x509.ParseCertificate(cases[i].cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		cases[i].descriptor.Claims.ServerSPKISHA256 = hex.EncodeToString(digest[:])
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := serveFixture(t, tc.cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			d, err := SignDescriptor(f.hub, tc.descriptor.Claims)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewHTTPClient(d, s.Listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			r, err := http.NewRequest(http.MethodPost, d.Claims.Origin+"/must-not-receive", bytes.NewReader([]byte("CICADA SYNTHETIC SECRET TEST ONLY")))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(r)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || calls.Load() != 0 {
				t.Fatal("untrusted server received HTTP request")
			}
		})
	}
}

func TestNativeTLSRejectsCrossOriginBeforeDial(t *testing.T) {
	f := newFixture(t)
	client, err := NewHTTPClient(f.d, "127.0.0.1:1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	for _, tc := range []struct{ name, target, host, origin string }{
		{"foreign-url", "https://foreign.synthetic.invalid/p", "", ""},
		{"http", strings.Replace(f.d.Claims.Origin, "https:", "http:", 1) + "/p", "", ""},
		{"foreign-host", f.d.Claims.Origin + "/p", "foreign.synthetic.invalid", ""},
		{"foreign-origin-header", f.d.Claims.Origin + "/p", "", "https://foreign.synthetic.invalid"},
		{"userinfo", strings.Replace(f.d.Claims.Origin, "https://", "https://user@", 1) + "/p", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, tc.target, strings.NewReader("CICADA SYNTHETIC TEST ONLY"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.host != "" {
				r.Host = tc.host
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			_, err = client.Transport.RoundTrip(r)
			if err != ErrOrigin {
				t.Fatal("request did not fail at origin boundary")
			}
		})
	}
}

func TestNativeTLSRejectsInvalidLocatorsAndNeverUsesDefaultClient(t *testing.T) {
	f := newFixture(t)
	for _, address := range []string{"", "hub.synthetic.invalid:443", "0.0.0.0:443", "[::]:443", "127.0.0.1:0", "127.0.0.1:0443", "::1:443", "[fe80::1%lo]:443", "[::ffff:127.0.0.1]:443"} {
		if _, err := NewTransport(f.d, address); err == nil {
			t.Fatal("invalid numeric locator accepted")
		}
	}
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "192.0.2.1:8443", "[2001:db8::1]:8443"} {
		transport, err := NewTransport(f.d, address)
		if err != nil {
			t.Fatal("canonical locator rejected")
		}
		transport.CloseIdleConnections()
	}
	if _, err := NewHTTPClient(f.d, "127.0.0.1:443", -time.Second); err == nil {
		t.Fatal("negative timeout accepted")
	}
	if _, err := NewTransport(Descriptor{}, "127.0.0.1:443"); err == nil {
		t.Fatal("missing trust material accepted")
	}
}

func TestNativeTLSIPv6NumericDial(t *testing.T) {
	f := newFixture(t)
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback listener unavailable; IPv6 is not accepted by this run")
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if "https://"+r.Host != f.d.Claims.Origin || r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
			t.Error("IPv6 request lost logical origin or TLS")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	s.Listener.Close()
	s.Listener = listener
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.leaf}}
	s.StartTLS()
	t.Cleanup(s.Close)
	client, err := NewHTTPClient(f.d, listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get(f.d.Claims.Origin + "/ipv6")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("unexpected IPv6 response")
	}
}
