package n3_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// This independent negative peer qualifies the newly delivered discovery API.
// It is not the product Hub/Node/App and cannot qualify onboarding or authority.
// Different certificates on its two real handshakes exercise the first-probe
// boundary without providing a custom client/Doer to the production function.
type nodePairDiscoveryPeer struct {
	server     *httptest.Server
	handshakes atomic.Int64
	requests   atomic.Int64
	badRequest atomic.Bool
}

func newNodePairDiscoveryPeer(t *testing.T, host string, first, next tls.Certificate, body string, status int, location string) *nodePairDiscoveryPeer {
	t.Helper()
	p := &nodePairDiscoveryPeer{}
	p.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests.Add(1)
		n, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1))
		if err != nil || n != 0 || r.Method != http.MethodGet || r.URL.Path != wire.NodePairTrustDescriptorPath ||
			r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			p.badRequest.Store(true)
		}
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	p.server.Listener.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal("required owned numeric discovery listener unavailable")
	}
	p.server.Listener = listener
	p.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cert := next
		if p.handshakes.Add(1) == 1 {
			cert = first
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, nil
	}}
	p.server.StartTLS()
	t.Cleanup(p.server.Close)
	return p
}

func TestN3NodePairTrustDiscoveryBoundary(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	now := time.Now().UTC()
	chain := func(key *ecdsa.PrivateKey, before, after time.Time) tls.Certificate {
		cert := a.leaf(t, a.descriptor.Claims.ServerName, before, after, key)
		cert.Certificate = append(cert.Certificate, a.ca.Raw)
		return cert
	}
	first := chain(a.serviceKey, now.Add(-time.Hour), now.Add(time.Hour))
	text := must(hubtransport.EncodeDescriptor(a.descriptor))
	for _, kind := range []string{"changed-SPKI", "changed-root", "same-key-new-leaf", "IPv6", "extra-chain-certificate", "future-leaf"} {
		t.Run(kind, func(t *testing.T) {
			host, before, after, accepted := "127.0.0.1", first, first, false
			switch kind {
			case "changed-SPKI":
				after = chain(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), now.Add(-time.Hour), now.Add(time.Hour))
			case "changed-root":
				other := newDirectIPTLSAdversary(t)
				after = other.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), other.serviceKey)
				after.Certificate = append(after.Certificate, other.ca.Raw)
			case "same-key-new-leaf":
				after, accepted = chain(a.serviceKey, now.Add(-time.Minute), now.Add(2*time.Hour)), true
			case "IPv6":
				host, accepted = "::1", true
			case "extra-chain-certificate":
				before.Certificate = append(append([][]byte(nil), first.Certificate...), a.ca.Raw)
			case "future-leaf":
				before = chain(a.serviceKey, now.Add(time.Hour), now.Add(2*time.Hour))
				after = before
			}
			peer := newNodePairDiscoveryPeer(t, host, before, after, text, http.StatusOK, "")
			candidate, err := hubtransport.DiscoverCandidate(context.Background(), peer.server.Listener.Addr().String())
			if accepted {
				if err != nil || candidate.DescriptorText != text || candidate.DialAddress != peer.server.Listener.Addr().String() ||
					!reflect.DeepEqual(candidate.Descriptor, a.descriptor) || peer.requests.Load() != 1 || peer.handshakes.Load() != 2 {
					t.Fatal("independent candidate control failed its two real handshakes and sole public GET")
				}
				// A second, independently pinned client must still reject this
				// candidate. Discovery must not install process-global trust.
				wrong := newDirectIPTLSAdversary(t)
				client := must(hubtransport.NewHTTPClient(wrong.descriptor, candidate.DialAddress, time.Second))
				defer client.CloseIdleConnections()
				response, requestErr := client.Get(wrong.descriptor.Claims.Origin + "/forbidden-business")
				if response != nil {
					response.Body.Close()
				}
				if requestErr == nil || peer.requests.Load() != 1 {
					t.Fatal("public candidate discovery altered independent business trust")
				}
			} else if err == nil || peer.requests.Load() != 0 || candidate.DescriptorText != "" {
				t.Fatal("changed TLS probe identity or invalid chain/time reached HTTP or returned a candidate")
			}
			if peer.badRequest.Load() {
				t.Fatal("candidate discovery sent a body, credential or non-metadata request")
			}
		})
	}
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run("redirect-"+strconv.Itoa(status), func(t *testing.T) {
			var destinationCalls atomic.Int64
			destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
			t.Cleanup(destination.Close)
			peer := newNodePairDiscoveryPeer(t, "127.0.0.1", first, first, text, status, destination.URL+"/must-not-follow")
			_, err := hubtransport.DiscoverCandidate(context.Background(), peer.server.Listener.Addr().String())
			if err == nil || peer.requests.Load() != 1 || peer.handshakes.Load() != 2 || peer.badRequest.Load() || destinationCalls.Load() != 0 {
				t.Fatal("candidate redirect followed, retried or sent non-public data")
			}
		})
	}
}
