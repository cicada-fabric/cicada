//go:build linux && (amd64 || arm64) && cgo && cicada_pqtls

package pqtls

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPDialNativeHTTPWithoutDNS(t *testing.T) {
	var dnsCalls atomic.Int64
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("SYNTHETIC DNS MUST NOT BE CALLED")
	}}
	defer func() { net.DefaultResolver = oldResolver }()
	for _, socket := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(socket, func(t *testing.T) {
			listener, err := Listen("tcp", socket, hubConfig)
			if err != nil {
				t.Fatal("native IP listener", err)
			}
			const logical = "hub.synthetic.invalid:7443"
			server := &http.Server{ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0), ConnContext: HTTPConnContext, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				state, err := StateFromContext(r.Context())
				if err != nil || state.Peer != nodeConfig.LocalIdentity || r.Host != logical {
					http.Error(w, "SYNTHETIC IDENTITY FAILURE", http.StatusForbidden)
					return
				}
				io.WriteString(w, "SYNTHETIC IP TRANSPORT TEST ONLY")
			})}
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			defer func() {
				server.Close()
				if err := <-done; !errors.Is(err, http.ErrServerClosed) {
					t.Error(err)
				}
			}()
			client, err := NewClient(nodeConfig)
			if err != nil {
				t.Fatal(err)
			}
			transport, err := client.HTTPTransportWithDialAddress(logical, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrIdentity }}
			response, err := httpClient.Get("https://" + logical + "/v2/node/control/rpc")
			if err != nil {
				t.Fatal("direct IP verified TLS failed", err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(data) != "SYNTHETIC IP TRANSPORT TEST ONLY" {
				t.Fatal("physical IP logical Host/SAN mismatch")
			}
			for _, mutate := range []func(*Config){func(c *Config) { c.Peers[0].Identity.DNSName = "foreign.synthetic.invalid" }, func(c *Config) { c.Peers[0].Pin.SHA256[0] ^= 1 }} {
				config := clone(nodeConfig)
				mutate(&config)
				bad, err := NewClient(config)
				if err != nil {
					continue
				}
				narrowed, err := bad.HTTPTransportWithDialAddress(logical, listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				badHTTP := &http.Client{Transport: narrowed, Timeout: 3 * time.Second}
				if response, err := badHTTP.Get("https://" + logical + "/v2/node/control/rpc"); err == nil {
					response.Body.Close()
					t.Fatal("IP bypassed approved SAN/pin")
				}
				narrowed.CloseIdleConnections()
			}
			config := clone(nodeConfig)
			config.Peers[0].Identity.HubID = "foreign-hub"
			if _, err := NewClient(config); !errors.Is(err, ErrConfig) {
				t.Fatal("foreign HubID entered IP transport")
			}
		})
	}
	if n := dnsCalls.Load(); n != 0 {
		t.Fatalf("DNS used by IP socket: %d", n)
	}
}
