package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestControlHTTPServerBoundsHeadersAndIdleConnections(t *testing.T) {
	server := newControlHTTPServer("::1", 8787, http.NotFoundHandler())
	if server.Addr != "[::1]:8787" {
		t.Fatalf("IPv6 listener address=%q", server.Addr)
	}
	if server.ReadHeaderTimeout != 10*time.Second || server.ReadTimeout != 2*time.Minute || server.IdleTimeout != 60*time.Second {
		t.Fatalf("HTTP resource timeouts: header=%s read=%s idle=%s", server.ReadHeaderTimeout,
			server.ReadTimeout, server.IdleTimeout)
	}
	if server.WriteTimeout != 0 {
		t.Fatalf("global write timeout %s would truncate long-lived event streams", server.WriteTimeout)
	}
}

func TestControlHTTPServerReadTimeoutStopsSlowRequestBody(t *testing.T) {
	readResult := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		readResult <- err
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ReadTimeout = 100 * time.Millisecond
	server.Start()
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	request := "POST / HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\na"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("handler read an incomplete slow request body without error")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("incomplete body error=%v, want read timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not time out the slow request body")
	}
}

func TestServeRequiresTokenOutsideLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if err := validateServeExposure(host, ""); err != nil {
			t.Fatalf("loopback host %q required a token: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.10", "control.example"} {
		if err := validateServeExposure(host, ""); err == nil {
			t.Fatalf("non-loopback host %q accepted an empty API token", host)
		}
		if err := validateServeExposure(host, "configured-token"); err != nil {
			t.Fatalf("non-loopback host %q rejected configured auth: %v", host, err)
		}
	}
}
