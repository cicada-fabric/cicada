package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
)

func TestProductHTTPDrainsActiveRequestBeforeClosingControlStore(t *testing.T) {
	root := t.TempDir()
	c, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-drain-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Shutdown(ctx)
	})
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finishHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer finishHandler()
	storeResult := make(chan error, 1)
	front := newControlHTTPServer("", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
		<-release
		_, err := c.Groups()
		storeResult <- err
		if err != nil {
			w.WriteHeader(500)
		} else {
			w.WriteHeader(200)
		}
		io.WriteString(w, "drained")
	}))
	front.Addr = address
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveManagedProductHTTP(ctx, front, c, nil) }()
	requestDone := make(chan error, 1)
	go func() {
		var requestErr error
		for i := 0; i < 100; i++ {
			response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + address + "/drain")
			requestErr = err
			if err == nil {
				_, err = io.ReadAll(response.Body)
				response.Body.Close()
				if response.StatusCode != 200 {
					requestErr = io.ErrUnexpectedEOF
				} else {
					requestErr = err
				}
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		requestDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("drain request did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("signal did not cancel request context")
	}
	if _, err := c.Groups(); err != nil {
		t.Fatal("Control Store closed before HTTP drain")
	}
	select {
	case <-done:
		t.Fatal("managed service returned before active request drain")
	default:
	}
	finishHandler()
	if err := <-storeResult; err != nil {
		t.Fatal("in-flight request lost shared Store while draining")
	}
	if err := <-requestDone; err != nil {
		t.Fatal("active response did not finish")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("managed HTTP/Control shutdown was not joined")
	}
	if _, err := c.Groups(); err == nil {
		t.Fatal("Control Store stayed open after joined shutdown")
	}
}

func TestProductHTTPListenerFailureClosesControlStore(t *testing.T) {
	root := t.TempDir()
	c, err := control.New(control.Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"), APIToken: "synthetic-listen-failure"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Shutdown(ctx)
	})
	front := newControlHTTPServer("", 0, http.NotFoundHandler())
	front.Addr = "invalid-listener-address"
	if err := serveManagedProductHTTP(context.Background(), front, c, nil); err == nil {
		t.Fatal("invalid listener did not fail")
	}
	if _, err := c.Groups(); err == nil {
		t.Fatal("listener failure left shared Control Store open")
	}
}
