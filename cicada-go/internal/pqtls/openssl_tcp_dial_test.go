//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestPQTCPConnectDeadlineAndCancellation(t *testing.T) {
	const address = "127.0.0.1:1"
	injected := errors.New("synthetic TCP control failure")
	t.Run("default_connect_deadline", func(t *testing.T) {
		dialer := newPQTCPDialer()
		started := time.Now()
		called := false
		dialer.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
			called = true
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(started.Add(29*time.Second)) || deadline.After(time.Now().Add(30*time.Second)) {
				t.Error("TCP connector did not receive its finite default deadline")
			}
			return injected // Stop before connect; no packet or TLS handshake.
		}
		conn, err := dialer.DialContext(context.Background(), "tcp", address)
		if conn != nil || !called || !errors.Is(err, injected) {
			t.Fatal("injected dial failure did not fail closed")
		}
	})
	t.Run("earlier_parent_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		parentDeadline, _ := ctx.Deadline()
		dialer := newPQTCPDialer()
		called := false
		dialer.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
			called = true
			deadline, ok := ctx.Deadline()
			if !ok || deadline.After(parentDeadline) {
				t.Error("TCP connector extended its parent deadline")
				return injected
			}
			<-ctx.Done()
			return ctx.Err()
		}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if conn != nil || !called || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked connector did not stop at the earlier parent deadline")
		}
	})
	t.Run("parent_cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		entered := make(chan struct{})
		dialer := newPQTCPDialer()
		dialer.ControlContext = func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
		finished := make(chan error, 1)
		go func() {
			conn, err := dialer.DialContext(ctx, "tcp", address)
			if conn != nil {
				conn.Close()
				finished <- injected
				return
			}
			finished <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("connector did not enter its controlled pre-connect hook")
		}
		cancel()
		select {
		case err := <-finished:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("connector did not preserve parent cancellation")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled connector remained blocked")
		}
	})
	t.Run("established_connection_has_no_connect_timer", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn, err := newPQTCPDialer().DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		peer, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		cancel()
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		var value [1]byte
		if _, err := conn.Read(value[:]); err != nil || value[0] != 1 {
			t.Fatal("connect context cancellation closed an already established connection")
		}
	})
}
