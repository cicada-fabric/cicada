//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

/*
#cgo LDFLAGS: -lssl -lcrypto
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

func Available() error {
	if C.pq_available() != 1 {
		return ErrUnavailable
	}
	return nil
}
func native(cfg Config, server bool, fd int) (*C.pq_connection, error) {
	info, err := os.Lstat(cfg.PrivateKeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0 {
		return nil, failure(ErrConfig, "private TLS key permissions")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, failure(ErrConfig, "private TLS key owner")
	}
	cert, key, ca := C.CString(cfg.CertificateFile), C.CString(cfg.PrivateKeyFile), C.CString(cfg.TrustFile)
	defer C.free(unsafe.Pointer(cert))
	defer C.free(unsafe.Pointer(key))
	defer C.free(unsafe.Pointer(ca))
	name := cfg.LocalIdentity.DNSName
	if !server {
		name = cfg.Peers[0].Identity.DNSName
	}
	host := C.CString(name)
	defer C.free(unsafe.Pointer(host))
	isServer := C.int(0)
	if server {
		isServer = 1
	}
	policy := C.calloc(C.size_t(len(cfg.Peers)), C.size_t(C.sizeof_pq_peer))
	if policy == nil {
		return nil, ErrUnavailable
	}
	defer C.free(policy)
	peers := unsafe.Slice((*C.pq_peer)(policy), len(cfg.Peers))
	for i, p := range cfg.Peers {
		dns := C.CString(p.Identity.DNSName)
		pin := C.CBytes(p.Pin.SHA256[:])
		spki := C.int(0)
		if p.Pin.Kind == "spki-sha256" {
			spki = 1
		}
		ok := C.pq_peer_set(&peers[i], dns, (*C.uchar)(pin), spki)
		C.free(unsafe.Pointer(dns))
		C.free(pin)
		if ok != 1 {
			return nil, ErrConfig
		}
	}
	c := C.pq_new(cert, key, ca, host, isServer, C.int(fd), (*C.pq_peer)(policy), C.size_t(len(cfg.Peers)))
	if c == nil {
		return nil, failure(ErrConfig, "certificate/profile setup")
	}
	local := C.CString(cfg.LocalIdentity.DNSName)
	defer C.free(unsafe.Pointer(local))
	if C.pq_localname(c, local) != 1 {
		C.pq_free(c)
		return nil, failure(ErrIdentity, "local certificate SAN")
	}
	return c, nil
}
func checkMaterial(cfg Config) error {
	c, err := native(cfg, cfg.LocalIdentity.Kind == "hub", -1)
	if c != nil {
		C.pq_free(c)
	}
	return err
}

// Conn owns an isolated nonblocking descriptor. OpenSSL never retains Go
// memory; poll sees only fd integers. State calls serialize, without locking
// out the opposite direction while waiting for socket readiness.
type Conn struct {
	readMu, writeMu, sslMu      sync.Mutex
	ssl                         *C.pq_connection
	fd, readEvent, writeEvent   int
	closed                      bool
	readDeadline, writeDeadline time.Time
	local, remote               net.Addr
	state                       State
	verified, validityFailed    bool      // guarded by sslMu; handshake has no state yet
	validityDeadline            time.Time // monotonic bound prevents rollback extending IO
}

var _ net.Conn = (*Conn)(nil)

func wrap(ctx context.Context, tcp *net.TCPConn, cfg Config, server bool) (*Conn, error) {
	local, remote := tcp.LocalAddr(), tcp.RemoteAddr()
	raw, err := tcp.SyscallConn()
	if err != nil {
		tcp.Close()
		return nil, err
	}
	fd := -1
	var duplicateError error
	err = raw.Control(func(original uintptr) {
		v, _, e := syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_DUPFD_CLOEXEC, 0)
		if e != 0 {
			duplicateError = e
		} else {
			fd = int(v)
		}
	})
	// Duplicate belongs exclusively to Conn; Go's original closes immediately.
	tcp.Close()
	if err != nil || duplicateError != nil || fd < 0 {
		if fd >= 0 {
			syscall.Close(fd)
		}
		return nil, failure(ErrUnavailable, "descriptor ownership")
	}
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	c, err := native(cfg, server, fd)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	r, w := int(C.pq_event()), int(C.pq_event())
	if r < 0 || w < 0 {
		if r >= 0 {
			syscall.Close(r)
		}
		if w >= 0 {
			syscall.Close(w)
		}
		C.pq_free(c)
		syscall.Close(fd)
		return nil, ErrUnavailable
	}
	conn := &Conn{ssl: c, fd: fd, readEvent: r, writeEvent: w, local: local, remote: remote}
	hctx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(hctx, func() { conn.Close() })
	defer stop()
	deadline, _ := hctx.Deadline()
	conn.SetDeadline(deadline)
	conn.readMu.Lock()
	err = conn.operate(false, func() (int, int) { return int(C.pq_handshake(c)), 0 })
	conn.readMu.Unlock()
	if err == nil {
		err = conn.verify(cfg)
	}
	if hctx.Err() != nil {
		err = hctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Stop cancellation before clearing handshake deadlines. If it has already
	// fired, completion must fail even when OpenSSL just finished successfully.
	if !stop() {
		conn.Close()
		return nil, hctx.Err()
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Conn) verify(cfg Config) error {
	c.sslMu.Lock()
	defer c.sslMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	var s C.pq_state
	if C.pq_snapshot(c.ssl, &s) != 1 {
		return failure(ErrProfile, "negotiated values/chain")
	}
	state := State{TLSVersion: C.GoString(&s.version[0]), Group: C.GoString(&s.group[0]),
		CipherSuite: C.GoString(&s.cipher[0]), PeerSignature: C.GoString(&s.signature[0]),
		ALPN: C.GoString(&s.alpn[0]), VerificationResult: int64(s.verification),
		VerifiedNotBefore: time.Unix(int64(s.verified_not_before), 0).UTC(),
		VerifiedNotAfter:  time.Unix(int64(s.verified_not_after), 0).UTC()}
	now := time.Now()
	if !state.ValidAt(now) {
		return failure(ErrCertificateValidity, "verified chain interval")
	}
	copy(state.CertificateSHA256[:], C.GoBytes(unsafe.Pointer(&s.certificate[0]), 32))
	copy(state.SPKISHA256[:], C.GoBytes(unsafe.Pointer(&s.spki[0]), 32))
	matched := false
	for _, peer := range cfg.Peers {
		pin := state.CertificateSHA256
		if peer.Pin.Kind == "spki-sha256" {
			pin = state.SPKISHA256
		}
		if subtle.ConstantTimeCompare(peer.Pin.SHA256[:], pin[:]) != 1 {
			continue
		}
		name := C.CString(peer.Identity.DNSName)
		matches := C.pq_hostname(c.ssl, name) == 1
		C.free(unsafe.Pointer(name))
		if !matches {
			continue
		}
		if matched && state.Peer != peer.Identity {
			return failure(ErrIdentity, "ambiguous certificate identity")
		}
		state.Peer = peer.Identity
		state.HostnameVerified = true
		matched = true
	}
	if !matched {
		return failure(ErrIdentity, "peer pin/SAN")
	}
	c.state = state
	c.validityDeadline = now.Add(state.VerifiedNotAfter.Sub(now))
	c.verified = true
	return nil
}

// Caller holds sslMu. Once invalid, a verified connection cannot regain
// authority after a clock change; handshake IO has not established state yet.
func (c *Conn) certificateCurrentLocked(now time.Time) bool {
	if !c.verified {
		return true
	}
	if c.validityFailed || !c.state.ValidAt(now) || !now.Before(c.validityDeadline) {
		c.validityFailed = true
		return false
	}
	return true
}

func (c *Conn) operationDeadlineLocked(writing bool) time.Time {
	deadline := c.readDeadline
	if writing {
		deadline = c.writeDeadline
	}
	if c.verified && (deadline.IsZero() || c.validityDeadline.Before(deadline)) {
		deadline = c.validityDeadline
	}
	return deadline
}

// operate holds the caller's direction gate until poll completes. Close may
// mark/shutdown/wake immediately, but cannot free descriptors while a gate is
// active. WANT directions can change independently of the operation deadline.
func (c *Conn) operate(writing bool, step func() (int, int)) error {
operation:
	for {
		c.sslMu.Lock()
		if c.closed || c.ssl == nil {
			c.sslMu.Unlock()
			return net.ErrClosed
		}
		now := time.Now()
		if !c.certificateCurrentLocked(now) {
			c.sslMu.Unlock()
			return failure(ErrCertificateValidity, "application IO")
		}
		deadline := c.operationDeadlineLocked(writing)
		event := c.readEvent
		if writing {
			event = c.writeEvent
		}
		if !deadline.IsZero() && !now.Before(deadline) {
			c.sslMu.Unlock()
			return os.ErrDeadlineExceeded
		}
		result, _ := step()
		current := c.certificateCurrentLocked(time.Now())
		fd := c.fd
		c.sslMu.Unlock()
		if !current {
			return failure(ErrCertificateValidity, "application IO")
		}
		switch result {
		case 1:
			return nil
		case 4:
			return io.EOF
		case 0:
			return failure(ErrProfile, "TLS IO/handshake")
		}
		if result != 2 && result != 3 {
			return ErrProfile
		}
		for {
			c.sslMu.Lock()
			if c.closed {
				c.sslMu.Unlock()
				return net.ErrClosed
			}
			if !c.certificateCurrentLocked(time.Now()) {
				c.sslMu.Unlock()
				return failure(ErrCertificateValidity, "application IO")
			}
			deadline = c.operationDeadlineLocked(writing)
			c.sslMu.Unlock()
			ms := -1
			if !deadline.IsZero() {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					continue operation // distinguish expiry from caller's deadline
				}
				if remaining > 2147483647*time.Millisecond {
					ms = 2147483647
				} else {
					ms = int((remaining + time.Millisecond - 1) / time.Millisecond)
				}
			}
			wantWrite := C.int(0)
			if result == 3 {
				wantWrite = 1
			}
			r := int(C.pq_wait(C.int(fd), C.int(event), wantWrite, C.int(ms)))
			if r == -2 || r == 0 || r == 2 {
				continue
			}
			if r < 0 {
				return failure(ErrProfile, "socket readiness")
			}
			break
		}
	}
}
func (c *Conn) Read(buf []byte) (int, error) {
	c.readMu.Lock()
	var resultErr error
	defer func() {
		c.readMu.Unlock()
		if errors.Is(resultErr, ErrCertificateValidity) {
			c.Close() // no direction or SSL lock is held during teardown
		}
	}()
	if len(buf) == 0 {
		return 0, nil
	}
	var n C.size_t
	err := c.operate(false, func() (int, int) {
		r := C.pq_read(c.ssl, unsafe.Pointer(&buf[0]), C.size_t(len(buf)), &n)
		return int(r), int(n)
	})
	resultErr = err
	if errors.Is(err, ErrCertificateValidity) {
		return 0, &net.OpError{Op: "read", Net: "pqtls", Addr: c.remote, Err: err}
	}
	if err != nil && err != io.EOF {
		return int(n), &net.OpError{Op: "read", Net: "pqtls", Addr: c.remote, Err: err}
	}
	return int(n), err
}
func (c *Conn) Write(buf []byte) (total int, resultErr error) {
	c.writeMu.Lock()
	defer func() {
		c.writeMu.Unlock()
		// A partial TLS write cannot be retried with different bytes. Abort the
		// connection after releasing its gate, preserving the original error.
		if resultErr != nil {
			c.Close()
		}
	}()
	for len(buf) > 0 {
		size := len(buf)
		if size > 16384 {
			size = 16384
		}
		// SSL_write retries require identical bytes; C owns this immutable copy.
		ptr := C.CBytes(buf[:size])
		var n C.size_t
		err := c.operate(true, func() (int, int) { return int(C.pq_write(c.ssl, ptr, C.size_t(size), &n)), int(n) })
		C.free(ptr)
		total += int(n)
		if err != nil {
			return total, &net.OpError{Op: "write", Net: "pqtls", Addr: c.remote, Err: err}
		}
		if int(n) != size {
			return total, failure(ErrProfile, "short TLS record")
		}
		buf = buf[size:]
	}
	return total, nil
}

// Close aborts the socket, rather than blocking for peer close_notify. It
// unblocks poll/IO first and only then frees SSL and the owned descriptors.
func (c *Conn) Close() error {
	c.sslMu.Lock()
	if c.closed {
		c.sslMu.Unlock()
		return nil
	}
	c.closed = true
	if c.ssl == nil {
		c.sslMu.Unlock()
		return nil
	}
	C.pq_signal(C.int(c.readEvent))
	C.pq_signal(C.int(c.writeEvent))
	_ = syscall.Shutdown(c.fd, syscall.SHUT_RDWR)
	c.sslMu.Unlock()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.sslMu.Lock()
	defer c.sslMu.Unlock()
	C.pq_free(c.ssl)
	c.ssl = nil
	syscall.Close(c.fd)
	syscall.Close(c.readEvent)
	syscall.Close(c.writeEvent)
	return nil
}
func (c *Conn) LocalAddr() net.Addr                { return c.local }
func (c *Conn) RemoteAddr() net.Addr               { return c.remote }
func (c *Conn) PQTLSState() State                  { return c.state }
func (c *Conn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true, true) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true, false) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }
func (c *Conn) setDeadline(t time.Time, read, write bool) error {
	c.sslMu.Lock()
	defer c.sslMu.Unlock()
	if c.closed || c.ssl == nil {
		return net.ErrClosed
	}
	if read {
		c.readDeadline = t
		C.pq_signal(C.int(c.readEvent))
	}
	if write {
		c.writeDeadline = t
		C.pq_signal(C.int(c.writeEvent))
	}
	return nil
}
func dial(ctx context.Context, address string, cfg Config) (net.Conn, error) {
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		raw.Close()
		return nil, ErrUnavailable
	}
	conn, err := wrap(ctx, tcp, cfg, false)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type listener struct {
	net.Listener
	ctx           context.Context
	cancel        context.CancelFunc
	cfg           Config
	once          sync.Once
	ready         chan *Conn
	credits       chan struct{}
	pumpDone      chan struct{}
	workers       sync.WaitGroup
	errMu         sync.Mutex
	terminalError error
	overloaded    atomic.Uint64
}

func listen(address string, cfg Config) (net.Listener, error) {
	raw, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{Listener: raw, ctx: ctx, cancel: cancel, cfg: cfg,
		ready: make(chan *Conn, cfg.MaxPendingHandshakes), credits: make(chan struct{}, cfg.MaxPendingHandshakes), pumpDone: make(chan struct{})}
	go l.acceptPump()
	return l, nil
}

// One pump admits bounded workers. A credit remains held until the verified
// connection is exposed to Accept; the ready queue cannot bypass the bound.
func (l *listener) acceptPump() {
	defer close(l.pumpDone)
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			l.errMu.Lock()
			l.terminalError = err
			l.errMu.Unlock()
			l.cancel()
			l.Listener.Close()
			return
		}
		if l.ctx.Err() != nil {
			raw.Close()
			return
		}
		select {
		case l.credits <- struct{}{}:
		default:
			l.overloaded.Add(1)
			raw.Close()
			continue
		}
		tcp, ok := raw.(*net.TCPConn)
		if !ok {
			raw.Close()
			<-l.credits
			continue
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			conn, err := wrap(l.ctx, tcp, l.cfg, true)
			if err != nil {
				<-l.credits
				return
			}
			select {
			case l.ready <- conn:
			case <-l.ctx.Done():
				conn.Close()
				<-l.credits
			}
		}()
	}
}
func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		<-l.credits
		if l.ctx.Err() != nil {
			c.Close()
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.ctx.Done():
		l.errMu.Lock()
		err := l.terminalError
		l.errMu.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
}
func (l *listener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		err = l.Listener.Close()
		<-l.pumpDone // no more worker additions before Wait
		l.workers.Wait()
		for {
			select {
			case c := <-l.ready:
				c.Close()
				<-l.credits
			default:
				return
			}
		}
	})
	return err
}
