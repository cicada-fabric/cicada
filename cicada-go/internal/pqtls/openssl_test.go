//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var fixtureDirectory, opensslExecutable string
var hubConfig, nodeConfig, otherNodeConfig Config

const libctxCleanupChildEnv = "CICADA_PQTLS_LIBCTX_CLEANUP_CHILD"

func TestMain(m *testing.M) {
	opensslExecutable = os.Getenv("PQTLS_TEST_OPENSSL")
	base := os.Getenv("PQTLS_TEST_ARTIFACT_DIR")
	if opensslExecutable == "" || base == "" {
		log.Print("required private fixture directory and pinned OpenSSL executable missing")
		os.Exit(1)
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		log.Print("fixture setup failed")
		os.Exit(1)
	}
	var err error
	fixtureDirectory, err = os.MkdirTemp(base, "synthetic-tls-")
	if err != nil {
		log.Print("fixture setup failed")
		os.Exit(1)
	}
	if err = generateFixtures(); err != nil {
		os.RemoveAll(fixtureDirectory)
		log.Printf("synthetic fixture setup failed: %v", err)
		os.Exit(1)
	}
	status := m.Run()
	if err = os.RemoveAll(fixtureDirectory); err != nil {
		log.Print("private fixture cleanup failed")
		status = 1
	}
	os.Exit(status)
}
func runOpenSSL(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, opensslExecutable, args...)
	cmd.Dir = fixtureDirectory
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.New("synthetic OpenSSL command failed")
	}
	return out, nil
}
func generateFixtures() error {
	for _, root := range []string{"ca", "other-ca"} {
		if _, e := runOpenSSL("req", "-new", "-x509", "-newkey", "ML-DSA-65", "-nodes", "-keyout", root+".key", "-out", root+".pem", "-days", "1", "-subj", "/CN=CICADA SYNTHETIC TEST ONLY "+root, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"); e != nil {
			return e
		}
	}
	for _, leaf := range []string{"hub", "node", "other-node"} {
		if _, e := runOpenSSL("req", "-new", "-newkey", "ML-DSA-65", "-nodes", "-keyout", leaf+".key", "-out", leaf+".csr", "-subj", "/CN=CICADA SYNTHETIC TEST ONLY "+leaf); e != nil {
			return e
		}
		purpose := "clientAuth"
		if leaf == "hub" {
			purpose = "serverAuth"
		}
		ext := "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + purpose + "\nsubjectAltName=DNS:" + leaf + ".synthetic.invalid\n"
		if e := os.WriteFile(filepath.Join(fixtureDirectory, leaf+".ext"), []byte(ext), 0600); e != nil {
			return e
		}
		if _, e := runOpenSSL("x509", "-req", "-in", leaf+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", leaf+".pem", "-days", "1", "-extfile", leaf+".ext"); e != nil {
			return e
		}
	}
	// Deliberately reuse the Node TLS key for a separately issued Hub leaf.
	// The adapter must reject this configuration after inspecting peer keys.
	if _, e := runOpenSSL("req", "-new", "-key", "node.key", "-out", "reused-hub.csr", "-subj", "/CN=CICADA SYNTHETIC TEST ONLY REUSED TLS KEY"); e != nil {
		return e
	}
	if _, e := runOpenSSL("x509", "-req", "-in", "reused-hub.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "reused-hub.pem", "-days", "1", "-extfile", "hub.ext"); e != nil {
		return e
	}
	identity := func(name string) Identity {
		v := Identity{Kind: "node", HubID: "synthetic-hub", NodeID: "synthetic-" + name, BindingEpoch: 1, DNSName: name + ".synthetic.invalid"}
		if name == "hub" {
			v.Kind = "hub"
			v.NodeID = ""
			v.BindingEpoch = 0
		}
		return v
	}
	pin := func(name string) (Pin, error) {
		data, e := os.ReadFile(filepath.Join(fixtureDirectory, name+".pem"))
		if e != nil {
			return Pin{}, e
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return Pin{}, ErrConfig
		}
		return Pin{Kind: "certificate-sha256", SHA256: sha256.Sum256(block.Bytes)}, nil
	}
	hp, e := pin("hub")
	if e != nil {
		return e
	}
	np, e := pin("node")
	if e != nil {
		return e
	}
	config := func(name string, peers ...Peer) Config {
		return Config{CertificateFile: filepath.Join(fixtureDirectory, name+".pem"), PrivateKeyFile: filepath.Join(fixtureDirectory, name+".key"), TrustFile: filepath.Join(fixtureDirectory, "ca.pem"), LocalIdentity: identity(name), Peers: peers, HandshakeTimeout: 2 * time.Second}
	}
	hubConfig = config("hub", Peer{Identity: identity("node"), Pin: np})
	nodeConfig = config("node", Peer{Identity: identity("hub"), Pin: hp})
	otherNodeConfig = config("other-node", Peer{Identity: identity("hub"), Pin: hp})
	return nil
}
func clone(cfg Config) Config { cfg.Peers = append([]Peer(nil), cfg.Peers...); return cfg }
func pair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	l, e := Listen("tcp", "127.0.0.1:0", hubConfig)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			failed <- e
		} else {
			accepted <- c
		}
	}()
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, e := client.DialContext(ctx, "tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	select {
	case c := <-accepted:
		t.Cleanup(func() { c.Close() })
		return raw.(*Conn), c.(*Conn)
	case e := <-failed:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal("server handshake did not complete")
	}
	return nil, nil
}
func assertState(t *testing.T, c *Conn, kind string) {
	t.Helper()
	s := c.PQTLSState()
	if s.TLSVersion != "TLSv1.3" || s.Group != "MLKEM768" || s.CipherSuite != "TLS_AES_256_GCM_SHA384" || s.PeerSignature != "ML-DSA-65" || s.ALPN != "http/1.1" || s.VerificationResult != 0 || !s.HostnameVerified || s.Peer.Kind != kind {
		t.Fatalf("unexpected negotiated state: %+v", s)
	}
	t.Logf("verified %s: version=%s group=%s suite=%s signature=%s alpn=%s verify=%d SAN=true pin=true", kind, s.TLSVersion, s.Group, s.CipherSuite, s.PeerSignature, s.ALPN, s.VerificationResult)
}
func TestExactProfileAndSPKIPin(t *testing.T) {
	a, b := pair(t)
	assertState(t, a, "hub")
	assertState(t, b, "node")
	if a.state.CertificateSHA256 != nodeConfig.Peers[0].Pin.SHA256 || b.state.CertificateSHA256 != hubConfig.Peers[0].Pin.SHA256 {
		t.Fatal("wrong certificate pin")
	}
	pub, e := runOpenSSL("x509", "-in", "hub.pem", "-pubkey", "-noout")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(pub)
	if block == nil {
		t.Fatal("missing public key")
	}
	if a.state.SPKISHA256 != sha256.Sum256(block.Bytes) {
		t.Fatal("SPKI digest is not DER SubjectPublicKeyInfo")
	}
	cfg := clone(nodeConfig)
	cfg.Peers[0].Pin = Pin{Kind: "spki-sha256", SHA256: a.state.SPKISHA256}
	l, e := Listen("tcp", "127.0.0.1:0", hubConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	client, e := NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, e := client.DialContext(ctx, "tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("SPKI accept timeout")
	}
}
func TestConcurrentDuplex(t *testing.T) {
	a, b := pair(t)
	deadline := time.Now().Add(5 * time.Second)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	left := bytes.Repeat([]byte("synthetic-left"), 20000)
	right := bytes.Repeat([]byte("synthetic-right"), 20000)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for _, p := range []struct {
		c    *Conn
		data []byte
	}{{a, left}, {b, right}} {
		wg.Add(1)
		go func(c *Conn, data []byte) { defer wg.Done(); _, e := c.Write(data); errs <- e }(p.c, p.data)
	}
	for _, p := range []struct {
		c    *Conn
		data []byte
	}{{a, right}, {b, left}} {
		wg.Add(1)
		go func(c *Conn, data []byte) {
			defer wg.Done()
			got := make([]byte, len(data))
			_, e := io.ReadFull(c, got)
			if e == nil && !bytes.Equal(data, got) {
				e = errors.New("duplex mismatch")
			}
			errs <- e
		}(p.c, p.data)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}

// This process-level regression forces one SSL connection's read/write calls
// onto distinct locked OS threads, then checks the test process can exit cleanly.
// OpenSSL documents that non-default library-context thread-local state must be
// stopped on every thread before that context is freed.
func TestLibctxThreadCleanupBeforeProcessExit(t *testing.T) {
	if os.Getenv(libctxCleanupChildEnv) != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestLibctxThreadCleanupBeforeProcessExit$")
		child.Env = append(os.Environ(), libctxCleanupChildEnv+"=1")
		_, err := child.CombinedOutput()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
					t.Fatalf("TLS worker subprocess terminated during process cleanup (signal=%s)", status.Signal())
				}
				t.Fatalf("TLS worker subprocess failed to exit cleanly (exit=%d)", exitErr.ExitCode())
			}
			t.Fatalf("TLS worker subprocess failed to exit cleanly (%T)", err)
		}
		return
	}

	a, b := pair(t)
	deadline := time.Now().Add(5 * time.Second)
	if err := a.SetDeadline(deadline); err != nil {
		t.Fatal("set client deadline")
	}
	if err := b.SetDeadline(deadline); err != nil {
		t.Fatal("set server deadline")
	}
	left := bytes.Repeat([]byte("synthetic-thread-local-left"), 8192)
	right := bytes.Repeat([]byte("synthetic-thread-local-right"), 8192)
	results := make(chan error, 4)
	var workers sync.WaitGroup
	write := func(conn *Conn, data []byte) {
		defer workers.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		written, err := conn.Write(data)
		if err == nil && written != len(data) {
			err = io.ErrShortWrite
		}
		results <- err
	}
	read := func(conn *Conn, want []byte) {
		defer workers.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		got := make([]byte, len(want))
		_, err := io.ReadFull(conn, got)
		if err == nil && !bytes.Equal(got, want) {
			err = errors.New("synthetic duplex payload mismatch")
		}
		results <- err
	}
	workers.Add(4)
	go write(a, left)
	go read(b, left)
	go write(b, right)
	go read(a, right)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("synthetic duplex transfer failed")
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal("close client TLS connection")
	}
	if err := b.Close(); err != nil {
		t.Fatal("close server TLS connection")
	}
}

func TestReadDeadlineChangeAndCloseBlocked(t *testing.T) {
	a, b := pair(t)
	done := make(chan error, 1)
	go func() { _, e := a.Read(make([]byte, 1)); done <- e }()
	if e := a.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline error: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline failed to unblock")
	}
	a.SetReadDeadline(time.Time{})
	go func() { _, e := b.Write([]byte{1}); done <- e }()
	if _, e := a.Read(make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	go func() { _, e := a.Read(make([]byte, 1)); done <- e }()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.Close() }()
	}
	wg.Wait()
	select {
	case e := <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("close: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("close failed to unblock")
	}
}
func TestWriteDeadlineAndCloseBlocked(t *testing.T) {
	for _, useClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "close"}[useClose], func(t *testing.T) {
			a, _ := pair(t)
			a.sslMu.Lock()
			e := syscallSetsockopt(a.fd)
			a.sslMu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if !useClose {
				a.SetWriteDeadline(time.Now().Add(80 * time.Millisecond))
			}
			done := make(chan error, 1)
			go func() { _, e := a.Write(make([]byte, 16*1024*1024)); done <- e }()
			if useClose {
				time.Sleep(40 * time.Millisecond)
				a.Close()
			}
			select {
			case e := <-done:
				want := error(os.ErrDeadlineExceeded)
				if useClose {
					want = net.ErrClosed
				}
				if !errors.Is(e, want) {
					t.Fatalf("expected %v got %v", want, e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked write did not stop")
			}
		})
	}
}
func TestHandshakeCancellationAndListenerClose(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := raw.Accept(); accepted <- c }()
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		c, e := client.DialContext(ctx, "tcp", raw.Addr().String())
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	peer := <-accepted
	defer peer.Close()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancel: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake cancel blocked")
	}
	l, e := Listen("tcp", "127.0.0.1:0", hubConfig)
	if e != nil {
		t.Fatal(e)
	}
	go func() { _, e := l.Accept(); done <- e }()
	stall, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer stall.Close()
	l.Close()
	select {
	case e := <-done:
		if !isClosed(e) {
			t.Fatalf("listener close: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("listener handshake close blocked")
	}
}

func httpFixture(t *testing.T, cfg Config, handler http.Handler) (string, *http.Server) {
	t.Helper()
	l, e := Listen("tcp", "127.0.0.1:0", cfg)
	if e != nil {
		t.Fatal(e)
	}
	s := &http.Server{Handler: handler, ConnContext: HTTPConnContext, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("HTTP server did not stop")
		}
	})
	return l.Addr().String(), s
}
func request(t *testing.T, cfg Config, address string) (*http.Response, error) {
	t.Helper()
	c, e := NewClient(cfg)
	if e != nil {
		return nil, e
	}
	tr, e := c.HTTPTransport(address)
	if e != nil {
		return nil, e
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrIdentity }}
	req, _ := http.NewRequest("POST", "https://"+address+"/synthetic", strings.NewReader("synthetic-test-body"))
	req.Header.Set("Authorization", "CicadaNode synthetic-not-a-real-credential")
	return client.Do(req)
}
func TestIdentityFailuresNeverReachHTTP(t *testing.T) {
	for _, name := range []string{"wrong-ca", "wrong-hub-pin", "wrong-hub-hostname", "unapproved-node-certificate", "wrong-node-pin", "wrong-node-hostname", "wrong-server-trust"} {
		t.Run(name, func(t *testing.T) {
			server, client := clone(hubConfig), clone(nodeConfig)
			switch name {
			case "wrong-ca":
				client.TrustFile = filepath.Join(fixtureDirectory, "other-ca.pem")
			case "wrong-hub-pin":
				client.Peers[0].Pin.SHA256[0] ^= 1
			case "wrong-hub-hostname":
				client.Peers[0].Identity.DNSName = "wrong.synthetic.invalid"
			case "unapproved-node-certificate":
				client = clone(otherNodeConfig)
			case "wrong-node-pin":
				server.Peers[0].Pin.SHA256[0] ^= 1
			case "wrong-node-hostname":
				server.Peers[0].Identity.DNSName = "wrong.synthetic.invalid"
			case "wrong-server-trust":
				server.TrustFile = filepath.Join(fixtureDirectory, "other-ca.pem")
			}
			var hits atomic.Int32
			addr, _ := httpFixture(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
			resp, e := request(t, client, addr)
			if resp != nil {
				resp.Body.Close()
			}
			if e == nil {
				t.Fatal("identity mismatch accepted")
			}
			if hits.Load() != 0 {
				t.Fatal("rejected connection reached HTTP credentials/body handler")
			}
			t.Logf("%s: rejected; HTTP handler calls=0", name)
		})
	}
}
func TestProfileFailuresNeverReachHTTP(t *testing.T) {
	var hits atomic.Int32
	addr, _ := httpFixture(t, hubConfig, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	base := []string{"s_client", "-connect", addr, "-CAfile", filepath.Join(fixtureDirectory, "ca.pem"), "-cert", filepath.Join(fixtureDirectory, "node.pem"), "-key", filepath.Join(fixtureDirectory, "node.key"), "-verify_return_error", "-alpn", "http/1.1"}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"X25519", []string{"-tls1_3", "-groups", "X25519"}},
		{"X25519MLKEM768", []string{"-tls1_3", "-groups", "X25519MLKEM768"}},
		{"AES128", []string{"-tls1_3", "-groups", "MLKEM768", "-ciphersuites", "TLS_AES_128_GCM_SHA256"}},
		{"TLS12", []string{"-tls1_2"}},
		{"classical-signature", []string{"-tls1_3", "-groups", "MLKEM768", "-sigalgs", "rsa_pss_rsae_sha256"}},
		{"HTTP2", []string{"-tls1_3", "-groups", "MLKEM768", "-alpn", "h2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, opensslExecutable, append(append([]string{}, base...), test.args...)...)
			cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
			cmd.Stdin = strings.NewReader("POST /synthetic HTTP/1.1\r\nAuthorization: synthetic\r\nContent-Length: 0\r\n\r\n")
			out, e := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("negative CLI timed out")
			}
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() == 0 {
				t.Fatalf("profile not rejected: %v", e)
			}
			if !bytes.Contains(out, []byte("alert")) && !bytes.Contains(out, []byte("handshake")) {
				t.Fatal("no handshake rejection evidence")
			}
			if hits.Load() != 0 {
				t.Fatal("wrong profile reached HTTP")
			}
			t.Logf("%s: CLI exit=%d, HTTP calls=0", test.name, exit.ExitCode())
		})
	}
	t.Run("missing-client-certificate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		args := []string{"s_client", "-connect", addr, "-CAfile", filepath.Join(fixtureDirectory, "ca.pem"), "-tls1_3", "-groups", "MLKEM768", "-sigalgs", "mldsa65", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-alpn", "http/1.1", "-quiet"}
		cmd := exec.CommandContext(ctx, opensslExecutable, args...)
		cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
		cmd.Stdin = strings.NewReader("GET / HTTP/1.1\r\nHost: synthetic\r\n\r\n")
		out, e := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatal("missing-cert test timed out")
		}
		if e == nil || !bytes.Contains(out, []byte("certificate required")) {
			t.Fatal("missing cert not rejected")
		}
		if hits.Load() != 0 {
			t.Fatal("missing cert reached HTTP")
		}
		t.Log("missing client certificate: rejected, HTTP calls=0")
	})
	// Failed handshakes must not stop the http.Server accept loop.
	resp, e := request(t, nodeConfig, addr)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("healthy request after rejection failed")
	}
}
func TestClassicalOnlyServerRejected(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"hub.synthetic.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"http/1.1"}})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	var bodyBytes atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		bodyBytes.Add(int32(n))
	}()
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, e := client.DialContext(ctx, "tcp", l.Addr().String())
	if c != nil {
		c.Close()
	}
	if e == nil {
		t.Fatal("classical-only server accepted")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("classical server did not finish")
	}
	if bodyBytes.Load() != 0 {
		t.Fatal("HTTP bytes sent to classical server")
	}
}
func TestHTTP11SSEDisconnectReconnectAndState(t *testing.T) {
	var hits atomic.Int32
	var bad atomic.Bool
	var active sync.WaitGroup
	serverCfg := clone(hubConfig)
	serverCfg.HandshakeTimeout = 200 * time.Millisecond
	addr, _ := httpFixture(t, serverCfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Done()
		state, e := StateFromContext(r.Context())
		if e != nil || state.Peer.Kind != "node" || r.TLS != nil || r.Proto != "HTTP/1.1" {
			bad.Store(true)
			w.WriteHeader(500)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: wake\ndata: synthetic\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-time.After(300 * time.Millisecond):
			io.WriteString(w, "event: still-live\ndata: synthetic\n\n")
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
		<-r.Context().Done()
	}))
	clientCfg := clone(nodeConfig)
	clientCfg.HandshakeTimeout = 200 * time.Millisecond
	c, e := NewClient(clientCfg)
	if e != nil {
		t.Fatal(e)
	}
	tr, e := c.HTTPTransport(addr)
	if e != nil {
		t.Fatal(e)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+addr+"/events", nil)
		resp, e := client.Do(req)
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		if resp.Proto != "HTTP/1.1" || resp.TLS != nil {
			t.Fatal("invented Go TLS/HTTP2 state")
		}
		scan := bufio.NewScanner(resp.Body)
		if !scan.Scan() || scan.Text() != "event: wake" {
			t.Fatal("SSE event missing")
		}
		if !scan.Scan() || scan.Text() != "data: synthetic" {
			t.Fatal("SSE data missing")
		}
		if !scan.Scan() || scan.Text() != "" || !scan.Scan() || scan.Text() != "event: still-live" {
			t.Fatal("SSE inherited handshake deadline")
		}
		cancel()
		resp.Body.Close()
	}
	finished := make(chan struct{})
	go func() { active.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("mid-SSE disconnect retained handler")
	}
	if bad.Load() || hits.Load() != 2 {
		t.Fatal("SSE state/reconnect failed")
	}
	if _, e = StateFromContext(context.Background()); !errors.Is(e, ErrHTTPState) {
		t.Fatal("missing state not typed")
	}
	if _, e = RequireGoTLSState(nil); !errors.Is(e, ErrHTTPState) {
		t.Fatal("Go state not typed")
	}
}

func waitPending(t *testing.T, l *listener, want int) {
	t.Helper()
	timeout := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(l.credits) != want {
		select {
		case <-tick.C:
		case <-timeout:
			t.Fatal("pending handshake count did not settle")
		}
	}
}

func TestStalledHandshakeDoesNotBlockApprovedPeer(t *testing.T) {
	cfg := clone(hubConfig)
	cfg.MaxPendingHandshakes = 2
	cfg.HandshakeTimeout = 2 * time.Second
	raw, e := Listen("tcp", "127.0.0.1:0", cfg)
	if e != nil {
		t.Fatal(e)
	}
	l := raw.(*listener)
	defer l.Close()
	stall, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer stall.Close()
	waitPending(t, l, 1)
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	peer, e := client.DialContext(ctx, "tcp", l.Addr().String())
	if e != nil {
		t.Fatal("stalled handshake blocked approved peer:", e)
	}
	defer peer.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("approved peer not accepted")
		}
		assertState(t, c.(*Conn), "node")
		c.Close()
	case <-ctx.Done():
		t.Fatal("approved peer waited for stalled handshake")
	}
	closed := make(chan struct{})
	go func() { l.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close failed to cancel pending handshake")
	}
	if len(l.credits) != 0 {
		t.Fatal("pending handshake credit leaked")
	}
}

func TestPendingHandshakeOverloadAndReadyQueueAreBounded(t *testing.T) {
	cfg := clone(hubConfig)
	cfg.MaxPendingHandshakes = 1
	raw, e := Listen("tcp", "127.0.0.1:0", cfg)
	if e != nil {
		t.Fatal(e)
	}
	l := raw.(*listener)
	defer l.Close()
	stall, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	waitPending(t, l, 1)
	extra, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	extra.SetReadDeadline(time.Now().Add(time.Second))
	_, e = extra.Read(make([]byte, 1))
	extra.Close()
	if e == nil || errors.Is(e, os.ErrDeadlineExceeded) || l.overloaded.Load() != 1 {
		t.Fatal("overload did not immediately close unadmitted socket")
	}
	stall.Close()
	waitPending(t, l, 0)
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := client.DialContext(ctx, "tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(l.ready) != 1 {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("verified peer not queued")
		}
	}
	if len(l.credits) != 1 {
		t.Fatal("verified queue released admission credit early")
	}
	excess, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	excess.SetReadDeadline(time.Now().Add(time.Second))
	_, e = excess.Read(make([]byte, 1))
	excess.Close()
	if e == nil || errors.Is(e, os.ErrDeadlineExceeded) || l.overloaded.Load() != 2 {
		t.Fatal("ready queue bypassed pending bound")
	}
	l.Close()
	if len(l.ready) != 0 || len(l.credits) != 0 {
		t.Fatal("Close retained verified unaccepted connection")
	}
}

func TestPrivateTLSMaterialFailsClosed(t *testing.T) {
	key, e := os.ReadFile(nodeConfig.PrivateKeyFile)
	if e != nil {
		t.Fatal("fixture key read")
	}
	for _, name := range []string{"world-readable", "malformed", "symlink", "NUL-path", "wrong-private-key"} {
		t.Run(name, func(t *testing.T) {
			cfg := clone(nodeConfig)
			path := filepath.Join(fixtureDirectory, "invalid-"+name+".key")
			switch name {
			case "world-readable":
				if e := os.WriteFile(path, key, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
				cfg.PrivateKeyFile = path
			case "malformed":
				if e := os.WriteFile(path, []byte("CICADA SYNTHETIC MALFORMED KEY"), 0600); e != nil {
					t.Fatal(e)
				}
				cfg.PrivateKeyFile = path
			case "symlink":
				if e := os.Symlink(nodeConfig.PrivateKeyFile, path); e != nil {
					t.Fatal(e)
				}
				cfg.PrivateKeyFile = path
			case "NUL-path":
				cfg.CertificateFile += "\x00ignored"
			case "wrong-private-key":
				cfg.PrivateKeyFile = otherNodeConfig.PrivateKeyFile
			}
			if _, e := NewClient(cfg); e == nil || (!errors.Is(e, ErrConfig) && !errors.Is(e, ErrIdentity)) {
				t.Fatalf("unsafe material accepted: %v", e)
			}
		})
	}
}
func TestHTTPOriginAndPlaintextFailClosed(t *testing.T) {
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	tr, e := client.HTTPTransport("127.0.0.1:9")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tr.DialTLSContext(context.Background(), "tcp", "127.0.0.1:10"); !errors.Is(e, ErrIdentity) {
		t.Fatal("origin substitution accepted")
	}
	if _, e = tr.DialContext(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(e, ErrProfile) {
		t.Fatal("plaintext dial accepted")
	}
}

func TestHandshakeDeadlineAndDescriptorOwnership(t *testing.T) {
	baseline, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 8; i++ {
		raw, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		accepted := make(chan net.Conn, 1)
		go func() { c, _ := raw.Accept(); accepted <- c }()
		cfg := clone(nodeConfig)
		cfg.HandshakeTimeout = 30 * time.Millisecond
		client, e := NewClient(cfg)
		if e != nil {
			t.Fatal(e)
		}
		conn, e := client.DialContext(context.Background(), "tcp", raw.Addr().String())
		if conn != nil {
			conn.Close()
			t.Fatal("failed handshake returned a nonnil connection")
		}
		if !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatalf("handshake timeout: %v", e)
		}
		peer := <-accepted
		if peer != nil {
			peer.Close()
		}
		raw.Close()
	}
	after, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	if len(after) > len(baseline) {
		t.Fatalf("descriptor leak: before=%d after=%d", len(baseline), len(after))
	}
}

func TestNodeAndHubCannotReuseTLSKey(t *testing.T) {
	server, client := clone(hubConfig), clone(nodeConfig)
	server.CertificateFile = filepath.Join(fixtureDirectory, "reused-hub.pem")
	server.PrivateKeyFile = filepath.Join(fixtureDirectory, "node.key")
	public, e := os.ReadFile(server.CertificateFile)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("fixture cert missing")
	}
	client.Peers[0].Pin.SHA256 = sha256.Sum256(block.Bytes)
	var hits atomic.Int32
	addr, _ := httpFixture(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	resp, e := request(t, client, addr)
	if resp != nil {
		resp.Body.Close()
	}
	if e == nil || hits.Load() != 0 {
		t.Fatal("same TLS key reused between Node and Hub")
	}
}

func TestCertificateCannotMapToConflictingNodeIdentities(t *testing.T) {
	public, e := runOpenSSL("x509", "-in", "node.pem", "-pubkey", "-noout")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("synthetic public key missing")
	}
	server := clone(hubConfig)
	alias := server.Peers[0]
	alias.Pin = Pin{Kind: "spki-sha256", SHA256: sha256.Sum256(block.Bytes)}
	alias.Identity.BindingEpoch++
	server.Peers = append(server.Peers, alias)
	var hits atomic.Int32
	addr, _ := httpFixture(t, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	resp, e := request(t, nodeConfig, addr)
	if resp != nil {
		resp.Body.Close()
	}
	if e == nil || hits.Load() != 0 {
		t.Fatal("certificate/SPKI aliases chose conflicting Node binding epochs")
	}
}

func TestPeerDisconnectUnblocksConcurrentIO(t *testing.T) {
	a, b := pair(t)
	a.SetDeadline(time.Now().Add(time.Second))
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { _, e := a.Read(make([]byte, 1)); readDone <- e }()
	go func() { _, e := a.Write(make([]byte, 16*1024*1024)); writeDone <- e }()
	b.Close()
	for _, ch := range []chan error{readDone, writeDone} {
		select {
		case e := <-ch:
			if e == nil {
				t.Fatal("IO succeeded after peer disconnect")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("peer disconnect left blocked IO")
		}
	}
}

func TestUninitializedConnectionOwnsNoDescriptor(t *testing.T) {
	var c Conn
	if e := c.SetDeadline(time.Now()); !errors.Is(e, net.ErrClosed) {
		t.Fatal("uninitialized connection accepted deadlines")
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Read(make([]byte, 1)); !errors.Is(e, net.ErrClosed) {
		t.Fatal("uninitialized read")
	}
	if _, e := c.Write([]byte{1}); !errors.Is(e, net.ErrClosed) {
		t.Fatal("uninitialized write")
	}
}
