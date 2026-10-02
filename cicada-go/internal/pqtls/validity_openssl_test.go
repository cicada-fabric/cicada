//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func lifetimePin(t *testing.T, path string) Pin {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid synthetic lifetime certificate")
	}
	return Pin{Kind: "certificate-sha256", SHA256: sha256.Sum256(block.Bytes)}
}

func lifetimeLeaf(t *testing.T, name, output string, start, end time.Time) string {
	t.Helper()
	_, err := runOpenSSL("x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", output,
		"-not_before", start.UTC().Format("20060102150405Z"), "-not_after", end.UTC().Format("20060102150405Z"), "-extfile", name+".ext")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(fixtureDirectory, output)
}

func lifetimePair(t *testing.T, server, clientConfig Config) (*Conn, *Conn) {
	t.Helper()
	l, err := Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			failed <- err
		} else {
			accepted <- c
		}
	}()
	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := client.DialContext(ctx, "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	select {
	case c := <-accepted:
		t.Cleanup(func() { c.Close() })
		return raw.(*Conn), c.(*Conn)
	case err := <-failed:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("synthetic lifetime handshake timed out")
	}
	return nil, nil
}

func lifetimeHandshakeDenied(t *testing.T, server, clientConfig Config) {
	t.Helper()
	l, err := Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "tcp", l.Addr().String())
	if c != nil {
		// TLS 1.3 clients can finish their side before the server validates
		// their certificate. Observe the server alert and verified Accept too.
		if err == nil {
			c.SetReadDeadline(time.Now().Add(time.Second))
			_, err = c.Read(make([]byte, 1))
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("invalid-certificate handshake did not produce a server alert")
			}
		}
		c.Close()
	}
	if err == nil {
		t.Fatal("expired or not-yet-valid certificate established a connection")
	}
	l.Close()
	select {
	case c := <-accepted:
		if c != nil {
			c.Close()
			t.Fatal("server exposed an invalid-certificate connection")
		}
	case <-time.After(time.Second):
		t.Fatal("invalid handshake listener cleanup blocked")
	}
}

// One finite real certificate window serves all three cases, with no global
// clock hooks or fabricated TLS state. Both IO directions use verified Conns.
func TestVerifiedChainValidityAndRetainedIO(t *testing.T) {
	start, end := time.Now().Add(-time.Minute).UTC().Truncate(time.Second), time.Now().Add(12*time.Second).UTC().Truncate(time.Second)
	hubLeaf := lifetimeLeaf(t, "hub", "short-hub.pem", start, end)
	nodeLeaf := lifetimeLeaf(t, "node", "short-node.pem", start, end)
	_, err := runOpenSSL("x509", "-in", "ca.pem", "-key", "ca.key", "-out", "short-ca.pem", "-not_before", start.Format("20060102150405Z"), "-not_after", end.Format("20060102150405Z"))
	if err != nil {
		t.Fatal(err)
	}
	hubShort, nodeForHubShort := clone(hubConfig), clone(nodeConfig)
	hubShort.CertificateFile = hubLeaf
	nodeForHubShort.Peers[0].Pin = lifetimePin(t, hubLeaf)
	nodeShort, hubForNodeShort := clone(nodeConfig), clone(hubConfig)
	nodeShort.CertificateFile = nodeLeaf
	hubForNodeShort.Peers[0].Pin = lifetimePin(t, nodeLeaf)
	hubChain, nodeChain := clone(hubConfig), clone(nodeConfig)
	hubChain.TrustFile, nodeChain.TrustFile = filepath.Join(fixtureDirectory, "short-ca.pem"), filepath.Join(fixtureDirectory, "short-ca.pem")
	futureNode := clone(nodeConfig)
	futureNode.CertificateFile = lifetimeLeaf(t, "node", "future-node.pem", end.Add(time.Minute), end.Add(time.Hour))
	futureHub := clone(hubConfig)
	futureHub.Peers[0].Pin = lifetimePin(t, futureNode.CertificateFile)
	lifetimeHandshakeDenied(t, futureHub, futureNode)
	cases := []struct {
		name          string
		hub, node     Config
		clientExpires bool
	}{
		{"Hub_leaf", hubShort, nodeForHubShort, true},
		{"Node_leaf", hubForNodeShort, nodeShort, false},
		{"verified_CA_earlier_than_leaf", hubChain, nodeChain, true},
	}
	type pending struct {
		name               string
		write              *Conn
		read, blockedWrite chan error
		server, client     Config
	}
	var waits []pending
	for _, tc := range cases {
		selectSide := func(a, b *Conn) *Conn {
			if tc.clientExpires {
				return a
			}
			return b
		}
		a, b := lifetimePair(t, tc.hub, tc.node)
		writer := selectSide(a, b)
		if !writer.PQTLSState().VerifiedNotAfter.Equal(end) || !writer.PQTLSState().ValidAt(time.Now()) {
			t.Fatal("real verified chain lifetime was not extracted")
		}
		if tc.name == "verified_CA_earlier_than_leaf" && !b.PQTLSState().VerifiedNotAfter.Equal(end) {
			t.Fatal("verified root interval was not intersected on both sides")
		}
		x, y := lifetimePair(t, tc.hub, tc.node)
		reader := selectSide(x, y)
		if err := reader.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		readDone := make(chan error, 1)
		go func() {
			n, err := reader.Read(make([]byte, 1))
			if n != 0 {
				readDone <- errors.New("expired blocked Read returned application bytes")
			} else {
				readDone <- err
			}
		}()
		u, v := lifetimePair(t, tc.hub, tc.node)
		blockedWriter := selectSide(u, v)
		if err := syscallSetsockopt(blockedWriter.fd); err != nil {
			t.Fatal(err)
		}
		writeDone := make(chan error, 1)
		go func() {
			_, err := blockedWriter.Write(bytes.Repeat([]byte("synthetic opaque fixture"), 256*1024))
			writeDone <- err
		}()
		waits = append(waits, pending{tc.name, writer, readDone, writeDone, tc.hub, tc.node})
	}
	if time.Until(end) < time.Second {
		t.Fatal("synthetic lifetime setup exceeded its finite certificate window")
	}
	<-time.After(time.Until(end) + 20*time.Millisecond)
	for _, p := range waits {
		t.Run(p.name, func(t *testing.T) {
			if n, err := p.write.Write([]byte("synthetic post-expiry application bytes")); n != 0 || !errors.Is(err, ErrCertificateValidity) {
				t.Fatalf("post-expiry Write n=%d err=%v", n, err)
			}
			for _, done := range []chan error{p.read, p.blockedWrite} {
				select {
				case err := <-done:
					if !errors.Is(err, ErrCertificateValidity) {
						t.Fatalf("certificate did not bound blocked IO: %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("expired IO or teardown deadlocked")
				}
			}
			lifetimeHandshakeDenied(t, p.server, p.client)
			t.Log("actual verified chain expired; retained Write refused before new bytes, blocked Read/Write expired without caller deadline, fresh handshake refused")
		})
	}
}
