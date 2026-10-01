//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Observe the receiving server, including a positive control, rather than
// inferring client-certificate privacy from an HTTP handler's invocation count.
func TestHubPinVerifiedBeforeNodeCertificate(t *testing.T) {
	for _, wrongPin := range []bool{false, true} {
		name := "approved-hub-control"
		if wrongPin {
			name = "valid-chain-hostname-wrong-pin"
		}
		t.Run(name, func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reserved.Addr().String()
			reserved.Close()
			tracePath := filepath.Join(fixtureDirectory, name+".trace")
			trace, err := os.OpenFile(tracePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer trace.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			args := []string{"s_server", "-accept", address, "-cert", hubConfig.CertificateFile, "-key", hubConfig.PrivateKeyFile,
				"-CAfile", hubConfig.TrustFile, "-Verify", "1", "-verify_return_error", "-tls1_3", "-groups", "MLKEM768",
				"-sigalgs", "mldsa65", "-client_sigalgs", "mldsa65", "-ciphersuites", "TLS_AES_256_GCM_SHA384",
				"-alpn", "http/1.1", "-num_tickets", "0", "-naccept", "1", "-www", "-state", "-msg"}
			cmd := exec.CommandContext(ctx, opensslExecutable, args...)
			cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
			cmd.Stdout, cmd.Stderr = trace, trace
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			defer func() {
				cancel()
				if !waited {
					<-done
				}
			}()
			for {
				data, err := os.ReadFile(tracePath)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "ACCEPT") {
					break
				}
				select {
				case <-done:
					waited = true
					t.Fatal("synthetic observing server exited before accepting")
				case <-ctx.Done():
					t.Fatal("synthetic observing server did not become ready")
				case <-time.After(5 * time.Millisecond):
				}
			}
			cfg := clone(nodeConfig)
			if wrongPin {
				cfg.Peers[0].Pin.SHA256[0] ^= 1
			}
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialContext(ctx, "tcp", address)
			if conn != nil {
				conn.Close()
			}
			if wrongPin && err == nil || !wrongPin && err != nil {
				t.Fatalf("unexpected handshake result for wrongPin=%v: %v", wrongPin, err)
			}
			select {
			case <-done:
				waited = true // OpenSSL may report unexpected EOF after Conn.Close.
			case <-ctx.Done():
				t.Fatal("synthetic observing server did not stop")
			}
			data, err := os.ReadFile(tracePath)
			if err != nil {
				t.Fatal(err)
			}
			var hello, serverCertificate, clientCertificate, clientVerify int
			for _, line := range strings.Split(string(data), "\n") {
				if !strings.Contains(line, ", Handshake [length ") {
					continue
				}
				switch {
				case strings.HasPrefix(line, "<<<") && strings.HasSuffix(line, ", ClientHello"):
					hello++
				case strings.HasPrefix(line, ">>>") && strings.HasSuffix(line, ", Certificate"):
					serverCertificate++
				case strings.HasPrefix(line, "<<<") && strings.HasSuffix(line, ", Certificate"):
					clientCertificate++
				case strings.HasPrefix(line, "<<<") && strings.HasSuffix(line, ", CertificateVerify"):
					clientVerify++
				}
			}
			if hello != 1 || serverCertificate != 1 {
				t.Fatalf("observer did not exercise the server certificate: hello=%d serverCertificate=%d", hello, serverCertificate)
			}
			if wrongPin && (clientCertificate != 0 || clientVerify != 0) || !wrongPin && (clientCertificate != 1 || clientVerify != 1) {
				t.Fatalf("unexpected Node authentication records: Certificate=%d CertificateVerify=%d", clientCertificate, clientVerify)
			}
			t.Logf("wrongPin=%v server observer: Node Certificate=%d CertificateVerify=%d", wrongPin, clientCertificate, clientVerify)
		})
	}
}
