package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/pqtls"
)

type diagnosticStateConn struct {
	net.Conn
	state pqtls.State
}

func (c diagnosticStateConn) PQTLSState() pqtls.State { return c.state }

type diagnosticRoundTripper struct{ conn diagnosticStateConn }

func (t diagnosticRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(request.Context()); trace != nil && trace.GotConn != nil {
		left, right := net.Pipe()
		defer left.Close()
		defer right.Close()
		conn := t.conn
		conn.Conn = left
		trace.GotConn(httptrace.GotConnInfo{Conn: conn, Reused: true})
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
}

func resetMachinePQDiagnosticForTest(t *testing.T) {
	t.Helper()
	machinePQDiagnosticMu.Lock()
	defer machinePQDiagnosticMu.Unlock()
	if machinePQDiagnosticFile != nil {
		_ = machinePQDiagnosticFile.Close()
	}
	machinePQDiagnosticFile = nil
	machinePQDiagnosticPath = ""
	machinePQDiagnosticBytes = 0
	machinePQDiagnosticRecords = 0
	t.Cleanup(func() {
		machinePQDiagnosticMu.Lock()
		defer machinePQDiagnosticMu.Unlock()
		if machinePQDiagnosticFile != nil {
			_ = machinePQDiagnosticFile.Close()
		}
		machinePQDiagnosticFile = nil
		machinePQDiagnosticPath = ""
		machinePQDiagnosticBytes = 0
		machinePQDiagnosticRecords = 0
	})
}

func TestMachinePQDiagnosticIsOffByDefault(t *testing.T) {
	resetMachinePQDiagnosticForTest(t)
	t.Setenv("CICADA_PQTLS_DIAGNOSTIC_FILE", "")
	ctx := withMachinePQDiagnostic(context.Background(), "sealed-ask", "request-public", "message-public")
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://hub.invalid/v2/relay/nodes/node/sealed/ask", nil)
	client := &http.Client{Transport: machinePQDiagnosticTransport{base: diagnosticRoundTripper{}}}
	_, err := client.Do(request)
	if err != nil {
		t.Fatal("diagnostic-off request failed", err)
	}
	if machinePQDiagnosticFile != nil {
		t.Fatal("diagnostic-off request opened an evidence file")
	}
}

func TestMachineNodeHTTPClientStandardPinnedTransportUnchanged(t *testing.T) {
	t.Setenv("CICADA_NODE_PQTLS_CONFIG", "")
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer plain.Close()
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub-standard", Origin: plain.URL, NodeID: "node-standard"})
	client, err := machineNodeHTTPClient(ctx, 0)
	if err != nil {
		t.Fatal("standard client construction failed", err)
	}
	if client.Transport != nil {
		t.Fatal("standard pinned client unexpectedly replaced its default transport")
	}
	response, err := client.Get(plain.URL + "/ordinary-health")
	if err != nil {
		t.Fatal("standard pinned request panicked or failed", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("standard transport status %d", response.StatusCode)
	}
}

func TestMachinePQDiagnosticCapturesOnlyMeasuredConnectionMetadata(t *testing.T) {
	resetMachinePQDiagnosticForTest(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tls.jsonl")
	t.Setenv("CICADA_PQTLS_DIAGNOSTIC_FILE", path)
	cert := sha256.Sum256([]byte("synthetic-cert"))
	spki := sha256.Sum256([]byte("synthetic-spki"))
	state := pqtls.State{TLSVersion: "TLSv1.3", Group: "MLKEM768", CipherSuite: "TLS_AES_256_GCM_SHA384",
		PeerSignature: "ML-DSA-65", ALPN: "http/1.1", VerificationResult: 0, HostnameVerified: true,
		Peer:              pqtls.Identity{Kind: "hub", HubID: "hub-public", DNSName: "hub.synthetic.invalid"},
		CertificateSHA256: cert, SPKISHA256: spki}
	ctx := withMachinePQDiagnostic(context.Background(), "sealed-ask", "request-public", "message-public")
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hub.synthetic.invalid/v2/relay/nodes/node-public/group/sealed/ask", nil)
	client := &http.Client{Transport: machinePQDiagnosticTransport{base: diagnosticRoundTripper{conn: diagnosticStateConn{state: state}}}}
	_, err := client.Do(request)
	if err != nil {
		t.Fatal("measured diagnostic request failed", err)
	}
	if machinePQDiagnosticFile == nil {
		t.Fatal("GotConn state was not recorded")
	}
	if err := machinePQDiagnosticFile.Sync(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record machinePQDiagnosticRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal("invalid private diagnostic record", err)
	}
	if record.SchemaVersion != 1 || record.Event != "got-conn" || record.Operation != "sealed-ask" || record.RequestID != "request-public" || record.MessageID != "message-public" || record.ObservationID == "" ||
		record.Route != "fabric-ask" || !record.Reused || record.TLSVersion != "TLSv1.3" || record.Group != "MLKEM768" ||
		record.PeerKind != "hub" || record.HubID != "hub-public" || record.CertificateSHA256 != hex.EncodeToString(cert[:]) ||
		record.SPKISHA256 != hex.EncodeToString(spki[:]) {
		t.Fatal("diagnostic did not retain exact correlation and measured TLS state")
	}
	if strings.Contains(string(data), "synthetic-cert") || strings.Contains(string(data), "Authorization") || strings.Contains(string(data), "ciphertext") {
		t.Fatal("diagnostic contains secret material or payload")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("diagnostic file is not private", err)
	}
	if err := writeMachinePQDiagnostic(machinePQDiagnosticRecord{}); err != nil {
		t.Fatal("bounded follow-up evidence write failed", err)
	}
}
