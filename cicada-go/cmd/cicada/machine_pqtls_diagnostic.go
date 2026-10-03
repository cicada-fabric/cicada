package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cicada-ai/cicada/internal/pqtls"
)

// This opt-in sink records only measured connections from the checked Node
// transport. Its path must be new in a private owner-only directory.
type machinePQDiagnosticContext struct {
	mu           sync.Mutex
	operation    string
	requestID    string
	messageID    string
	connectionID string
}

type machinePQDiagnosticKey struct{}

func withMachinePQDiagnostic(ctx context.Context, operation, requestID, messageID string) context.Context {
	if os.Getenv("CICADA_PQTLS_DIAGNOSTIC_FILE") == "" {
		return ctx
	}
	return context.WithValue(ctx, machinePQDiagnosticKey{}, &machinePQDiagnosticContext{
		operation: operation, requestID: requestID, messageID: messageID,
	})
}

type machinePQDiagnosticTransport struct{ base http.RoundTripper }

func (t machinePQDiagnosticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.base == nil {
		return http.DefaultTransport.RoundTrip(request)
	}
	if os.Getenv("CICADA_PQTLS_DIAGNOSTIC_FILE") == "" {
		return t.base.RoundTrip(request)
	}
	diagnostic, ok := request.Context().Value(machinePQDiagnosticKey{}).(*machinePQDiagnosticContext)
	if !ok {
		return t.base.RoundTrip(request)
	}
	request = request.Clone(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			stateConn, ok := info.Conn.(interface{ PQTLSState() pqtls.State })
			if !ok {
				return
			}
			state := stateConn.PQTLSState()
			diagnostic.mu.Lock()
			diagnostic.connectionID = "conn-" + strconv.FormatUint(machinePQDiagnosticConnection.Add(1), 10)
			connectionID := diagnostic.connectionID
			diagnostic.mu.Unlock()
			localNodeID := ""
			if hub, found := machineHubFrom(request.Context()); found {
				localNodeID = hub.NodeID
			}
			if err := writeMachinePQDiagnostic(machinePQDiagnosticRecord{
				Operation: diagnostic.operation, RequestID: diagnostic.requestID, MessageID: diagnostic.messageID,
				Event: "got-conn", ObservationID: connectionID, Route: machinePQDiagnosticRoute(request.URL.Path), Reused: info.Reused,
				TLSVersion: state.TLSVersion, Group: state.Group, CipherSuite: state.CipherSuite,
				PeerSignature: state.PeerSignature, ALPN: state.ALPN, VerificationResult: state.VerificationResult,
				HostnameVerified: state.HostnameVerified, PeerKind: state.Peer.Kind, HubID: state.Peer.HubID,
				LocalNodeID: localNodeID, PeerNodeID: state.Peer.NodeID, TLSEpoch: state.Peer.BindingEpoch,
				CertificateSHA256: hex.EncodeToString(state.CertificateSHA256[:]),
				SPKISHA256:        hex.EncodeToString(state.SPKISHA256[:]),
			}); err != nil {
				machinePQDiagnosticFailures.Add(1)
			}
		},
	}))
	return t.base.RoundTrip(request)
}

type machinePQDiagnosticRecord struct {
	SchemaVersion      int    `json:"schema_version"`
	Operation          string `json:"operation"`
	RequestID          string `json:"request_id,omitempty"`
	MessageID          string `json:"message_id,omitempty"`
	Event              string `json:"event,omitempty"`
	ObservationID      string `json:"observation_id,omitempty"`
	Route              string `json:"route"`
	Reused             bool   `json:"reused_connection"`
	TLSVersion         string `json:"tls_version"`
	Group              string `json:"group"`
	CipherSuite        string `json:"cipher_suite"`
	PeerSignature      string `json:"peer_signature"`
	ALPN               string `json:"alpn"`
	VerificationResult int64  `json:"verification_result"`
	HostnameVerified   bool   `json:"hostname_verified"`
	PeerKind           string `json:"peer_kind"`
	HubID              string `json:"hub_id"`
	LocalNodeID        string `json:"local_node_id,omitempty"`
	PeerNodeID         string `json:"peer_node_id,omitempty"`
	TLSEpoch           uint64 `json:"tls_epoch,omitempty"`
	CertificateSHA256  string `json:"certificate_sha256"`
	SPKISHA256         string `json:"spki_sha256"`
}

func machinePQDiagnosticRoute(path string) string {
	switch {
	case strings.HasSuffix(path, "/fabric/whoami"):
		return "fabric-whoami"
	case strings.HasSuffix(path, "/fabric/find"):
		return "fabric-find"
	case strings.HasSuffix(path, "/fabric/resolve"):
		return "fabric-resolve"
	case strings.HasSuffix(path, "/fabric/heartbeat"):
		return "fabric-heartbeat"
	case strings.HasSuffix(path, "/sealed/ask"), strings.HasSuffix(path, "/group/sealed/ask"):
		return "fabric-ask"
	case strings.HasSuffix(path, "/sealed/reply"), strings.HasSuffix(path, "/group/sealed/reply"):
		return "fabric-reply"
	case strings.HasSuffix(path, "/events"):
		return "relay-events"
	default:
		return "other"
	}
}

var machinePQDiagnosticMu sync.Mutex
var machinePQDiagnosticFile *os.File
var machinePQDiagnosticPath string
var machinePQDiagnosticBytes int64
var machinePQDiagnosticRecords int
var machinePQDiagnosticConnection atomic.Uint64
var machinePQDiagnosticFailures atomic.Uint64

func writeMachinePQDiagnostic(record machinePQDiagnosticRecord) error {
	machinePQDiagnosticMu.Lock()
	defer machinePQDiagnosticMu.Unlock()
	path := os.Getenv("CICADA_PQTLS_DIAGNOSTIC_FILE")
	if path == "" || machinePQDiagnosticRecords >= 4096 {
		return errors.New("diagnostic disabled or full")
	}
	if machinePQDiagnosticFile == nil {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		parent := filepath.Dir(abs)
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 || !machinePQOwnedByCurrentUser(info) || !machinePQNoSymlinkPath(parent) {
			return errors.New("diagnostic parent must be an existing private directory")
		}
		file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		fileInfo, err := file.Stat()
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0600 || !machinePQOwnedByCurrentUser(fileInfo) {
			_ = file.Close()
			return errors.New("diagnostic target is not a new owner-private regular file")
		}
		machinePQDiagnosticFile, machinePQDiagnosticPath = file, abs
	}
	abs, err := filepath.Abs(path)
	if err != nil || machinePQDiagnosticPath != abs {
		return errors.New("diagnostic path changed during process")
	}
	record.SchemaVersion = 1
	data, err := json.Marshal(record)
	if err != nil || len(data) > 4096 || machinePQDiagnosticBytes+int64(len(data)+1) > 8*1024*1024 {
		return errors.New("diagnostic record limit")
	}
	data = append(data, '\n')
	n, err := machinePQDiagnosticFile.Write(data)
	if err != nil || n != len(data) {
		return errors.New("diagnostic write failed")
	}
	machinePQDiagnosticRecords++
	machinePQDiagnosticBytes += int64(n)
	return nil
}

func machinePQNoSymlinkPath(path string) bool {
	current := string(filepath.Separator)
	relative, err := filepath.Rel(current, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
	}
	return true
}

func recordMachinePQDiagnosticEvent(ctx context.Context, event string) {
	diagnostic, ok := ctx.Value(machinePQDiagnosticKey{}).(*machinePQDiagnosticContext)
	if !ok || event != "ready" && event != "wake" {
		return
	}
	diagnostic.mu.Lock()
	connectionID := diagnostic.connectionID
	diagnostic.mu.Unlock()
	if connectionID == "" {
		return
	}
	if err := writeMachinePQDiagnostic(machinePQDiagnosticRecord{
		Operation: diagnostic.operation, RequestID: diagnostic.requestID, MessageID: diagnostic.messageID,
		Event: event, ObservationID: connectionID, Route: "relay-events",
	}); err != nil {
		machinePQDiagnosticFailures.Add(1)
	}
}
