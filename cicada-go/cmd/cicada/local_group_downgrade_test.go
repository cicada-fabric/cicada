package main

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

type localGroupRecordingTransport struct {
	base         http.RoundTripper
	marker       string
	mu           sync.Mutex
	paths        []string
	sawPlaintext bool
}

func (transport *localGroupRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	var err error
	if request.Body != nil {
		body, err = io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	transport.mu.Lock()
	transport.paths = append(transport.paths, request.URL.Path)
	if bytes.Contains(body, []byte(transport.marker)) {
		transport.sawPlaintext = true
	}
	transport.mu.Unlock()
	forward := request.Clone(request.Context())
	forward.Body = io.NopCloser(bytes.NewReader(body))
	forward.ContentLength = int64(len(body))
	return transport.base.RoundTrip(forward)
}

func recordLocalGroupHubHTTP(t *testing.T, marker string) *localGroupRecordingTransport {
	t.Helper()
	originalTransport := http.DefaultTransport
	recorder := &localGroupRecordingTransport{base: originalTransport, marker: marker}
	http.DefaultTransport = recorder
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	return recorder
}

func TestMCPSealedSameNodeAskIgnoresClearedCachedCapability(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	const question = "private local failure-path question"

	// Simulate a stale or altered local status cache. The MCP path must use a
	// fresh session-authenticated WhoAmI and current same-Group target card
	// before it chooses any plaintext Relay route.
	f.sourceMCP.sessionMu.Lock()
	delete(f.sourceMCP.sessionPublic.Endpoint.Capabilities, "local_peer_delivery")
	delete(f.sourceMCP.sessionPublic.NetworkCard.Capabilities, "local_peer_delivery")
	f.sourceMCP.sessionMu.Unlock()

	recorder := recordLocalGroupHubHTTP(t, question)

	f.ask(t)

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sawPlaintext {
		t.Fatal("private ASK body crossed the Hub HTTP boundary")
	}
	for _, path := range recorder.paths {
		if path == "/v2/fabric/ask" {
			t.Fatal("MCP dispatched the ASK through the plaintext Relay endpoint")
		}
	}
	f.sourceMCP.sessionMu.RLock()
	principalID := f.sourceMCP.sessionPublic.NetworkCard.PrincipalID
	f.sourceMCP.sessionMu.RUnlock()
	requests, err := f.store.ListRelayRequests(store.RelayRequestFilter{
		SenderPrincipalID: principalID, SenderGroupID: f.groupID, Limit: 10,
	})
	if err != nil || len(requests) != 0 {
		t.Fatalf("cache-cleared local ASK created plaintext Relay state: count=%d err=%v", len(requests), err)
	}
}

func TestMCPSealedSameNodeAskFailsClosedOnFreshCapabilityDowngrade(t *testing.T) {
	f := newLocalGroupFailureFixture(t)
	const question = "private local downgrade question"
	f.sourceMCP.sessionMu.RLock()
	sourceEndpointID := f.sourceMCP.endpointID
	f.sourceMCP.sessionMu.RUnlock()
	endpoint, err := f.store.GetEndpointV2(sourceEndpointID)
	if err != nil || endpoint == nil {
		t.Fatalf("load current source Endpoint: %#v err=%v", endpoint, err)
	}
	delete(endpoint.Capabilities, "local_peer_delivery")
	if _, err := f.store.UpsertEndpoint(*endpoint); err != nil {
		t.Fatal(err)
	}
	recorder := recordLocalGroupHubHTTP(t, question)
	t.Setenv("CODEX_THREAD_ID", f.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+f.nativeA)
	result, err := f.sourceMCP.callTool("cicada_ask", map[string]any{
		"target": f.targetMCP.endpointID, "question": question,
	})
	if err != nil {
		t.Fatalf("fresh capability mismatch returned an unexpected MCP error: %v", err)
	}
	public, ok := result.(map[string]any)
	if !ok || public["status"] != mcpOutboxStatusFailed {
		t.Fatalf("fresh capability downgrade did not fail the operation closed: %#v", result)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sawPlaintext {
		t.Fatal("private ASK body crossed the Hub HTTP boundary after a capability mismatch")
	}
	for _, path := range recorder.paths {
		if path == "/v2/fabric/ask" {
			t.Fatal("MCP dispatched the mismatched-capability ASK through plaintext Relay")
		}
	}
	requests, err := f.store.ListRelayRequests(store.RelayRequestFilter{
		SenderGroupID: f.groupID, Limit: 10,
	})
	if err != nil || len(requests) != 0 {
		t.Fatalf("fresh capability downgrade created plaintext Relay state: count=%d err=%v", len(requests), err)
	}
}
