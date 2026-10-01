package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMachineSealedAskReconnectClaimsDurableOfflineMessage crosses the real
// TLS/SSE Node reconnect loop with the production sealed claim/decrypt/inbox
// path. The Hub has only the Fabric handler and an ephemeral SQLite Store.
// Codex queue is a fake executable, so queue acceptance is the last runtime
// evidence here; this test does not claim a real Runtime wake or model consume.
func TestMachineSealedAskReconnectClaimsDurableOfflineMessage(t *testing.T) {
	fixture := newMachineSealedReceiveFixtureWithActions(t, false, "ask", []string{"ask", "reply"})
	hubID, err := fixture.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	// This direct Agent harness uses the configured Hub identity when it
	// checks the fixture's authoritative native-context projection.
	t.Setenv("CICADA_HUB_ID", hubID)
	const privateText = "private message for the original session"
	if bytes.Contains(fixture.ciphertext, []byte(privateText)) {
		t.Fatal("synthetic endpoint envelope unexpectedly contains its plaintext")
	}

	queueArgsPath, queueCountPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()

	// Build a Fabric-only Hub below, then install its certificate as the trust
	// root for runMachineRelayEventStream and machineAPIJSON.
	var callsMu sync.Mutex
	var calls []*sealedReconnectHTTPCall
	var unexpectedPaths []string
	var hubSawPlaintext bool
	var streamArrivals = make(chan sealedReconnectStreamArrival, 8)
	var streamDepartures = make(chan struct{}, 8)
	targetPrefix := "/v2/relay/nodes/" + fixture.targetNodeID
	sourcePrefix := "/v2/relay/nodes/" + fixture.sourceNodeID
	allowedPath := func(method, path string) bool {
		switch {
		case method == http.MethodPost && path == sourcePrefix+"/sealed/ask":
			return true
		case method == http.MethodGet && path == targetPrefix+"/events":
			return true
		case method == http.MethodPost && path == targetPrefix+"/sealed/claim":
			return true
		case method == http.MethodPost && path == targetPrefix+"/group/sealed/claim":
			return true
		case method == http.MethodPost && path == targetPrefix+"/claim":
			return true
		case method == http.MethodPost && path == "/v2/fabric/node/networks/direct/claim":
			return true
		case method == http.MethodGet && path == targetPrefix+"/sealed/"+fixture.messageID+"/authorization":
			return true
		case method == http.MethodPost && path == targetPrefix+"/receipts":
			return true
		default:
			return false
		}
	}
	fabricHandler := serverpkg.NewFabricHandler(fixture.service, "")
	hub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024+1))
		_ = r.Body.Close()
		if readErr != nil || len(body) > 2*1024*1024 {
			http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		call := &sealedReconnectHTTPCall{
			Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr,
			TLS: r.TLS != nil, RequestBody: append([]byte(nil), body...),
		}
		callsMu.Lock()
		if !allowedPath(r.Method, r.URL.Path) {
			unexpectedPaths = append(unexpectedPaths, r.Method+" "+r.URL.Path)
		}
		if bytes.Contains(body, []byte(privateText)) {
			hubSawPlaintext = true
		}
		calls = append(calls, call)
		callsMu.Unlock()

		if r.URL.Path == targetPrefix+"/events" {
			select {
			case streamArrivals <- sealedReconnectStreamArrival{RemoteAddr: r.RemoteAddr, TLS: r.TLS != nil}:
			default:
			}
			defer func() {
				callsMu.Lock()
				if bytes.Contains(call.ResponseBody, []byte(privateText)) {
					hubSawPlaintext = true
				}
				callsMu.Unlock()
				select {
				case streamDepartures <- struct{}{}:
				default:
				}
			}()
		}

		observedWriter := &sealedReconnectCaptureWriter{ResponseWriter: w}
		fabricHandler.ServeHTTP(observedWriter, r)
		callsMu.Lock()
		call.Status = observedWriter.status
		call.ResponseBody = append([]byte(nil), observedWriter.body.Bytes()...)
		if bytes.Contains(call.ResponseBody, []byte(privateText)) {
			hubSawPlaintext = true
		}
		callsMu.Unlock()
	}))
	defer hub.Close()
	roots := x509.NewCertPool()
	roots.AddCert(hub.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	originalTransport := http.DefaultTransport
	observedTransport := &sealedReconnectObservingTransport{base: transport}
	http.DefaultTransport = observedTransport
	defer func() {
		transport.CloseIdleConnections()
		http.DefaultTransport = originalTransport
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	wake := make(chan struct{}, 8)
	revoked := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMachineRelayEventStream(ctx, hub.URL, fixture.targetNodeID, wake, revoked)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("production Node SSE reconnect loop did not stop after cancellation")
		}
	}()

	waitForWake := func(label string) {
		t.Helper()
		select {
		case <-wake:
		case err := <-revoked:
			t.Fatalf("Node SSE authorization was revoked while waiting for %s: %v", label, err)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", label)
		}
	}
	waitForArrival := func(label string) sealedReconnectStreamArrival {
		t.Helper()
		select {
		case arrival := <-streamArrivals:
			return arrival
		case err := <-revoked:
			t.Fatalf("Node SSE authorization was revoked while waiting for %s: %v", label, err)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", label)
		}
		return sealedReconnectStreamArrival{}
	}
	waitForDeparture := func(label string) {
		t.Helper()
		select {
		case <-streamDepartures:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", label)
		}
	}

	firstStream := waitForArrival("initial B TLS/SSE connection")
	if !firstStream.TLS || firstStream.RemoteAddr == "" {
		t.Fatalf("initial event stream was not an observed TLS/TCP connection: tls=%t remote_addr_present=%t",
			firstStream.TLS, firstStream.RemoteAddr != "")
	}
	waitForWake("initial ready reconciliation")
	if err := processPinnedTestMachineFabricDeliveries(ctx, hub.URL, fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("initial empty sealed claim reconciliation: %v", err)
	}
	if _, err := os.Stat(queueCountPath); !os.IsNotExist(err) {
		t.Fatalf("fake Codex queue ran before an ASK existed: stat err=%v", err)
	}

	// Close the live TCP/TLS stream, then submit from A while B is offline.
	// There is no Node listener or Hub callback route in this fixture.
	hub.CloseClientConnections()
	waitForDeparture("forced SSE/TCP disconnect")

	askInput := fabric.NodeSealedLinkAskInput{
		LinkID: fixture.link.ID, MessageID: fixture.messageID, RequestID: fixture.requestID,
		IdempotencyKey: "synthetic-v71-offline-link-ask",
		DataScope:      fixture.dataScope, ExpiresAt: fixture.link.ExpiresAt,
		Ciphertext: fixture.ciphertext,
	}
	postSealedAsk := func() map[string]any {
		t.Helper()
		body, err := json.Marshal(askInput)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			hub.URL+sourcePrefix+"/sealed/ask", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "CicadaNode "+fixture.sourceToken)
		request.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Transport: transport, CheckRedirect: rejectNodeRedirect}).Do(request)
		if err != nil {
			t.Fatalf("source Node sealed ASK over TLS: %v", err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			t.Fatalf("read sealed ASK response: %v", err)
		}
		if response.StatusCode != http.StatusAccepted {
			t.Fatalf("Hub did not accept sealed ASK: status=%d", response.StatusCode)
		}
		var accepted map[string]any
		if err := json.Unmarshal(responseBody, &accepted); err != nil {
			t.Fatalf("decode sealed ASK acceptance: %v", err)
		}
		return accepted
	}
	accepted := postSealedAsk()
	if accepted["message_id"] != fixture.messageID || accepted["request_id"] != fixture.requestID ||
		accepted["payload_mode"] != store.RelayPayloadModeSealedV1 {
		t.Fatalf("Hub acceptance lost sealed ASK identity or payload mode: expected_message=%s expected_request=%s mode=%v",
			fixture.messageID, fixture.requestID, accepted["payload_mode"])
	}
	requestState, err := fixture.service.NodeSealedLinkRequestStatus(fixture.sourceToken, fixture.requestID)
	if err != nil || requestState == nil || requestState.State != store.FabricRequestOpen ||
		requestState.MessageID != fixture.messageID || requestState.ReceiverEndpointID != fixture.targetEndpoint {
		t.Fatalf("offline ASK was not durably open for the original B Endpoint: expected_message=%s target=%s err=%v",
			fixture.messageID, fixture.targetEndpoint, err)
	}
	stored, err := fixture.store.GetRelaySealedV1(fixture.messageID)
	if err != nil || stored == nil || stored.PayloadMode != store.RelayPayloadModeSealedV1 ||
		stored.Route.Kind != "ask" || stored.Route.RequestID != fixture.requestID ||
		stored.Route.ReceiverEndpointID != fixture.targetEndpoint || !bytes.Equal(stored.Ciphertext, fixture.ciphertext) ||
		bytes.Contains(stored.Ciphertext, []byte(privateText)) {
		mode, kind, messageID, requestID, receiverEndpointID, ciphertextMatches := "", "", "", "", "", false
		if stored != nil {
			mode, kind, messageID, requestID, receiverEndpointID = stored.PayloadMode, stored.Route.Kind,
				stored.Route.MessageID, stored.Route.RequestID, stored.Route.ReceiverEndpointID
			ciphertextMatches = bytes.Equal(stored.Ciphertext, fixture.ciphertext)
		}
		t.Fatalf("Hub did not persist the opaque ASK envelope and exact route: mode=%s route=%s message=%s request=%s receiver=%s ciphertext_matches=%t err=%v",
			mode, kind, messageID, requestID, receiverEndpointID, ciphertextMatches, err)
	}
	acceptedReceipts, err := fixture.store.ListRelayReceipts(fixture.messageID, 20)
	if err != nil || len(acceptedReceipts) != 1 || acceptedReceipts[0].Layer != fabric.ReceiptRelayAccepted {
		t.Fatalf("offline Hub acceptance lacks exactly one durable RELAY_ACCEPTED receipt: count=%d err=%v", len(acceptedReceipts), err)
	}
	if _, err := os.Stat(queueCountPath); !os.IsNotExist(err) {
		t.Fatalf("offline B was queued before reconnect: stat err=%v", err)
	}

	secondStream := waitForArrival("Node-initiated SSE reconnect")
	if !secondStream.TLS || secondStream.RemoteAddr == "" || secondStream.RemoteAddr == firstStream.RemoteAddr {
		t.Fatalf("B did not establish a new outbound TLS/TCP stream after disconnect: tls=%t remote_addr_changed=%t",
			secondStream.TLS, secondStream.RemoteAddr != firstStream.RemoteAddr)
	}
	if _, err := os.Stat(queueCountPath); !os.IsNotExist(err) {
		t.Fatalf("offline ASK reached fake Codex before reconnect ready reconciliation: stat err=%v", err)
	}
	waitForWake("ready reconciliation wake after reconnect")
	if err := processPinnedTestMachineFabricDeliveries(ctx, hub.URL, fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("claim/decrypt/queue sealed ASK after reconnect wake: %v", err)
	}
	queueCount, err := os.ReadFile(queueCountPath)
	if err != nil || string(queueCount) != "x" {
		t.Fatalf("sealed ASK did not reach fake Codex exactly once: count=%q err=%v", queueCount, err)
	}
	queueArgs, err := os.ReadFile(queueArgsPath)
	if err != nil {
		t.Fatalf("read fake Codex argv: %v", err)
	}
	argv := strings.Split(strings.TrimSuffix(string(queueArgs), "\n"), "\n")
	expectedNativeID := "native_" + fixture.targetEndpoint
	queuedPrompt := ""
	if len(argv) > 4 {
		queuedPrompt = strings.Join(argv[4:], "\n")
	}
	if len(argv) < 5 || argv[0] != "queue" || argv[1] != "--thread" || argv[2] != expectedNativeID || argv[3] != "--message" ||
		!strings.Contains(queuedPrompt, fixture.requestID) || !strings.Contains(queuedPrompt, fixture.messageID) ||
		!strings.Contains(queuedPrompt, privateText) {
		t.Fatalf("sealed ASK queue arguments did not match the original native target or decrypted message: exact_thread=%t request_id_present=%t message_id_present=%t plaintext_present=%t",
			len(argv) > 2 && argv[2] == expectedNativeID,
			strings.Contains(queuedPrompt, fixture.requestID), strings.Contains(queuedPrompt, fixture.messageID),
			strings.Contains(queuedPrompt, privateText))
	}
	if bytes.Contains(queueArgs, fixture.ciphertext) {
		t.Fatal("fake Codex queue received the Hub ciphertext instead of the verified plaintext body")
	}

	// A sender retry uses the same immutable Link ASK identity. The Hub emits a
	// real wake over B's still-open SSE stream; Node reconciliation must not
	// create a second injection after the first queue acceptance.
	duplicateAccepted := postSealedAsk()
	if duplicateAccepted["message_id"] != fixture.messageID || duplicateAccepted["request_id"] != fixture.requestID {
		t.Fatalf("idempotent offline ASK retry changed identity: %#v", duplicateAccepted)
	}
	waitForWake("duplicate idempotent ASK wake")
	if err := processPinnedTestMachineFabricDeliveries(ctx, hub.URL, fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("process duplicate sealed ASK wake: %v", err)
	}
	queueCount, err = os.ReadFile(queueCountPath)
	if err != nil || string(queueCount) != "x" {
		t.Fatalf("duplicate SSE wake caused a second fake Codex queue: count=%q err=%v", queueCount, err)
	}

	requestState, err = fixture.service.NodeSealedLinkRequestStatus(fixture.sourceToken, fixture.requestID)
	if err != nil || requestState == nil || requestState.State != store.FabricRequestOpen {
		t.Fatalf("Node queue acceptance was incorrectly promoted to a peer reply/result: request_id=%s err=%v",
			fixture.requestID, err)
	}
	receipts, err := fixture.store.ListRelayReceipts(fixture.messageID, 20)
	if err != nil {
		t.Fatal(err)
	}
	claimedAttemptID := ""
	var receiptLayers = map[string]int{}
	for _, receipt := range receipts {
		receiptLayers[receipt.Layer]++
		if receipt.Layer == fabric.ReceiptNodeReceived || receipt.Layer == fabric.ReceiptCodexQueueAccepted ||
			receipt.Layer == fabric.ReceiptConsumptionUncertain {
			if receipt.AttemptID == "" {
				t.Fatalf("Node receipt %s lacks a delivery attempt identity", receipt.Layer)
			}
			if claimedAttemptID == "" {
				claimedAttemptID = receipt.AttemptID
			} else if receipt.AttemptID != claimedAttemptID {
				t.Fatalf("Node receipt layers crossed delivery attempts: first=%s receipt=%#v", claimedAttemptID, receipt)
			}
		}
	}
	for _, layer := range []string{fabric.ReceiptRelayAccepted, fabric.ReceiptNodeReceived,
		fabric.ReceiptCodexQueueAccepted, fabric.ReceiptConsumptionUncertain} {
		if receiptLayers[layer] != 1 {
			t.Fatalf("expected exactly one %s receipt, got layers=%v", layer, receiptLayers)
		}
	}
	if claimedAttemptID == "" || receiptLayers[fabric.ReceiptRuntimeInjected] != 0 ||
		receiptLayers[fabric.ReceiptApplicationAcked] != 0 || receiptLayers[fabric.ReceiptResultAccepted] != 0 {
		t.Fatalf("receipt evidence overstates delivery or omits the current attempt: attempt=%q layers=%v", claimedAttemptID, receiptLayers)
	}

	callsMu.Lock()
	if len(unexpectedPaths) != 0 {
		paths := append([]string(nil), unexpectedPaths...)
		callsMu.Unlock()
		t.Fatalf("Fabric-only Hub saw a Control/business or unexpected route: %v", paths)
	}
	if hubSawPlaintext {
		callsMu.Unlock()
		t.Fatal("Hub HTTP request/response observed sealed peer plaintext")
	}
	allCalls := append([]*sealedReconnectHTTPCall(nil), calls...)
	callsMu.Unlock()
	eventStreams := 0
	seenAttemptIDs := make(map[string]struct{})
	var receiptPosts []fabric.NodeReceiptInput
	var claimedDeliveries []fabric.NodeSealedDelivery
	for _, call := range allCalls {
		if !call.TLS {
			t.Fatalf("Hub route was not reached over TLS: %s %s", call.Method, call.Path)
		}
		if bytes.Contains(call.RequestBody, []byte(privateText)) || bytes.Contains(call.ResponseBody, []byte(privateText)) {
			t.Fatalf("Hub observed peer plaintext on %s %s", call.Method, call.Path)
		}
		if call.Path == targetPrefix+"/events" {
			eventStreams++
			if call.Method != http.MethodGet || call.RemoteAddr == "" {
				t.Fatalf("unexpected Node SSE network event: method=%s path=%s tls=%t remote_addr_present=%t",
					call.Method, call.Path, call.TLS, call.RemoteAddr != "")
			}
		}
		if call.Method == http.MethodPost && call.Path == targetPrefix+"/sealed/claim" && len(call.ResponseBody) > 0 {
			var payload struct {
				Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
			}
			if err := json.Unmarshal(call.ResponseBody, &payload); err != nil {
				t.Fatalf("decode captured sealed claim result: %v", err)
			}
			for _, delivery := range payload.Deliveries {
				claimedDeliveries = append(claimedDeliveries, delivery)
				seenAttemptIDs[delivery.AttemptID] = struct{}{}
			}
		}
		if call.Method == http.MethodPost && call.Path == targetPrefix+"/receipts" {
			var input fabric.NodeReceiptInput
			if err := json.Unmarshal(call.RequestBody, &input); err != nil {
				t.Fatalf("decode captured Node receipt request: %v", err)
			}
			receiptPosts = append(receiptPosts, input)
		}
	}
	if eventStreams != 2 {
		t.Fatalf("expected one initial SSE TCP connection and one reconnect, got %d", eventStreams)
	}
	streamResponses := observedTransport.snapshots()
	if len(streamResponses) != 2 {
		t.Fatalf("production SSE client observed %d HTTP event stream responses, expected initial connect and reconnect", len(streamResponses))
	}
	for index, response := range streamResponses {
		streamBody := response.bodyBytes()
		if response.Status != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.ContentType), "text/event-stream") ||
			!bytes.Contains(streamBody, []byte("event: ready\ndata: claim\n\n")) {
			t.Fatalf("Node SSE stream %d did not receive the Hub's actual ready event over HTTP: status=%d content_type=%q ready_present=%t bytes=%d",
				index+1, response.Status, response.ContentType,
				bytes.Contains(streamBody, []byte("event: ready\ndata: claim\n\n")), len(streamBody))
		}
		if bytes.Contains(streamBody, []byte(privateText)) {
			t.Fatalf("Hub exposed peer plaintext in Node SSE response %d", index+1)
		}
	}
	if len(claimedDeliveries) != 1 || len(seenAttemptIDs) != 1 || claimedDeliveries[0].AttemptID != claimedAttemptID ||
		claimedDeliveries[0].MessageID != fixture.messageID || claimedDeliveries[0].Route.RequestID != fixture.requestID ||
		claimedDeliveries[0].PayloadMode != store.RelayPayloadModeSealedV1 ||
		claimedDeliveries[0].NativeSessionID != expectedNativeID || claimedDeliveries[0].NodeID != fixture.targetNodeID {
		t.Fatalf("captured Node claim did not preserve one current sealed attempt and original native target: deliveries=%d attempt=%s message=%s native=%s receipts=%d",
			len(claimedDeliveries), claimedAttemptID, fixture.messageID, expectedNativeID, len(receiptPosts))
	}
	if len(receiptPosts) != 3 {
		t.Fatalf("expected one network receipt post for each Node acceptance layer, got %#v", receiptPosts)
	}
	postedLayers := map[string]int{}
	for _, receipt := range receiptPosts {
		postedLayers[receipt.Layer]++
		if receipt.AttemptID != claimedAttemptID || receipt.MessageID != fixture.messageID ||
			receipt.EndpointID != fixture.targetEndpoint {
			t.Fatalf("network receipt does not bind to the claimed attempt and target: %#v", receipt)
		}
	}
	for _, layer := range []string{fabric.ReceiptNodeReceived, fabric.ReceiptCodexQueueAccepted, fabric.ReceiptConsumptionUncertain} {
		if postedLayers[layer] != 1 {
			t.Fatalf("missing exact network receipt layer %s: %v", layer, postedLayers)
		}
	}
	cancel()
	select {
	case <-streamDepartures:
	case <-time.After(3 * time.Second):
		t.Fatal("Node SSE stream did not close after test cancellation")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("production Node SSE reconnect loop did not stop after cancellation")
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(fixture.databasePath, privateText); err != nil {
		t.Fatalf("Hub SQLite/WAL contains sealed peer plaintext: %v", err)
	}
	t.Logf("TLS/SSE sealed offline ASK passed: one reconnect, one sealed attempt=%s, one fake queue to exact native ID; receipt layers=%v; model consumption remains unconfirmed",
		claimedAttemptID, receiptLayers)
}

type sealedReconnectStreamArrival struct {
	RemoteAddr string
	TLS        bool
}

type sealedReconnectHTTPCall struct {
	Method       string
	Path         string
	RemoteAddr   string
	TLS          bool
	Status       int
	RequestBody  []byte
	ResponseBody []byte
}

type sealedReconnectObservingTransport struct {
	base      http.RoundTripper
	mu        sync.Mutex
	responses []*sealedReconnectStreamResponse
}

type sealedReconnectStreamResponse struct {
	mu          sync.Mutex
	Status      int
	ContentType string
	body        bytes.Buffer
}

func (t *sealedReconnectObservingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/events") {
		return response, err
	}
	capture := &sealedReconnectStreamResponse{
		Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"),
	}
	t.mu.Lock()
	t.responses = append(t.responses, capture)
	t.mu.Unlock()
	response.Body = &sealedReconnectObservedBody{ReadCloser: response.Body, capture: capture}
	return response, nil
}

func (t *sealedReconnectObservingTransport) snapshots() []*sealedReconnectStreamResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*sealedReconnectStreamResponse(nil), t.responses...)
}

func (r *sealedReconnectStreamResponse) bodyBytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.body.Bytes()...)
}

type sealedReconnectObservedBody struct {
	io.ReadCloser
	capture *sealedReconnectStreamResponse
}

func (b *sealedReconnectObservedBody) Read(buffer []byte) (int, error) {
	n, err := b.ReadCloser.Read(buffer)
	if n > 0 {
		b.capture.mu.Lock()
		_, _ = b.capture.body.Write(buffer[:n])
		b.capture.mu.Unlock()
	}
	return n, err
}

type sealedReconnectCaptureWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *sealedReconnectCaptureWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *sealedReconnectCaptureWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	_, _ = w.body.Write(body)
	return w.ResponseWriter.Write(body)
}

func (w *sealedReconnectCaptureWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

var _ http.Flusher = (*sealedReconnectCaptureWriter)(nil)
