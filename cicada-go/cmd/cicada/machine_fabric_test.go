package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func TestMachineRelayV2PersistsBeforeExactInjectionAndDedupes(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_NODE_TOKEN", "cicada_node_test-v2")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	arguments := filepath.Join(root, "arguments")
	binary := filepath.Join(root, "codex")
	script := "#!/bin/sh\nif [ -n \"$CICADA_API_TOKEN\" ] || [ -n \"$CICADA_NODE_TOKEN\" ]; then exit 9; fi\nprintf '%s\\n' \"$@\" >> " + arguments + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", binary)
	t.Setenv("CICADA_API_TOKEN", "must-not-reach-codex")
	inbox, err := nodeinbox.Open(machineNodeInboxPath(root, "node-v2"))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	delivery := fabric.Delivery{
		MessageID: "msg-v2", RequestID: "rq-v2", Kind: "ask", Digest: "digest-v2",
		SenderEndpointID: "ep-origin",
		EndpointID:       "ep-v2", GroupID: "group-v2", BindingID: "binding-v2",
		BindingEpoch: 3, Harness: "codex", NativeSessionID: "native-exact-v2",
		NodeID: "node-v2", AttemptID: "remote-attempt-v2", Body: "bounded v2 body",
	}
	var layers []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/identity" {
			if got := request.Header.Get("Authorization"); got != "" {
				t.Errorf("public Node-Control Hub identity authorization=%q", got)
			}
			_ = json.NewEncoder(response).Encode(map[string]string{"hub_id": "hub-node-v2"})
			return
		}
		if got := request.Header.Get("Authorization"); got != "CicadaNode cicada_node_test-v2" {
			t.Errorf("relay authorization = %q", got)
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/sealed/claim"):
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.NodeSealedDelivery{}})
		case strings.HasSuffix(request.URL.Path, "/claim"):
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.Delivery{delivery}})
		case strings.HasSuffix(request.URL.Path, "/authorization"):
			_ = json.NewEncoder(response).Encode(map[string]any{
				"node_id": delivery.NodeID, "message_id": delivery.MessageID,
				"attempt_id": delivery.AttemptID, "digest": delivery.Digest,
				"endpoint_id": delivery.EndpointID, "principal_id": "principal-v2",
				"harness": delivery.Harness, "binding_id": delivery.BindingID,
				"binding_epoch": delivery.BindingEpoch, "native_session_id": delivery.NativeSessionID,
				"lease_owner": "lease-v2", "group_id": delivery.GroupID,
				"native_context_scope": map[string]any{"hub_id": "hub-node-v2", "group_id": delivery.GroupID},
			})
		case strings.HasSuffix(request.URL.Path, "/receipts"):
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode receipt: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			layers = append(layers, input.Layer)
			_ = json.NewEncoder(response).Encode(map[string]any{"status": input.Layer})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	if err := processPinnedTestMachineFabricDeliveries(context.Background(), server.URL, "node-v2", inbox, root); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(data)
	for _, expected := range []string{"queue\n", "--thread\n", "native-exact-v2\n", "--message\n", `"body":"bounded v2 body"`, `"request_id":"rq-v2"`, `"sender_endpoint_id":"ep-origin"`} {
		if !strings.Contains(argv, expected) {
			t.Fatalf("missing %q in argv %q", expected, argv)
		}
	}
	if got := strings.Count(argv, "queue\n"); got != 1 {
		t.Fatalf("native queue count after first delivery = %d, want 1", got)
	}
	if strings.Join(layers, ",") != "NODE_RECEIVED,CODEX_QUEUE_ACCEPTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("receipt order = %v", layers)
	}

	// The relay may hand the same immutable message to a later attempt. The
	// SQLite message identity prevents a second native injection.
	if err := processPinnedTestMachineFabricDeliveries(context.Background(), server.URL, "node-v2", inbox, root); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "queue\n"); got != 1 {
		t.Fatalf("native queue count after duplicate = %d, want 1", got)
	}
}

func TestMachineRelayTemporaryNativeAuthorizationOutageKeepsDeliveryClaimable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_TOKEN", "cicada_node_test-auth-outage")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	delivery := fabric.Delivery{MessageID: "msg-auth-outage", RequestID: "rq-auth-outage",
		Kind: "ask", Digest: "digest-auth-outage", SenderEndpointID: "ep-origin",
		EndpointID: "ep-auth-outage", GroupID: "group-auth-outage", BindingID: "binding-auth-outage",
		BindingEpoch: 7, Harness: "codex", NativeSessionID: "native-auth-outage",
		NodeID: "node-auth-outage", AttemptID: "attempt-auth-outage", Body: "synthetic retryable message"}
	var receipts []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/identity" {
			if request.Header.Get("Authorization") != "" {
				t.Errorf("public Hub key identity unexpectedly required a Node credential")
			}
			_ = json.NewEncoder(response).Encode(map[string]string{"hub_id": "hub-auth-outage"})
			return
		}
		if got := request.Header.Get("Authorization"); got != "CicadaNode cicada_node_test-auth-outage" {
			t.Errorf("peer Relay request %s authorization=%q", request.URL.Path, got)
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/sealed/claim"),
			strings.HasSuffix(request.URL.Path, "/group/sealed/claim"),
			request.URL.Path == "/v2/fabric/node/networks/direct/claim":
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []any{}})
		case strings.HasSuffix(request.URL.Path, "/claim"):
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.Delivery{delivery}})
		case strings.HasSuffix(request.URL.Path, "/authorization"):
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write([]byte(`{"error":"temporary authorization outage"}`))
		case strings.HasSuffix(request.URL.Path, "/receipts"):
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode peer receipt: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			receipts = append(receipts, input.Layer)
			response.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected peer Relay route: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(root, "node-auth-outage"))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if err := processPinnedTestMachineFabricDeliveries(context.Background(), server.URL,
		"node-auth-outage", inbox, root); err != nil {
		t.Fatalf("temporary native authorization outage terminated peer reconciliation: %v", err)
	}
	stored, err := inbox.Get(context.Background(), delivery.MessageID)
	if err != nil || stored == nil || stored.State != nodeinbox.NODE_RECEIVED ||
		stored.AttemptID != "" || stored.ConsumerID != "" {
		t.Fatalf("temporary authority failure did not release only the pre-injection claim: delivery=%#v err=%v",
			stored, err)
	}
	if strings.Join(receipts, ",") != string(fabric.ReceiptNodeReceived) {
		t.Fatalf("temporary authority failure was misreported as a terminal receipt: %v", receipts)
	}
}

func TestMachineRelayRevokedNativeAuthorizationRejectsClaimBeforeInjection(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	queueMarker := filepath.Join(root, "queue-marker")
	queue := filepath.Join(root, "fake-codex")
	if err := os.WriteFile(queue, []byte("#!/bin/sh\nprintf invoked >> '"+queueMarker+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", queue)
	t.Setenv("CICADA_NODE_TOKEN", "cicada_node_test-revoked-wake")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	delivery := fabric.Delivery{MessageID: "msg-revoked-wake", RequestID: "rq-revoked-wake",
		Kind: "ask", Digest: "digest-revoked-wake", SenderEndpointID: "ep-origin",
		EndpointID: "ep-revoked-wake", GroupID: "group-revoked-wake", BindingID: "binding-revoked-wake",
		BindingEpoch: 4, Harness: "codex", NativeSessionID: "native-revoked-wake",
		NodeID: "node-revoked-wake", AttemptID: "remote-attempt-revoked-wake", Body: "synthetic revoked delivery"}
	var receipts []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/node/identity" {
			_ = json.NewEncoder(response).Encode(map[string]string{"hub_id": "hub-revoked-wake"})
			return
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/sealed/claim"),
			strings.HasSuffix(request.URL.Path, "/group/sealed/claim"),
			request.URL.Path == "/v2/fabric/node/networks/direct/claim":
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []any{}})
		case strings.HasSuffix(request.URL.Path, "/claim"):
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.Delivery{delivery}})
		case strings.HasSuffix(request.URL.Path, "/authorization"):
			if request.URL.Query().Get("attempt_id") != delivery.AttemptID {
				t.Errorf("native authorization used attempt_id=%q, want remote relay attempt %q",
					request.URL.Query().Get("attempt_id"), delivery.AttemptID)
			}
			response.WriteHeader(http.StatusNotFound)
			_, _ = response.Write([]byte(`{"error":"current native wake authorization unavailable"}`))
		case strings.HasSuffix(request.URL.Path, "/receipts"):
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode peer receipt: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			receipts = append(receipts, input.Layer)
			response.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected peer Relay route: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(root, delivery.NodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if err := processPinnedTestMachineFabricDeliveries(context.Background(), server.URL,
		delivery.NodeID, inbox, root); err != nil {
		t.Fatalf("definitive revoked native authorization terminated reconciliation: %v", err)
	}
	stored, err := inbox.Get(context.Background(), delivery.MessageID)
	if err != nil || stored == nil || stored.State != nodeinbox.FAILED {
		t.Fatalf("revoked authorization did not permanently reject the pre-injection claim: delivery=%#v err=%v",
			stored, err)
	}
	if _, err := os.Stat(queueMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native Codex queue ran despite revoked authorization: stat err=%v", err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,FAILED" {
		t.Fatalf("revoked authorization receipt sequence = %v, want NODE_RECEIVED then FAILED", receipts)
	}
}

func TestMachineRelayV2PlaintextPathRejectsSealedDelivery(t *testing.T) {
	root := t.TempDir()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(root, "node-sealed"))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	journal, err := openMachineRelayJournal(root, "node-sealed")
	if err != nil {
		t.Fatal(err)
	}
	delivery := fabric.Delivery{
		MessageID: "msg-sealed", Digest: "digest-sealed", EndpointID: "ep-sealed",
		NativeSessionID: "native-sealed", BindingEpoch: 1, PayloadMode: "SEALED_V1",
		Body: "must never become a native prompt",
	}
	if err := acceptMachineRelayDelivery(context.Background(), "", "node-sealed", inbox, journal, delivery); err == nil || !strings.Contains(err.Error(), "unsupported payload mode") {
		t.Fatalf("sealed delivery must be rejected by plaintext Node path: %v", err)
	}
	if _, err := inbox.Get(context.Background(), delivery.MessageID); !errors.Is(err, nodeinbox.ErrNotFound) {
		t.Fatalf("sealed delivery entered plaintext inbox: %v", err)
	}
	if journal.entry(delivery.MessageID) != nil {
		t.Fatal("sealed delivery entered plaintext recovery journal")
	}
}

func TestMachineRelayV2ReportsRecoveredInjectionUncertain(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_NODE_TOKEN", "cicada_node_test-uncertain")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	inboxPath := machineNodeInboxPath(root, "node-uncertain")
	first, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	delivery := fabric.Delivery{
		MessageID: "msg-uncertain", Digest: "digest-uncertain", EndpointID: "ep-uncertain",
		BindingID: "binding-uncertain", BindingEpoch: 4, Harness: "codex",
		NativeSessionID: "native-uncertain", NodeID: "node-uncertain",
		AttemptID: "remote-attempt-uncertain", Body: "do not retry blindly",
	}
	if _, _, err := first.Save(context.Background(), nodeinbox.Message{
		MessageID: delivery.MessageID, Digest: delivery.Digest, EndpointID: delivery.EndpointID,
		SessionID: delivery.NativeSessionID, BindingEpoch: delivery.BindingEpoch,
		Payload: []byte(delivery.Body),
	}); err != nil {
		t.Fatal(err)
	}
	claim, err := first.Claim(context.Background(), machineRelayConsumerID("node-uncertain"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.BeginInjection(context.Background(), claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	journal, err := openMachineRelayJournal(root, "node-uncertain")
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.put(delivery); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	var layers []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/sealed/claim") {
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.NodeSealedDelivery{}})
			return
		}
		if strings.HasSuffix(request.URL.Path, "/claim") {
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.Delivery{}})
			return
		}
		if strings.HasSuffix(request.URL.Path, "/receipts") {
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode receipt: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			layers = append(layers, input.Layer)
			_ = json.NewEncoder(response).Encode(map[string]any{"status": input.Layer})
			return
		}
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	if err := processPinnedTestMachineFabricDeliveries(context.Background(), server.URL, "node-uncertain", second, root); err != nil {
		t.Fatal(err)
	}
	if strings.Join(layers, ",") != "NODE_RECEIVED,INJECTION_UNCERTAIN" {
		t.Fatalf("recovery receipt order = %v", layers)
	}
	stored, err := second.Get(context.Background(), delivery.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != nodeinbox.INJECTION_UNCERTAIN {
		t.Fatalf("recovered state = %s, want %s", stored.State, nodeinbox.INJECTION_UNCERTAIN)
	}
}
