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
		if got := request.Header.Get("Authorization"); got != "CicadaNode cicada_node_test-v2" {
			t.Errorf("relay authorization = %q", got)
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/sealed/claim"):
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.NodeSealedDelivery{}})
		case strings.HasSuffix(request.URL.Path, "/claim"):
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": []fabric.Delivery{delivery}})
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

	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL, "node-v2", inbox, root); err != nil {
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
	if strings.Join(layers, ",") != "NODE_RECEIVED,RUNTIME_INJECTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("receipt order = %v", layers)
	}

	// The relay may hand the same immutable message to a later attempt. The
	// SQLite message identity prevents a second native injection.
	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL, "node-v2", inbox, root); err != nil {
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

	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL, "node-uncertain", second, root); err != nil {
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
