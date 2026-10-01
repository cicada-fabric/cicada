package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

// This is a process-fault protocol test, not a claim of native Codex support.
// The adapter may fail after accepting a request but before returning success.
func TestNativeProcessFailureAfterStartIsUncertainAndNeverReinjected(t *testing.T) {
	root := t.TempDir()
	counter := filepath.Join(root, "injected")
	binary := filepath.Join(root, "queue")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf x >> "+counter+"\nexit 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", binary)
	t.Setenv("CICADA_NODE_TOKEN", "cicada_node_test-fault")
	delivery := fabric.Delivery{MessageID: "msg-fault", RequestID: "rq-fault", Kind: "ask", Digest: "digest-fault", EndpointID: "ep-b", GroupID: "group-b", BindingID: "bind-b", BindingEpoch: 1, NativeSessionID: "native-b", Harness: "codex", NodeID: "b", AttemptID: "attempt-b", Body: "synthetic operation"}
	var layers []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/node/identity" {
			if r.Header.Get("Authorization") != "" {
				t.Errorf("public Hub identity included Authorization")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"hub_id": "hub-fault"})
			return
		}
		if r.URL.Path == "/v2/fabric/node/networks/direct/claim" {
			if r.Header.Get("Authorization") != "CicadaNode cicada_node_test-fault" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"deliveries": []fabric.NetworkDirectDelivery{}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/sealed/claim") {
			_ = json.NewEncoder(w).Encode(map[string]any{"deliveries": []fabric.NodeSealedDelivery{}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/claim") {
			_ = json.NewEncoder(w).Encode(map[string]any{"deliveries": []fabric.Delivery{delivery}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/authorization") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node_id": delivery.NodeID, "message_id": delivery.MessageID,
				"attempt_id": delivery.AttemptID, "digest": delivery.Digest,
				"endpoint_id": delivery.EndpointID, "principal_id": "principal-fault",
				"harness": delivery.Harness, "binding_id": delivery.BindingID,
				"binding_epoch": delivery.BindingEpoch, "native_session_id": delivery.NativeSessionID,
				"lease_owner": "lease-fault", "group_id": delivery.GroupID,
				"native_context_scope": map[string]any{"hub_id": "hub-fault", "group_id": delivery.GroupID},
			})
			return
		}
		var receipt fabric.NodeReceiptInput
		if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
			t.Error(err)
		}
		layers = append(layers, receipt.Layer)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer remote.Close()
	for attempt := 0; attempt < 2; attempt++ {
		inbox, err := nodeinbox.Open(machineNodeInboxPath(root, "b"))
		if err != nil {
			t.Fatal(err)
		}
		if err := processPinnedTestMachineFabricDeliveries(context.Background(), remote.URL, "b", inbox, root); err != nil {
			inbox.Close()
			t.Fatal(err)
		}
		stored, err := inbox.Get(context.Background(), delivery.MessageID)
		if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN {
			t.Fatalf("state=%v error=%v", stored, err)
		}
		inbox.Close()
	}
	data, err := os.ReadFile(counter)
	if err != nil || string(data) != "x" {
		t.Fatalf("injection attempts=%q error=%v", data, err)
	}
	if strings.Join(layers, ",") != "NODE_RECEIVED,INJECTION_UNCERTAIN" {
		t.Fatalf("layers=%v", layers)
	}
}
