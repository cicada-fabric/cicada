package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestTaskPeerPrivacyPlaintextMCPDeniedBeforeTransport(t *testing.T) {
	var calls atomic.Int64
	hub := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer hub.Close()
	m := &mcpServer{baseURL: hub.URL, sessionToken: "synthetic-private-session"}
	result, err := m.callTool("cicada_task_submit", map[string]any{
		"task_id": "synthetic-task", "owner_epoch": 1, "expected_revision": 2,
		"summary": "synthetic private result", "evidence": []any{"synthetic-evidence"},
	})
	if !errors.Is(err, store.ErrSharedTaskPeerPlaintext) || result != nil || calls.Load() != 0 {
		t.Fatalf("plaintext submit crossed transport: result=%v err=%v calls=%d", result, err, calls.Load())
	}
}
