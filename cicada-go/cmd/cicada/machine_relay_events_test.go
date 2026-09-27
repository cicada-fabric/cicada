package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMachineRelayEventStreamUsesOutboundNodeCredentialAndWakeHints(t *testing.T) {
	t.Setenv("CICADA_NODE_TOKEN", "node-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v2/relay/nodes/node-b/events" ||
			request.Header.Get("Authorization") != "CicadaNode node-test-token" {
			t.Errorf("unexpected event stream request: %s %s auth=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
			http.Error(response, "invalid request", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = response.Write([]byte("event: ready\ndata: claim\n\nevent: wake\ndata: claim\n\n"))
	}))
	defer server.Close()
	wake := make(chan struct{}, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connected, err := streamMachineRelayEvents(ctx, server.URL, "node-b", wake)
	if err != nil || !connected {
		t.Fatalf("stream connected=%v err=%v", connected, err)
	}
	if len(wake) != 2 {
		t.Fatalf("expected ready reconciliation and immediate wake; got %d hints", len(wake))
	}
}

func TestMachineRelayEventStreamReportsRevokedNodeAuthorization(t *testing.T) {
	t.Setenv("CICADA_NODE_TOKEN", "node-revoked-token")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	revoked := make(chan error, 1)
	go runMachineRelayEventStream(ctx, server.URL, "node-b", make(chan struct{}, 1), revoked)
	select {
	case err := <-revoked:
		if !machineAPIHasStatus(err, http.StatusUnauthorized) {
			t.Fatalf("revocation cause=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("event stream did not stop on revoked Node authorization")
	}
}
