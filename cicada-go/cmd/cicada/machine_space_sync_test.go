package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestGroupSpaceFirstSyncRejectsForeignHubWatermark(t *testing.T) {
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/fabric/node/spaces/sync" || r.Header.Get("Authorization") != "CicadaNode node-token" {
			t.Errorf("unexpected Group Space sync request: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(store.GroupSpaceSyncResult{HubID: "foreign-hub", NetworkID: "net-a",
			GroupID: "group-a", BindingEpoch: 1, WatermarkVersion: "commit_v1", NextSeq: 1, LatestSeq: 1})
	}))
	defer hub.Close()
	stateDir := t.TempDir()
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "pinned-hub", Origin: hub.URL,
		NodeID: "node-a", StateDir: stateDir, Token: "node-token"})
	bridge := &machineAgentJoinBridge{ctx: ctx, stateDir: stateDir, baseURL: hub.URL,
		nodeID: "node-a", nodeToken: "node-token"}
	request := groupSpaceLocalRequest{localSealedSendRequest: localSealedSendRequest{
		GroupID: "group-a", SessionToken: "session-a", BindingEpoch: 1}}
	actor := store.GroupSpaceEndpointEvidence{EndpointID: "endpoint-a"}
	if err := bridge.rememberGroupSpaceSubscription(request, actor, &store.GroupSpaceSyncResult{
		GroupID: "group-a", HubID: "foreign-hub", NetworkID: "net-a", BindingEpoch: 1,
		WatermarkVersion: "commit_v1", NextSeq: 1, LatestSeq: 1}); err == nil {
		t.Fatal("first sync accepted another Hub's watermark")
	}
	if err := bridge.rememberGroupSpaceSubscription(request, actor, nil); err != nil {
		t.Fatal(err)
	}
	if err := bridge.reconcileGroupSpaces(); err == nil {
		t.Fatal("background reconciliation accepted foreign Hub cursor")
	}
	watches, err := bridge.loadSpaceSubscriptions()
	if err != nil || len(watches.Items) != 1 || watches.Items[0].FetchedSeq != 0 {
		t.Fatalf("foreign Hub response advanced private cursor: %#v %v", watches, err)
	}
}
