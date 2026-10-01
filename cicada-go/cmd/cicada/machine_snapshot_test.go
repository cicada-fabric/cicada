package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Snapshot transfers use the Node-Control stream only after an Owner-approved
// Hub/Node key binding is available. This boundary test ensures the old raw
// Worker snapshot routes cannot be reached without that private context.
func TestBoundNodeSnapshotRequiresOwnerApprovedNodeControlContext(t *testing.T) {
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()
	job := machineJob{WorkerID: "worker-a", Attempt: 1, WorkspaceID: "workspace-a",
		WorkspaceSnapshotDigest: strings.Repeat("a", 64)}
	workspace := filepath.Join(t.TempDir(), "workspace")

	if err := downloadBoundNodeSnapshot(context.Background(), api.URL, "node-a", "node-token", job, workspace); err == nil ||
		!strings.Contains(err.Error(), "current private Hub/Node context") {
		t.Fatalf("unpaired snapshot download error=%v", err)
	}
	if _, err := uploadBoundNodeSnapshot(context.Background(), api.URL, "node-a", "node-token", job, workspace); err == nil ||
		!strings.Contains(err.Error(), "current private Hub/Node context") {
		t.Fatalf("unpaired snapshot upload error=%v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("unpaired snapshot transfer made %d HTTP requests", requests.Load())
	}
}

func TestBoundNodeSnapshotDoesNotForwardCredentialOnRedirect(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		leaked.Store(request.Header.Get("Authorization") != "")
		response.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	var snapshotRequests atomic.Int32
	var authorization atomic.Value
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		snapshotRequests.Add(1)
		authorization.Store(request.Header.Get("Authorization"))
		if request.URL.Path != "/v2/relay/nodes/node-recovery-test/jobs/worker-a/snapshot/download" {
			t.Errorf("unexpected snapshot stream route: %s %s", request.Method, request.URL.Path)
		}
		if request.Method != http.MethodPost {
			t.Errorf("snapshot stream method=%s", request.Method)
		}
		// Drain the bounded request frame so the Node's streaming writer can end
		// before this fixture replies with the redirect.
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			t.Errorf("read Node-Control snapshot request frame: %v", err)
		}
		http.Redirect(response, request, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	_, ctx, _, _ := newMachineNodeControlRecoveryFixture(t, redirect.URL)
	const nodeID, nodeToken = "node-recovery-test", "synthetic-node-token"
	job := machineJob{WorkerID: "worker-a", Attempt: 1, WorkspaceID: "workspace-a",
		WorkspaceSnapshotDigest: strings.Repeat("a", 64)}
	err := downloadBoundNodeSnapshot(ctx, redirect.URL, nodeID, nodeToken, job,
		filepath.Join(t.TempDir(), "workspace"))
	if err == nil {
		t.Fatal("bound snapshot transfer unexpectedly followed a redirect")
	}
	if snapshotRequests.Load() != 1 || authorization.Load() != "CicadaNode "+nodeToken {
		t.Fatalf("paired snapshot stream was not reached with its Node credential: requests=%d auth=%v err=%v",
			snapshotRequests.Load(), authorization.Load(), err)
	}
	if leaked.Load() {
		t.Fatal("snapshot redirect forwarded the Node credential")
	}
}
