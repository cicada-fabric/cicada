package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func TestMachineAgentRestoresAndUploadsBoundNodeWorkspaceSnapshot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CICADA_WORKSPACE_ROOT", root)
	seed := filepath.Join(root, "seed")
	if err := os.MkdirAll(seed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "input.txt"), []byte("restored"), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	initial, err := snapshot.Pack(context.Background(), seed, &archive)
	if err != nil {
		t.Fatal(err)
	}
	const nodeID, workerID, workspaceID, nodeToken = "node-a", "worker-a", "workspace-a", "node-token"
	workspace := filepath.Join(root, "workspaces", workspaceID)
	job := machineJob{
		MachineID: nodeID, WorkerID: workerID, WorkspaceID: workspaceID,
		Workspace: "/hub/goals/worker-a", WorkspaceSnapshotDigest: initial.Digest, Attempt: 2,
		Harness: "shell", Resources: map[string]any{"argv": []any{"/bin/sh", "-c", "cat input.txt && printf done > output.txt"}},
	}
	var uploadedDigest string
	api := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "CicadaNode "+nodeToken {
			t.Errorf("snapshot request authorization=%q", got)
		}
		if got := request.Header.Get("X-Cicada-Worker-Attempt"); got != "2" {
			t.Errorf("snapshot attempt=%q", got)
		}
		if got := request.Header.Get("X-Cicada-Workspace-ID"); got != workspaceID {
			t.Errorf("snapshot workspace=%q", got)
		}
		switch request.Method {
		case http.MethodGet:
			if request.URL.Path != "/v2/relay/nodes/node-a/jobs/worker-a/snapshot/"+initial.Digest {
				t.Errorf("snapshot GET route=%q", request.URL.Path)
			}
			response.Header().Set("X-Cicada-Snapshot-Digest", initial.Digest)
			_, _ = response.Write(archive.Bytes())
		case http.MethodPost:
			if request.URL.Path != "/v2/relay/nodes/node-a/jobs/worker-a/snapshot" {
				t.Errorf("snapshot POST route=%q", request.URL.Path)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read uploaded snapshot: %v", err)
			}
			digest := sha256.Sum256(body)
			uploadedDigest = hex.EncodeToString(digest[:])
			if got := request.Header.Get("X-Cicada-Snapshot-Digest"); got != uploadedDigest {
				t.Errorf("upload digest header=%q, actual=%q", got, uploadedDigest)
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(snapshot.Snapshot{Digest: uploadedDigest, Size: int64(len(body))})
		default:
			t.Errorf("unexpected snapshot method: %s", request.Method)
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer api.Close()
	result := executeMachineJobWithHeartbeats(context.Background(), api.URL, nodeID, nodeToken, time.Hour, job)
	if result.Status != "completed" || result.Summary != "restored" || result.WorkspaceSnapshotDigest == "" || result.WorkspaceSnapshotDigest != uploadedDigest {
		t.Fatalf("Node Workspace execution/result=%#v, upload=%q", result, uploadedDigest)
	}
	if output, err := os.ReadFile(filepath.Join(workspace, "output.txt")); err != nil || string(output) != "done" {
		t.Fatalf("Workspace output=%q err=%v", output, err)
	}
}

func TestBoundNodeSnapshotDoesNotForwardCredentialOnRedirect(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		leaked.Store(request.Header.Get("Authorization") != "")
		response.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	root := t.TempDir()
	job := machineJob{WorkerID: "worker-a", WorkspaceID: "workspace-a", Attempt: 1,
		WorkspaceSnapshotDigest: "abcdef", Workspace: filepath.Join(root, "workspace")}
	if err := downloadBoundNodeSnapshot(context.Background(), redirect.URL, "node-a", "sensitive-node-token", job, job.Workspace); err == nil {
		t.Fatal("snapshot redirect unexpectedly followed")
	}
	if leaked.Load() {
		t.Fatal("snapshot redirect forwarded the Node credential")
	}
}
