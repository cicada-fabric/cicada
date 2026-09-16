package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func TestWorkspaceSnapshotUploadDownloadAndRestore(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := control.New(control.Config{
		StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	workspace, err := controlPlane.CreateWorkspace(control.WorkspaceInput{Path: filepath.Join(root, "workspace", "goal"), Source: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.Path, "result.txt"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := snapshot.Pack(context.Background(), workspace.Path, &archive); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(controlPlane)
	request := httptest.NewRequest(http.MethodPost, "/v1/workspaces/"+workspace.ID+"/snapshot", &archive)
	request.Header.Set("content-type", "application/x-cicada-workspace-tar")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("upload status=%d body=%s", response.Code, response.Body.String())
	}
	var uploaded snapshot.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &uploaded); err != nil {
		t.Fatal(err)
	}
	if uploaded.Digest == "" || uploaded.FileCount != 1 {
		t.Fatalf("unexpected uploaded metadata: %#v", uploaded)
	}
	workspace, err = controlPlane.Workspace(workspace.ID)
	if err != nil || workspace.SnapshotDigest != uploaded.Digest {
		t.Fatalf("workspace snapshot not persisted: %#v err=%v", workspace, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+workspace.ID+"/snapshot/"+uploaded.Digest, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("X-Cicada-Snapshot-Digest") != uploaded.Digest {
		t.Fatalf("download status=%d headers=%v", response.Code, response.Header())
	}
	archivePath := filepath.Join(t.TempDir(), "download.tar")
	if err := os.WriteFile(archivePath, response.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := snapshot.UnpackFile(context.Background(), archivePath, target); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(target, "result.txt"))
	if err != nil || string(content) != "done" {
		t.Fatalf("restored content=%q err=%v", content, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+workspace.ID+"/snapshot/"+uploaded.Digest[:63]+"0", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("mismatched digest status=%d body=%s", response.Code, response.Body.String())
	}
	_, _ = io.Copy(io.Discard, response.Body)
}
