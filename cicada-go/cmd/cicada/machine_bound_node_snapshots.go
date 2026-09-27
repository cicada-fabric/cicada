package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func boundNodeSnapshotURL(base, nodeID, workerID, digest string) string {
	endpoint := strings.TrimRight(base, "/") + "/v2/relay/nodes/" + urlPath(nodeID) +
		"/jobs/" + urlPath(workerID) + "/snapshot"
	if digest != "" {
		endpoint += "/" + urlPath(digest)
	}
	return endpoint
}

func boundNodeSnapshotRequest(ctx context.Context, method, endpoint, token string, job machineJob, body io.Reader, digest string) (*http.Request, error) {
	if strings.TrimSpace(token) == "" || job.WorkerID == "" || job.WorkspaceID == "" || job.Attempt <= 0 {
		return nil, errors.New("current Node credential, Worker, Workspace and attempt are required for snapshot transfer")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "CicadaNode "+strings.TrimSpace(token))
	request.Header.Set("X-Cicada-Worker-Attempt", strconv.Itoa(job.Attempt))
	request.Header.Set("X-Cicada-Workspace-ID", job.WorkspaceID)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-cicada-workspace-tar")
		request.Header.Set("X-Cicada-Snapshot-Digest", digest)
	} else {
		request.Header.Set("Accept", "application/x-cicada-workspace-tar")
	}
	return request, nil
}

func boundNodeSnapshotError(response *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
		Body: strings.TrimSpace(string(data))}
}

func downloadBoundNodeSnapshot(ctx context.Context, base, nodeID, token string, job machineJob, workspace string) error {
	if job.WorkspaceSnapshotDigest == "" {
		return nil
	}
	endpoint := boundNodeSnapshotURL(base, nodeID, job.WorkerID, job.WorkspaceSnapshotDigest)
	request, err := boundNodeSnapshotRequest(ctx, http.MethodGet, endpoint, token, job, nil, "")
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute, CheckRedirect: rejectNodeRedirect}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return boundNodeSnapshotError(response)
	}
	if response.Header.Get("X-Cicada-Snapshot-Digest") != job.WorkspaceSnapshotDigest {
		return errors.New("Hub returned a different Workspace snapshot digest")
	}
	if err := os.MkdirAll(filepath.Dir(workspace), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(workspace), ".cicada-node-download-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	n, copyErr := io.Copy(temporary, io.LimitReader(response.Body, snapshot.MaxArchiveBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > snapshot.MaxArchiveBytes {
		return errors.New("Workspace snapshot exceeds the maximum archive size")
	}
	metadata, err := snapshot.Inspect(path)
	if err != nil {
		return err
	}
	if metadata.Digest != job.WorkspaceSnapshotDigest {
		return errors.New("Workspace snapshot digest does not match the assigned job")
	}
	_, err = snapshot.UnpackFile(ctx, path, workspace)
	return err
}

func uploadBoundNodeSnapshot(ctx context.Context, base, nodeID, token string, job machineJob, workspace string) (string, error) {
	temporary, err := os.CreateTemp(filepath.Dir(workspace), ".cicada-node-upload-*")
	if err != nil {
		return "", err
	}
	path := temporary.Name()
	defer os.Remove(path)
	metadata, packErr := snapshot.Pack(ctx, workspace, temporary)
	closeErr := temporary.Close()
	if packErr != nil {
		return "", packErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	endpoint := boundNodeSnapshotURL(base, nodeID, job.WorkerID, "")
	request, err := boundNodeSnapshotRequest(ctx, http.MethodPost, endpoint, token, job, file, metadata.Digest)
	if err != nil {
		return "", err
	}
	response, err := (&http.Client{Timeout: 5 * time.Minute, CheckRedirect: rejectNodeRedirect}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return "", boundNodeSnapshotError(response)
	}
	var stored snapshot.Snapshot
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&stored); err != nil {
		return "", fmt.Errorf("decode Node Workspace snapshot response: %w", err)
	}
	if stored.Digest != metadata.Digest {
		return "", errors.New("Hub returned a different Workspace snapshot digest")
	}
	return stored.Digest, nil
}
