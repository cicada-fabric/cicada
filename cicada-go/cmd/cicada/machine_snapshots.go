package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func downloadMachineSnapshot(ctx context.Context, base string, job machineJob, workspace string) error {
	endpoint := base + "/v1/workspaces/" + url.PathEscape(job.WorkspaceID) + "/snapshot/" + url.PathEscape(job.WorkspaceSnapshotDigest)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	setMachineAuth(request)
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Control returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	temporary, err := os.CreateTemp(filepath.Dir(workspace), ".cicada-download-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	_, copyErr := io.Copy(temporary, io.LimitReader(response.Body, snapshot.MaxArchiveBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	metadata, err := snapshot.Inspect(path)
	if err != nil {
		return err
	}
	if metadata.Digest != job.WorkspaceSnapshotDigest {
		return errors.New("workspace snapshot digest does not match the job")
	}
	_, err = snapshot.UnpackFile(ctx, path, workspace)
	return err
}

func uploadMachineSnapshot(ctx context.Context, base string, job machineJob, workspace string) (string, error) {
	temporary, err := os.CreateTemp(filepath.Dir(workspace), ".cicada-upload-*")
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
	endpoint := base + "/v1/workspaces/" + url.PathEscape(job.WorkspaceID) + "/snapshot"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, file)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-cicada-workspace-tar")
	setMachineAuth(request)
	response, err := (&http.Client{Timeout: 5 * time.Minute}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("Control returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var stored snapshot.Snapshot
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&stored); err != nil {
		return "", err
	}
	if stored.Digest != metadata.Digest {
		return "", errors.New("Control returned a different workspace snapshot digest")
	}
	return stored.Digest, nil
}

func setMachineAuth(request *http.Request) {
	if token := strings.TrimSpace(os.Getenv("CICADA_API_TOKEN")); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
}
