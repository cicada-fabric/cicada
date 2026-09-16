package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func (h *Handler) snapshotGC(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	result, err := h.control.CollectWorkspaceSnapshots(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

// snapshots accepts a CAS archive from an authenticated Control replication
// client. The destination verifies the archive digest before attaching it to a
// local Workspace with the same stable path, if one exists.
func (h *Handler) snapshots(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	digest := strings.TrimSpace(request.Header.Get("X-Cicada-Snapshot-Digest"))
	if digest == "" {
		writeError(response, http.StatusBadRequest, errors.New("X-Cicada-Snapshot-Digest is required"))
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, snapshot.MaxArchiveBytes+1)
	result, workspace, err := h.control.ReceiveReplicatedSnapshot(digest, request.Body, request.Header.Get("X-Cicada-Workspace-Path"))
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]any{"snapshot": result, "workspace": workspace})
}

func (h *Handler) snapshot(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/snapshots/"), "/")
	if len(parts) != 1 || parts[0] == "" || request.Method != http.MethodGet {
		writeError(response, http.StatusNotFound, errors.New("snapshot not found"))
		return
	}
	file, metadata, err := h.control.OpenSnapshotByDigest(parts[0])
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	defer file.Close()
	response.Header().Set("Content-Type", "application/x-cicada-workspace-tar")
	response.Header().Set("X-Cicada-Snapshot-Digest", metadata.Digest)
	response.Header().Set("Content-Length", strconv.FormatInt(metadata.Size, 10))
	if _, err := io.Copy(response, file); err != nil {
		return
	}
}
