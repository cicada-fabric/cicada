package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

const (
	nodeSnapshotAttemptHeader   = "X-Cicada-Worker-Attempt"
	nodeSnapshotWorkspaceHeader = "X-Cicada-Workspace-ID"
	nodeSnapshotDigestHeader    = "X-Cicada-Snapshot-Digest"
)

// relayNodeWorkerSnapshot handles the Node-scoped streamed Workspace CAS
// routes. relayNodeV2 authenticates the token before dispatch; this handler
// repeats that check immediately before Store preauthorization and passes only
// its digest to Control and Store.
func (h *Handler) relayNodeWorkerSnapshot(response http.ResponseWriter, request *http.Request, nodeID, workerID, digest, token string) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Control workspace snapshots are unavailable"))
		return
	}
	if !h.relayNodeCredentialCurrent(nodeID, token) {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	attempt, err := strconv.Atoi(strings.TrimSpace(request.Header.Get(nodeSnapshotAttemptHeader)))
	if err != nil || attempt <= 0 {
		writeError(response, http.StatusBadRequest, errors.New(nodeSnapshotAttemptHeader+" must be a positive integer"))
		return
	}
	workspaceID := strings.TrimSpace(request.Header.Get(nodeSnapshotWorkspaceHeader))
	if workspaceID == "" {
		writeError(response, http.StatusBadRequest, errors.New(nodeSnapshotWorkspaceHeader+" is required"))
		return
	}
	credentialDigest := fabricpkg.HashSessionCredential(token)
	switch request.Method {
	case http.MethodPost:
		if digest != "" {
			writeError(response, http.StatusNotFound, errors.New("snapshot route not found"))
			return
		}
		expectedDigest := strings.TrimSpace(request.Header.Get(nodeSnapshotDigestHeader))
		if !isServerSnapshotDigest(expectedDigest) {
			writeError(response, http.StatusBadRequest, errors.New("a lowercase SHA-256 "+nodeSnapshotDigestHeader+" is required"))
			return
		}
		request.Body = http.MaxBytesReader(response, request.Body, snapshot.MaxArchiveBytes)
		stored, err := h.control.ReceiveBoundNodeWorkspaceSnapshot(request.Context(), credentialDigest,
			nodeID, workerID, attempt, workspaceID, expectedDigest, request.Body)
		if err != nil {
			relayNodeSnapshotError(response, h, nodeID, token, err)
			return
		}
		writeJSON(response, http.StatusCreated, stored)
	case http.MethodGet:
		if !isServerSnapshotDigest(digest) {
			writeError(response, http.StatusNotFound, errors.New("workspace snapshot is unavailable"))
			return
		}
		file, metadata, err := h.control.OpenBoundNodeWorkspaceSnapshot(credentialDigest,
			nodeID, workerID, attempt, workspaceID, digest)
		if err != nil {
			relayNodeSnapshotError(response, h, nodeID, token, err)
			return
		}
		defer file.Close()
		if !h.relayNodeCredentialCurrent(nodeID, token) {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			return
		}
		response.Header().Set("Content-Type", "application/x-cicada-workspace-tar")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set(nodeSnapshotDigestHeader, metadata.Digest)
		response.Header().Set("Content-Length", strconv.FormatInt(metadata.Size, 10))
		_, _ = io.Copy(response, file)
	default:
		response.Header().Set("Allow", "GET, POST")
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func relayNodeSnapshotError(response http.ResponseWriter, h *Handler, nodeID, token string, err error) {
	switch {
	case errors.Is(err, store.ErrNodeWorkerNotAuthorized):
		if !h.relayNodeCredentialCurrent(nodeID, token) {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			return
		}
		writeError(response, http.StatusNotFound, errors.New("Node Workspace snapshot is unavailable"))
	case errors.Is(err, store.ErrNodeWorkerUnavailable), errors.Is(err, control.ErrWorkerUnavailable):
		writeError(response, http.StatusConflict, errors.New("Node Worker attempt is no longer current"))
	case errors.Is(err, os.ErrNotExist):
		writeError(response, http.StatusNotFound, errors.New("Node Workspace snapshot is unavailable"))
	case errors.Is(err, control.ErrNodeWorkspaceSnapshotInvalidArchive),
		errors.Is(err, control.ErrNodeWorkspaceSnapshotDigestMismatch):
		writeError(response, http.StatusBadRequest, errors.New("workspace snapshot archive or digest is invalid"))
	default:
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(response, http.StatusRequestEntityTooLarge, errors.New("workspace snapshot exceeds size limit"))
			return
		}
		writeError(response, http.StatusInternalServerError, errors.New("unable to process Node Workspace snapshot"))
	}
}

func isServerSnapshotDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
