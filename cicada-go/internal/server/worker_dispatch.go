package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) workerDispatch(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/workers/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("worker dispatch route not found"))
		return
	}
	workerID := parts[0]
	switch {
	case parts[1] == "claim" && request.Method == http.MethodPost:
		var input struct {
			MachineID string `json:"machine_id"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		job, err := h.control.ClaimRemoteWorker(workerID, strings.TrimSpace(input.MachineID))
		if err != nil {
			status := dispatchErrorStatus(err)
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, job)
	case parts[1] == "result" && request.Method == http.MethodPost:
		var input struct {
			MachineID         string `json:"machine_id"`
			Status            string `json:"status"`
			Summary           string `json:"summary"`
			ThreadID          string `json:"thread_id"`
			Error             string `json:"error"`
			WorkspaceRevision string `json:"workspace_revision"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		worker, err := h.control.CompleteRemoteWorker(workerID, strings.TrimSpace(input.MachineID), input.Status, input.Summary, input.ThreadID, input.Error, input.WorkspaceRevision)
		if err != nil {
			status := dispatchErrorStatus(err)
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, worker)
	default:
		writeError(response, http.StatusNotFound, errors.New("worker dispatch route not found"))
	}
}

func dispatchErrorStatus(err error) int {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, control.ErrWorkerUnavailable):
		return http.StatusConflict
	case errors.Is(err, control.ErrPermissionDenied), errors.Is(err, control.ErrPermissionApproval):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}
