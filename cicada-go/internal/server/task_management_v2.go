package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/store"
)

func (h *Handler) groupTasks(response http.ResponseWriter, request *http.Request, groupID string, parts []string) {
	if len(parts) == 1 && parts[0] == "results" {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		results, err := h.control.SharedTaskResults(groupID, queryInt(request, "limit", 100))
		if err != nil {
			taskManagementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"results": results})
		return
	}
	if len(parts) == 0 {
		switch request.Method {
		case http.MethodGet:
			tasks, err := h.control.SharedTasks(groupID, queryInt(request, "limit", 100))
			if err != nil {
				taskManagementError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"tasks": tasks})
		case http.MethodPost:
			var input store.SharedTask
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
			task, err := h.control.CreateSharedTask(groupID, input)
			if err != nil {
				taskManagementError(response, err)
				return
			}
			writeJSON(response, http.StatusCreated, task)
		default:
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
		return
	}
	if len(parts) != 2 || request.Method != http.MethodPost || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("task management route not found"))
		return
	}
	switch parts[1] {
	case "dependencies":
		var input struct {
			DependsOnID      string `json:"depends_on_id"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.control.AddSharedTaskDependency(groupID, parts[0], input.DependsOnID, input.ExpectedRevision)
		if err != nil {
			taskManagementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	case "ready":
		var input struct {
			ExpectedRevision int64 `json:"expected_revision"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.control.ReadySharedTask(groupID, parts[0], input.ExpectedRevision)
		if err != nil {
			taskManagementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	case "reconcile-expired":
		var input struct {
			ExpectedRevision int64 `json:"expected_revision"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.control.ReconcileExpiredSharedTask(groupID, parts[0], input.ExpectedRevision)
		if err != nil {
			taskManagementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	default:
		writeError(response, http.StatusNotFound, errors.New("task management route not found"))
	}
}

func taskManagementError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, store.ErrGroupNotFound), errors.Is(err, store.ErrSharedTaskNotFound):
		status = http.StatusNotFound
	case errors.Is(err, store.ErrSharedTaskConflict), errors.Is(err, store.ErrSharedTaskDependency):
		status = http.StatusConflict
	}
	writeError(response, status, err)
}
