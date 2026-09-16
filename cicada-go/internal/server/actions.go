package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) actions(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		actions, err := h.control.ExternalActions(request.URL.Query().Get("goal_id"), request.URL.Query().Get("status"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"actions": actions})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.ExternalActionInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	action, err := h.control.RequestExternalAction(input)
	if err != nil {
		writeActionError(response, err)
		return
	}
	status := http.StatusAccepted
	if action.Status == "pending_approval" {
		status = http.StatusAccepted
	}
	writeJSON(response, status, action)
}

func (h *Handler) action(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/actions/"), "/")
	if len(parts) == 0 || parts[0] == "" || strings.Contains(parts[0], "?") {
		writeError(response, http.StatusNotFound, errors.New("external action not found"))
		return
	}
	id := parts[0]
	if len(parts) == 1 && request.Method == http.MethodGet {
		action, err := h.control.ExternalAction(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if action == nil {
			writeError(response, http.StatusNotFound, errors.New("external action not found"))
			return
		}
		writeJSON(response, http.StatusOK, action)
		return
	}
	if len(parts) != 2 || request.Method != http.MethodPost {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	switch parts[1] {
	case "execute":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		action, err := h.control.ExecuteExternalAction(request.Context(), id)
		if err != nil {
			if action != nil && action.Status == "failed" {
				writeJSON(response, http.StatusBadGateway, action)
				return
			}
			writeActionError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, action)
	case "claim":
		action, err := h.control.ClaimExternalAction(id)
		if err != nil {
			writeActionError(response, err)
			return
		}
		if action == nil {
			writeError(response, http.StatusNotFound, errors.New("external action not found"))
			return
		}
		writeJSON(response, http.StatusAccepted, action)
	case "complete":
		var input struct {
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		action, err := h.control.CompleteExternalAction(id, input.Result, input.Error)
		if err != nil {
			writeActionError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, action)
	case "cancel":
		action, err := h.control.CancelExternalAction(id)
		if err != nil {
			writeActionError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, action)
	default:
		writeError(response, http.StatusNotFound, errors.New("route not found"))
	}
}

func writeActionError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not found") {
		status = http.StatusNotFound
	} else if errors.Is(err, control.ErrPermissionDenied) {
		status = http.StatusForbidden
	} else if errors.Is(err, control.ErrPermissionApproval) {
		status = http.StatusConflict
	}
	writeError(response, status, err)
}
