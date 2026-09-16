package server

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) threadSessions(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		sessions, err := h.control.ThreadSessions()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"sessions": sessions})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.ThreadSessionInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	session, err := h.control.RegisterThreadSession(input)
	if err != nil {
		writeError(response, threadErrorStatus(err), err)
		return
	}
	writeJSON(response, http.StatusCreated, session)
}

func (h *Handler) threadSession(response http.ResponseWriter, request *http.Request) {
	threadID := strings.TrimPrefix(request.URL.Path, "/v1/threads/sessions/")
	if threadID == "" || strings.Contains(threadID, "/") {
		writeError(response, http.StatusNotFound, errors.New("thread session not found"))
		return
	}
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	session, err := h.control.ThreadSession(threadID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if session == nil {
		writeError(response, http.StatusNotFound, errors.New("thread session not found"))
		return
	}
	writeJSON(response, http.StatusOK, session)
}

func (h *Handler) threadQueue(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.ThreadQueueInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	delivery, err := h.control.QueueThreadSessionMessage(input)
	if err != nil {
		status := threadErrorStatus(err)
		if strings.HasPrefix(err.Error(), "codex queue failed:") {
			status = http.StatusBadGateway
		}
		if delivery != nil {
			writeJSON(response, status, map[string]any{"error": err.Error(), "delivery": delivery})
		} else {
			writeError(response, status, err)
		}
		return
	}
	writeJSON(response, http.StatusAccepted, delivery)
}

func (h *Handler) threadDeliveries(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	limit := 100
	if raw := strings.TrimSpace(request.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeError(response, http.StatusBadRequest, errors.New("limit must be between 1 and 1000"))
			return
		}
		limit = parsed
	}
	deliveries, err := h.control.ThreadDeliveries(limit)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"deliveries": deliveries})
}

func threadErrorStatus(err error) int {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, control.ErrPermissionDenied), errors.Is(err, control.ErrPermissionApproval):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}
