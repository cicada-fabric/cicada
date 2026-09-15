package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) intents(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		intents, err := h.control.Intents(request.URL.Query().Get("status"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"intents": intents})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.IntentInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	intent, err := h.control.RouteIntent(input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeJSON(response, status, map[string]any{"error": err.Error(), "intent": intent})
		return
	}
	writeJSON(response, http.StatusAccepted, intent)
}

func (h *Handler) intent(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/v1/intents/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("intent not found"))
		return
	}
	intent, err := h.control.Intent(id)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if intent == nil {
		writeError(response, http.StatusNotFound, errors.New("intent not found"))
		return
	}
	writeJSON(response, http.StatusOK, intent)
}
