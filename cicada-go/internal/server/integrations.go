package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func readBody(request *http.Request, limit int64) ([]byte, error) {
	if request.Body == nil {
		return nil, errors.New("request body is required")
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("request body exceeds %d bytes", limit)
	}
	return data, nil
}

func (h *Handler) externalEvents(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		events, err := h.control.ExternalEvents(request.URL.Query().Get("connector"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"events": events})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	connector := strings.TrimSpace(request.Header.Get("X-Cicada-Connector"))
	eventID := strings.TrimSpace(request.Header.Get("X-Cicada-Event-ID"))
	eventType := strings.TrimSpace(request.Header.Get("X-Cicada-Event-Type"))
	goalID := strings.TrimSpace(request.Header.Get("X-Cicada-Goal-ID"))
	signature := strings.TrimSpace(request.Header.Get("X-Cicada-Signature"))
	body, err := readBody(request, 1<<20)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	event, err := h.control.IngestExternalEvent(connector, eventID, eventType, signature, body, goalID)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusAccepted, event)
}

func (h *Handler) externalEvent(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/v1/connectors/events/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("external event not found"))
		return
	}
	event, err := h.control.ExternalEvent(id)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if event == nil {
		writeError(response, http.StatusNotFound, errors.New("external event not found"))
		return
	}
	writeJSON(response, http.StatusOK, event)
}
