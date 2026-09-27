package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
)

func (h *Handler) contactAnnouncement(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Label string `json:"label"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	announcement, err := h.control.SignContactAnnouncement(input.Label)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	var record json.RawMessage = announcement
	writeJSON(response, http.StatusOK, json.RawMessage(record))
}

func (h *Handler) discoveryRequests(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		requests, err := h.control.DiscoveryRequests(request.URL.Query().Get("status"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"requests": requests})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Announcement json.RawMessage `json:"announcement"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	discovery, err := h.control.SubmitContactDiscovery(input.Announcement)
	if err != nil {
		writeDiscoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, discovery)
}

func (h *Handler) discoveryRequest(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/discovery/requests/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("discovery request not found"))
		return
	}
	id := parts[0]
	if len(parts) == 1 && request.Method == http.MethodGet {
		discovery, err := h.control.DiscoveryRequest(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if discovery == nil {
			writeError(response, http.StatusNotFound, errors.New("discovery request not found"))
			return
		}
		writeJSON(response, http.StatusOK, discovery)
		return
	}
	if len(parts) != 2 || request.Method != http.MethodPost {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	var (
		discovery any
		err       error
	)
	switch parts[1] {
	case "accept":
		discovery, err = h.control.AcceptContactDiscovery(id)
	case "reject":
		discovery, err = h.control.RejectContactDiscovery(id)
	default:
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	if err != nil {
		writeDiscoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, discovery)
}

func writeDiscoveryError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	}
	writeError(response, status, err)
}
