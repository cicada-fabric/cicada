package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

func (h *Handler) directoryAnnouncement(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Label     string   `json:"label"`
		Endpoints []string `json:"endpoints"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	expires := time.Now().UTC().Add(7 * 24 * time.Hour)
	if strings.TrimSpace(input.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(input.ExpiresAt))
		if err != nil {
			writeError(response, http.StatusBadRequest, errors.New("expires_at must be RFC3339"))
			return
		}
		expires = parsed
	}
	announcement, err := h.control.SignDirectoryAnnouncement(input.Label, input.Endpoints, expires)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusOK, json.RawMessage(announcement))
}

func (h *Handler) directoryRecords(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		records, err := h.control.DirectoryRecords(request.URL.Query().Get("active") != "false")
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"records": records})
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
	record, err := h.control.PublishDirectoryAnnouncement(input.Announcement)
	if err != nil {
		writeDirectoryError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, record)
}

func (h *Handler) directoryRecord(response http.ResponseWriter, request *http.Request, prefix string) {
	id := strings.TrimPrefix(request.URL.Path, prefix)
	if id == "" || strings.Contains(id, "/") || request.Method != http.MethodGet {
		writeError(response, http.StatusNotFound, errors.New("directory record not found"))
		return
	}
	record, err := h.control.DirectoryRecord(id)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, record)
}

func writeDirectoryError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	}
	writeError(response, status, err)
}
