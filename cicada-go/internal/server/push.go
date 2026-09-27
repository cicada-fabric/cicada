package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) pushConfiguration(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(response, http.StatusOK, h.control.PushConfiguration())
}

func (h *Handler) pushSubscription(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPost {
		var input control.PushSubscriptionInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		registration, err := h.control.RegisterPushSubscription(input)
		if err != nil {
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not configured") {
				status = http.StatusServiceUnavailable
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusCreated, registration)
		return
	}
	if request.Method == http.MethodDelete {
		id := strings.TrimPrefix(request.URL.Path, "/v1/notifications/push/subscriptions/")
		if id == "" || strings.Contains(id, "/") {
			writeError(response, http.StatusNotFound, os.ErrNotExist)
			return
		}
		if err := h.control.DeletePushSubscription(id); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		response.WriteHeader(http.StatusNoContent)
		return
	}
	writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}
