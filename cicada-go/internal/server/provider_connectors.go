package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/connectors/calendar"
	"github.com/cicada-ai/cicada/internal/connectors/documents"
	"github.com/cicada-ai/cicada/internal/connectors/email"
	"github.com/cicada-ai/cicada/internal/connectors/social"
	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) emailConnector(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	body, err := readBody(request, email.MaxMessageBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	externalID, eventType, normalized, err := email.Normalize(body)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	event, err := h.control.IngestNormalizedExternalEvent(
		"email", externalID, eventType, strings.TrimSpace(request.Header.Get("X-Cicada-Signature")),
		body, normalized, strings.TrimSpace(request.Header.Get("X-Cicada-Goal-ID")),
	)
	if err != nil {
		providerConnectorError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, event)
}

func (h *Handler) calendarConnector(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	body, err := readBody(request, calendar.MaxEventBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	externalID, eventType, normalized, err := calendar.Normalize(body)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	event, err := h.control.IngestNormalizedExternalEvent(
		"calendar", externalID, eventType, strings.TrimSpace(request.Header.Get("X-Cicada-Signature")),
		body, normalized, strings.TrimSpace(request.Header.Get("X-Cicada-Goal-ID")),
	)
	if err != nil {
		providerConnectorError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, event)
}

func (h *Handler) documentsConnector(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	body, err := readBody(request, documents.MaxDocumentBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	externalID, eventType, normalized, err := documents.Normalize(body)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	event, err := h.control.IngestNormalizedExternalEvent(
		"documents", externalID, eventType, strings.TrimSpace(request.Header.Get("X-Cicada-Signature")),
		body, normalized, strings.TrimSpace(request.Header.Get("X-Cicada-Goal-ID")),
	)
	if err != nil {
		providerConnectorError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, event)
}

func (h *Handler) socialConnector(response http.ResponseWriter, request *http.Request, provider string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	body, err := readBody(request, social.MaxMessageBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	externalID, eventType, normalized, err := social.Normalize(provider, body)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	event, err := h.control.IngestNormalizedExternalEvent(
		provider, externalID, eventType, strings.TrimSpace(request.Header.Get("X-Cicada-Signature")),
		body, normalized, strings.TrimSpace(request.Header.Get("X-Cicada-Goal-ID")),
	)
	if err != nil {
		providerConnectorError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, event)
}

func (h *Handler) connectorReply(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.ExternalReplyInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	action, err := h.control.RequestExternalReply(input)
	if err != nil {
		writeActionError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, action)
}

func providerConnectorError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	}
	writeError(response, status, err)
}
