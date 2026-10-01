package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

func (h *Handler) fabricV2SealedTaskHandoff(response http.ResponseWriter, request *http.Request,
	actor fabricpkg.Actor, path string) {
	if path == "/local" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.LocalSealedTaskHandoffProposeInput
		request.Body = http.MaxBytesReader(response, request.Body, 32*1024)
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid local sealed Task handoff proposal"))
			return
		}
		handoff, err := h.fabricService.ProposeLocalSealedTaskHandoff(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusAccepted, handoff)
		return
	}
	if path == "" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.SealedTaskHandoffProposeInput
		request.Body = http.MaxBytesReader(response, request.Body, 32*1024)
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid sealed Task handoff proposal"))
			return
		}
		handoff, err := h.fabricService.ProposeSealedTaskHandoff(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusAccepted, handoff)
		return
	}
	if !strings.HasPrefix(path, "/") {
		writeError(response, http.StatusNotFound, errors.New("sealed Task handoff route not found"))
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if (len(parts) != 1 && len(parts) != 2) || parts[0] == "" ||
		(len(parts) == 2 && parts[1] != "accept") {
		writeError(response, http.StatusNotFound, errors.New("sealed Task handoff route not found"))
		return
	}
	handoffID, err := url.PathUnescape(parts[0])
	if err != nil || handoffID == "" || strings.ContainsAny(handoffID, "/\\\r\n\x00") {
		writeError(response, http.StatusNotFound, errors.New("sealed Task handoff not found"))
		return
	}
	if len(parts) == 1 && request.Method == http.MethodGet {
		handoff, err := h.fabricService.GetSealedTaskHandoff(actor, handoffID)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusOK, handoff)
		return
	}
	if len(parts) == 2 && request.Method == http.MethodPost {
		var input fabricpkg.SealedTaskHandoffAcceptInput
		request.Body = http.MaxBytesReader(response, request.Body, 4096)
		if err := readJSON(request, &input); err != nil || input.HandoffID != handoffID || input.ExpectedVersion <= 0 {
			writeError(response, http.StatusBadRequest, errors.New("invalid sealed Task handoff acceptance"))
			return
		}
		task, err := h.fabricService.AcceptSealedTaskHandoff(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusOK, task)
		return
	}
	writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}
