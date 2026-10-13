package server

import (
	"errors"
	"io"
	"net/http"
)

// Bound unauthenticated proof verification independently of actor IDs. No
// attacker-controlled map or waiting queue grows on this public ingress.
var ownerBootstrapVerificationSlots = make(chan struct{}, 2)

func (h *Handler) ownerBootstrapAccept(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Owner bootstrap is unavailable"))
		return
	}
	select {
	case ownerBootstrapVerificationSlots <- struct{}{}:
		defer func() { <-ownerBootstrapVerificationSlots }()
	default:
		response.Header().Set("Retry-After", "1")
		writeError(response, http.StatusServiceUnavailable, errors.New("Owner bootstrap is busy"))
		return
	}
	packet, e := io.ReadAll(io.LimitReader(request.Body, 256*1024+1))
	if e != nil || len(packet) == 0 || len(packet) > 256*1024 {
		writeError(response, http.StatusBadRequest, errors.New("invalid Owner bootstrap packet size"))
		return
	}
	receipt, e := h.control.AcceptOwnerBootstrap(packet)
	if e != nil {
		writeError(response, http.StatusForbidden, errors.New("Owner bootstrap authorization failed"))
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(receipt)
}
