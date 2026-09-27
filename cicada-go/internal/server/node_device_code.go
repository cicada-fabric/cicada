package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/store"
)

// nodeDeviceCode accepts only a locally generated Node bearer digest. The
// bearer never crosses this unauthenticated bootstrap endpoint; only an owner
// Client can activate the pending credential through encrypted RPC.
func (h *Handler) nodeDeviceCode(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Node binding is unavailable"))
		return
	}
	var input struct {
		NodeID           string `json:"node_id"`
		NodeName         string `json:"node_name"`
		CredentialDigest string `json:"credential_digest"`
	}
	if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid Node device code request"))
		return
	}
	code, err := h.control.StartNodeDeviceBinding(input.NodeID, input.NodeName, input.CredentialDigest)
	if err != nil {
		if errors.Is(err, store.ErrNodeDeviceBindingRateLimited) {
			writeError(response, http.StatusTooManyRequests, errors.New("Node device code request rate limited"))
			return
		}
		if errors.Is(err, store.ErrNodeDeviceBindingConflict) {
			writeError(response, http.StatusConflict, errors.New("Node binding request already pending or active"))
			return
		}
		writeError(response, http.StatusBadRequest, errors.New("Node binding request rejected"))
		return
	}
	writeJSON(response, http.StatusCreated, code)
}
