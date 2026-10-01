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
	var input nodeControlPairingInput
	if err := decodeStrictClientJSON(request.Body, 96*1024, &input); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid Node device code request"))
		return
	}
	challenge, err := h.control.StartNodeControlDeviceBinding(input.controlInput())
	if err != nil {
		if errors.Is(err, store.ErrNodeDeviceBindingRateLimited) {
			writeError(response, http.StatusTooManyRequests, errors.New("Node device code request rate limited"))
			return
		}
		if errors.Is(err, store.ErrNodeControlPairingConflict) {
			writeError(response, http.StatusConflict, errors.New("Node-Control pairing request already pending"))
			return
		}
		if errors.Is(err, store.ErrNodeControlMigrationBlocked) {
			writeError(response, http.StatusUpgradeRequired, errors.New("MIGRATION_BLOCKED: use Owner-approved Node-Control key upgrade"))
			return
		}
		writeError(response, http.StatusBadRequest, errors.New("Node-Control device-code request rejected"))
		return
	}
	writeJSON(response, http.StatusCreated, challenge)
}
