package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// Network Tasks expose only route IDs and responsibility state. Offer and
// result prose must already be persisted as Endpoint-sealed NetworkDirect SEND.
func (h *Handler) fabricV2NetworkTask(w http.ResponseWriter, r *http.Request, networkID, operation string) {
	token, err := networkCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabric.ErrUnauthenticated)
		return
	}
	actor, err := h.fabricService.AuthenticateForNetwork(token, networkID)
	if err != nil {
		networkV2Error(w, err)
		return
	}
	switch operation {
	case "list":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		value, err := h.fabricService.ListNetworkTaskOffers(actor, queryInt(r, "limit", 16))
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tasks": value})
	case "get":
		if r.Method != http.MethodGet || r.URL.Query().Get("task_id") == "" {
			writeError(w, http.StatusBadRequest, errors.New("task_id is required for GET"))
			return
		}
		value, err := h.fabricService.GetNetworkTaskOffer(actor, r.URL.Query().Get("task_id"))
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "publish":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input store.NetworkTaskOfferInput
		if err := decodeStrictClientJSON(r.Body, 8192, &input); err != nil || input.TaskID == "" || input.ExpiresAt == "" || len(input.OfferMessageIDs) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network Task offer"))
			return
		}
		value, err := h.fabricService.PublishNetworkTaskOffer(actor, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, value)
	case "claim":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabric.TaskClaimInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.TaskID == "" || input.ExpectedRevision <= 0 || input.IdempotencyKey == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network Task claim"))
			return
		}
		value, err := h.fabricService.ClaimNetworkTaskOffer(actor, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "result":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input store.NetworkTaskResultInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.TaskID == "" || input.ExpectedRevision <= 0 || input.OwnerEpoch <= 0 || input.ResultMessageID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network Task result"))
			return
		}
		value, err := h.fabricService.SubmitNetworkTaskResult(actor, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, value)
	case "accept":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabric.TaskAcceptInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.TaskID == "" || input.ResultID == "" || input.ExpectedRevision <= 0 {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network Task acceptance"))
			return
		}
		value, err := h.fabricService.AcceptNetworkTaskResult(actor, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	default:
		writeError(w, http.StatusNotFound, errors.New("Network Task route not found"))
	}
}
