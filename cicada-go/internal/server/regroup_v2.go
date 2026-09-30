package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func regroupHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrRegroupInvalid):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, store.ErrRegroupConflict):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, store.ErrRegroupDenied), errors.Is(err, store.ErrRegroupNotFound):
		writeError(w, http.StatusNotFound, errors.New("current regroup authority unavailable"))
	default:
		fabricV2Error(w, err)
	}
}

// The Monitor's native Session and bound Node must both authenticate. Owner
// delegation is issued only on the separate encrypted Client management path.
func (h *Handler) fabricV2NodeRegroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeToken, err := fabric.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabric.ErrUnauthenticated)
		return
	}
	sessionToken, err := fabric.SessionCredentialFromAuthorization(r.Header.Get("Cicada-Regroup-Session"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabric.ErrUnauthenticated)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/v2/fabric/node/regroup/") {
	case "propose":
		var input store.RegroupProposalInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid regroup proposal"))
			return
		}
		result, err := h.fabricService.ProposeRegroup(nodeToken, sessionToken, input)
		if err != nil {
			regroupHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, result)
	case "apply":
		var input struct {
			ProposalID   string `json:"proposal_id"`
			DelegationID string `json:"delegation_id"`
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.ProposalID == "" || input.DelegationID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid delegated regroup request"))
			return
		}
		result, err := h.fabricService.ApplyDelegatedRegroup(nodeToken, sessionToken, input.ProposalID, input.DelegationID)
		if err != nil {
			regroupHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		writeError(w, http.StatusNotFound, errors.New("regroup route not found"))
	}
}
