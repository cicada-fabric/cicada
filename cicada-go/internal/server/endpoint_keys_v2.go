package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// endpointKeysV2 accepts only a self-attested public-key candidate from the
// authenticated native Session. It does not create a trusted cross-user pin or
// enable a peer ciphertext route.
func (h *Handler) endpointKeysV2(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	if request.URL.Path == "/v2/fabric/endpoint-keys" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Attestation json.RawMessage `json:"attestation"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		candidate, err := h.fabricService.RegisterEndpointKeyCandidate(actor, input.Attestation)
		if err != nil {
			endpointKeyError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, candidate)
		return
	}
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	encodedID := strings.TrimPrefix(request.URL.Path, "/v2/fabric/endpoint-keys/")
	endpointID, err := url.PathUnescape(encodedID)
	if err != nil || endpointID == "" || strings.Contains(endpointID, "/") {
		writeError(response, http.StatusBadRequest, errors.New("invalid Endpoint ID"))
		return
	}
	candidate, err := h.fabricService.EndpointKeyCandidate(actor, endpointID)
	if err != nil {
		endpointKeyError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, candidate)
}

func endpointKeyError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrEndpointKeyNotFound):
		writeError(response, http.StatusNotFound, err)
	case errors.Is(err, store.ErrEndpointKeyConflict):
		writeError(response, http.StatusConflict, err)
	default:
		fabricV2Error(response, err)
	}
}
