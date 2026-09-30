package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

const groupSpaceHTTPMaxBytes = 4 << 20

func groupSpaceHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrGroupSpaceInvalid):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, store.ErrGroupSpaceDenied), errors.Is(err, store.ErrGroupSpaceHistory):
		writeError(w, http.StatusForbidden, err)
	case errors.Is(err, store.ErrGroupSpaceNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, store.ErrGroupSpaceConflict), errors.Is(err, store.ErrGroupSpaceNotReady):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, store.ErrGroupSpaceLimit):
		writeError(w, http.StatusTooManyRequests, err)
	default:
		fabricV2Error(w, err)
	}
}

// Group Space bodies cross this route only as per-reader sealed ciphertext.
// Both credentials are required: the Node credential identifies the trusted
// native bridge, and the Session credential identifies its current Endpoint.
func (h *Handler) fabricV2NodeSpaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeToken, err := fabricpkg.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	sessionToken, err := fabricpkg.SessionCredentialFromAuthorization(r.Header.Get("Cicada-Space-Session"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/v2/fabric/node/spaces/") {
	case "prepare":
		var input store.GroupSpacePrepareInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Group Space prepare request"))
			return
		}
		value, err := h.fabricService.PrepareGroupSpaceWrite(nodeToken, sessionToken, input)
		if err != nil {
			groupSpaceHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "commit":
		var input store.GroupSpaceCommitInput
		if err := decodeStrictClientJSON(r.Body, groupSpaceHTTPMaxBytes, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Group Space commit request"))
			return
		}
		value, err := h.fabricService.CommitGroupSpaceWrite(nodeToken, sessionToken, input)
		if err != nil {
			groupSpaceHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, value)
	case "list":
		var input store.GroupSpaceListInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Group Space list request"))
			return
		}
		value, err := h.fabricService.ListGroupSpace(nodeToken, sessionToken, input)
		if err != nil {
			groupSpaceHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "get":
		var input store.GroupSpaceGetInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Group Space get request"))
			return
		}
		value, err := h.fabricService.GetGroupSpace(nodeToken, sessionToken, input)
		if err != nil {
			groupSpaceHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "history/manifest":
		var input store.GroupSpaceHistoryManifestInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Group Space history manifest request"))
			return
		}
		value, err := h.fabricService.GetGroupSpaceHistoryManifest(nodeToken, sessionToken, input)
		if err != nil {
			groupSpaceHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "history/grant":
		var input store.GroupSpaceHistoryCommitInput
		if err := decodeStrictClientJSON(r.Body, 128*1024, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Group Space history grant request"))
			return
		}
		value, err := h.fabricService.GrantGroupSpaceHistorySealed(nodeToken, sessionToken, input)
		if err != nil {
			groupSpaceHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, value)
	default:
		writeError(w, http.StatusNotFound, errors.New("Group Space route not found"))
	}
}
