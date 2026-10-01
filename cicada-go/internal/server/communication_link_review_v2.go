package server

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

func (h *Handler) fabricV2CommunicationLinkReview(w http.ResponseWriter, r *http.Request,
	actor fabricpkg.Actor, path string) {
	if path == "" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		query := r.URL.Query()
		if len(query["cursor"]) > 1 || len(query["limit"]) > 1 {
			writeError(w, http.StatusBadRequest, errors.New("duplicate communication Link review query parameter"))
			return
		}
		limit := communicationLinkReviewQueryInt(r, "limit", 16)
		if limit < 1 || limit > 100 {
			writeError(w, http.StatusBadRequest, errors.New("invalid communication Link review page limit"))
			return
		}
		page, err := h.fabricService.ListCommunicationLinkReviews(actor, r.URL.Query().Get("cursor"), limit)
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, page)
		return
	}
	if !strings.HasPrefix(path, "/") {
		writeError(w, http.StatusNotFound, errors.New("communication Link review not found"))
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, errors.New("communication Link review not found"))
		return
	}
	messageID, err := url.PathUnescape(parts[0])
	if err != nil || messageID == "" || strings.ContainsAny(messageID, "/\\\r\n\x00") {
		writeError(w, http.StatusNotFound, errors.New("communication Link review not found"))
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		review, err := h.fabricService.GetCommunicationLinkReview(actor, messageID)
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, review)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, errors.New("communication Link review route not found"))
		return
	}
	requestBody := http.MaxBytesReader(w, r.Body, 4096)
	switch parts[1] {
	case "claim-next":
		var input fabricpkg.CommunicationLinkReviewClaimInput
		if err := decodeStrictClientJSON(requestBody, 4096, &input); err != nil ||
			input.MessageID != messageID || input.ExpectedVersion <= 0 || input.ExpectedOwnerEpoch <= 0 {
			writeError(w, http.StatusBadRequest, errors.New("invalid communication Link review claim"))
			return
		}
		review, err := h.fabricService.ClaimNextCommunicationLinkReview(actor, input)
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, review)
	case "decision":
		var input fabricpkg.CommunicationLinkReviewDecisionInput
		if err := decodeStrictClientJSON(requestBody, 4096, &input); err != nil ||
			input.MessageID != messageID || input.ExpectedVersion <= 0 || input.ExpectedOwnerEpoch <= 0 ||
			(input.Decision != "APPROVED" && input.Decision != "REJECTED") {
			writeError(w, http.StatusBadRequest, errors.New("invalid communication Link review decision"))
			return
		}
		review, err := h.fabricService.DecideCommunicationLinkReview(actor, input)
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, review)
	default:
		writeError(w, http.StatusNotFound, errors.New("communication Link review route not found"))
	}
}

func communicationLinkReviewQueryInt(r *http.Request, key string, fallback int) int {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return parsed
}
