package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

const relayNodeMonitorBroadcastV2Limit = 16

func (h *Handler) relayNodeMonitorBroadcastV2(response http.ResponseWriter,
	request *http.Request, nodeToken string, route []string) {
	response.Header().Set("Cache-Control", "no-store")
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	switch {
	case len(route) == 0:
		h.relayNodeMonitorBroadcastList(response, request, nodeToken)
	case len(route) == 2 && route[0] != "" && route[1] == "review":
		h.relayNodeMonitorBroadcastReview(response, request, nodeToken, route[0])
	case len(route) == 1 && route[0] != "authorize" && route[0] != "receipt":
		h.relayNodeMonitorBroadcastGet(response, request, nodeToken, route[0])
	case len(route) == 2 && route[0] != "" && route[1] == "authorize":
		h.relayNodeMonitorBroadcastAuthorize(response, request, nodeToken, route[0])
	case len(route) == 2 && route[0] != "" && route[1] == "receipt":
		h.relayNodeMonitorBroadcastReceipt(response, request, nodeToken, route[0])
	case len(route) == 2 && route[0] != "" && route[1] == "outcomes":
		h.relayNodeMonitorBroadcastOutcomes(response, request, nodeToken, route[0])
	default:
		writeError(response, http.StatusNotFound, errors.New("Monitor broadcast Node route not found"))
	}
}

func (h *Handler) relayNodeMonitorBroadcastReview(response http.ResponseWriter,
	request *http.Request, nodeToken, previewID string) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if request.URL.RawQuery != "" || strings.TrimSpace(previewID) != previewID || !relayNodeMonitorBroadcastEmptyBody(request) {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast review request"))
		return
	}
	sessionToken, ok := relayNodeMonitorBroadcastSessionToken(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	delivery, err := h.fabricService.PreviewNodeMonitorBroadcastV2Delivery(nodeToken, sessionToken, previewID)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("current Monitor broadcast review unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, delivery)
}

func relayNodeMonitorBroadcastEmptyBody(request *http.Request) bool {
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 || request.Body == nil || request.Body == http.NoBody {
		return request.ContentLength == 0 && len(request.TransferEncoding) == 0
	}
	var one [1]byte
	n, err := request.Body.Read(one[:])
	return n == 0 && errors.Is(err, io.EOF)
}

func (h *Handler) relayNodeMonitorBroadcastList(response http.ResponseWriter,
	request *http.Request, nodeToken string) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	query := request.URL.Query()
	if len(query) > 1 || (len(query) == 1 && (len(query["limit"]) != 1)) {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast notification request"))
		return
	}
	limit := relayNodeMonitorBroadcastV2Limit
	if values, present := query["limit"]; present {
		raw := values[0]
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > relayNodeMonitorBroadcastV2Limit {
			writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast notification request"))
			return
		}
		limit = parsed
	}
	notifications, err := h.fabricService.ListNodeMonitorBroadcastV2Notifications(nodeToken, limit)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("Monitor broadcast notifications unavailable"))
		return
	}
	hubID, err := h.fabricService.ClientHubID()
	if err != nil || strings.TrimSpace(hubID) == "" {
		writeError(response, http.StatusInternalServerError, errors.New("Monitor broadcast notifications unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, struct {
		HubID         string                                         `json:"hub_id"`
		Notifications []fabricpkg.NodeMonitorBroadcastV2Notification `json:"notifications"`
	}{HubID: hubID, Notifications: notifications})
}

func (h *Handler) relayNodeMonitorBroadcastGet(response http.ResponseWriter,
	request *http.Request, nodeToken, previewID string) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if request.URL.RawQuery != "" || strings.TrimSpace(previewID) != previewID {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast notification request"))
		return
	}
	notification, err := h.fabricService.GetNodeMonitorBroadcastV2Notification(nodeToken, previewID)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("Monitor broadcast notification unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, struct {
		HubID        string                                        `json:"hub_id"`
		Notification *fabricpkg.NodeMonitorBroadcastV2Notification `json:"notification"`
	}{HubID: notification.HubID, Notification: notification})
}

func (h *Handler) relayNodeMonitorBroadcastAuthorize(response http.ResponseWriter,
	request *http.Request, nodeToken, previewID string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if request.URL.RawQuery != "" || strings.TrimSpace(previewID) != previewID {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast authorization request"))
		return
	}
	var input fabricpkg.NodeMonitorBroadcastV2AuthorizeInput
	if err := decodeStrictClientJSON(request.Body, 2048, &input); err != nil ||
		strings.TrimSpace(input.BroadcastID) == "" || strings.TrimSpace(input.OperationID) == "" ||
		strings.TrimSpace(input.BodyDigest) == "" || strings.TrimSpace(input.SnapshotDigest) == "" {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast authorization request"))
		return
	}
	sessionToken, ok := relayNodeMonitorBroadcastSessionToken(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	input.PreviewID = previewID
	delivery, err := h.fabricService.AuthorizeNodeMonitorBroadcastV2Delivery(nodeToken, sessionToken, input)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("current Monitor broadcast delivery authorization unavailable"))
		return
	}
	// The Node route is the only recipient of the native-session context and
	// sealed payload. The Client never receives this response.
	writeJSON(response, http.StatusOK, delivery)
}

func (h *Handler) relayNodeMonitorBroadcastReceipt(response http.ResponseWriter,
	request *http.Request, nodeToken, previewID string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if request.URL.RawQuery != "" || strings.TrimSpace(previewID) != previewID {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast receipt request"))
		return
	}
	var input fabricpkg.NodeMonitorBroadcastV2ReceiptInput
	if err := decodeStrictClientJSON(request.Body, 2048, &input); err != nil ||
		strings.TrimSpace(input.BroadcastID) == "" || strings.TrimSpace(input.SnapshotDigest) == "" ||
		strings.TrimSpace(input.BindingID) == "" || input.BindingEpoch == 0 || strings.TrimSpace(input.State) == "" {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast receipt request"))
		return
	}
	input.PreviewID = previewID
	notification, err := h.fabricService.RecordNodeMonitorBroadcastV2NotificationReceipt(nodeToken, input)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("Monitor broadcast receipt unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, struct {
		HubID        string                                        `json:"hub_id"`
		Notification *fabricpkg.NodeMonitorBroadcastV2Notification `json:"notification"`
	}{HubID: notification.HubID, Notification: notification})
}

func (h *Handler) relayNodeMonitorBroadcastOutcomes(response http.ResponseWriter,
	request *http.Request, nodeToken, previewID string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if request.URL.RawQuery != "" || strings.TrimSpace(previewID) != previewID {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast outcome report"))
		return
	}
	var input fabricpkg.NodeMonitorBroadcastV2OutcomeInput
	if err := decodeStrictClientJSON(request.Body, 16*1024, &input); err != nil ||
		input.BroadcastID == "" || input.OperationID == "" || input.SnapshotDigest == "" ||
		len(input.Results) == 0 || len(input.Results) > 8 {
		writeError(response, http.StatusBadRequest, errors.New("invalid Monitor broadcast outcome report"))
		return
	}
	sessionToken, ok := relayNodeMonitorBroadcastSessionToken(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	input.PreviewID = previewID
	results, err := h.fabricService.ReportNodeMonitorBroadcastV2RecipientOutcomes(nodeToken, sessionToken, input)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("Monitor broadcast outcome report unavailable"))
		return
	}
	hubID, err := h.fabricService.ClientHubID()
	if err != nil || strings.TrimSpace(hubID) == "" {
		writeError(response, http.StatusInternalServerError, errors.New("Monitor broadcast outcome report unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, struct {
		HubID          string                                             `json:"hub_id"`
		PreviewID      string                                             `json:"preview_id"`
		BroadcastID    string                                             `json:"broadcast_id"`
		OperationID    string                                             `json:"operation_id"`
		SnapshotDigest string                                             `json:"snapshot_digest"`
		Results        []fabricpkg.NodeMonitorBroadcastV2RecipientOutcome `json:"results"`
	}{HubID: hubID, PreviewID: previewID, BroadcastID: input.BroadcastID,
		OperationID: input.OperationID, SnapshotDigest: input.SnapshotDigest, Results: results})
}

func relayNodeMonitorBroadcastSessionToken(request *http.Request) (string, bool) {
	values := request.Header.Values("X-Cicada-Session")
	if len(values) != 1 {
		return "", false
	}
	token := values[0]
	if strings.TrimSpace(token) != token || !strings.HasPrefix(token, "cicada_session_") ||
		strings.ContainsAny(token, " \t\r\n,") {
		return "", false
	}
	return token, true
}
