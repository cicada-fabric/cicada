package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

const relayNodeStreamRevalidateInterval = time.Second
const relayNodeStreamWriteTimeout = 5 * time.Second

// Establish deadline and flush support before registering either subscription.
// A wrapper must forward these capabilities or expose its underlying writer.
func relayNodeStreamController(w http.ResponseWriter) (*http.ResponseController, error) {
	current := w
	flushable, deadlineSupported := false, false
	for depth := 0; depth < 32 && current != nil; depth++ {
		if _, ok := current.(interface{ FlushError() error }); ok {
			flushable = true
		}
		if _, ok := current.(http.Flusher); ok {
			flushable = true
		}
		if _, ok := current.(interface{ SetWriteDeadline(time.Time) error }); ok {
			deadlineSupported = true
		}
		if flushable && deadlineSupported {
			break
		}
		next, ok := current.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		current = next.Unwrap()
	}
	if !flushable || !deadlineSupported {
		return nil, http.ErrNotSupported
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(relayNodeStreamWriteTimeout)); err != nil {
		return nil, err
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return controller, nil
}

// Write and flush share one budget, rather than granting each a fresh timeout.
// Clearing only after success permits the 25-second idle keepalive interval.
// A failure retains the deadline for net/http finalization after handler return.
func relayNodeStreamFrame(w http.ResponseWriter, controller *http.ResponseController, frame string) error {
	if err := controller.SetWriteDeadline(time.Now().Add(relayNodeStreamWriteTimeout)); err != nil {
		return err
	}
	n, err := io.WriteString(w, frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	if err := controller.Flush(); err != nil {
		return err
	}
	return controller.SetWriteDeadline(time.Time{})
}

func (h *Handler) relayNodeV2(response http.ResponseWriter, request *http.Request) {
	remainder := strings.Trim(strings.TrimPrefix(request.URL.Path, "/v2/relay/nodes/"), "/")
	parts := strings.Split(remainder, "/")
	monitorBroadcastPath := len(parts) >= 3 && parts[0] != "" &&
		parts[1] == "monitor" && parts[2] == "broadcasts"
	if len(parts) == 4 && parts[1] == "group" && parts[2] == "broadcast" && parts[3] == "snapshot" {
		response.Header().Set("Cache-Control", "no-store")
	}
	if monitorBroadcastPath {
		response.Header().Set("Cache-Control", "no-store")
	}
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	if len(parts) < 2 || len(parts) > 5 || strings.TrimSpace(parts[0]) == "" {
		writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
		return
	}
	nodeID := parts[0]
	token, err := fabricpkg.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	authenticatedNodeID, err := h.fabricService.AuthenticateNode(token)
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	if authenticatedNodeID != nodeID {
		writeError(response, http.StatusForbidden, fabricpkg.ErrPermissionDenied)
		return
	}
	if len(parts) == 4 && parts[1] == "group" && parts[2] == "broadcast" && parts[3] == "snapshot" {
		h.relayNodeGroupBroadcastSnapshot(response, request, token)
		return
	}
	if monitorBroadcastPath {
		h.relayNodeMonitorBroadcastV2(response, request, token, parts[3:])
		return
	}
	if parts[1] == "links" {
		if len(parts) != 4 || parts[2] == "" || parts[3] != "authorization" || request.Method != http.MethodGet {
			writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
			return
		}
		bundle, err := h.fabricService.NodeCommunicationLinkAuthorizationBundle(token, parts[2])
		if err != nil {
			// Do not reveal whether a Link exists, expired, was revoked, or has
			// only one owner's proof to a Node without current bilateral scope.
			writeError(response, http.StatusNotFound, errors.New("current Link authorization unavailable"))
			return
		}
		writeJSON(response, http.StatusOK, bundle)
		return
	}
	if parts[1] == "deliveries" {
		response.Header().Set("Cache-Control", "no-store")
		if len(parts) != 4 || parts[2] == "" || parts[3] != "authorization" {
			writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
			return
		}
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		attemptID := request.URL.Query().Get("attempt_id")
		if attemptID == "" {
			writeError(response, http.StatusBadRequest, errors.New("attempt_id is required"))
			return
		}
		authorization, err := h.fabricService.AuthorizeNodeNativeWake(token, nodeID,
			fabricpkg.RelayNativeWakeAuthorizationInput{MessageID: parts[2], AttemptID: attemptID})
		if err != nil {
			// Current authorization deliberately hides whether a message,
			// attempt, Endpoint, Group join, or binding still exists.
			writeError(response, http.StatusNotFound, errors.New("current native wake authorization unavailable"))
			return
		}
		writeJSON(response, http.StatusOK, authorization)
		return
	}
	if parts[1] == "sealed" {
		if len(parts) == 4 && parts[2] == "requests" && parts[3] != "" && request.Method == http.MethodGet {
			status, err := h.fabricService.NodeSealedLinkRequestStatus(token, parts[3])
			if err != nil {
				writeError(response, http.StatusNotFound, errors.New("sealed request status unavailable"))
				return
			}
			writeJSON(response, http.StatusOK, status)
			return
		}
		if len(parts) == 5 && parts[2] == "requests" && parts[3] != "" && parts[4] == "cancel" &&
			request.Method == http.MethodPost {
			var input struct {
				Reason string `json:"reason,omitempty"`
			}
			if err := decodeStrictClientJSON(request.Body, 1024, &input); err != nil {
				writeError(response, http.StatusBadRequest, errors.New("invalid sealed request cancellation"))
				return
			}
			status, err := h.fabricService.CancelNodeSealedLinkRequest(token, parts[3], input.Reason)
			if err != nil {
				if errors.Is(err, store.ErrRelayRequestTerminal) {
					writeError(response, http.StatusConflict, err)
				} else {
					writeError(response, http.StatusNotFound, errors.New("sealed request cancellation unavailable"))
				}
				return
			}
			writeJSON(response, http.StatusOK, status)
			return
		}
		if len(parts) == 4 && parts[3] == "authorization" && request.Method == http.MethodGet &&
			parts[2] != "" {
			attemptID := request.URL.Query().Get("attempt_id")
			if attemptID == "" {
				writeError(response, http.StatusBadRequest, errors.New("attempt_id is required"))
				return
			}
			authorization, err := h.fabricService.AuthorizeNodeSealedDelivery(token, parts[2], attemptID)
			if err != nil {
				// A stale attempt, revoked Link, or wrong Node must all be
				// indistinguishable to the caller.
				writeError(response, http.StatusNotFound, errors.New("current sealed delivery authorization unavailable"))
				return
			}
			writeJSON(response, http.StatusOK, authorization)
			return
		}
		if len(parts) != 3 {
			writeError(response, http.StatusNotFound, errors.New("sealed Node route not found"))
			return
		}
		h.relayNodeSealedV2(response, request, nodeID, token, parts[2])
		return
	}
	if parts[1] == "jobs" {
		if len(parts) == 2 || validNodeApprovalRoute(parts) || len(parts) == 4 &&
			parts[2] != "" && (parts[3] == "claim" || parts[3] == "result") {
			writeError(response, http.StatusUpgradeRequired,
				errors.New("MIGRATION_BLOCKED: Node Worker management requires Owner-approved Node-Control encryption"))
			return
		}
		if len(parts) == 5 && parts[2] != "" && parts[3] == "snapshot" &&
			(parts[4] == "upload" || parts[4] == "download") {
			direction := nodewire.SnapshotDirectionUpload
			if parts[4] == "download" {
				direction = nodewire.SnapshotDirectionDownload
			}
			h.relayNodeWorkerSnapshotStream(response, request, nodeID, parts[2], direction, token)
			return
		}
		if validNodeApprovalRoute(parts) {
			h.relayNodeWorkerApprovals(response, request, nodeID, token, parts)
			return
		}
		if len(parts) == 4 && parts[2] != "" && parts[3] == "snapshot" && request.Method == http.MethodPost {
			h.relayNodeWorkerSnapshot(response, request, nodeID, parts[2], "", token)
			return
		}
		if len(parts) == 5 && parts[2] != "" && parts[3] == "snapshot" && parts[4] != "" && request.Method == http.MethodGet {
			h.relayNodeWorkerSnapshot(response, request, nodeID, parts[2], parts[4], token)
			return
		}
		h.relayNodeWorkerJobs(response, request, nodeID, token, parts)
		return
	}
	if parts[1] == "local" {
		if len(parts) != 3 {
			writeError(response, http.StatusNotFound, errors.New("local Node route not found"))
			return
		}
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		switch parts[2] {
		case "authorize":
			var input fabricpkg.LocalDeliveryAuthorizationInput
			if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
				writeError(response, http.StatusBadRequest, errors.New("invalid local authorization request"))
				return
			}
			// The native Session credential is deliberately carried in a separate
			// header from the Node credential and is never copied into the body.
			sessionToken := strings.TrimSpace(request.Header.Get("X-Cicada-Session"))
			if sessionToken == "" || strings.ContainsAny(sessionToken, " \t\r\n") {
				writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
				return
			}
			authorization, err := h.fabricService.AuthorizeNodeLocalDelivery(token, sessionToken, input)
			if errors.Is(err, store.ErrLocalDeliveryNotLocal) {
				response.Header().Set("Cache-Control", "no-store")
				writeJSON(response, http.StatusConflict, map[string]string{"code": "NOT_LOCAL"})
				return
			}
			if errors.Is(err, store.ErrLocalDeliveryAmbiguousTarget) {
				response.Header().Set("Cache-Control", "no-store")
				writeJSON(response, http.StatusConflict, map[string]string{"code": "AMBIGUOUS_TARGET"})
				return
			}
			if err != nil {
				// Membership, binding, lease, owner and key failures intentionally
				// share one response so this route cannot enumerate Group members.
				writeError(response, http.StatusNotFound, errors.New("local authorization unavailable"))
				return
			}
			response.Header().Set("Cache-Control", "no-store")
			writeJSON(response, http.StatusOK, authorization)
			return
		case "revalidate":
			var input fabricpkg.LocalDeliveryRevalidationInput
			if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
				writeError(response, http.StatusBadRequest, errors.New("invalid local revalidation request"))
				return
			}
			authorization, err := h.fabricService.RevalidateNodeLocalDelivery(token, input)
			if errors.Is(err, store.ErrSealedTaskHandoffPending) {
				response.Header().Set("Cache-Control", "no-store")
				writeJSON(response, http.StatusTooEarly, map[string]string{"code": "HANDOFF_PENDING"})
				return
			}
			if err != nil {
				writeError(response, http.StatusNotFound, errors.New("local authorization unavailable"))
				return
			}
			response.Header().Set("Cache-Control", "no-store")
			writeJSON(response, http.StatusOK, authorization)
			return
		default:
			writeError(response, http.StatusNotFound, errors.New("local Node route not found"))
			return
		}
	}
	if len(parts) != 2 {
		writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
		return
	}
	switch parts[1] {
	case "heartbeat":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Status       string         `json:"status,omitempty"`
			Capabilities map[string]any `json:"capabilities,omitempty"`
		}
		if err := decodeStrictClientJSON(request.Body, 64*1024, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid Node heartbeat"))
			return
		}
		if err := h.fabricService.RecordBoundNodeMachineHeartbeat(token, input.Status, input.Capabilities); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, store.ErrNodeWorkerNotAuthorized) || errors.Is(err, store.ErrNodeMachineOwnershipConflict) {
				status = http.StatusUnauthorized
			} else if errors.Is(err, store.ErrOwnerNodeUnavailable) {
				status = http.StatusConflict
			} else if !errors.Is(err, store.ErrNodeMachineHeartbeatInput) {
				status = http.StatusInternalServerError
				err = errors.New("Node heartbeat could not be recorded")
			}
			writeError(response, status, err)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	case "events":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		h.relayNodeEvents(response, request, nodeID, token)
	case "claim":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.NodeClaimInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		deliveries, err := h.fabricService.ClaimNodeDeliveries(nodeID, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"deliveries": deliveries})
	case "receipts":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.NodeReceiptInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		receipt, err := h.fabricService.RecordNodeReceipt(nodeID, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, receipt)
	default:
		writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
	}
}

func (h *Handler) relayNodeWorkerJobs(response http.ResponseWriter, request *http.Request, nodeID, token string, parts []string) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Control service is unavailable"))
		return
	}
	digest := fabricpkg.HashSessionCredential(token)
	if len(parts) == 2 {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		jobs, err := h.control.BoundNodeMachineJobs(digest, nodeID)
		if err != nil {
			relayNodeJobError(response, h, nodeID, token, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"jobs": jobs})
		return
	}
	if len(parts) != 4 || parts[2] == "" || (parts[3] != "claim" && parts[3] != "result") {
		writeError(response, http.StatusNotFound, errors.New("Node Worker route not found"))
		return
	}
	workerID := parts[2]
	switch parts[3] {
	case "claim":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct{}
		if err := decodeStrictClientJSON(request.Body, 64, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("Node Worker claim body must be an empty JSON object"))
			return
		}
		job, err := h.control.ClaimBoundNodeRemoteWorker(digest, nodeID, workerID)
		if err != nil {
			relayNodeJobError(response, h, nodeID, token, err)
			return
		}
		writeJSON(response, http.StatusOK, job)
	case "result":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Attempt           int    `json:"attempt"`
			Status            string `json:"status"`
			Summary           string `json:"summary,omitempty"`
			ThreadID          string `json:"thread_id,omitempty"`
			Error             string `json:"error,omitempty"`
			WorkspaceRevision string `json:"workspace_revision,omitempty"`
		}
		if err := decodeStrictClientJSON(request.Body, 64*1024, &input); err != nil || input.Attempt <= 0 {
			writeError(response, http.StatusBadRequest, errors.New("invalid Node Worker result"))
			return
		}
		worker, err := h.control.CompleteBoundNodeRemoteWorker(digest, nodeID, workerID, input.Attempt,
			input.Status, input.Summary, input.ThreadID, input.Error, input.WorkspaceRevision)
		if err != nil {
			relayNodeJobError(response, h, nodeID, token, err)
			return
		}
		writeJSON(response, http.StatusOK, worker)
	}
}

func relayNodeJobError(response http.ResponseWriter, h *Handler, nodeID, token string, err error) {
	switch {
	case errors.Is(err, store.ErrNodeWorkerNotAuthorized):
		if !h.relayNodeCredentialCurrent(nodeID, token) {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			return
		}
		writeError(response, http.StatusNotFound, errors.New("Node Worker is unavailable"))
	case errors.Is(err, store.ErrNodeWorkerUnavailable), errors.Is(err, control.ErrWorkerUnavailable):
		writeError(response, http.StatusConflict, err)
	case errors.Is(err, control.ErrPermissionDenied), errors.Is(err, control.ErrPermissionApproval):
		writeError(response, http.StatusForbidden, err)
	case errors.Is(err, os.ErrNotExist):
		writeError(response, http.StatusNotFound, errors.New("Node Worker is unavailable"))
	default:
		writeError(response, http.StatusInternalServerError, errors.New("Node Worker request could not be completed"))
	}
}

// relayNodeEvents keeps a Node-initiated HTTPS connection open. Hints contain
// no message content and never replace the durable claim/receipt protocol.
func (h *Handler) relayNodeEvents(response http.ResponseWriter, request *http.Request, nodeID, token string) {
	if !h.relayNodeCredentialCurrent(nodeID, token) || !nodePQTransportCurrent(request.Context()) {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	controller, err := relayNodeStreamController(response)
	if err != nil {
		// Do not attempt an unbounded error-body write through this writer.
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	releaseStream, admitted := h.fabricService.AdmitNodeSSEStream(nodeID)
	if !admitted {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Retry-After", "1")
		response.WriteHeader(http.StatusTooManyRequests)
		_ = relayNodeStreamFrame(response, controller, "Node event stream capacity is full; retry later.\n")
		return
	}
	defer releaseStream()
	events, unsubscribe := h.fabricService.SubscribeNodeEvents(nodeID)
	defer unsubscribe()
	spaceEvents, unsubscribeSpaces := h.fabricService.SubscribeNodeSpaceEvents(nodeID)
	defer unsubscribeSpaces()
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache, no-transform")
	response.Header().Set("X-Accel-Buffering", "no")
	if err := relayNodeStreamFrame(response, controller, "event: ready\ndata: claim\n\n"); err != nil {
		return
	}
	lastCredentialCheck := time.Now()
	credentialCurrentIfDue := func() bool {
		if !nodePQTransportValidityCurrent(request.Context()) {
			return false
		}
		if time.Since(lastCredentialCheck) < relayNodeStreamRevalidateInterval {
			return true
		}
		lastCredentialCheck = time.Now()
		return h.relayNodeCredentialCurrent(nodeID, token) && nodePQTransportCurrent(request.Context())
	}
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	var transportRecheck <-chan time.Time
	if _, strict := request.Context().Value(nodeTransportCheckKey{}).(nodeTransportCheck); strict {
		ticker := time.NewTicker(relayNodeStreamRevalidateInterval)
		defer ticker.Stop()
		transportRecheck = ticker.C
	}
	for {
		select {
		case <-request.Context().Done():
			return
		case <-transportRecheck:
			if !nodePQTransportCurrent(request.Context()) {
				return
			}
		case <-events:
			// An already-open stream is still an authenticated Node capability.
			// Check at most once per second during active streams so revocation
			// takes effect promptly without making wake traffic drive unbounded DB
			// reads. Idle streams are rechecked by the keepalive timer below.
			if !credentialCurrentIfDue() {
				return
			}
			if err := relayNodeStreamFrame(response, controller, "event: wake\ndata: claim\n\n"); err != nil {
				return
			}
		case <-spaceEvents:
			// A space hint carries no Group, reader or record coordinates. The
			// Node must reconcile its own current subscriptions through Guard.
			if !credentialCurrentIfDue() {
				return
			}
			if err := relayNodeStreamFrame(response, controller, "event: space\ndata: sync\n\n"); err != nil {
				return
			}
		case <-heartbeat.C:
			// Credential rotation/revocation fences an already-open stream.
			if !h.relayNodeCredentialCurrent(nodeID, token) || !nodePQTransportCurrent(request.Context()) {
				return
			}
			lastCredentialCheck = time.Now()
			if err := relayNodeStreamFrame(response, controller, ": keepalive\n\n"); err != nil {
				return
			}
		}
	}
}

func (h *Handler) relayNodeCredentialCurrent(nodeID, token string) bool {
	currentNode, err := h.fabricService.AuthenticateNode(token)
	return err == nil && currentNode == nodeID
}
