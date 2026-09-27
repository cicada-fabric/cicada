package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func isFabricSessionPath(path string) bool {
	return (strings.HasPrefix(path, "/v2/fabric/") && path != "/v2/fabric/join") || isArtifactV2Path(path)
}

func (h *Handler) fabricV2(response http.ResponseWriter, request *http.Request) {
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	if request.URL.Path == "/v2/fabric/node/join" {
		h.fabricV2NodeJoin(response, request)
		return
	}
	if request.URL.Path == "/v2/fabric/node/networks/join" || request.URL.Path == "/v2/fabric/node/networks/renew" || strings.HasPrefix(request.URL.Path, "/v2/fabric/networks/") {
		h.fabricV2Network(response, request)
		return
	}
	if request.URL.Path == "/v2/fabric/join" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.JoinInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		// Public enrollment never accepts a model supplied existing Principal.
		// Rejoin recovers it from the native-session/Endpoint association.
		input.PrincipalID = ""
		input.LeaseOwner = ""
		result, err := h.fabricService.Join(input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, result)
		return
	}
	token, err := fabricpkg.SessionCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	// The header selects one already joined Group; it never supplies identity
	// or grants. The Session credential fixes the native Endpoint/Principal.
	actor, err := h.fabricService.AuthenticateForGroup(token, request.Header.Get("Cicada-Group-Scope"))
	if err != nil {
		if errors.Is(err, fabricpkg.ErrUnauthenticated) {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		} else {
			fabricV2Error(response, err)
		}
		return
	}
	switch request.URL.Path {
	case "/v2/fabric/send", "/v2/fabric/ask", "/v2/fabric/reply":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		writeError(response, http.StatusGone,
			errors.New("plaintext Fabric peer writes are retired; use sealed Node delivery"))
	case "/v2/fabric/whoami":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		card, err := h.fabricService.WhoAmI(actor)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, card)
	case "/v2/fabric/members", "/v2/fabric/list":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		cards, err := h.fabricService.List(actor, request.URL.Query().Get("status"), request.URL.Query().Get("node_id"), request.URL.Query().Get("harness"), queryInt(request, "limit", 200))
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"endpoints": cards})
	case "/v2/fabric/find", "/v2/fabric/resolve", "/v2/fabric/inspect":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.ResolveInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		card, err := h.fabricService.Resolve(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, card)
	case "/v2/fabric/heartbeat":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		renewed, err := h.fabricService.RenewForGroup(token, actor.GroupID, 0)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, renewed)
	case "/v2/fabric/leave":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Reason string `json:"reason"`
		}
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		if err := h.fabricService.Leave(actor, input.Reason); err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"status": "left"})
	case "/v2/fabric/leave-group":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Reason string `json:"reason"`
		}
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		remaining, err := h.fabricService.LeaveGroup(actor, input.Reason)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"status": "left_group", "left_group_id": actor.GroupID, "remaining_group_id": remaining})
	case "/v2/fabric/receive":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.ReceiveInput
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		result, err := h.fabricService.Receive(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case "/v2/fabric/federate":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		writeError(response, http.StatusGone, fabricpkg.ErrFederationBodyWritesRetired)
	default:
		if request.URL.Path == "/v2/fabric/endpoint-keys" || strings.HasPrefix(request.URL.Path, "/v2/fabric/endpoint-keys/") {
			h.endpointKeysV2(response, request, actor)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/leases/") {
			h.fabricV2ResourceLease(response, request, actor)
			return
		}
		if request.URL.Path == "/v2/fabric/tasks" || strings.HasPrefix(request.URL.Path, "/v2/fabric/tasks/") {
			h.fabricV2Task(response, request, actor)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/requests/") {
			h.fabricV2Request(response, request, actor)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/representatives/") {
			h.fabricV2Representative(response, request, actor)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/v2/fabric/federation/") {
			h.fabricV2Federation(response, request, actor)
			return
		}
		writeError(response, http.StatusNotFound, errors.New("fabric route not found"))
	}
}

// fabricV2NodeJoin is the guest-owner enrollment path. The request schema
// intentionally excludes owner_id, node_id, principal_id, endpoint_id, and
// lease_owner: identity comes from the active owner-bound Node credential and
// the Node's local Harness adapter. The Hub authenticates that Node boundary,
// but cannot independently prove a native Session ID supplied by the adapter.
func (h *Handler) fabricV2NodeJoin(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeToken, err := fabricpkg.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	var body struct {
		GroupID           string         `json:"group_id"`
		EndpointName      string         `json:"endpoint_name,omitempty"`
		Harness           string         `json:"harness"`
		NativeSessionID   string         `json:"native_session_id"`
		Workspace         string         `json:"workspace,omitempty"`
		Capabilities      map[string]any `json:"capabilities,omitempty"`
		Tags              []string       `json:"tags,omitempty"`
		LeaseSeconds      int            `json:"lease_seconds,omitempty"`
		ContextContinuity string         `json:"context_continuity,omitempty"`
	}
	if err := readJSON(request, &body); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid Node Fabric join request"))
		return
	}
	joined, err := h.fabricService.JoinForNodeCredential(nodeToken, fabricpkg.JoinInput{
		GroupID: body.GroupID, EndpointName: body.EndpointName, Harness: body.Harness,
		NativeSessionID: body.NativeSessionID, Workspace: body.Workspace,
		Capabilities: body.Capabilities, Tags: body.Tags, LeaseSeconds: body.LeaseSeconds,
		ContextContinuity: body.ContextContinuity,
	})
	if err != nil {
		fabricV2Error(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, joined)
}

func (h *Handler) fabricV2Representative(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	remainder := strings.Trim(strings.TrimPrefix(request.URL.Path, "/v2/fabric/representatives/"), "/")
	if request.Method != http.MethodPost || !strings.HasSuffix(remainder, "/claim") {
		writeError(response, http.StatusNotFound, errors.New("representative route not found"))
		return
	}
	assignmentID := strings.Trim(strings.TrimSuffix(remainder, "/claim"), "/")
	var input struct {
		LeaseSeconds int `json:"lease_seconds"`
	}
	if err := readOptionalJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	result, err := h.fabricService.ClaimRepresentation(actor, assignmentID, input.LeaseSeconds)
	if err != nil {
		fabricV2Error(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *Handler) fabricV2Federation(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	remainder := strings.Trim(strings.TrimPrefix(request.URL.Path, "/v2/fabric/federation/"), "/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && request.Method == http.MethodGet {
		result, err := h.fabricService.FederationRequest(actor, parts[0])
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
		return
	}
	if len(parts) != 2 || request.Method != http.MethodPost {
		writeError(response, http.StatusNotFound, errors.New("federation route not found"))
		return
	}
	requestID := parts[0]
	switch parts[1] {
	case "accept":
		result, err := h.fabricService.AcceptFederation(actor, requestID)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, result)
	case "result", "accept-result":
		writeError(response, http.StatusGone, fabricpkg.ErrFederationBodyWritesRetired)
	default:
		writeError(response, http.StatusNotFound, errors.New("federation route not found"))
	}
}

func (h *Handler) fabricV2Request(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	remainder := strings.Trim(strings.TrimPrefix(request.URL.Path, "/v2/fabric/requests/"), "/")
	if remainder == "" {
		writeError(response, http.StatusNotFound, errors.New("fabric request not found"))
		return
	}
	if strings.HasSuffix(remainder, "/cancel") {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		requestID := strings.TrimSuffix(remainder, "/cancel")
		requestID = strings.Trim(requestID, "/")
		var body struct {
			Reason string `json:"reason"`
		}
		if err := readOptionalJSON(request, &body); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		result, err := h.fabricService.CancelRequest(actor, fabricpkg.RequestCancelInput{RequestID: requestID, Reason: body.Reason})
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, result)
		return
	}
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	result, err := h.fabricService.Request(actor, remainder)
	if err != nil {
		fabricV2Error(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func fabricV2Error(response http.ResponseWriter, err error) {
	var admission *fabricpkg.ResourceExhaustedError
	if errors.As(err, &admission) {
		retryAfter := admission.RetryAfterDuration()
		retryAfterSeconds := int(retryAfter / time.Second)
		if retryAfter%time.Second != 0 {
			retryAfterSeconds++
		}
		if retryAfterSeconds < 1 {
			retryAfterSeconds = 1
		}
		response.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds))
		writeJSON(response, http.StatusTooManyRequests, map[string]any{
			"error":               err.Error(),
			"code":                "RESOURCE_EXHAUSTED",
			"scope":               admission.Scope,
			"limit":               admission.Limit,
			"pending":             admission.Pending,
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, fabricpkg.ErrUnauthenticated):
		status = http.StatusUnauthorized
	case errors.Is(err, fabricpkg.ErrPermissionDenied), errors.Is(err, fabricpkg.ErrStaleBinding), errors.Is(err, fabricpkg.ErrCrossGroupDirectDenied):
		status = http.StatusForbidden
	case errors.Is(err, fabricpkg.ErrNotFoundOrNotAuthorized):
		status = http.StatusNotFound
	case errors.Is(err, fabricpkg.ErrAmbiguous), errors.Is(err, fabricpkg.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, fabricpkg.ErrRequestTerminal):
		status = http.StatusConflict
	case errors.Is(err, fabricpkg.ErrFederationBodyWritesRetired):
		status = http.StatusGone
	case errors.Is(err, store.ErrSharedTaskHandoffMissingArtifact):
		status = http.StatusConflict
	}
	writeError(response, status, err)
}
