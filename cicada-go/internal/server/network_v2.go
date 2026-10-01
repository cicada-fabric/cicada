package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// The Network credential is independent of the Group session and Node
// credentials. A scope in the URL selects an existing registration; it never
// supplies the caller identity or creates membership.
func networkCredentialFromAuthorization(value string) (string, error) {
	const scheme = "Cicada-Network-Session "
	if !strings.HasPrefix(value, scheme) {
		return "", fabricpkg.ErrUnauthenticated
	}
	token := strings.TrimPrefix(value, scheme)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n") {
		return "", fabricpkg.ErrUnauthenticated
	}
	return token, nil
}

func (h *Handler) fabricV2Network(response http.ResponseWriter, request *http.Request) {
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	if request.URL.Path == "/v2/fabric/node/networks/join" || request.URL.Path == "/v2/fabric/node/networks/renew" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		token, err := fabricpkg.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
		if err != nil {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			return
		}
		var joined *fabricpkg.NetworkJoinResult
		if request.URL.Path == "/v2/fabric/node/networks/join" {
			var input fabricpkg.NetworkJoinInput
			if err := decodeStrictClientJSON(request.Body, 64*1024, &input); err != nil {
				writeError(response, http.StatusBadRequest, errors.New("invalid Network Join request"))
				return
			}
			joined, err = h.fabricService.JoinNetworkForNodeCredential(token, input)
		} else {
			var input fabricpkg.NetworkRenewInput
			if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
				writeError(response, http.StatusBadRequest, errors.New("invalid Network Renew request"))
				return
			}
			joined, err = h.fabricService.RenewNetworkForNodeCredential(token, input)
		}
		if err != nil {
			networkV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, joined)
		return
	}

	remainder := strings.TrimPrefix(request.URL.Path, "/v2/fabric/networks/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 3 && parts[0] != "" && parts[1] == "tasks" {
		h.fabricV2NetworkTask(response, request, parts[0], parts[2])
		return
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "direct" {
		h.fabricV2NetworkDirectSession(response, request, parts[0], parts[2])
		return
	}
	if len(parts) == 3 && parts[0] != "" && parts[1] == "broadcasts" {
		h.fabricV2NetworkBroadcast(response, request, parts[0], parts[2])
		return
	}
	if len(parts) != 2 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("Network route not found"))
		return
	}
	networkID, operation := parts[0], parts[1]
	if operation != "whoami" && operation != "directory" && operation != "resolve" && operation != "leave" && operation != "invitations" {
		writeError(response, http.StatusNotFound, errors.New("Network route not found"))
		return
	}
	token, err := networkCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	actor, err := h.fabricService.AuthenticateForNetwork(token, networkID)
	if err != nil {
		networkV2Error(response, err)
		return
	}
	switch operation {
	case "whoami":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"network_id": actor.NetworkID,
			"endpoint_id": actor.EndpointID, "principal_id": actor.PrincipalID})
	case "invitations":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			TargetOwnerID string   `json:"target_owner_id"`
			Grants        []string `json:"grants"`
			TTLSeconds    int      `json:"ttl_seconds"`
		}
		if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil || strings.TrimSpace(input.TargetOwnerID) == "" {
			writeError(response, http.StatusBadRequest, errors.New("invalid Network invitation request"))
			return
		}
		token, expiresAt, err := h.fabricService.IssueNetworkInvitation(actor, input.TargetOwnerID, input.Grants, input.TTLSeconds)
		if err != nil {
			networkV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, map[string]any{"network_id": networkID,
			"target_owner_id": input.TargetOwnerID, "invitation_token": token,
			"grants": input.Grants, "expires_at": expiresAt})
	case "directory":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		cards, err := h.fabricService.ListNetwork(actor, queryInt(request, "limit", 100))
		if err != nil {
			networkV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"endpoints": cards})
	case "resolve":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Query string `json:"query"`
		}
		if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil || strings.TrimSpace(input.Query) == "" {
			writeError(response, http.StatusBadRequest, errors.New("query is required"))
			return
		}
		card, err := h.fabricService.ResolveNetwork(actor, input.Query)
		if err != nil {
			networkV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, card)
	case "leave":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Reason string `json:"reason"`
		}
		if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid Network Leave request"))
			return
		}
		if err := h.fabricService.LeaveNetwork(actor, input.Reason); err != nil {
			networkV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"status": "left", "network_id": networkID})
	}
}

// New Network routes expose only stable denial classes. An invitation,
// membership or hidden Endpoint must not become an existence oracle.
func networkV2Error(response http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrRelayResourceExhausted) {
		var limit *store.RelayAdmissionError
		if errors.As(err, &limit) && limit.RetryAfterSeconds > 0 {
			response.Header().Set("Retry-After", strconv.Itoa(limit.RetryAfterSeconds))
		}
		writeError(response, http.StatusTooManyRequests, errors.New("Network direct relay is busy"))
		return
	}
	switch {
	case errors.Is(err, store.ErrNetworkTaskPending):
		// A Relay SEND may become READY just before its sealed Task metadata is
		// committed. Nodes must defer this exact attempt without opening, ACKing
		// or injecting its ciphertext.
		writeError(response, http.StatusTooEarly, errors.New("Network Task route metadata is pending"))
	case errors.Is(err, store.ErrNetworkBroadcastPending):
		writeError(response, http.StatusTooEarly, errors.New("Network Broadcast route metadata is pending"))
	case errors.Is(err, fabricpkg.ErrUnauthenticated):
		writeError(response, http.StatusUnauthorized, errors.New("Network session is unavailable"))
	case errors.Is(err, fabricpkg.ErrAmbiguous):
		writeError(response, http.StatusConflict, errors.New("AMBIGUOUS Network nickname"))
	case errors.Is(err, fabricpkg.ErrNotFoundOrNotAuthorized):
		writeError(response, http.StatusNotFound, errors.New("Network resource unavailable"))
	case errors.Is(err, store.ErrNetworkDirectKeyUnavailable):
		writeError(response, http.StatusNotFound, errors.New("Network resource unavailable"))
	case errors.Is(err, fabricpkg.ErrPermissionDenied), errors.Is(err, store.ErrNetworkPermission),
		errors.Is(err, store.ErrNetworkConsent):
		writeError(response, http.StatusForbidden, errors.New("Network operation denied"))
	case errors.Is(err, store.ErrNetworkConflict), errors.Is(err, store.ErrNetworkMigration),
		errors.Is(err, fabricpkg.ErrConflict), errors.Is(err, store.ErrRelayCausalBudget),
		errors.Is(err, store.ErrRelayIdempotencyConflict), errors.Is(err, store.ErrRelayMessageConflict),
		errors.Is(err, store.ErrRelayRequestTerminal), errors.Is(err, store.ErrNetworkTaskAlreadyClaimed),
		errors.Is(err, store.ErrNetworkTaskExpired), errors.Is(err, store.ErrNetworkTaskLeaseExpired),
		errors.Is(err, store.ErrNetworkTaskUnavailable), errors.Is(err, store.ErrNetworkBroadcastSnapshotChanged),
		errors.Is(err, store.ErrNetworkBroadcastRecipientLimit), errors.Is(err, store.ErrNetworkBroadcastCandidateLimit),
		errors.Is(err, store.ErrNetworkBroadcastQuota):
		writeError(response, http.StatusConflict, errors.New("Network scope conflict"))
	case errors.Is(err, store.ErrNetworkBroadcastExpired), errors.Is(err, store.ErrNetworkBroadcastUnavailable):
		writeError(response, http.StatusNotFound, errors.New("Network Broadcast unavailable"))
	default:
		writeError(response, http.StatusInternalServerError, errors.New("Network operation failed"))
	}
}
