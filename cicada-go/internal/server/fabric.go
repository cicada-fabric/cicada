package server

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) fabricEndpoints(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		endpoints, err := h.control.DirectoryCards(control.EndpointListInput{
			RequesterEndpointID: request.URL.Query().Get("requester_endpoint_id"),
			Status:              request.URL.Query().Get("status"),
			MachineID:           request.URL.Query().Get("machine_id"),
			Owner:               request.URL.Query().Get("owner"),
			Harness:             request.URL.Query().Get("harness"),
			Limit:               queryInt(request, "limit", 200),
		})
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"endpoints": endpoints})
	case http.MethodPost:
		var input control.EndpointJoinInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		endpoint, err := h.control.JoinEndpoint(input)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, endpoint)
	default:
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (h *Handler) fabricEndpoint(response http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/v1/endpoints/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("endpoint not found"))
		return
	}
	id, err := url.PathUnescape(parts[0])
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid endpoint id"))
		return
	}
	if len(parts) == 1 {
		switch request.Method {
		case http.MethodGet:
			endpoint, err := h.control.Endpoint(id)
			if err != nil {
				fabricError(response, err)
				return
			}
			if endpoint == nil {
				writeError(response, http.StatusNotFound, errors.New("endpoint not found"))
				return
			}
			writeJSON(response, http.StatusOK, endpoint)
		case http.MethodDelete:
			endpoint, err := h.control.LeaveEndpoint(id)
			if err != nil {
				fabricError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, endpoint)
		default:
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
		return
	}
	if len(parts) != 2 {
		writeError(response, http.StatusNotFound, errors.New("endpoint route not found"))
		return
	}
	switch parts[1] {
	case "heartbeat":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Status string `json:"status"`
		}
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		endpoint, err := h.control.HeartbeatEndpoint(id, input.Status)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, endpoint)
	case "leave":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		endpoint, err := h.control.LeaveEndpoint(id)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, endpoint)
	case "messages":
		if request.Method != http.MethodGet && request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		limit := queryInt(request, "limit", 50)
		if request.Method == http.MethodPost || request.URL.Query().Get("claim") == "true" {
			messages, err := h.control.ClaimFabricMessages(id, limit)
			if err != nil {
				fabricError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"messages": messages})
			return
		}
		messages, err := h.control.FabricMessages(id, request.URL.Query().Get("status"), limit)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"messages": messages})
	default:
		writeError(response, http.StatusNotFound, errors.New("endpoint route not found"))
	}
}

func (h *Handler) fabric(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/v1/fabric/list":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		endpoints, err := h.control.DirectoryCards(control.EndpointListInput{
			RequesterEndpointID: request.URL.Query().Get("endpoint_id"),
			Status:              request.URL.Query().Get("status"),
			MachineID:           request.URL.Query().Get("machine_id"),
			Harness:             request.URL.Query().Get("harness"),
			Limit:               queryInt(request, "limit", 200),
		})
		if err != nil {
			fabricError(response, err)
			return
		}
		machines, err := h.control.Machines()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"machines": machines, "endpoints": endpoints})
	case "/v1/fabric/whoami":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		card, err := h.control.WhoAmI(request.URL.Query().Get("endpoint_id"))
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, card)
	case "/v1/fabric/events":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		after := int64(queryInt(request, "after", 0))
		events, err := h.control.FabricEvents(request.URL.Query().Get("endpoint_id"), after, queryInt(request, "limit", 200))
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"events": events})
	case "/v1/fabric/resolve", "/v1/fabric/inspect":
		if request.Method != http.MethodGet && request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		input := control.EndpointResolveInput{
			Query:               request.URL.Query().Get("q"),
			RequesterEndpointID: request.URL.Query().Get("endpoint_id"),
			MachineID:           request.URL.Query().Get("machine_id"),
			Workspace:           request.URL.Query().Get("workspace"),
		}
		if request.Method == http.MethodPost {
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
		}
		if request.URL.Path == "/v1/fabric/inspect" {
			card, err := h.control.InspectEndpoint(input)
			if err != nil {
				fabricError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, card)
			return
		}
		endpoint, err := h.control.InspectEndpoint(input)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, endpoint)
	case "/v1/fabric/send":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input control.FabricSendInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		message, err := h.control.SendFabricMessage(input)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, message)
	case "/v1/fabric/ask":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input control.FabricAskInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		message, err := h.control.AskFabric(input)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, message)
	case "/v1/fabric/reply":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input control.FabricReplyInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		message, err := h.control.ReplyFabric(input)
		if err != nil {
			fabricError(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, message)
	default:
		if strings.HasPrefix(request.URL.Path, "/v1/fabric/messages/") && request.Method == http.MethodGet {
			id, err := url.PathUnescape(strings.TrimPrefix(request.URL.Path, "/v1/fabric/messages/"))
			if err != nil || id == "" || strings.Contains(id, "/") {
				writeError(response, http.StatusNotFound, errors.New("fabric message not found"))
				return
			}
			message, err := h.control.FabricMessage(id)
			if err != nil {
				fabricError(response, err)
				return
			}
			if message == nil {
				writeError(response, http.StatusNotFound, errors.New("fabric message not found"))
				return
			}
			writeJSON(response, http.StatusOK, message)
			return
		}
		writeError(response, http.StatusNotFound, errors.New("fabric route not found"))
	}
}

func queryInt(request *http.Request, name string, fallback int) int {
	value := request.URL.Query().Get(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func fabricError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, control.ErrEndpointAmbiguous):
		var ambiguity *control.EndpointAmbiguityError
		if errors.As(err, &ambiguity) {
			addresses := make([]string, 0, len(ambiguity.Candidates))
			for _, endpoint := range ambiguity.Candidates {
				addresses = append(addresses, endpoint.Address)
			}
			writeJSON(response, http.StatusConflict, map[string]any{
				"error": err.Error(), "query": ambiguity.Query, "candidates": addresses,
			})
			return
		}
		status = http.StatusConflict
	case errors.Is(err, control.ErrPermissionDenied), errors.Is(err, control.ErrPermissionApproval):
		status = http.StatusForbidden
	}
	writeError(response, status, err)
}

// Heartbeats may use an empty object or no body at all.
func readOptionalJSON(request *http.Request, value any) error {
	if request.Body == nil || request.ContentLength == 0 {
		return nil
	}
	return readJSON(request, value)
}
