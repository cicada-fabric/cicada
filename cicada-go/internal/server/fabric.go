package server

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

func (h *Handler) fabricEndpoints(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	endpoints, err := h.control.ManagementEndpointCards(control.EndpointListInput{
		Status:    request.URL.Query().Get("status"),
		MachineID: request.URL.Query().Get("machine_id"),
		Harness:   request.URL.Query().Get("harness"),
		Limit:     queryInt(request, "limit", 200),
	})
	if err != nil {
		fabricError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"endpoints": endpoints})
}

func (h *Handler) fabricEndpoint(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/v2/management/endpoints/")
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
		endpoint, err := h.control.ManagementEndpointCard(id)
		if err != nil {
			fabricError(response, err)
			return
		}
		if endpoint == nil {
			writeError(response, http.StatusNotFound, errors.New("endpoint not found"))
			return
		}
		writeJSON(response, http.StatusOK, endpoint)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("endpoint route not found"))
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
	case errors.Is(err, os.ErrNotExist), errors.Is(err, store.ErrEndpointNotFound):
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
