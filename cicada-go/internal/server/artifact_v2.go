package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// NewArtifactV2Handler exposes the same Service guard as the embedded server.
// It is useful for Fabric-only deployments and for callers that mount the
// artifact router under their own mux.
func NewArtifactV2Handler(service *fabricpkg.Service) http.Handler {
	return &Handler{fabricService: service}
}

// ArtifactV2 handles /v2/artifacts and /v2/fabric/artifacts routes.  The main
// server calls this method from its route switch; keeping the implementation
// here prevents HTTP from growing a separate permission path.
func (h *Handler) ArtifactV2(response http.ResponseWriter, request *http.Request) {
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	token, err := fabricpkg.SessionCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	actor, err := h.fabricService.AuthenticateForGroup(token, request.Header.Get("Cicada-Group-Scope"))
	if err != nil {
		if errors.Is(err, fabricpkg.ErrUnauthenticated) {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		} else {
			artifactV2Error(response, err)
		}
		return
	}
	remainder, matched := artifactV2Remainder(request.URL.Path)
	if !matched {
		writeError(response, http.StatusNotFound, errors.New("artifact ref route not found"))
		return
	}
	if remainder == "" {
		h.artifactV2Collection(response, request, actor)
		return
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) == 1 {
		if request.Method == http.MethodGet {
			h.artifactV2Read(response, request, actor, parts[0])
			return
		}
		if request.Method == http.MethodPost {
			// POST /v2/artifacts/<ref>/revoke is intentionally a separate
			// action from metadata/content reads.
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
	}
	if len(parts) == 2 && parts[1] == "read" && request.Method == http.MethodGet {
		h.artifactV2Read(response, request, actor, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "grant" && request.Method == http.MethodPost {
		var input fabricpkg.ArtifactRefGrantInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		input.ArtifactRefID = parts[0]
		grant, err := h.fabricService.GrantArtifactRefV2(actor, input)
		if err != nil {
			artifactV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, grant)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && request.Method == http.MethodPost {
		var input struct {
			Reason string `json:"reason,omitempty"`
		}
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		ref, err := h.fabricService.RevokeArtifactRefV2(actor, parts[0], input.Reason)
		if err != nil {
			artifactV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, ref)
		return
	}
	if len(parts) == 3 && parts[0] == "grants" && parts[2] == "revoke" && request.Method == http.MethodPost {
		var input struct {
			Reason string `json:"reason,omitempty"`
		}
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		grant, err := h.fabricService.RevokeArtifactRefV2Grant(actor, parts[1], input.Reason)
		if err != nil {
			artifactV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, grant)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("artifact ref route not found"))
}

func artifactV2Remainder(path string) (string, bool) {
	for _, prefix := range []string{"/v2/artifacts", "/v2/artifact-refs", "/v2/fabric/artifacts", "/v2/fabric/artifact-refs"} {
		if path == prefix {
			return "", true
		}
		if strings.HasPrefix(path, prefix+"/") {
			return strings.TrimPrefix(path, prefix+"/"), true
		}
	}
	return "", false
}

func (h *Handler) artifactV2Collection(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	switch request.Method {
	case http.MethodGet:
		if err := h.fabricService.Authorize(actor, "artifact.read"); err != nil {
			artifactV2Error(response, err)
			return
		}
		refs, err := h.fabricService.ListArtifactRefsV2(actor, queryInt(request, "limit", 100))
		if err != nil {
			artifactV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"artifact_refs": refs})
	case http.MethodPost:
		var input store.ArtifactRefV2Input
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		ref, err := h.fabricService.CreateArtifactRefV2(actor, input)
		if err != nil {
			artifactV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, ref)
	default:
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func artifactV2ReadScopes(request *http.Request) []string {
	values := request.URL.Query()["scope"]
	if len(values) == 0 {
		values = request.URL.Query()["scopes"]
	}
	var scopes []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.TrimSpace(part) != "" {
				scopes = append(scopes, strings.TrimSpace(part))
			}
		}
	}
	return scopes
}

func (h *Handler) artifactV2Read(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor, refID string) {
	result, err := h.fabricService.ReadArtifactRefV2(actor, fabricpkg.ArtifactRefReadInput{ArtifactRefID: refID, Scopes: artifactV2ReadScopes(request)})
	if err != nil {
		artifactV2Error(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func artifactV2Error(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, fabricpkg.ErrUnauthenticated):
		status = http.StatusUnauthorized
	case errors.Is(err, fabricpkg.ErrPermissionDenied), errors.Is(err, fabricpkg.ErrStaleBinding),
		errors.Is(err, store.ErrArtifactRefV2Denied), errors.Is(err, store.ErrArtifactRefV2ScopeDenied),
		errors.Is(err, store.ErrArtifactRefV2Revoked), errors.Is(err, store.ErrArtifactRefV2GrantRevoked):
		status = http.StatusForbidden
	case errors.Is(err, store.ErrArtifactRefV2NotFound), errors.Is(err, store.ErrArtifactRefV2GrantNotFound):
		status = http.StatusNotFound
	case errors.Is(err, store.ErrArtifactRefV2DigestMismatch), errors.Is(err, store.ErrArtifactRefV2UnsafePath),
		errors.Is(err, fabricpkg.ErrArtifactV2PathTraversal), errors.Is(err, fabricpkg.ErrArtifactV2SymlinkEscape):
		status = http.StatusUnprocessableEntity
	}
	writeError(response, status, err)
}
