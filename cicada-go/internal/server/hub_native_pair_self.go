package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/fabric"
)

func (h *hubNodesHandler) nativePairSelf(w http.ResponseWriter, r *http.Request) {
	want := http.MethodGet
	if r.URL.Path == "/v2/fabric/endpoint-keys" || r.URL.Path == "/v2/fabric/heartbeat" || r.URL.Path == "/v2/fabric/resolve" {
		want = http.MethodPost
	}
	if r.Method != want {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	token, err := fabric.SessionCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabric.ErrUnauthenticated)
		return
	}
	actor, err := h.nodes.Fabric().AuthenticateForGroup(token, r.Header.Get("Cicada-Group-Scope"))
	if err != nil || h.nodes.Fabric().RequireNativeCollaborationSelf(actor) != nil {
		writeError(w, http.StatusForbidden, fabric.ErrPermissionDenied)
		return
	}
	if r.URL.Path == "/v2/fabric/members" || r.URL.Path == "/v2/fabric/list" {
		cards, err := h.nodes.Fabric().List(actor, r.URL.Query().Get("status"), r.URL.Query().Get("node_id"), r.URL.Query().Get("harness"), queryInt(r, "limit", 200))
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": cards})
		return
	}
	if r.URL.Path == "/v2/fabric/resolve" {
		var input fabric.ResolveInput
		if decodeStrictClientJSON(r.Body, 4096, &input) != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid peer query"))
			return
		}
		card, err := h.nodes.Fabric().Resolve(actor, input)
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, card)
		return
	}
	if r.URL.Path == "/v2/fabric/endpoint-keys" {
		h.base.endpointKeysV2(w, r, actor)
		return
	}
	if r.URL.Path == "/v2/fabric/heartbeat" {
		renewed, err := h.nodes.Fabric().RenewForGroup(token, actor.GroupID, 0)
		if err != nil {
			fabricV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, renewed)
		return
	}
	card, err := h.nodes.Fabric().WhoAmI(actor)
	if err != nil {
		fabricV2Error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, card)
}
