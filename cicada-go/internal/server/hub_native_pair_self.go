package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/fabric"
)

func (h *hubNodesHandler) nativePairSelf(w http.ResponseWriter, r *http.Request) {
	want := http.MethodGet
	if r.URL.Path == "/v2/fabric/endpoint-keys" || r.URL.Path == "/v2/fabric/heartbeat" {
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
	if err != nil || h.nodes.Fabric().RequireNativePairSelf(actor) != nil {
		writeError(w, http.StatusForbidden, fabric.ErrPermissionDenied)
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
