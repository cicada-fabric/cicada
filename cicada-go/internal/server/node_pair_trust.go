package server

import (
	"errors"
	"io"
	"net/http"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
)

func (h *hubNodesHandler) nodePairTrust(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == wire.NodePairTrustDescriptorPath || r.URL.Path == wire.NodePairTrustCapabilitiesPath {
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || !hubauth.NodePairTrustCredentialsAbsent(r.Header.Get("Authorization"), r.Header.Get("Cookie")) {
			writeError(w, http.StatusBadRequest, errors.New("public Node pairing metadata request rejected"))
			return true
		}
		if r.URL.Path == wire.NodePairTrustDescriptorPath {
			text, err := h.account.NodePairTrustDescriptor()
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("native Hub descriptor unavailable"))
				return true
			}
			w.Header().Set("Content-Type", "text/plain; charset=us-ascii")
			_, _ = io.WriteString(w, text)
		} else {
			caps, err := h.account.NodePairTrustCapabilities()
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("Node pairing unavailable"))
				return true
			}
			writeJSON(w, http.StatusOK, caps)
		}
		return true
	}
	op := hubauth.NodePairTrustOperationForPath(r.URL.Path)
	if op == "" {
		return false
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || !hubauth.NodePairTrustCredentialsAbsent(r.Header.Get("Authorization"), r.Header.Get("Cookie")) {
		writeError(w, http.StatusBadRequest, errors.New("Node pairing request rejected"))
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		expected, err := h.account.ExpectedOrigin()
		if err != nil || expected != origin {
			writeError(w, http.StatusForbidden, errors.New("Node pairing origin rejected"))
			return true
		}
	}
	limit := wire.MaxNodePairTrustPacketBytes
	if op == wire.OperationNodePairTrustReconcile {
		limit = wire.MaxNodePairTrustReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(raw) == 0 || len(raw) > limit {
		writeError(w, http.StatusBadRequest, errors.New("Node pairing packet rejected"))
		return true
	}
	packet, err := h.account.HandleNodePairTrust(r.Context(), op, raw)
	if err != nil {
		if errors.Is(err, hubauth.ErrBusy) {
			writeError(w, http.StatusServiceUnavailable, errors.New("Node pairing busy"))
		} else if errors.Is(err, hubauth.ErrNodePairTrustACKRequired) {
			writeError(w, http.StatusConflict, hubauth.ErrNodePairTrustACKRequired)
		} else {
			writeError(w, http.StatusForbidden, errors.New("Node pairing request rejected"))
		}
		return true
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packet)
	return true
}
