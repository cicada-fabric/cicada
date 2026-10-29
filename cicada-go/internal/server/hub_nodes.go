package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type hubNodesHandler struct {
	base    *Handler
	account *hubauth.Service
	nodes   *hubnodes.Service
}

// NewHubNodesHandler exposes a deliberately bounded composition. Existing
// account/Owner identity and Fabric Node heartbeat/SSE handlers are reused;
// no Control, Worker, Manager API, broad snapshot or arbitrary RPC is attached.
func NewHubNodesHandler(owner *hubowner.Service, account *hubauth.Service, nodes *hubnodes.Service) http.Handler {
	base := NewHubHandlerWithAccount(owner, account).(*Handler)
	if nodes != nil {
		base.fabricService = nodes.Fabric()
	}
	return &hubNodesHandler{base: base, account: account, nodes: nodes}
}

func (h *hubNodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if h.account == nil || h.nodes == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("Hub Nodes service unavailable"))
		return
	}
	path := r.URL.Path
	if path == wire.OwnerEndpointGroupsCapabilitiesPath {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		caps, err := h.account.OwnerEndpointGroupsCapabilities()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("endpoint groups unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, caps)
		return
	}
	for _, op := range wire.OwnerEndpointGroupsHTTPOperations() {
		if path == wire.OwnerEndpointGroupsHTTPPath(op) {
			h.base.hubAccount(w, r, op)
			return
		}
	}
	if h.nodePairTrust(w, r) {
		return
	}
	if path == wire.LocalDomainCapabilitiesPath {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		caps, err := h.account.LocalDomainCapabilities()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("local domain unavailable"))
			return
		}
		raw, err := json.Marshal(caps)
		if err != nil || len(raw) > wire.MaxLocalDomainCapabilitiesBytes {
			writeError(w, http.StatusServiceUnavailable, errors.New("local domain metadata unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	for _, op := range wire.LocalDomainHTTPOperations() {
		if path == wire.LocalDomainHTTPPath(op) {
			h.base.hubAccount(w, r, op)
			return
		}
	}
	if path == wire.NativePairCapabilitiesPath {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		caps, err := h.account.NativePairCapabilities()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("native pair unavailable"))
			return
		}
		raw, err := json.Marshal(caps)
		if err != nil || len(raw) > wire.MaxNativePairCapabilitiesBytes {
			writeError(w, http.StatusServiceUnavailable, errors.New("native pair metadata unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	for _, op := range wire.NativePairHTTPOperations() {
		if path == wire.NativePairHTTPPath(op) {
			h.base.hubAccount(w, r, op)
			return
		}
	}
	if path == wire.AppNodeScopedCapabilitiesPath || path == wire.NodePairTrustScopedCapabilitiesPath {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		caps, err := h.account.AppNodeCapabilities()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("Hub Node metadata unavailable"))
			return
		}
		var metadata any = wire.AppNodeScopedContractCapabilities(caps.TransportPolicy)
		if path == wire.NodePairTrustScopedCapabilitiesPath {
			metadata = wire.NodePairTrustScopedContractCapabilities()
		}
		raw, err := json.Marshal(metadata)
		if err != nil || len(raw) > wire.MaxAppNodeScopedCapabilitiesBytes {
			writeError(w, http.StatusServiceUnavailable, errors.New("Hub Node metadata unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	if path == wire.AppNodeCapabilitiesPath {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		caps, err := h.account.AppNodeCapabilities()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("Hub Node authority unavailable"))
			return
		}
		raw, err := json.Marshal(caps)
		if err != nil || len(raw) > wire.MaxAppNodeCapabilitiesBytes {
			writeError(w, http.StatusServiceUnavailable, errors.New("Hub Node metadata unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
		return
	}
	for _, op := range []string{wire.OperationAppNodePrepare, wire.OperationAppNodeComplete, wire.OperationAppNodeStatus, wire.OperationAppNodeCancel, wire.OperationAppNodeReconcile} {
		if path == wire.AppNodeHTTPPath(op) {
			h.base.hubAccount(w, r, op)
			return
		}
	}
	if path == "/v2/client/rpc" {
		h.client(w, r)
		return
	}
	if path == "/v2/node/identity" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		identity, err := h.nodes.Identity()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("Node identity unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, identity)
		return
	}
	if path == "/v2/nodes/device-code" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input nodeControlPairingInput
		if decodeStrictClientJSON(r.Body, 96*1024, &input) != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Node device code request"))
			return
		}
		code, err := h.nodes.Start(r.Context(), input.controlInput())
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("Node device code request rejected"))
			return
		}
		writeJSON(w, http.StatusCreated, code)
		return
	}
	if strings.HasPrefix(path, "/v2/node/device-code/") && strings.HasSuffix(path, "/status") {
		h.pairingStatus(w, r)
		return
	}
	if path == "/v2/node/control/rpc" {
		h.nodeRPC(w, r)
		return
	}
	if path == "/healthz" || path == "/v2/client/identity" || path == "/v2/client/capabilities" || path == "/v2/owner/bootstrap/accept" || accountOperation(path) != "" {
		h.base.ServeHTTP(w, r)
		return
	}
	if path == "/v2/fabric/whoami" || path == "/v2/fabric/endpoint-keys" || path == "/v2/fabric/heartbeat" || path == "/v2/fabric/resolve" || path == "/v2/fabric/find" || path == "/v2/fabric/inspect" || path == "/v2/fabric/members" || path == "/v2/fabric/list" {
		h.nativePairSelf(w, r)
		return
	}
	if hubNodesRelayPath(path) {
		h.base.ServeHTTP(w, r)
		return
	}
	if h.localDomainRelaySend(w, r) {
		return
	}
	// Route availability is not a grant. Only these existing Network methods
	// are composed here; their original Node/Network/current-Owner Guards run
	// in the base handler. Join, invitations and management remain absent.
	if hubNodesExistingNetworkRoute(path, r.Method) {
		h.base.ServeHTTP(w, r)
		return
	}
	writeError(w, http.StatusNotFound, errors.New("route unavailable in Hub Nodes mode"))
}

func hubNodesExistingNetworkRoute(path, method string) bool {
	if len(path) > 512 {
		return false
	}
	if method == http.MethodPost {
		switch path {
		case "/v2/fabric/node/networks/renew", "/v2/fabric/node/networks/direct/send", "/v2/fabric/node/networks/direct/ask", "/v2/fabric/node/networks/direct/reply", "/v2/fabric/node/networks/direct/claim", "/v2/fabric/node/networks/direct/authorize", "/v2/fabric/node/networks/direct/receipt", "/v2/fabric/node/networks/direct/reply-route":
			return true
		}
	}
	if !strings.HasPrefix(path, "/v2/fabric/networks/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/v2/fabric/networks/"), "/")
	if len(parts) < 2 || len(parts[0]) < 1 || len(parts[0]) > 256 || parts[0] == "." || parts[0] == ".." {
		return false
	}
	for _, r := range parts[0] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	if len(parts) == 2 {
		return method == http.MethodGet && (parts[1] == "whoami" || parts[1] == "directory") || method == http.MethodPost && parts[1] == "resolve"
	}
	if len(parts) != 3 || parts[1] != "direct" {
		return false
	}
	if method == http.MethodGet {
		return parts[2] == "request-status"
	}
	if method != http.MethodPost {
		return false
	}
	switch parts[2] {
	case "native-binding", "peer-key", "key-candidate", "request-cancel":
		return true
	}
	return false
}

func hubNodesRelayPath(path string) bool {
	if !strings.HasPrefix(path, "/v2/relay/nodes/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/v2/relay/nodes/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		return false
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "heartbeat", "events", "claim", "receipts":
			return true
		}
	}
	if len(parts) == 3 && parts[1] == "sealed" && parts[2] == "claim" {
		return true
	}
	if len(parts) < 4 || parts[1] != "group" || parts[2] != "sealed" {
		return false
	}
	if len(parts) == 4 {
		switch parts[3] {
		case "claim", "peer-key", "ask", "reply":
			return true
		}
		return false
	}
	if len(parts) == 5 {
		return parts[3] == "requests" && parts[4] != ""
	}
	return len(parts) == 6 && parts[4] != "" && ((parts[3] == "requests" && parts[5] == "cancel") || (parts[3] == "deliveries" && parts[5] == "authorization"))
}

func (h *hubNodesHandler) client(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		expected, e := h.account.ExpectedOrigin()
		if e != nil || origin != expected {
			writeError(w, http.StatusForbidden, errors.New("Hub Node authentication rejected"))
			return
		}
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, wire.MaxAppNodeOriginalBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("Hub Node packet exceeds limit"))
		return
	}
	packet, err := h.account.HandleAppNodeClient(r.Context(), raw)
	if err != nil {
		if errors.Is(err, hubauth.ErrNodePairTrustACKRequired) {
			writeError(w, http.StatusConflict, hubauth.ErrNodePairTrustACKRequired)
			return
		}
		hubNodesAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packet)
}
func hubNodesAuthError(w http.ResponseWriter, err error) {
	if errors.Is(err, hubauth.ErrBusy) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, errors.New("Hub Node authentication busy"))
		return
	}
	if errors.Is(err, hubauth.ErrAppNodeCounterConflict) {
		writeError(w, http.StatusConflict, hubauth.ErrAppNodeCounterConflict)
		return
	}
	writeError(w, http.StatusForbidden, errors.New("Hub Node authentication rejected"))
}
func (h *hubNodesHandler) pairingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[3] == "" || parts[4] != "status" {
		writeError(w, http.StatusNotFound, errors.New("Node pairing unavailable"))
		return
	}
	token, err := fabric.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("Node credential required"))
		return
	}
	status, err := h.nodes.PairingStatus(token, r.URL.Query().Get("node_id"), parts[3])
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("Node pairing unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, status)
}
func (h *hubNodesHandler) nodeRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	token, err := fabric.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("Node credential required"))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, nodewire.MaxRequestPacketBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("Node packet exceeds limit"))
		return
	}
	packet, err := h.nodes.RPC(r.Context(), token, raw)
	if err != nil {
		if errors.Is(err, hubnodes.ErrBusy) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, errors.New("Node request capacity is busy; retain and retry the original packet"))
			return
		}
		writeError(w, http.StatusForbidden, errors.New("Node binding status request rejected"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packet)
}
