// Package server exposes the small language-neutral Control API.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/clientcontract"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

type Handler struct {
	control       *control.Control
	fabricService *fabricpkg.Service
	apiToken      string
}

func NewHandler(controlPlane *control.Control) http.Handler {
	handler := &Handler{control: controlPlane}
	if controlPlane != nil {
		handler.apiToken = strings.TrimSpace(controlPlane.APIToken())
		handler.fabricService = controlPlane.Fabric()
	}
	return handler
}

// NewFabricHandler constructs only the collaboration data-plane HTTP surface.
// Tests and deployments can disable Control planner/reporting entirely while
// keeping Directory, Relay, Authorization, and State reachable.
func NewFabricHandler(service *fabricpkg.Service, apiToken string) http.Handler {
	return &Handler{fabricService: service, apiToken: strings.TrimSpace(apiToken)}
}

func isArtifactV2Path(path string) bool {
	for _, prefix := range []string{"/v2/artifacts", "/v2/artifact-refs", "/v2/fabric/artifacts", "/v2/fabric/artifact-refs"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodOptions {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	// Client enrollment and encrypted management traffic have their own trust
	// boundary. They never fall through to the legacy management bearer.
	if request.URL.Path == "/v2/nodes/device-code" {
		h.nodeDeviceCode(response, request)
		return
	}
	if request.URL.Path == "/v2/client/identity" ||
		request.URL.Path == "/v2/client/devices/enroll" ||
		request.URL.Path == "/v2/client/rpc" ||
		request.URL.Path == "/v2/client/rpc/recover" {
		h.clientV2(response, request)
		return
	}
	// A public, metadata-only negotiation point for the separate Android
	// Client. Advertise only operations that have a real PQ device boundary;
	// the whole Android product contract remains partial until the complete
	// status stream and external Thread link flows exist.
	if request.URL.Path == "/v2/client/capabilities" {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		clientReady := h.control != nil
		status := "not_ready"
		if clientReady {
			status = "partial"
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"contract":                        "android-hub-v1-draft",
			"contract_revision":               clientcontract.ContractRevision,
			"catalog_sha256":                  clientcontract.CatalogSHA256(),
			"status":                          status,
			"planned_platform":                "android",
			"legacy_management_api_available": h.control != nil,
			"client_control_pq_e2ee":          clientReady,
			"authenticated_client_session":    clientReady,
			"status_snapshot":                 clientReady,
			"topology_management":             clientReady,
			"status_events":                   false,
			"status_changes_partial":          clientReady,
			"control_intents":                 clientReady,
			"device_binding":                  clientReady,
			"external_thread_links":           false,
			"external_link_invites":           clientReady,
			"external_client_sessions":        clientReady,
			"link_key_consent":                clientReady,
			"group_endpoint_key_grants":       clientReady,
			"client_device_enrollment":        clientReady,
			"rpc_recovery":                    clientReady,
			"client_device_management":        clientReady,
			"approval_read_and_decide":        clientReady,
			"queued_goal_lifecycle":           clientReady,
			"available_rpc_operations": func() []string {
				if !clientReady {
					return []string{}
				}
				return managerClientRPCOperations()
			}(),
			"external_rpc_operations": func() []string {
				if !clientReady {
					return []string{}
				}
				return externalClientRPCOperations()
			}(),
		})
		return
	}
	// The embedded client and health probe remain readable so a deployment can
	// bootstrap and monitor itself. Every state-changing or data API request is
	// protected when an operator configures CICADA_API_TOKEN.
	if h.apiToken != "" && !isPublicClientPath(request.URL.Path) && request.URL.Path != "/healthz" &&
		!isFabricSessionPath(request.URL.Path) && !strings.HasPrefix(request.URL.Path, "/v2/relay/nodes/") && !h.authorized(request) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="cicada"`)
		writeError(response, http.StatusUnauthorized, errors.New("missing or invalid API bearer token"))
		return
	}
	// The old browser Push service registered subscriptions against a single
	// Hub-wide bearer and broadcast complete notification text to every row.
	// Keep an explicit tombstone so old clients cannot mistake removal for a
	// transient route failure. Durable notification records and the remaining
	// local history surface are independent of browser Push delivery.
	if request.URL.Path == "/v1/notifications/push/config" ||
		request.URL.Path == "/v1/notifications/push/subscriptions" ||
		strings.HasPrefix(request.URL.Path, "/v1/notifications/push/subscriptions/") {
		writeError(response, http.StatusGone, errors.New("browser Push API is retired"))
		return
	}
	if isPublicClientPath(request.URL.Path) {
		serveClient(response, request)
		return
	}
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		serviceName := "cicada-control"
		if h.control == nil {
			serviceName = "cicada-fabric"
		}
		provenance := buildinfo.CurrentProvenance()
		writeJSON(response, http.StatusOK, map[string]any{
			"status":             "ok",
			"service":            serviceName,
			"version":            buildinfo.Version,
			"stage":              buildinfo.Stage,
			"revision":           provenance.Revision,
			"dirty":              provenance.Dirty,
			"source_fingerprint": provenance.SourceFingerprint,
			"catalog_sha256":     clientcontract.CatalogSHA256(),
		})
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v2/relay/nodes/") {
		if isRelayNodeGroupSealedV2Path(request.URL.Path) {
			h.relayNodeGroupSealedV2(response, request)
			return
		}
		h.relayNodeV2(response, request)
		return
	}
	if isArtifactV2Path(request.URL.Path) {
		h.ArtifactV2(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v2/fabric/") {
		h.fabricV2(response, request)
		return
	}
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Control management is disabled in Fabric-only mode"))
		return
	}
	if request.URL.Path == "/v1/machines" {
		h.machines(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/machines/") {
		h.machine(response, request)
		return
	}
	if request.URL.Path == "/v1/workers" && request.Method == http.MethodGet {
		workers, err := h.control.Workers()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"workers": workers})
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/workers/") {
		if strings.HasSuffix(request.URL.Path, "/log") && request.Method == http.MethodGet {
			h.workerLog(response, request)
			return
		}
		h.workerDispatch(response, request)
		return
	}
	if request.URL.Path == "/v1/groups" {
		h.groups(response, request)
		return
	}
	if request.URL.Path == "/v1/resource-leases" || strings.HasPrefix(request.URL.Path, "/v1/resource-leases/") || request.URL.Path == "/v1/resources/reconcile" {
		h.resourceManagementV2(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/groups/") {
		h.group(response, request)
		return
	}
	if request.URL.Path == "/v1/group-cards" || request.URL.Path == "/v1/federation/group-cards" {
		h.groupCardsCollection(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/group-cards/") || strings.HasPrefix(request.URL.Path, "/v1/federation/group-cards/") {
		h.groupCardCollectionItem(response, request)
		return
	}
	if request.URL.Path == "/v1/federation/contracts" {
		h.federationContracts(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/federation/contracts/") {
		h.federationContract(response, request)
		return
	}
	if request.URL.Path == "/v1/federation/representatives" {
		h.representativeAssignments(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/federation/representatives/") {
		h.representativeAssignment(response, request)
		return
	}
	if request.URL.Path == "/v2/management/endpoints" {
		h.fabricEndpoints(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v2/management/endpoints/") {
		h.fabricEndpoint(response, request)
		return
	}
	if request.URL.Path == "/v1/approvals" && request.Method == http.MethodGet {
		pendingOnly := request.URL.Query().Get("pending") != "false"
		approvals, err := h.control.Approvals(pendingOnly)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"approvals": approvals})
		return
	}
	if request.URL.Path == "/v1/identity/announcement" {
		h.contactAnnouncement(response, request)
		return
	}
	if request.URL.Path == "/v1/directory/announcement" {
		h.directoryAnnouncement(response, request)
		return
	}
	if request.URL.Path == "/v1/directory/records" {
		h.directoryRecords(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/directory/records/") {
		h.directoryRecord(response, request, "/v1/directory/records/")
		return
	}
	if request.URL.Path == "/v1/identity" && request.Method == http.MethodGet {
		writeJSON(response, http.StatusOK, h.control.Identity())
		return
	}
	if request.URL.Path == "/v1/contacts" {
		h.contacts(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/contacts/") {
		h.contact(response, request)
		return
	}
	if request.URL.Path == "/v1/discovery/requests" {
		h.discoveryRequests(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/discovery/requests/") {
		h.discoveryRequest(response, request)
		return
	}
	if request.URL.Path == "/v1/permissions" {
		h.permissions(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/permissions/") {
		h.permission(response, request)
		return
	}
	if request.URL.Path == "/v1/connectors/email" {
		h.emailConnector(response, request)
		return
	}
	if request.URL.Path == "/v1/connectors/calendar" {
		h.calendarConnector(response, request)
		return
	}
	if request.URL.Path == "/v1/connectors/documents" {
		h.documentsConnector(response, request)
		return
	}
	if request.URL.Path == "/v1/connectors/x" {
		h.socialConnector(response, request, "x")
		return
	}
	if request.URL.Path == "/v1/connectors/wechat" {
		h.socialConnector(response, request, "wechat")
		return
	}
	if request.URL.Path == "/v1/connectors/qq" {
		h.socialConnector(response, request, "qq")
		return
	}
	if request.URL.Path == "/v1/connectors/slack" {
		h.socialConnector(response, request, "slack")
		return
	}
	if request.URL.Path == "/v1/connectors/discord" {
		h.socialConnector(response, request, "discord")
		return
	}
	if request.URL.Path == "/v1/connectors/replies" {
		h.connectorReply(response, request)
		return
	}
	if request.URL.Path == "/v1/connectors/events" {
		h.externalEvents(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/connectors/events/") {
		h.externalEvent(response, request)
		return
	}
	if request.URL.Path == "/v1/snapshots/gc" {
		h.snapshotGC(response, request)
		return
	}
	if request.URL.Path == "/v1/snapshots" {
		h.snapshots(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/snapshots/") {
		h.snapshot(response, request)
		return
	}
	if request.URL.Path == "/v1/actions" {
		h.actions(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/actions/") {
		h.action(response, request)
		return
	}
	if request.URL.Path == "/v1/notifications" && request.Method == http.MethodGet {
		unreadOnly := request.URL.Query().Get("unread") != "false"
		notifications, err := h.control.Notifications(unreadOnly)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"notifications": notifications})
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/notifications/") && strings.HasSuffix(request.URL.Path, "/read") && request.Method == http.MethodPost {
		id := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/notifications/"), "/read")
		if id == "" || strings.Contains(id, "/") {
			writeError(response, http.StatusNotFound, errors.New("notification not found"))
			return
		}
		notification, err := h.control.MarkNotificationRead(id)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, notification)
		return
	}
	if request.URL.Path == "/v1/intents" {
		h.intents(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/intents/") {
		h.intent(response, request)
		return
	}
	if request.URL.Path == "/v1/attachments" {
		h.attachments(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/attachments/") {
		h.attachment(response, request)
		return
	}
	if request.URL.Path == "/v1/ideas" {
		h.ideas(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/ideas/") {
		h.idea(response, request)
		return
	}
	if request.URL.Path == "/v1/memories" {
		h.memories(response, request)
		return
	}
	if request.URL.Path == "/v1/artifacts" {
		h.artifacts(response, request)
		return
	}
	if request.URL.Path == "/v1/workspaces" {
		h.workspaces(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/workspaces/") {
		h.workspace(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/approvals/") && request.Method == http.MethodPost {
		approvalID := strings.TrimPrefix(request.URL.Path, "/v1/approvals/")
		if approvalID == "" || strings.Contains(approvalID, "/") {
			writeError(response, http.StatusNotFound, errors.New("approval not found"))
			return
		}
		var input struct {
			Decision string `json:"decision"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		approval, err := h.control.ResolveApproval(approvalID, input.Decision)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, approval)
		return
	}
	if request.URL.Path == "/v1/goals" {
		h.goals(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/goals/") {
		h.goal(response, request)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("route not found"))
}

func (h *Handler) authorized(request *http.Request) bool {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	const prefix = "Bearer "
	if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return false
	}
	presented := strings.TrimSpace(value[len(prefix):])
	if presented == "" || len(presented) != len(h.apiToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.apiToken)) == 1
}

func (h *Handler) workspaces(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		workspaces, err := h.control.Workspaces(request.URL.Query().Get("goal_id"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"workspaces": workspaces})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.WorkspaceInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	workspace, err := h.control.CreateWorkspace(input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusCreated, workspace)
}

func (h *Handler) contacts(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		contacts, err := h.control.Contacts()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"contacts": contacts})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Label    string              `json:"label"`
		Identity e2ee.PublicIdentity `json:"identity"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	contact, err := h.control.CreateContact(input.Label, input.Identity)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, contact)
}

func (h *Handler) contact(response http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, "/v1/contacts/")
	id := path
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("contact not found"))
		return
	}
	if request.Method == http.MethodGet {
		contact, err := h.control.Contact(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if contact == nil {
			writeError(response, http.StatusNotFound, errors.New("contact not found"))
			return
		}
		writeJSON(response, http.StatusOK, contact)
		return
	}
	if request.Method != http.MethodPatch {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Label  string `json:"label"`
		Status string `json:"status"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	contact, err := h.control.UpdateContact(id, input.Label, input.Status)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, contact)
}

func (h *Handler) permissions(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		permissions, err := h.control.Permissions(request.URL.Query().Get("subject_type"), request.URL.Query().Get("subject_id"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"permissions": permissions})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.PermissionInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	permission, err := h.control.SetPermission(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusOK, permission)
}

func (h *Handler) permission(response http.ResponseWriter, request *http.Request) {
	id := strings.TrimPrefix(request.URL.Path, "/v1/permissions/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("permission not found"))
		return
	}
	if request.Method == http.MethodGet {
		permission, err := h.control.Permission(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if permission == nil {
			writeError(response, http.StatusNotFound, errors.New("permission not found"))
			return
		}
		writeJSON(response, http.StatusOK, permission)
		return
	}
	if request.Method != http.MethodDelete {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if err := h.control.DeletePermission(id); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ideas(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		ideas, err := h.control.Ideas(request.URL.Query().Get("status"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"ideas": ideas})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.IdeaInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	idea, err := h.control.CreateIdea(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, idea)
}

func (h *Handler) idea(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/ideas/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("idea id is required"))
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "promote" && request.Method == http.MethodPost {
		var input control.GoalInput
		if request.ContentLength != 0 {
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
		}
		goal, err := h.control.PromoteIdea(id, input)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusCreated, goal)
		return
	}
	if len(parts) == 2 && parts[1] == "research" && request.Method == http.MethodPost {
		goal, err := h.control.ResearchIdea(id)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, goal)
		return
	}
	if len(parts) != 1 {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	if request.Method == http.MethodGet {
		idea, err := h.control.Idea(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if idea == nil {
			writeError(response, http.StatusNotFound, errors.New("idea not found"))
			return
		}
		writeJSON(response, http.StatusOK, idea)
		return
	}
	if request.Method != http.MethodPatch {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Status      string `json:"status"`
		Rationale   string `json:"rationale"`
		RevisitWhen string `json:"revisit_when"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	idea, err := h.control.UpdateIdea(id, input.Status, input.Rationale, input.RevisitWhen)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, idea)
}

func (h *Handler) memories(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		memories, err := h.control.Memories(request.URL.Query().Get("scope"), request.URL.Query().Get("namespace"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"memories": memories})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var memory store.Memory
	if err := readJSON(request, &memory); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	created, err := h.control.CreateMemory(memory)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, created)
}

func (h *Handler) artifacts(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		var artifacts []store.Artifact
		var err error
		if h.apiToken == "" {
			artifacts, err = h.control.ListArtifactsIfNoScopedRefs(request.URL.Query().Get("goal_id"))
		} else {
			artifacts, err = h.control.Artifacts(request.URL.Query().Get("goal_id"))
		}
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, store.ErrLegacyArtifactAPIDisabled) || errors.Is(err, store.ErrLegacyArtifactGuardUnavailable) {
				status = http.StatusServiceUnavailable
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"artifacts": artifacts})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var artifact store.Artifact
	if err := readJSON(request, &artifact); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	var created *store.Artifact
	var err error
	if h.apiToken == "" {
		created, err = h.control.CreateArtifactIfNoScopedRefs(artifact)
	} else {
		created, err = h.control.CreateArtifact(artifact)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrLegacyArtifactAPIDisabled) || errors.Is(err, store.ErrLegacyArtifactGuardUnavailable) {
			status = http.StatusServiceUnavailable
		} else if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusCreated, created)
}

func (h *Handler) workspace(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/workspaces/"), "/")
	id := parts[0]
	if id == "" {
		writeError(response, http.StatusNotFound, errors.New("workspace not found"))
		return
	}
	if len(parts) == 2 && parts[1] == "snapshot" && request.Method == http.MethodPost {
		request.Body = http.MaxBytesReader(response, request.Body, snapshot.MaxArchiveBytes+1)
		stored, err := h.control.ReceiveWorkspaceSnapshot(id, request.Body)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusCreated, stored)
		return
	}
	if len(parts) == 3 && parts[1] == "snapshot" && request.Method == http.MethodGet {
		file, metadata, err := h.control.OpenWorkspaceSnapshot(id, parts[2])
		if err != nil {
			status := http.StatusNotFound
			if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		defer file.Close()
		response.Header().Set("Content-Type", "application/x-cicada-workspace-tar")
		response.Header().Set("Content-Length", strconv.FormatInt(metadata.Size, 10))
		response.Header().Set("X-Cicada-Snapshot-Digest", metadata.Digest)
		_, _ = io.Copy(response, file)
		return
	}
	if len(parts) == 2 && parts[1] == "actions" && request.Method == http.MethodPost {
		var input struct {
			Action     string `json:"action"`
			TargetPath string `json:"target_path"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		workspace, err := h.control.WorkspaceAction(id, input.Action, input.TargetPath)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, workspace)
		return
	}
	if len(parts) != 1 {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	if request.Method == http.MethodGet {
		workspace, err := h.control.Workspace(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if workspace == nil {
			writeError(response, http.StatusNotFound, errors.New("workspace not found"))
			return
		}
		writeJSON(response, http.StatusOK, workspace)
		return
	}
	if request.Method != http.MethodPatch {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Status   string `json:"status"`
		Revision string `json:"revision"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	workspace, err := h.control.UpdateWorkspace(id, input.Status, input.Revision)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, workspace)
}

func (h *Handler) machines(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		machines, err := h.control.Machines()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"machines": machines})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		ID           string         `json:"id"`
		Name         string         `json:"name"`
		Status       string         `json:"status"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	if input.ID == "" || input.Name == "" {
		writeError(response, http.StatusBadRequest, errors.New("id and name are required"))
		return
	}
	if input.Status == "" {
		input.Status = "available"
	}
	// Machine registration is intentionally idempotent. The local machine
	// records are created at Control startup; future agents use this endpoint.
	registered, err := h.control.RegisterMachine(input.ID, input.Name, input.Capabilities, input.Status)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, registered)
}

func (h *Handler) machine(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/machines/"), "/")
	if len(parts) == 2 && parts[1] == "jobs" && request.Method == http.MethodGet && parts[0] != "" {
		jobs, err := h.control.MachineJobs(parts[0])
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"jobs": jobs})
		return
	}
	if len(parts) != 2 || parts[1] != "heartbeat" || request.Method != http.MethodPost || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("machine route not found"))
		return
	}
	var input struct {
		Status       string         `json:"status"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	machine, err := h.control.HeartbeatMachine(parts[0], input.Status, input.Capabilities)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, machine)
}

func (h *Handler) goals(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		goals, err := h.control.Goals()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"goals": goals})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.GoalInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	goal, err := h.control.CreateGoal(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, goal)
}

func (h *Handler) goal(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/goals/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("goal id is required"))
		return
	}
	goalID := parts[0]
	if len(parts) == 2 && parts[1] == "events" && request.Method == http.MethodGet {
		after, _ := strconv.ParseInt(request.URL.Query().Get("after"), 10, 64)
		events, err := h.control.Events(goalID, after)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"events": events})
		return
	}
	if len(parts) == 3 && parts[1] == "events" && parts[2] == "stream" && request.Method == http.MethodGet {
		h.goalEventStream(response, request, goalID)
		return
	}
	if len(parts) == 2 && parts[1] == "workers" {
		if request.Method == http.MethodGet {
			goal, err := h.control.Goal(goalID)
			if err != nil {
				writeError(response, http.StatusInternalServerError, err)
				return
			}
			if goal == nil {
				writeError(response, http.StatusNotFound, errors.New("goal not found"))
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"workers": goal.Workers})
			return
		}
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input control.WorkerInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		worker, err := h.control.AddWorker(goalID, input)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, worker)
		return
	}
	if len(parts) == 2 && parts[1] == "commands" && request.Method == http.MethodPost {
		var input struct {
			Command string `json:"command"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		command, err := h.control.SendCommand(goalID, input.Command)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, command)
		return
	}
	if len(parts) == 2 && parts[1] == "stop" && request.Method == http.MethodPost {
		goal, err := h.control.StopGoal(goalID)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if goal == nil {
			writeError(response, http.StatusNotFound, errors.New("goal not found"))
			return
		}
		writeJSON(response, http.StatusOK, goal)
		return
	}
	if len(parts) != 1 || request.Method != http.MethodGet {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	goal, err := h.control.Goal(goalID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if goal == nil {
		writeError(response, http.StatusNotFound, errors.New("goal not found"))
		return
	}
	writeJSON(response, http.StatusOK, goal)
}

func readJSON(request *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(request.Body, 2<<20+1))
	if len(data) > 2<<20 {
		return errors.New("request body exceeds 2 MiB")
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, err error) {
	message := err.Error()
	if status >= 500 {
		message = "internal server error"
	}
	writeJSON(response, status, map[string]any{"error": message})
}
