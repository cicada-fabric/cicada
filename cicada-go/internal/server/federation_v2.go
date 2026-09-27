package server

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// groupFederationProvisioning handles the nested management routes under one
// Group. The route is reached from groups.go only after the global HTTP
// bearer check in Handler.ServeHTTP.
func (h *Handler) groupFederationProvisioning(response http.ResponseWriter, request *http.Request, groupID, resource string, remainder []string) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	groupID = strings.TrimSpace(groupID)
	for i := range remainder {
		decoded, err := url.PathUnescape(remainder[i])
		if err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid management resource id"))
			return
		}
		remainder[i] = decoded
	}
	switch resource {
	case "cards":
		h.groupCards(response, request, groupID, remainder)
	case "representatives":
		h.groupRepresentatives(response, request, groupID, remainder)
	default:
		writeError(response, http.StatusNotFound, errors.New("group management route not found"))
	}
}

func (h *Handler) groupCards(response http.ResponseWriter, request *http.Request, groupID string, remainder []string) {
	if len(remainder) == 0 {
		switch request.Method {
		case http.MethodGet:
			cards, err := h.control.GroupCards(groupID)
			if err != nil {
				managementError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"group_cards": cards})
		case http.MethodPost:
			var input store.GroupCard
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
			if input.GroupID != "" && strings.TrimSpace(input.GroupID) != groupID {
				writeError(response, http.StatusBadRequest, errors.New("group card group does not match route"))
				return
			}
			input.GroupID = groupID
			card, err := h.control.CreateGroupCard(input)
			if err != nil {
				managementError(response, err)
				return
			}
			writeJSON(response, http.StatusCreated, card)
		default:
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
		return
	}
	if len(remainder) == 1 && remainder[0] == "publish" && request.Method == http.MethodPost {
		var input store.GroupCard
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		if input.GroupID != "" && strings.TrimSpace(input.GroupID) != groupID {
			writeError(response, http.StatusBadRequest, errors.New("group card group does not match route"))
			return
		}
		input.GroupID = groupID
		card, err := h.control.PublishGroupCard(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, card)
		return
	}
	cardID := strings.TrimSpace(remainder[0])
	if cardID == "" {
		writeError(response, http.StatusBadRequest, errors.New("invalid group card id"))
		return
	}
	if len(remainder) == 1 && request.Method == http.MethodGet {
		card, err := h.control.GroupCard(cardID)
		if err != nil {
			managementError(response, err)
			return
		}
		if card.GroupID != groupID {
			writeError(response, http.StatusNotFound, errors.New("group card not found"))
			return
		}
		writeJSON(response, http.StatusOK, card)
		return
	}
	if len(remainder) == 2 && remainder[1] == "publish" && request.Method == http.MethodPost {
		card, err := h.control.GroupCard(cardID)
		if err != nil {
			managementError(response, err)
			return
		}
		if card.GroupID != groupID {
			writeError(response, http.StatusBadRequest, errors.New("group card group does not match route"))
			return
		}
		var input store.GroupCard
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		if input.GroupID != "" && strings.TrimSpace(input.GroupID) != card.GroupID {
			writeError(response, http.StatusBadRequest, errors.New("group card group does not match route"))
			return
		}
		mergeGroupCardInput(&input, *card)
		input.ID = cardID
		input.GroupID = groupID
		published, err := h.control.PublishGroupCard(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, published)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("group card route not found"))
}

func (h *Handler) groupRepresentatives(response http.ResponseWriter, request *http.Request, groupID string, remainder []string) {
	if len(remainder) == 0 {
		if request.Method == http.MethodGet {
			assignments, err := h.control.RepresentativeAssignments(store.RepresentativeAssignmentFilter{GroupID: groupID, Limit: 200})
			if err != nil {
				managementError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"representative_assignments": assignments})
			return
		}
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input store.RepresentativeAssignment
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		if input.GroupID != "" && strings.TrimSpace(input.GroupID) != groupID {
			writeError(response, http.StatusBadRequest, errors.New("representative group does not match route"))
			return
		}
		input.GroupID = groupID
		assignment, err := h.control.CreateRepresentativeAssignment(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, assignment)
		return
	}
	if len(remainder) == 1 && request.Method == http.MethodGet {
		assignment, err := h.control.RepresentativeAssignment(remainder[0])
		if err != nil {
			managementError(response, err)
			return
		}
		if assignment.GroupID != groupID {
			writeError(response, http.StatusNotFound, errors.New("representative assignment not found"))
			return
		}
		writeJSON(response, http.StatusOK, assignment)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("representative route not found"))
}

// groupCards is the global card collection route. The nested route remains
// the preferred spelling because it makes the Group scope visible in the URL;
// this collection is useful for operators and tests that provision from a
// single management client.
func (h *Handler) groupCardsCollection(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	if request.URL.Path != "/v1/group-cards" && request.URL.Path != "/v1/federation/group-cards" {
		writeError(response, http.StatusNotFound, errors.New("group card route not found"))
		return
	}
	switch request.Method {
	case http.MethodGet:
		cards, err := h.control.GroupCards(request.URL.Query().Get("group_id"))
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"group_cards": cards})
	case http.MethodPost:
		var input store.GroupCard
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		card, err := h.control.CreateGroupCard(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, card)
	default:
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (h *Handler) groupCardCollectionItem(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	prefix := "/v1/group-cards/"
	if strings.HasPrefix(request.URL.Path, "/v1/federation/group-cards/") {
		prefix = "/v1/federation/group-cards/"
	}
	remainder := strings.TrimPrefix(request.URL.Path, prefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("group card not found"))
		return
	}
	if len(parts) == 1 && parts[0] == "publish" && request.Method == http.MethodPost {
		var input store.GroupCard
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		card, err := h.control.PublishGroupCard(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, card)
		return
	}
	cardID, err := url.PathUnescape(parts[0])
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid group card id"))
		return
	}
	card, err := h.control.GroupCard(cardID)
	if err != nil {
		managementError(response, err)
		return
	}
	if len(parts) == 1 && request.Method == http.MethodGet {
		writeJSON(response, http.StatusOK, card)
		return
	}
	if len(parts) == 2 && parts[1] == "publish" && request.Method == http.MethodPost {
		var input store.GroupCard
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		mergeGroupCardInput(&input, *card)
		input.ID = card.ID
		published, err := h.control.PublishGroupCard(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, published)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("group card route not found"))
}

func mergeGroupCardInput(input *store.GroupCard, existing store.GroupCard) {
	if input.ID == "" {
		input.ID = existing.ID
	}
	if input.CardID == "" {
		input.CardID = existing.CardID
	}
	if input.GroupID == "" {
		input.GroupID = existing.GroupID
	}
	if input.Version == 0 {
		input.Version = existing.Version
	}
	if input.TrustDomainID == "" {
		input.TrustDomainID = existing.TrustDomainID
	}
	if len(input.PublicCapabilities) == 0 {
		input.PublicCapabilities = existing.PublicCapabilities
	}
	if len(input.RepresentativeEndpointIDs) == 0 {
		input.RepresentativeEndpointIDs = existing.RepresentativeEndpointIDs
	}
	if input.InputContracts == nil {
		input.InputContracts = existing.InputContracts
	}
	if input.OutputContracts == nil {
		input.OutputContracts = existing.OutputContracts
	}
	if input.SecuritySummary == nil {
		input.SecuritySummary = existing.SecuritySummary
	}
	if input.SecuritySummaryRef == "" {
		input.SecuritySummaryRef = existing.SecuritySummaryRef
	}
	if input.AvailabilityAt == "" {
		input.AvailabilityAt = existing.AvailabilityAt
	}
	if input.ExpiresAt == "" {
		input.ExpiresAt = existing.ExpiresAt
	}
}

func (h *Handler) federationContracts(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	if request.URL.Path != "/v1/federation/contracts" {
		writeError(response, http.StatusNotFound, errors.New("federation contract route not found"))
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input store.FederationContract
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	contract, err := h.control.CreateFederationContract(input)
	if err != nil {
		managementError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, contract)
}

func (h *Handler) federationContract(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	prefix := "/v1/federation/contracts/"
	remainder := strings.TrimPrefix(request.URL.Path, prefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("federation contract not found"))
		return
	}
	if len(parts) == 1 && parts[0] == "publish" && request.Method == http.MethodPost {
		var input store.FederationContract
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		contract, err := h.control.PublishFederationContract(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, contract)
		return
	}
	contractID, err := url.PathUnescape(parts[0])
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid federation contract id"))
		return
	}
	contract, err := h.control.FederationContract(contractID)
	if err != nil {
		managementError(response, err)
		return
	}
	if len(parts) == 1 && request.Method == http.MethodGet {
		writeJSON(response, http.StatusOK, contract)
		return
	}
	if len(parts) == 2 && parts[1] == "publish" && request.Method == http.MethodPost {
		var input store.FederationContract
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		mergeFederationContractInput(&input, *contract)
		input.ID = contract.ID
		published, err := h.control.PublishFederationContract(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, published)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("federation contract route not found"))
}

func mergeFederationContractInput(input *store.FederationContract, existing store.FederationContract) {
	if input.ID == "" {
		input.ID = existing.ID
	}
	if input.ContractID == "" {
		input.ContractID = existing.ContractID
	}
	if input.SourceGroupID == "" {
		input.SourceGroupID = existing.SourceGroupID
	}
	if input.TargetGroupID == "" {
		input.TargetGroupID = existing.TargetGroupID
	}
	if input.Capability == "" {
		input.Capability = existing.Capability
	}
	if len(input.Scopes) == 0 {
		input.Scopes = existing.Scopes
	}
	if input.Version == 0 {
		input.Version = existing.Version
	}
	if input.ExpiresAt == "" {
		input.ExpiresAt = existing.ExpiresAt
	}
	if input.NotBefore == "" {
		input.NotBefore = existing.NotBefore
	}
	if input.AuthorizationRef == "" {
		input.AuthorizationRef = existing.AuthorizationRef
	}
	if input.SourceAuthorizationRef == "" {
		input.SourceAuthorizationRef = existing.SourceAuthorizationRef
	}
	if input.TargetAuthorizationRef == "" {
		input.TargetAuthorizationRef = existing.TargetAuthorizationRef
	}
	if input.InputContract == nil {
		input.InputContract = existing.InputContract
	}
	if input.OutputContract == nil {
		input.OutputContract = existing.OutputContract
	}
}

func (h *Handler) representativeAssignments(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	if request.URL.Path != "/v1/federation/representatives" {
		writeError(response, http.StatusNotFound, errors.New("representative route not found"))
		return
	}
	switch request.Method {
	case http.MethodGet:
		assignments, err := h.control.RepresentativeAssignments(store.RepresentativeAssignmentFilter{
			GroupID: request.URL.Query().Get("group_id"), PrincipalID: request.URL.Query().Get("principal_id"),
			EndpointID: request.URL.Query().Get("endpoint_id"), Status: request.URL.Query().Get("status"), Limit: queryInt(request, "limit", 200),
		})
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"representative_assignments": assignments})
	case http.MethodPost:
		var input store.RepresentativeAssignment
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		assignment, err := h.control.CreateRepresentativeAssignment(input)
		if err != nil {
			managementError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, assignment)
	default:
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (h *Handler) representativeAssignment(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	prefix := "/v1/federation/representatives/"
	id := strings.TrimPrefix(request.URL.Path, prefix)
	if strings.Contains(id, "/") || strings.TrimSpace(id) == "" || request.Method != http.MethodGet {
		writeError(response, http.StatusNotFound, errors.New("representative route not found"))
		return
	}
	decoded, err := url.PathUnescape(id)
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid representative assignment id"))
		return
	}
	assignment, err := h.control.RepresentativeAssignment(decoded)
	if err != nil {
		managementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, assignment)
}

func managementError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, store.ErrGroupNotFound),
		errors.Is(err, store.ErrPrincipalNotFound), errors.Is(err, store.ErrMembershipNotFound),
		errors.Is(err, store.ErrEndpointNotFound), errors.Is(err, store.ErrGroupCardNotFound),
		errors.Is(err, store.ErrFederationContractNotFound), errors.Is(err, store.ErrRepresentativeAssignmentNotFound):
		status = http.StatusNotFound
	case errors.Is(err, store.ErrVersionConflict):
		status = http.StatusConflict
	case errors.Is(err, store.ErrMembershipNotActive), errors.Is(err, store.ErrEndpointMigrationRequired),
		errors.Is(err, store.ErrGatewayGroupMismatch), errors.Is(err, store.ErrGatewayScopeDenied),
		errors.Is(err, store.ErrGatewayContractExpired), errors.Is(err, store.ErrGatewayAuthorization):
		status = http.StatusForbidden
	}
	writeError(response, status, err)
}
