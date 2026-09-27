package server

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

func (h *Handler) groups(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	switch request.Method {
	case http.MethodGet:
		groups, err := h.control.Groups()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"groups": groups})
	case http.MethodPost:
		var input control.GroupCreateInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		group, err := h.control.CreateGroup(input)
		if err != nil {
			groupError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, group)
	default:
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (h *Handler) group(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management plane is unavailable"))
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/v1/groups/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("group not found"))
		return
	}
	groupID, err := url.PathUnescape(parts[0])
	if err != nil || groupID == "" {
		writeError(response, http.StatusBadRequest, errors.New("invalid group id"))
		return
	}
	if len(parts) == 1 {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		group, err := h.control.Group(groupID)
		if err != nil {
			groupError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, group)
		return
	}
	if parts[1] == "parent" && len(parts) == 2 {
		if request.Method != http.MethodPut && request.Method != http.MethodPatch {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			ParentGroupID   string `json:"parent_group_id"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		group, err := h.control.SetGroupParent(groupID, input.ParentGroupID, input.ExpectedVersion)
		if err != nil {
			groupError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, group)
		return
	}
	if parts[1] != "members" {
		if parts[1] == "tasks" {
			h.groupTasks(response, request, groupID, parts[2:])
			return
		}
		if parts[1] == "representative-requests" {
			h.groupRepresentativeRequests(response, request, groupID, parts[2:])
			return
		}
		if parts[1] == "role-bindings" || parts[1] == "roles" {
			if len(parts) != 2 || (request.Method != http.MethodPost && request.Method != http.MethodPatch && request.Method != http.MethodPut) {
				writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
				return
			}
			var input control.MembershipRoleBindingInput
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
			if input.GroupID != "" && strings.TrimSpace(input.GroupID) != groupID {
				writeError(response, http.StatusBadRequest, errors.New("role binding group does not match route"))
				return
			}
			if strings.TrimSpace(input.MembershipID) == "" {
				writeError(response, http.StatusBadRequest, errors.New("membership_id is required"))
				return
			}
			membership, err := h.control.BindMembershipRoleInput(groupID, input.MembershipID, input)
			if err != nil {
				groupError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, membership)
			return
		}
		if parts[1] == "cards" || parts[1] == "card" || parts[1] == "group-cards" ||
			parts[1] == "representatives" || parts[1] == "representative-assignments" {
			resource := parts[1]
			if resource == "card" || resource == "group-cards" {
				resource = "cards"
			} else if resource == "representative-assignments" {
				resource = "representatives"
			}
			h.groupFederationProvisioning(response, request, groupID, resource, parts[2:])
			return
		}
		writeError(response, http.StatusNotFound, errors.New("group route not found"))
		return
	}
	if len(parts) == 2 {
		switch request.Method {
		case http.MethodGet:
			members, err := h.control.GroupMembers(groupID)
			if err != nil {
				groupError(response, err)
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"memberships": members})
		case http.MethodPost:
			var input control.GroupMemberInput
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
			membership, err := h.control.AddGroupMember(groupID, input)
			if err != nil {
				groupError(response, err)
				return
			}
			writeJSON(response, http.StatusCreated, membership)
		default:
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
		return
	}
	if len(parts) == 4 && (parts[3] == "role" || parts[3] == "roles" || parts[3] == "role-binding" || parts[3] == "authorization") &&
		(request.Method == http.MethodPost || request.Method == http.MethodPatch || request.Method == http.MethodPut) {
		membershipID, err := url.PathUnescape(parts[2])
		if err != nil || membershipID == "" {
			writeError(response, http.StatusBadRequest, errors.New("invalid membership id"))
			return
		}
		var input control.MembershipRoleBindingInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		membership, err := h.control.BindMembershipRoleInput(groupID, membershipID, input)
		if err != nil {
			groupError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, membership)
		return
	}
	if len(parts) == 4 && parts[3] == "revoke" && request.Method == http.MethodPost {
		membershipID, err := url.PathUnescape(parts[2])
		if err != nil || membershipID == "" {
			writeError(response, http.StatusBadRequest, errors.New("invalid membership id"))
			return
		}
		var input struct {
			Reason string `json:"reason"`
		}
		if err := readOptionalJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		membership, err := h.control.RevokeGroupMember(groupID, membershipID, input.Reason)
		if err != nil {
			groupError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, membership)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("group route not found"))
}

func groupError(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, store.ErrGroupNotFound) ||
		errors.Is(err, store.ErrPrincipalNotFound) || errors.Is(err, store.ErrMembershipNotFound) {
		status = http.StatusNotFound
	} else if errors.Is(err, store.ErrVersionConflict) {
		status = http.StatusConflict
	} else if errors.Is(err, store.ErrMembershipNotActive) {
		status = http.StatusForbidden
	}
	writeError(response, status, err)
}
