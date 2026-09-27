package control

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const ClientTopologyContractVersion = 1

// ClientTopologySnapshot is a metadata-only owner view for the management
// Client. It intentionally excludes credentials, capabilities, message bodies,
// prompts, key material, and link contract digests.
type ClientTopologySnapshot struct {
	ContractVersion  int                      `json:"contract_version"`
	OwnerPrincipalID string                   `json:"owner_principal_id"`
	CapturedAt       string                   `json:"captured_at"`
	ReadConsistency  string                   `json:"read_consistency"`
	Groups           []ClientTopologyGroup    `json:"groups"`
	Memberships      []ClientTopologyMember   `json:"memberships"`
	Endpoints        []ClientTopologyEndpoint `json:"endpoints"`
	Links            []ClientTopologyLink     `json:"links"`
}

type ClientTopologyGroup struct {
	GroupID       string `json:"group_id"`
	ParentGroupID string `json:"parent_group_id,omitempty"`
	Name          string `json:"name"`
	State         string `json:"state"`
	Version       int64  `json:"version"`
}

type ClientTopologyMember struct {
	MembershipID string   `json:"membership_id"`
	PrincipalID  string   `json:"principal_id"`
	DisplayName  string   `json:"display_name,omitempty"`
	GroupID      string   `json:"group_id"`
	Role         string   `json:"role"`
	Roles        []string `json:"roles,omitempty"`
	Status       string   `json:"status"`
	Version      int64    `json:"version"`
}

type ClientTopologyEndpoint struct {
	EndpointID      string   `json:"endpoint_id"`
	Name            string   `json:"name"`
	PrincipalID     string   `json:"principal_id"`
	GroupIDs        []string `json:"group_ids"`
	NodeID          string   `json:"node_id,omitempty"`
	Harness         string   `json:"harness,omitempty"`
	NativeSessionID string   `json:"native_session_id,omitempty"`
	Presence        string   `json:"presence"`
	BindingID       string   `json:"binding_id,omitempty"`
	BindingEpoch    uint64   `json:"binding_epoch,omitempty"`
	BindingStatus   string   `json:"binding_status,omitempty"`
}

type ClientTopologyLink struct {
	LinkID           string   `json:"link_id"`
	SourceEndpointID string   `json:"source_endpoint_id"`
	SourceGroupID    string   `json:"source_group_id"`
	TargetEndpointID string   `json:"target_endpoint_id"`
	TargetGroupID    string   `json:"target_group_id"`
	Direction        string   `json:"direction"`
	Actions          []string `json:"actions"`
	DataScopes       []string `json:"data_scopes"`
	TransportHubID   string   `json:"transport_hub_id,omitempty"`
	ExpiresAt        string   `json:"expires_at"`
	State            string   `json:"state"`
	Version          int64    `json:"version"`
}

type ClientTopologyActionKind string

const (
	ClientTopologyCreateGroup ClientTopologyActionKind = "group.create"
	ClientTopologySetParent   ClientTopologyActionKind = "group.set_parent"
	ClientTopologyJoinGroup   ClientTopologyActionKind = "endpoint.join_group"
	ClientTopologyLeaveGroup  ClientTopologyActionKind = "endpoint.leave_group"
	ClientTopologyBindRole    ClientTopologyActionKind = "membership.bind_role"
	ClientTopologyProposeLink ClientTopologyActionKind = "link.propose"
	ClientTopologyRevokeLink  ClientTopologyActionKind = "link.revoke"
)

// ClientTopologyAction is a tagged union. Exactly one payload must be set and
// it must match Kind. Object-specific versions are used where the Store
// supports compare-and-swap; the API does not invent a global topology version.
type ClientTopologyAction struct {
	Kind        ClientTopologyActionKind         `json:"kind"`
	CreateGroup *ClientTopologyCreateGroupAction `json:"create_group,omitempty"`
	SetParent   *ClientTopologySetParentAction   `json:"set_parent,omitempty"`
	JoinGroup   *ClientTopologyJoinGroupAction   `json:"join_group,omitempty"`
	LeaveGroup  *ClientTopologyLeaveGroupAction  `json:"leave_group,omitempty"`
	BindRole    *ClientTopologyBindRoleAction    `json:"bind_role,omitempty"`
	ProposeLink *ClientTopologyProposeLinkAction `json:"propose_link,omitempty"`
	RevokeLink  *ClientTopologyRevokeLinkAction  `json:"revoke_link,omitempty"`
}

type ClientTopologyCreateGroupAction struct {
	Group         GroupCreateInput `json:"group"`
	ParentGroupID string           `json:"parent_group_id,omitempty"`
}

type ClientTopologySetParentAction struct {
	GroupID              string `json:"group_id"`
	ParentGroupID        string `json:"parent_group_id,omitempty"`
	ExpectedGroupVersion int64  `json:"expected_group_version"`
}

type ClientTopologyJoinGroupAction struct {
	EndpointID string `json:"endpoint_id"`
	GroupID    string `json:"group_id"`
}

type ClientTopologyLeaveGroupAction struct {
	EndpointID           string `json:"endpoint_id"`
	GroupID              string `json:"group_id"`
	BindingID            string `json:"binding_id"`
	ExpectedBindingEpoch uint64 `json:"expected_binding_epoch"`
}

type ClientTopologyBindRoleAction struct {
	GroupID                   string `json:"group_id"`
	MembershipID              string `json:"membership_id"`
	Role                      string `json:"role"`
	ExpectedMembershipVersion int64  `json:"expected_membership_version"`
}

type ClientTopologyProposeLinkAction struct {
	Proposal CommunicationLinkProposalInput `json:"proposal"`
}

type ClientTopologyRevokeLinkAction struct {
	LinkID              string `json:"link_id"`
	ExpectedLinkVersion int64  `json:"expected_link_version"`
	Reason              string `json:"reason,omitempty"`
}

type ClientTopologyChangeResult struct {
	ContractVersion  int                            `json:"contract_version"`
	Action           ClientTopologyActionKind       `json:"action"`
	Changed          bool                           `json:"changed"`
	Group            *ClientTopologyGroup           `json:"group,omitempty"`
	EndpointGroup    *store.EndpointGroupMembership `json:"endpoint_group,omitempty"`
	RemainingGroupID string                         `json:"remaining_group_id,omitempty"`
	Membership       *ClientTopologyMember          `json:"membership,omitempty"`
	Link             *ClientTopologyLink            `json:"link,omitempty"`
}

// BuildClientTopologySnapshot returns current owner-managed Group,
// Membership, Endpoint, and communication-link metadata. The authenticated
// owner must be supplied by the transport after verifying the Client device;
// this method performs an additional single-owner Control scope check.
func (c *Control) BuildClientTopologySnapshot(authenticatedOwnerID string) (*ClientTopologySnapshot, error) {
	if err := c.ValidateClientOwnerScope(authenticatedOwnerID); err != nil {
		return nil, err
	}
	ownerID := strings.TrimSpace(authenticatedOwnerID)
	groups, err := c.store.ListGroups(store.GroupFilter{Owner: ownerID, Limit: 1000})
	if err != nil {
		return nil, err
	}
	ownedGroups := make(map[string]store.Group, len(groups))
	view := &ClientTopologySnapshot{
		ContractVersion: ClientTopologyContractVersion, OwnerPrincipalID: ownerID,
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), ReadConsistency: "best_effort",
		Groups:      make([]ClientTopologyGroup, 0, len(groups)),
		Memberships: make([]ClientTopologyMember, 0),
		Endpoints:   make([]ClientTopologyEndpoint, 0),
		Links:       make([]ClientTopologyLink, 0),
	}
	for _, group := range groups {
		if group.OwnerPrincipalID != ownerID {
			continue
		}
		ownedGroups[group.ID] = group
	}
	for _, group := range groups {
		if _, ok := ownedGroups[group.ID]; !ok {
			continue
		}
		parentID := group.ParentGroupID
		if _, ok := ownedGroups[parentID]; !ok {
			parentID = ""
		}
		view.Groups = append(view.Groups, ClientTopologyGroup{
			GroupID: group.ID, ParentGroupID: parentID, Name: group.Name, State: group.State, Version: group.Version,
		})
		memberships, err := c.store.ListMemberships(store.MembershipFilter{GroupID: group.ID, Limit: 1000})
		if err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			principal, err := c.store.GetPrincipal(membership.PrincipalID)
			if err != nil {
				return nil, err
			}
			if principal == nil {
				return nil, store.ErrPrincipalNotFound
			}
			// In the current dedicated-owner database, only project principals
			// owned by this authenticated owner. This is defense in depth against
			// foreign principals manually placed into an owner Group.
			if principal.OwnerID != ownerID {
				continue
			}
			view.Memberships = append(view.Memberships, ClientTopologyMember{
				MembershipID: membership.ID, PrincipalID: principal.ID, DisplayName: principal.DisplayName,
				GroupID: group.ID, Role: membership.Role, Roles: append([]string(nil), membership.Roles...),
				Status: membership.Status, Version: membership.Version,
			})
		}
		if group.State != store.GroupStateActive {
			continue
		}
		endpoints, err := c.store.ListEndpointsV2(store.EndpointV2Filter{GroupID: group.ID, Limit: 1000})
		if err != nil {
			return nil, err
		}
		for _, endpoint := range endpoints {
			if endpoint.PrincipalID == "" {
				continue
			}
			principal, err := c.store.GetPrincipal(endpoint.PrincipalID)
			if err != nil {
				return nil, err
			}
			if principal == nil {
				return nil, store.ErrPrincipalNotFound
			}
			if principal.OwnerID != ownerID {
				continue
			}
			entryIndex := -1
			for i := range view.Endpoints {
				if view.Endpoints[i].EndpointID == endpoint.ID {
					entryIndex = i
					break
				}
			}
			if entryIndex < 0 {
				entry := ClientTopologyEndpoint{
					EndpointID: endpoint.ID, Name: endpoint.Name, PrincipalID: principal.ID,
					GroupIDs: []string{}, NodeID: endpoint.MachineID, Harness: endpoint.Harness,
					NativeSessionID: endpoint.NativeSessionID, Presence: endpoint.Status,
				}
				if binding, bindingErr := c.store.GetActiveSessionBinding(endpoint.ID); bindingErr == nil {
					entry.BindingID, entry.BindingEpoch, entry.BindingStatus = binding.ID, binding.Epoch, binding.Status
				} else if !errors.Is(bindingErr, store.ErrSessionBindingNotFound) {
					return nil, bindingErr
				}
				view.Endpoints = append(view.Endpoints, entry)
				entryIndex = len(view.Endpoints) - 1
			}
			view.Endpoints[entryIndex].GroupIDs = append(view.Endpoints[entryIndex].GroupIDs, group.ID)
		}
	}
	links, err := c.store.ListCommunicationLinksForOwner(ownerID, 200)
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.SourceOwnerID != ownerID || link.TargetOwnerID != ownerID {
			continue
		}
		view.Links = append(view.Links, projectClientTopologyLink(link))
	}
	sort.Slice(view.Groups, func(i, j int) bool { return view.Groups[i].GroupID < view.Groups[j].GroupID })
	sort.Slice(view.Memberships, func(i, j int) bool {
		if view.Memberships[i].GroupID == view.Memberships[j].GroupID {
			return view.Memberships[i].MembershipID < view.Memberships[j].MembershipID
		}
		return view.Memberships[i].GroupID < view.Memberships[j].GroupID
	})
	sort.Slice(view.Endpoints, func(i, j int) bool { return view.Endpoints[i].EndpointID < view.Endpoints[j].EndpointID })
	for i := range view.Endpoints {
		sort.Strings(view.Endpoints[i].GroupIDs)
	}
	sort.Slice(view.Links, func(i, j int) bool { return view.Links[i].LinkID < view.Links[j].LinkID })
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return view, nil
}

// ApplyClientTopologyChange executes one explicitly typed owner action. It
// derives the acting owner from the authenticated transport argument and
// reuses Control and Store authorization/CAS checks. Cross-owner links remain
// rejected by the Store and are never activated by this method.
func (c *Control) ApplyClientTopologyChange(authenticatedOwnerID string, action ClientTopologyAction) (*ClientTopologyChangeResult, error) {
	if err := c.ValidateClientOwnerScope(authenticatedOwnerID); err != nil {
		return nil, err
	}
	ownerID := strings.TrimSpace(authenticatedOwnerID)
	if err := validateClientTopologyUnion(action); err != nil {
		return nil, err
	}
	result := &ClientTopologyChangeResult{ContractVersion: ClientTopologyContractVersion, Action: action.Kind, Changed: true}
	switch action.Kind {
	case ClientTopologyCreateGroup:
		input := action.CreateGroup
		parentID := strings.TrimSpace(input.ParentGroupID)
		if parentID != "" {
			if _, err := c.clientOwnedGroup(ownerID, parentID); err != nil {
				return nil, err
			}
		}
		group, err := c.CreateGroup(input.Group)
		if err != nil {
			return nil, err
		}
		// Group creation has no Store transaction that includes SetGroupParent;
		// this is an intentionally visible two-step operation. A parent update
		// error can leave the newly created group as a root Group.
		if parentID != "" {
			group, err = c.store.SetGroupParent(group.ID, parentID, group.Version)
			if err != nil {
				return nil, fmt.Errorf("group was created but parent assignment failed: %w", err)
			}
		}
		result.Group = projectClientTopologyGroup(*group)
	case ClientTopologySetParent:
		input := action.SetParent
		if _, err := c.clientOwnedGroup(ownerID, input.GroupID); err != nil {
			return nil, err
		}
		if input.ParentGroupID != "" {
			if _, err := c.clientOwnedGroup(ownerID, input.ParentGroupID); err != nil {
				return nil, err
			}
		}
		group, err := c.store.SetGroupParent(input.GroupID, input.ParentGroupID, input.ExpectedGroupVersion)
		if err != nil {
			return nil, err
		}
		result.Group = projectClientTopologyGroup(*group)
	case ClientTopologyJoinGroup:
		input := action.JoinGroup
		if _, err := c.clientOwnedGroup(ownerID, input.GroupID); err != nil {
			return nil, err
		}
		endpoint, err := c.clientOwnedEndpoint(ownerID, input.EndpointID)
		if err != nil {
			return nil, err
		}
		if _, err := c.store.GetMembershipByPrincipalGroup(endpoint.PrincipalID, input.GroupID); err != nil {
			return nil, store.ErrMembershipNotActive
		}
		joined, err := c.store.JoinEndpointGroup(input.EndpointID, input.GroupID)
		if err != nil {
			return nil, err
		}
		result.EndpointGroup = joined
	case ClientTopologyLeaveGroup:
		input := action.LeaveGroup
		if _, err := c.clientOwnedGroup(ownerID, input.GroupID); err != nil {
			return nil, err
		}
		if _, err := c.clientOwnedEndpoint(ownerID, input.EndpointID); err != nil {
			return nil, err
		}
		remaining, err := c.store.LeaveEndpointGroup(input.EndpointID, input.GroupID, input.BindingID, input.ExpectedBindingEpoch, "client topology change")
		if err != nil {
			return nil, err
		}
		result.RemainingGroupID = remaining
	case ClientTopologyBindRole:
		input := action.BindRole
		if _, err := c.clientOwnedGroup(ownerID, input.GroupID); err != nil {
			return nil, err
		}
		membership, err := c.store.GetMembership(input.MembershipID)
		if err != nil {
			return nil, err
		}
		if membership == nil {
			return nil, store.ErrMembershipNotFound
		}
		if membership.GroupID != input.GroupID {
			return nil, store.ErrMembershipNotFound
		}
		principal, err := c.store.GetPrincipal(membership.PrincipalID)
		if err != nil {
			return nil, err
		}
		if principal == nil {
			return nil, store.ErrPrincipalNotFound
		}
		if principal.OwnerID != ownerID {
			return nil, ErrPermissionDenied
		}
		updated, err := c.BindMembershipRole(input.GroupID, input.MembershipID, input.Role, input.ExpectedMembershipVersion)
		if err != nil {
			return nil, err
		}
		result.Membership = projectClientTopologyMember(*updated, principal.DisplayName)
	case ClientTopologyProposeLink:
		input := action.ProposeLink.Proposal
		if _, err := c.clientOwnedGroup(ownerID, input.SourceGroupID); err != nil {
			return nil, err
		}
		if _, err := c.clientOwnedGroup(ownerID, input.TargetGroupID); err != nil {
			return nil, err
		}
		if _, err := c.clientOwnedEndpoint(ownerID, input.SourceEndpointID); err != nil {
			return nil, err
		}
		if _, err := c.clientOwnedEndpoint(ownerID, input.TargetEndpointID); err != nil {
			return nil, err
		}
		link, err := c.ProposeCommunicationLink(input)
		if err != nil {
			return nil, err
		}
		result.Link = clientTopologyLinkIfOwned(*link, ownerID)
		if result.Link == nil {
			return nil, ErrPermissionDenied
		}
	case ClientTopologyRevokeLink:
		input := action.RevokeLink
		link, err := c.CommunicationLink(input.LinkID)
		if err != nil {
			return nil, err
		}
		if link == nil {
			return nil, store.ErrCommunicationLinkNotFound
		}
		if link.SourceOwnerID != ownerID || link.TargetOwnerID != ownerID {
			return nil, ErrPermissionDenied
		}
		revoked, err := c.RevokeCommunicationLink(input.LinkID, input.ExpectedLinkVersion, input.Reason)
		if err != nil {
			return nil, err
		}
		projected := projectClientTopologyLink(*revoked)
		result.Link = &projected
	default:
		return nil, errors.New("unsupported topology action")
	}
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return result, nil
}

func validateClientTopologyUnion(action ClientTopologyAction) error {
	count := 0
	for _, present := range []bool{
		action.CreateGroup != nil, action.SetParent != nil, action.JoinGroup != nil,
		action.LeaveGroup != nil, action.BindRole != nil, action.ProposeLink != nil,
		action.RevokeLink != nil,
	} {
		if present {
			count++
		}
	}
	if count != 1 {
		return errors.New("topology action must contain exactly one operation payload")
	}
	valid := map[ClientTopologyActionKind]bool{
		ClientTopologyCreateGroup: action.CreateGroup != nil,
		ClientTopologySetParent:   action.SetParent != nil,
		ClientTopologyJoinGroup:   action.JoinGroup != nil,
		ClientTopologyLeaveGroup:  action.LeaveGroup != nil,
		ClientTopologyBindRole:    action.BindRole != nil,
		ClientTopologyProposeLink: action.ProposeLink != nil,
		ClientTopologyRevokeLink:  action.RevokeLink != nil,
	}
	if !valid[action.Kind] {
		return errors.New("topology action kind does not match its operation payload")
	}
	return nil
}

func (c *Control) clientOwnedGroup(ownerID, groupID string) (*store.Group, error) {
	group, err := c.store.GetGroup(strings.TrimSpace(groupID))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, store.ErrGroupNotFound
	}
	if group.OwnerPrincipalID != ownerID {
		return nil, ErrPermissionDenied
	}
	return group, nil
}

func (c *Control) clientOwnedEndpoint(ownerID, endpointID string) (*store.Endpoint, error) {
	endpoint, err := c.store.GetEndpointWithIdentity(strings.TrimSpace(endpointID))
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, store.ErrEndpointNotFound
	}
	if endpoint.PrincipalID == "" || endpoint.MigrationState != store.EndpointMigrationReady {
		return nil, store.ErrEndpointMigrationRequired
	}
	principal, err := c.store.GetPrincipal(endpoint.PrincipalID)
	if err != nil {
		return nil, err
	}
	if principal == nil {
		return nil, store.ErrPrincipalNotFound
	}
	if principal.OwnerID != ownerID || principal.Status != store.PrincipalStatusActive {
		return nil, ErrPermissionDenied
	}
	return endpoint, nil
}

func projectClientTopologyGroup(group store.Group) *ClientTopologyGroup {
	return &ClientTopologyGroup{GroupID: group.ID, ParentGroupID: group.ParentGroupID, Name: group.Name, State: group.State, Version: group.Version}
}

func projectClientTopologyMember(membership store.Membership, displayName string) *ClientTopologyMember {
	return &ClientTopologyMember{
		MembershipID: membership.ID, PrincipalID: membership.PrincipalID, DisplayName: displayName,
		GroupID: membership.GroupID, Role: membership.Role, Roles: append([]string(nil), membership.Roles...),
		Status: membership.Status, Version: membership.Version,
	}
}

func projectClientTopologyLink(link store.CommunicationLink) ClientTopologyLink {
	return ClientTopologyLink{
		LinkID: link.ID, SourceEndpointID: link.SourceEndpointID, SourceGroupID: link.SourceGroupID,
		TargetEndpointID: link.TargetEndpointID, TargetGroupID: link.TargetGroupID,
		Direction: link.Direction, Actions: append([]string(nil), link.Actions...),
		DataScopes: append([]string(nil), link.DataScopes...), TransportHubID: link.TransportHubID,
		ExpiresAt: link.ExpiresAt, State: link.State, Version: link.Version,
	}
}

func clientTopologyLinkIfOwned(link store.CommunicationLink, ownerID string) *ClientTopologyLink {
	if link.SourceOwnerID != ownerID || link.TargetOwnerID != ownerID {
		return nil
	}
	projected := projectClientTopologyLink(link)
	return &projected
}
