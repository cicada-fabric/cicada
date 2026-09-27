package control

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

type GroupCreateInput struct {
	Name             string `json:"name"`
	Purpose          string `json:"purpose,omitempty"`
	PolicyRef        string `json:"policy_ref,omitempty"`
	ContextPolicy    string `json:"context_policy,omitempty"`
	IsolationProfile string `json:"isolation_profile,omitempty"`
	ExternalMode     string `json:"external_mode,omitempty"`
}

type GroupMemberInput struct {
	PrincipalID   string         `json:"principal_id"`
	Name          string         `json:"name,omitempty"`
	Role          string         `json:"role,omitempty"`
	Roles         []string       `json:"roles,omitempty"`
	Grants        []string       `json:"grants,omitempty"`
	Authorization map[string]any `json:"authorization,omitempty"`
}

// MembershipRoleBindingInput is deliberately separate from GroupMemberInput.
// Joining a Fabric session creates (or reuses) a plain membership; it never
// grants an execution or representative role.  A role is an explicit,
// versioned management-plane authorization change.
type MembershipRoleBindingInput struct {
	GroupID         string   `json:"group_id,omitempty"`
	MembershipID    string   `json:"membership_id,omitempty"`
	Role            string   `json:"role"`
	Roles           []string `json:"roles,omitempty"`
	Version         int64    `json:"version,omitempty"`
	ExpectedVersion int64    `json:"expected_version,omitempty"`
}

const (
	groupRoleMember  = "member"
	groupRoleWorker  = "worker"
	groupRoleMonitor = "monitor"
)

var roleBindingGrants = map[string][]string{
	groupRoleWorker:  {"federation.request", "federation.produce", "task.read", "task.claim", "task.submit", "artifact.publish", "resource.execute"},
	groupRoleMonitor: {"federation.represent", "task.read", "task.verify", "artifact.share"},
}

var roleGrantNames = map[string]struct{}{
	"federation.request":   {},
	"federation.produce":   {},
	"federation.represent": {},
	"task.claim":           {},
	"task.submit":          {},
	"task.verify":          {},
	"artifact.publish":     {},
	"artifact.share":       {},
	"resource.execute":     {},
}

// CreateGroup is a management-plane operation. It creates the local human
// owner Principal and owner Membership explicitly; Fabric peer operations only
// read the resulting authority and never call this method.
func (c *Control) CreateGroup(input GroupCreateInput) (*store.Group, error) {
	identity := c.Identity()
	if strings.TrimSpace(identity.ID) == "" {
		return nil, errors.New("local control identity is unavailable")
	}
	return c.createGroupForOwner(identity.ID, input)
}

func (c *Control) createGroupForOwner(ownerID string, input GroupCreateInput) (*store.Group, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return nil, errors.New("group name is required")
	}
	if err := c.store.EnsureLocalOwnerPrincipal(ownerID); err != nil {
		return nil, err
	}
	owner, err := c.store.GetPrincipal(ownerID)
	if err != nil {
		return nil, err
	}
	if input.ContextPolicy == "" {
		input.ContextPolicy = "group_scoped"
	}
	if input.IsolationProfile == "" {
		input.IsolationProfile = "trusted_host"
	}
	if input.ExternalMode == "" {
		input.ExternalMode = "monitor_mediated"
	}
	group, err := c.store.CreateGroup(store.Group{
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID, Name: input.Name,
		State: store.GroupStateActive, Purpose: strings.TrimSpace(input.Purpose),
		PolicyRef: strings.TrimSpace(input.PolicyRef), ContextPolicy: input.ContextPolicy,
		IsolationProfile: input.IsolationProfile, ExternalMode: input.ExternalMode,
	})
	if err != nil {
		return nil, err
	}
	if _, err := c.store.UpsertMembership(store.Membership{
		PrincipalID: owner.ID, GroupID: group.ID, Role: "owner",
		Roles: []string{"owner"}, Grants: []string{"group.manage", "membership.manage", "representative.manage", "policy.manage"},
		Status: store.MembershipStatusActive,
	}); err != nil {
		return nil, err
	}
	return group, nil
}

func (c *Control) Groups() ([]store.Group, error) {
	return c.store.ListGroups(store.GroupFilter{Limit: 200})
}

func (c *Control) Group(id string) (*store.Group, error) {
	return c.store.GetGroup(strings.TrimSpace(id))
}

// SetGroupParent is a versioned management edit. Fabric authorization remains
// attached to explicit Principal and Endpoint memberships in each Group.
func (c *Control) SetGroupParent(groupID, parentGroupID string, expectedVersion int64) (*store.Group, error) {
	return c.store.SetGroupParent(groupID, parentGroupID, expectedVersion)
}

func (c *Control) AddGroupMember(groupID string, input GroupMemberInput) (*store.Membership, error) {
	groupID = strings.TrimSpace(groupID)
	if _, err := c.store.GetGroup(groupID); err != nil {
		return nil, err
	}
	// Membership creation is intentionally limited to the base member role.
	// Worker/Monitor are authority bindings and must go through
	// BindMembershipRole, which performs an optimistic version check.
	role := strings.ToLower(strings.TrimSpace(input.Role))
	if role == "" {
		role = groupRoleMember
	}
	if role != groupRoleMember {
		return nil, errors.New("only the member role may be created with a membership; bind worker or monitor explicitly")
	}
	for _, candidate := range input.Roles {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			continue
		}
		if candidate != groupRoleMember {
			return nil, errors.New("worker and monitor require an explicit role binding")
		}
	}
	for _, grant := range input.Grants {
		if _, roleGrant := roleGrantNames[strings.ToLower(strings.TrimSpace(grant))]; roleGrant {
			return nil, errors.New("federation role grants require an explicit role binding")
		}
	}
	for grant, value := range input.Authorization {
		if _, roleGrant := roleGrantNames[strings.ToLower(strings.TrimSpace(grant))]; roleGrant {
			if allowed, ok := value.(bool); !ok || allowed {
				return nil, errors.New("federation role grants require an explicit role binding")
			}
		}
	}
	principalID := strings.TrimSpace(input.PrincipalID)
	if principalID == "" {
		name := strings.TrimSpace(input.Name)
		if name == "" {
			return nil, errors.New("principal_id or name is required")
		}
		principal, err := c.store.CreatePrincipal(store.Principal{
			Kind: store.PrincipalKindAgent, OwnerID: c.Identity().ID,
			TrustDomainID: c.Identity().ID, Name: name, DisplayName: name,
			Status: store.PrincipalStatusActive,
		})
		if err != nil {
			return nil, err
		}
		principalID = principal.ID
	} else if _, err := c.store.GetPrincipal(principalID); err != nil {
		return nil, err
	}
	roles := input.Roles
	if len(roles) == 0 {
		roles = []string{role}
	}
	grants := input.Grants
	if len(grants) == 0 {
		grants = []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"}
	}
	return c.store.UpsertMembership(store.Membership{
		PrincipalID: principalID, GroupID: groupID, Role: role, Roles: roles,
		Grants: grants, Authorization: input.Authorization,
		Status: store.MembershipStatusActive,
	})
}

// BindMembershipRole applies one of the three supported Group roles through
// the store's compare-and-swap authorization writer.  The Group and
// Membership IDs are checked independently so a caller cannot use a valid
// membership ID under another Group; expectedVersion is mandatory so stale
// management clients cannot silently overwrite a newer authorization.
func (c *Control) BindMembershipRole(groupID, membershipID, role string, expectedVersion int64) (*store.Membership, error) {
	groupID = strings.TrimSpace(groupID)
	membershipID = strings.TrimSpace(membershipID)
	if groupID == "" || membershipID == "" {
		return nil, errors.New("group_id and membership_id are required")
	}
	if expectedVersion <= 0 {
		return nil, errors.New("membership version is required")
	}
	if _, err := c.store.GetGroup(groupID); err != nil {
		return nil, err
	}
	membership, err := c.store.GetMembership(membershipID)
	if err != nil {
		return nil, err
	}
	if membership.GroupID != groupID {
		return nil, fmt.Errorf("membership %q does not belong to group %q", membershipID, groupID)
	}
	if membership.Version != expectedVersion {
		return nil, store.ErrVersionConflict
	}
	if membership.Status != store.MembershipStatusActive {
		// UpdateMembershipAuthorization is intentionally a low-level CAS writer;
		// management role binding must reject revoked/suspended memberships before
		// it reaches that writer. Expiry is also checked below by IsMembershipActive.
		return nil, store.ErrMembershipNotActive
	}
	active, err := c.store.IsMembershipActive(membership.PrincipalID, membership.GroupID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, store.ErrMembershipNotActive
	}

	role = strings.ToLower(strings.TrimSpace(role))
	if role != groupRoleMember && role != groupRoleWorker && role != groupRoleMonitor {
		return nil, errors.New("role must be member, worker, or monitor")
	}

	// Preserve all existing non-role grants, including the normal Group
	// message grants. Remove grants owned by a previous execution role before
	// adding the new role's grants so a worker/monitor downgrade cannot leave a
	// stale federation capability behind.
	grants := make([]string, 0, len(membership.Grants)+2)
	seen := make(map[string]struct{}, len(membership.Grants)+2)
	for _, grant := range membership.Grants {
		grant = strings.TrimSpace(grant)
		if grant == "" {
			continue
		}
		if _, roleGrant := roleGrantNames[strings.ToLower(grant)]; roleGrant {
			continue
		}
		if _, duplicate := seen[grant]; duplicate {
			continue
		}
		seen[grant] = struct{}{}
		grants = append(grants, grant)
	}
	for _, grant := range roleBindingGrants[role] {
		if _, duplicate := seen[grant]; duplicate {
			continue
		}
		seen[grant] = struct{}{}
		grants = append(grants, grant)
	}

	authorization := make(map[string]any, len(membership.Authorization))
	for grant, value := range membership.Authorization {
		if _, roleGrant := roleGrantNames[strings.ToLower(strings.TrimSpace(grant))]; roleGrant {
			continue
		}
		authorization[grant] = value
	}
	roles := []string{role}
	return c.store.UpdateMembershipAuthorization(membership.ID, roles, grants, authorization, expectedVersion)
}

// BindGroupMemberRole is the Group-scoped spelling used by management
// callers. Keep BindMembershipRole as the lower-level, identity-oriented
// spelling for in-process callers.
func (c *Control) BindGroupMemberRole(groupID, membershipID, role string, expectedVersion int64) (*store.Membership, error) {
	return c.BindMembershipRole(groupID, membershipID, role, expectedVersion)
}

// BindGroupMembershipRole is the plural Membership spelling used by some
// management clients. All aliases converge on the same versioned writer.
func (c *Control) BindGroupMembershipRole(groupID, membershipID, role string, expectedVersion int64) (*store.Membership, error) {
	return c.BindMembershipRole(groupID, membershipID, role, expectedVersion)
}

// UpdateGroupMemberRole is a compatibility alias for clients that model role
// binding as an update operation. It still takes the same mandatory CAS
// version and uses the same authorization writer.
func (c *Control) UpdateGroupMemberRole(groupID, membershipID, role string, expectedVersion int64) (*store.Membership, error) {
	return c.BindMembershipRole(groupID, membershipID, role, expectedVersion)
}

func (c *Control) BindRole(groupID, membershipID, role string, expectedVersion int64) (*store.Membership, error) {
	return c.BindMembershipRole(groupID, membershipID, role, expectedVersion)
}

func (c *Control) BindMembershipRoleInput(groupID, membershipID string, input MembershipRoleBindingInput) (*store.Membership, error) {
	if strings.TrimSpace(input.Role) == "" && len(input.Roles) == 1 {
		input.Role = input.Roles[0]
	}
	if len(input.Roles) > 1 {
		return nil, errors.New("role binding accepts exactly one role")
	}
	expectedVersion := input.ExpectedVersion
	if expectedVersion == 0 {
		expectedVersion = input.Version
	}
	return c.BindMembershipRole(groupID, membershipID, input.Role, expectedVersion)
}

func (c *Control) CreateMembershipRoleBinding(groupID, membershipID string, input MembershipRoleBindingInput) (*store.Membership, error) {
	return c.BindMembershipRoleInput(groupID, membershipID, input)
}

func (c *Control) GroupMembers(groupID string) ([]store.Membership, error) {
	if _, err := c.store.GetGroup(strings.TrimSpace(groupID)); err != nil {
		return nil, err
	}
	return c.store.ListMemberships(store.MembershipFilter{GroupID: strings.TrimSpace(groupID), Limit: 500})
}

func (c *Control) RevokeGroupMember(groupID, membershipID, reason string) (*store.Membership, error) {
	membership, err := c.store.GetMembership(strings.TrimSpace(membershipID))
	if err != nil {
		return nil, err
	}
	if membership.GroupID != strings.TrimSpace(groupID) {
		return nil, store.ErrMembershipNotFound
	}
	return c.store.RevokeMembership(membership.ID, strings.TrimSpace(reason))
}
