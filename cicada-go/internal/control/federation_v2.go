package control

// This file contains the v2 Group/Monitor/Federation provisioning facade.
// These methods are deliberately on Control rather than on Fabric: Fabric
// sessions may join and use their already-authorized membership, but they do
// not create public Group cards, bilateral contracts, or Monitor
// representative assignments.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// The aliases keep the management API's input types stable while allowing the
// store's versioned wire fields to be used directly by HTTP and in-process
// callers. A card/contract/assignment is still validated by Control before it
// reaches the persistence writer.
type GroupCardInput = store.GroupCard
type GroupCardCreateInput = store.GroupCard
type GroupCardPublishInput = store.GroupCard
type GroupCardProvisionInput = store.GroupCard
type FederationContractInput = store.FederationContract
type FederationContractCreateInput = store.FederationContract
type FederationContractPublishInput = store.FederationContract
type FederationContractProvisionInput = store.FederationContract
type RepresentativeAssignmentInput = store.RepresentativeAssignment
type RepresentativeCreateInput = store.RepresentativeAssignment
type RepresentativeAssignmentProvisionInput = store.RepresentativeAssignment

const groupCardDraftState = "DRAFT"

// CreateGroupCard provisions a public, versioned description for an existing
// Group. A card is a declaration; its endpoint and capability fields do not
// grant access by themselves. The gateway/store still checks contracts and
// representative assignments at request time.
func (c *Control) CreateGroupCard(input store.GroupCard) (*store.GroupCard, error) {
	input.GroupID = strings.TrimSpace(input.GroupID)
	if input.GroupID == "" {
		return nil, errors.New("group_id is required")
	}
	group, err := c.store.GetGroup(input.GroupID)
	if err != nil {
		return nil, err
	}
	if group.State == store.GroupStateArchived {
		return nil, errors.New("cannot publish a card for an archived group")
	}
	if strings.TrimSpace(input.TrustDomainID) == "" {
		input.TrustDomainID = group.TrustDomainID
	}
	input.State = strings.ToUpper(strings.TrimSpace(input.State))
	if input.State == "" {
		input.State = store.GroupCardPublished
	}
	switch input.State {
	case groupCardDraftState, store.GroupCardPublished, store.GroupCardRevoked:
	default:
		return nil, fmt.Errorf("unsupported group card state %q", input.State)
	}
	return c.store.CreateGroupCard(input)
}

// PublishGroupCard is the explicit management operation used by the HTTP
// publish route. Store cards are immutable by (group, version), so callers
// that publish a new version should provide that version in the input.
func (c *Control) PublishGroupCard(input store.GroupCard) (*store.GroupCard, error) {
	if strings.TrimSpace(input.ID) != "" {
		if existing, err := c.store.GetGroupCard(input.ID); err == nil {
			mergeGroupCardForPublish(&input, *existing)
		}
	}
	input.State = store.GroupCardPublished
	return c.CreateGroupCard(input)
}

// ProvisionGroupCard is an intentionally descriptive alias for callers that
// use "provision" for the management-plane operation.
func (c *Control) ProvisionGroupCard(input store.GroupCard) (*store.GroupCard, error) {
	return c.CreateGroupCard(input)
}

func (c *Control) GroupCard(id string) (*store.GroupCard, error) {
	return c.store.GetGroupCard(strings.TrimSpace(id))
}

func (c *Control) GroupCards(groupID string) ([]store.GroupCard, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID != "" {
		if _, err := c.store.GetGroup(groupID); err != nil {
			return nil, err
		}
	}
	return c.store.ListGroupCards(groupID, 200)
}

// CreateFederationContract provisions one bilateral contract. The source and
// target Groups are both resolved by Control so an arbitrary group ID cannot
// be published merely by writing a gateway row. The store keeps the contract
// immutable by source/target/capability/version and uses the two authorization
// references as the bilateral audit links.
func (c *Control) CreateFederationContract(input store.FederationContract) (*store.FederationContract, error) {
	input.SourceGroupID = strings.TrimSpace(input.SourceGroupID)
	input.TargetGroupID = strings.TrimSpace(input.TargetGroupID)
	if input.SourceGroupID == "" || input.TargetGroupID == "" {
		return nil, errors.New("source_group_id and target_group_id are required")
	}
	if input.SourceGroupID == input.TargetGroupID {
		return nil, store.ErrGatewayGroupMismatch
	}
	for _, groupID := range []string{input.SourceGroupID, input.TargetGroupID} {
		group, err := c.store.GetGroup(groupID)
		if err != nil {
			return nil, err
		}
		if group.State == store.GroupStateArchived {
			return nil, fmt.Errorf("group %q is archived", groupID)
		}
	}
	if strings.TrimSpace(input.Capability) == "" {
		return nil, errors.New("capability is required")
	}
	input.State = strings.ToUpper(strings.TrimSpace(input.State))
	if input.State == "" {
		input.State = store.FederationContractActive
	}
	switch input.State {
	case store.FederationContractDraft, store.FederationContractActive,
		store.FederationContractPaused, store.FederationContractExpired,
		store.FederationContractRevoked:
	default:
		return nil, fmt.Errorf("unsupported federation contract state %q", input.State)
	}
	return c.store.CreateFederationContract(input)
}

// PublishFederationContract is the explicit active-state management spelling.
// Contracts are versioned immutable records; publishing a changed contract
// therefore requires a new version.
func (c *Control) PublishFederationContract(input store.FederationContract) (*store.FederationContract, error) {
	// Gateway contracts are immutable by pair/capability/version. If an
	// operator created a DRAFT row, publishing it is represented by the next
	// version so the store's digest and audit history remain immutable.
	if strings.TrimSpace(input.ID) != "" {
		if existing, err := c.store.GetFederationContract(input.ID); err == nil {
			mergeFederationContractForPublish(&input, *existing)
		}
	}
	input.State = store.FederationContractActive
	return c.CreateFederationContract(input)
}

func mergeGroupCardForPublish(input *store.GroupCard, existing store.GroupCard) {
	if input.CardID == "" {
		input.CardID = existing.CardID
	}
	if input.GroupID == "" {
		input.GroupID = existing.GroupID
	}
	if input.Version <= 0 {
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
	if existing.State != store.GroupCardPublished {
		if input.Version == existing.Version {
			input.Version = existing.Version + 1
		}
		input.ID = ""
		input.CardID = ""
		input.Digest = ""
	}
}

func mergeFederationContractForPublish(input *store.FederationContract, existing store.FederationContract) {
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
	if input.Version <= 0 {
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
	if existing.State != store.FederationContractActive {
		if input.Version == existing.Version {
			input.Version = existing.Version + 1
		}
		input.ID = ""
		input.ContractID = ""
		input.Digest = ""
	}
}

func (c *Control) ProvisionFederationContract(input store.FederationContract) (*store.FederationContract, error) {
	return c.CreateFederationContract(input)
}

func (c *Control) CreateBilateralFederationContract(input store.FederationContract) (*store.FederationContract, error) {
	return c.CreateFederationContract(input)
}

func (c *Control) FederationContract(id string) (*store.FederationContract, error) {
	return c.store.GetFederationContract(strings.TrimSpace(id))
}

// CreateRepresentativeAssignment is the only Control entry point for
// representative provisioning. Every identity relationship is checked here;
// the gateway store intentionally remains useful to protocol tests but does
// not infer endpoint/group/principal authority from a caller-supplied row.
func (c *Control) CreateRepresentativeAssignment(input store.RepresentativeAssignment) (*store.RepresentativeAssignment, error) {
	input.GroupID = strings.TrimSpace(input.GroupID)
	input.PrincipalID = strings.TrimSpace(input.PrincipalID)
	input.EndpointID = strings.TrimSpace(input.EndpointID)
	input.Status = strings.ToUpper(strings.TrimSpace(input.Status))
	if input.Status == "" {
		input.Status = store.RepresentativeAssignmentActive
	}
	if input.GroupID == "" || input.PrincipalID == "" || input.EndpointID == "" {
		return nil, errors.New("group_id, principal_id, and endpoint_id are required")
	}
	group, err := c.store.GetGroup(input.GroupID)
	if err != nil {
		return nil, err
	}
	if group.State != store.GroupStateActive {
		return nil, errors.New("representative group is not active")
	}
	principal, err := c.store.GetPrincipal(input.PrincipalID)
	if err != nil {
		return nil, err
	}
	if principal.Status != store.PrincipalStatusActive {
		return nil, store.ErrMembershipNotActive
	}

	endpoint, err := c.store.GetEndpointV2(input.EndpointID)
	if err != nil {
		return nil, err
	}
	if endpoint.MigrationState != store.EndpointMigrationReady {
		return nil, store.ErrEndpointMigrationRequired
	}
	// An offline representative is still assignable: its Gateway mailbox is
	// durable and requests wait until the same Endpoint reconnects. Leaving is
	// an explicit membership exit and must not create a usable assignment.
	if endpoint.Status == "left" {
		return nil, fmt.Errorf("%w: representative endpoint has left", store.ErrGatewayAuthorization)
	}
	if endpoint.GroupID != input.GroupID || endpoint.PrincipalID != input.PrincipalID {
		return nil, fmt.Errorf("%w: endpoint %q does not match representative group and principal", store.ErrGatewayGroupMismatch, input.EndpointID)
	}

	membership, err := c.store.GetMembershipByPrincipalGroup(input.PrincipalID, input.GroupID)
	if err != nil {
		return nil, err
	}
	if membership.Status != store.MembershipStatusActive {
		return nil, store.ErrMembershipNotActive
	}
	active, err := c.store.IsMembershipActive(input.PrincipalID, input.GroupID)
	if err != nil {
		return nil, err
	}
	if !active || !membershipHasRole(*membership, groupRoleMonitor) {
		return nil, fmt.Errorf("%w: representative requires an active monitor membership", store.ErrGatewayAuthorization)
	}

	contractIDs := representativeContractIDs(input)
	if len(contractIDs) == 0 {
		return nil, errors.New("at least one federation contract is required")
	}
	for _, contractID := range contractIDs {
		contract, getErr := c.store.GetFederationContract(contractID)
		if getErr != nil {
			return nil, getErr
		}
		if contract.SourceGroupID != input.GroupID && contract.TargetGroupID != input.GroupID {
			return nil, store.ErrGatewayGroupMismatch
		}
		if contract.State != store.FederationContractActive {
			return nil, store.ErrGatewayContractExpired
		}
	}
	// Normalize aliases before persistence so HTTP callers receive the same
	// durable shape regardless of whether they used contract_id or refs.
	input.ContractIDs = contractIDs
	input.ContractRefs = append([]string(nil), contractIDs...)
	input.ContractID = contractIDs[0]
	input.ContractRef = contractIDs[0]
	return c.store.CreateRepresentativeAssignment(input)
}

func (c *Control) CreateRepresentative(input store.RepresentativeAssignment) (*store.RepresentativeAssignment, error) {
	return c.CreateRepresentativeAssignment(input)
}

func (c *Control) ProvisionRepresentativeAssignment(input store.RepresentativeAssignment) (*store.RepresentativeAssignment, error) {
	return c.CreateRepresentativeAssignment(input)
}

func (c *Control) AssignRepresentative(input store.RepresentativeAssignment) (*store.RepresentativeAssignment, error) {
	return c.CreateRepresentativeAssignment(input)
}

func (c *Control) RepresentativeAssignment(id string) (*store.RepresentativeAssignment, error) {
	return c.store.GetRepresentativeAssignment(strings.TrimSpace(id))
}

func (c *Control) RepresentativeAssignments(filter store.RepresentativeAssignmentFilter) ([]store.RepresentativeAssignment, error) {
	return c.store.ListRepresentativeAssignments(filter)
}

func representativeContractIDs(input store.RepresentativeAssignment) []string {
	values := make([]string, 0, len(input.ContractIDs)+len(input.ContractRefs)+2)
	values = append(values, input.ContractID, input.ContractRef)
	values = append(values, input.ContractIDs...)
	values = append(values, input.ContractRefs...)
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func membershipHasRole(membership store.Membership, role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	if strings.ToLower(strings.TrimSpace(membership.Role)) == role {
		return true
	}
	for _, candidate := range membership.Roles {
		if strings.ToLower(strings.TrimSpace(candidate)) == role {
			return true
		}
	}
	return false
}
