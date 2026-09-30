package fabric

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

type Service struct {
	store         *store.Store
	ownerID       string
	trustDomainID string
	now           func() time.Time
	joinMu        sync.Mutex
	nodeEventsMu  sync.Mutex
	nodeEvents    map[string]map[chan struct{}]struct{}
	spaceEventsMu sync.Mutex
	spaceEvents   map[string]map[chan struct{}]struct{}
}

func NewService(persistence *store.Store, ownerID, trustDomainID string) (*Service, error) {
	if persistence == nil {
		return nil, errors.New("fabric store is required")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, errors.New("fabric owner identity is required")
	}
	if trustDomainID = strings.TrimSpace(trustDomainID); trustDomainID == "" {
		trustDomainID = ownerID
	}
	return &Service{store: persistence, ownerID: ownerID, trustDomainID: trustDomainID, now: time.Now}, nil
}

func (s *Service) Join(input JoinInput) (*JoinResult, error) {
	return s.join(input, s.ownerID, s.trustDomainID, "")
}

// JoinForNodeCredential allows a currently owner-bound Node to join an
// Endpoint into one of its owner's active Groups. The caller identity, owner,
// and Node ID are derived from the current Node credential binding; none are
// accepted from JoinInput. The authenticated Node Agent is the trusted local
// boundary here. It must obtain native_session_id from a local Harness adapter
// that has verified the live native Session; the Hub cannot independently
// prove that association.
func (s *Service) JoinForNodeCredential(nodeToken string, input JoinInput) (*JoinResult, error) {
	credential, binding, err := s.store.GetOwnerBoundNodeCredentialByHash(HashSessionCredential(nodeToken))
	if err != nil || credential.Status != store.NodeCredentialActive ||
		binding.State != "ACTIVE" || binding.NodeID != credential.NodeID {
		return nil, ErrUnauthenticated
	}
	owner, err := s.store.GetPrincipal(binding.OwnerID)
	if err != nil || owner.Kind != store.PrincipalKindHuman || owner.Status != store.PrincipalStatusActive ||
		strings.TrimSpace(owner.TrustDomainID) == "" {
		return nil, ErrUnauthenticated
	}

	// The request is only a proposal for this Node's verified local session.
	// It cannot choose an existing Endpoint, Principal, Node, or adapter lease.
	input.EndpointID = ""
	input.PrincipalID = ""
	input.LeaseOwner = ""
	input.NodeID = credential.NodeID
	return s.join(input, owner.ID, owner.TrustDomainID, credential.NodeID)
}

func (s *Service) join(input JoinInput, ownerID, trustDomainID, authenticatedNodeID string) (*JoinResult, error) {
	s.joinMu.Lock()
	defer s.joinMu.Unlock()

	input.GroupID = strings.TrimSpace(input.GroupID)
	input.PrincipalID = strings.TrimSpace(input.PrincipalID)
	input.EndpointID = strings.TrimSpace(input.EndpointID)
	input.Harness = harness.Canonical(input.Harness)
	input.NativeSessionID = strings.TrimSpace(input.NativeSessionID)
	input.NodeID = strings.TrimSpace(input.NodeID)
	input.Workspace = cleanWorkspace(input.Workspace)
	if input.GroupID == "" || input.NativeSessionID == "" || input.NodeID == "" {
		return nil, errors.New("group_id, native_session_id, and node_id are required")
	}
	if input.Harness == "" {
		input.Harness = "codex"
	}
	if input.Harness != "codex" && !harness.IsOptional(input.Harness) {
		return nil, fmt.Errorf("unsupported endpoint harness: %s", input.Harness)
	}
	group, err := s.store.GetGroup(input.GroupID)
	if err != nil || group.State != store.GroupStateActive {
		return nil, ErrNotFoundOrNotAuthorized
	}
	// The configured Fabric owner is the trust boundary for this Service.
	// Knowing an active Group ID does not authorize this owner to create or
	// rejoin an Endpoint in another owner's Group, even when both happen to be
	// in the same trust domain. Keep the public failure indistinguishable from
	// an unavailable Group. Legacy Groups owned by this Service may have an
	// empty trust-domain field; those inherit the Service's configured default.
	groupTrustDomainID := strings.TrimSpace(group.TrustDomainID)
	foreignGroup := strings.TrimSpace(group.OwnerPrincipalID) != ownerID
	if !foreignGroup && groupTrustDomainID != "" && groupTrustDomainID != trustDomainID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	capabilities, err := sanitizeCapabilities(input.Capabilities)
	if err != nil {
		return nil, err
	}
	input.Tags = normalizeTags(input.Tags)

	var previous *store.Endpoint
	if input.EndpointID != "" {
		previous, err = s.store.GetEndpointV2(input.EndpointID)
		if err != nil && !errors.Is(err, store.ErrEndpointNotFound) {
			return nil, err
		}
	}
	bySession, sessionErr := s.store.GetEndpointV2BySession(input.Harness, input.NativeSessionID)
	if sessionErr != nil {
		return nil, sessionErr
	}
	if bySession != nil {
		bound := bySession
		if previous != nil && previous.ID != bound.ID {
			return nil, ErrConflict
		}
		previous = bound
	}
	if previous != nil {
		if previous.NativeSessionID != input.NativeSessionID || previous.Harness != input.Harness {
			return nil, ErrConflict
		}
		// Stable Endpoint IDs and native Session IDs cannot be adopted by a
		// different owner or Node through Join. Movement requires a separate,
		// explicit handoff flow that this endpoint does not implement.
		if strings.TrimSpace(previous.Owner) != ownerID || previous.MachineID != input.NodeID ||
			(authenticatedNodeID != "" && previous.MachineID != authenticatedNodeID) {
			return nil, ErrPermissionDenied
		}
		if input.PrincipalID == "" {
			input.PrincipalID = previous.PrincipalID
		} else if previous.PrincipalID != "" && input.PrincipalID != previous.PrincipalID {
			return nil, ErrPermissionDenied
		}
	}
	// Foreign Group admission is only a rejoin of this Node's existing native
	// Endpoint. Reject an unknown session before resolveJoinPrincipal can create
	// a Principal as a side effect of an unauthorized Join.
	if foreignGroup && (previous == nil || previous.Owner != ownerID ||
		previous.MachineID != input.NodeID || previous.PrincipalID == "") {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if group.NetworkID != "" && previous == nil {
		return nil, ErrNotFoundOrNotAuthorized
	}

	principal, createdPrincipal, err := s.resolveJoinPrincipal(input, ownerID, trustDomainID)
	if err != nil {
		return nil, err
	}
	if group.NetworkID != "" && !foreignGroup {
		if createdPrincipal || previous == nil || previous.PrincipalID != principal.ID ||
			s.store.NetworkGuardGroup(principal.ID, previous.ID, group.ID, group.NetworkID) != nil {
			return nil, ErrNotFoundOrNotAuthorized
		}
	}
	var foreignPriorEpoch uint64
	var foreignBindingID string
	if foreignGroup {
		if group.NetworkID == "" || createdPrincipal || previous == nil || previous.PrincipalID != principal.ID ||
			previous.Owner != ownerID || previous.MachineID != input.NodeID {
			return nil, ErrNotFoundOrNotAuthorized
		}
		priorBinding, priorErr := s.store.GetActiveSessionBinding(previous.ID)
		if priorErr != nil || priorBinding == nil || priorBinding.NodeID != input.NodeID ||
			priorBinding.NativeSessionID != input.NativeSessionID ||
			s.store.CheckCrossOwnerGroupJoin(ownerID, previous.ID, group.ID, input.NodeID,
				priorBinding.ID, priorBinding.Epoch) != nil {
			return nil, ErrNotFoundOrNotAuthorized
		}
		foreignPriorEpoch, foreignBindingID = priorBinding.Epoch, priorBinding.ID
	}
	membership, err := s.store.GetMembershipByPrincipalGroup(principal.ID, input.GroupID)
	if err != nil {
		if !errors.Is(err, store.ErrMembershipNotFound) || !createdPrincipal || group.NetworkID != "" {
			return nil, ErrNotFoundOrNotAuthorized
		}
		membership, err = s.store.CreateMembership(store.Membership{
			PrincipalID: principal.ID, GroupID: input.GroupID, Role: "member",
			Roles:  []string{"member"},
			Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive", "artifact.read"},
			Status: store.MembershipStatusActive,
		})
		if err != nil {
			return nil, err
		}
	}
	if membership.Status != store.MembershipStatusActive || membershipExpired(*membership, s.now()) {
		return nil, ErrNotFoundOrNotAuthorized
	}

	name := normalizeName(input.EndpointName)
	if name == "" && previous != nil {
		name = previous.Name
	}
	if name == "" {
		name = endpointDefaultName(input.Workspace, input.Harness, input.NativeSessionID)
	}
	endpointID := input.EndpointID
	if previous != nil {
		endpointID = previous.ID
	}
	endpoint, err := s.store.UpsertEndpoint(store.Endpoint{
		ID: endpointID, Name: name, Role: "thread", Harness: input.Harness,
		NativeSessionID: input.NativeSessionID, MachineID: input.NodeID,
		Workspace: input.Workspace, Status: "online", Capabilities: capabilities,
		Tags: input.Tags, Owner: ownerID, Visibility: "private",
	})
	if err != nil {
		return nil, err
	}

	token, credentialHash, err := NewSessionCredential()
	if err != nil {
		return nil, err
	}
	leaseDuration := time.Duration(input.LeaseSeconds) * time.Second
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}
	if leaseDuration > time.Hour {
		leaseDuration = time.Hour
	}
	leaseOwner := store.NewID("adapter")
	leaseExpiresAt := s.now().UTC().Add(leaseDuration).Format(time.RFC3339Nano)
	reused := false
	binding, err := s.store.GetActiveSessionBinding(endpoint.ID)
	if err == nil {
		previousBindingID, previousBindingEpoch := binding.ID, binding.Epoch
		if binding.NativeSessionID != input.NativeSessionID || binding.PrincipalID != principal.ID ||
			binding.NodeID != input.NodeID || (authenticatedNodeID != "" && binding.NodeID != authenticatedNodeID) {
			return nil, ErrConflict
		}
		// An explicit, management-authenticated rejoin of the same verified
		// native session rotates its credential under the existing adapter
		// ownership. A different owner must use the separate handoff/takeover
		// flow after the lease expires.
		if binding.LeaseOwner != "" {
			leaseOwner = binding.LeaseOwner
		}
		if foreignGroup {
			binding, err = s.store.RotateAndJoinEndpointGroupCrossOwner(ownerID, endpoint.ID, group.ID,
				input.NodeID, binding.ID, binding.Epoch, credentialHash, leaseOwner, leaseExpiresAt)
		} else {
			binding, err = s.store.RotateSessionBindingCredential(binding.ID, binding.Epoch, credentialHash, leaseOwner, leaseExpiresAt)
		}
		if err == nil {
			// A stable Endpoint may have messages queued while its adapter was
			// disconnected. Move only READY rows from the exact prior epoch to
			// this verified rejoin; claimed/uncertain work stays fenced.
			if _, rebindErr := s.store.RebindPendingRelayInbox(endpoint.ID, previousBindingID, previousBindingEpoch, binding.ID, binding.Epoch); rebindErr != nil &&
				!errors.Is(rebindErr, store.ErrRelayBindingMismatch) {
				return nil, rebindErr
			}
		}
		reused = true
	} else if errors.Is(err, store.ErrSessionBindingNotFound) {
		continuity := strings.TrimSpace(input.ContextContinuity)
		if continuity == "" {
			continuity = "NATIVE_RESUME"
		}
		binding, err = s.store.CreateSessionBinding(store.SessionBinding{
			EndpointID: endpoint.ID, PrincipalID: principal.ID, GroupID: input.GroupID,
			NativeSessionID: input.NativeSessionID, NodeID: input.NodeID,
			WorkspaceID: input.Workspace, Epoch: 1, LeaseOwner: leaseOwner,
			LeaseExpiresAt: leaseExpiresAt, Status: store.SessionBindingStatusLeased,
			CredentialHash: credentialHash, Mode: "adopted",
			ContextContinuity: continuity, Capabilities: capabilities,
		})
	} else {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if foreignGroup {
		if binding.ID != foreignBindingID || binding.Epoch != foreignPriorEpoch+1 {
			return nil, ErrNotFoundOrNotAuthorized
		}
	} else if _, err := s.store.JoinEndpointGroup(endpoint.ID, input.GroupID); err != nil {
		return nil, err
	}
	endpoint, err = s.store.GetEndpointV2(endpoint.ID)
	if err != nil {
		return nil, err
	}
	card := s.networkCard(*endpoint, binding, input.GroupID)
	return &JoinResult{
		Endpoint: *endpoint, NetworkCard: card, SessionToken: token,
		BindingID: binding.ID, BindingEpoch: binding.Epoch,
		LeaseExpiresAt: binding.LeaseExpiresAt, Reused: reused,
	}, nil
}

func (s *Service) resolveJoinPrincipal(input JoinInput, ownerID, trustDomainID string) (*store.Principal, bool, error) {
	if input.PrincipalID != "" {
		principal, err := s.store.GetPrincipal(input.PrincipalID)
		if err != nil || principal.Status != store.PrincipalStatusActive ||
			principal.OwnerID != ownerID || principal.TrustDomainID != trustDomainID {
			return nil, false, ErrNotFoundOrNotAuthorized
		}
		return principal, false, nil
	}
	name := normalizeName(input.PrincipalName)
	if name == "" {
		name = normalizeName(input.EndpointName)
	}
	if name == "" {
		name = endpointDefaultName(input.Workspace, input.Harness, input.NativeSessionID)
	}
	principal, err := s.store.CreatePrincipal(store.Principal{
		Kind: store.PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: trustDomainID,
		Name: name, DisplayName: name, Status: store.PrincipalStatusActive,
	})
	return principal, true, err
}

func (s *Service) Authenticate(sessionToken string) (Actor, error) {
	return s.AuthenticateForGroup(sessionToken, "")
}

// AuthenticateForGroup treats groupID as a requested scope, never as proof of
// membership. The native binding credential fixes the Endpoint/Principal;
// both independent Group relations must still be active at the authority.
func (s *Service) AuthenticateForGroup(sessionToken, groupID string) (Actor, error) {
	binding, err := s.store.GetSessionBindingByCredentialHash(HashSessionCredential(sessionToken))
	if err != nil {
		return Actor{}, ErrUnauthenticated
	}
	if err := s.store.ValidateSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch); err != nil {
		return Actor{}, ErrUnauthenticated
	}
	endpoint, err := s.store.GetEndpointV2(binding.EndpointID)
	if err != nil || endpoint.MigrationState != store.EndpointMigrationReady ||
		endpoint.BindingID != binding.ID || endpoint.PrincipalID != binding.PrincipalID || endpoint.GroupID != binding.GroupID ||
		endpoint.Status == "left" || endpoint.Status == "offline" {
		return Actor{}, ErrUnauthenticated
	}
	principal, err := s.store.GetPrincipal(binding.PrincipalID)
	if err != nil || principal.Status != store.PrincipalStatusActive {
		return Actor{}, ErrUnauthenticated
	}
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		groupID = binding.GroupID
	}
	group, err := s.store.GetGroup(groupID)
	if err != nil || group.State != store.GroupStateActive {
		return Actor{}, ErrPermissionDenied
	}
	if err := s.store.NetworkGuardGroup(binding.PrincipalID, binding.EndpointID, groupID, group.NetworkID); err != nil {
		return Actor{}, ErrPermissionDenied
	}
	joined, err := s.store.GetEndpointGroupMembership(binding.EndpointID, groupID)
	if err != nil || joined.Status != store.MembershipStatusActive {
		return Actor{}, ErrPermissionDenied
	}
	membership, err := s.store.GetMembershipByPrincipalGroup(binding.PrincipalID, groupID)
	if err != nil || membership.Status != store.MembershipStatusActive || membershipExpired(*membership, s.now()) {
		return Actor{}, ErrPermissionDenied
	}
	actor := Actor{
		PrincipalID: binding.PrincipalID, EndpointID: binding.EndpointID,
		NetworkID: group.NetworkID,
		GroupID:   groupID, MembershipID: membership.ID,
		MembershipRevision: membership.Revision, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, LeaseOwner: binding.LeaseOwner,
		LeaseExpiresAt: binding.LeaseExpiresAt,
	}
	if endpoint.Owner != s.ownerID {
		if _, err := s.validateActorCurrent(actor); err != nil {
			return Actor{}, ErrUnauthenticated
		}
	}
	return actor, actor.Validate()
}

// AuthenticateNode binds the Relay transport caller to one provisioned Node.
// A global management bearer is deliberately insufficient for Node claim and
// receipt operations because it does not prove which machine owns the call.
func (s *Service) AuthenticateNode(nodeToken string) (string, error) {
	credential, _, err := s.store.GetOwnerBoundNodeCredentialByHash(HashSessionCredential(nodeToken))
	if err != nil || credential.Status != store.NodeCredentialActive {
		return "", ErrUnauthenticated
	}
	return credential.NodeID, nil
}

// HeartbeatNode records an owner-bound Node's liveness for the Manager status
// projection. The Store repeats the credential check in the write transaction.
func (s *Service) HeartbeatNode(nodeToken string) error {
	if err := s.store.RecordBoundNodeHeartbeat(HashSessionCredential(nodeToken)); err != nil {
		return ErrUnauthenticated
	}
	return nil
}

// RecordBoundNodeMachineHeartbeat updates the owner-tagged machine projection
// for the authenticated Relay Node. Store rechecks the active credential and
// owner binding in the same transaction as the liveness/status write.
func (s *Service) RecordBoundNodeMachineHeartbeat(nodeToken, status string, capabilities map[string]any) error {
	return s.store.RecordBoundNodeMachineHeartbeat(HashSessionCredential(nodeToken), status, capabilities)
}

func (s *Service) Authorize(actor Actor, action string) error {
	if _, err := s.validateActorCurrent(actor); err != nil {
		return err
	}
	membership, err := s.store.GetMembership(actor.MembershipID)
	if err != nil || membership.PrincipalID != actor.PrincipalID || membership.GroupID != actor.GroupID ||
		membership.Status != store.MembershipStatusActive || membership.Revision != actor.MembershipRevision ||
		membershipExpired(*membership, s.now()) {
		return ErrPermissionDenied
	}
	for _, grant := range membership.Grants {
		if grant == "*" || grant == action {
			return nil
		}
	}
	return ErrPermissionDenied
}

func (s *Service) Renew(sessionToken string, leaseSeconds int) (Actor, error) {
	return s.RenewForGroup(sessionToken, "", leaseSeconds)
}

func (s *Service) RenewForGroup(sessionToken, groupID string, leaseSeconds int) (Actor, error) {
	if _, err := s.AuthenticateForGroup(sessionToken, groupID); err != nil {
		return Actor{}, err
	}
	binding, err := s.store.GetSessionBindingByCredentialHash(HashSessionCredential(sessionToken))
	if err != nil {
		return Actor{}, ErrUnauthenticated
	}
	duration := time.Duration(leaseSeconds) * time.Second
	if duration <= 0 {
		duration = 5 * time.Minute
	}
	if duration > time.Hour {
		duration = time.Hour
	}
	if _, err := s.store.RenewSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch, s.now().UTC().Add(duration).Format(time.RFC3339Nano)); err != nil {
		return Actor{}, ErrUnauthenticated
	}
	return s.AuthenticateForGroup(sessionToken, groupID)
}

func (s *Service) Leave(actor Actor, reason string) error {
	if _, err := s.validateActorCurrent(actor); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "endpoint left fabric"
	}
	// All-Group leave belongs to this Endpoint only. Principal Membership may
	// be shared with another native Endpoint and must remain untouched.
	return s.store.LeaveEndpointAllGroups(actor.EndpointID, actor.BindingID, actor.BindingEpoch, reason)
}

// LeaveGroup withdraws the current Group scope while preserving the stable
// Endpoint and native binding if another authorized Group remains.
func (s *Service) LeaveGroup(actor Actor, reason string) (string, error) {
	if _, err := s.validateActorCurrent(actor); err != nil {
		return "", err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "endpoint left group"
	}
	return s.store.LeaveEndpointGroup(actor.EndpointID, actor.GroupID, actor.BindingID, actor.BindingEpoch, reason)
}

func (s *Service) WhoAmI(actor Actor) (*NetworkCard, error) {
	if err := s.Authorize(actor, "directory.read"); err != nil {
		return nil, err
	}
	endpoint, err := s.store.GetEndpointV2(actor.EndpointID)
	if err != nil || endpoint.BindingID != actor.BindingID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	binding, err := s.store.GetSessionBinding(actor.BindingID)
	if err != nil || binding.Epoch != actor.BindingEpoch {
		return nil, ErrStaleBinding
	}
	card := s.networkCard(*endpoint, binding, actor.GroupID)
	card.NativeSessionID = binding.NativeSessionID
	return &card, nil
}

func (s *Service) List(actor Actor, status, nodeID, harnessName string, limit int) ([]NetworkCard, error) {
	if err := s.Authorize(actor, "directory.read"); err != nil {
		return nil, err
	}
	endpoints, err := s.store.ListEndpointsV2(store.EndpointV2Filter{
		GroupID: actor.GroupID, Status: strings.TrimSpace(status), NodeID: strings.TrimSpace(nodeID),
		Harness: strings.TrimSpace(harnessName), MigrationState: store.EndpointMigrationReady, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	cards := make([]NetworkCard, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Status == "left" {
			continue
		}
		binding, bindingErr := s.store.GetActiveSessionBinding(endpoint.ID)
		if bindingErr != nil {
			continue
		}
		cards = append(cards, s.networkCard(endpoint, binding, actor.GroupID))
	}
	return cards, nil
}

func (s *Service) Resolve(actor Actor, input ResolveInput) (*NetworkCard, error) {
	query := strings.TrimSpace(input.Query)
	if query == "" {
		return nil, errors.New("endpoint query is required")
	}
	if err := s.Authorize(actor, "directory.read"); err != nil {
		return nil, err
	}
	if endpoint, err := s.store.GetEndpointV2(query); err == nil {
		joined, joinedErr := s.store.IsEndpointGroupActive(endpoint.ID, actor.GroupID)
		if joinedErr != nil || !joined ||
			endpoint.MigrationState != store.EndpointMigrationReady || endpoint.Status == "left" {
			return nil, ErrNotFoundOrNotAuthorized
		}
		binding, bindErr := s.store.GetActiveSessionBinding(endpoint.ID)
		if bindErr != nil {
			return nil, ErrNotFoundOrNotAuthorized
		}
		card := s.networkCard(*endpoint, binding, actor.GroupID)
		return &card, nil
	}
	cards, err := s.List(actor, "", input.NodeID, "", 1000)
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(query)
	var exact, aliases []NetworkCard
	for _, card := range cards {
		switch {
		case strings.EqualFold(card.Address, query):
			exact = append(exact, card)
		case strings.EqualFold(card.Name+"@"+card.NodeID, query), strings.EqualFold(card.GroupID+"/"+card.Name, query):
			exact = append(exact, card)
		case strings.ToLower(card.Name) == lower:
			aliases = append(aliases, card)
		}
	}
	candidates := exact
	if len(candidates) == 0 {
		candidates = aliases
	}
	if len(candidates) == 0 {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if len(candidates) > 1 {
		return nil, &AmbiguityError{Query: query, Candidates: candidates}
	}
	return &candidates[0], nil
}

func (s *Service) networkCard(endpoint store.Endpoint, binding *store.SessionBinding, groupID string) NetworkCard {
	card := NetworkCard{
		PrincipalID: endpoint.PrincipalID, EndpointID: endpoint.ID, GroupID: groupID,
		Address: groupID + "/" + endpoint.Name + "@" + normalizeName(endpoint.MachineID),
		Name:    endpoint.Name, Harness: endpoint.Harness, NodeID: endpoint.MachineID,
		Workspace: endpoint.Workspace, Status: endpoint.Status,
		Capabilities: endpoint.Capabilities, Tags: endpoint.Tags, LastSeen: endpoint.LastSeen,
		Tools: []string{"cicada_whoami", "cicada_members", "cicada_find", "cicada_send", "cicada_ask", "cicada_reply", "cicada_receive"},
	}
	if binding != nil {
		card.BindingID = binding.ID
		card.BindingEpoch = binding.Epoch
		card.BindingStatus = binding.Status
		card.ContextContinuity = binding.ContextContinuity
	}
	return card
}

func membershipExpired(membership store.Membership, current time.Time) bool {
	if strings.TrimSpace(membership.ExpiresAt) == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, membership.ExpiresAt)
	return err != nil || !expiresAt.After(current)
}

func cleanWorkspace(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "~/") || value == "~" {
		return filepath.Clean(value)
	}
	if absolute, err := filepath.Abs(value); err == nil {
		value = filepath.Clean(absolute)
	}
	// This is the Node's verified native workspace, not a path relative to the
	// Hub's home. Rewriting it to "~" when both happen to share a home prefix
	// breaks the exact native SessionBinding check on subsequent requests.
	return value
}
