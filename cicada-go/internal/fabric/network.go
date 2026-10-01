package fabric

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

type NetworkJoinInput struct {
	NetworkID       string         `json:"network_id"`
	InvitationToken string         `json:"invitation_token"`
	OwnerJoinProof  string         `json:"owner_join_proof"`
	Harness         string         `json:"harness"`
	NativeSessionID string         `json:"native_session_id"`
	EndpointName    string         `json:"endpoint_name"`
	Capabilities    map[string]any `json:"capabilities,omitempty"`
	LeaseSeconds    int            `json:"lease_seconds,omitempty"`
}

type NetworkRenewInput struct {
	NetworkID       string `json:"network_id"`
	EndpointID      string `json:"endpoint_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	LeaseSeconds    int    `json:"lease_seconds,omitempty"`
}

type NetworkJoinResult struct {
	Endpoint           store.Endpoint                   `json:"endpoint"`
	NetworkID          string                           `json:"network_id"`
	NativeContextScope store.NativeContextScopeMetadata `json:"native_context_scope"`
	SessionToken       string                           `json:"session_token"`
	BindingID          string                           `json:"binding_id"`
	BindingEpoch       uint64                           `json:"binding_epoch"`
	LeaseExpiresAt     string                           `json:"lease_expires_at"`
}

type NetworkActor struct {
	PrincipalID                string `json:"principal_id"`
	EndpointID                 string `json:"endpoint_id"`
	NetworkID                  string `json:"network_id"`
	MembershipID               string `json:"membership_id"`
	MembershipRevision         int64  `json:"membership_revision"`
	EndpointMembershipRevision int64  `json:"endpoint_membership_revision"`
	BindingID                  string `json:"binding_id"`
	BindingEpoch               uint64 `json:"binding_epoch"`
	LeaseOwner                 string `json:"lease_owner"`
	LeaseExpiresAt             string `json:"lease_expires_at"`
}

type NetworkEndpointCard struct {
	NetworkID    string         `json:"network_id"`
	EndpointID   string         `json:"endpoint_id"`
	Nickname     string         `json:"nickname"`
	Availability string         `json:"availability"`
	Capabilities map[string]any `json:"capabilities"`
}

func networkDirectoryScope(actor NetworkActor) store.NetworkAccessScope {
	return store.NetworkAccessScope{
		NetworkID: actor.NetworkID, PrincipalID: actor.PrincipalID,
		EndpointID: actor.EndpointID, AccessSessionID: actor.BindingID,
		AccessEpoch: actor.BindingEpoch, LeaseOwner: actor.LeaseOwner,
		MembershipID: actor.MembershipID, MembershipRevision: actor.MembershipRevision,
		EndpointMembershipRevision: actor.EndpointMembershipRevision,
	}
}

func networkLease(seconds int, at time.Time) string {
	duration := time.Duration(seconds) * time.Second
	if duration <= 0 {
		duration = 5 * time.Minute
	}
	if duration > time.Hour {
		duration = time.Hour
	}
	return at.UTC().Add(duration).Format(time.RFC3339Nano)
}

func (s *Service) JoinNetworkForNodeCredential(nodeToken string, input NetworkJoinInput) (*NetworkJoinResult, error) {
	credential, binding, err := s.store.GetOwnerBoundNodeCredentialByHash(HashSessionCredential(nodeToken))
	if err != nil || credential.Status != store.NodeCredentialActive || binding.State != "ACTIVE" || binding.NodeID != credential.NodeID {
		return nil, ErrUnauthenticated
	}
	input.NetworkID = strings.TrimSpace(input.NetworkID)
	input.NativeSessionID = strings.TrimSpace(input.NativeSessionID)
	input.Harness = harness.Canonical(input.Harness)
	input.EndpointName = normalizeName(input.EndpointName)
	if input.NetworkID == "" || input.NativeSessionID == "" || input.EndpointName == "" || input.Harness == "" {
		return nil, ErrPermissionDenied
	}
	network, err := s.store.GetNetwork(input.NetworkID)
	if err != nil || network.State != store.NetworkStateActive || network.HubID != binding.HubID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	ownerPrincipal, err := s.store.GetPrincipal(binding.OwnerID)
	if err != nil || ownerPrincipal.Kind != store.PrincipalKindHuman || ownerPrincipal.Status != store.PrincipalStatusActive || ownerPrincipal.TrustDomainID == "" {
		return nil, ErrUnauthenticated
	}
	invitation, err := s.store.GetNetworkInvitation(input.InvitationToken)
	if err != nil || invitation.NetworkID != network.ID || invitation.TargetOwnerID != binding.OwnerID {
		return nil, ErrNotFoundOrNotAuthorized
	}
	var proposed e2ee.OwnerNetworkJoinGrant
	if err := json.Unmarshal([]byte(input.OwnerJoinProof), &proposed); err != nil {
		return nil, ErrPermissionDenied
	}
	ownerKey, err := s.store.GetOwnerApprovalKey(binding.OwnerID, proposed.OwnerKeyID)
	if err != nil || ownerKey.State != store.OwnerApprovalKeyActive {
		return nil, ErrPermissionDenied
	}
	expected := e2ee.OwnerNetworkJoinGrant{HubID: binding.HubID, NetworkID: network.ID, OwnerID: binding.OwnerID, NodeID: credential.NodeID, NativeSessionID: input.NativeSessionID, InvitationDigest: store.NetworkInvitationDigest(input.InvitationToken), Grants: invitation.Grants, Discoverable: proposed.Discoverable}
	grant, err := e2ee.VerifyOwnerNetworkJoinGrant([]byte(input.OwnerJoinProof), ownerKey.Public, expected, s.now())
	if err != nil {
		return nil, ErrPermissionDenied
	}
	if grant.Discoverable && !containsGrant(grant.Grants, "directory.publish") {
		return nil, ErrPermissionDenied
	}
	if input.Harness != "codex" && !harness.IsOptional(input.Harness) {
		return nil, ErrPermissionDenied
	}
	// Return a fresh access credential even on exact proof retry. It is only a
	// directory credential and never owns a native runtime writer.
	token, credentialHash, err := NewSessionCredential()
	if err != nil {
		return nil, err
	}
	accepted, err := s.store.AcceptNetworkJoin(store.AcceptNetworkJoinInput{NetworkID: network.ID, OwnerID: binding.OwnerID, TrustDomainID: ownerPrincipal.TrustDomainID, NodeID: credential.NodeID, NativeSessionID: input.NativeSessionID, Harness: input.Harness, EndpointName: input.EndpointName, InvitationToken: input.InvitationToken, ProofNonce: grant.Nonce, ProofDigest: store.NetworkInvitationDigest(input.OwnerJoinProof), ProofExpiresAt: grant.ExpiresAt, OwnerKeyID: grant.OwnerKeyID, OwnerJoinProof: input.OwnerJoinProof, NodeCredentialHash: HashSessionCredential(nodeToken), Grants: grant.Grants, Discoverable: grant.Discoverable, CredentialHash: credentialHash, LeaseOwner: store.NewID("netlease"), LeaseExpiresAt: networkLease(input.LeaseSeconds, s.now())})
	if err != nil {
		return nil, err
	}
	endpoint, err := s.store.GetEndpointV2(accepted.EndpointID)
	if err != nil {
		return nil, err
	}
	contextScope := store.NativeContextScopeMetadata{HubID: network.HubID, NetworkID: network.ID,
		NetworkContextPolicy: network.ContextPolicy}
	return &NetworkJoinResult{Endpoint: *endpoint, NetworkID: network.ID, NativeContextScope: contextScope,
		SessionToken: token, BindingID: accepted.AccessSessionID, BindingEpoch: accepted.AccessSessionEpoch,
		LeaseExpiresAt: networkLease(input.LeaseSeconds, s.now())}, nil
}

func containsGrant(grants []string, action string) bool {
	for _, grant := range grants {
		if grant == action {
			return true
		}
	}
	return false
}

func networkLeaseCurrent(value string, at time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && expiresAt.After(at)
}

func networkMembershipCurrent(value string, at time.Time) bool {
	return value == "" || networkLeaseCurrent(value, at)
}

func (s *Service) AuthenticateForNetwork(sessionToken, networkID string) (NetworkActor, error) {
	access, err := s.store.GetNetworkAccessSessionByHash(HashSessionCredential(sessionToken))
	if err != nil || access.Status != "active" || access.NetworkID != strings.TrimSpace(networkID) ||
		!networkLeaseCurrent(access.LeaseExpiresAt, s.now()) {
		return NetworkActor{}, ErrUnauthenticated
	}
	endpoint, err := s.store.GetEndpointV2(access.EndpointID)
	if err != nil || endpoint.PrincipalID != access.PrincipalID || endpoint.NativeSessionID != access.NativeSessionID || endpoint.MachineID != access.NodeID || endpoint.Status == "left" {
		return NetworkActor{}, ErrUnauthenticated
	}
	network, err := s.store.GetNetwork(access.NetworkID)
	if err != nil || network.State != store.NetworkStateActive {
		return NetworkActor{}, ErrPermissionDenied
	}
	owner, err := s.store.CurrentBoundNodeOwner(access.NodeID)
	if err != nil || owner != endpoint.Owner {
		return NetworkActor{}, ErrUnauthenticated
	}
	ownerKey, err := s.store.GetOwnerApprovalKey(endpoint.Owner, access.OwnerKeyID)
	if err != nil || ownerKey.State != store.OwnerApprovalKeyActive {
		return NetworkActor{}, ErrUnauthenticated
	}
	membership, err := s.store.GetNetworkMembership(access.NetworkID, access.PrincipalID)
	if err != nil || membership.Status != "active" ||
		!networkMembershipCurrent(membership.ExpiresAt, s.now()) {
		return NetworkActor{}, ErrPermissionDenied
	}
	enrollment, err := s.store.GetEndpointNetworkMembership(access.NetworkID, access.EndpointID)
	if err != nil || enrollment.Status != "active" {
		return NetworkActor{}, ErrPermissionDenied
	}
	return NetworkActor{PrincipalID: access.PrincipalID, EndpointID: access.EndpointID, NetworkID: access.NetworkID, MembershipID: membership.ID, MembershipRevision: membership.Revision, EndpointMembershipRevision: enrollment.Revision, BindingID: access.ID, BindingEpoch: access.Epoch, LeaseOwner: access.LeaseOwner, LeaseExpiresAt: access.LeaseExpiresAt}, nil
}

func (s *Service) authorizeNetwork(actor NetworkActor, action string) error {
	access, err := s.store.GetNetworkAccessSessionByID(actor.BindingID)
	if err != nil || access.NetworkID != actor.NetworkID || access.EndpointID != actor.EndpointID || access.PrincipalID != actor.PrincipalID || access.Epoch != actor.BindingEpoch || access.LeaseOwner != actor.LeaseOwner || access.Status != "active" ||
		!networkLeaseCurrent(access.LeaseExpiresAt, s.now()) {
		return ErrPermissionDenied
	}
	endpoint, err := s.store.GetEndpointV2(actor.EndpointID)
	if err != nil || endpoint.PrincipalID != actor.PrincipalID || endpoint.MachineID != access.NodeID || endpoint.Status == "left" {
		return ErrPermissionDenied
	}
	owner, err := s.store.CurrentBoundNodeOwner(access.NodeID)
	if err != nil || owner != endpoint.Owner {
		return ErrPermissionDenied
	}
	ownerKey, err := s.store.GetOwnerApprovalKey(endpoint.Owner, access.OwnerKeyID)
	if err != nil || ownerKey.State != store.OwnerApprovalKeyActive {
		return ErrPermissionDenied
	}
	membership, err := s.store.GetNetworkMembership(actor.NetworkID, actor.PrincipalID)
	if err != nil || membership.ID != actor.MembershipID || membership.Revision != actor.MembershipRevision ||
		membership.Status != "active" || !networkMembershipCurrent(membership.ExpiresAt, s.now()) {
		return ErrPermissionDenied
	}
	enrollment, err := s.store.GetEndpointNetworkMembership(actor.NetworkID, actor.EndpointID)
	if err != nil || enrollment.Revision != actor.EndpointMembershipRevision ||
		enrollment.Status != "active" {
		return ErrPermissionDenied
	}
	if action == "" {
		return nil
	}
	allowed, err := s.store.NetworkAllows(actor.NetworkID, actor.PrincipalID, actor.EndpointID, action)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func (s *Service) ListNetwork(actor NetworkActor, limit int) ([]NetworkEndpointCard, error) {
	if err := s.authorizeNetwork(actor, "directory.discover"); err != nil {
		return nil, err
	}
	entries, err := s.store.ListNetworkDirectory(networkDirectoryScope(actor), limit)
	if err != nil {
		if err == store.ErrNetworkPermission {
			return nil, ErrPermissionDenied
		}
		return nil, err
	}
	cards := make([]NetworkEndpointCard, 0, len(entries))
	for _, entry := range entries {
		cards = append(cards, NetworkEndpointCard{NetworkID: entry.NetworkID, EndpointID: entry.EndpointID, Nickname: entry.Nickname, Availability: entry.Availability, Capabilities: map[string]any{}})
	}
	return cards, nil
}

func (s *Service) ResolveNetwork(actor NetworkActor, query string) (*NetworkEndpointCard, error) {
	if err := s.authorizeNetwork(actor, "directory.discover"); err != nil {
		return nil, err
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, ErrNotFoundOrNotAuthorized
	}
	entries, err := s.store.ResolveNetworkDirectory(networkDirectoryScope(actor), query)
	if err != nil {
		if err == store.ErrNetworkPermission {
			return nil, ErrPermissionDenied
		}
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrNotFoundOrNotAuthorized
	}
	if len(entries) > 1 {
		return nil, ErrAmbiguous
	}
	entry := entries[0]
	return &NetworkEndpointCard{NetworkID: entry.NetworkID, EndpointID: entry.EndpointID, Nickname: entry.Nickname, Availability: entry.Availability, Capabilities: map[string]any{}}, nil
}

func (s *Service) LeaveNetwork(actor NetworkActor, reason string) error {
	if err := s.authorizeNetwork(actor, ""); err != nil {
		return err
	}
	return s.store.LeaveEndpointNetwork(actor.NetworkID, actor.EndpointID, actor.EndpointMembershipRevision)
}

// RenewNetworkForNodeCredential refreshes only the Network directory access
// session. The Node must independently reverify the original native session
// before presenting these coordinates; the Hub rechecks owner and enrollment.
func (s *Service) RenewNetworkForNodeCredential(nodeToken string, input NetworkRenewInput) (*NetworkJoinResult, error) {
	credential, binding, err := s.store.GetOwnerBoundNodeCredentialByHash(HashSessionCredential(nodeToken))
	if err != nil || credential.Status != store.NodeCredentialActive || binding.State != "ACTIVE" || binding.NodeID != credential.NodeID {
		return nil, ErrUnauthenticated
	}
	input.NetworkID = strings.TrimSpace(input.NetworkID)
	input.EndpointID = strings.TrimSpace(input.EndpointID)
	input.NativeSessionID = strings.TrimSpace(input.NativeSessionID)
	input.Harness = harness.Canonical(input.Harness)
	if input.NetworkID == "" || input.EndpointID == "" || input.NativeSessionID == "" || input.Harness == "" {
		return nil, ErrPermissionDenied
	}
	network, err := s.store.GetNetwork(input.NetworkID)
	if err != nil || network.State != store.NetworkStateActive || network.HubID != binding.HubID {
		return nil, ErrPermissionDenied
	}
	token, hash, err := NewSessionCredential()
	if err != nil {
		return nil, err
	}
	lease := networkLease(input.LeaseSeconds, s.now())
	accepted, err := s.store.RenewNetworkAccess(store.RenewNetworkAccessInput{NetworkID: input.NetworkID, EndpointID: input.EndpointID, OwnerID: binding.OwnerID, NodeID: credential.NodeID, Harness: input.Harness, NativeSessionID: input.NativeSessionID, NodeCredentialHash: HashSessionCredential(nodeToken), CredentialHash: hash, LeaseOwner: store.NewID("netlease"), LeaseExpiresAt: lease})
	if err != nil {
		return nil, ErrPermissionDenied
	}
	endpoint, err := s.store.GetEndpointV2(accepted.EndpointID)
	if err != nil {
		return nil, err
	}
	contextScope := store.NativeContextScopeMetadata{HubID: network.HubID, NetworkID: network.ID,
		NetworkContextPolicy: network.ContextPolicy}
	return &NetworkJoinResult{Endpoint: *endpoint, NetworkID: input.NetworkID, NativeContextScope: contextScope,
		SessionToken: token, BindingID: accepted.AccessSessionID, BindingEpoch: accepted.AccessSessionEpoch,
		LeaseExpiresAt: lease}, nil
}

// IssueNetworkInvitation is a narrow NetworkAdmin action. The access session
// fixes the issuer and Network; it cannot approve another owner's Thread.
func (s *Service) IssueNetworkInvitation(actor NetworkActor, targetOwnerID string, grants []string, ttlSeconds int) (string, string, error) {
	if err := s.authorizeNetwork(actor, "network.admin.invite"); err != nil {
		return "", "", err
	}
	targetOwnerID = strings.TrimSpace(targetOwnerID)
	if targetOwnerID == "" {
		return "", "", ErrPermissionDenied
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 900
	}
	if ttlSeconds > 86400 {
		return "", "", ErrPermissionDenied
	}
	token, _, err := NewSessionCredential()
	if err != nil {
		return "", "", err
	}
	expires := s.now().UTC().Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339Nano)
	if err := s.store.IssueNetworkInvitation(actor.NetworkID, targetOwnerID, actor.PrincipalID, token, expires, grants); err != nil {
		return "", "", ErrPermissionDenied
	}
	return token, expires, nil
}
