package fabric

import "github.com/cicada-ai/cicada/internal/store"

// Projection only: Store already committed the Owner-specific zero admission
// and exact native binding in the same transaction as its sealed response.
func (s *Service) NativePairZeroJoinResult(join store.HubNativePairZeroJoin) JoinResult {
	return JoinResult{Endpoint: join.Endpoint, NetworkCard: s.networkCard(join.Endpoint, &join.Binding, join.Binding.GroupID), NativeContextScope: join.NativeContextScope, SessionToken: join.SessionToken, BindingID: join.Binding.ID, BindingEpoch: join.Binding.Epoch, LeaseExpiresAt: join.Binding.LeaseExpiresAt, Reused: false}
}

// Hub Nodes exposes these two self operations only for a genuinely admitted
// pair Endpoint. The ordinary Store self guard repeats the checks at use time.
func (s *Service) RequireNativePairSelf(actor Actor) error {
	return s.store.RequireHubNativePairSelf(nativeActorScope(actor))
}

func (s *Service) RequireNativeCollaborationSelf(actor Actor) error {
	return s.store.RequireHubNativeCollaborationSelf(nativeActorScope(actor))
}

// Hub's exact self routes may publish the original zero-member key before
// Owner classification. Every business route retains AuthenticateForGroup.
func (s *Service) AuthenticateNativeCollaborationSelf(token, group string) (Actor, error) {
	scope, err := s.store.AuthenticateLocalDomainZeroSelf(HashSessionCredential(token), group)
	if err != nil {
		return s.AuthenticateForGroup(token, group)
	}
	b, err := s.store.GetSessionBinding(scope.BindingID)
	if err != nil {
		return Actor{}, ErrUnauthenticated
	}
	a := Actor{PrincipalID: scope.PrincipalID, EndpointID: scope.EndpointID, GroupID: scope.GroupID, NetworkID: scope.NetworkID, MembershipID: scope.MembershipID, MembershipRevision: scope.MembershipRevision, BindingID: scope.BindingID, BindingEpoch: scope.BindingEpoch, LeaseOwner: scope.LeaseOwner, LeaseExpiresAt: b.LeaseExpiresAt}
	return a, a.Validate()
}

func (s *Service) RequireLocalDomainRelay(nodeToken, groupID string) error {
	return s.store.RequireHubLocalDomainRelay(HashSessionCredential(nodeToken), groupID)
}
