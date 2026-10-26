package fabric

// RegistrationHeartbeat returns identity/liveness only. Its empty Group and
// membership cannot be used as a business Actor. Ordinary Group authentication
// remains authoritative for every business path.
func (s *Service) RegistrationHeartbeat(token string) (Actor, bool, error) {
	anchor, managed, err := s.store.RenewEndpointGroupsHeartbeat(HashSessionCredential(token), s.now)
	if err != nil {
		return Actor{}, managed, ErrUnauthenticated
	}
	if !managed {
		return Actor{}, false, nil
	}
	return Actor{PrincipalID: anchor.Registration.PrincipalID, EndpointID: anchor.Registration.EndpointID, NetworkID: anchor.NetworkID, BindingID: anchor.BindingID, BindingEpoch: anchor.BindingEpoch, LeaseOwner: anchor.LeaseOwner, LeaseExpiresAt: anchor.LeaseExpiresAt}, true, nil
}
