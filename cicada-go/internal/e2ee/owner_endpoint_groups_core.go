package e2ee

// EndpointGroupPolicyCore excludes only the review ID/digest to avoid a
// self-reference. Its exact typed field order is part of the signed contract.
type EndpointGroupPolicyCore struct {
	Version                    int                 `json:"version"`
	Purpose                    string              `json:"purpose"`
	PolicyID                   string              `json:"policy_id"`
	Epoch                      uint64              `json:"epoch"`
	Origin                     string              `json:"origin"`
	HubID                      string              `json:"hub_id"`
	HubFingerprint             string              `json:"hub_fingerprint"`
	OwnerID                    string              `json:"owner_id"`
	OwnerPublic                PublicIdentity      `json:"owner_public_identity"`
	OwnerKeyVersion            uint64              `json:"owner_key_version"`
	Node                       OwnerAppNodeBinding `json:"node"`
	LocalUserScope             string              `json:"local_user_scope"`
	NetworkID                  string              `json:"network_id"`
	GroupID                    string              `json:"group_id"`
	EndpointID                 string              `json:"endpoint_id"`
	PrincipalID                string              `json:"principal_id"`
	RegistrationDigest         string              `json:"registration_digest"`
	RegistrationRevision       uint64              `json:"registration_revision"`
	BindingID                  string              `json:"binding_id"`
	BindingEpoch               uint64              `json:"binding_epoch"`
	EndpointKeyID              string              `json:"endpoint_key_id"`
	EndpointPublic             PublicIdentity      `json:"endpoint_public_identity"`
	EndpointFingerprint        string              `json:"endpoint_fingerprint"`
	CandidateVersion           uint64              `json:"candidate_version"`
	CandidateProofDigest       string              `json:"candidate_proof_digest"`
	ExpectedOwnerControlDigest string              `json:"expected_owner_control_digest"`
	ExpectedDecisionRevision   uint64              `json:"expected_decision_revision"`
	Rights                     []string            `json:"rights"`
	IssuedAt                   string              `json:"issued_at"`
	ExpiresAt                  string              `json:"expires_at"`
	ServerNonce                string              `json:"server_nonce"`
}

func (p EndpointGroupPolicy) Core() EndpointGroupPolicyCore {
	return EndpointGroupPolicyCore{
		Version:                    p.Version,
		Purpose:                    p.Purpose,
		PolicyID:                   p.PolicyID,
		Epoch:                      p.Epoch,
		Origin:                     p.Origin,
		HubID:                      p.HubID,
		HubFingerprint:             p.HubFingerprint,
		OwnerID:                    p.OwnerID,
		OwnerPublic:                p.OwnerPublic,
		OwnerKeyVersion:            p.OwnerKeyVersion,
		Node:                       p.Node,
		LocalUserScope:             p.LocalUserScope,
		NetworkID:                  p.NetworkID,
		GroupID:                    p.GroupID,
		EndpointID:                 p.EndpointID,
		PrincipalID:                p.PrincipalID,
		RegistrationDigest:         p.RegistrationDigest,
		RegistrationRevision:       p.RegistrationRevision,
		BindingID:                  p.BindingID,
		BindingEpoch:               p.BindingEpoch,
		EndpointKeyID:              p.EndpointKeyID,
		EndpointPublic:             p.EndpointPublic,
		EndpointFingerprint:        p.EndpointFingerprint,
		CandidateVersion:           p.CandidateVersion,
		CandidateProofDigest:       p.CandidateProofDigest,
		ExpectedOwnerControlDigest: p.ExpectedOwnerControlDigest,
		ExpectedDecisionRevision:   p.ExpectedDecisionRevision,
		Rights:                     p.Rights,
		IssuedAt:                   p.IssuedAt,
		ExpiresAt:                  p.ExpiresAt,
		ServerNonce:                p.ServerNonce,
	}
}

func (p EndpointGroupPolicyCore) WithReview(id, digest string) EndpointGroupPolicy {
	return EndpointGroupPolicy{
		Version:                    p.Version,
		Purpose:                    p.Purpose,
		PolicyID:                   p.PolicyID,
		Epoch:                      p.Epoch,
		Origin:                     p.Origin,
		HubID:                      p.HubID,
		HubFingerprint:             p.HubFingerprint,
		OwnerID:                    p.OwnerID,
		OwnerPublic:                p.OwnerPublic,
		OwnerKeyVersion:            p.OwnerKeyVersion,
		Node:                       p.Node,
		LocalUserScope:             p.LocalUserScope,
		NetworkID:                  p.NetworkID,
		GroupID:                    p.GroupID,
		EndpointID:                 p.EndpointID,
		PrincipalID:                p.PrincipalID,
		RegistrationDigest:         p.RegistrationDigest,
		RegistrationRevision:       p.RegistrationRevision,
		BindingID:                  p.BindingID,
		BindingEpoch:               p.BindingEpoch,
		EndpointKeyID:              p.EndpointKeyID,
		EndpointPublic:             p.EndpointPublic,
		EndpointFingerprint:        p.EndpointFingerprint,
		CandidateVersion:           p.CandidateVersion,
		CandidateProofDigest:       p.CandidateProofDigest,
		ExpectedOwnerControlDigest: p.ExpectedOwnerControlDigest,
		ExpectedDecisionRevision:   p.ExpectedDecisionRevision,
		Rights:                     p.Rights,
		IssuedAt:                   p.IssuedAt,
		ExpiresAt:                  p.ExpiresAt,
		ServerNonce:                p.ServerNonce,
		ReviewID:                   id, ReviewDigest: digest,
	}
}
