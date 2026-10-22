package main

import wire "github.com/cicada-ai/cicada/internal/hubaccountwire"

// The private Node verifies the original Owner pin, policy delegation, Node
// signature and candidate chain before returning ACTIVE. This consumer has no
// independent Owner key pin: it binds that authenticated Node result to the
// exact consumed policy digest and original native command, then lets current
// Hub Guard decide every later business call.
func validateCodexDomainOperatorResult(p codexOperatorPending, r *localEndpointResult, responseErr error) error {
	q := p.Request
	if q.Operation != "endpoint_register" || q.LocalDomainVersion != 1 || wire.ValidateLocalDomainSelection(q.LocalDomain) != nil || r.State != "COMPLETED" || responseErr != nil || r.Directory != nil || r.Pairs != nil || r.Registration == nil || r.Join == nil || r.LocalDomain == nil || r.NativeContextScope == nil || !r.NativeContextScope.Accepted {
		return errCodexOperatorIntentResponse
	}
	d := r.LocalDomain
	description := d.Description
	policy := description.Policy
	member := d.Member
	j := r.Join
	registration := r.Registration
	selection, err := wire.LocalDomainSelectionForPolicy(policy)
	if err != nil || selection != q.LocalDomain || d.ContractRevision != wire.LocalDomainContractRevision || description.ContractRevision != wire.LocalDomainContractRevision || description.State != wire.LocalDomainActive || description.Revision == 0 || description.Revision >= 1<<63 || policy.HubID != r.HubID || policy.Node.NodeID != p.NodeID || policy.Origin != q.APIOrigin {
		return errCodexOperatorIntentResponse
	}
	if p.ConnectionPin != nil {
		pin := p.ConnectionPin.Binding
		node := policy.Node
		// Discovery pins the Owner binding version. The distinct Control-key
		// row revision remains bound by the policy digest and Node validation.
		if node.OwnerBindingID != pin.BindingID || node.BindingVersion != pin.BindingVersion || node.NodeKeyEpoch != pin.NodeKeyEpoch || node.NodeKeyVersion != pin.NodeKeyVersion || node.NodePublic.ID != pin.NodeKeyID || node.NodeKeyFingerprint != pin.NodeKeyFingerprint || node.HubNodeControlKeyVersion != pin.HubKeyVersion || node.HubNodeControlPublic.ID != pin.HubKeyID || node.HubNodeControlFingerprint != pin.HubFingerprint {
			return errCodexOperatorIntentResponse
		}
	}
	if member.State != wire.LocalDomainMemberActive || member.Selection != q.LocalDomain || member.NodeID != p.NodeID || member.Runtime != q.Harness || member.NativeSessionID != q.NativeSessionID || member.Workspace != q.Workspace || member.LocalUserScope != policy.LocalUserScope || member.MemberID == "" || member.Revision == 0 || member.Revision >= 1<<63 || member.BindingEpoch >= 1<<63 {
		return errCodexOperatorIntentResponse
	}
	if member.MembershipRevision == 0 || member.MembershipRevision >= 1<<63 || member.EndpointJoinRevision == 0 || member.EndpointJoinRevision >= 1<<63 || member.CandidateVersion == 0 || member.CandidateVersion >= 1<<63 || member.CandidateKeyID == "" || !localContextText(member.CandidateFingerprint, 128) || !localContextHex(member.CandidateProofDigest, 64) {
		return errCodexOperatorIntentResponse
	}
	if j.SessionToken == "" || len(j.SessionToken) > 512 || j.Endpoint.ID == "" || j.Endpoint.ID != member.EndpointID || j.Endpoint.GroupID != policy.GroupID || j.Endpoint.PrincipalID != member.PrincipalID || j.Endpoint.Owner != policy.OwnerID || j.Endpoint.MachineID != p.NodeID || j.Endpoint.Harness != q.Harness || j.Endpoint.NativeSessionID != q.NativeSessionID || j.Endpoint.Workspace != q.Workspace || j.BindingID == "" || j.BindingID != member.BindingID || j.BindingEpoch == 0 || j.BindingEpoch != member.BindingEpoch {
		return errCodexOperatorIntentResponse
	}
	if registration.EndpointID != member.EndpointID || registration.Workspace != q.Workspace || !localContextHex(registration.StateDigest, 64) || registration.Presence == "left" {
		return errCodexOperatorIntentResponse
	}
	grant := d.Grant
	manifest := grant.Manifest
	if manifest.OwnerKeyID != policy.OwnerPublic.ID || manifest.ExpiresAt != policy.ExpiresAt {
		return errCodexOperatorIntentResponse
	}
	if grant.ContractRevision != wire.LocalDomainContractRevision || grant.Member != member || len(grant.PolicyProof) == 0 || len(grant.NodeProof) == 0 || !localContextHex(manifest.Digest, 64) || manifest.HubID != r.HubID || manifest.OwnerID != policy.OwnerID || manifest.NodeID != p.NodeID || manifest.GroupID != policy.GroupID || manifest.EndpointID != member.EndpointID || manifest.PrincipalID != member.PrincipalID || manifest.BindingID != member.BindingID || manifest.BindingEpoch != member.BindingEpoch || manifest.MembershipRevision != int64(member.MembershipRevision) || manifest.EndpointJoinRevision != int64(member.EndpointJoinRevision) || manifest.CandidateVersion != int64(member.CandidateVersion) || manifest.CandidateKeyID != member.CandidateKeyID || manifest.CandidatePublicIdentity.ID != member.CandidateKeyID || manifest.CandidateFingerprint != member.CandidateFingerprint || manifest.CandidateProofDigest != member.CandidateProofDigest {
		return errCodexOperatorIntentResponse
	}
	return nil
}
