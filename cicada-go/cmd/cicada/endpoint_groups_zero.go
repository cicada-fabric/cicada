package main

import (
	"bytes"
	"context"
	"reflect"
	"strconv"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

const endpointGroupsZeroAttested = "ZERO_ATTESTED"

// A fresh explicit register proof resumes the protected original command. It
// cannot allocate another Endpoint or select a new policy/Network for this SID.
func (b *machineAgentJoinBridge) resumeEndpointGroupsZeroRegistration(c *machineNodeControlClient, r machineEndpointGroupsRegistration) (machineEndpointGroupsRegistration, error) {
	step, ok, err := c.localEndpointStep(r.IntentID, r.IntentDigest, "domain.command")
	if err != nil || !ok {
		return r, errEndpointGroupsRegistration
	}
	var original localEndpointRequest
	if decodeStrictBridgeJSON(step.Body, &original) != nil || original.Operation != "endpoint_register" || original.LocalDomainVersion != 1 || original.RequestID != r.IntentID || codexOperatorDigest(original, false) != r.IntentDigest || original.NativeSessionID != r.Anchor.Registration.NativeSessionID || original.Workspace != r.Anchor.Registration.Workspace {
		return r, errEndpointGroupsRegistration
	}
	if _, err = b.localDomainEndpointOperation(original); err != nil {
		return r, err
	}
	next, enrolled, err := c.endpointGroupsRegistrationCandidate(original.NativeSessionID, original.Workspace)
	if err != nil || !enrolled || next.Phase != "" || !sameEndpointGroupsAnchor(r.Anchor, next.Anchor) {
		return r, errEndpointGroupsRegistration
	}
	return next, nil
}

// This returns only the actual sealed zero-Join. It never substitutes a
// projected member or an invented completed key grant for retained evidence.
func (c *machineNodeControlClient) endpointGroupsOriginalJoin(r machineEndpointGroupsRegistration) (machineManagedLocalDomainLease, wire.LocalDomainNodeJoinResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.state.ManagedLocalDomainLeases[r.LeaseID]
	var j wire.LocalDomainNodeJoinResult
	if !ok || m.IntentID != r.IntentID || m.IntentDigest != r.IntentDigest || m.TranscriptPath != r.TranscriptPath || c.localDomainOriginalLocked(m, "domain.join", &j) != nil || j.SessionToken == "" {
		return m, j, errEndpointGroupsRegistration
	}
	return m, j, nil
}

func (b *machineAgentJoinBridge) endpointGroupsZeroPolicy(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration) (nodekeys.LocalDomainPolicy, error) {
	var empty nodekeys.LocalDomainPolicy
	_, j, err := c.endpointGroupsOriginalJoin(r)
	if err != nil {
		return empty, err
	}
	state, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return empty, err
	}
	defer state.Close()
	p, err := state.LocalDomainPolicyForGroup(ctx, j.Description.Policy.GroupID)
	binding := c.approvedBinding()
	if err != nil || p == nil || !reflect.DeepEqual(p.Policy, j.Description.Policy) || !bytes.Equal(p.Proof, j.Description.PolicyProof) || p.Hub.HubID != binding.HubID || p.Policy.Origin != b.baseURL || !machineSamePublicIdentity(binding.HubKey, p.Policy.Node.HubNodeControlPublic) {
		return empty, errEndpointGroupsRegistration
	}
	return *p, nil
}

// ZERO_ATTESTED admits registration/classification reads only. Business source
// activation still requires the original key_complete receipt and live Guard.
func (b *machineAgentJoinBridge) validateEndpointGroupsZeroRegistration(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, a wire.EndpointGroupsRegistrationAnchor, hub wire.HubIdentity) error {
	if r.Phase != endpointGroupsZeroAttested || wire.ValidateEndpointGroupsRegistrationAnchor(a, hub) != nil || a.State == "REVOKED" || a.Profile != LocalCodexContextProfileEndpointGroups || a.RegistrationSource != "CODEX_LOCAL_DOMAIN" {
		return errEndpointGroupsRegistration
	}
	m, j, err := c.endpointGroupsOriginalJoin(r)
	if err != nil {
		return err
	}
	p, err := b.endpointGroupsZeroPolicy(ctx, c, r)
	if err != nil || !reflect.DeepEqual(p.Hub, hub) {
		return errEndpointGroupsRegistration
	}
	member := j.Member
	registration := e2ee.EndpointGroupRegistration{HubID: p.Policy.HubID, OwnerID: p.Policy.OwnerID, NodeID: member.NodeID, Harness: member.Runtime, NativeSessionID: member.NativeSessionID, Workspace: member.Workspace, EndpointID: member.EndpointID, PrincipalID: member.PrincipalID}
	digest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	uid, ue := machineAgentJoinSocketCurrentUID()
	if err != nil || ue != nil || a.Registration != registration || a.RegistrationDigest != digest || a.LocalUserScope != "uid:"+strconv.FormatUint(uint64(uid), 10) || a.LocalUserScope != member.LocalUserScope || a.NetworkID != p.Policy.NetworkID || a.BindingID != member.BindingID || a.BindingEpoch != member.BindingEpoch || a.NodeKeyEpoch != p.Policy.Node.NodeKeyEpoch || a.LeaseOwner != member.LeaseOwner || a.NetworkAccessBindingID != member.NetworkAccessBindingID || a.NetworkAccessEpoch != member.NetworkAccessEpoch || a.NetworkMembershipRevision != member.NetworkMembershipRevision || a.EndpointNetworkRevision != member.EndpointNetworkRevision || m.Join.NativeSessionID != member.NativeSessionID || m.Join.Workspace != member.Workspace || member.Runtime != m.Join.Runtime || j.Endpoint.EndpointID != member.EndpointID || j.Endpoint.Workspace != member.Workspace || verifyCodexContextTranscriptProfile(r.TranscriptPath, member.NativeSessionID, member.Workspace, true) != nil {
		return errEndpointGroupsRegistration
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return err
	}
	defer state.Close()
	public, err := state.LocalDomainOriginalLocalKey(ctx, member.EndpointID)
	if err != nil || !machineSamePublicIdentity(public, a.CandidatePublic) {
		return errEndpointGroupsRegistration
	}
	candidate, err := state.LocalDomainLocalAttestation(ctx, member.EndpointID, member.BindingID, member.BindingEpoch)
	if err != nil || candidate.KeyID != a.CandidateKeyID || candidate.KeyFingerprint != a.CandidateFingerprint || candidate.ProofDigest != a.CandidateProofDigest || candidate.EndpointID != member.EndpointID || candidate.PrincipalID != member.PrincipalID || candidate.NodeID != member.NodeID || !machineSamePublicIdentity(candidate.PublicIdentity, a.CandidatePublic) {
		return errEndpointGroupsRegistration
	}
	identity, err := nodekeys.LoadExisting(machineNodeStateDir(b.stateDir, b.nodeID), member.EndpointID)
	if err != nil || !machineSamePublicIdentity(identity.Public(), a.CandidatePublic) {
		return errEndpointGroupsRegistration
	}
	c.mu.Lock()
	epoch, key := c.state.NodeKeyEpoch, c.identity.Public()
	c.mu.Unlock()
	if epoch != a.NodeKeyEpoch || !machineSamePublicIdentity(key, p.Policy.Node.NodePublic) {
		return errEndpointGroupsRegistration
	}
	return state.CheckEndpointGroupsRegistration(ctx, hub, a, time.Now().UTC())
}
