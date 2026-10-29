package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

var errEndpointGroupsUnsupported = errors.New("UNSUPPORTED_PROFILE: independent registered-Thread Group authority is unavailable")
var errEndpointGroupsRegistration = errors.New("OWNER_ENDPOINT_GROUPS_REJECTED: the original registered native identity could not be verified")
var errEndpointGroupsOffline = errors.New("ENDPOINT_LOCAL_OFFLINE: this Thread stopped local Cicada access; use explicit cicada join to restore the original registration")

// The token remains only in the original encrypted LocalDomain Join receipt.
// This protected record pins that receipt and its original writer/key identity;
// it grants no Group permission and survives the last Group's removal.
type machineEndpointGroupsRegistration struct {
	Anchor                wire.EndpointGroupsRegistrationAnchor `json:"anchor"`
	LeaseID               string                                `json:"lease_id"`
	IntentID              string                                `json:"intent_id"`
	IntentDigest          string                                `json:"intent_digest"`
	TranscriptPath        string                                `json:"transcript_path"`
	Authorities           []wire.EndpointGroupCurrentEndpoint   `json:"authorities"`
	RelationsRevision     uint64                                `json:"relations_revision"`
	ObservedAt            string                                `json:"observed_at"`
	RelationsCursor       string                                `json:"relations_cursor,omitempty"`
	KeyPrepareGenerations map[string]uint64                     `json:"key_prepare_generations,omitempty"`
	LocallyOffline        bool                                  `json:"locally_offline,omitempty"`
	LocalAccessRevision   uint64                                `json:"local_access_revision"`
}

func cloneMachineEndpointGroupsState(s machineNodeControlState) machineNodeControlState {
	if s.EndpointGroupsDiagnostic != nil {
		d := *s.EndpointGroupsDiagnostic
		d.Packet = bytes.Clone(d.Packet)
		d.OriginalPacket = bytes.Clone(d.OriginalPacket)
		d.ResponsePacket = bytes.Clone(d.ResponsePacket)
		s.EndpointGroupsDiagnostic = &d
	}
	if s.EndpointGroupsLastReadFence != nil {
		d := *s.EndpointGroupsLastReadFence
		d.OriginalPacket = bytes.Clone(d.OriginalPacket)
		d.Packet = bytes.Clone(d.Packet)
		d.ResponsePacket = bytes.Clone(d.ResponsePacket)
		s.EndpointGroupsLastReadFence = &d
	}
	if s.EndpointGroupsRegistrations != nil {
		raw, _ := json.Marshal(s.EndpointGroupsRegistrations)
		var copy map[string]machineEndpointGroupsRegistration
		_ = json.Unmarshal(raw, &copy)
		s.EndpointGroupsRegistrations = copy
	}
	return s
}

func (c *machineNodeControlClient) endpointGroupsIntentRetainedLocked(id string) bool {
	for _, r := range c.state.EndpointGroupsRegistrations {
		if r.IntentID == id {
			return true
		}
	}
	return false
}

func (c *machineNodeControlClient) endpointGroupsLeaseRetainedLocked(id string) bool {
	for _, r := range c.state.EndpointGroupsRegistrations {
		if r.LeaseID == id {
			return true
		}
	}
	return false
}

func endpointGroupsContextForAnchor(a wire.EndpointGroupsRegistrationAnchor, q localCodexContextIssue) localCodexContext {
	return localCodexContext{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, TurnID: q.TurnID, ToolUseID: q.ToolUseID, VerificationProfile: LocalCodexContextProfileEndpointGroups, EndpointGroupsVersion: 1, RegistrationDigest: a.RegistrationDigest, RegistrationRevision: a.RegistrationRevision, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, NodeKeyEpoch: a.NodeKeyEpoch}
}

func sameEndpointGroupsAnchor(old, current wire.EndpointGroupsRegistrationAnchor) bool {
	// State/liveness can change without changing the enrolled authority. All
	// native, key, binding and access coordinates remain an exact equality fence.
	old.State, current.State = "", ""
	old.LeaseExpiresAt, current.LeaseExpiresAt = "", ""
	return reflect.DeepEqual(old, current)
}

func (c *machineNodeControlClient) endpointGroupsOriginal(r machineEndpointGroupsRegistration) (machineManagedLocalDomainLease, wire.LocalDomainNodeJoinResult, wire.LocalDomainNodeKeyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.endpointGroupsOriginalLocked(r)
}

func (c *machineNodeControlClient) endpointGroupsOriginalLocked(r machineEndpointGroupsRegistration) (machineManagedLocalDomainLease, wire.LocalDomainNodeJoinResult, wire.LocalDomainNodeKeyResult, error) {
	m, ok := c.state.ManagedLocalDomainLeases[r.LeaseID]
	var joined wire.LocalDomainNodeJoinResult
	var completed wire.LocalDomainNodeKeyResult
	if !ok || m.IntentID != r.IntentID || m.IntentDigest != r.IntentDigest || m.TranscriptPath != r.TranscriptPath ||
		c.localDomainOriginalLocked(m, "domain.join", &joined) != nil || c.localDomainOriginalLocked(m, "domain.complete", &completed) != nil || joined.SessionToken == "" {
		return m, joined, completed, errEndpointGroupsRegistration
	}
	return m, joined, completed, nil
}

// Actual local UID, original transcript, retained possession evidence and
// private key are checked before accepting a Hub registration projection.
// The default policy's CURRENT state is deliberately not an identity source.
func (b *machineAgentJoinBridge) validateEndpointGroupsRegistration(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, a wire.EndpointGroupsRegistrationAnchor, hub wire.HubIdentity) error {
	if wire.ValidateEndpointGroupsRegistrationAnchor(a, hub) != nil || a.Profile != LocalCodexContextProfileEndpointGroups || a.RegistrationSource != "CODEX_LOCAL_DOMAIN" || a.State == "REVOKED" {
		return errEndpointGroupsRegistration
	}
	m, j, completed, err := c.endpointGroupsOriginal(r)
	if err != nil || c.verifyLocalDomainHistory(ctx, m, j, completed) != nil {
		return errEndpointGroupsRegistration
	}
	member, p, k := completed.Member, completed.Description.Policy, completed.Grant.Manifest
	registration := e2ee.EndpointGroupRegistration{HubID: p.HubID, OwnerID: p.OwnerID, NodeID: member.NodeID, Harness: member.Runtime, NativeSessionID: member.NativeSessionID, Workspace: member.Workspace, EndpointID: member.EndpointID, PrincipalID: member.PrincipalID}
	digest, err := e2ee.EndpointGroupRegistrationDigest(registration)
	uid, ue := machineAgentJoinSocketCurrentUID()
	if err != nil || ue != nil || a.LocalUserScope != "uid:"+strconv.FormatUint(uint64(uid), 10) || a.LocalUserScope != member.LocalUserScope ||
		a.Registration != registration || a.RegistrationDigest != digest || a.NetworkID != p.NetworkID || a.BindingID != member.BindingID || a.BindingEpoch != member.BindingEpoch ||
		a.NodeKeyEpoch != p.Node.NodeKeyEpoch || a.LeaseOwner != member.LeaseOwner || a.NetworkAccessBindingID != member.NetworkAccessBindingID || a.NetworkAccessEpoch != member.NetworkAccessEpoch ||
		a.NetworkMembershipRevision != member.NetworkMembershipRevision || a.EndpointNetworkRevision != member.EndpointNetworkRevision || a.CandidateVersion != member.CandidateVersion ||
		a.CandidateKeyID != k.CandidateKeyID || !machineSamePublicIdentity(a.CandidatePublic, k.CandidatePublicIdentity) || a.CandidateFingerprint != k.CandidateFingerprint || a.CandidateProofDigest != k.CandidateProofDigest {
		return errEndpointGroupsRegistration
	}
	c.mu.Lock()
	currentEpoch, currentKey := c.state.NodeKeyEpoch, c.identity.Public()
	c.mu.Unlock()
	if currentEpoch != a.NodeKeyEpoch || !machineSamePublicIdentity(currentKey, p.Node.NodePublic) || verifyCodexContextTranscriptProfile(r.TranscriptPath, member.NativeSessionID, member.Workspace, true) != nil {
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
	attestation, err := state.LocalDomainLocalAttestation(ctx, member.EndpointID, member.BindingID, member.BindingEpoch)
	if err != nil || !bytes.Equal(attestation.Attestation, k.CandidateAttestation) || attestation.ProofDigest != a.CandidateProofDigest {
		return errEndpointGroupsRegistration
	}
	identity, err := nodekeys.LoadExisting(machineNodeStateDir(b.stateDir, b.nodeID), member.EndpointID)
	if err != nil || !machineSamePublicIdentity(identity.Public(), a.CandidatePublic) {
		return errEndpointGroupsRegistration
	}
	return state.CheckEndpointGroupsRegistration(ctx, hub, a, time.Now().UTC())
}

func (c *machineNodeControlClient) saveEndpointGroupsRegistration(r machineEndpointGroupsRegistration) error {
	if r.LocalAccessRevision == 0 {
		r.LocalAccessRevision = 1
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var detached machineEndpointGroupsRegistration
	if err := json.Unmarshal(raw, &detached); err != nil {
		return err
	}
	r = detached
	c.mu.Lock()
	defer c.mu.Unlock()
	previous := cloneMachineNodeControlState(c.state)
	id := r.Anchor.RegistrationDigest
	if old, ok := c.state.EndpointGroupsRegistrations[id]; ok {
		if !sameEndpointGroupsAnchor(old.Anchor, r.Anchor) || old.LeaseID != r.LeaseID || old.IntentID != r.IntentID || old.IntentDigest != r.IntentDigest || old.TranscriptPath != r.TranscriptPath || r.RelationsRevision < old.RelationsRevision || r.LocalAccessRevision < old.LocalAccessRevision {
			return errEndpointGroupsRegistration
		}
		if r.KeyPrepareGenerations == nil {
			r.KeyPrepareGenerations = make(map[string]uint64)
		}
		for key, generation := range old.KeyPrepareGenerations {
			if r.KeyPrepareGenerations[key] < generation {
				r.KeyPrepareGenerations[key] = generation
			}
		}
	} else if len(c.state.EndpointGroupsRegistrations) >= maxManagedPairLiveLeases {
		return errManagedPairLeaseFull
	}
	if c.state.EndpointGroupsRegistrations == nil {
		c.state.EndpointGroupsRegistrations = make(map[string]machineEndpointGroupsRegistration)
	}
	c.state.EndpointGroupsRegistrations[id] = r
	if err := c.localEndpointCapacityLocked(); err != nil {
		c.state = previous
		return err
	}
	if err := c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	return nil
}
