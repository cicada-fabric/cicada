package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func endpointGroupsPeerSource(e crossNodeGroupEndpointEvidence) wire.EndpointGroupPeerSource {
	return wire.EndpointGroupPeerSource{LocalDomainGrant: e.LocalDomainGrant, EndpointGroupGrant: e.EndpointGroupGrant}
}

func validateEndpointGroupsCarrierBounds(raw []byte, carrier any, sender, receiver crossNodeGroupEndpointEvidence, current *wire.EndpointGroupCurrent, old *wire.LocalDomainCurrent, pair *wire.NativePairPeerEvidence, pairCurrent *wire.NativePairPeerCurrent) error {
	if current == nil && sender.EndpointGroupGrant == nil && receiver.EndpointGroupGrant == nil {
		return validateLocalDomainCarrierBounds(raw, carrier, sender, receiver, old)
	}
	encoded, err := json.Marshal(carrier)
	if err != nil || len(raw) > wire.MaxEndpointGroupCarrierBytes || len(encoded) > wire.MaxEndpointGroupCarrierBytes || current == nil || old != nil || pair != nil || pairCurrent != nil || !crossNodeGroupHasGrant(sender) || !crossNodeGroupHasGrant(receiver) || sender.Grant != nil || receiver.Grant != nil {
		return errEndpointGroupsRegistration
	}
	return nil
}

func matchEndpointGroupsEndpoint(actual crossNodeGroupEndpointEvidence, snapshot wire.EndpointGroupCurrentEndpoint) error {
	r, k, c := snapshot.Relation, crossNodeGroupManifest(actual), actual.Candidate
	if !crossNodeGroupHasGrant(actual) || actual.Grant != nil || actual.EndpointID != r.EndpointID || actual.PrincipalID != r.PrincipalID || actual.OwnerID != r.OwnerID || actual.NodeID != r.NodeID || actual.GroupID != r.GroupID || actual.BindingID != r.BindingID || actual.BindingEpoch != r.BindingEpoch || actual.GroupRevision != k.GroupRevision || uint64(actual.MembershipRevision) != r.MembershipRevision || uint64(actual.EndpointJoinRevision) != r.EndpointJoinRevision ||
		c.EndpointID != r.EndpointID || c.PrincipalID != r.PrincipalID || c.OwnerID != r.OwnerID || c.NodeID != r.NodeID || c.BindingID != r.BindingID || c.BindingEpoch != r.BindingEpoch || c.State != store.EndpointKeyCandidateStateCandidate || c.Version <= 0 || uint64(c.Version) != r.CandidateVersion || c.KeyID != r.CandidateKeyID || c.ProofDigest != r.CandidateProofDigest || !bytes.Equal(c.Proof, k.CandidateAttestation) || !machineSamePublicIdentity(c.Public, k.CandidatePublicIdentity) {
		return errEndpointGroupsRegistration
	}
	if actual.LocalDomainGrant != nil {
		if matchLocalDomainEndpoint(actual, *actual.LocalDomainGrant) != nil {
			return errEndpointGroupsRegistration
		}
	} else if actual.EndpointGroupGrant == nil || actual.EndpointGroupGrant.Relation != r {
		return errEndpointGroupsRegistration
	}
	return nil
}

func verifyEndpointGroupsPeerTarget(ctx context.Context, s *nodekeys.CryptoState, localEndpoint, hub, group string, sender, receiver crossNodeGroupEndpointEvidence, current *wire.EndpointGroupCurrent, operation, attempt string) (bool, error) {
	if current == nil && sender.EndpointGroupGrant == nil && receiver.EndpointGroupGrant == nil {
		// Legacy DEFAULT evidence is selected by its original current verifier.
		// A per-Endpoint new-profile marker still refuses missing new Current.
		return s.VerifyEndpointGroupsGroupAuthorization(ctx, localEndpoint, group, wire.EndpointGroupPeerSource{}, wire.EndpointGroupPeerSource{}, nil, operation, attempt, time.Now().UTC())
	}
	required, err := s.VerifyEndpointGroupsGroupAuthorization(ctx, localEndpoint, group, endpointGroupsPeerSource(sender), endpointGroupsPeerSource(receiver), current, operation, attempt, time.Now().UTC())
	if err != nil || !required {
		return required, err
	}
	if current == nil || current.HubID != hub || sender.Grant != nil || receiver.Grant != nil {
		return true, errEndpointGroupsRegistration
	}
	if matchEndpointGroupsEndpoint(sender, current.Sender) != nil || matchEndpointGroupsEndpoint(receiver, current.Receiver) != nil {
		return true, errEndpointGroupsRegistration
	}
	return true, nil
}

// Match the authenticated independent registration before querying the current
// exact source. No default-policy scan, regenerated key or new SID is involved.
func (b *machineAgentJoinBridge) verifyEndpointGroupsSource(ctx context.Context, token, endpoint, principal, sid, cwd, group, binding string, epoch uint64, frozen codexOutboxBinding) (bool, error) {
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	_, path := machineNodeControlPaths(b.stateDir, b.nodeID)
	_, cached := machineNodeControlClients.Load(path)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && frozen.EndpointGroupsVersion == 0 && !cached {
		return false, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return frozen.EndpointGroupsVersion != 0, err
	}
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return false, err
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(sid, cwd)
	if err != nil {
		if !enrolled && frozen.EndpointGroupsVersion == 0 {
			return false, nil
		}
		return true, err
	}
	if !enrolled && frozen.EndpointGroupsVersion == 0 {
		s, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
		if err != nil {
			return false, err
		}
		defer s.Close()
		required, err := s.EndpointGroupsRequired(ctx, endpoint, group)
		if err != nil {
			return true, err
		}
		if required {
			return true, errEndpointGroupsRegistration
		}
		return false, nil
	}
	if !enrolled || frozen.EndpointGroupsVersion != 1 || frozen.codexOutboxBindingValid(group, endpoint, binding, epoch) != nil {
		return true, errEndpointGroupsRegistration
	}
	if r.LocallyOffline {
		return true, errEndpointGroupsOffline
	}
	a := r.Anchor
	if a.Registration.EndpointID != endpoint || a.Registration.PrincipalID != principal || a.BindingID != binding || a.BindingEpoch != epoch || a.RegistrationDigest != frozen.RegistrationDigest || a.RegistrationRevision != frozen.RegistrationRevision || a.NodeKeyEpoch != frozen.RegistrationNodeKeyEpoch {
		return true, errEndpointGroupsRegistration
	}
	_, original, _, err := c.endpointGroupsOriginal(r)
	if err != nil || original.SessionToken != token {
		return true, errEndpointGroupsRegistration
	}
	for cursor := ""; ; {
		var d wire.EndpointGroupsNodeDescribeResult
		r, d, err = b.describeEndpointGroups(ctx, c, r, cursor, 64)
		if err != nil {
			return true, err
		}
		for _, a := range d.Authorities {
			if a.Relation.GroupID == group {
				if a != frozen.EndpointGroupAuthority {
					return true, errMCPOutboxContext
				}
				return true, nil
			}
		}
		if d.Complete {
			return true, errEndpointGroupsSelection
		}
		cursor = d.NextCursor
		if ctx.Err() != nil {
			return true, errMachineNodeControlOutcomeUncertain
		}
	}
}

func (b *machineAgentJoinBridge) rejectEndpointGroupsLegacySource(sid, cwd string) error {
	_, path := machineNodeControlPaths(b.stateDir, b.nodeID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return err
	}
	_, enrolled, err := c.endpointGroupsRegistrationCandidate(sid, cwd)
	if enrolled {
		return errEndpointGroupsRegistration
	}
	if errors.Is(err, errEndpointGroupsUnsupported) {
		return nil
	}
	return err
}

func (b codexOutboxBinding) codexOutboxBindingValid(group, endpoint, binding string, epoch uint64) error {
	if b.validate() != nil || b.EndpointGroupsVersion != 1 || b.NativeBindingID != binding || b.NativeBindingEpoch != epoch || b.EndpointGroupAuthority.Relation.GroupID != group || b.EndpointGroupAuthority.Relation.EndpointID != endpoint {
		return errMCPOutboxContext
	}
	return nil
}

func endpointGroupsPeerPublic(e crossNodeGroupEndpointEvidence) e2ee.PublicIdentity {
	return crossNodeGroupManifest(e).CandidatePublicIdentity
}

func endpointGroupsDeliveryDeadline(a crossNodeGroupDeliveryAuthorization) time.Time {
	if a.EndpointGroupCurrent != nil {
		return parseMachineNativePairTime(a.EndpointGroupCurrent.ExpiresAt)
	}
	if a.LocalDomainCurrent != nil {
		return parseMachineNativePairTime(a.LocalDomainCurrent.ExpiresAt)
	}
	return time.Time{}
}

func endpointGroupsLocalNativeOnline(ctx context.Context, stateDir, nodeID, endpoint, binding string, epoch uint64, current *wire.EndpointGroupCurrent) error {
	_, path := machineNodeControlPaths(stateDir, nodeID)
	client, ok := machineNodeControlClients.Load(path)
	if !ok {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		hub, pinned := machineHubFrom(ctx)
		if !pinned || hub.NodeID != nodeID || hub.Origin == "" || hub.StateDir != stateDir {
			return errEndpointGroupsRegistration
		}
		loaded, err := openMachineNodeControlClientMode(stateDir, hub.Origin, nodeID, true)
		if err != nil {
			return err
		}
		client = loaded
	}
	c := client.(*machineNodeControlClient)
	c.mu.Lock()
	var found *machineEndpointGroupsRegistration
	for _, r := range c.state.EndpointGroupsRegistrations {
		if r.Anchor.Registration.EndpointID == endpoint {
			copy := r
			found = &copy
			break
		}
	}
	c.mu.Unlock()
	if found == nil {
		return nil
	}
	if found.LocallyOffline {
		return errEndpointGroupsOffline
	}
	if current == nil {
		return errEndpointGroupsRegistration
	}
	if found.Anchor.BindingID != binding || found.Anchor.BindingEpoch != epoch || verifyCodexContextTranscriptProfile(found.TranscriptPath, found.Anchor.Registration.NativeSessionID, found.Anchor.Registration.Workspace, true) != nil {
		return errEndpointGroupsRegistration
	}
	return nil
}
