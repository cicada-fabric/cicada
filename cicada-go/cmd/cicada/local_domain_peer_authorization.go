package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func crossNodeGroupHasGrant(e crossNodeGroupEndpointEvidence) bool {
	return (e.Grant != nil) != (e.LocalDomainGrant != nil)
}
func crossNodeGroupManifest(e crossNodeGroupEndpointEvidence) store.GroupEndpointKeyGrantManifest {
	if e.Grant != nil && e.LocalDomainGrant == nil {
		return e.Grant.Manifest
	}
	var m store.GroupEndpointKeyGrantManifest
	if e.LocalDomainGrant != nil && e.Grant == nil {
		raw, _ := json.Marshal(e.LocalDomainGrant.Manifest)
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func validateLocalDomainCarrierBounds(raw []byte, carrier any, sender, receiver crossNodeGroupEndpointEvidence, current *wire.LocalDomainCurrent) error {
	if sender.LocalDomainGrant == nil && receiver.LocalDomainGrant == nil && current == nil {
		return nil
	}
	encoded, err := json.Marshal(carrier)
	if err != nil || len(raw) > wire.MaxLocalDomainCarrierBytes || len(encoded) > wire.MaxLocalDomainCarrierBytes || sender.LocalDomainGrant == nil || receiver.LocalDomainGrant == nil || current == nil || sender.Grant != nil || receiver.Grant != nil {
		return nodekeys.ErrLocalDomainPolicy
	}
	return nil
}

func localDomainGroupRequired(ctx context.Context, stateDir, node, group string) (bool, error) {
	s, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, node))
	if err != nil {
		return false, err
	}
	defer s.Close()
	return s.LocalDomainPolicyRequired(ctx, group)
}

func matchLocalDomainEndpoint(actual crossNodeGroupEndpointEvidence, g wire.LocalDomainEndpointKeyGrant) error {
	m, k, c := g.Member, g.Manifest, actual.Candidate
	if actual.Grant != nil || actual.LocalDomainGrant == nil || actual.EndpointID != m.EndpointID || actual.PrincipalID != m.PrincipalID || actual.OwnerID != k.OwnerID || actual.NodeID != m.NodeID || actual.GroupID != k.GroupID || actual.BindingID != m.BindingID || actual.BindingEpoch != m.BindingEpoch || (actual.NativeSessionID != "" && actual.NativeSessionID != m.NativeSessionID) || actual.GroupRevision != k.GroupRevision || actual.MembershipRevision != k.MembershipRevision || actual.EndpointJoinRevision != k.EndpointJoinRevision {
		return nodekeys.ErrLocalDomainPolicy
	}
	if c.EndpointID != m.EndpointID || c.PrincipalID != m.PrincipalID || c.OwnerID != k.OwnerID || c.NodeID != m.NodeID || c.BindingID != m.BindingID || c.BindingEpoch != m.BindingEpoch || c.State != store.EndpointKeyCandidateStateCandidate || c.Version != k.CandidateVersion || c.KeyID != k.CandidateKeyID || c.ProofDigest != k.CandidateProofDigest || !bytes.Equal(c.Proof, k.CandidateAttestation) || !machineSamePublicIdentity(c.Public, k.CandidatePublicIdentity) {
		return nodekeys.ErrLocalDomainPolicy
	}
	return nil
}

func verifyLocalDomainPeerTarget(ctx context.Context, s *nodekeys.CryptoState, hub, group string, sender, receiver crossNodeGroupEndpointEvidence, current *wire.LocalDomainCurrent, operation, attempt string) (bool, error) {
	required, err := s.VerifyLocalDomainGroupAuthorization(ctx, group, sender.LocalDomainGrant, receiver.LocalDomainGrant, current, operation, attempt, time.Now().UTC())
	if err != nil || !required {
		return required, err
	}
	if sender.LocalDomainGrant.Manifest.HubID != hub || receiver.LocalDomainGrant.Manifest.HubID != hub {
		return true, nodekeys.ErrLocalDomainPolicy
	}
	for _, e := range []crossNodeGroupEndpointEvidence{sender, receiver} {
		if err := matchLocalDomainEndpoint(e, *e.LocalDomainGrant); err != nil {
			return true, err
		}
	}
	return true, nil
}

func loadLocalDomainPeerIdentity(ctx context.Context, s *nodekeys.CryptoState, root, endpoint string) (*e2ee.Identity, error) {
	pub, err := s.LocalDomainOriginalLocalKey(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	identity, err := nodekeys.LoadExisting(root, endpoint)
	if err != nil || !machineSamePublicIdentity(identity.Public(), pub) {
		return nil, errors.New("original local-domain Endpoint key is missing or differs; replacement refused")
	}
	return identity, nil
}

// The complete domain chain checks both local and peer keys; the legacy branch
// continues using its original finite Owner grant verifier without conversion.
func pinCurrentSameGroupPeer(ctx context.Context, s *nodekeys.CryptoState, peerKey crossNodeGroupPeerKey, local, peer crossNodeGroupEndpointEvidence, identity *e2ee.Identity) (*nodekeys.PeerKeyPin, error) {
	operation, attempt := "peer_key", peerKey.Sender.EndpointID+":"+peerKey.Receiver.EndpointID
	if peerKey.LocalDomainCurrent != nil && peerKey.LocalDomainCurrent.Operation == "native_delivery" {
		operation, attempt = "native_delivery", peerKey.LocalDomainCurrent.AttemptID
	}
	domain, err := verifyLocalDomainPeerTarget(ctx, s, peerKey.HubID, peerKey.GroupID, peerKey.Sender, peerKey.Receiver, peerKey.LocalDomainCurrent, operation, attempt)
	if err != nil {
		return nil, err
	}
	if domain {
		if peerKey.NativePairEvidence != nil || peerKey.NativePairCurrent != nil || local.LocalDomainGrant == nil || !machineSamePublicIdentity(local.LocalDomainGrant.Manifest.CandidatePublicIdentity, identity.Public()) {
			return nil, nodekeys.ErrLocalDomainPolicy
		}
		return s.PinLocalDomainPeer(ctx, local.EndpointID, *peerKey.Sender.LocalDomainGrant, *peerKey.Receiver.LocalDomainGrant, *peerKey.LocalDomainCurrent, operation, attempt, time.Now().UTC())
	}
	evidence, err := crossNodeGroupPinEvidence(peerKey, local, peer)
	if err != nil {
		return nil, err
	}
	pin, err := s.PinOwnerGrantedGroupEndpointPeerKey(ctx, evidence)
	if err != nil {
		return nil, err
	}
	localEvidence, err := crossNodeGroupPinEvidence(peerKey, peer, local)
	if err != nil {
		return nil, err
	}
	verified, err := s.VerifyGroupEndpointKeyGrant(ctx, localEvidence)
	if err != nil || !machineSamePublicIdentity(verified.Public, identity.Public()) {
		return nil, errors.New("current local Endpoint Owner grant differs from its private key")
	}
	return pin, nil
}
