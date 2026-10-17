package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func loadNativePairPublicationIdentity(stateDir, endpointID string, original *e2ee.PublicIdentity) (*e2ee.Identity, error) {
	if original == nil {
		return nodekeys.LoadOrCreate(stateDir, endpointID)
	}
	identity, err := nodekeys.LoadExisting(stateDir, endpointID)
	if err != nil {
		return nil, errors.New("original Pair Endpoint key is unavailable; refusing replacement")
	}
	if !sameMCPKeyPublic(identity.Public(), *original) {
		return nil, errors.New("local Pair Endpoint key differs from its retained original identity")
	}
	return identity, nil
}

func prepareNativePairLocalCandidate(ctx context.Context, state *nodekeys.CryptoState, stateDir string, policy nodekeys.NativePairPolicy, card fabric.NetworkCard, owner string) (*e2ee.Identity, nodekeys.GroupEndpointKeyCandidate, error) {
	var empty nodekeys.GroupEndpointKeyCandidate
	if card.GroupID != policy.GroupID || card.NodeID != policy.NodeID {
		return nil, empty, nodekeys.ErrNativePairPolicy
	}
	original, err := state.NativePairOriginalLocalKey(ctx, card.EndpointID)
	var expected *e2ee.PublicIdentity
	if err == nil {
		expected = &original
	} else if !errors.Is(err, nodekeys.ErrCryptoStateNotFound) {
		return nil, empty, err
	}
	identity, err := loadNativePairPublicationIdentity(stateDir, card.EndpointID, expected)
	if err != nil {
		return nil, empty, err
	}
	candidate, err := state.NativePairLocalAttestation(ctx, policy.PairID, card.EndpointID, card.BindingID, card.BindingEpoch)
	if err == nil {
		if !sameMCPKeyPublic(candidate.PublicIdentity, identity.Public()) || candidate.PrincipalID != card.PrincipalID || candidate.OwnerID != owner || candidate.NodeID != card.NodeID || candidate.GroupID != card.GroupID {
			return nil, empty, nodekeys.ErrNativePairConflict
		}
		return identity, candidate, nil
	}
	if !errors.Is(err, nodekeys.ErrCryptoStateNotFound) {
		return nil, empty, err
	}
	proof, err := identity.SignEndpointKeyAttestation(card.EndpointID, card.PrincipalID, card.NodeID, card.BindingID, card.BindingEpoch)
	if err != nil {
		return nil, empty, err
	}
	fp, err := nodekeys.PeerKeyFingerprint(identity.Public())
	if err != nil {
		return nil, empty, err
	}
	hash := sha256.Sum256(proof)
	candidate = nodekeys.GroupEndpointKeyCandidate{EndpointID: card.EndpointID, GroupID: card.GroupID, PrincipalID: card.PrincipalID, OwnerID: owner, NodeID: card.NodeID, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch, KeyID: identity.Public().ID, KeyFingerprint: fp, ProofDigest: hex.EncodeToString(hash[:]), PublicIdentity: identity.Public(), Attestation: proof}
	if err := state.RememberNativePairLocalAttestation(ctx, policy.PairID, candidate); err != nil {
		return nil, empty, err
	}
	return identity, candidate, nil
}

func nativePairPublishedCandidate(c store.EndpointKeyCandidate) nodekeys.GroupEndpointKeyCandidate {
	fp, _ := nodekeys.PeerKeyFingerprint(c.Public)
	return nodekeys.GroupEndpointKeyCandidate{EndpointID: c.EndpointID, GroupID: "", PrincipalID: c.PrincipalID, OwnerID: c.OwnerID, NodeID: c.NodeID, BindingID: c.BindingID, BindingEpoch: c.BindingEpoch, CandidateVersion: c.Version, KeyID: c.KeyID, KeyFingerprint: fp, ProofDigest: c.ProofDigest, PublicIdentity: c.Public, Attestation: c.Proof}
}
