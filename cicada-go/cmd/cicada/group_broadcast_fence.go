package main

import (
	"bytes"
	"errors"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// A broadcast may span several batches. Fresh SEND authorization must not
// silently replace the binding or key that was in the immutable snapshot.
// This constraint is internal to the Node, never a caller-supplied grant.
type groupBroadcastDeliveryFence struct {
	source    store.SameGroupBroadcastV2Endpoint
	recipient store.SameGroupBroadcastV2Endpoint
}

var errGroupBroadcastSnapshotChanged = errors.New("broadcast endpoint authorization changed since the recipient snapshot")

func (f *groupBroadcastDeliveryFence) validateLocal(current *store.LocalDeliveryAuthorization) error {
	if f == nil {
		return nil
	}
	if current == nil || current.Action != "message.send" ||
		!broadcastLocalEndpointMatches(f.source, current.Source, current.SourceKey) ||
		!broadcastLocalEndpointMatches(f.recipient, current.Target, current.TargetKey) {
		return errGroupBroadcastSnapshotChanged
	}
	return nil
}

func (f *groupBroadcastDeliveryFence) validateRemote(current crossNodeGroupPeerKey) error {
	if f == nil {
		return nil
	}
	if !broadcastRemoteEndpointMatches(f.source, current.Sender) ||
		!broadcastRemoteEndpointMatches(f.recipient, current.Receiver) {
		return errGroupBroadcastSnapshotChanged
	}
	return nil
}

func broadcastLocalEndpointMatches(expected store.SameGroupBroadcastV2Endpoint,
	current store.LocalDeliveryEndpointAuthorization, key store.LocalDeliveryKeyCandidate) bool {
	return expected.EndpointID == current.EndpointID && expected.PrincipalID == current.PrincipalID &&
		expected.OwnerID == current.OwnerID && expected.NodeID == current.NodeID &&
		expected.GroupID == current.GroupID && expected.MembershipRevision == current.MembershipRevision &&
		expected.GroupJoinRevision == current.GroupJoinRevision && expected.BindingID == current.BindingID &&
		expected.BindingEpoch == current.BindingEpoch &&
		expected.KeyID == key.KeyID && expected.KeyVersion == key.Version &&
		expected.KeyProofDigest == key.ProofDigest && broadcastPublicKeysEqual(expected.PublicKey, key.Public)
}

func broadcastRemoteEndpointMatches(expected store.SameGroupBroadcastV2Endpoint,
	current crossNodeGroupEndpointEvidence) bool {
	return expected.GroupRevision == current.GroupRevision &&
		(expected.NativeSessionID == "" || expected.NativeSessionID == current.NativeSessionID) &&
		broadcastLocalEndpointMatches(expected,
			store.LocalDeliveryEndpointAuthorization{
				EndpointID: current.EndpointID, PrincipalID: current.PrincipalID, OwnerID: current.OwnerID,
				NodeID: current.NodeID, GroupID: current.GroupID, MembershipRevision: current.MembershipRevision,
				GroupJoinRevision: current.EndpointJoinRevision, BindingID: current.BindingID,
				BindingEpoch: current.BindingEpoch, NativeSessionID: current.NativeSessionID,
			}, store.LocalDeliveryKeyCandidate{
				KeyID: current.Candidate.KeyID, Version: current.Candidate.Version,
				ProofDigest: current.Candidate.ProofDigest, Public: current.Candidate.Public,
			})
}

func broadcastPublicKeysEqual(a, b e2ee.PublicIdentity) bool {
	return a.ID == b.ID && bytes.Equal(a.KEMPublic, b.KEMPublic) && bytes.Equal(a.SigningPublic, b.SigningPublic)
}
