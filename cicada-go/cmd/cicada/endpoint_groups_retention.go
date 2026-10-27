package main

import (
	"bytes"
	"context"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// Retention also avoids legacy execution/transfer state. Issuer verification
// keeps its separate read fence: an ordinary retained Claim is not a denial of
// current native-context verification.
func endpointGroupsRetentionIdle(s machineNodeControlState) bool {
	return endpointGroupsNodePendingEmpty(s) && len(s.PendingNativePairBody) == 0 && s.PendingWorkerID == "" && s.PendingWorkerAttempt == 0 && s.PendingSnapshotPath == "" && s.PendingSnapshotManifest == nil && s.ClaimTicket == nil
}

// Local metadata can only exclude work. In particular, an ACTIVE read uses the
// advanced relation revision and has no Complete with that expected revision.
// A match never establishes successful completion; full authentication follows.
func endpointGroupsRetirementMetadata(intent machineLocalEndpointIntent, read machineLocalEndpointStep) bool {
	var q wire.EndpointGroupsNodeKeyPrepare
	if read.Operation != wire.OperationEndpointGroupsNodeKeyPrepare || !read.Settled || len(read.RequestPacket) == 0 || len(read.ResponsePacket) == 0 || decodeStrictBridgeJSON(read.Body, &q) != nil {
		return false
	}
	for _, write := range intent.Steps {
		var request wire.EndpointGroupsNodeKeyComplete
		if write.Operation == wire.OperationEndpointGroupsNodeKeyComplete && write.Settled && len(write.RequestPacket) > 0 && len(write.ResponsePacket) > 0 && decodeStrictBridgeJSON(write.Body, &request) == nil &&
			request.PolicyID == q.PolicyID && request.PolicyEpoch == q.PolicyEpoch && request.EndpointID == q.EndpointID && request.GroupID == q.GroupID && request.ExpectedRelationRevision == q.ExpectedRelationRevision {
			return true
		}
	}
	return false
}

// A successful original Complete supersedes only its historical Challenge
// response. A previously ACTIVE read can retire only behind a durable higher
// Owner head, as checked separately below. Original requests remain fenced.
func (b *machineAgentJoinBridge) retireEndpointGroupsChallenges(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, hub wire.HubIdentity) error {
	c.mu.Lock()
	stored, enrolled := c.state.EndpointGroupsRegistrations[r.Anchor.RegistrationDigest]
	candidate := false
	challengeCandidate := false
	if enrolled && stored.IntentID == r.IntentID && stored.IntentDigest == r.IntentDigest && sameEndpointGroupsAnchor(stored.Anchor, r.Anchor) && endpointGroupsRetentionIdle(c.state) {
		for _, step := range c.state.LocalEndpointIntents[r.IntentID].Steps {
			if endpointGroupsRetirementMetadata(c.state.LocalEndpointIntents[r.IntentID], step) {
				challengeCandidate = true
				candidate = true
				break
			}
			if endpointGroupsActiveRetirementMetadata(c.state.LocalEndpointIntents[r.IntentID], step) {
				candidate = true
			}
		}
	}
	c.mu.Unlock()
	if !candidate {
		return nil
	}
	if !challengeCandidate && !b.endpointGroupsHasSupersededActive(ctx, c, r, hub) {
		return nil
	}
	_, _, original, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return err
	}
	state, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return err
	}
	defer state.Close()
	owner := original.Description.Policy.OwnerPublic
	trust, err := state.GetNodeOwnerKeyTrustLocalContext(ctx, r.Anchor.Registration.OwnerID, owner.ID)
	if err != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive || !machineSamePublicIdentity(trust.PublicIdentity, owner) {
		return errEndpointGroupsRegistration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !endpointGroupsRetentionIdle(c.state) {
		return nil
	}
	stored, enrolled = c.state.EndpointGroupsRegistrations[r.Anchor.RegistrationDigest]
	if !enrolled || stored.IntentID != r.IntentID || stored.IntentDigest != r.IntentDigest || !sameEndpointGroupsAnchor(stored.Anchor, r.Anchor) {
		return nil
	}
	intent, ok := c.state.LocalEndpointIntents[r.IntentID]
	if !ok || intent.Digest != r.IntentDigest {
		return errLocalEndpointIntentConflict
	}
	previous := cloneMachineNodeControlState(c.state)
	changed := false
	for readID, read := range intent.Steps {
		if !endpointGroupsRetirementMetadata(intent, read) {
			continue
		}
		prepared, p, ok := c.endpointGroupsRetainedKeyResultLocked(readID, read, r, hub, trust.PublicIdentity)
		var q wire.EndpointGroupsNodeKeyPrepare
		if !ok || prepared.Challenge == nil || prepared.Grant != nil || decodeStrictBridgeJSON(read.Body, &q) != nil ||
			q.PolicyID != p.PolicyID || q.PolicyEpoch != p.Epoch || q.EndpointID != p.EndpointID || q.GroupID != p.GroupID || q.ExpectedRelationRevision != prepared.Challenge.Expected.RelationRevision {
			continue
		}
		claims, err := wire.EndpointGroupKeyClaimsForChallenge(*prepared.Challenge, p)
		observed, observedErr := endpointGroupsHistoricalObservedAt(prepared.ObservedAt)
		if err != nil || observedErr != nil {
			continue
		}
		matched, unsettled := false, false
		for writeID, write := range intent.Steps {
			var request wire.EndpointGroupsNodeKeyComplete
			if write.Operation != wire.OperationEndpointGroupsNodeKeyComplete || decodeStrictBridgeJSON(write.Body, &request) != nil ||
				request.PolicyID != q.PolicyID || request.PolicyEpoch != q.PolicyEpoch || request.EndpointID != q.EndpointID || request.GroupID != q.GroupID {
				continue
			}
			if !write.Settled || len(write.ResponsePacket) == 0 {
				unsettled = true
				continue
			}
			completed, actual, valid := c.endpointGroupsRetainedKeyResultLocked(writeID, write, r, hub, trust.PublicIdentity)
			verified, proofErr := e2ee.VerifyEndpointGroupKey(p, request.NodeProof, observed)
			ch := prepared.Challenge
			if valid && proofErr == nil && verified == claims && completed.Grant != nil && reflect.DeepEqual(actual, p) && request.ExpectedRelationRevision == q.ExpectedRelationRevision && request.ChallengeID == ch.ChallengeID &&
				completed.OwnerControl == ch.ProjectedOwnerControl && completed.Grant.Relation == ch.ProjectedRelation && reflect.DeepEqual(completed.Grant.Manifest, ch.ProjectedKeyManifest) &&
				bytes.Equal(completed.Grant.PolicyProof, prepared.PolicyProof) && bytes.Equal(completed.Grant.NodeProof, request.NodeProof) {
				matched = true
			}
		}
		if matched && !unsettled {
			read.ResponsePacket = nil
			intent.Steps[readID] = read
			changed = true
		}
	}
	if c.retireSupersededEndpointGroupsActiveLocked(ctx, state, r, hub, trust.PublicIdentity, intent) {
		changed = true
	}
	if !changed {
		return nil
	}
	c.state.LocalEndpointIntents[r.IntentID] = intent
	if err := c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	return nil
}

// Caller holds c.mu. Historical time authenticates retention evidence only;
// it is never used to mint a ticket or authorize a current Group operation.
func (c *machineNodeControlClient) endpointGroupsRetainedKeyResultLocked(id string, step machineLocalEndpointStep, r machineEndpointGroupsRegistration, hub wire.HubIdentity, owner e2ee.PublicIdentity) (wire.EndpointGroupsNodeKeyResult, e2ee.EndpointGroupPolicy, bool) {
	return c.endpointGroupsRetainedResultLocked(id, step, r, hub, owner, false)
}

func (c *machineNodeControlClient) endpointGroupsRetainedResultLocked(id string, step machineLocalEndpointStep, r machineEndpointGroupsRegistration, hub wire.HubIdentity, owner e2ee.PublicIdentity, allowActiveRead bool) (wire.EndpointGroupsNodeKeyResult, e2ee.EndpointGroupPolicy, bool) {
	var result wire.EndpointGroupsNodeKeyResult
	var empty e2ee.EndpointGroupPolicy
	packet, err := wire.DecodeEndpointGroupsNodePacket(step.RequestPacket)
	if err != nil || packet.Route.Operation != step.Operation || packet.Route.OperationID != id {
		return result, empty, false
	}
	envelope, err := c.openEndpointGroupsEnvelopeLocked(step.RequestPacket, step.ResponsePacket)
	if err != nil || !envelope.OK || decodeStrictBridgeJSON(envelope.Result, &result) != nil {
		return result, empty, false
	}
	if !allowActiveRead && step.Operation == wire.OperationEndpointGroupsNodeKeyPrepare && (result.Challenge == nil || result.Grant != nil) {
		return result, empty, false
	}
	observed, err := endpointGroupsHistoricalObservedAt(result.ObservedAt)
	if err != nil {
		return result, empty, false
	}
	p, err := wire.ValidateEndpointGroupsNodeKeyResult(result, hub, r.Anchor.Registration.OwnerID, owner, observed)
	if err != nil || !sameEndpointGroupsAnchor(r.Anchor, result.Registration) || p.RegistrationDigest != r.Anchor.RegistrationDigest || p.Node.OwnerBindingID != c.state.BindingID ||
		!machineSamePublicIdentity(p.Node.NodePublic, c.identity.Public()) {
		return result, empty, false
	}
	return result, p, true
}
