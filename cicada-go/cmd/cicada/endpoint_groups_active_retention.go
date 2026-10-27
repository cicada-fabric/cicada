package main

import (
	"bytes"
	"context"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// An ACTIVE read follows its Complete's expected relation revision. Local
// metadata only selects possible work; it never proves an outcome or a head.
func endpointGroupsActiveRetirementMetadata(intent machineLocalEndpointIntent, read machineLocalEndpointStep) bool {
	var q wire.EndpointGroupsNodeKeyPrepare
	if read.Operation != wire.OperationEndpointGroupsNodeKeyPrepare || !read.Settled || len(read.RequestPacket) == 0 || len(read.ResponsePacket) == 0 || decodeStrictBridgeJSON(read.Body, &q) != nil {
		return false
	}
	for _, write := range intent.Steps {
		var request wire.EndpointGroupsNodeKeyComplete
		if write.Operation == wire.OperationEndpointGroupsNodeKeyComplete && write.Settled && len(write.RequestPacket) > 0 && len(write.ResponsePacket) > 0 && decodeStrictBridgeJSON(write.Body, &request) == nil &&
			request.PolicyID == q.PolicyID && request.PolicyEpoch == q.PolicyEpoch && request.EndpointID == q.EndpointID && request.GroupID == q.GroupID && request.ExpectedRelationRevision < q.ExpectedRelationRevision {
			return true
		}
	}
	return false
}

// A persisted terminal head may retain an earlier relation identity. The
// existing-only nodekeys reader authenticates its immutable scope and computes
// the new head digest independently. Authorities is not a highwater source.
func endpointGroupsHeadMaySupersede(head e2ee.EndpointGroupOwnerControl, policyID string, epoch uint64) bool {
	if head.Mode != "OWNER" {
		return false
	}
	if head.DenyReason == "NONE" {
		return head.PolicyEpoch > epoch
	}
	return (head.DenyReason == "REMOVED" || head.DenyReason == "EXPIRED") &&
		(head.PolicyEpoch > epoch || head.PolicyEpoch == epoch && head.PolicyID == policyID)
}

// Keep stable current reads out of original receipt/Owner cryptography. This
// prefilter reads only existing durable heads; an absent Authorities entry is
// never grounds to exclude a terminal head. Full checks follow before removal.
func (b *machineAgentJoinBridge) endpointGroupsHasSupersededActive(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, hub wire.HubIdentity) bool {
	state, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return false
	}
	defer state.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !endpointGroupsRetentionIdle(c.state) {
		return false
	}
	intent, ok := c.state.LocalEndpointIntents[r.IntentID]
	if !ok || intent.Digest != r.IntentDigest {
		return false
	}
	for _, read := range intent.Steps {
		if !endpointGroupsActiveRetirementMetadata(intent, read) {
			continue
		}
		var q wire.EndpointGroupsNodeKeyPrepare
		if decodeStrictBridgeJSON(read.Body, &q) != nil || q.EndpointID != r.Anchor.Registration.EndpointID {
			continue
		}
		head, err := state.ReadEndpointGroupStoredOwnerHead(ctx, hub, r.Anchor, q.GroupID)
		if err == nil && endpointGroupsHeadMaySupersede(head, q.PolicyID, q.PolicyEpoch) {
			return true
		}
	}
	return false
}

// Caller holds c.mu and has checked the original intent, Owner pin and all
// thirteen idle coordinates. Only old read response bytes can change.
func (c *machineNodeControlClient) retireSupersededEndpointGroupsActiveLocked(ctx context.Context, state *nodekeys.CryptoState, r machineEndpointGroupsRegistration, hub wire.HubIdentity, owner e2ee.PublicIdentity, intent machineLocalEndpointIntent) bool {
	type recordedHead struct {
		head e2ee.EndpointGroupOwnerControl
		err  error
	}
	// This call-local memo avoids repeated DB reads; no authority cache or new
	// persistent state is created. Heads can only move forward after this read.
	heads := make(map[string]recordedHead)
	changed := false
	for id, read := range intent.Steps {
		if !endpointGroupsActiveRetirementMetadata(intent, read) {
			continue
		}
		var q wire.EndpointGroupsNodeKeyPrepare
		if decodeStrictBridgeJSON(read.Body, &q) != nil || q.EndpointID != r.Anchor.Registration.EndpointID {
			continue
		}
		stored, ok := heads[q.GroupID]
		if !ok {
			stored.head, stored.err = state.ReadEndpointGroupStoredOwnerHead(ctx, hub, r.Anchor, q.GroupID)
			heads[q.GroupID] = stored
		}
		if stored.err != nil || !endpointGroupsHeadMaySupersede(stored.head, q.PolicyID, q.PolicyEpoch) {
			continue
		}
		old, p, valid := c.endpointGroupsRetainedResultLocked(id, read, r, hub, owner, true)
		if !valid || old.Grant == nil || old.Challenge != nil || p.PolicyID != q.PolicyID || p.Epoch != q.PolicyEpoch || p.EndpointID != q.EndpointID || p.GroupID != q.GroupID || old.OwnerControl.Mode != "OWNER" || old.OwnerControl.DenyReason != "NONE" || stored.head.Revision <= old.OwnerControl.Revision {
			continue
		}
		oldComplete, unsettled := false, false
		for writeID, write := range intent.Steps {
			var request wire.EndpointGroupsNodeKeyComplete
			if write.Operation != wire.OperationEndpointGroupsNodeKeyComplete || decodeStrictBridgeJSON(write.Body, &request) != nil || request.PolicyID != p.PolicyID || request.PolicyEpoch != p.Epoch || request.EndpointID != p.EndpointID || request.GroupID != p.GroupID {
				continue
			}
			if !write.Settled || len(write.RequestPacket) == 0 || len(write.ResponsePacket) == 0 {
				unsettled = true
				continue
			}
			complete, actual, verified := c.endpointGroupsRetainedKeyResultLocked(writeID, write, r, hub, owner)
			if verified && reflect.DeepEqual(actual, p) && complete.OwnerControl == old.OwnerControl && reflect.DeepEqual(complete.Grant, old.Grant) && endpointGroupsCompleteProofMatches(request, complete, p) {
				oldComplete = true
			}
		}
		if !oldComplete || unsettled {
			continue
		}
		if stored.head.DenyReason == "NONE" && !c.endpointGroupsReplacementCompleteLocked(intent, r, hub, owner, p, old.OwnerControl, stored.head) {
			continue
		}
		read.ResponsePacket = nil
		intent.Steps[id] = read
		changed = true
	}
	return changed
}

func endpointGroupsCompleteProofMatches(q wire.EndpointGroupsNodeKeyComplete, result wire.EndpointGroupsNodeKeyResult, p e2ee.EndpointGroupPolicy) bool {
	if result.Grant == nil || result.Challenge != nil || q.PolicyID != p.PolicyID || q.PolicyEpoch != p.Epoch || q.EndpointID != p.EndpointID || q.GroupID != p.GroupID || !bytes.Equal(q.NodeProof, result.Grant.NodeProof) {
		return false
	}
	observed, err := endpointGroupsHistoricalObservedAt(result.ObservedAt)
	if err != nil {
		return false
	}
	claims, err := e2ee.VerifyEndpointGroupKey(p, q.NodeProof, observed)
	return err == nil && claims.ChallengeID == q.ChallengeID
}

func (c *machineNodeControlClient) endpointGroupsReplacementCompleteLocked(intent machineLocalEndpointIntent, r machineEndpointGroupsRegistration, hub wire.HubIdentity, owner e2ee.PublicIdentity, old e2ee.EndpointGroupPolicy, oldHead, known e2ee.EndpointGroupOwnerControl) bool {
	if known.Mode != "OWNER" || known.DenyReason != "NONE" || known.Revision <= oldHead.Revision || known.PolicyEpoch <= old.Epoch {
		return false
	}
	for id, write := range intent.Steps {
		var q wire.EndpointGroupsNodeKeyComplete
		if write.Operation != wire.OperationEndpointGroupsNodeKeyComplete || !write.Settled || len(write.RequestPacket) == 0 || len(write.ResponsePacket) == 0 || decodeStrictBridgeJSON(write.Body, &q) != nil ||
			q.PolicyID != known.PolicyID || q.PolicyEpoch != known.PolicyEpoch || q.EndpointID != old.EndpointID || q.GroupID != old.GroupID {
			continue
		}
		result, p, valid := c.endpointGroupsRetainedKeyResultLocked(id, write, r, hub, owner)
		if valid && result.Grant != nil && result.OwnerControl == known && p.Epoch > old.Epoch && p.GroupID == old.GroupID && p.EndpointID == old.EndpointID && endpointGroupsCompleteProofMatches(q, result, p) {
			return true
		}
	}
	return false
}
