package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// An authenticated historical success can be settled without reinstalling a
// grant that is independently known to be obsolete. The caller still receives
// this explicit local terminal result; unknown validation failures remain pending.
type endpointGroupsRecoveredGrantObsolete struct{ reason string }

func (e *endpointGroupsRecoveredGrantObsolete) Error() string {
	return "ENDPOINT_GROUPS_RECOVERED_GRANT_" + e.reason
}

// Caller holds c.mu, after authenticating and remembering the exact recovered
// Complete but before clearing its pending outbox. CryptoState never calls back
// into c. Its transaction commits first; retry after either persistence boundary
// is idempotent and cannot lower an independently retained Owner head.
func (c *machineNodeControlClient) installRecoveredEndpointGroupGrantLocked(ctx context.Context, clock func() time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	origin := c.state.PendingLocalEndpointIntentID
	intent, ok := c.state.LocalEndpointIntents[origin]
	step, found := intent.Steps[c.state.PendingOperationID]
	if !ok || !found || origin == "" || step.Operation != wire.OperationEndpointGroupsNodeKeyComplete || !step.Settled || !bytes.Equal(step.RequestPacket, c.state.PendingPacket) || !bytes.Equal(step.ResponsePacket, c.state.PendingResponsePacket) {
		return errLocalEndpointIntentConflict
	}
	var r machineEndpointGroupsRegistration
	matches := 0
	for _, candidate := range c.state.EndpointGroupsRegistrations {
		if candidate.IntentID == origin {
			if candidate.IntentDigest != intent.Digest || candidate.LocallyOffline {
				return errEndpointGroupsRegistration
			}
			r = candidate
			matches++
		}
	}
	if matches != 1 || r.Anchor.NodeKeyEpoch != c.state.NodeKeyEpoch {
		return errEndpointGroupsRegistration
	}
	_, _, original, err := c.endpointGroupsOriginalLocked(r)
	if err != nil {
		return err
	}
	root := machineNodeStateDir(c.stateDir, c.nodeID)
	reader, err := nodekeys.OpenExistingCryptoState(ctx, root)
	if err != nil {
		return err
	}
	defer reader.Close()
	policy, err := reader.LocalDomainPolicyForGroup(ctx, original.Description.Policy.GroupID)
	if err != nil {
		return err
	}
	if policy.Policy.Origin != c.base || !reflect.DeepEqual(policy.Policy, original.Description.Policy) || policy.Hub.HubID != c.state.HubID || !machineSamePublicIdentity(policy.Policy.Node.HubNodeControlPublic, c.state.HubPublicIdentity) {
		return errEndpointGroupsRegistration
	}
	hub, owner := policy.Hub, original.Description.Policy.OwnerPublic
	trust, err := reader.GetNodeOwnerKeyTrustLocalContext(ctx, r.Anchor.Registration.OwnerID, owner.ID)
	if err != nil {
		return err
	}
	if !machineSamePublicIdentity(trust.PublicIdentity, owner) {
		return errEndpointGroupsRegistration
	}
	result, p, valid := c.endpointGroupsRetainedKeyResultLocked(c.state.PendingOperationID, step, r, hub, owner)
	var request wire.EndpointGroupsNodeKeyComplete
	if !valid || decodeStrictBridgeJSON(step.Body, &request) != nil || !endpointGroupsCompleteProofMatches(request, result, p) {
		return errEndpointGroupsRegistration
	}
	// Reuse the original authenticated Challenge and exactly the same projection
	// comparisons as the normal Complete path. No new Prepare or action is sent.
	key := fmt.Sprintf("%s.%d.%d", request.PolicyID, request.PolicyEpoch, request.ExpectedRelationRevision)
	generation := r.KeyPrepareGenerations[key]
	if c.state.PendingOperationID != localEndpointStepID(origin, intent.Digest, fmt.Sprintf("groups.complete.%s.%d", key, generation)) {
		return errLocalEndpointIntentConflict
	}
	prepareID := localEndpointStepID(origin, intent.Digest, fmt.Sprintf("groups.prepare.%s.%d", key, generation))
	read, ok := intent.Steps[prepareID]
	var q wire.EndpointGroupsNodeKeyPrepare
	if !ok || read.Operation != wire.OperationEndpointGroupsNodeKeyPrepare || !read.Settled || decodeStrictBridgeJSON(read.Body, &q) != nil || q.PolicyID != request.PolicyID || q.PolicyEpoch != request.PolicyEpoch || q.EndpointID != request.EndpointID || q.GroupID != request.GroupID || q.ExpectedRelationRevision != request.ExpectedRelationRevision {
		return errEndpointGroupsRegistration
	}
	prepared, expected, verified := c.endpointGroupsRetainedKeyResultLocked(prepareID, read, r, hub, owner)
	if !verified || prepared.Challenge == nil || !reflect.DeepEqual(expected, p) {
		return errEndpointGroupsRegistration
	}
	ch := prepared.Challenge
	if ch.ChallengeID != request.ChallengeID || result.OwnerControl != ch.ProjectedOwnerControl || result.Grant.Relation != ch.ProjectedRelation || !reflect.DeepEqual(result.Grant.Manifest, ch.ProjectedKeyManifest) || !bytes.Equal(result.Grant.PolicyProof, prepared.PolicyProof) {
		return errEndpointGroupsRegistration
	}
	now := clock().UTC()
	if err := ctx.Err(); err != nil {
		return err
	}
	if trust.State == nodekeys.NodeOwnerKeyTrustRevoked {
		return &endpointGroupsRecoveredGrantObsolete{"OWNER_PIN_REVOKED"}
	}
	if trust.State != nodekeys.NodeOwnerKeyTrustActive {
		return errEndpointGroupsRegistration
	}
	if err := reader.CheckEndpointGroupsRegistration(ctx, hub, r.Anchor, now); err != nil {
		return err
	}
	if p.ExpiresAt != "" && !now.Before(parseMachineNativePairTime(p.ExpiresAt)) {
		return &endpointGroupsRecoveredGrantObsolete{"POLICY_EXPIRED"}
	}
	head, headErr := reader.ReadEndpointGroupStoredOwnerHead(ctx, hub, r.Anchor, p.GroupID)
	if headErr == nil && head.Mode == "OWNER" && head.Revision > result.OwnerControl.Revision && (head.PolicyEpoch > result.OwnerControl.PolicyEpoch || head.PolicyEpoch == result.OwnerControl.PolicyEpoch && head.PolicyID == result.OwnerControl.PolicyID) {
		return &endpointGroupsRecoveredGrantObsolete{"SUPERSEDED_HEAD"}
	}
	if headErr != nil && !errors.Is(headErr, sql.ErrNoRows) {
		return headErr
	}
	// Historical response time authenticated evidence only. The real current
	// time and transaction recheck pin, expiry, registration and monotonic head.
	state, err := nodekeys.OpenCryptoState(root)
	if err != nil {
		return err
	}
	defer state.Close()
	now = clock().UTC()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.ExpiresAt != "" && !now.Before(parseMachineNativePairTime(p.ExpiresAt)) {
		return &endpointGroupsRecoveredGrantObsolete{"POLICY_EXPIRED"}
	}
	return state.RememberEndpointGroupGrant(ctx, hub, r.Anchor, *result.Grant, result.OwnerControl, now)
}
