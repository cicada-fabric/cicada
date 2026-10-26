package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func (b *machineAgentJoinBridge) renewEndpointGroupsRegistration(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration) (machineEndpointGroupsRegistration, error) {
	if r.LocallyOffline {
		return r, errEndpointGroupsOffline
	}
	hub, err := b.endpointGroupsOriginalHub(ctx, c, r)
	if err != nil {
		return r, err
	}
	if b.validateEndpointGroupsRegistration(ctx, c, r, r.Anchor, hub) != nil {
		return r, errEndpointGroupsRegistration
	}
	_, original, _, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return r, err
	}
	a := r.Anchor
	if !time.Now().Before(parseMachineNativePairTime(a.LeaseExpiresAt)) || a.State == "OFFLINE" {
		hash := sha256.Sum256([]byte(a.LeaseExpiresAt))
		step := "groups.renew." + hex.EncodeToString(hash[:])
		q := wire.EndpointGroupsNodeRenew{EndpointID: a.Registration.EndpointID, RegistrationDigest: a.RegistrationDigest, ExpectedBindingID: a.BindingID, ExpectedBindingEpoch: a.BindingEpoch}
		var resumed wire.EndpointGroupsNodeRenewResult
		if err := c.callLocalEndpoint(ctx, b.nodeToken, r.IntentID, r.IntentDigest, step, wire.OperationEndpointGroupsNodeRenew, q, &resumed); err != nil {
			return r, err
		}
		if resumed.ContractRevision != wire.OwnerEndpointGroupsContractRevision || !sameEndpointGroupsAnchor(a, resumed.Registration) || b.validateEndpointGroupsRegistration(ctx, c, r, resumed.Registration, hub) != nil {
			return r, errEndpointGroupsRegistration
		}
		r.Anchor = resumed.Registration
	} else {
		// Registration-only heartbeat preserves the original writer and grants no
		// Group or Network business permission. Ordinary ticks create no RPC receipt.
		raw, err := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/heartbeat", nil, "CicadaSession "+original.SessionToken, "")
		if err != nil {
			return r, err
		}
		var actor fabric.Actor
		if decodeStrictBridgeJSON(raw, &actor) != nil || actor.EndpointID != a.Registration.EndpointID || actor.PrincipalID != a.Registration.PrincipalID || actor.BindingID != a.BindingID || actor.BindingEpoch != a.BindingEpoch || actor.LeaseExpiresAt == "" {
			return r, errEndpointGroupsRegistration
		}
		r.Anchor.LeaseExpiresAt = actor.LeaseExpiresAt
		r.Anchor.State = "REGISTERED"
	}
	if err := c.saveEndpointGroupsRegistration(r); err != nil {
		return r, err
	}
	return r, nil
}

func (b *machineAgentJoinBridge) completeEndpointGroupPolicy(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, card wire.OwnerEndpointGroupsRelationCard, source wire.OwnerEndpointGroupsContributionCard) error {
	hub, err := b.endpointGroupsOriginalHub(ctx, c, r)
	if err != nil {
		return err
	}
	if b.validateEndpointGroupsRegistration(ctx, c, r, r.Anchor, hub) != nil {
		return errEndpointGroupsRegistration
	}
	_, original, completed, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return err
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return err
	}
	defer state.Close()
	owner := completed.Description.Policy.OwnerPublic
	trust, err := state.GetNodeOwnerKeyTrustLocalContext(ctx, r.Anchor.Registration.OwnerID, owner.ID)
	if err != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive || !machineSamePublicIdentity(trust.PublicIdentity, owner) {
		return errEndpointGroupsRegistration
	}
	if r.KeyPrepareGenerations == nil {
		r.KeyPrepareGenerations = make(map[string]uint64)
	}
	key := fmt.Sprintf("%s.%d.%d", source.AuthorityID, source.AuthorityEpoch, card.RelationRevision)
	generation := r.KeyPrepareGenerations[key]
	prepareStep := fmt.Sprintf("groups.prepare.%s.%d", key, generation)
	completeStep := fmt.Sprintf("groups.complete.%s.%d", key, generation)
	q := wire.EndpointGroupsNodeKeyPrepare{PolicyID: source.AuthorityID, PolicyEpoch: source.AuthorityEpoch, EndpointID: r.Anchor.Registration.EndpointID, GroupID: card.GroupID, ExpectedRelationRevision: card.RelationRevision}
	var prepared wire.EndpointGroupsNodeKeyResult
	if err := c.callLocalEndpoint(ctx, b.nodeToken, r.IntentID, r.IntentDigest, prepareStep, wire.OperationEndpointGroupsNodeKeyPrepare, q, &prepared); err != nil {
		if errors.Is(err, errLocalEndpointReceiptExpired) {
			old, ok, readErr := c.localEndpointStep(r.IntentID, r.IntentDigest, prepareStep)
			_, hasComplete, completeErr := c.localEndpointStep(r.IntentID, r.IntentDigest, completeStep)
			if readErr == nil && completeErr == nil && ok && old.Settled && len(old.DiagnosticResponse) > 0 && !hasComplete && source.State == "PENDING_KEY" {
				if generation >= 1<<63-1 {
					return errLocalEndpointHistoryFull
				}
				r.KeyPrepareGenerations[key] = generation + 1
				return c.saveEndpointGroupsRegistration(r)
			}
		}
		return err
	}
	// Historical verification settles this original only. Current permission
	// separately needs the retained Owner pin, registration and fresh Hub Guard.
	observed, err := endpointGroupsHistoricalObservedAt(prepared.ObservedAt)
	if err != nil {
		return err
	}
	p, err := wire.ValidateEndpointGroupsNodeKeyResult(prepared, hub, r.Anchor.Registration.OwnerID, trust.PublicIdentity, observed)
	if err != nil || !sameEndpointGroupsAnchor(r.Anchor, prepared.Registration) || p.PolicyID != q.PolicyID || p.Epoch != q.PolicyEpoch || p.EndpointID != q.EndpointID || p.GroupID != q.GroupID ||
		p.RegistrationDigest != r.Anchor.RegistrationDigest || p.BindingID != r.Anchor.BindingID || p.BindingEpoch != r.Anchor.BindingEpoch || p.CandidateVersion != r.Anchor.CandidateVersion ||
		p.EndpointKeyID != r.Anchor.CandidateKeyID || !machineSamePublicIdentity(p.EndpointPublic, r.Anchor.CandidatePublic) || p.CandidateProofDigest != r.Anchor.CandidateProofDigest ||
		p.Node.OwnerBindingID != c.approvedBinding().BindingID || !machineSamePublicIdentity(p.Node.NodePublic, c.publicIdentity()) {
		return errEndpointGroupsRegistration
	}
	now := time.Now().UTC()
	if err := state.RequireEndpointGroupPolicy(ctx, hub, p, prepared.PolicyProof, now); err != nil {
		return err
	}
	if prepared.Grant != nil {
		return state.RememberEndpointGroupGrant(ctx, hub, r.Anchor, *prepared.Grant, prepared.OwnerControl, now)
	}
	if prepared.Challenge == nil {
		return errEndpointGroupsRegistration
	}
	ch := *prepared.Challenge
	if ch.Expected.RelationRevision != q.ExpectedRelationRevision || ch.ProjectedRelation.EndpointID != q.EndpointID || ch.ProjectedRelation.GroupID != q.GroupID {
		return errEndpointGroupsRegistration
	}
	step, hasComplete, err := c.localEndpointStep(r.IntentID, r.IntentDigest, completeStep)
	if err != nil {
		return err
	}
	if !now.Before(parseMachineNativePairTime(ch.ExpiresAt)) && !hasComplete {
		if generation >= 1<<63-1 {
			return errLocalEndpointHistoryFull
		}
		r.KeyPrepareGenerations[key] = generation + 1
		return c.saveEndpointGroupsRegistration(r)
	}
	claims, err := wire.EndpointGroupKeyClaimsForChallenge(ch, p)
	if err != nil {
		return err
	}
	if claims.RegistrationDigest != r.Anchor.RegistrationDigest || claims.NodeKeyEpoch != r.Anchor.NodeKeyEpoch {
		return errEndpointGroupsRegistration
	}
	decision, err := recordMachineNativeContextMetadata(ctx, r.Anchor.Registration.Harness, r.Anchor.Registration.NativeSessionID, r.Anchor.Registration.EndpointID, r.Anchor.BindingID, r.Anchor.BindingEpoch, store.NativeContextScopeMetadata{HubID: r.Anchor.Registration.HubID, NetworkID: r.Anchor.NetworkID, GroupID: p.GroupID, GroupContextPolicy: nodeinbox.NativeContextPolicyGroupScoped, NetworkContextPolicy: original.NativeContextScope.NetworkContextPolicy})
	if err != nil {
		return err
	}
	if decision == nil || !decision.Accepted {
		return errEndpointGroupsRegistration
	}
	request := wire.EndpointGroupsNodeKeyComplete{PolicyID: q.PolicyID, PolicyEpoch: q.PolicyEpoch, EndpointID: q.EndpointID, GroupID: q.GroupID, ExpectedRelationRevision: q.ExpectedRelationRevision, ChallengeID: ch.ChallengeID}
	if hasComplete {
		if decodeStrictBridgeJSON(step.Body, &request) != nil || request.PolicyID != q.PolicyID || request.PolicyEpoch != q.PolicyEpoch || request.EndpointID != q.EndpointID || request.GroupID != q.GroupID || request.ExpectedRelationRevision != q.ExpectedRelationRevision || request.ChallengeID != ch.ChallengeID {
			return errLocalEndpointIntentConflict
		}
		verified, err := e2ee.VerifyEndpointGroupKey(p, request.NodeProof, observed)
		if err != nil || verified != claims {
			return errEndpointGroupsRegistration
		}
	} else {
		if _, err := wire.ValidateEndpointGroupsNodeKeyResult(prepared, hub, r.Anchor.Registration.OwnerID, trust.PublicIdentity, time.Now().UTC()); err != nil {
			return errEndpointGroupsRegistration
		}
		if b.validateEndpointGroupsRegistration(ctx, c, r, r.Anchor, hub) != nil {
			return errEndpointGroupsRegistration
		}
		request.NodeProof, err = e2ee.SignEndpointGroupKey(c.identity, p, claims)
		if err != nil {
			return err
		}
	}
	var result wire.EndpointGroupsNodeKeyResult
	if err := c.callLocalEndpoint(ctx, b.nodeToken, r.IntentID, r.IntentDigest, completeStep, wire.OperationEndpointGroupsNodeKeyComplete, request, &result); err != nil {
		var refusal *endpointGroupsNodeError
		if errors.As(err, &refusal) && refusal.code == "REVIEW_EXPIRED" && card.OwnerControl == prepared.OwnerControl && source.State == "PENDING_KEY" {
			settled, ok, readErr := c.localEndpointStep(r.IntentID, r.IntentDigest, completeStep)
			if readErr == nil && ok && settled.Settled && len(settled.RequestPacket) > 0 && len(settled.ResponsePacket) > 0 {
				if generation >= 1<<63-1 {
					return errLocalEndpointHistoryFull
				}
				r.KeyPrepareGenerations[key] = generation + 1
				return c.saveEndpointGroupsRegistration(r)
			}
		}
		return err
	}
	completedAt, err := endpointGroupsHistoricalObservedAt(result.ObservedAt)
	if err != nil {
		return err
	}
	actual, err := wire.ValidateEndpointGroupsNodeKeyResult(result, hub, r.Anchor.Registration.OwnerID, trust.PublicIdentity, completedAt)
	if err != nil || result.Grant == nil || !sameEndpointGroupsAnchor(r.Anchor, result.Registration) || !reflect.DeepEqual(actual, p) || result.OwnerControl != ch.ProjectedOwnerControl || result.Grant.Relation != ch.ProjectedRelation || !reflect.DeepEqual(result.Grant.Manifest, ch.ProjectedKeyManifest) || !bytes.Equal(result.Grant.PolicyProof, prepared.PolicyProof) || !bytes.Equal(result.Grant.NodeProof, request.NodeProof) {
		return errEndpointGroupsRegistration
	}
	return state.RememberEndpointGroupGrant(ctx, hub, r.Anchor, *result.Grant, result.OwnerControl, time.Now().UTC())
}

// The durable step has already authenticated the original Hub envelope and
// response route. Its own canonical observation time validates that historical
// projection; current use still passes the real clock to nodekeys and Guard.
func endpointGroupsHistoricalObservedAt(raw string) (time.Time, error) {
	observed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || observed.IsZero() || observed.UTC().Format(time.RFC3339Nano) != raw {
		return time.Time{}, errEndpointGroupsRegistration
	}
	return observed.UTC(), nil
}

func (b *machineAgentJoinBridge) renewEndpointGroupsRegistrationBatch(ctx context.Context) {
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return
	}
	c.mu.Lock()
	var natives [][2]string
	for _, m := range c.state.ManagedLocalDomainLeases {
		if m.TranscriptPath != "" {
			natives = append(natives, [2]string{m.Join.NativeSessionID, m.Join.Workspace})
		}
	}
	c.mu.Unlock()
	sort.Slice(natives, func(i, j int) bool { return natives[i][0]+"\x00"+natives[i][1] < natives[j][0]+"\x00"+natives[j][1] })
	unique := natives[:0]
	for _, n := range natives {
		if len(unique) == 0 || unique[len(unique)-1] != n {
			unique = append(unique, n)
		}
	}
	if len(unique) == 0 {
		return
	}
	start := b.endpointGroupsNext % len(unique)
	count := len(unique)
	if count > 4 {
		count = 4
	}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return
		}
		native := unique[(start+i)%len(unique)]
		r, _, err := c.endpointGroupsRegistrationCandidate(native[0], native[1])
		if err != nil {
			continue
		}
		if r.LocallyOffline {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		updated, d, err := b.describeEndpointGroups(bounded, c, r, r.RelationsCursor, 64)
		if err != nil {
			var refused *endpointGroupsNodeError
			if errors.As(err, &refused) && refused.code == "CURSOR_STALE" {
				r.RelationsCursor = ""
				_ = c.saveEndpointGroupsRegistration(r)
			}
			cancel()
			continue
		}
		updated, err = b.renewEndpointGroupsRegistration(bounded, c, updated)
		if err == nil {
			for _, card := range d.Relations {
				for _, source := range card.Contributions {
					if source.Source == "OWNER_EXPLICIT" && (source.State == "PENDING_KEY" || source.State == "ACTIVE" && source.Effective) {
						_ = b.completeEndpointGroupPolicy(bounded, c, updated, card, source)
					}
				}
			}
		}
		updated.RelationsCursor = d.NextCursor
		_ = c.saveEndpointGroupsRegistration(updated)
		cancel()
	}
	b.endpointGroupsNext = (start + count) % len(unique)
}
