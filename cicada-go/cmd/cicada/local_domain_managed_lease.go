package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

const localDomainLeaseReserveBytes = 768 << 10

// Tokens remain solely inside the original encrypted zero-Join step. This
// bounded record points to it; worker recovery reuses the original AttemptID,
// which the Hub permanently fences after Leave instead of admitting a new one.
type machineManagedLocalDomainLease struct {
	IntentID            string                   `json:"intent_id"`
	IntentDigest        string                   `json:"intent_digest"`
	Join                wire.LocalDomainNodeJoin `json:"join"`
	TranscriptPath      string                   `json:"transcript_path"`
	State               string                   `json:"state"`
	KnownLeaseExpiresAt string                   `json:"known_lease_expires_at,omitempty"`
	FrozenDigest        string                   `json:"frozen_digest,omitempty"`
	StopCode            string                   `json:"stop_code,omitempty"`
	Reuses              localDomainOriginalRef   `json:"reuses,omitzero"`
}

func localDomainStateReserve(s machineNodeControlState) int {
	n := 0
	for _, m := range s.ManagedLocalDomainLeases {
		if m.State == "RESERVED" {
			n += localDomainLeaseReserveBytes
		}
	}
	return n
}

func (client *machineNodeControlClient) localDomainIntentRetainedLocked(id string) bool {
	for _, m := range client.state.ManagedLocalDomainLeases {
		if m.IntentID == id && m.State != "STOPPED" {
			return true
		}
	}
	return false
}

func (client *machineNodeControlClient) reserveLocalDomainLease(q localEndpointRequest, digest, path string, join wire.LocalDomainNodeJoin) (machineManagedLocalDomainLease, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	id := localEndpointStepID(q.RequestID, digest, "domain.join")
	if m, ok := client.state.ManagedLocalDomainLeases[id]; ok {
		if m.IntentID != q.RequestID || m.IntentDigest != digest || m.Join != join || m.State == "STOPPED" {
			return m, errManagedPairLeaseStopped
		}
		return m, nil
	}
	previous := cloneMachineNodeControlState(client.state)
	live := 0
	var reuses localDomainOriginalRef
	for key, m := range client.state.ManagedLocalDomainLeases {
		if m.State == "STOPPED" {
			end := parseMachineNativePairTime(m.KnownLeaseExpiresAt)
			if !end.IsZero() && !time.Now().Before(end.Add(localEndpointIntentTTL)) {
				delete(client.state.ManagedLocalDomainLeases, key)
			}
			continue
		}
		if m.Join.NativeSessionID == q.NativeSessionID && m.Join.Workspace == q.Workspace {
			if m.Join.Selection == join.Selection {
				if m.State == "ACTIVE" {
					reuses = localDomainOriginalRef{m.IntentID, m.IntentDigest}
					continue
				}
				return m, errMachineNodeControlOutcomeUncertain
			}
			// The caller already verified the exact newly current policy. The
			// old policy cannot continue via a stale local worker snapshot.
			m.State, m.StopCode = "STOPPED", "CURRENT_POLICY_CHANGED"
			client.state.ManagedLocalDomainLeases[key] = m
			continue
		}
		live++
	}
	for _, m := range client.state.ManagedPairLeases {
		if m.State != "STOPPED" {
			live++
		}
	}
	if live >= maxManagedPairLiveLeases || len(client.state.ManagedLocalDomainLeases) >= maxLocalEndpointMutationIntents {
		client.state = previous
		return machineManagedLocalDomainLease{}, errManagedPairLeaseFull
	}
	m := machineManagedLocalDomainLease{IntentID: q.RequestID, IntentDigest: digest, Join: join, TranscriptPath: path, State: "RESERVED", Reuses: reuses}
	if client.state.ManagedLocalDomainLeases == nil {
		client.state.ManagedLocalDomainLeases = make(map[string]machineManagedLocalDomainLease)
	}
	client.state.ManagedLocalDomainLeases[id] = m
	if err := client.localEndpointCapacityLocked(); err != nil {
		client.state = previous
		return m, err
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return m, err
	}
	return m, nil
}

// Choose the token's original receipt only after the authenticated Join result.
// Reserving this command beforehand also reserves space if a concurrent Leave
// makes it a genuinely new admission instead of a current-member reuse.
func (client *machineNodeControlClient) resolveLocalDomainLease(m machineManagedLocalDomainLease, j wire.LocalDomainNodeJoinResult) (machineManagedLocalDomainLease, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	id := localEndpointStepID(m.IntentID, m.IntentDigest, "domain.join")
	current, ok := client.state.ManagedLocalDomainLeases[id]
	if !ok || current.Join != m.Join || current.State != "RESERVED" {
		return m, errLocalEndpointIntentConflict
	}
	origin := current
	var old machineManagedLocalDomainLease
	if current.Reuses.IntentID != "" {
		old, ok = client.state.ManagedLocalDomainLeases[localEndpointStepID(current.Reuses.IntentID, current.Reuses.Digest, "domain.join")]
		if !ok || old.IntentID != current.Reuses.IntentID || old.IntentDigest != current.Reuses.Digest {
			return m, errLocalEndpointIntentConflict
		}
		var completed wire.LocalDomainNodeKeyResult
		if err := client.localDomainOriginalLocked(old, "domain.complete", &completed); err != nil {
			return m, err
		}
		if j.SessionToken == "" {
			if j.Member != completed.Member {
				return m, nodekeys.ErrLocalDomainConflict
			}
			origin = old
		} else if j.Member.MemberID == completed.Member.MemberID || j.Member.BindingEpoch <= completed.Member.BindingEpoch || j.Member.EndpointID != completed.Member.EndpointID || j.Member.PrincipalID != completed.Member.PrincipalID || j.Member.NativeSessionID != completed.Member.NativeSessionID || j.Member.Workspace != completed.Member.Workspace || j.Member.NetworkAccessBindingID != completed.Member.NetworkAccessBindingID || j.Member.NetworkAccessEpoch <= completed.Member.NetworkAccessEpoch {
			return m, nodekeys.ErrLocalDomainConflict
		}
	} else if j.SessionToken == "" {
		return m, errMachineNodeControlOutcomeUncertain
	}
	ref := localDomainOriginalRef{origin.IntentID, origin.IntentDigest}
	body, err := json.Marshal(ref)
	if err != nil {
		return m, err
	}
	intent, ok := client.state.LocalEndpointIntents[m.IntentID]
	if !ok || intent.Digest != m.IntentDigest {
		return m, errLocalEndpointIntentConflict
	}
	stepID := localEndpointStepID(m.IntentID, m.IntentDigest, "domain.origin")
	if step, ok := intent.Steps[stepID]; ok && (step.Operation != "local.domain.origin" || !bytes.Equal(step.Body, body)) {
		return m, errLocalEndpointIntentConflict
	}
	previous := cloneMachineNodeControlState(client.state)
	intent.Steps[stepID] = machineLocalEndpointStep{Operation: "local.domain.origin", Body: body}
	client.state.LocalEndpointIntents[m.IntentID] = intent
	if j.SessionToken == "" {
		current.State, current.StopCode, current.KnownLeaseExpiresAt = "STOPPED", "REUSED_CURRENT_MEMBER", j.LeaseExpiresAt
		client.state.ManagedLocalDomainLeases[id] = current
	} else if old.IntentID != "" {
		old.State, old.StopCode = "STOPPED", "EXPLICIT_NEW_ADMISSION"
		client.state.ManagedLocalDomainLeases[localEndpointStepID(old.IntentID, old.IntentDigest, "domain.join")] = old
	}
	if err = client.persistLocked(); err != nil {
		client.state = previous
		return m, err
	}
	return origin, nil
}

// Return original authenticated history without a fresh policy lookup or
// redispatch. The caller separately checks current authority before new work.
func (client *machineNodeControlClient) localDomainOriginalLocked(m machineManagedLocalDomainLease, step string, target any) error {
	i, ok := client.state.LocalEndpointIntents[m.IntentID]
	if !ok || i.Digest != m.IntentDigest {
		return errLocalEndpointIntentConflict
	}
	id := localEndpointStepID(m.IntentID, m.IntentDigest, step)
	s, ok := i.Steps[id]
	if !ok || !s.Settled {
		return errMachineNodeControlOutcomeUncertain
	}
	replayed, err := client.replayLocalEndpointLocked(localEndpointCallScope{m.IntentID, m.IntentDigest, id}, s.Operation, s.Body, target)
	if !replayed && err == nil {
		return errMachineNodeControlOutcomeUncertain
	}
	return err
}

func (client *machineNodeControlClient) stopLocalDomainLeasesForNative(harness, sid, cwd string) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	previous := cloneMachineNodeControlState(client.state)
	for id, m := range client.state.ManagedLocalDomainLeases {
		if m.Join.Runtime == harness && m.Join.NativeSessionID == sid && m.Join.Workspace == cwd && m.State != "STOPPED" {
			m.State, m.StopCode = "STOPPED", "LEFT"
			client.state.ManagedLocalDomainLeases[id] = m
		}
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (b *machineAgentJoinBridge) renewLocalDomainLeaseBatch(ctx context.Context) {
	b.managedLeaseMu.Lock()
	defer b.managedLeaseMu.Unlock()
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return
	}
	client.mu.Lock()
	var ids []string
	for id, m := range client.state.ManagedLocalDomainLeases {
		if m.State == "ACTIVE" || m.State == "RESERVED" {
			ids = append(ids, id)
		}
	}
	client.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	sort.Strings(ids)
	start := b.managedDomainNext % len(ids)
	count := len(ids)
	if count > managedPairLeaseBatch {
		count = managedPairLeaseBatch
	}
	for i := 0; i < count && ctx.Err() == nil; i++ {
		bounded, cancel := context.WithTimeout(ctx, managedPairLeaseRequestTimeout)
		b.renewLocalDomainLease(bounded, client, ids[(start+i)%len(ids)])
		cancel()
	}
	b.managedDomainNext = (start + count) % len(ids)
}

func (b *machineAgentJoinBridge) renewLocalDomainLease(ctx context.Context, client *machineNodeControlClient, id string) {
	client.mu.Lock()
	m, ok := client.state.ManagedLocalDomainLeases[id]
	var original wire.LocalDomainNodeJoinResult
	var completed wire.LocalDomainNodeKeyResult
	if !ok || (m.State != "ACTIVE" && m.State != "RESERVED") || client.localDomainOriginalLocked(m, "domain.join", &original) != nil || client.localDomainOriginalLocked(m, "domain.complete", &completed) != nil {
		client.mu.Unlock()
		return
	}
	scopeStep, scopeOK := client.state.LocalEndpointIntents[m.IntentID].Steps[localEndpointStepID(m.IntentID, m.IntentDigest, "domain.scope")]
	var scope nodeinbox.NativeContextScopeDecision
	if !scopeOK || decodeStrictBridgeJSON(scopeStep.Body, &scope) != nil || !scope.Accepted {
		client.mu.Unlock()
		return
	}
	client.mu.Unlock()
	state, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return
	}
	p, err := state.LocalDomainPolicyForGroup(ctx, completed.Description.Policy.GroupID)
	if err == nil {
		err = state.CheckLocalDomainPolicy(ctx, *p, time.Now().UTC())
	}
	if err == nil && (!reflect.DeepEqual(p.Policy, completed.Description.Policy) || !bytes.Equal(p.Proof, completed.Grant.PolicyProof) || completed.Member != completed.Grant.Member) {
		err = nodekeys.ErrLocalDomainPolicy
	}
	if err == nil {
		_, err = wire.VerifyLocalDomainEndpointKeyGrant(completed.Grant, p.Hub, p.Policy.OwnerID, p.Policy.OwnerPublic, time.Now().UTC())
	}
	frozen := managedPairDigest(m.Join, completed.Member, completed.Grant.PolicyProof, completed.Grant.NodeProof)
	if err == nil && m.FrozenDigest != "" && m.FrozenDigest != frozen {
		err = nodekeys.ErrLocalDomainPolicy
	}
	_ = state.Close()
	stop := false
	if err != nil {
		stop = errors.Is(err, nodekeys.ErrLocalDomainPolicy)
	} else {
		knownEnd := m.KnownLeaseExpiresAt
		if knownEnd == "" {
			knownEnd = original.LeaseExpiresAt
		}
		cold := !time.Now().Before(parseMachineNativePairTime(knownEnd))
		if cold || m.State == "RESERVED" {
			var current wire.LocalDomainDescription
			err = client.call(ctx, b.nodeToken, wire.OperationLocalDomainNodeDescribe, wire.LocalDomainNodeDescribe{ContractRevision: wire.LocalDomainContractRevision, Selection: m.Join.Selection, LocalUserScope: m.Join.LocalUserScope}, &current)
			if err == nil && (current.State != wire.LocalDomainActive || !reflect.DeepEqual(current.Policy, p.Policy) || !bytes.Equal(current.PolicyProof, p.Proof)) {
				err = nodekeys.ErrLocalDomainConflict
			}
		}
		if err == nil && cold {
			var resumed wire.LocalDomainNodeJoinResult
			// Only cold recovery needs a fresh encrypted operation. Ordinary
			// heartbeats must not grow a permanent mutation receipt per tick.
			// The original AttemptID permanently fences any terminal member.
			err = client.call(ctx, b.nodeToken, wire.OperationLocalDomainNodeJoin, m.Join, &resumed)
			if err == nil && (resumed.Member != completed.Member || resumed.SessionToken != "" || !resumed.Reused) {
				err = nodekeys.ErrLocalDomainConflict
			}
		}
		if err == nil {
			var actor fabric.Actor
			raw, e := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/heartbeat", nil, "CicadaSession "+original.SessionToken, p.Policy.GroupID)
			if e != nil {
				err = e
			} else if json.Unmarshal(raw, &actor) != nil || actor.EndpointID != completed.Member.EndpointID || actor.BindingID != completed.Member.BindingID || actor.BindingEpoch != completed.Member.BindingEpoch {
				err = nodekeys.ErrLocalDomainConflict
			} else {
				original.LeaseExpiresAt = actor.LeaseExpiresAt
			}
		}
		stop = errors.Is(err, errLocalDomainNodeRejected) || errors.Is(err, nodekeys.ErrLocalDomainConflict)
	}
	if ctx.Err() != nil && !stop {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	current, ok := client.state.ManagedLocalDomainLeases[id]
	if !ok || current.State != m.State || current.FrozenDigest != m.FrozenDigest {
		return
	}
	previous := cloneMachineNodeControlState(client.state)
	if stop {
		current.State, current.StopCode = "STOPPED", "CURRENT_AUTHORITY_LOST"
	} else if err == nil {
		current.State, current.FrozenDigest = "ACTIVE", frozen
		current.KnownLeaseExpiresAt = original.LeaseExpiresAt
	} else {
		return
	}
	client.state.ManagedLocalDomainLeases[id] = current
	if client.persistLocked() != nil {
		client.state = previous
	}
}

func (client *machineNodeControlClient) localDomainHub() wire.HubIdentity {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.LocalDomainReport == nil {
		return wire.HubIdentity{}
	}
	return client.state.LocalDomainReport.Hub
}
