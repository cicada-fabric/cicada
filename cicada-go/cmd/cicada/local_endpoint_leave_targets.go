package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localEndpointLeaveTargets struct {
	Pairs   []string `json:"pairs"`
	Domains []string `json:"domains"`
}

func (client *machineNodeControlClient) prepareLocalLeaveTargets(q localEndpointRequest, digest string) (localEndpointLeaveTargets, error) {
	var targets localEndpointLeaveTargets
	step, exists, err := client.localEndpointStep(q.RequestID, digest, "leave.targets")
	if err != nil {
		return targets, err
	}
	if exists {
		if decodeStrictBridgeJSON(step.Body, &targets) != nil {
			return targets, errLocalEndpointIntentConflict
		}
		return targets, nil
	}
	client.mu.Lock()
	for id, m := range client.state.ManagedPairLeases {
		if m.Join.Runtime == q.Harness && m.Join.NativeSessionID == q.NativeSessionID && m.Join.Workspace == q.Workspace && m.State != "STOPPED" {
			targets.Pairs = append(targets.Pairs, id)
		}
	}
	for id, m := range client.state.ManagedLocalDomainLeases {
		if m.Join.Runtime == q.Harness && m.Join.NativeSessionID == q.NativeSessionID && m.Join.Workspace == q.Workspace && m.State != "STOPPED" {
			targets.Domains = append(targets.Domains, id)
		}
	}
	client.mu.Unlock()
	sort.Strings(targets.Pairs)
	sort.Strings(targets.Domains)
	_, err = client.prepareLocalEndpointStep(q.RequestID, digest, "leave.targets", "local.leave.targets", targets)
	return targets, err
}

func (client *machineNodeControlClient) stopLocalLeaveTargets(targets localEndpointLeaveTargets) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	previous := cloneMachineNodeControlState(client.state)
	for _, id := range targets.Pairs {
		if m, ok := client.state.ManagedPairLeases[id]; ok && m.State != "STOPPED" {
			m.State, m.StopCode = "STOPPED", "EXPLICIT_LEAVE"
			client.state.ManagedPairLeases[id] = m
		}
	}
	for _, id := range targets.Domains {
		if m, ok := client.state.ManagedLocalDomainLeases[id]; ok && m.State != "STOPPED" {
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

// Exact historical Leave recovery precedes record/current-policy checks and
// stops only the original snapshotted lease IDs, never a later same-SID Join.
func (b *machineAgentJoinBridge) replaySettledLocalLeave(q localEndpointRequest) (*localEndpointResult, bool, error) {
	if q.Operation != "endpoint_leave" {
		return nil, false, nil
	}
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, false, nil
	}
	raw, _ := json.Marshal(q)
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	step, ok, err := client.localEndpointStep(q.RequestID, digest, "leave")
	if err != nil || !ok {
		return nil, false, nil
	}
	client.mu.Lock()
	pending := client.state.PendingLocalEndpointIntentID == q.RequestID
	client.mu.Unlock()
	if !step.Settled && len(step.RequestPacket) == 0 && !pending {
		return nil, false, nil
	}
	b.endpointMu.Lock()
	defer b.endpointMu.Unlock()
	binding := client.approvedBinding()
	r := &localEndpointResult{RequestID: q.RequestID, IntentDigest: digest, HubID: binding.HubID, NodeID: b.nodeID, Operation: q.Operation, State: "UNKNOWN"}
	if !step.Settled {
		if err = client.recoverPending(b.ctx, b.nodeToken); err != nil {
			return r, true, err
		}
		step, ok, err = client.localEndpointStep(q.RequestID, digest, "leave")
		if err != nil || !ok || !step.Settled {
			return r, true, errMachineNodeControlOutcomeUncertain
		}
	}
	var registration nodewire.EndpointRegistrationResult
	client.mu.Lock()
	replayed, err := client.replayLocalEndpointLocked(localEndpointCallScope{q.RequestID, digest, localEndpointStepID(q.RequestID, digest, "leave")}, step.Operation, step.Body, &registration)
	client.mu.Unlock()
	if !replayed {
		return nil, false, nil
	}
	r.Registration, r.State = &registration, "COMPLETED"
	if err != nil {
		r.State = "REFUSED"
		return r, true, err
	}
	targets, exists, e := client.localEndpointStep(q.RequestID, digest, "leave.targets")
	if e != nil {
		return r, true, e
	}
	if exists {
		var original localEndpointLeaveTargets
		if decodeStrictBridgeJSON(targets.Body, &original) != nil {
			return r, true, errLocalEndpointIntentConflict
		}
		if e = client.stopLocalLeaveTargets(original); e != nil {
			return r, true, e
		}
	}
	return r, true, nil
}
