package main

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type endpointGroupsOperatorContextProof struct {
	ContextTicketID        string `json:"context_ticket_id,omitempty"`
	ContextConnectionNonce string `json:"context_connection_nonce,omitempty"`
}

func (b *machineAgentJoinBridge) endpointGroupsHistoricalDomainIntent(q localEndpointRequest) bool {
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return false
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || q.Operation != "endpoint_register" || q.LocalDomainVersion != 1 || r.IntentID != q.RequestID {
		return false
	}
	return codexOperatorDigest(q, false) == r.IntentDigest
}

func (a *localCodexContextAuthority) consumeEndpointGroupsOperator(q localEndpointRequest, invocation *endpointGroupsOperatorContextProof, now time.Time) error {
	arguments := map[string]any{"operation": q.Operation, "name": q.Name, "pair_label": q.PairLabel, "slot": q.Slot}
	proof := q.endpointGroupsOperatorContextProof
	if invocation != nil {
		proof = *invocation
		arguments["original_request_id"] = q.RequestID
		arguments["original_intent_digest"] = codexOperatorDigest(q, false)
	}
	digest, err := codexArgumentsDigest(arguments)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.operatorIntents == nil {
		a.operatorIntents = map[string]string{}
	}
	for id := range a.operatorIntents {
		r, ok := a.consumed[id]
		if !ok || !now.Before(r.Expires) {
			delete(a.operatorIntents, id)
		}
	}
	r, ok := a.consumed[proof.ContextTicketID]
	if !ok || !now.Before(r.Expires) || r.Nonce != proof.ContextConnectionNonce || r.Origin != q.APIOrigin || r.Tool != codexOperatorContextTool(q.Operation) || r.Arguments != digest || r.Context.NativeSessionID != q.NativeSessionID || r.Context.Workspace != q.Workspace {
		return errCodexMCPContext
	}
	binding, e := codexContextBinding(r.Context)
	if e != nil || binding.codexEndpointGroupsBinding != q.codexEndpointGroupsBinding {
		return errCodexMCPContext
	}
	if request, used := a.operatorIntents[proof.ContextTicketID]; used && request != q.RequestID {
		return errCodexMCPContext
	}
	a.operatorIntents[proof.ContextTicketID] = q.RequestID
	return nil
}

func (b *machineAgentJoinBridge) endpointGroupsOperatorRegister(q localEndpointRequest) (*localEndpointResult, error) {
	invocation := q.InvocationProof
	q.InvocationProof = nil
	if (q.Operation != "endpoint_register" && q.Operation != "endpoint_leave") || q.APIOrigin != b.baseURL || q.EndpointGroupsVersion != 1 {
		return nil, errEndpointGroupsRegistration
	}
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	freshOriginal := false
	c.mu.Lock()
	_, known := c.state.LocalEndpointIntents[q.RequestID]
	c.mu.Unlock()
	issued, _ := localEndpointIssuedAt(q)
	if !known && !now.Before(issued.Add(localEndpointIntentTTL)) && invocation != nil {
		if err := b.codexContexts.consumeEndpointGroupsOperator(q, invocation, now); err != nil {
			return nil, err
		}
		freshOriginal = true
	}
	digest, err := c.retainLocalEndpointIntentAuthenticated(q, now, freshOriginal)
	if err != nil {
		return nil, err
	}
	result := &localEndpointResult{RequestID: q.RequestID, IntentDigest: digest, HubID: c.approvedBinding().HubID, NodeID: b.nodeID, Operation: q.Operation, State: "UNKNOWN"}
	resultStep := "groups.operator." + q.Operation
	if old, ok, err := c.localEndpointStep(q.RequestID, digest, resultStep); err != nil {
		return result, err
	} else if ok {
		if decodeStrictBridgeJSON(old.Body, result) != nil {
			return nil, errLocalEndpointIntentConflict
		}
		return result, nil
	}
	if old, ok, err := c.localEndpointStep(q.RequestID, digest, "groups.operator.verified"); err != nil {
		return result, err
	} else if ok {
		var original localEndpointRequest
		if decodeStrictBridgeJSON(old.Body, &original) != nil || original != q {
			return result, errLocalEndpointIntentConflict
		}
	} else {
		if err := b.codexContexts.consumeEndpointGroupsOperator(q, invocation, time.Now()); err != nil {
			return result, err
		}
		if err := c.rememberEndpointGroupsOperatorVerified(q, digest); err != nil {
			return result, err
		}
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || r.Anchor.RegistrationDigest != q.RegistrationDigest || r.Anchor.RegistrationRevision != q.RegistrationRevision || r.Anchor.BindingID != q.RegistrationBindingID || r.Anchor.BindingEpoch != q.RegistrationBindingEpoch || r.Anchor.NodeKeyEpoch != q.RegistrationNodeKeyEpoch {
		return result, errEndpointGroupsRegistration
	}
	_, original, _, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return result, err
	}
	description := wire.EndpointGroupsNodeDescribeResult{ContractRevision: wire.OwnerEndpointGroupsContractRevision, Registration: r.Anchor}
	registration := original.Endpoint
	if q.Operation == "endpoint_leave" {
		// Local stop is durable before acknowledging. Hub presence remains a
		// lease/snapshot fact; no Group config, deny, Root or native Runtime changes.
		if !r.LocallyOffline {
			if r.LocalAccessRevision >= 1<<63-1 {
				return result, errLocalEndpointHistoryFull
			}
			r.LocalAccessRevision++
		}
		r.LocallyOffline = true
		if err := c.saveEndpointGroupsRegistration(r); err != nil {
			return result, err
		}
		registration.Presence = "left"
		result.EndpointGroupsLocalOffline = true
	} else {
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancel()
		r, description, err = b.describeEndpointGroups(ctx, c, r, "", 64)
		if err != nil {
			return result, err
		}
		r.LocallyOffline = false
		r, err = b.renewEndpointGroupsRegistration(ctx, c, r)
		if err != nil {
			return result, err
		}
	}
	result.Registration = &registration
	description.Registration = r.Anchor
	result.EndpointGroups = &description
	result.State = "COMPLETED"
	if _, err := c.prepareLocalEndpointStep(q.RequestID, digest, resultStep, "local.endpoint_groups.operator_result", result); err != nil {
		return result, err
	}
	return result, nil
}

// The caller has consumed a fresh proof for the retained original. Persisting
// that acceptance has no age exception for any other operation or request.
func (c *machineNodeControlClient) rememberEndpointGroupsOperatorVerified(q localEndpointRequest, digest string) error {
	q.InvocationProof = nil
	if q.EndpointGroupsVersion != 1 || codexOperatorDigest(q, false) != digest {
		return errLocalEndpointIntentConflict
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	intent, ok := c.state.LocalEndpointIntents[q.RequestID]
	if !ok || intent.Digest != digest {
		return errLocalEndpointIntentConflict
	}
	id := localEndpointStepID(q.RequestID, digest, "groups.operator.verified")
	if old, ok := intent.Steps[id]; ok {
		if old.Operation != "local.endpoint_groups.operator_verified" || !bytes.Equal(old.Body, raw) {
			return errLocalEndpointIntentConflict
		}
		return nil
	}
	previous := cloneMachineNodeControlState(c.state)
	if intent.Steps == nil {
		intent.Steps = map[string]machineLocalEndpointStep{}
	}
	intent.Steps[id] = machineLocalEndpointStep{Operation: "local.endpoint_groups.operator_verified", Body: raw}
	c.state.LocalEndpointIntents[q.RequestID] = intent
	if err := c.localEndpointCapacityLocked(); err != nil {
		c.state = previous
		return err
	}
	if err := c.persistLocked(); err != nil {
		c.state = previous
		return err
	}
	return nil
}

func (c *machineNodeControlClient) endpointGroupsLocalOperatorRetainedLocked(id string) bool {
	intent, ok := c.state.LocalEndpointIntents[id]
	if !ok {
		return false
	}
	step, ok := intent.Steps[localEndpointStepID(id, intent.Digest, "groups.operator.verified")]
	return ok && step.Operation == "local.endpoint_groups.operator_verified" && len(step.Body) > 0
}

func validateEndpointGroupsOperatorResult(p codexOperatorPending, r *localEndpointResult, responseErr error) error {
	q := p.Request
	if (q.Operation != "endpoint_register" && q.Operation != "endpoint_leave") || r.Join != nil || r.LocalDomain != nil || r.Directory != nil || r.Pairs != nil || r.NativeContextScope != nil {
		return errCodexOperatorIntentResponse
	}
	if r.State != "COMPLETED" || responseErr != nil || r.Registration == nil || r.EndpointGroups == nil {
		return errCodexOperatorIntentResponse
	}
	if r.EndpointGroupsLocalOffline != (q.Operation == "endpoint_leave") || q.Operation == "endpoint_leave" && r.Registration.Presence != "left" {
		return errCodexOperatorIntentResponse
	}
	a := r.EndpointGroups.Registration
	if a.Profile != LocalCodexContextProfileEndpointGroups || a.RegistrationSource != wire.EndpointGroupsRegistrationSource || a.Registration.HubID != r.HubID || a.Registration.NodeID != p.NodeID || a.Registration.Harness != q.Harness || a.Registration.NativeSessionID != q.NativeSessionID || a.Registration.Workspace != q.Workspace || a.RegistrationDigest != q.RegistrationDigest || a.RegistrationRevision != q.RegistrationRevision || a.BindingID != q.RegistrationBindingID || a.BindingEpoch != q.RegistrationBindingEpoch || a.NodeKeyEpoch != q.RegistrationNodeKeyEpoch || r.Registration.EndpointID != a.Registration.EndpointID || r.Registration.Workspace != q.Workspace || !localContextHex(r.Registration.StateDigest, 64) {
		return errCodexOperatorIntentResponse
	}
	encoded, err := json.Marshal(r.EndpointGroups)
	if err != nil || len(encoded) > wire.MaxOwnerEndpointGroupsPageBytes {
		return errCodexOperatorIntentResponse
	}
	return nil
}
