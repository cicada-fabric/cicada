package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localDomainOriginalRef struct {
	IntentID string `json:"intent_id"`
	Digest   string `json:"digest"`
}

func (b *machineAgentJoinBridge) localDomainEndpointOperation(q localEndpointRequest) (*localEndpointResult, error) {
	origin, err := normalizeMCPAPIOrigin(q.APIOrigin)
	expected, e := normalizeMCPAPIOrigin(b.baseURL)
	if err != nil || e != nil || origin != expected || origin != q.APIOrigin {
		return nil, nodewire.ErrEndpointContext
	}
	b.endpointMu.Lock()
	defer b.endpointMu.Unlock()
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, err
	}
	digest, err := client.retainLocalEndpointIntent(q, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	binding := client.approvedBinding()
	r := &localEndpointResult{RequestID: q.RequestID, IntentDigest: digest, HubID: binding.HubID, NodeID: b.nodeID, Operation: q.Operation, State: "UNKNOWN"}
	// Settle the sealed original before any current-policy lookup or native
	// record verification. An original selector never follows a newer policy.
	if err = client.recoverPending(b.ctx, b.nodeToken); err != nil && !errors.Is(err, errLocalDomainNodeRejected) && !errors.Is(err, errLocalEndpointReceiptExpired) {
		return r, err
	}
	if _, refused, e := client.localEndpointStep(q.RequestID, digest, "domain.refused"); e != nil {
		return r, e
	} else if refused {
		r.State = "REFUSED"
		return r, errLocalDomainNodeRejected
	}
	ref := localDomainOriginalRef{q.RequestID, digest}
	if step, ok, e := client.localEndpointStep(q.RequestID, digest, "domain.origin"); e != nil {
		return r, e
	} else if ok {
		if decodeStrictBridgeJSON(step.Body, &ref) != nil {
			return r, errLocalEndpointIntentConflict
		}
	}
	leaseID := localEndpointStepID(ref.IntentID, ref.Digest, "domain.join")
	client.mu.Lock()
	managed, retained := client.state.ManagedLocalDomainLeases[leaseID]
	client.mu.Unlock()
	var original wire.LocalDomainNodeJoinResult
	var completed wire.LocalDomainNodeKeyResult
	var decision nodeinbox.NativeContextScopeDecision
	if retained {
		if managed.IntentID != ref.IntentID || managed.IntentDigest != ref.Digest || managed.Join.Selection != q.LocalDomain || managed.Join.NativeSessionID != q.NativeSessionID || managed.Join.Workspace != q.Workspace {
			return r, errLocalEndpointIntentConflict
		}
		client.mu.Lock()
		joinErr := client.localDomainOriginalLocked(managed, "domain.join", &original)
		completeErr := client.localDomainOriginalLocked(managed, "domain.complete", &completed)
		client.mu.Unlock()
		scopeStep, hasScope, scopeErr := client.localEndpointStep(ref.IntentID, ref.Digest, "domain.scope")
		if joinErr == nil && completeErr == nil && scopeErr == nil && hasScope && decodeStrictBridgeJSON(scopeStep.Body, &decision) == nil && decision.Accepted {
			if err = client.verifyLocalDomainHistory(b.ctx, managed, original, completed); err != nil {
				return r, err
			}
			if managed.State == "RESERVED" {
				// The Hub receipt and accepted scope survived a crash before
				// local activation. Recover only this original member/attempt.
				b.renewLocalDomainLease(b.ctx, client, leaseID)
				client.mu.Lock()
				managed = client.state.ManagedLocalDomainLeases[leaseID]
				client.mu.Unlock()
			}
			// Return authenticated original history even after revocation. New
			// calls and native delivery still require their separate fresh Guard.
			p := nodekeys.LocalDomainPolicy{Policy: completed.Description.Policy, Proof: completed.Description.PolicyProof}
			joined := localDomainFabricJoin(original, p, fabricCardFromDomain(original, completed))
			if managed.KnownLeaseExpiresAt != "" {
				joined.LeaseExpiresAt = managed.KnownLeaseExpiresAt
			}
			r.Registration, r.Join, r.LocalDomain, r.NativeContextScope = &original.Endpoint, joined, &completed, &decision
			r.State = "COMPLETED"
			return r, nil
		}
	}
	// New work uses only one exact previously verified native record. This is
	// bounded private metadata, never a scan of the user's session history.
	path := ""
	if retained {
		path = managed.TranscriptPath
	} else if record, ok := b.codexContexts.verifiedNative(q.NativeSessionID, q.Workspace, time.Now()); ok && record.Context.VerificationProfile == LocalCodexContextProfileDomain && record.Context.LocalDomain == q.LocalDomain {
		path = record.TranscriptPath
	}
	if path == "" {
		if fenced, e := client.fenceUncompletedLocalDomain(q.RequestID, digest); e != nil {
			return r, e
		} else if fenced {
			r.State = "REFUSED"
			return r, errLocalDomainNodeRejected
		}
		return r, errLocalCodexContext
	}
	if cwd, e := filepath.EvalSymlinks(q.Workspace); e != nil || cwd != q.Workspace {
		return r, nodewire.ErrEndpointContext
	}
	p, err := client.currentLocalDomainPolicy(b.ctx, b.nodeToken, time.Now().UTC())
	if err != nil || p == nil {
		if fenced, e := client.fenceUncompletedLocalDomain(q.RequestID, digest); e != nil {
			return r, e
		} else if fenced {
			r.State = "REFUSED"
			return r, errLocalDomainNodeRejected
		}
		return r, nodekeys.ErrLocalDomainPolicy
	}
	selection, err := wire.LocalDomainSelectionForPolicy(p.Policy)
	if err != nil || selection != q.LocalDomain {
		if fenced, e := client.fenceUncompletedLocalDomain(q.RequestID, digest); e != nil {
			return r, e
		} else if fenced {
			r.State = "REFUSED"
			return r, errLocalDomainNodeRejected
		}
		return r, nodekeys.ErrLocalDomainPolicy
	}
	if err = verifyCodexContextTranscriptProfile(path, q.NativeSessionID, q.Workspace, true); err != nil {
		return r, err
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return r, err
	}
	defer state.Close()
	if err = state.CheckLocalDomainPolicy(b.ctx, *p, time.Now().UTC()); err != nil {
		return r, err
	}
	var join wire.LocalDomainNodeJoin
	if step, ok, e := client.localEndpointStep(q.RequestID, digest, "domain.join"); e != nil {
		return r, e
	} else if ok {
		if decodeStrictBridgeJSON(step.Body, &join) != nil {
			return r, errLocalEndpointIntentConflict
		}
	} else {
		// The immutable local command fixes this attempt as well as its scope.
		attempt := localEndpointStepID(q.RequestID, digest, "domain.attempt")
		join = wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: q.LocalDomain, LocalUserScope: p.Policy.LocalUserScope, AttemptID: attempt[len("ncrpc_"):], Runtime: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, EndpointName: q.Name}
	}
	managed, err = client.reserveLocalDomainLease(q, digest, path, join)
	if err != nil {
		return r, err
	}
	if err = client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "domain.join", wire.OperationLocalDomainNodeJoin, join, &original); err != nil {
		return r, err
	}
	if err = validateLocalDomainZeroJoin(join, original, *p); err != nil {
		return r, err
	}
	managed, err = client.resolveLocalDomainLease(managed, original)
	if err != nil {
		return r, err
	}
	ref = localDomainOriginalRef{managed.IntentID, managed.IntentDigest}
	if original.SessionToken == "" {
		// Another explicit current registration may refer to the same active
		// member. Its original token remains in the first encrypted receipt.
		client.mu.Lock()
		var first wire.LocalDomainNodeJoinResult
		err = client.localDomainOriginalLocked(managed, "domain.join", &first)
		if err == nil {
			err = client.localDomainOriginalLocked(managed, "domain.complete", &completed)
		}
		client.mu.Unlock()
		if err != nil || original.Member != completed.Member || first.SessionToken == "" {
			return r, errMachineNodeControlOutcomeUncertain
		}
		original.SessionToken = first.SessionToken
		if _, err = wire.VerifyLocalDomainEndpointKeyGrant(completed.Grant, p.Hub, p.Policy.OwnerID, p.Policy.OwnerPublic, time.Now().UTC()); err != nil {
			return r, err
		}
	} else {
		candidate, e := b.publishLocalDomainCandidate(state, *p, original)
		if e != nil {
			return r, e
		}
		var challenge wire.LocalDomainKeyChallenge
		prepare := wire.LocalDomainNodeKeyPrepare{ContractRevision: wire.LocalDomainContractRevision, Selection: q.LocalDomain, MemberID: original.Member.MemberID, ExpectedRevision: original.Member.Revision}
		if err = client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "domain.prepare", wire.OperationLocalDomainNodeKeyPrepare, prepare, &challenge); err != nil {
			return r, err
		}
		if err = validateLocalDomainKeyChallenge(*p, original.Member, candidate, challenge, time.Now().UTC()); err != nil {
			return r, err
		}
		// The local scope decision precedes granting communication rights.
		joined := localDomainFabricJoin(original, *p, fabricCardFromDomain(original, wire.LocalDomainNodeKeyResult{}))
		scope, e := recordMachineNativeContextMetadata(b.ctx, q.Harness, q.NativeSessionID, original.Member.EndpointID, original.Member.BindingID, original.Member.BindingEpoch, joined.NativeContextScope)
		if e != nil || scope == nil || !scope.Accepted {
			if e != nil {
				return r, e
			}
			return r, nodekeys.ErrLocalDomainPolicy
		}
		decision = *scope
		if _, err = client.prepareLocalEndpointStep(ref.IntentID, ref.Digest, "domain.scope", "local.domain.scope", decision); err != nil {
			return r, err
		}
		var complete wire.LocalDomainNodeKeyComplete
		if step, ok, e := client.localEndpointStep(q.RequestID, digest, "domain.complete"); e != nil {
			return r, e
		} else if ok {
			if decodeStrictBridgeJSON(step.Body, &complete) != nil {
				return r, errLocalEndpointIntentConflict
			}
		} else {
			if err = state.CheckLocalDomainPolicy(b.ctx, *p, time.Now().UTC()); err != nil {
				return r, err
			}
			proof, e := e2ee.SignLocalDomainEndpointKey(client.identity, p.Policy, challenge.Claims)
			if e != nil {
				return r, e
			}
			complete = wire.LocalDomainNodeKeyComplete{ContractRevision: wire.LocalDomainContractRevision, Selection: q.LocalDomain, MemberID: original.Member.MemberID, ExpectedRevision: original.Member.Revision, ChallengeID: challenge.ChallengeID, NodeProof: proof}
		}
		if err = client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "domain.complete", wire.OperationLocalDomainNodeKeyComplete, complete, &completed); err != nil {
			return r, err
		}
		if completed.Member != challenge.Member || completed.Grant.Member != challenge.Member || !bytes.Equal(completed.Grant.NodeProof, complete.NodeProof) || !bytes.Equal(completed.Grant.PolicyProof, p.Proof) {
			return r, nodekeys.ErrLocalDomainConflict
		}
		if err = state.RememberLocalDomainGrant(b.ctx, completed.Grant, time.Now().UTC()); err != nil {
			return r, err
		}
	}
	if !decision.Accepted {
		scope, e := recordMachineNativeContextMetadata(b.ctx, q.Harness, q.NativeSessionID, original.Member.EndpointID, original.Member.BindingID, original.Member.BindingEpoch, localDomainFabricJoin(original, *p, fabricCardFromDomain(original, completed)).NativeContextScope)
		if e != nil {
			return r, e
		}
		if scope == nil || !scope.Accepted {
			return r, nodekeys.ErrLocalDomainPolicy
		}
		decision = *scope
	}
	card, err := b.verifyCurrentMCPBinding(original.SessionToken, p.Policy.GroupID)
	if err != nil || card.EndpointID != completed.Member.EndpointID || card.BindingID != completed.Member.BindingID || card.BindingEpoch != completed.Member.BindingEpoch {
		return r, nodekeys.ErrLocalDomainPolicy
	}
	joined := localDomainFabricJoin(original, *p, card)
	if err = client.activateLocalDomainLease(managed, original, completed); err != nil {
		return r, err
	}
	r.Registration, r.Join, r.LocalDomain, r.NativeContextScope = &original.Endpoint, joined, &completed, &decision
	r.State = "COMPLETED"
	select {
	case b.managedLeaseWake <- struct{}{}:
	default:
	}
	return r, nil
}

// Historical transport authentication is not proof that a returned grant was
// checked before a crash. Recheck the entire original chain and exact signed
// request using the immutable already-adopted policy, without reviving current
// authority or requiring a currently live App/report/policy lease.
func (client *machineNodeControlClient) verifyLocalDomainHistory(ctx context.Context, m machineManagedLocalDomainLease, j wire.LocalDomainNodeJoinResult, completed wire.LocalDomainNodeKeyResult) error {
	state, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(client.stateDir, client.nodeID))
	if err != nil {
		return err
	}
	p, err := state.LocalDomainPolicyForGroup(ctx, completed.Grant.Manifest.GroupID)
	_ = state.Close()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(j.Description.Policy, p.Policy) || !reflect.DeepEqual(completed.Description.Policy, p.Policy) || !bytes.Equal(p.Proof, completed.Grant.PolicyProof) || !bytes.Equal(p.Proof, completed.Description.PolicyProof) || completed.Member != completed.Grant.Member || j.Member.MemberID != completed.Member.MemberID || j.Member.BindingID != completed.Member.BindingID || j.Member.BindingEpoch != completed.Member.BindingEpoch || j.Member.NativeSessionID != m.Join.NativeSessionID || j.Member.Workspace != m.Join.Workspace {
		return nodekeys.ErrLocalDomainConflict
	}
	client.mu.Lock()
	var prepared wire.LocalDomainKeyChallenge
	err = client.localDomainOriginalLocked(m, "domain.prepare", &prepared)
	step, ok := client.state.LocalEndpointIntents[m.IntentID].Steps[localEndpointStepID(m.IntentID, m.IntentDigest, "domain.complete")]
	client.mu.Unlock()
	var request wire.LocalDomainNodeKeyComplete
	if err != nil || !ok || decodeStrictBridgeJSON(step.Body, &request) != nil || !bytes.Equal(request.NodeProof, completed.Grant.NodeProof) || prepared.Member != completed.Member || !reflect.DeepEqual(prepared.Manifest, completed.Grant.Manifest) {
		return nodekeys.ErrLocalDomainConflict
	}
	at := parseMachineNativePairTime(completed.Grant.Manifest.IssuedAt)
	if at.IsZero() {
		return nodekeys.ErrLocalDomainConflict
	}
	_, err = wire.VerifyLocalDomainEndpointKeyGrant(completed.Grant, p.Hub, p.Policy.OwnerID, p.Policy.OwnerPublic, at)
	return err
}

// A completed key grant is never relabeled as no-effect. Only a known absence
// or an authenticated rejection of key_complete can fence an unfinished local
// admission; unknown sealed packets remain pending and keep their originals.
func (client *machineNodeControlClient) fenceUncompletedLocalDomain(id, digest string) (bool, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	intent, ok := client.state.LocalEndpointIntents[id]
	if !ok || intent.Digest != digest {
		return false, errLocalEndpointIntentConflict
	}
	if client.state.PendingLocalEndpointIntentID == id || client.state.PendingOperationID == localEndpointStepID(id, digest, "domain.complete") {
		return false, nil
	}
	for _, step := range intent.Steps {
		if !step.Settled && len(step.RequestPacket) > 0 {
			return false, nil
		}
	}
	completeID := localEndpointStepID(id, digest, "domain.complete")
	if step, ok := intent.Steps[completeID]; ok && len(step.RequestPacket) > 0 {
		replayed, err := client.replayLocalEndpointLocked(localEndpointCallScope{id, digest, completeID}, step.Operation, step.Body, nil)
		if !replayed || err == nil {
			return false, nil
		}
		if !errors.Is(err, errLocalDomainNodeRejected) {
			return false, err
		}
	}
	previous := cloneMachineNodeControlState(client.state)
	intent.Steps[localEndpointStepID(id, digest, "domain.refused")] = machineLocalEndpointStep{Operation: "local.domain.refused", Body: []byte(`{"state":"NO_COMMUNICATION_ADMISSION"}`)}
	client.state.LocalEndpointIntents[id] = intent
	leaseID := localEndpointStepID(id, digest, "domain.join")
	if m, ok := client.state.ManagedLocalDomainLeases[leaseID]; ok && m.State == "RESERVED" {
		m.State, m.StopCode = "STOPPED", "ADMISSION_NOT_COMPLETED"
		client.state.ManagedLocalDomainLeases[leaseID] = m
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return false, err
	}
	return true, nil
}

func (client *machineNodeControlClient) activateLocalDomainLease(m machineManagedLocalDomainLease, j wire.LocalDomainNodeJoinResult, completed wire.LocalDomainNodeKeyResult) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	id := localEndpointStepID(m.IntentID, m.IntentDigest, "domain.join")
	current, ok := client.state.ManagedLocalDomainLeases[id]
	if !ok || current.State == "STOPPED" || current.Join != m.Join {
		return errManagedPairLeaseStopped
	}
	frozen := managedPairDigest(current.Join, completed.Member, completed.Grant.PolicyProof, completed.Grant.NodeProof)
	if current.FrozenDigest != "" && current.FrozenDigest != frozen {
		return nodekeys.ErrLocalDomainConflict
	}
	previous := cloneMachineNodeControlState(client.state)
	current.State, current.FrozenDigest, current.KnownLeaseExpiresAt = "ACTIVE", frozen, j.LeaseExpiresAt
	client.state.ManagedLocalDomainLeases[id] = current
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

// The temporary card is used only for assembling exact public tuple metadata.
// Successful admission replaces it with the authenticated current self card.
func fabricCardFromDomain(j wire.LocalDomainNodeJoinResult, completed wire.LocalDomainNodeKeyResult) fabric.NetworkCard {
	m := j.Member
	return fabric.NetworkCard{EndpointID: m.EndpointID, PrincipalID: m.PrincipalID, GroupID: j.Description.Policy.GroupID, NodeID: m.NodeID, NativeSessionID: m.NativeSessionID, Workspace: m.Workspace, Harness: m.Runtime, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, Name: j.Endpoint.Name, Status: j.Endpoint.Presence}
}
