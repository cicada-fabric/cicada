package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localEndpointRequest struct {
	Version            int                       `json:"version"`
	Operation          string                    `json:"operation"`
	RequestID          string                    `json:"request_id"`
	IssuedAt           string                    `json:"issued_at"`
	APIOrigin          string                    `json:"api_origin"`
	Harness            string                    `json:"harness,omitempty"`
	NativeSessionID    string                    `json:"native_session_id,omitempty"`
	Workspace          string                    `json:"workspace,omitempty"`
	Name               string                    `json:"name,omitempty"`
	PairLabel          string                    `json:"pair_label,omitempty"`
	Slot               string                    `json:"slot,omitempty"`
	Cursor             string                    `json:"cursor,omitempty"`
	Limit              int                       `json:"limit,omitempty"`
	LocalDomainVersion int                       `json:"local_domain_version,omitempty"`
	LocalDomain        wire.LocalDomainSelection `json:"local_domain,omitzero"`
}

type localEndpointResult struct {
	RequestID          string                                `json:"request_id"`
	IntentDigest       string                                `json:"intent_digest"`
	HubID              string                                `json:"hub_id"`
	NodeID             string                                `json:"node_id"`
	Operation          string                                `json:"operation"`
	State              string                                `json:"state"`
	Registration       *nodewire.EndpointRegistrationResult  `json:"registration,omitempty"`
	Directory          *nodewire.EndpointDirectoryResult     `json:"directory,omitempty"`
	Pairs              *nodewire.AvailableNativePairs        `json:"pairs,omitempty"`
	Join               *fabric.JoinResult                    `json:"join,omitempty"`
	NativeContextScope *nodeinbox.NativeContextScopeDecision `json:"native_context_scope,omitempty"`
	LocalDomain        *wire.LocalDomainNodeKeyResult        `json:"local_domain,omitempty"`
}

func localEndpointOperation(operation string) bool {
	return localEndpointMutation(operation) || operation == "endpoint_directory" || operation == "native_pair_available"
}

func (q localEndpointRequest) validate() error {
	if q.Version != localJoinProtocolVersion || !localEndpointOperation(q.Operation) || !localContextHex(q.RequestID, 32) || !localContextText(q.IssuedAt, 64) {
		return nodewire.ErrEndpointContext
	}
	if q.LocalDomain != (wire.LocalDomainSelection{}) {
		if q.Operation != "endpoint_register" || q.LocalDomainVersion != 1 || wire.ValidateLocalDomainSelection(q.LocalDomain) != nil {
			return nodewire.ErrEndpointContext
		}
	} else if q.LocalDomainVersion != 0 {
		return nodewire.ErrEndpointContext
	}
	if _, err := localEndpointIssuedAt(q); err != nil {
		return err
	}
	if q.Operation != "endpoint_directory" && (q.Cursor != "" || q.Limit != 0) {
		return nodewire.ErrEndpointContext
	}
	if q.Operation != "endpoint_register" && q.Name != "" {
		return nodewire.ErrEndpointContext
	}
	if q.Operation != "native_pair_join_named" && (q.PairLabel != "" || q.Slot != "") {
		return nodewire.ErrEndpointContext
	}
	if q.Operation == "endpoint_directory" {
		if q.Harness != "" || q.NativeSessionID != "" || q.Workspace != "" {
			return nodewire.ErrEndpointContext
		}
		return (nodewire.EndpointDirectoryRequest{Cursor: q.Cursor, Limit: q.Limit}).Validate()
	}
	if q.Operation == "native_pair_available" && q.Harness == "" && q.NativeSessionID == "" && q.Workspace == "" {
		return nil
	}
	if q.Harness != "codex" || !localContextText(q.NativeSessionID, 128) || strings.ContainsAny(q.NativeSessionID, "/\\") || !filepath.IsAbs(q.Workspace) || filepath.Clean(q.Workspace) != q.Workspace || !localContextText(q.Workspace, 1024) {
		return nodewire.ErrEndpointContext
	}
	if q.Operation == "endpoint_register" {
		return (nodewire.EndpointRegistration{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, Name: q.Name}).Validate()
	}
	if q.Operation == "native_pair_join_named" && (!localContextText(q.PairLabel, 256) || (q.Slot != "A" && q.Slot != "B")) {
		return nodewire.ErrEndpointContext
	}
	return nil
}

func (b *machineAgentJoinBridge) nodeOperatorAvailable(client *machineNodeControlClient) error {
	raw, err := b.httpWithAuthorization(http.MethodGet, wire.OwnerEndpointReadPath+"?profile="+nodewire.NodeOperatorProfile, nil, "", "")
	if err != nil {
		return errors.New("Node operator profile is unavailable; no new intent prepared")
	}
	caps, err := nodewire.ParseNodeOperatorCapabilities(raw, client.approvedBinding())
	if err != nil || !caps.Available {
		return errors.New("Node operator profile is unsupported; no new intent prepared")
	}
	return nil
}

var errLocalNamedPairSelection = errors.New("PAIR_SELECTION_REFUSED: choose one unambiguous available Pair label and slot")

func localNamedJoinRefusalEligible(err error) bool {
	return errors.Is(err, errLocalNamedPairSelection) || errors.Is(err, errManagedPairLeaseFull) || errors.Is(err, errManagedPairLeaseStopped) || errors.Is(err, errLocalEndpointReceiptExpired) || errors.Is(err, nodewire.ErrEndpointContext) || errors.Is(err, nodewire.ErrEndpointConflict) || errors.Is(err, nodewire.ErrEndpointUnavailable)
}

func (b *machineAgentJoinBridge) endpointOperation(q localEndpointRequest) (*localEndpointResult, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	// A selected domain must never silently downgrade to zero/legacy admission.
	// The delegated path is connected below with the rest of the Node service.
	if q.LocalDomain != (wire.LocalDomainSelection{}) {
		return nil, nodewire.ErrEndpointUnavailable
	}
	origin, err := normalizeMCPAPIOrigin(q.APIOrigin)
	expected, expectedErr := normalizeMCPAPIOrigin(b.baseURL)
	if err != nil || expectedErr != nil || origin != expected || origin != q.APIOrigin {
		return nil, nodewire.ErrEndpointContext
	}
	if q.Harness != "" {
		cwd, err := filepath.EvalSymlinks(q.Workspace)
		if err != nil || cwd != q.Workspace {
			return nil, nodewire.ErrEndpointContext
		}
		if err := verifyCodexSessionRecord(q.NativeSessionID, q.Workspace); err != nil {
			return nil, err
		}
	}
	// A local intent spans several Node calls. Serialize preparation/selection;
	// the existing client lock still owns the shared counter and exact outbox.
	b.endpointMu.Lock()
	defer b.endpointMu.Unlock()
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, err
	}
	client.mu.Lock()
	_, exists := client.state.LocalEndpointIntents[q.RequestID]
	client.mu.Unlock()
	if !exists {
		if err := b.nodeOperatorAvailable(client); err != nil {
			return nil, err
		}
	}
	digest, err := client.retainLocalEndpointIntent(q, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	binding := client.approvedBinding()
	r := &localEndpointResult{RequestID: q.RequestID, IntentDigest: digest, HubID: binding.HubID, NodeID: b.nodeID, Operation: q.Operation, State: "UNKNOWN"}
	if q.Operation == "native_pair_join_named" && client.localNamedJoinRefused(q.RequestID, digest) {
		r.State = "REFUSED"
		return r, errNativePairNodeRejected
	}
	// Recover only the already sealed packet. A terminal refusal is retained in
	// its step and will be returned below; unresolved outcomes stop new work.
	if err := client.recoverPending(b.ctx, b.nodeToken); err != nil {
		if !errors.Is(err, nodewire.ErrEndpointContext) && !errors.Is(err, nodewire.ErrEndpointConflict) && !errors.Is(err, nodewire.ErrEndpointUnavailable) {
			return r, err
		}
	}
	switch q.Operation {
	case "endpoint_register":
		var result nodewire.EndpointRegistrationResult
		err = client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "register", nodewire.EndpointRegisterOperation, nodewire.EndpointRegistration{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Name: q.Name, Workspace: q.Workspace}, &result)
		if err == nil {
			r.Registration = &result
		}
	case "endpoint_leave":
		err = b.localEndpointLeave(client, q, digest, r)
	case "endpoint_directory":
		var result nodewire.EndpointDirectoryResult
		err = client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "directory", nodewire.EndpointDirectoryOperation, nodewire.EndpointDirectoryRequest{Cursor: q.Cursor, Limit: q.Limit}, &result)
		if err == nil {
			r.Directory = &result
		}
	case "native_pair_available":
		var result nodewire.AvailableNativePairs
		err = client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "available", nodewire.NativePairAvailableOperation, struct{}{}, &result)
		if err == nil {
			r.Pairs = &result
		}
	case "native_pair_join_named":
		err = b.localEndpointNamedJoin(client, q, digest, r)
	}
	if q.Operation == "native_pair_join_named" && err != nil {
		if errors.Is(err, errNativePairNodeRejected) {
			r.State = "REFUSED"
			return r, err
		}
		if localNamedJoinRefusalEligible(err) {
			fenced, fenceErr := client.fenceLocalNamedJoinRefusal(q.RequestID, digest)
			if fenceErr != nil {
				return r, fenceErr
			}
			if fenced {
				r.State = "REFUSED"
				return r, errNativePairNodeRejected
			}
		}
		return r, err // Dispatched/uncertain Join can never become a local refusal.
	}
	if err == nil {
		r.State = "COMPLETED"
	} else if errors.Is(err, nodewire.ErrEndpointContext) || errors.Is(err, nodewire.ErrEndpointConflict) || errors.Is(err, nodewire.ErrEndpointUnavailable) {
		r.State = "REFUSED"
	} else if errors.Is(err, errNativePairNodeRejected) {
		r.State = "REFUSED"
	} else if errors.Is(err, errLocalEndpointReceiptExpired) {
		r.State = "FENCED_RECEIPT_EXPIRED"
	}
	return r, err
}

func (b *machineAgentJoinBridge) localEndpointLeave(client *machineNodeControlClient, q localEndpointRequest, digest string, r *localEndpointResult) error {
	step, exists, err := client.localEndpointStep(q.RequestID, digest, "leave")
	if err != nil {
		return err
	}
	var leave nodewire.EndpointLeave
	if exists {
		if decodeMachineNodeControlJSON(step.Body, &leave) != nil {
			return errLocalEndpointIntentConflict
		}
	} else {
		var self nodewire.EndpointDirectoryResult
		if err := client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "self", nodewire.EndpointDirectoryOperation, nodewire.EndpointDirectoryRequest{Harness: q.Harness, NativeSessionID: q.NativeSessionID, Limit: 1}, &self); err != nil {
			return err
		}
		if len(self.Endpoints) != 1 || self.Endpoints[0].Harness != q.Harness || self.Endpoints[0].NativeSessionID != q.NativeSessionID || self.Endpoints[0].Workspace != q.Workspace {
			return nodewire.ErrEndpointUnavailable
		}
		leave = nodewire.EndpointLeave{Harness: q.Harness, NativeSessionID: q.NativeSessionID, StateDigest: self.Endpoints[0].StateDigest}
	}
	var result nodewire.EndpointRegistrationResult
	if err := client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "leave", nodewire.EndpointLeaveOperation, leave, &result); err != nil {
		return err
	}
	if err := client.stopManagedPairLeasesForNative(q.Harness, q.NativeSessionID, q.Workspace); err != nil {
		return err
	}
	r.Registration = &result
	return nil
}

type localNamedPairSelection struct {
	PairID     string `json:"pair_id"`
	Generation uint64 `json:"generation"`
}

func (b *machineAgentJoinBridge) localEndpointNamedJoin(client *machineNodeControlClient, q localEndpointRequest, digest string, r *localEndpointResult) error {
	var join wire.NativePairNodeJoin
	step, exists, err := client.localEndpointStep(q.RequestID, digest, "join")
	if err != nil {
		return err
	}
	if exists {
		if decodeMachineNodeControlJSON(step.Body, &join) != nil {
			return errLocalEndpointIntentConflict
		}
	} else {
		var selected localNamedPairSelection
		selection, exists, err := client.localEndpointStep(q.RequestID, digest, "selection")
		if err != nil {
			return err
		}
		if exists {
			if decodeMachineNodeControlJSON(selection.Body, &selected) != nil {
				return errLocalEndpointIntentConflict
			}
		} else {
			var available nodewire.AvailableNativePairs
			if err := client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "available", nodewire.NativePairAvailableOperation, struct{}{}, &available); err != nil {
				return err
			}
			if available.Truncated {
				return errLocalNamedPairSelection
			}
			matches := 0
			for _, pair := range available.Pairs {
				if pair.Label != q.PairLabel {
					continue
				}
				matches++
				for _, slot := range pair.Slots {
					if slot.Slot == q.Slot {
						selected = localNamedPairSelection{pair.PairID, slot.Generation}
					}
				}
			}
			if matches != 1 || selected.PairID == "" || selected.Generation == 0 {
				return errLocalNamedPairSelection
			}
			if _, err := client.prepareLocalEndpointStep(q.RequestID, digest, "selection", "local.selection", selected); err != nil {
				return err
			}
		}
		if err := b.nativePairAvailable(); err != nil {
			return err
		}
		var description wire.NativePairNodeDescription
		if err := client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "describe", wire.OperationNativePairNodeDescribe, wire.NativePairNodeDescribe{ContractRevision: wire.NativePairContractRevision, PairID: selected.PairID}, &description); err != nil {
			return err
		}
		if err := client.acceptNativePairDescription(b.ctx, b.nodeToken, description, selected.PairID); err != nil {
			return err
		}
		generation := description.SlotAGeneration
		if q.Slot == "B" {
			generation = description.SlotBGeneration
		}
		if generation != selected.Generation {
			return errLocalNamedPairSelection
		}
		join = wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: selected.PairID, Slot: q.Slot, ExpectedGeneration: generation, BootstrapProofDigest: wire.NativePairProofDigest(description.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: q.NativeSessionID, Workspace: q.Workspace}
	}
	var joined fabric.JoinResult
	if err := client.reserveManagedPairLease(b.ctx, q, digest, join, time.Now().UTC()); err != nil {
		return err
	}
	if err := client.callLocalEndpoint(b.ctx, b.nodeToken, q.RequestID, digest, "join", wire.OperationNativePairNodeJoin, join, &joined); err != nil {
		if errors.Is(err, errNativePairNodeRejected) {
			if stopErr := client.stopManagedPairLease(localEndpointStepID(q.RequestID, digest, "join"), "", "JOIN_REJECTED_FENCED", true); stopErr != nil {
				return stopErr
			}
		}
		return err
	}
	local := localNativePairJoinRequest{Version: localJoinProtocolVersion, Operation: "native_pair_join", PairID: join.PairID, Slot: q.Slot, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, APIOrigin: q.APIOrigin}
	result, scope, err := b.completeNativePairJoin(local, &joined)
	if err != nil {
		return err
	}
	if err := client.activateManagedPairLease(b.ctx, q, digest, result, scope, time.Now().UTC()); err != nil {
		return err
	}
	select {
	case b.managedLeaseWake <- struct{}{}:
	default:
	}
	r.Join, r.NativeContextScope = result, scope
	return nil
}

func requestMachineAgentEndpoint(socketPath string, q localEndpointRequest) (*localEndpointResult, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	response, err := requestLocalNodeOperation(socketPath, q)
	if response == nil {
		return nil, err
	}
	r := response.EndpointOperation
	if r == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("incomplete local endpoint result")
	}
	data, _ := json.Marshal(q)
	sum := sha256.Sum256(data)
	if r.RequestID != q.RequestID || r.IntentDigest != hex.EncodeToString(sum[:]) || r.Operation != q.Operation || r.HubID == "" || r.NodeID == "" {
		return nil, errLocalEndpointIntentConflict
	}
	return r, err
}
