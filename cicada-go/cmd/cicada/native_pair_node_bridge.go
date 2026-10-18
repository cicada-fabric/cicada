package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func (client *machineNodeControlClient) takeNativePairDescription(pairID string) (*wire.NativePairNodeDescription, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	var selectedID string
	var selected machineNativePairReceipt
	for id, record := range client.state.NativePairReceipts {
		if record.Operation == wire.OperationNativePairNodeDescribe && record.PairID == pairID && !record.Consumed && !record.Fenced && (selectedID == "" || record.Sequence > selected.Sequence) {
			selectedID, selected = id, record
		}
	}
	if selectedID == "" {
		return nil, nil
	}
	result, err := client.openNativePairRecordedResultLocked(selected)
	if err != nil {
		return nil, err
	}
	description, err := wire.DecodeNativePairNodeDescription(result)
	if err != nil || description.PairID != pairID {
		return nil, errors.New("retained native Pair description changed its target")
	}
	previous := cloneMachineNodeControlState(client.state)
	selected.Consumed = true
	client.state.NativePairReceipts[selectedID] = selected
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return nil, err
	}
	return &description, nil
}

func (client *machineNodeControlClient) retainedNativePairJoin(request localNativePairJoinRequest) (*fabric.JoinResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	var selected *machineNativePairReceipt
	var selectedID string
	var selection wire.NativePairNodeJoin
	for id, record := range client.state.NativePairReceipts {
		if record.Operation != wire.OperationNativePairNodeJoin || record.PairID != request.PairID {
			continue
		}
		decoded, err := nativePairNodeBody(record.Operation, record.RequestBody)
		if err != nil {
			return nil, err
		}
		q := decoded.(wire.NativePairNodeJoin)
		if q.PairID == request.PairID && q.Slot == request.Slot && q.NativeSessionID == request.NativeSessionID && q.Workspace == request.Workspace && (selected == nil || record.Sequence > selected.Sequence) {
			copy := record
			selected, selection = &copy, q
			selectedID = id
		}
	}
	if selected == nil {
		return nil, nil
	}
	if selected.Fenced {
		if selected.Consumed {
			return nil, nil // A later explicit invocation may start a new intent.
		}
		previous := cloneMachineNodeControlState(client.state)
		selected.Consumed = true
		client.state.NativePairReceipts[selectedID] = *selected
		if err := client.persistLocked(); err != nil {
			client.state = previous
			return nil, err
		}
		return nil, errNativePairNodeRejected
	}
	result, err := client.openNativePairRecordedResultLocked(*selected)
	if err != nil {
		return nil, err
	}
	return client.validateNativePairJoinResultLocked(selection, result)
}

func (client *machineNodeControlClient) acceptNativePairDescription(ctx context.Context, token string, d wire.NativePairNodeDescription, pairID string) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	var unsigned e2ee.OwnerNativePairProof
	if decodeMachineNodeControlJSON(d.BootstrapOwnerProof, &unsigned) != nil {
		return nodekeys.ErrNativePairPolicy
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(client.stateDir, client.nodeID))
	if err != nil {
		return err
	}
	defer state.Close()
	trust, err := state.GetNodeOwnerKeyTrustLocal(unsigned.Claims.Scope.Actor.OwnerID, unsigned.Claims.Scope.Actor.OwnerPublic.ID)
	if err != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive {
		return nodekeys.ErrNativePairPolicy
	}
	now := time.Now().UTC()
	claims, err := wire.VerifyNativePairNodeDescription(d, trust.PublicIdentity, pairID, now)
	if err != nil {
		return err
	}
	n := claims.Scope.Node
	actual := client.state
	if claims.Scope.Actor.Origin != client.base || d.HubIdentity.HubID != actual.HubID || n.HubID != actual.HubID || n.NodeID != client.nodeID || n.OwnerBindingID != actual.BindingID || n.BindingVersion != actual.BindingVersion || n.NodeKeyVersion != actual.NodeKeyVersion || n.NodeKeyEpoch != actual.NodeKeyEpoch || n.NodeKeyFingerprint != actual.NodeKeyFingerprint || !sameMachineNodeControlPublicIdentity(n.NodePublic, client.identity.Public()) || n.HubNodeControlKeyVersion != actual.HubKeyVersion || n.HubNodeControlFingerprint != actual.HubFingerprint || !sameMachineNodeControlPublicIdentity(n.HubNodeControlPublic, actual.HubPublicIdentity) || n.ApprovedRequestID != actual.ApprovedRequestID || n.ApprovedRequestVersion != uint64(actual.ApprovedRequestVersion) || n.ApprovedCandidateDigest != actual.ApprovedCandidateDigest || claims.Scope.CredentialCommitment != wire.NativePairCredentialCommitment(token) {
		return errors.New("Owner Pair proof differs from the original local Node, Hub pin or credential")
	}
	_, err = state.RequireNativePairPolicy(ctx, d.HubIdentity, claims.Scope, d.BootstrapOwnerProof, now)
	return err
}

func (b *machineAgentJoinBridge) nativePairAvailable() error {
	raw, err := b.httpWithAuthorization(http.MethodGet, wire.NativePairCapabilitiesPath, nil, "", "")
	if err != nil || len(raw) > wire.MaxNativePairCapabilitiesBytes {
		return errors.New("native Pair service is unavailable")
	}
	caps, err := wire.DecodeNativePairCapabilities(raw)
	if err != nil || !caps.Available {
		return errors.New("native Pair service is unavailable")
	}
	origin, err := url.Parse(b.baseURL)
	if err != nil {
		return err
	}
	if origin.Scheme == "https" && caps.TransportPolicy == wire.AppNodeTransportHTTPS {
		return nil
	}
	address := net.ParseIP(origin.Hostname())
	if origin.Scheme == "http" && caps.TransportPolicy == wire.AppNodeTransportLoopbackTest && (origin.Hostname() == "localhost" || address != nil && address.IsLoopback()) {
		return nil
	}
	return errors.New("native Pair transport differs from the declared bounded profile")
}

func (b *machineAgentJoinBridge) nativePairJoin(request localNativePairJoinRequest) (*fabric.JoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	selection := nativePairJoinSelection{PairID: request.PairID, Slot: request.Slot}
	if _, err := nativePairLocalJoinRequest(selection, harness.SessionContext{Harness: request.Harness, NativeSessionID: request.NativeSessionID, MachineID: b.nodeID, Workspace: request.Workspace}); err != nil || request.Version != localJoinProtocolVersion || request.Operation != "native_pair_join" {
		return nil, nil, errors.New("invalid reserved Pair Join context")
	}
	origin, err := normalizeMCPAPIOrigin(request.APIOrigin)
	expected, expectedErr := normalizeMCPAPIOrigin(b.baseURL)
	if err != nil || expectedErr != nil || origin != expected {
		return nil, nil, errors.New("reserved Pair Join belongs to a different selected Hub origin")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, nil, err
	}
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, nil, err
	}
	// This includes an accepted Join whose response was lost or fetched late.
	if err := client.recoverNativePairOriginal(b.ctx, b.nodeToken); err != nil {
		return nil, nil, err
	}
	joined, err := client.retainedNativePairJoin(request)
	if err != nil {
		return nil, nil, err
	}
	if joined != nil {
		joined.Reused = true
		return b.completeNativePairJoin(request, joined)
	}
	if err := b.nativePairAvailable(); err != nil {
		return nil, nil, err
	}
	description, err := client.takeNativePairDescription(request.PairID)
	if err != nil {
		return nil, nil, err
	}
	if description == nil {
		q := wire.NativePairNodeDescribe{ContractRevision: wire.NativePairContractRevision, PairID: request.PairID}
		callError := client.call(b.ctx, b.nodeToken, wire.OperationNativePairNodeDescribe, q, nil)
		if callError != nil {
			if err := client.recoverNativePairOriginal(b.ctx, b.nodeToken); err != nil {
				return nil, nil, err
			}
		}
		description, err = client.takeNativePairDescription(request.PairID)
		if err != nil || description == nil {
			if err != nil {
				return nil, nil, err
			}
			return nil, nil, errors.New("native Pair Describe has no applicable authenticated result")
		}
	}
	if err := client.acceptNativePairDescription(b.ctx, b.nodeToken, *description, request.PairID); err != nil {
		return nil, nil, err
	}
	generation := description.SlotAGeneration
	if request.Slot == "B" {
		generation = description.SlotBGeneration
	}
	q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: request.PairID, Slot: request.Slot, ExpectedGeneration: generation, BootstrapProofDigest: wire.NativePairProofDigest(description.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: request.NativeSessionID, Workspace: request.Workspace}
	if err := client.call(b.ctx, b.nodeToken, wire.OperationNativePairNodeJoin, q, nil); err != nil {
		if recoveryError := client.recoverNativePairOriginal(b.ctx, b.nodeToken); recoveryError != nil {
			return nil, nil, recoveryError
		}
	}
	joined, err = client.retainedNativePairJoin(request)
	if err != nil || joined == nil {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("native Pair Join has no retained authenticated receipt")
	}
	return b.completeNativePairJoin(request, joined)
}

func (b *machineAgentJoinBridge) completeNativePairJoin(request localNativePairJoinRequest, joined *fabric.JoinResult) (*fabric.JoinResult, *nodeinbox.NativeContextScopeDecision, error) {
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return nil, nil, err
	}
	policy, policyError := state.NativePairPolicyForGroup(b.ctx, joined.Endpoint.GroupID)
	var proof e2ee.OwnerNativePairProof
	if policyError != nil || policy.PairID != request.PairID || json.Unmarshal(policy.BootstrapProof, &proof) != nil || !time.Now().UTC().Before(parseMachineNativePairTime(policy.PeerExpiresAt)) {
		_ = state.Close()
		return nil, nil, nodekeys.ErrNativePairPolicy
	}
	trust, trustError := state.GetNodeOwnerKeyTrustLocal(proof.Claims.Scope.Actor.OwnerID, proof.Claims.Scope.Actor.OwnerPublic.ID)
	closeError := state.Close()
	if trustError != nil || closeError != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive {
		return nil, nil, nodekeys.ErrNativePairPolicy
	}
	// Never interpret the original receipt's old five-minute expiry as either
	// fresh permission or a demand to rejoin. Inspect and renew the same binding.
	card, err := b.verifyCurrentMCPBinding(joined.SessionToken, joined.Endpoint.GroupID)
	if err != nil || card.EndpointID != joined.Endpoint.ID || card.NativeSessionID != request.NativeSessionID || card.Workspace != request.Workspace || card.BindingID != joined.BindingID || card.BindingEpoch != joined.BindingEpoch {
		return nil, nil, errors.New("original Pair Join recovered; its current lease is unavailable, and no replacement Join was sent")
	}
	raw, err := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/heartbeat", nil, "CicadaSession "+joined.SessionToken, joined.Endpoint.GroupID)
	if err != nil {
		return nil, nil, err
	}
	var actor fabric.Actor
	if decodeStrictBridgeJSON(raw, &actor) != nil || actor.EndpointID != joined.Endpoint.ID || actor.GroupID != joined.Endpoint.GroupID || actor.BindingID != joined.BindingID || actor.BindingEpoch != joined.BindingEpoch || !time.Now().UTC().Before(parseMachineNativePairTime(actor.LeaseExpiresAt)) || parseMachineNativePairTime(actor.LeaseExpiresAt).After(parseMachineNativePairTime(policy.PeerExpiresAt)) {
		return nil, nil, errors.New("Pair heartbeat did not retain the original live binding")
	}
	decision, err := recordMachineNativeContextMetadata(b.ctx, request.Harness, request.NativeSessionID, joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch, joined.NativeContextScope)
	if err != nil || decision == nil || !decision.Accepted {
		return nil, nil, b.blockCommittedLocalJoin("GROUP", joined.NativeContextScope.HubID, joined.Endpoint.GroupID, "", joined.Endpoint.ID, joined.BindingID, joined.BindingEpoch, actor.LeaseExpiresAt, errors.New("original Pair Join has no accepted local native context"))
	}
	if err := b.publishJoinedLocalEndpointKey(joined); err != nil {
		return nil, nil, err
	}
	copy := *joined
	copy.NetworkCard, copy.LeaseExpiresAt = card, actor.LeaseExpiresAt
	return &copy, decision, nil
}
