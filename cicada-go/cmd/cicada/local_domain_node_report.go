package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

var errLocalDomainNodeRejected = errors.New("LOCAL_DOMAIN_REJECTED: original local collaboration operation remains fenced")

type machineLocalDomainReportState struct {
	BindingID    string                       `json:"binding_id"`
	NodeKeyEpoch uint64                       `json:"node_key_epoch"`
	NextAt       string                       `json:"next_at"`
	Failures     uint32                       `json:"failures"`
	Hub          wire.HubIdentity             `json:"hub_identity"`
	Current      *wire.LocalDomainDescription `json:"current,omitempty"`
	ObservedAt   string                       `json:"observed_at,omitempty"`
	ReportProof  []byte                       `json:"report_proof,omitempty"`
}

func localDomainNodeBusinessOperation(operation string) bool {
	for _, op := range wire.LocalDomainNodeOperations() {
		if op == operation {
			return true
		}
	}
	return false
}

func cloneMachineLocalDomainState(state machineNodeControlState) machineNodeControlState {
	if state.ManagedLocalDomainLeases != nil {
		original := state.ManagedLocalDomainLeases
		state.ManagedLocalDomainLeases = make(map[string]machineManagedLocalDomainLease, len(original))
		for id, m := range original {
			state.ManagedLocalDomainLeases[id] = m
		}
	}
	if state.LocalDomainReport != nil {
		raw, _ := json.Marshal(state.LocalDomainReport)
		var copy machineLocalDomainReportState
		_ = json.Unmarshal(raw, &copy)
		state.LocalDomainReport = &copy
	}
	return state
}

func localDomainTransportAllowed(origin string, c wire.LocalDomainCapabilities) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && c.TransportPolicy == wire.AppNodeTransportHTTPS || u.Scheme == "http" && c.TransportPolicy == wire.AppNodeTransportLoopbackTest && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")
}

func (b *machineAgentJoinBridge) localDomainCapabilities(ctx context.Context) (wire.LocalDomainCapabilities, error) {
	var raw machineNativePairRawJSON
	if err := machineAPIJSON(ctx, b.baseURL+wire.LocalDomainCapabilitiesPath, http.MethodGet, nil, &raw); err != nil {
		return wire.LocalDomainCapabilities{}, err
	}
	caps, err := wire.DecodeLocalDomainCapabilities(raw)
	if err != nil || !caps.Available || !localDomainTransportAllowed(b.baseURL, caps) {
		return wire.LocalDomainCapabilities{}, nodekeys.ErrLocalDomainPolicy
	}
	return caps, nil
}

// Existing worker tick, no added daemon or per-tool report. Reserve the next
// attempt durably before I/O: at most one refresh every two minutes, including
// concurrent wakeups/restarts, with bounded exponential failure backoff.
func (b *machineAgentJoinBridge) refreshLocalDomainReport(ctx context.Context, clock func() time.Time) {
	b.localDomainMu.Lock()
	defer b.localDomainMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return
	}
	now := clock().UTC()
	client.mu.Lock()
	if client.state.BindingID == "" || client.state.NodeKeyEpoch == 0 {
		client.mu.Unlock()
		return
	}
	previous := cloneMachineNodeControlState(client.state)
	r := client.state.LocalDomainReport
	if r == nil || r.BindingID != client.state.BindingID || r.NodeKeyEpoch != client.state.NodeKeyEpoch {
		r = &machineLocalDomainReportState{BindingID: client.state.BindingID, NodeKeyEpoch: client.state.NodeKeyEpoch}
	}
	if next, e := time.Parse(time.RFC3339Nano, r.NextAt); e == nil && now.Before(next) {
		client.mu.Unlock()
		return
	}
	copy := *r
	backoff := 2 * time.Minute
	for i := uint32(0); i < r.Failures && backoff < 16*time.Minute; i++ {
		backoff *= 2
	}
	copy.NextAt = now.Add(backoff).Format(time.RFC3339Nano)
	if copy.Failures < 4 {
		copy.Failures++
	}
	client.state.LocalDomainReport = &copy
	if err = client.persistLocked(); err != nil {
		client.state = previous
		client.mu.Unlock()
		return
	}
	actual := client.state
	client.mu.Unlock()
	if _, err = b.localDomainCapabilities(ctx); err != nil {
		return
	} // old Hub is optional
	if err = client.recoverPending(ctx, b.nodeToken); err != nil && !errors.Is(err, errLocalEndpointReceiptExpired) && !errors.Is(err, errLocalDomainNodeRejected) {
		return
	}
	// Existing public Client identity is informational metadata here. It is
	// accepted as policy authority only after the independent Owner signature
	// authenticates its exact fingerprint; it never replaces the Node Hub pin.
	hub := r.Hub
	if hub.HubID == "" {
		if err = machineAPIJSON(ctx, b.baseURL+"/v2/client/identity", http.MethodGet, nil, &hub); err != nil {
			return
		}
		if _, err = wire.HubFingerprint(hub); err != nil || hub.HubID != actual.HubID {
			return
		}
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return
	}
	scope := "uid:" + strconv.FormatUint(uint64(uid), 10)
	nonce, err := wire.NewNonce()
	if err != nil {
		return
	}
	report := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: actual.HubID, NodeID: client.nodeID, OwnerBindingID: actual.BindingID, NodeKeyEpoch: actual.NodeKeyEpoch, LocalUserScope: scope, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	proof, err := e2ee.SignLocalDomainUserReport(client.identity, report)
	if err != nil {
		return
	}
	// Retain only the latest original public report before I/O. A subsequent
	// explicit current-policy read reuses its signature and fixed expiry; it
	// cannot republish a fresh report on every tool or wait for the next tick.
	client.mu.Lock()
	beforeProof := cloneMachineNodeControlState(client.state)
	if client.state.BindingID != actual.BindingID || client.state.NodeKeyEpoch != actual.NodeKeyEpoch {
		client.mu.Unlock()
		return
	}
	retained := copy
	retained.Hub, retained.ReportProof = hub, append([]byte(nil), proof...)
	client.state.LocalDomainReport = &retained
	if err = client.persistLocked(); err != nil {
		client.state = beforeProof
		client.mu.Unlock()
		return
	}
	client.mu.Unlock()
	var result json.RawMessage
	if err = client.call(ctx, b.nodeToken, wire.OperationLocalDomainNodeAvailable, wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: scope, LocalUserReport: proof}, &result); err != nil {
		return
	}
	available, err := wire.DecodeLocalDomainNodeAvailable(result, hub, e2ee.OwnerAppNodeBinding{NodeID: client.nodeID, OwnerBindingID: actual.BindingID, NodeKeyEpoch: actual.NodeKeyEpoch, NodeKeyFingerprint: actual.NodeKeyFingerprint}, scope, clock().UTC())
	if err != nil {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.BindingID != actual.BindingID || client.state.NodeKeyEpoch != actual.NodeKeyEpoch {
		return
	}
	before := cloneMachineNodeControlState(client.state)
	fresh := copy
	fresh.Hub = hub
	fresh.ReportProof = append([]byte(nil), proof...)
	fresh.Failures = 0
	fresh.NextAt = now.Add(2 * time.Minute).Format(time.RFC3339Nano)
	fresh.ObservedAt = available.ObservedAt
	fresh.Current = nil
	if len(available.Policies) == 1 {
		description := available.Policies[0]
		fresh.Current = &description
	}
	client.state.LocalDomainReport = &fresh
	if err = client.persistLocked(); err != nil {
		client.state = before
	}
}

func (client *machineNodeControlClient) acceptLocalDomainPolicy(ctx context.Context, token string, hub wire.HubIdentity, d wire.LocalDomainDescription, now time.Time) (*nodekeys.LocalDomainPolicy, error) {
	client.mu.Lock()
	actual := client.state
	identity := client.identity.Public()
	client.mu.Unlock()
	p, n := d.Policy, d.Policy.Node
	uid, err := machineAgentJoinSocketCurrentUID()
	if err != nil {
		return nil, err
	}
	if d.State != wire.LocalDomainActive || wire.ValidateLocalDomainDescription(d, hub, now) != nil || p.Origin != client.base || p.HubID != actual.HubID || p.CredentialCommitment != wire.NativePairCredentialCommitment(token) || p.LocalUserScope != "uid:"+strconv.FormatUint(uint64(uid), 10) || n.NodeID != client.nodeID || n.OwnerBindingID != actual.BindingID || n.BindingVersion != actual.BindingVersion || n.NodeKeyEpoch != actual.NodeKeyEpoch || n.NodeKeyVersion != actual.NodeKeyVersion || n.NodeKeyFingerprint != actual.NodeKeyFingerprint || !machineSamePublicIdentity(n.NodePublic, identity) || n.HubNodeControlKeyVersion != actual.HubKeyVersion || n.HubNodeControlFingerprint != actual.HubFingerprint || !machineSamePublicIdentity(n.HubNodeControlPublic, actual.HubPublicIdentity) || n.ApprovedRequestID != actual.ApprovedRequestID || n.ApprovedRequestVersion != uint64(actual.ApprovedRequestVersion) || n.ApprovedCandidateDigest != actual.ApprovedCandidateDigest {
		return nil, nodekeys.ErrLocalDomainPolicy
	}
	s, err := nodekeys.OpenCryptoState(machineNodeStateDir(client.stateDir, client.nodeID))
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.RequireLocalDomainPolicy(ctx, hub, p, d.PolicyProof, now)
}

func (client *machineNodeControlClient) currentLocalDomainPolicy(ctx context.Context, token string, now time.Time) (*nodekeys.LocalDomainPolicy, error) {
	client.mu.Lock()
	r := cloneMachineLocalDomainState(client.state).LocalDomainReport
	binding, epoch := client.state.BindingID, client.state.NodeKeyEpoch
	client.mu.Unlock()
	if r == nil || r.Current == nil {
		return nil, nil
	}
	if r.BindingID != binding || r.NodeKeyEpoch != epoch {
		return nil, nodekeys.ErrLocalDomainPolicy
	}
	return client.acceptLocalDomainPolicy(ctx, token, r.Hub, *r.Current, now)
}

// A user explicitly registering the current Thread must see an activation
// committed after the periodic report. Reuse the exact latest report; this is
// a bounded current read, never another report signature or expiry extension.
func (b *machineAgentJoinBridge) readLocalDomainCurrent(ctx context.Context, client *machineNodeControlClient) (*nodekeys.LocalDomainPolicy, error) {
	b.localDomainMu.Lock()
	defer b.localDomainMu.Unlock()
	client.mu.Lock()
	r := cloneMachineLocalDomainState(client.state).LocalDomainReport
	actual, pub := client.state, client.identity.Public()
	client.mu.Unlock()
	if r == nil || r.Hub.HubID == "" {
		return nil, nil // An optional profile absent from an older Hub.
	}
	now := time.Now().UTC()
	if r.BindingID != actual.BindingID || r.NodeKeyEpoch != actual.NodeKeyEpoch || r.Hub.HubID != actual.HubID {
		return nil, nodekeys.ErrLocalDomainPolicy
	}
	node := e2ee.OwnerAppNodeBinding{HubID: actual.HubID, NodeID: client.nodeID, OwnerBindingID: actual.BindingID, NodeKeyEpoch: actual.NodeKeyEpoch, NodePublic: pub, NodeKeyFingerprint: actual.NodeKeyFingerprint}
	report, err := e2ee.VerifyLocalDomainUserReport(node, r.ReportProof, now)
	uid, uidErr := machineAgentJoinSocketCurrentUID()
	if err != nil || uidErr != nil || report.LocalUserScope != "uid:"+strconv.FormatUint(uint64(uid), 10) {
		return nil, nodekeys.ErrLocalDomainPolicy
	}
	if err = client.recoverPending(ctx, b.nodeToken); err != nil && !errors.Is(err, errLocalEndpointReceiptExpired) && !errors.Is(err, errLocalDomainNodeRejected) {
		return nil, err
	}
	var raw json.RawMessage
	if err = client.call(ctx, b.nodeToken, wire.OperationLocalDomainNodeAvailable, wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: report.LocalUserScope, LocalUserReport: r.ReportProof}, &raw); err != nil {
		return nil, err
	}
	available, err := wire.DecodeLocalDomainNodeAvailable(raw, r.Hub, node, report.LocalUserScope, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	client.mu.Lock()
	if client.state.BindingID != actual.BindingID || client.state.NodeKeyEpoch != actual.NodeKeyEpoch || client.state.LocalDomainReport == nil || !bytes.Equal(client.state.LocalDomainReport.ReportProof, r.ReportProof) {
		client.mu.Unlock()
		return nil, nodekeys.ErrLocalDomainPolicy
	}
	previous := cloneMachineNodeControlState(client.state)
	fresh := *client.state.LocalDomainReport
	fresh.Current, fresh.ObservedAt = nil, available.ObservedAt
	if len(available.Policies) == 1 {
		d := available.Policies[0]
		fresh.Current = &d
	}
	client.state.LocalDomainReport = &fresh
	if err = client.persistLocked(); err != nil {
		client.state = previous
		client.mu.Unlock()
		return nil, err
	}
	client.mu.Unlock()
	if fresh.Current == nil {
		return nil, nil
	}
	return client.acceptLocalDomainPolicy(ctx, b.nodeToken, r.Hub, *fresh.Current, time.Now().UTC())
}
