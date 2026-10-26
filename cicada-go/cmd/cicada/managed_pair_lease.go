package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const (
	maxManagedPairLiveLeases       = 32
	managedPairLeaseReserveBytes   = 16 << 10
	managedPairLeaseInterval       = 30 * time.Second
	managedPairLeaseRequestTimeout = 5 * time.Second
	managedPairLeaseBatch          = 4
)

var errManagedPairLeaseStopped = errors.New("MANAGED_PAIR_LEASE_STOPPED: original binding is not reactivated")
var errManagedPairLeaseFull = errors.New("MANAGED_PAIR_LEASE_CAPACITY: no new Pair Join was issued")

// Only named, explicit local connect may create this record, before its Hub
// mutation. It references the original sealed receipt; no token is duplicated.
type machineManagedPairLease struct {
	IntentID            string                  `json:"intent_id"`
	IntentDigest        string                  `json:"intent_digest"`
	IssuedAt            string                  `json:"issued_at"`
	JoinOperationID     string                  `json:"join_operation_id"`
	Join                wire.NativePairNodeJoin `json:"join"`
	PreparationDigest   string                  `json:"preparation_digest"`
	FrozenDigest        string                  `json:"frozen_digest,omitempty"`
	PeerCeiling         string                  `json:"peer_ceiling"`
	KnownLeaseExpiresAt string                  `json:"known_lease_expires_at,omitempty"`
	State               string                  `json:"state"`
	StopCode            string                  `json:"stop_code,omitempty"`
	NoEffect            bool                    `json:"no_effect,omitempty"`
}

func cloneManagedPairLeaseState(state machineNodeControlState) machineNodeControlState {
	if state.ManagedPairLeases != nil {
		original := state.ManagedPairLeases
		state.ManagedPairLeases = make(map[string]machineManagedPairLease, len(original))
		for id, m := range original {
			state.ManagedPairLeases[id] = m
		}
	}
	return state
}

func managedPairStateReserve(state machineNodeControlState) int {
	reserved := localDomainStateReserve(state)
	for _, m := range state.ManagedPairLeases {
		if m.State == "RESERVED" {
			reserved += managedPairLeaseReserveBytes
		}
	}
	return reserved
}

func managedPairDigest(values ...any) string {
	data, _ := json.Marshal(values)
	sum := sha256.Sum256(append([]byte("cicada/managed-pair-lease/v1\x00"), data...))
	return hex.EncodeToString(sum[:])
}

// The accepted, signed original Describe and independently installed Owner
// pin remain authoritative. No latest-slot lookup or new proof is performed.
func (client *machineNodeControlClient) managedPairPreparationLocked(ctx context.Context, m machineManagedPairLease) (string, string, error) {
	describeID := localEndpointStepID(m.IntentID, m.IntentDigest, "describe")
	record, ok := client.state.NativePairReceipts[describeID]
	if !ok || record.Operation != wire.OperationNativePairNodeDescribe || record.PairID != m.Join.PairID || record.Fenced {
		return "", "", errManagedPairLeaseStopped
	}
	raw, err := client.openNativePairRecordedResultLocked(record)
	if err != nil {
		return "", "", errManagedPairLeaseStopped
	}
	d, err := wire.DecodeNativePairNodeDescription(raw)
	if err != nil || d.PairID != m.Join.PairID || wire.NativePairProofDigest(d.BootstrapOwnerProof) != m.Join.BootstrapProofDigest {
		return "", "", errManagedPairLeaseStopped
	}
	var proof e2ee.OwnerNativePairProof
	if json.Unmarshal(d.BootstrapOwnerProof, &proof) != nil || proof.Claims.Bootstrap == nil {
		return "", "", errManagedPairLeaseStopped
	}
	crypto, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(client.stateDir, client.nodeID))
	if err != nil {
		return "", "", err
	}
	defer crypto.Close()
	policy, err := crypto.NativePairPolicyForGroup(ctx, proof.Claims.Bootstrap.GroupID)
	if err != nil {
		return "", "", err
	}
	if policy.PairID != m.Join.PairID || policy.NodeID != client.nodeID || policy.BootstrapDigest != m.Join.BootstrapProofDigest || policy.HubIdentity.HubID != client.state.HubID {
		return "", "", errManagedPairLeaseStopped
	}
	trust, err := crypto.GetNodeOwnerKeyTrustLocalContext(ctx, proof.Claims.Scope.Actor.OwnerID, proof.Claims.Scope.Actor.OwnerPublic.ID)
	if err != nil {
		return "", "", err
	}
	if trust.State != nodekeys.NodeOwnerKeyTrustActive || !sameMachineNodeControlPublicIdentity(trust.PublicIdentity, proof.Claims.Scope.Actor.OwnerPublic) {
		return "", "", errManagedPairLeaseStopped
	}
	// Timestamps on the trust row are not authority coordinates. Key version,
	// independent fingerprint/public pin and the complete original policy are.
	pin := struct {
		Owner, Key, Fingerprint string
		Version                 int64
		Public                  e2ee.PublicIdentity
	}{trust.OwnerID, trust.KeyID, trust.ExpectedFingerprint, trust.Version, trust.PublicIdentity}
	return managedPairDigest(machineNodeControlBindingFromState(client), m.Join, policy, pin), policy.PeerExpiresAt, nil
}

func (client *machineNodeControlClient) collectManagedPairLeasesLocked(now time.Time) {
	for id, m := range client.state.ManagedPairLeases {
		if m.State != "STOPPED" {
			continue
		} // Unknown RESERVED records never expire into replacement authority.
		end := parseMachineNativePairTime(m.PeerCeiling)
		issued := parseMachineNativePairTime(m.IssuedAt)
		if m.NoEffect {
			end = issued.Add(localEndpointIntentTTL)
		}
		if end.IsZero() || now.Before(end) {
			continue
		}
		if issued.UnixMilli() > client.state.LocalEndpointAdmissionFloorMS {
			client.state.LocalEndpointAdmissionFloorMS = issued.UnixMilli()
		}
		delete(client.state.ManagedPairLeases, id)
	}
}

func (client *machineNodeControlClient) reserveManagedPairLease(ctx context.Context, q localEndpointRequest, digest string, join wire.NativePairNodeJoin, now time.Time) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	id := localEndpointStepID(q.RequestID, digest, "join")
	if old, ok := client.state.ManagedPairLeases[id]; ok {
		if old.IntentID != q.RequestID || old.IntentDigest != digest || old.Join != join {
			return errLocalEndpointIntentConflict
		}
		if old.State == "STOPPED" {
			if old.NoEffect {
				return errNativePairNodeRejected
			}
			return errManagedPairLeaseStopped
		}
		if old.State != "ACTIVE" && old.State != "RESERVED" {
			return errManagedPairLeaseStopped
		}
		preparation, ceiling, err := client.managedPairPreparationLocked(ctx, old)
		if err != nil {
			return err
		}
		if preparation != old.PreparationDigest || ceiling != old.PeerCeiling {
			return errManagedPairLeaseStopped
		}
		return nil
	}
	issued, err := localEndpointIssuedAt(q)
	if err != nil || issued.UnixMilli() <= client.state.LocalEndpointAdmissionFloorMS || !now.Before(issued.Add(localEndpointIntentTTL)) {
		return errLocalEndpointReceiptExpired
	}
	intent, ok := client.state.LocalEndpointIntents[q.RequestID]
	if !ok || intent.Digest != digest || intent.Operation != "native_pair_join_named" {
		return errLocalEndpointIntentConflict
	}
	previous := cloneMachineNodeControlState(client.state)
	client.collectManagedPairLeasesLocked(now)
	if issued.UnixMilli() <= client.state.LocalEndpointAdmissionFloorMS {
		client.state = previous
		return errLocalEndpointReceiptExpired
	}
	live := 0
	for _, m := range client.state.ManagedPairLeases {
		if m.State == "RESERVED" || m.State == "ACTIVE" {
			live++
		}
	}
	if live >= maxManagedPairLiveLeases {
		client.state = previous
		return errManagedPairLeaseFull
	}
	m := machineManagedPairLease{IntentID: q.RequestID, IntentDigest: digest, IssuedAt: q.IssuedAt, JoinOperationID: id, Join: join, State: "RESERVED"}
	m.PreparationDigest, m.PeerCeiling, err = client.managedPairPreparationLocked(ctx, m)
	if err != nil || !now.Before(parseMachineNativePairTime(m.PeerCeiling)) {
		client.state = previous
		if err != nil {
			return err
		}
		return errManagedPairLeaseStopped
	}
	if client.state.ManagedPairLeases == nil {
		client.state.ManagedPairLeases = make(map[string]machineManagedPairLease)
	}
	client.state.ManagedPairLeases[id] = m
	data, _ := json.Marshal(client.state)
	if len(data)+managedPairStateReserve(client.state)+localEndpointResponseReserve >= maxMachineNodeControlStateBytes {
		client.state = previous
		return errManagedPairLeaseFull
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (client *machineNodeControlClient) managedPairOriginalLocked(ctx context.Context, m machineManagedPairLease) (*fabric.JoinResult, string, error) {
	record, ok := client.state.NativePairReceipts[m.JoinOperationID]
	if !ok || record.Operation != wire.OperationNativePairNodeJoin || record.PairID != m.Join.PairID || record.Fenced {
		return nil, "", errManagedPairLeaseStopped
	}
	body, err := nativePairNodeBody(record.Operation, record.RequestBody)
	if err != nil || body.(wire.NativePairNodeJoin) != m.Join {
		return nil, "", errManagedPairLeaseStopped
	}
	raw, err := client.openNativePairRecordedResultLocked(record)
	if err != nil {
		return nil, "", errManagedPairLeaseStopped
	}
	var decoded fabric.JoinResult
	if decodeMachineNodeControlJSON(raw, &decoded) != nil {
		return nil, "", errManagedPairLeaseStopped
	}
	crypto, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(client.stateDir, client.nodeID))
	if err != nil {
		return nil, "", err
	}
	defer crypto.Close()
	policy, err := crypto.NativePairPolicyForGroup(ctx, decoded.Endpoint.GroupID)
	if err != nil {
		return nil, "", err
	}
	joined, err := client.validateNativePairJoinResultWithPolicyLocked(m.Join, raw, policy)
	if err != nil {
		return nil, "", errManagedPairLeaseStopped
	}
	return joined, managedPairDigest(m.PreparationDigest, wire.NativePairNodePacketDigest(record.ResponsePacket)), nil
}

func (client *machineNodeControlClient) activateManagedPairLease(ctx context.Context, q localEndpointRequest, digest string, joined *fabric.JoinResult, scope *nodeinbox.NativeContextScopeDecision, now time.Time) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	id := localEndpointStepID(q.RequestID, digest, "join")
	m, ok := client.state.ManagedPairLeases[id]
	if !ok || m.State == "STOPPED" || (m.State != "RESERVED" && m.State != "ACTIVE") || scope == nil || !scope.Accepted {
		return errManagedPairLeaseStopped
	}
	preparation, ceiling, err := client.managedPairPreparationLocked(ctx, m)
	if err != nil {
		return err
	}
	if preparation != m.PreparationDigest || ceiling != m.PeerCeiling {
		return errManagedPairLeaseStopped
	}
	original, frozen, err := client.managedPairOriginalLocked(ctx, m)
	if err != nil {
		return err
	}
	if joined == nil || joined.Endpoint.ID != original.Endpoint.ID || joined.Endpoint.PrincipalID != original.Endpoint.PrincipalID || joined.Endpoint.GroupID != original.Endpoint.GroupID || joined.Endpoint.MachineID != original.Endpoint.MachineID || joined.Endpoint.NativeSessionID != original.Endpoint.NativeSessionID || joined.Endpoint.Workspace != original.Endpoint.Workspace || joined.SessionToken != original.SessionToken || joined.BindingID != original.BindingID || joined.BindingEpoch != original.BindingEpoch {
		return errManagedPairLeaseStopped
	}
	if m.FrozenDigest != "" && m.FrozenDigest != frozen {
		return errManagedPairLeaseStopped
	}
	end := parseMachineNativePairTime(joined.LeaseExpiresAt)
	if !now.Before(end) || end.After(parseMachineNativePairTime(m.PeerCeiling)) {
		return errManagedPairLeaseStopped
	}
	previous := cloneMachineNodeControlState(client.state)
	m.State, m.FrozenDigest, m.KnownLeaseExpiresAt = "ACTIVE", frozen, joined.LeaseExpiresAt
	client.state.ManagedPairLeases[id] = m
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (client *machineNodeControlClient) stopManagedPairLease(id, frozen, code string, noEffect bool) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	m, ok := client.state.ManagedPairLeases[id]
	if !ok || m.State == "STOPPED" || frozen != "" && m.FrozenDigest != frozen {
		return nil
	}
	previous := cloneMachineNodeControlState(client.state)
	m.State, m.StopCode, m.NoEffect = "STOPPED", code, noEffect
	client.state.ManagedPairLeases[id] = m
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

// All three independently retained coordinates must prove absence. In
// particular a missing/new marker after an upgrade says nothing about dispatch.
func (client *machineNodeControlClient) namedJoinUndispatchedLocked(id, digest string) bool {
	intent, ok := client.state.LocalEndpointIntents[id]
	if !ok || intent.Digest != digest || intent.Operation != "native_pair_join_named" {
		return false
	}
	joinID := localEndpointStepID(id, digest, "join")
	if client.state.PendingOperationID == joinID {
		return false
	}
	if len(client.state.PendingPacket) > 0 {
		packet, err := nodewire.DecodePacket(client.state.PendingPacket)
		if err != nil || packet.Route.OperationID == joinID {
			return false
		}
	}
	if _, ok := client.state.NativePairReceipts[joinID]; ok {
		return false
	}
	if step, ok := intent.Steps[joinID]; ok && (step.Settled || len(step.RequestPacket) > 0 || len(step.ResponsePacket) > 0) {
		return false
	}
	return true
}

func (client *machineNodeControlClient) localNamedJoinRefused(id, digest string) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	intent, ok := client.state.LocalEndpointIntents[id]
	return ok && intent.Digest == digest && intent.Operation == "native_pair_join_named" && intent.LocalJoinRefused
}

// Persist the original command's no-dispatch fence before permitting its client
// to ACK. A later capacity/label repair can authorize only a fresh command.
func (client *machineNodeControlClient) fenceLocalNamedJoinRefusal(id, digest string) (bool, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if !client.namedJoinUndispatchedLocked(id, digest) {
		return false, nil
	}
	previous := cloneMachineNodeControlState(client.state)
	intent := client.state.LocalEndpointIntents[id]
	if intent.LocalJoinRefused {
		return true, nil
	}
	intent.LocalJoinRefused = true
	client.state.LocalEndpointIntents[id] = intent
	joinID := localEndpointStepID(id, digest, "join")
	if m, ok := client.state.ManagedPairLeases[joinID]; ok {
		if m.State != "RESERVED" {
			client.state = previous
			return false, nil
		}
		m.State, m.StopCode, m.NoEffect = "STOPPED", "JOIN_NOT_DISPATCHED", true
		client.state.ManagedPairLeases[joinID] = m
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return false, err
	}
	return true, nil
}

func (client *machineNodeControlClient) stopManagedPairLeasesForNative(harness, sid, workspace string) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	previous := cloneMachineNodeControlState(client.state)
	for id, m := range client.state.ManagedPairLeases {
		if m.Join.Runtime == harness && m.Join.NativeSessionID == sid && m.Join.Workspace == workspace {
			m.State, m.StopCode = "STOPPED", "EXPLICIT_LEAVE"
			client.state.ManagedPairLeases[id] = m
		}
	}
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (b *machineAgentJoinBridge) runManagedPairLeaseWorker() {
	defer b.wg.Done()
	ticker := time.NewTicker(managedPairLeaseInterval)
	defer ticker.Stop()
	for {
		if b.localDomainReportsEnabled.Load() {
			b.refreshLocalDomainReport(b.ctx, time.Now)
		}
		b.renewManagedPairLeaseBatch(b.ctx, time.Now)
		b.renewEndpointGroupsRegistrationBatch(b.ctx)
		b.renewLocalDomainLeaseBatch(b.ctx)
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
		case <-b.managedLeaseWake:
		}
	}
}

type managedPairLeaseUpdate struct {
	ID, FrozenDigest, LeaseExpiresAt, StopCode string
}

func (b *machineAgentJoinBridge) renewManagedPairLeaseBatch(ctx context.Context, clock func() time.Time) {
	b.managedLeaseMu.Lock()
	defer b.managedLeaseMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	client, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return
	}
	client.mu.Lock()
	var ids []string
	for id, m := range client.state.ManagedPairLeases {
		if m.State == "ACTIVE" {
			ids = append(ids, id)
		}
	}
	client.mu.Unlock()
	sort.Strings(ids)
	if len(ids) == 0 {
		return
	}
	start := b.managedLeaseNext % len(ids)
	count := len(ids)
	if count > managedPairLeaseBatch {
		count = managedPairLeaseBatch
	}
	var updates []managedPairLeaseUpdate
	for i := 0; i < count && ctx.Err() == nil; i++ {
		deadline, cancel := context.WithTimeout(ctx, managedPairLeaseRequestTimeout)
		update := b.prepareManagedPairLeaseRenewal(deadline, client, ids[(start+i)%len(ids)], clock)
		cancel()
		if update != nil {
			updates = append(updates, *update)
		}
	}
	// Re-read current state under the shared lock; never restore a snapshot
	// taken before HTTP over a concurrent outbox, activation or Leave.
	_ = client.applyManagedPairLeaseUpdates(updates, clock)
	b.managedLeaseNext = (start + count) % len(ids)
}

func (b *machineAgentJoinBridge) prepareManagedPairLeaseRenewal(ctx context.Context, client *machineNodeControlClient, id string, clock func() time.Time) *managedPairLeaseUpdate {
	client.mu.Lock()
	m, ok := client.state.ManagedPairLeases[id]
	if !ok || m.State != "ACTIVE" {
		client.mu.Unlock()
		return nil
	}
	stop := func(code string) *managedPairLeaseUpdate {
		return &managedPairLeaseUpdate{ID: id, FrozenDigest: m.FrozenDigest, StopCode: code}
	}
	now := clock().UTC()
	if !now.Before(parseMachineNativePairTime(m.PeerCeiling)) || !now.Before(parseMachineNativePairTime(m.KnownLeaseExpiresAt)) {
		client.mu.Unlock()
		return stop("LEASE_OR_CEILING_EXPIRED")
	}
	preparation, ceiling, err := client.managedPairPreparationLocked(ctx, m)
	var joined *fabric.JoinResult
	var frozen string
	if err == nil && preparation == m.PreparationDigest && ceiling == m.PeerCeiling {
		joined, frozen, err = client.managedPairOriginalLocked(ctx, m)
	} else if err == nil {
		err = errManagedPairLeaseStopped
	}
	client.mu.Unlock()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		if errors.Is(err, errManagedPairLeaseStopped) || errors.Is(err, sql.ErrNoRows) || errors.Is(err, nodekeys.ErrNodeOwnerKeyTrustNotFound) || errors.Is(err, nodekeys.ErrNodeOwnerKeyTrustRevoked) || errors.Is(err, nodekeys.ErrNativePairPolicy) {
			return stop("FROZEN_AUTHORITY_CHANGED")
		}
		return nil // Unproven local I/O/busy failures neither POST nor tombstone.
	}
	if frozen != m.FrozenDigest {
		return stop("FROZEN_AUTHORITY_CHANGED")
	}
	now = clock().UTC()
	if !now.Before(parseMachineNativePairTime(m.PeerCeiling)) || !now.Before(parseMachineNativePairTime(m.KnownLeaseExpiresAt)) {
		return stop("LEASE_OR_CEILING_EXPIRED")
	}
	raw, err := b.httpWithAuthorizationContext(ctx, http.MethodPost, "/v2/fabric/heartbeat", nil, "CicadaSession "+joined.SessionToken, joined.Endpoint.GroupID)
	if err != nil {
		if !localSealedSendRetryable(err) {
			return stop("CURRENT_GUARD_REFUSED")
		}
		return nil
	}
	var actor fabric.Actor
	end := time.Time{}
	if decodeStrictBridgeJSON(raw, &actor) == nil {
		end = parseMachineNativePairTime(actor.LeaseExpiresAt)
	}
	now = clock().UTC() // A delayed reply cannot borrow the batch's old clock.
	if actor.EndpointID != joined.Endpoint.ID || actor.GroupID != joined.Endpoint.GroupID || actor.BindingID != joined.BindingID || actor.BindingEpoch != joined.BindingEpoch || !now.Before(end) || !now.Before(parseMachineNativePairTime(m.PeerCeiling)) || end.After(parseMachineNativePairTime(m.PeerCeiling)) {
		return stop("HEARTBEAT_CONTEXT_INVALID")
	}
	return &managedPairLeaseUpdate{ID: id, FrozenDigest: m.FrozenDigest, LeaseExpiresAt: actor.LeaseExpiresAt}
}

func (client *machineNodeControlClient) applyManagedPairLeaseUpdates(updates []managedPairLeaseUpdate, clock func() time.Time) error {
	if len(updates) == 0 {
		return nil
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	previous := cloneMachineNodeControlState(client.state)
	changed := false
	for _, update := range updates {
		m, ok := client.state.ManagedPairLeases[update.ID]
		if !ok || m.State != "ACTIVE" || m.FrozenDigest != update.FrozenDigest {
			continue
		} // Concurrent Leave/stop wins.
		now := clock().UTC()
		end := parseMachineNativePairTime(update.LeaseExpiresAt)
		if update.StopCode != "" {
			m.State, m.StopCode = "STOPPED", update.StopCode
			changed = true
		} else if !now.Before(end) || !now.Before(parseMachineNativePairTime(m.PeerCeiling)) || end.After(parseMachineNativePairTime(m.PeerCeiling)) {
			m.State, m.StopCode = "STOPPED", "LEASE_OR_CEILING_EXPIRED"
			changed = true
		} else if end.After(parseMachineNativePairTime(m.KnownLeaseExpiresAt)) {
			m.KnownLeaseExpiresAt = update.LeaseExpiresAt
			changed = true
		}
		client.state.ManagedPairLeases[update.ID] = m
	}
	if !changed {
		return nil
	} // Equal/older heartbeat metadata causes no disk write.
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}
