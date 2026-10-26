package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Only issuer verification uses this read fence. An invocation may recover its
// exact registration Describe; it cannot recover another intent's pending write.
type endpointGroupsIssueReadKey struct{}
type endpointGroupsIssueReadScope struct {
	Request  wire.EndpointGroupsNodeDescribe
	Original []byte
}

func endpointGroupsNodePendingEmpty(s machineNodeControlState) bool {
	return len(s.PendingPacket) == 0 && s.PendingOperation == "" && s.PendingOperationID == "" && s.PendingSequence == 0 && s.PendingPlaintextDigest == "" && len(s.PendingResponsePacket) == 0 && s.PendingLocalEndpointIntentID == ""
}

// Caller holds c.mu. The original plaintext digest, complete Node route and
// optional exact packet fence are checked before any recovery dispatch.
func (c *machineNodeControlClient) endpointGroupsIssuePendingReadLocked(scope *endpointGroupsIssueReadScope) bool {
	if len(c.state.PendingPacket) == 0 {
		return endpointGroupsNodePendingEmpty(c.state)
	}
	if c.state.PendingOperation != wire.OperationEndpointGroupsNodeDescribe || c.state.PendingLocalEndpointIntentID != "" || len(scope.Original) != 0 && !bytes.Equal(scope.Original, c.state.PendingPacket) {
		return false
	}
	plain, err := wire.CanonicalEndpointGroupsNodeRequest(wire.OperationEndpointGroupsNodeDescribe, scope.Request)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(plain)
	packet, err := wire.DecodeEndpointGroupsNodePacket(c.state.PendingPacket)
	if err != nil || hex.EncodeToString(digest[:]) != c.state.PendingPlaintextDigest {
		return false
	}
	r := packet.Route
	b := machineNodeControlBindingFromState(c)
	return r.Direction == nodewire.DirectionRequest && r.Operation == wire.OperationEndpointGroupsNodeDescribe && r.OperationID == c.state.PendingOperationID && r.Sequence == c.state.PendingSequence && r.HubID == b.HubID && r.NodeID == b.NodeID && r.BindingID == b.BindingID && r.BindingVersion == b.BindingVersion && r.NodeKeyEpoch == b.NodeKeyEpoch && r.SenderKeyID == b.NodeKey.ID && r.SenderKeyVersion == b.NodeKeyVersion && r.ReceiverKeyID == b.HubKey.ID && r.ReceiverKeyVersion == b.HubKeyVersion
}

func (b *machineAgentJoinBridge) endpointGroupsOriginalHub(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration) (wire.HubIdentity, error) {
	_, _, completed, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return wire.HubIdentity{}, err
	}
	state, err := nodekeys.OpenExistingCryptoState(ctx, machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return wire.HubIdentity{}, err
	}
	defer state.Close()
	p, err := state.LocalDomainPolicyForGroup(ctx, completed.Description.Policy.GroupID)
	if err != nil || p.Hub.HubID != completed.Description.Policy.HubID || p.Policy.Origin != b.baseURL || !reflect.DeepEqual(p.Policy, completed.Description.Policy) {
		return wire.HubIdentity{}, errEndpointGroupsRegistration
	}
	binding := c.approvedBinding()
	if binding.HubID != p.Policy.HubID || !machineSamePublicIdentity(binding.HubKey, p.Policy.Node.HubNodeControlPublic) {
		return wire.HubIdentity{}, errEndpointGroupsRegistration
	}
	return p.Hub, nil
}

func (b *machineAgentJoinBridge) endpointGroupsAvailable(ctx context.Context, hub wire.HubIdentity) error {
	var raw machineNativePairRawJSON
	if err := machineAPIJSON(ctx, b.baseURL+wire.OwnerEndpointGroupsCapabilitiesPath, http.MethodGet, nil, &raw); err != nil {
		return errEndpointGroupsUnsupported
	}
	caps, err := wire.DecodeOwnerEndpointGroupsCapabilities(raw, hub)
	if err != nil || !caps.Available || !caps.NativeSelfGroups {
		return errEndpointGroupsUnsupported
	}
	return nil
}

// Registration candidates come only from original, completed, protected local
// receipts. The native session directory is never enumerated or substituted.
func (c *machineNodeControlClient) endpointGroupsRegistrationCandidate(sid, cwd string) (machineEndpointGroupsRegistration, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var found *machineEndpointGroupsRegistration
	for _, r := range c.state.EndpointGroupsRegistrations {
		if r.Anchor.Registration.NativeSessionID == sid && r.Anchor.Registration.Workspace == cwd {
			if found != nil {
				return machineEndpointGroupsRegistration{}, true, errEndpointGroupsRegistration
			}
			copy := r
			found = &copy
		}
	}
	if found != nil {
		raw, _ := json.Marshal(found)
		var copy machineEndpointGroupsRegistration
		if json.Unmarshal(raw, &copy) != nil {
			return machineEndpointGroupsRegistration{}, true, errEndpointGroupsRegistration
		}
		return copy, true, nil
	}
	var originalBinding, originalEndpoint, originalNetwork string
	for id, m := range c.state.ManagedLocalDomainLeases {
		if m.Join.NativeSessionID != sid || m.Join.Workspace != cwd || m.TranscriptPath == "" {
			continue
		}
		var j wire.LocalDomainNodeJoinResult
		var completed wire.LocalDomainNodeKeyResult
		if c.localDomainOriginalLocked(m, "domain.join", &j) != nil || c.localDomainOriginalLocked(m, "domain.complete", &completed) != nil || j.SessionToken == "" {
			continue
		}
		if found != nil && (originalBinding != j.Member.BindingID || originalEndpoint != j.Member.EndpointID || originalNetwork != completed.Description.Policy.NetworkID) {
			return machineEndpointGroupsRegistration{}, false, errEndpointGroupsUnsupported
		}
		if found == nil || id < found.LeaseID {
			r := machineEndpointGroupsRegistration{LeaseID: id, IntentID: m.IntentID, IntentDigest: m.IntentDigest, TranscriptPath: m.TranscriptPath}
			found = &r
		}
		originalBinding, originalEndpoint, originalNetwork = j.Member.BindingID, j.Member.EndpointID, completed.Description.Policy.NetworkID
	}
	if found == nil {
		return machineEndpointGroupsRegistration{}, false, errEndpointGroupsUnsupported
	}
	return *found, false, nil
}

func (b *machineAgentJoinBridge) describeEndpointGroups(ctx context.Context, c *machineNodeControlClient, r machineEndpointGroupsRegistration, cursor string, limit int) (machineEndpointGroupsRegistration, wire.EndpointGroupsNodeDescribeResult, error) {
	if r.LocalAccessRevision == 0 {
		r.LocalAccessRevision = 1
	}
	hub, err := b.endpointGroupsOriginalHub(ctx, c, r)
	if err != nil {
		return r, wire.EndpointGroupsNodeDescribeResult{}, err
	}
	if err := b.endpointGroupsAvailable(ctx, hub); err != nil {
		return r, wire.EndpointGroupsNodeDescribeResult{}, err
	}
	_, _, original, err := c.endpointGroupsOriginal(r)
	if err != nil {
		return r, wire.EndpointGroupsNodeDescribeResult{}, err
	}
	q := wire.EndpointGroupsNodeDescribe{EndpointID: original.Member.EndpointID, NetworkID: original.Description.Policy.NetworkID, Cursor: cursor, Limit: limit}
	scope, issuer := ctx.Value(endpointGroupsIssueReadKey{}).(*endpointGroupsIssueReadScope)
	if issuer {
		scope.Request = q
	}
	if err := c.recoverNodeControlPending(ctx, b.nodeToken); err != nil {
		if issuer && !errors.Is(err, errLocalEndpointReceiptExpired) {
			return r, wire.EndpointGroupsNodeDescribeResult{}, err
		}
		c.mu.Lock()
		unsettled := len(c.state.PendingPacket) > 0
		c.mu.Unlock()
		if unsettled {
			return r, wire.EndpointGroupsNodeDescribeResult{}, err
		}
	}
	if err := b.retireEndpointGroupsChallenges(ctx, c, r, hub); err != nil {
		return r, wire.EndpointGroupsNodeDescribeResult{}, err
	}
	var d wire.EndpointGroupsNodeDescribeResult
	if err := c.call(ctx, b.nodeToken, wire.OperationEndpointGroupsNodeDescribe, q, &d); err != nil {
		return r, d, err
	}
	now := time.Now().UTC()
	if wire.ValidateEndpointGroupsNodeDescribeResult(d, hub, now) != nil || d.Registration.Registration.EndpointID != q.EndpointID || d.Registration.NetworkID != q.NetworkID ||
		b.validateEndpointGroupsRegistration(ctx, c, r, d.Registration, hub) != nil {
		return r, d, errEndpointGroupsRegistration
	}
	if r.Anchor.RegistrationDigest != "" && (!sameEndpointGroupsAnchor(r.Anchor, d.Registration) || d.RelationsRevision < r.RelationsRevision) {
		return r, d, errEndpointGroupsRegistration
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return r, d, err
	}
	defer state.Close()
	// An authenticated terminal observation advances deny only. Pending/manual
	// provenance never takes over an existing active default contribution.
	for _, relation := range d.Relations {
		if relation.OwnerControl.Mode == "OWNER" && (relation.OwnerControl.DenyReason == "REMOVED" || relation.OwnerControl.DenyReason == "EXPIRED") {
			if err := state.ObserveEndpointGroupOwnerControl(ctx, d.Registration, relation.GroupID, relation.OwnerControl, now); err != nil {
				return r, d, err
			}
		}
	}
	if d.RelationsRevision != r.RelationsRevision {
		r.Authorities = nil
	}
	r.Authorities = append([]wire.EndpointGroupCurrentEndpoint(nil), r.Authorities...)
	for _, relation := range d.Relations {
		kept := r.Authorities[:0]
		for _, a := range r.Authorities {
			if a.Relation.GroupID != relation.GroupID {
				kept = append(kept, a)
			}
		}
		r.Authorities = kept
	}
	r.Authorities = append(r.Authorities, d.Authorities...)
	sort.Slice(r.Authorities, func(i, j int) bool { return r.Authorities[i].Relation.GroupID < r.Authorities[j].Relation.GroupID })
	for i, a := range r.Authorities {
		if i > 0 && r.Authorities[i-1].Relation.GroupID == a.Relation.GroupID {
			return r, d, errEndpointGroupsRegistration
		}
	}
	if len(r.Authorities) > 32 {
		return r, d, errManagedPairLeaseFull
	}
	r.Anchor, r.RelationsRevision, r.ObservedAt = d.Registration, d.RelationsRevision, d.ObservedAt
	if err := c.saveEndpointGroupsRegistration(r); err != nil {
		return r, d, err
	}
	return r, d, nil
}

func (b *machineAgentJoinBridge) endpointGroupsVerificationProfile(q localCodexContextIssue) (localCodexContext, bool, error) {
	deadline := q.verifyDeadline
	if deadline.IsZero() {
		deadline = time.Now().Add(30 * time.Second)
	}
	verification, finish := context.WithDeadline(b.ctx, deadline)
	defer finish()
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	if err := verification.Err(); err != nil {
		return localCodexContext{}, false, err
	}
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return localCodexContext{}, false, err
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil {
		if !enrolled && errors.Is(err, errEndpointGroupsUnsupported) {
			return localCodexContext{}, false, nil
		}
		return localCodexContext{}, enrolled, err
	}
	if enrolled && q.ToolName == "codex.operator.endpoint_leave" {
		if r.TranscriptPath != q.TranscriptPath || verifyCodexContextTranscriptProfile(r.TranscriptPath, q.NativeSessionID, q.Workspace, true) != nil {
			return localCodexContext{}, true, errEndpointGroupsRegistration
		}
		return endpointGroupsContextForAnchor(r.Anchor, q), true, nil
	}
	if enrolled && r.LocallyOffline && q.ToolName != "codex.operator.endpoint_register" {
		return localCodexContext{}, true, errEndpointGroupsOffline
	}
	// Known enrollment is never downgraded if the Hub later becomes unsupported.
	scope := &endpointGroupsIssueReadScope{}
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.WithValue(verification, endpointGroupsIssueReadKey{}, scope), 5*time.Second)
		var next machineEndpointGroupsRegistration
		next, _, err = b.describeEndpointGroups(ctx, c, r, "", 64)
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded)
		cancel()
		if err == nil {
			r = next
			break
		}
		if attempt != 0 || !timedOut || verification.Err() != nil {
			break
		}
		c.mu.Lock()
		retry := len(c.state.PendingPacket) > 0 && len(c.state.PendingResponsePacket) == 0 && c.endpointGroupsIssuePendingReadLocked(scope)
		if retry {
			scope.Original = bytes.Clone(c.state.PendingPacket)
		}
		c.mu.Unlock()
		if !retry {
			break
		}
	}
	if err != nil {
		if !enrolled && errors.Is(err, errEndpointGroupsUnsupported) {
			return localCodexContext{}, false, nil
		}
		return localCodexContext{}, true, err
	}
	if r.Anchor.Registration.NativeSessionID != q.NativeSessionID || r.Anchor.Registration.Workspace != q.Workspace || r.TranscriptPath != q.TranscriptPath {
		return localCodexContext{}, true, errEndpointGroupsRegistration
	}
	if err := verification.Err(); err != nil {
		return localCodexContext{}, true, err
	}
	return endpointGroupsContextForAnchor(r.Anchor, q), true, nil
}
