package hubaccountwire

import (
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func nodePairScopedPublic(c NodePairTrustScopedContext) e2ee.PublicIdentity {
	if c.Mode == NodePairTrustScopedInitial && c.Candidate != nil {
		return c.Candidate.NodePublic
	}
	if c.Mode == NodePairTrustScopedExisting && c.Binding != nil {
		return c.Binding.NodePublic
	}
	return e2ee.PublicIdentity{}
}
func ValidateNodePairTrustScopedContext(c NodePairTrustScopedContext, now time.Time) error {
	if validateNodePairScopedContextEnvelope(c, now) != nil {
		return ErrInvalid
	}
	return validateNodePairScopedContextBinding(c)
}
func validateNodePairScopedContextEnvelope(c NodePairTrustScopedContext, now time.Time) error {
	if c.ScopeVersion != AppNodeScopedScopeVersion || !appNodeScopedNodeID(c.AuthorityNodeID) || c.Format != NodePairTrustScopedFormat || !isHex(c.AttemptID, 16) || validateHubIdentity(c.Hub) != nil || len(c.Hub.HubID) > 96 || !nodePairOrigin(c.Origin) || !isHex(c.DescriptorDigest, 32) || !isHex(c.NodeNonce, 32) || nodePairWindow(c.IssuedAt, c.ExpiresAt, 10*time.Minute, now) != nil {
		return ErrInvalid
	}
	return nil
}
func validateNodePairScopedContextBinding(c NodePairTrustScopedContext) error {
	var nc e2ee.PublicIdentity
	switch c.Mode {
	case NodePairTrustScopedInitial:
		if c.Candidate == nil || c.Binding != nil || c.Candidate.NodeID != c.AuthorityNodeID || ValidateAppNodeCandidate(*c.Candidate, c.Hub.HubID) != nil {
			return ErrInvalid
		}
		end, _ := parseCanonicalUTC(c.ExpiresAt)
		candidateEnd, _ := parseCanonicalUTC(c.Candidate.ExpiresAt)
		if end.After(candidateEnd) {
			return ErrInvalid
		}
		nc = c.Candidate.HubNodeControlPublic
	case NodePairTrustScopedExisting:
		if c.Binding == nil || c.Candidate != nil || c.Binding.NodeID != c.AuthorityNodeID {
			return ErrInvalid
		}
		b := c.Binding
		if b.HubID != c.Hub.HubID || b.State != "ACTIVE" || !validID(b.OwnerBindingID) || !validID(b.OwnerID) || !validID(b.NodeID) || !validID(b.ClientDeviceID) || !validID(b.OwnerKeyID) || !validID(b.ApprovedRequestID) || !isHex(b.ApprovedCandidateDigest, 32) || validateCanonicalTime(b.ApprovedAt) != nil || e2ee.ValidatePublicIdentity(b.NodePublic) != nil || e2ee.ValidatePublicIdentity(b.HubNodeControlPublic) != nil || b.NodePublic.ID == b.HubNodeControlPublic.ID || b.NodeKeyFingerprint != nodewire.IdentityFingerprint(b.NodePublic) || b.HubNodeControlFingerprint != nodewire.IdentityFingerprint(b.HubNodeControlPublic) {
			return ErrInvalid
		}
		for _, n := range []uint64{b.CredentialVersion, b.BindingVersion, b.NodeKeyVersion, b.NodeKeyEpoch, b.HubNodeControlKeyVersion, b.ApprovedRequestVersion} {
			if n == 0 || n > math.MaxInt64 {
				return ErrInvalid
			}
		}
		nc = b.HubNodeControlPublic
	default:
		return ErrInvalid
	}
	if nc.ID == c.Hub.Public.ID || nodePairScopedPublic(c).ID == c.Hub.Public.ID {
		return ErrInvalid
	}
	return nil
}

func ValidateNodePairTrustScopedApproval(a NodePairTrustScopedApproval, c NodePairTrustScopedContext, o string, now time.Time) error {
	d, err := NodePairTrustScopedContextDigest(c)
	if err != nil || a.Format != NodePairTrustScopedFormat || a.ContextDigest != d || !isHex(o, 32) || a.OOBCommitment != o || ValidateAppNodeScopedScope(a.Scope, c.Hub) != nil || a.Scope.Version != c.ScopeVersion || a.Scope.AuthorityNodeID != c.AuthorityNodeID || a.Scope.Origin != c.Origin || !isHex(a.PrepareRequestID, 16) || !isHex(a.PreparePacketDigest, 32) || !isHex(a.ServerNonce, 32) || nodePairWindow(a.PreparedAt, a.AcceptBefore, 5*time.Minute, now) != nil {
		return ErrInvalid
	}
	prepared, _ := parseCanonicalUTC(a.PreparedAt)
	issued, _ := parseCanonicalUTC(c.IssuedAt)
	end, _ := parseCanonicalUTC(a.AcceptBefore)
	if prepared.Before(issued.Add(-30 * time.Second)) {
		return ErrInvalid
	}
	for _, text := range []string{c.ExpiresAt, a.Scope.AccountSessionExpiresAt} {
		limit, e := parseCanonicalUTC(text)
		if e != nil || end.After(limit) {
			return ErrInvalid
		}
	}
	if c.Mode == NodePairTrustScopedInitial {
		if !isHex(a.GrantID, 16) || !isHex(a.GrantProofDigest, 32) || !isHex(a.ConfirmationPacketDigest, 32) || a.Scope.HeadVersion == 0 {
			return ErrInvalid
		}
	} else if a.GrantID != "" || a.GrantProofDigest != "" || a.ConfirmationPacketDigest != "" || c.Binding.OwnerID != a.Scope.OwnerID || c.Binding.OwnerKeyID != a.Scope.OwnerPublic.ID {
		return ErrInvalid
	}
	return nil
}

// This validates the retained INITIAL grant and public original-packet route.
// The Hub must additionally open that exact Client packet and run its existing
// transaction/counter/Guard code at ACK. This function grants no admission.
func ValidateNodePairTrustScopedInitialAuthorization(c NodePairTrustScopedContext, a NodePairTrustScopedApproval, grantRaw, confirmRaw []byte, now time.Time) error {
	if ValidateNodePairTrustScopedApproval(a, c, a.OOBCommitment, now) != nil {
		return ErrInvalid
	}
	if c.Mode == NodePairTrustScopedExisting {
		if len(grantRaw) != 0 || len(confirmRaw) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if len(grantRaw) == 0 || len(grantRaw) > e2ee.MaxOwnerAppNodeScopedProofBytes || len(confirmRaw) == 0 || len(confirmRaw) > MaxAppNodeScopedMutationPacketBytes || a.GrantProofDigest != AppNodeScopedProofDigest(grantRaw) || a.ConfirmationPacketDigest != AppNodeScopedPacketDigest(confirmRaw) {
		return ErrInvalid
	}
	g, err := e2ee.VerifyOwnerAppNodeScopedGrant(a.Scope.OwnerPublic, grantRaw, now)
	if err != nil || ValidateAppNodeScopedGrantClaims(g, c.Hub, now) != nil || g.Profile != AppNodeScopedProfileInitial || !reflect.DeepEqual(g.Scope, a.Scope) || g.GrantID != a.GrantID || !reflect.DeepEqual(g.Candidate, c.Candidate) {
		return ErrInvalid
	}
	end, _ := parseCanonicalUTC(a.AcceptBefore)
	for _, text := range []string{g.ProofExpiresAt, g.LeaseExpiresAt} {
		limit, _ := parseCanonicalUTC(text)
		if end.After(limit) {
			return ErrInvalid
		}
	}
	var p clientwire.Packet
	if decodeCanonical(confirmRaw, MaxAppNodeScopedMutationPacketBytes, &p) != nil {
		return ErrInvalid
	}
	r := p.Route
	grantID, _, e := ParseAppNodeScopedBusinessOperationID(r.OperationID)
	if e != nil || grantID != g.GrantID || r.Version != 1 || r.Direction != clientwire.DirectionRequest || r.Operation != "nodes.confirm" || r.HubID != c.Hub.HubID || r.OwnerID != a.Scope.OwnerID || r.DeviceID != a.Scope.DeviceID || r.SessionEpoch != a.Scope.ClientSessionEpoch || r.Sequence == 0 || r.Sequence > math.MaxInt64 || r.SenderKeyID != a.Scope.DevicePublic.ID || r.ReceiverKeyID != c.Hub.Public.ID || r.SenderKeyVersion != 1 || r.ReceiverKeyVersion != c.Hub.KeyVersion {
		return ErrInvalid
	}
	return nil
}

// Caller supplies its locally S-verified approval and authenticated ACKED
// receipt. Historical matching is not permission to install a first pin late.
func ValidateNodePairTrustScopedAccepted(c NodePairTrustScopedContext, a NodePairTrustScopedApproval, b e2ee.OwnerAppNodeBinding) error {
	if ValidateNodePairTrustScopedApproval(a, c, a.OOBCommitment, time.Time{}) != nil {
		return ErrInvalid
	}
	if c.Mode == NodePairTrustScopedExisting {
		if !reflect.DeepEqual(*c.Binding, b) {
			return ErrInvalid
		}
		return nil
	}
	g := e2ee.OwnerAppNodeScopedGrantClaims{Profile: AppNodeScopedProfileInitial, Scope: a.Scope, Candidate: c.Candidate, PreparedAt: a.PreparedAt, LeaseExpiresAt: a.AcceptBefore}
	return ValidateAppNodeScopedConfirmationBinding(g, b)
}

func NodePairTrustScopedHTTPPath(operation string) string {
	switch operation {
	case OperationNodePairTrustScopedStart:
		return "/v2/node/pair-trust-scoped/start"
	case OperationNodePairTrustScopedExisting:
		return "/v2/node/pair-trust-scoped/existing"
	case OperationNodePairTrustScopedCommit:
		return "/v2/node/pair-trust-scoped/commit"
	case OperationNodePairTrustScopedPoll:
		return "/v2/node/pair-trust-scoped/poll"
	case OperationNodePairTrustScopedACK:
		return "/v2/node/pair-trust-scoped/ack"
	case OperationNodePairTrustScopedCancel:
		return "/v2/node/pair-trust-scoped/cancel"
	case OperationNodePairTrustScopedReconcile:
		return "/v2/node/pair-trust-scoped/reconcile"
	case OperationOwnerNodePairTrustScopedPrepare:
		return "/v2/owner/node-pair-trust-scoped/prepare"
	case OperationOwnerNodePairTrustScopedLookup:
		return "/v2/owner/node-pair-trust-scoped/lookup"
	case OperationOwnerNodePairTrustScopedComplete:
		return "/v2/owner/node-pair-trust-scoped/complete"
	case OperationOwnerNodePairTrustScopedStatus:
		return "/v2/owner/node-pair-trust-scoped/status"
	case OperationOwnerNodePairTrustScopedCancel:
		return "/v2/owner/node-pair-trust-scoped/cancel"
	}
	return ""
}

func nodePairScopedOperationOwner(op string) bool {
	return op == OperationOwnerNodePairTrustScopedLookup || op == OperationOwnerNodePairTrustScopedPrepare || op == OperationOwnerNodePairTrustScopedComplete || op == OperationOwnerNodePairTrustScopedStatus || op == OperationOwnerNodePairTrustScopedCancel
}

func validateNodePairScopedBody(h NodePairTrustScopedPacket, body any, hub HubIdentity, now time.Time) error {
	if now.IsZero() || NodePairTrustScopedHTTPPath(h.Operation) == "" || !isHex(h.RequestID, 16) || !isHex(h.AttemptID, 16) || validateHubIdentity(hub) != nil || e2ee.ValidatePublicIdentity(h.SenderPublic) != nil {
		return ErrInvalid
	}
	context := func(c NodePairTrustScopedContext, o, issued string, scope *e2ee.OwnerAppNodeScopedScope, token []byte) error {
		at := now
		if h.Operation == OperationNodePairTrustScopedPoll || h.Operation == OperationOwnerNodePairTrustScopedStatus || h.Operation == OperationNodePairTrustScopedCancel || h.Operation == OperationOwnerNodePairTrustScopedCancel {
			at = time.Time{}
		}
		if ValidateNodePairTrustScopedContext(c, at) != nil || c.AttemptID != h.AttemptID || !reflect.DeepEqual(c.Hub, hub) || !isHex(o, 32) || validateRecent(issued, now, time.Minute) != nil {
			return ErrInvalid
		}
		if nodePairScopedOperationOwner(h.Operation) {
			if scope == nil || len(token) != MaxSessionTokenBytes || ValidateAppNodeScopedScope(*scope, hub) != nil || !reflect.DeepEqual(scope.DevicePublic, h.SenderPublic) || scope.Origin != c.Origin || scope.Version != c.ScopeVersion || scope.AuthorityNodeID != c.AuthorityNodeID {
				return ErrInvalid
			}
		} else if !reflect.DeepEqual(nodePairScopedPublic(c), h.SenderPublic) {
			return ErrInvalid
		}
		return nil
	}
	switch b := dereference(body).(type) {
	case NodePairTrustScopedOwnerLookup:
		if h.Operation != OperationOwnerNodePairTrustScopedLookup || b.Format != NodePairTrustScopedFormat || len(b.SessionToken) != MaxSessionTokenBytes || ValidateAppNodeScopedScope(b.Scope, hub) != nil || !reflect.DeepEqual(b.Scope.DevicePublic, h.SenderPublic) || !isHex(b.ContextDigest, 32) || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		if b.Selector != "" {
			normalized, e := NormalizeAppNodeCode(b.Selector)
			if e != nil || normalized != b.Selector {
				return ErrInvalid
			}
		}
		return nil
	case NodePairTrustScopedStart:
		if b.ScopeVersion != AppNodeScopedScopeVersion {
			return ErrInvalid
		}
		if h.Operation != OperationNodePairTrustScopedStart || b.Format != NodePairTrustScopedFormat || !reflect.DeepEqual(b.Hub, hub) || !nodePairOrigin(b.Origin) || !isHex(b.DescriptorDigest, 32) || !validID(b.NodeID) || b.NodeID == "control-local" || b.NodeID == "worker-local" || !validUsername(b.NodeName) || len(b.NodeName) > 128 || !nodePairCredentialDigest(b.CredentialDigest) || len(b.RequestNonce) != 32 || e2ee.ValidatePublicIdentity(b.HubNodeControlPublic) != nil || b.HubNodeControlKeyVersion != 1 || b.HubNodeControlPublic.ID == h.SenderPublic.ID || hub.Public.ID == h.SenderPublic.ID || hub.Public.ID == b.HubNodeControlPublic.ID || len(b.PairingProof) == 0 || len(b.PairingProof) > 64<<10 || nodePairWindow(b.IssuedAt, b.ExpiresAt, 10*time.Minute, now) != nil || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		return nil
	case NodePairTrustScopedExistingStart:
		if h.Operation != OperationNodePairTrustScopedExisting || b.Format != NodePairTrustScopedFormat || b.Context.Mode != NodePairTrustScopedExisting || b.Context.Candidate != nil || b.Context.AttemptID != h.AttemptID || !reflect.DeepEqual(b.Context.Hub, hub) || validateNodePairScopedContextEnvelope(b.Context, now) != nil || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		if b.RetainedBinding != nil {
			if b.Context.AuthorityNodeID != b.RetainedBinding.NodeID || b.Context.Binding != nil || ValidateNodePairTrustRetainedBinding(*b.RetainedBinding, h.SenderPublic, hub) != nil {
				return ErrInvalid
			}
		} else if ValidateNodePairTrustScopedContext(b.Context, now) != nil || !reflect.DeepEqual(nodePairScopedPublic(b.Context), h.SenderPublic) {
			return ErrInvalid
		}
		return nil
	case NodePairTrustScopedCommit:
		if (h.Operation != OperationNodePairTrustScopedCommit && h.Operation != OperationNodePairTrustScopedPoll && h.Operation != OperationNodePairTrustScopedCancel) || b.Format != NodePairTrustScopedFormat {
			return ErrInvalid
		}
		return context(b.Context, b.OOBCommitment, b.IssuedAt, nil, nil)
	case NodePairTrustScopedACK:
		if h.Operation != OperationNodePairTrustScopedACK || b.Format != NodePairTrustScopedFormat || !isHex(b.PollPacketDigest, 32) || !isHex(b.PollReceiptDigest, 32) || !isHex(b.OwnerProofDigest, 32) || !isHex(b.CapsuleDigest, 32) || len(b.ACKNonce) != 32 {
			return ErrInvalid
		}
		return context(b.Context, b.OOBCommitment, b.IssuedAt, nil, nil)
	case NodePairTrustScopedOwnerPrepare:
		if h.Operation != OperationOwnerNodePairTrustScopedPrepare || b.Format != NodePairTrustScopedFormat {
			return ErrInvalid
		}
		if context(b.Context, b.OOBCommitment, b.IssuedAt, &b.Scope, b.SessionToken) != nil {
			return ErrInvalid
		}
		if b.Context.Mode == NodePairTrustScopedExisting {
			if len(b.GrantProof) != 0 || len(b.ConfirmationPacket) != 0 {
				return ErrInvalid
			}
		} else if len(b.GrantProof) == 0 || len(b.GrantProof) > e2ee.MaxOwnerAppNodeScopedProofBytes || len(b.ConfirmationPacket) == 0 || len(b.ConfirmationPacket) > MaxAppNodeScopedMutationPacketBytes {
			return ErrInvalid
		}
		return nil
	case NodePairTrustScopedOwnerComplete:
		if h.Operation != OperationOwnerNodePairTrustScopedComplete || b.Format != NodePairTrustScopedFormat || len(b.OwnerProof) == 0 || len(b.OwnerProof) > MaxNodePairTrustScopedProofBytes || len(b.TrustCapsule) == 0 || len(b.TrustCapsule) > MaxNodePairTrustScopedCapsuleBytes {
			return ErrInvalid
		}
		if context(b.Context, b.OOBCommitment, b.IssuedAt, &b.Scope, b.SessionToken) != nil {
			return ErrInvalid
		}
		claims, e := VerifyNodePairTrustScopedOwnerProof(b.Scope.OwnerPublic, b.Context, b.OOBCommitment, b.OwnerProof, now)
		if e != nil || !reflect.DeepEqual(claims.Approval.Scope, b.Scope) || claims.CapsuleDigest != NodePairTrustScopedCapsuleDigest(b.TrustCapsule) {
			return ErrInvalid
		}
		return nil
	case NodePairTrustScopedOwnerStatus:
		if (h.Operation != OperationOwnerNodePairTrustScopedStatus && h.Operation != OperationOwnerNodePairTrustScopedCancel) || b.Format != NodePairTrustScopedFormat {
			return ErrInvalid
		}
		return context(b.Context, b.OOBCommitment, b.IssuedAt, &b.Scope, b.SessionToken)
	case NodePairTrustScopedReconcile:
		if h.Operation != OperationNodePairTrustScopedReconcile || b.Format != NodePairTrustScopedFormat || len(b.OriginalPacket) == 0 || len(b.OriginalPacket) > MaxNodePairTrustScopedPacketBytes || NodePairTrustScopedPacketDigest(b.OriginalPacket) != b.OriginalPacketDigest || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		var old NodePairTrustScopedPacket
		if decodeCanonical(b.OriginalPacket, MaxNodePairTrustScopedPacketBytes, &old) != nil || old.Operation == OperationNodePairTrustScopedReconcile || old.AttemptID != h.AttemptID || !reflect.DeepEqual(old.SenderPublic, h.SenderPublic) || old.RequestID == h.RequestID || NodePairTrustScopedHTTPPath(old.Operation) == "" || len(old.Packet) == 0 {
			return ErrInvalid
		}
		return nil
	}
	return ErrInvalid
}

// Services repeat freshness/shape checks inside their single writer after
// authenticating exact old packets without granting historical admission.
func ValidateNodePairTrustScopedRequestBody(h NodePairTrustScopedPacket, body any, hub HubIdentity, now time.Time) error {
	return validateNodePairScopedBody(h, body, hub, now)
}
