package hubaccountwire

import (
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func nodePairPublic(c NodePairTrustContext) e2ee.PublicIdentity {
	if c.Mode == NodePairTrustInitial && c.Candidate != nil {
		return c.Candidate.NodePublic
	}
	if c.Mode == NodePairTrustExisting && c.Binding != nil {
		return c.Binding.NodePublic
	}
	return e2ee.PublicIdentity{}
}
func nodePairOrigin(origin string) bool {
	v, e := ownerbootstrap.CanonicalOrigin(origin, false)
	return e == nil && v == origin && len(origin) <= 256
}
func nodePairWindow(issued, end string, maximum time.Duration, now time.Time) error {
	if validateTimeWindowNow(issued, end, maximum, now) != nil {
		return ErrInvalid
	}
	return nil
}
func ValidateNodePairTrustContext(c NodePairTrustContext, now time.Time) error {
	if c.Format != NodePairTrustFormat || !isHex(c.AttemptID, 16) || validateHubIdentity(c.Hub) != nil || len(c.Hub.HubID) > 96 || !nodePairOrigin(c.Origin) || !isHex(c.DescriptorDigest, 32) || !isHex(c.NodeNonce, 32) || nodePairWindow(c.IssuedAt, c.ExpiresAt, 10*time.Minute, now) != nil {
		return ErrInvalid
	}
	var nc e2ee.PublicIdentity
	switch c.Mode {
	case NodePairTrustInitial:
		if c.Candidate == nil || c.Binding != nil || ValidateAppNodeCandidate(*c.Candidate, c.Hub.HubID) != nil {
			return ErrInvalid
		}
		end, _ := parseCanonicalUTC(c.ExpiresAt)
		candidateEnd, _ := parseCanonicalUTC(c.Candidate.ExpiresAt)
		if end.After(candidateEnd) {
			return ErrInvalid
		}
		nc = c.Candidate.HubNodeControlPublic
	case NodePairTrustExisting:
		if c.Binding == nil || c.Candidate != nil {
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
	if nc.ID == c.Hub.Public.ID || nodePairPublic(c).ID == c.Hub.Public.ID {
		return ErrInvalid
	}
	return nil
}

func ValidateNodePairTrustApproval(a NodePairTrustApproval, c NodePairTrustContext, o string, now time.Time) error {
	d, err := NodePairTrustContextDigest(c)
	if err != nil || a.Format != NodePairTrustFormat || a.ContextDigest != d || !isHex(o, 32) || a.OOBCommitment != o || ValidateAppNodeScope(a.Scope, c.Hub) != nil || a.Scope.Origin != c.Origin || !isHex(a.PrepareRequestID, 16) || !isHex(a.PreparePacketDigest, 32) || !isHex(a.ServerNonce, 32) || nodePairWindow(a.PreparedAt, a.AcceptBefore, 5*time.Minute, now) != nil {
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
	if c.Mode == NodePairTrustInitial {
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
func ValidateNodePairTrustInitialAuthorization(c NodePairTrustContext, a NodePairTrustApproval, grantRaw, confirmRaw []byte, now time.Time) error {
	if ValidateNodePairTrustApproval(a, c, a.OOBCommitment, now) != nil {
		return ErrInvalid
	}
	if c.Mode == NodePairTrustExisting {
		if len(grantRaw) != 0 || len(confirmRaw) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if len(grantRaw) == 0 || len(grantRaw) > e2ee.MaxOwnerAppNodeProofBytes || len(confirmRaw) == 0 || len(confirmRaw) > MaxAppNodeMutationPacketBytes || a.GrantProofDigest != AppNodeProofDigest(grantRaw) || a.ConfirmationPacketDigest != AppNodePacketDigest(confirmRaw) {
		return ErrInvalid
	}
	g, err := e2ee.VerifyOwnerAppNodeGrant(a.Scope.OwnerPublic, grantRaw, now)
	if err != nil || ValidateAppNodeGrantClaims(g, c.Hub, now) != nil || g.Profile != AppNodeProfileInitial || !reflect.DeepEqual(g.Scope, a.Scope) || g.GrantID != a.GrantID || !reflect.DeepEqual(g.Candidate, c.Candidate) {
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
	if decodeCanonical(confirmRaw, MaxAppNodeMutationPacketBytes, &p) != nil {
		return ErrInvalid
	}
	r := p.Route
	grantID, _, e := ParseAppNodeBusinessOperationID(r.OperationID)
	if e != nil || grantID != g.GrantID || r.Version != 1 || r.Direction != clientwire.DirectionRequest || r.Operation != "nodes.confirm" || r.HubID != c.Hub.HubID || r.OwnerID != a.Scope.OwnerID || r.DeviceID != a.Scope.DeviceID || r.SessionEpoch != a.Scope.ClientSessionEpoch || r.Sequence == 0 || r.Sequence > math.MaxInt64 || r.SenderKeyID != a.Scope.DevicePublic.ID || r.ReceiverKeyID != c.Hub.Public.ID || r.SenderKeyVersion != 1 || r.ReceiverKeyVersion != c.Hub.KeyVersion {
		return ErrInvalid
	}
	return nil
}

// Caller supplies its locally S-verified approval and authenticated ACKED
// receipt. Historical matching is not permission to install a first pin late.
func ValidateNodePairTrustAccepted(c NodePairTrustContext, a NodePairTrustApproval, b e2ee.OwnerAppNodeBinding) error {
	if ValidateNodePairTrustApproval(a, c, a.OOBCommitment, time.Time{}) != nil {
		return ErrInvalid
	}
	if c.Mode == NodePairTrustExisting {
		if !reflect.DeepEqual(*c.Binding, b) {
			return ErrInvalid
		}
		return nil
	}
	g := e2ee.OwnerAppNodeGrantClaims{Profile: AppNodeProfileInitial, Scope: a.Scope, Candidate: c.Candidate, PreparedAt: a.PreparedAt, LeaseExpiresAt: a.AcceptBefore}
	return ValidateAppNodeConfirmationBinding(g, b)
}

func NodePairTrustHTTPPath(operation string) string {
	switch operation {
	case OperationNodePairTrustStart:
		return "/v2/node/pair-trust/start"
	case OperationNodePairTrustExisting:
		return "/v2/node/pair-trust/existing"
	case OperationNodePairTrustCommit:
		return "/v2/node/pair-trust/commit"
	case OperationNodePairTrustPoll:
		return "/v2/node/pair-trust/poll"
	case OperationNodePairTrustACK:
		return "/v2/node/pair-trust/ack"
	case OperationNodePairTrustCancel:
		return "/v2/node/pair-trust/cancel"
	case OperationNodePairTrustReconcile:
		return "/v2/node/pair-trust/reconcile"
	case OperationOwnerNodePairTrustPrepare:
		return "/v2/owner/node-pair-trust/prepare"
	case OperationOwnerNodePairTrustLookup:
		return "/v2/owner/node-pair-trust/lookup"
	case OperationOwnerNodePairTrustComplete:
		return "/v2/owner/node-pair-trust/complete"
	case OperationOwnerNodePairTrustStatus:
		return "/v2/owner/node-pair-trust/status"
	case OperationOwnerNodePairTrustCancel:
		return "/v2/owner/node-pair-trust/cancel"
	}
	return ""
}

func nodePairOperationOwner(op string) bool {
	return op == OperationOwnerNodePairTrustLookup || op == OperationOwnerNodePairTrustPrepare || op == OperationOwnerNodePairTrustComplete || op == OperationOwnerNodePairTrustStatus || op == OperationOwnerNodePairTrustCancel
}

func validateNodePairBody(h NodePairTrustPacket, body any, hub HubIdentity, now time.Time) error {
	if now.IsZero() || NodePairTrustHTTPPath(h.Operation) == "" || !isHex(h.RequestID, 16) || !isHex(h.AttemptID, 16) || validateHubIdentity(hub) != nil || e2ee.ValidatePublicIdentity(h.SenderPublic) != nil {
		return ErrInvalid
	}
	context := func(c NodePairTrustContext, o, issued string, scope *e2ee.OwnerAppNodeScope, token []byte) error {
		at := now
		if h.Operation == OperationNodePairTrustPoll || h.Operation == OperationOwnerNodePairTrustStatus || h.Operation == OperationNodePairTrustCancel || h.Operation == OperationOwnerNodePairTrustCancel {
			at = time.Time{}
		}
		if ValidateNodePairTrustContext(c, at) != nil || c.AttemptID != h.AttemptID || !reflect.DeepEqual(c.Hub, hub) || !isHex(o, 32) || validateRecent(issued, now, time.Minute) != nil {
			return ErrInvalid
		}
		if nodePairOperationOwner(h.Operation) {
			if scope == nil || len(token) != MaxSessionTokenBytes || ValidateAppNodeScope(*scope, hub) != nil || !reflect.DeepEqual(scope.DevicePublic, h.SenderPublic) || scope.Origin != c.Origin {
				return ErrInvalid
			}
		} else if !reflect.DeepEqual(nodePairPublic(c), h.SenderPublic) {
			return ErrInvalid
		}
		return nil
	}
	switch b := dereference(body).(type) {
	case NodePairTrustOwnerLookup:
		if h.Operation != OperationOwnerNodePairTrustLookup || b.Format != NodePairTrustFormat || len(b.SessionToken) != MaxSessionTokenBytes || ValidateAppNodeScope(b.Scope, hub) != nil || !reflect.DeepEqual(b.Scope.DevicePublic, h.SenderPublic) || !isHex(b.ContextDigest, 32) || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		if b.Selector != "" {
			normalized, e := NormalizeAppNodeCode(b.Selector)
			if e != nil || normalized != b.Selector {
				return ErrInvalid
			}
		}
		return nil
	case NodePairTrustStart:
		if h.Operation != OperationNodePairTrustStart || b.Format != NodePairTrustFormat || !reflect.DeepEqual(b.Hub, hub) || !nodePairOrigin(b.Origin) || !isHex(b.DescriptorDigest, 32) || !validID(b.NodeID) || b.NodeID == "control-local" || b.NodeID == "worker-local" || !validUsername(b.NodeName) || len(b.NodeName) > 128 || !nodePairCredentialDigest(b.CredentialDigest) || len(b.RequestNonce) != 32 || e2ee.ValidatePublicIdentity(b.HubNodeControlPublic) != nil || b.HubNodeControlKeyVersion != 1 || b.HubNodeControlPublic.ID == h.SenderPublic.ID || hub.Public.ID == h.SenderPublic.ID || hub.Public.ID == b.HubNodeControlPublic.ID || len(b.PairingProof) == 0 || len(b.PairingProof) > 64<<10 || nodePairWindow(b.IssuedAt, b.ExpiresAt, 10*time.Minute, now) != nil || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		return nil
	case NodePairTrustExistingStart:
		if h.Operation != OperationNodePairTrustExisting || b.Format != NodePairTrustFormat || b.Context.Mode != NodePairTrustExisting || b.Context.AttemptID != h.AttemptID || !reflect.DeepEqual(b.Context.Hub, hub) || ValidateNodePairTrustContext(b.Context, now) != nil || !reflect.DeepEqual(nodePairPublic(b.Context), h.SenderPublic) || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		return nil
	case NodePairTrustCommit:
		if (h.Operation != OperationNodePairTrustCommit && h.Operation != OperationNodePairTrustPoll && h.Operation != OperationNodePairTrustCancel) || b.Format != NodePairTrustFormat {
			return ErrInvalid
		}
		return context(b.Context, b.OOBCommitment, b.IssuedAt, nil, nil)
	case NodePairTrustACK:
		if h.Operation != OperationNodePairTrustACK || b.Format != NodePairTrustFormat || !isHex(b.PollPacketDigest, 32) || !isHex(b.PollReceiptDigest, 32) || !isHex(b.OwnerProofDigest, 32) || !isHex(b.CapsuleDigest, 32) || len(b.ACKNonce) != 32 {
			return ErrInvalid
		}
		return context(b.Context, b.OOBCommitment, b.IssuedAt, nil, nil)
	case NodePairTrustOwnerPrepare:
		if h.Operation != OperationOwnerNodePairTrustPrepare || b.Format != NodePairTrustFormat {
			return ErrInvalid
		}
		if context(b.Context, b.OOBCommitment, b.IssuedAt, &b.Scope, b.SessionToken) != nil {
			return ErrInvalid
		}
		if b.Context.Mode == NodePairTrustExisting {
			if len(b.GrantProof) != 0 || len(b.ConfirmationPacket) != 0 {
				return ErrInvalid
			}
		} else if len(b.GrantProof) == 0 || len(b.GrantProof) > e2ee.MaxOwnerAppNodeProofBytes || len(b.ConfirmationPacket) == 0 || len(b.ConfirmationPacket) > MaxAppNodeMutationPacketBytes {
			return ErrInvalid
		}
		return nil
	case NodePairTrustOwnerComplete:
		if h.Operation != OperationOwnerNodePairTrustComplete || b.Format != NodePairTrustFormat || len(b.OwnerProof) == 0 || len(b.OwnerProof) > MaxNodePairTrustProofBytes || len(b.TrustCapsule) == 0 || len(b.TrustCapsule) > MaxNodePairTrustCapsuleBytes {
			return ErrInvalid
		}
		if context(b.Context, b.OOBCommitment, b.IssuedAt, &b.Scope, b.SessionToken) != nil {
			return ErrInvalid
		}
		claims, e := VerifyNodePairTrustOwnerProof(b.Scope.OwnerPublic, b.Context, b.OOBCommitment, b.OwnerProof, now)
		if e != nil || !reflect.DeepEqual(claims.Approval.Scope, b.Scope) || claims.CapsuleDigest != NodePairTrustCapsuleDigest(b.TrustCapsule) {
			return ErrInvalid
		}
		return nil
	case NodePairTrustOwnerStatus:
		if (h.Operation != OperationOwnerNodePairTrustStatus && h.Operation != OperationOwnerNodePairTrustCancel) || b.Format != NodePairTrustFormat {
			return ErrInvalid
		}
		return context(b.Context, b.OOBCommitment, b.IssuedAt, &b.Scope, b.SessionToken)
	case NodePairTrustReconcile:
		if h.Operation != OperationNodePairTrustReconcile || b.Format != NodePairTrustFormat || len(b.OriginalPacket) == 0 || len(b.OriginalPacket) > MaxNodePairTrustPacketBytes || NodePairTrustPacketDigest(b.OriginalPacket) != b.OriginalPacketDigest || validateRecent(b.IssuedAt, now, time.Minute) != nil {
			return ErrInvalid
		}
		var old NodePairTrustPacket
		if decodeCanonical(b.OriginalPacket, MaxNodePairTrustPacketBytes, &old) != nil || old.Operation == OperationNodePairTrustReconcile || old.AttemptID != h.AttemptID || !reflect.DeepEqual(old.SenderPublic, h.SenderPublic) || old.RequestID == h.RequestID || NodePairTrustHTTPPath(old.Operation) == "" || len(old.Packet) == 0 {
			return ErrInvalid
		}
		return nil
	}
	return ErrInvalid
}

// Services repeat freshness/shape checks inside their single writer after
// authenticating exact old packets without granting historical admission.
func ValidateNodePairTrustRequestBody(h NodePairTrustPacket, body any, hub HubIdentity, now time.Time) error {
	return validateNodePairBody(h, body, hub, now)
}
