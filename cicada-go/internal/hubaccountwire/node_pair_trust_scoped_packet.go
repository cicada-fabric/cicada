package hubaccountwire

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func nodePairScopedBody(op string) any {
	switch op {
	case OperationNodePairTrustScopedStart:
		return &NodePairTrustScopedStart{}
	case OperationNodePairTrustScopedExisting:
		return &NodePairTrustScopedExistingStart{}
	case OperationNodePairTrustScopedCommit, OperationNodePairTrustScopedPoll, OperationNodePairTrustScopedCancel:
		return &NodePairTrustScopedCommit{}
	case OperationNodePairTrustScopedACK:
		return &NodePairTrustScopedACK{}
	case OperationNodePairTrustScopedReconcile:
		return &NodePairTrustScopedReconcile{}
	case OperationOwnerNodePairTrustScopedPrepare:
		return &NodePairTrustScopedOwnerPrepare{}
	case OperationOwnerNodePairTrustScopedLookup:
		return &NodePairTrustScopedOwnerLookup{}
	case OperationOwnerNodePairTrustScopedComplete:
		return &NodePairTrustScopedOwnerComplete{}
	case OperationOwnerNodePairTrustScopedStatus, OperationOwnerNodePairTrustScopedCancel:
		return &NodePairTrustScopedOwnerStatus{}
	}
	return nil
}

// NewNodePairTrustScopedRequestBody returns only a closed typed decode target.
func NewNodePairTrustScopedRequestBody(operation string) any { return nodePairScopedBody(operation) }
func nodePairScopedLimits(op string) (int, int) {
	if op == OperationNodePairTrustScopedReconcile {
		return MaxNodePairTrustScopedReconcileBodyBytes, MaxNodePairTrustScopedReconcilePacketBytes
	}
	return MaxNodePairTrustScopedBodyBytes, MaxNodePairTrustScopedPacketBytes
}
func nodePairScopedHeader(p NodePairTrustScopedPacket) NodePairTrustScopedPacket {
	p.Packet = nil
	return p
}
func nodePairScopedAAD(p NodePairTrustScopedPacket, hub HubIdentity, direction, original string) []byte {
	raw, _ := json.Marshal(struct {
		Header    NodePairTrustScopedPacket `json:"header"`
		Hub       HubIdentity               `json:"hub"`
		Direction string                    `json:"direction"`
		Original  string                    `json:"original_packet_digest"`
	}{nodePairScopedHeader(p), hub, direction, original})
	return append([]byte("cicada/node-pair-trust-scoped/packet-aad/v1\x00"), raw...)
}
func preflightNodePairScoped(raw []byte, operation string, maximum int) (NodePairTrustScopedPacket, error) {
	var p NodePairTrustScopedPacket
	if decodeCanonical(raw, maximum, &p) != nil || p.Format != NodePairTrustScopedPacketFormat || p.Version != 1 || p.Operation != operation || NodePairTrustScopedHTTPPath(operation) == "" || !isHex(p.RequestID, 16) || !isHex(p.AttemptID, 16) || e2ee.ValidatePublicIdentity(p.SenderPublic) != nil || len(p.Packet) == 0 || len(p.Packet) > maximum {
		return p, ErrInvalid
	}
	return p, nil
}

func SealNodePairTrustScopedRequest(sender *e2ee.Identity, hub HubIdentity, h NodePairTrustScopedPacket, body any, now time.Time) ([]byte, error) {
	h.Format, h.Version = NodePairTrustScopedPacketFormat, 1
	if sender == nil {
		return nil, ErrInvalid
	}
	h.SenderPublic = sender.Public()
	if nodePairScopedBody(h.Operation) == nil || reflect.TypeOf(dereference(body)) != reflect.TypeOf(dereference(nodePairScopedBody(h.Operation))) || validateNodePairScopedBody(h, body, hub, now) != nil {
		return nil, ErrInvalid
	}
	plain, err := json.Marshal(body)
	bodyMax, packetMax := nodePairScopedLimits(h.Operation)
	if err != nil || len(plain) > bodyMax {
		return nil, ErrInvalid
	}
	defer clear(plain)
	h.Packet, err = e2ee.Seal(sender, hub.Public, plain, nodePairScopedAAD(h, hub, "REQUEST", ""), 1)
	if err != nil {
		return nil, ErrInvalid
	}
	out, err := json.Marshal(h)
	if err != nil || len(out) > packetMax {
		return nil, ErrInvalid
	}
	return out, nil
}

func OpenNodePairTrustScopedRequest(hubKey *e2ee.Identity, hub HubIdentity, raw []byte, operation string, out any, now time.Time) (NodePairTrustScopedPacket, error) {
	bodyMax, packetMax := nodePairScopedLimits(operation)
	h, err := preflightNodePairScoped(raw, operation, packetMax)
	if err != nil || hubKey == nil || !reflect.DeepEqual(hubKey.Public(), hub.Public) || reflect.TypeOf(out) != reflect.TypeOf(nodePairScopedBody(operation)) {
		return h, ErrInvalid
	}
	plain, seq, err := e2ee.Open(hubKey, h.SenderPublic, h.Packet, nodePairScopedAAD(h, hub, "REQUEST", ""))
	if err != nil || seq != 1 {
		return h, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, bodyMax, out) != nil || validateNodePairScopedBody(h, out, hub, now) != nil {
		return h, ErrInvalid
	}
	return h, nil
}

// Historical authentication has no fresh-admission result. The service may
// only recover the matching original receipt or permanently fence that exact
// packet; it must never dispatch this result as a new operation.
type NodePairTrustScopedHistoricalOriginal struct {
	Header       NodePairTrustScopedPacket
	PacketDigest string
}

func AuthenticateNodePairTrustScopedOriginal(hubKey *e2ee.Identity, hub HubIdentity, raw []byte, out any) (NodePairTrustScopedHistoricalOriginal, error) {
	var header struct {
		Operation string `json:"operation"`
	}
	if len(raw) > MaxNodePairTrustScopedPacketBytes || json.Unmarshal(raw, &header) != nil || header.Operation == OperationNodePairTrustScopedReconcile {
		return NodePairTrustScopedHistoricalOriginal{}, ErrInvalid
	}
	h, err := preflightNodePairScoped(raw, header.Operation, MaxNodePairTrustScopedPacketBytes)
	if err != nil || hubKey == nil || !reflect.DeepEqual(hubKey.Public(), hub.Public) || reflect.TypeOf(out) != reflect.TypeOf(nodePairScopedBody(h.Operation)) {
		return NodePairTrustScopedHistoricalOriginal{}, ErrInvalid
	}
	plain, seq, err := e2ee.Open(hubKey, h.SenderPublic, h.Packet, nodePairScopedAAD(h, hub, "REQUEST", ""))
	if err != nil || seq != 1 {
		return NodePairTrustScopedHistoricalOriginal{}, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, MaxNodePairTrustScopedBodyBytes, out) != nil {
		return NodePairTrustScopedHistoricalOriginal{}, ErrInvalid
	}
	return NodePairTrustScopedHistoricalOriginal{h, NodePairTrustScopedPacketDigest(raw)}, nil
}

func ValidateNodePairTrustScopedStartProof(hubNC *e2ee.Identity, node e2ee.PublicIdentity, b NodePairTrustScopedStart) error {
	if hubNC == nil || !reflect.DeepEqual(hubNC.Public(), b.HubNodeControlPublic) {
		return ErrInvalid
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: b.Hub.HubID, NodeID: b.NodeID, RequestNonce: b.RequestNonce, CredentialDigest: b.CredentialDigest, NodePublicIdentity: node, HubPublicIdentity: b.HubNodeControlPublic, HubKeyVersion: b.HubNodeControlKeyVersion})
	if err != nil {
		return ErrInvalid
	}
	plain, seq, err := e2ee.Open(hubNC, node, b.PairingProof, nodewire.PairingProofAAD())
	defer clear(plain)
	if err != nil || seq != 1 || !reflect.DeepEqual(plain, transcript) {
		return ErrInvalid
	}
	return nil
}

func nodePairScopedKnownState(s string) bool {
	switch s {
	case NodePairTrustScopedPending, NodePairTrustScopedOwnerApproved, NodePairTrustScopedACKed, NodePairTrustScopedExpired, NodePairTrustScopedCancelled, NodePairTrustScopedRevoked, NodePairTrustScopedFenced, NodePairTrustScopedRecovered:
		return true
	}
	return false
}
func nodePairScopedKnownError(s string) bool {
	switch s {
	case "", "INVALID_REQUEST", "NOT_FOUND", "CONFLICT", "EXPIRED", "CANCELLED", "REVOKED", "FENCED", "ACK_REQUIRED", "UNAVAILABLE", "OUTCOME_UNCERTAIN":
		return true
	}
	return false
}
func validateNodePairScopedResult(h NodePairTrustScopedPacket, r NodePairTrustScopedResult, hub HubIdentity) error {
	if r.Format != NodePairTrustScopedFormat || r.Operation != h.Operation || r.RequestID != h.RequestID || r.AttemptID != h.AttemptID || !isHex(r.RequestPacketDigest, 32) || !nodePairScopedKnownState(r.State) || !nodePairScopedKnownError(r.ErrorCode) || validateCanonicalTime(r.ObservedAt) != nil {
		return ErrInvalid
	}
	if h.Operation == OperationNodePairTrustScopedReconcile {
		if r.Context != nil || r.OOBCommitment != "" || r.Selector != "" || r.Approval != nil || len(r.OwnerProof) != 0 || len(r.TrustCapsule) != 0 || r.Binding != nil || len(r.ConfirmationResponse) != 0 {
			return ErrInvalid
		}
		if r.ErrorCode != "" {
			if r.ErrorCode != "FENCED" || r.State != NodePairTrustScopedFenced || r.OriginalPacketDigest != "" || len(r.OriginalReceipt) != 0 {
				return ErrInvalid
			}
			return nil
		}
		if r.State != NodePairTrustScopedRecovered || !isHex(r.OriginalPacketDigest, 32) || len(r.OriginalReceipt) == 0 || len(r.OriginalReceipt) > MaxNodePairTrustScopedOriginalReceiptBytes {
			return ErrInvalid
		}
		return nil
	}
	if r.State == NodePairTrustScopedRecovered || r.OriginalPacketDigest != "" || len(r.OriginalReceipt) != 0 {
		return ErrInvalid
	}
	if r.ErrorCode != "" {
		if r.Context != nil || r.OOBCommitment != "" || r.Selector != "" || r.Approval != nil || len(r.OwnerProof) != 0 || len(r.TrustCapsule) != 0 || r.Binding != nil || len(r.ConfirmationResponse) != 0 {
			return ErrInvalid
		}
		return nil
	}
	switch h.Operation {
	case OperationNodePairTrustScopedStart, OperationNodePairTrustScopedExisting, OperationNodePairTrustScopedCommit, OperationOwnerNodePairTrustScopedPrepare:
		if r.State != NodePairTrustScopedPending {
			return ErrInvalid
		}
	case OperationOwnerNodePairTrustScopedComplete:
		if r.State != NodePairTrustScopedOwnerApproved {
			return ErrInvalid
		}
	case OperationNodePairTrustScopedACK:
		if r.State != NodePairTrustScopedACKed {
			return ErrInvalid
		}
	case OperationNodePairTrustScopedCancel, OperationOwnerNodePairTrustScopedCancel:
		if r.State != NodePairTrustScopedCancelled && r.State != NodePairTrustScopedExpired && r.State != NodePairTrustScopedRevoked && r.State != NodePairTrustScopedFenced && r.State != NodePairTrustScopedACKed {
			return ErrInvalid
		}
	}
	if r.Context == nil || ValidateNodePairTrustScopedContext(*r.Context, time.Time{}) != nil || r.Context.AttemptID != h.AttemptID || !reflect.DeepEqual(r.Context.Hub, hub) {
		return ErrInvalid
	}
	if !nodePairScopedOperationOwner(h.Operation) && h.Operation != OperationNodePairTrustScopedReconcile && !reflect.DeepEqual(nodePairScopedPublic(*r.Context), h.SenderPublic) {
		return ErrInvalid
	}
	start := h.Operation == OperationNodePairTrustScopedStart || h.Operation == OperationNodePairTrustScopedExisting
	if start {
		if r.State != NodePairTrustScopedPending || r.OOBCommitment != "" {
			return ErrInvalid
		}
		if h.Operation == OperationNodePairTrustScopedStart {
			digest, e := AppNodeCodeDigest(hub.HubID, r.Selector)
			if e != nil || r.Context.Mode != NodePairTrustScopedInitial || digest != r.Context.Candidate.CodeDigest {
				return ErrInvalid
			}
		} else if r.Selector != "" || r.Context.Mode != NodePairTrustScopedExisting {
			return ErrInvalid
		}
	} else if !isHex(r.OOBCommitment, 32) || r.Selector != "" {
		return ErrInvalid
	}
	if h.Operation == OperationOwnerNodePairTrustScopedPrepare {
		if r.State != NodePairTrustScopedPending || r.Approval == nil || ValidateNodePairTrustScopedApproval(*r.Approval, *r.Context, r.OOBCommitment, time.Time{}) != nil {
			return ErrInvalid
		}
	} else if r.Approval != nil {
		return ErrInvalid
	}
	if h.Operation == OperationNodePairTrustScopedPoll && r.State == NodePairTrustScopedOwnerApproved {
		var p NodePairTrustScopedOwnerProof
		if decodeCanonical(r.OwnerProof, MaxNodePairTrustScopedProofBytes, &p) != nil || len(r.TrustCapsule) == 0 || len(r.TrustCapsule) > MaxNodePairTrustScopedCapsuleBytes || p.Claims.CapsuleDigest != NodePairTrustScopedCapsuleDigest(r.TrustCapsule) || ValidateNodePairTrustScopedApproval(p.Claims.Approval, *r.Context, r.OOBCommitment, time.Time{}) != nil {
			return ErrInvalid
		}
	} else if len(r.OwnerProof) != 0 || len(r.TrustCapsule) != 0 {
		return ErrInvalid
	}
	if r.State == NodePairTrustScopedACKed {
		if r.Binding == nil {
			return ErrInvalid
		}
		if (h.Operation == OperationOwnerNodePairTrustScopedStatus || h.Operation == OperationOwnerNodePairTrustScopedCancel) && r.Context.Mode == NodePairTrustScopedInitial {
			if len(r.ConfirmationResponse) == 0 || len(r.ConfirmationResponse) > MaxAppNodeReceiptBytes {
				return ErrInvalid
			}
		} else if len(r.ConfirmationResponse) != 0 {
			return ErrInvalid
		}
	} else if r.Binding != nil || len(r.ConfirmationResponse) != 0 {
		return ErrInvalid
	}
	return nil
}

func nodePairScopedResponseLimits(op string) (int, int) {
	if op == OperationNodePairTrustScopedReconcile {
		return MaxNodePairTrustScopedReconcileResponseBodyBytes, MaxNodePairTrustScopedReconcileResponsePacketBytes
	}
	return MaxNodePairTrustScopedResponseBodyBytes, MaxNodePairTrustScopedResponsePacketBytes
}

func SealNodePairTrustScopedResponse(hubKey *e2ee.Identity, hub HubIdentity, original []byte, requestBody any, r NodePairTrustScopedResult) ([]byte, error) {
	var q NodePairTrustScopedPacket
	if hubKey == nil || !reflect.DeepEqual(hubKey.Public(), hub.Public) || decodeCanonical(original, MaxNodePairTrustScopedReconcilePacketBytes, &q) != nil {
		return nil, ErrInvalid
	}
	_, limit := nodePairScopedLimits(q.Operation)
	h, err := preflightNodePairScoped(original, q.Operation, limit)
	if err != nil || r.RequestPacketDigest != NodePairTrustScopedPacketDigest(original) || validateNodePairScopedResult(h, r, hub) != nil || matchNodePairScopedResult(h, requestBody, r) != nil {
		return nil, ErrInvalid
	}
	plain, err := json.Marshal(r)
	bodyLimit, packetLimit := nodePairScopedResponseLimits(h.Operation)
	if err != nil || len(plain) > bodyLimit {
		return nil, ErrInvalid
	}
	defer clear(plain)
	response := nodePairScopedHeader(h)
	response.SenderPublic = hub.Public
	response.Packet, err = e2ee.Seal(hubKey, h.SenderPublic, plain, nodePairScopedAAD(response, hub, "RESPONSE", r.RequestPacketDigest), 1)
	if err != nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > packetLimit {
		return nil, ErrInvalid
	}
	return raw, nil
}

func OpenNodePairTrustScopedResponse(receiver *e2ee.Identity, hub HubIdentity, original, response []byte, requestBody any) (NodePairTrustScopedResult, error) {
	var q NodePairTrustScopedPacket
	var out NodePairTrustScopedResult
	if receiver == nil || decodeCanonical(original, MaxNodePairTrustScopedReconcilePacketBytes, &q) != nil || !reflect.DeepEqual(receiver.Public(), q.SenderPublic) {
		return out, ErrInvalid
	}
	_, limit := nodePairScopedLimits(q.Operation)
	h, err := preflightNodePairScoped(original, q.Operation, limit)
	bodyLimit, packetLimit := nodePairScopedResponseLimits(q.Operation)
	r, err2 := preflightNodePairScoped(response, q.Operation, packetLimit)
	if err != nil || err2 != nil || !reflect.DeepEqual(r.SenderPublic, hub.Public) || r.RequestID != h.RequestID || r.AttemptID != h.AttemptID {
		return out, ErrInvalid
	}
	digest := NodePairTrustScopedPacketDigest(original)
	plain, seq, err := e2ee.Open(receiver, hub.Public, r.Packet, nodePairScopedAAD(r, hub, "RESPONSE", digest))
	if err != nil || seq != 1 {
		return out, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, bodyLimit, &out) != nil || out.RequestPacketDigest != digest || validateNodePairScopedResult(h, out, hub) != nil || matchNodePairScopedResult(h, requestBody, out) != nil {
		return NodePairTrustScopedResult{}, ErrInvalid
	}
	return out, nil
}

func matchNodePairScopedResult(h NodePairTrustScopedPacket, body any, r NodePairTrustScopedResult) error {
	if reflect.TypeOf(dereference(body)) != reflect.TypeOf(dereference(nodePairScopedBody(h.Operation))) {
		return ErrInvalid
	}
	if r.ErrorCode != "" {
		return nil
	}
	var c *NodePairTrustScopedContext
	var o string
	switch b := dereference(body).(type) {
	case NodePairTrustScopedOwnerLookup:
		d, e := NodePairTrustScopedContextDigest(*r.Context)
		if e != nil || d != b.ContextDigest || r.Context.Origin != b.Scope.Origin || r.Context.ScopeVersion != b.Scope.Version || r.Context.AuthorityNodeID != b.Scope.AuthorityNodeID {
			return ErrInvalid
		}
		if r.Context.Mode == NodePairTrustScopedInitial {
			selector, e := AppNodeCodeDigest(r.Context.Hub.HubID, b.Selector)
			if e != nil || selector != r.Context.Candidate.CodeDigest {
				return ErrInvalid
			}
		} else if b.Selector != "" || r.Context.Binding.OwnerID != b.Scope.OwnerID || r.Context.Binding.OwnerKeyID != b.Scope.OwnerPublic.ID {
			return ErrInvalid
		}
		return nil
	case NodePairTrustScopedStart:
		x := r.Context
		n := x.Candidate
		if x.Mode != NodePairTrustScopedInitial || n == nil || x.Origin != b.Origin || x.DescriptorDigest != b.DescriptorDigest || x.NodeNonce != hex.EncodeToString(b.RequestNonce) || n.NodeID != b.NodeID || n.NodeName != b.NodeName || !reflect.DeepEqual(n.HubNodeControlPublic, b.HubNodeControlPublic) || n.HubNodeControlKeyVersion != b.HubNodeControlKeyVersion {
			return ErrInvalid
		}
		if n.Version != 1 || !reflect.DeepEqual(n.NodePublic, h.SenderPublic) {
			return ErrInvalid
		}
		digest, e := nodewire.PairingCandidateDigest(nodewire.PairingCandidateBasis{RequestID: n.RequestID, Version: int64(n.Version), Mode: n.Mode, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: n.CodeDigest, NodePublicIdentity: n.NodePublic, NodeFingerprint: n.NodeKeyFingerprint, HubPublicIdentity: n.HubNodeControlPublic, HubKeyVersion: n.HubNodeControlKeyVersion, HubFingerprint: n.HubNodeControlFingerprint, NodeKeyEpoch: n.NodeKeyEpoch, TargetBindingID: "", ExpiresAt: n.ExpiresAt})
		if e != nil || digest != n.CandidateDigest {
			return ErrInvalid
		}
		end, _ := parseCanonicalUTC(x.ExpiresAt)
		limit, _ := parseCanonicalUTC(b.ExpiresAt)
		issued, _ := parseCanonicalUTC(x.IssuedAt)
		start, _ := parseCanonicalUTC(b.IssuedAt)
		if end.After(limit) || issued.Before(start.Add(-30*time.Second)) {
			return ErrInvalid
		}
		return nil
	case NodePairTrustScopedExistingStart:
		copy := b.Context
		if b.RetainedBinding != nil {
			if b.Context.Binding != nil || r.Context.Binding == nil || MatchNodePairTrustRetainedBinding(*b.RetainedBinding, *r.Context.Binding, h.SenderPublic) != nil {
				return ErrInvalid
			}
			copy.Binding = r.Context.Binding
		}
		c = &copy
	case NodePairTrustScopedCommit:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustScopedACK:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustScopedOwnerPrepare:
		c = &b.Context
		o = b.OOBCommitment
		if r.Approval != nil && (!reflect.DeepEqual(r.Approval.Scope, b.Scope) || ValidateNodePairTrustScopedInitialAuthorization(*c, *r.Approval, b.GrantProof, b.ConfirmationPacket, time.Time{}) != nil) {
			return ErrInvalid
		}
	case NodePairTrustScopedOwnerComplete:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustScopedOwnerStatus:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustScopedReconcile:
		if r.State == NodePairTrustScopedRecovered && r.OriginalPacketDigest != b.OriginalPacketDigest {
			return ErrInvalid
		}
		return nil
	default:
		return ErrInvalid
	}
	if !reflect.DeepEqual(c, r.Context) || r.OOBCommitment != o {
		return ErrInvalid
	}
	return nil
}

// OpenNodePairTrustScopedRecoveredResponse authenticates both envelopes and returns
// the exact original response bytes. The old result remains historical and
// cannot authorize first trust or a fresh business operation.
func OpenNodePairTrustScopedRecoveredResponse(receiver *e2ee.Identity, hub HubIdentity, reconcilePacket, response []byte, q NodePairTrustScopedReconcile, originalBody any) (NodePairTrustScopedResult, []byte, error) {
	var original NodePairTrustScopedPacket
	if decodeCanonical(q.OriginalPacket, MaxNodePairTrustScopedPacketBytes, &original) != nil || original.Operation == OperationNodePairTrustScopedReconcile {
		return NodePairTrustScopedResult{}, nil, ErrInvalid
	}
	r, err := OpenNodePairTrustScopedResponse(receiver, hub, reconcilePacket, response, q)
	if err != nil || r.State != NodePairTrustScopedRecovered || r.OriginalPacketDigest != NodePairTrustScopedPacketDigest(q.OriginalPacket) {
		return NodePairTrustScopedResult{}, nil, ErrInvalid
	}
	old, err := OpenNodePairTrustScopedResponse(receiver, hub, q.OriginalPacket, r.OriginalReceipt, originalBody)
	if err != nil {
		return NodePairTrustScopedResult{}, nil, ErrInvalid
	}
	return old, r.OriginalReceipt, nil
}
