package hubaccountwire

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func nodePairCredentialDigest(s string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func nodePairBody(op string) any {
	switch op {
	case OperationNodePairTrustStart:
		return &NodePairTrustStart{}
	case OperationNodePairTrustExisting:
		return &NodePairTrustExistingStart{}
	case OperationNodePairTrustCommit, OperationNodePairTrustPoll, OperationNodePairTrustCancel:
		return &NodePairTrustCommit{}
	case OperationNodePairTrustACK:
		return &NodePairTrustACK{}
	case OperationNodePairTrustReconcile:
		return &NodePairTrustReconcile{}
	case OperationOwnerNodePairTrustPrepare:
		return &NodePairTrustOwnerPrepare{}
	case OperationOwnerNodePairTrustLookup:
		return &NodePairTrustOwnerLookup{}
	case OperationOwnerNodePairTrustComplete:
		return &NodePairTrustOwnerComplete{}
	case OperationOwnerNodePairTrustStatus, OperationOwnerNodePairTrustCancel:
		return &NodePairTrustOwnerStatus{}
	}
	return nil
}
func nodePairLimits(op string) (int, int) {
	if op == OperationNodePairTrustReconcile {
		return MaxNodePairTrustReconcileBodyBytes, MaxNodePairTrustReconcilePacketBytes
	}
	return MaxNodePairTrustBodyBytes, MaxNodePairTrustPacketBytes
}
func nodePairHeader(p NodePairTrustPacket) NodePairTrustPacket { p.Packet = nil; return p }
func nodePairAAD(p NodePairTrustPacket, hub HubIdentity, direction, original string) []byte {
	raw, _ := json.Marshal(struct {
		Header    NodePairTrustPacket `json:"header"`
		Hub       HubIdentity         `json:"hub"`
		Direction string              `json:"direction"`
		Original  string              `json:"original_packet_digest"`
	}{nodePairHeader(p), hub, direction, original})
	return append([]byte("cicada/node-pair-trust/packet-aad/v1\x00"), raw...)
}
func preflightNodePair(raw []byte, operation string, maximum int) (NodePairTrustPacket, error) {
	var p NodePairTrustPacket
	if decodeCanonical(raw, maximum, &p) != nil || p.Format != NodePairTrustPacketFormat || p.Version != 1 || p.Operation != operation || NodePairTrustHTTPPath(operation) == "" || !isHex(p.RequestID, 16) || !isHex(p.AttemptID, 16) || e2ee.ValidatePublicIdentity(p.SenderPublic) != nil || len(p.Packet) == 0 || len(p.Packet) > maximum {
		return p, ErrInvalid
	}
	return p, nil
}

func SealNodePairTrustRequest(sender *e2ee.Identity, hub HubIdentity, h NodePairTrustPacket, body any, now time.Time) ([]byte, error) {
	h.Format, h.Version = NodePairTrustPacketFormat, 1
	if sender == nil {
		return nil, ErrInvalid
	}
	h.SenderPublic = sender.Public()
	if nodePairBody(h.Operation) == nil || reflect.TypeOf(dereference(body)) != reflect.TypeOf(dereference(nodePairBody(h.Operation))) || validateNodePairBody(h, body, hub, now) != nil {
		return nil, ErrInvalid
	}
	plain, err := json.Marshal(body)
	bodyMax, packetMax := nodePairLimits(h.Operation)
	if err != nil || len(plain) > bodyMax {
		return nil, ErrInvalid
	}
	defer clear(plain)
	h.Packet, err = e2ee.Seal(sender, hub.Public, plain, nodePairAAD(h, hub, "REQUEST", ""), 1)
	if err != nil {
		return nil, ErrInvalid
	}
	out, err := json.Marshal(h)
	if err != nil || len(out) > packetMax {
		return nil, ErrInvalid
	}
	return out, nil
}

func OpenNodePairTrustRequest(hubKey *e2ee.Identity, hub HubIdentity, raw []byte, operation string, out any, now time.Time) (NodePairTrustPacket, error) {
	bodyMax, packetMax := nodePairLimits(operation)
	h, err := preflightNodePair(raw, operation, packetMax)
	if err != nil || hubKey == nil || !reflect.DeepEqual(hubKey.Public(), hub.Public) || reflect.TypeOf(out) != reflect.TypeOf(nodePairBody(operation)) {
		return h, ErrInvalid
	}
	plain, seq, err := e2ee.Open(hubKey, h.SenderPublic, h.Packet, nodePairAAD(h, hub, "REQUEST", ""))
	if err != nil || seq != 1 {
		return h, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, bodyMax, out) != nil || validateNodePairBody(h, out, hub, now) != nil {
		return h, ErrInvalid
	}
	return h, nil
}

// Historical authentication has no fresh-admission result. The service may
// only recover the matching original receipt or permanently fence that exact
// packet; it must never dispatch this result as a new operation.
type NodePairTrustHistoricalOriginal struct {
	Header       NodePairTrustPacket
	PacketDigest string
}

func AuthenticateNodePairTrustOriginal(hubKey *e2ee.Identity, hub HubIdentity, raw []byte, out any) (NodePairTrustHistoricalOriginal, error) {
	var header struct {
		Operation string `json:"operation"`
	}
	if len(raw) > MaxNodePairTrustPacketBytes || json.Unmarshal(raw, &header) != nil || header.Operation == OperationNodePairTrustReconcile {
		return NodePairTrustHistoricalOriginal{}, ErrInvalid
	}
	h, err := preflightNodePair(raw, header.Operation, MaxNodePairTrustPacketBytes)
	if err != nil || hubKey == nil || !reflect.DeepEqual(hubKey.Public(), hub.Public) || reflect.TypeOf(out) != reflect.TypeOf(nodePairBody(h.Operation)) {
		return NodePairTrustHistoricalOriginal{}, ErrInvalid
	}
	plain, seq, err := e2ee.Open(hubKey, h.SenderPublic, h.Packet, nodePairAAD(h, hub, "REQUEST", ""))
	if err != nil || seq != 1 {
		return NodePairTrustHistoricalOriginal{}, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, MaxNodePairTrustBodyBytes, out) != nil {
		return NodePairTrustHistoricalOriginal{}, ErrInvalid
	}
	return NodePairTrustHistoricalOriginal{h, NodePairTrustPacketDigest(raw)}, nil
}

func ValidateNodePairTrustStartProof(hubNC *e2ee.Identity, node e2ee.PublicIdentity, b NodePairTrustStart) error {
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

func nodePairKnownState(s string) bool {
	switch s {
	case NodePairTrustPending, NodePairTrustOwnerApproved, NodePairTrustACKed, NodePairTrustExpired, NodePairTrustCancelled, NodePairTrustRevoked, NodePairTrustFenced, NodePairTrustRecovered:
		return true
	}
	return false
}
func nodePairKnownError(s string) bool {
	switch s {
	case "", "INVALID_REQUEST", "NOT_FOUND", "CONFLICT", "EXPIRED", "CANCELLED", "REVOKED", "FENCED", "ACK_REQUIRED", "UNAVAILABLE", "OUTCOME_UNCERTAIN":
		return true
	}
	return false
}
func validateNodePairResult(h NodePairTrustPacket, r NodePairTrustResult, hub HubIdentity) error {
	if r.Format != NodePairTrustFormat || r.Operation != h.Operation || r.RequestID != h.RequestID || r.AttemptID != h.AttemptID || !isHex(r.RequestPacketDigest, 32) || !nodePairKnownState(r.State) || !nodePairKnownError(r.ErrorCode) || validateCanonicalTime(r.ObservedAt) != nil {
		return ErrInvalid
	}
	if h.Operation == OperationNodePairTrustReconcile {
		if r.Context != nil || r.OOBCommitment != "" || r.Selector != "" || r.Approval != nil || len(r.OwnerProof) != 0 || len(r.TrustCapsule) != 0 || r.Binding != nil || len(r.ConfirmationResponse) != 0 {
			return ErrInvalid
		}
		if r.ErrorCode != "" {
			if r.ErrorCode != "FENCED" || r.State != NodePairTrustFenced || r.OriginalPacketDigest != "" || len(r.OriginalReceipt) != 0 {
				return ErrInvalid
			}
			return nil
		}
		if r.State != NodePairTrustRecovered || !isHex(r.OriginalPacketDigest, 32) || len(r.OriginalReceipt) == 0 || len(r.OriginalReceipt) > MaxNodePairTrustOriginalReceiptBytes {
			return ErrInvalid
		}
		return nil
	}
	if r.State == NodePairTrustRecovered || r.OriginalPacketDigest != "" || len(r.OriginalReceipt) != 0 {
		return ErrInvalid
	}
	if r.ErrorCode != "" {
		if r.Context != nil || r.OOBCommitment != "" || r.Selector != "" || r.Approval != nil || len(r.OwnerProof) != 0 || len(r.TrustCapsule) != 0 || r.Binding != nil || len(r.ConfirmationResponse) != 0 {
			return ErrInvalid
		}
		return nil
	}
	switch h.Operation {
	case OperationNodePairTrustStart, OperationNodePairTrustExisting, OperationNodePairTrustCommit, OperationOwnerNodePairTrustPrepare:
		if r.State != NodePairTrustPending {
			return ErrInvalid
		}
	case OperationOwnerNodePairTrustComplete:
		if r.State != NodePairTrustOwnerApproved {
			return ErrInvalid
		}
	case OperationNodePairTrustACK:
		if r.State != NodePairTrustACKed {
			return ErrInvalid
		}
	case OperationNodePairTrustCancel, OperationOwnerNodePairTrustCancel:
		if r.State != NodePairTrustCancelled {
			return ErrInvalid
		}
	}
	if r.Context == nil || ValidateNodePairTrustContext(*r.Context, time.Time{}) != nil || r.Context.AttemptID != h.AttemptID || !reflect.DeepEqual(r.Context.Hub, hub) {
		return ErrInvalid
	}
	if !nodePairOperationOwner(h.Operation) && h.Operation != OperationNodePairTrustReconcile && !reflect.DeepEqual(nodePairPublic(*r.Context), h.SenderPublic) {
		return ErrInvalid
	}
	start := h.Operation == OperationNodePairTrustStart || h.Operation == OperationNodePairTrustExisting
	if start {
		if r.State != NodePairTrustPending || r.OOBCommitment != "" {
			return ErrInvalid
		}
		if h.Operation == OperationNodePairTrustStart {
			digest, e := AppNodeCodeDigest(hub.HubID, r.Selector)
			if e != nil || r.Context.Mode != NodePairTrustInitial || digest != r.Context.Candidate.CodeDigest {
				return ErrInvalid
			}
		} else if r.Selector != "" || r.Context.Mode != NodePairTrustExisting {
			return ErrInvalid
		}
	} else if !isHex(r.OOBCommitment, 32) || r.Selector != "" {
		return ErrInvalid
	}
	if h.Operation == OperationOwnerNodePairTrustPrepare {
		if r.State != NodePairTrustPending || r.Approval == nil || ValidateNodePairTrustApproval(*r.Approval, *r.Context, r.OOBCommitment, time.Time{}) != nil {
			return ErrInvalid
		}
	} else if r.Approval != nil {
		return ErrInvalid
	}
	if h.Operation == OperationNodePairTrustPoll && r.State == NodePairTrustOwnerApproved {
		var p NodePairTrustOwnerProof
		if decodeCanonical(r.OwnerProof, MaxNodePairTrustProofBytes, &p) != nil || len(r.TrustCapsule) == 0 || len(r.TrustCapsule) > MaxNodePairTrustCapsuleBytes || p.Claims.CapsuleDigest != NodePairTrustCapsuleDigest(r.TrustCapsule) || ValidateNodePairTrustApproval(p.Claims.Approval, *r.Context, r.OOBCommitment, time.Time{}) != nil {
			return ErrInvalid
		}
	} else if len(r.OwnerProof) != 0 || len(r.TrustCapsule) != 0 {
		return ErrInvalid
	}
	if r.State == NodePairTrustACKed {
		if r.Binding == nil {
			return ErrInvalid
		}
		if h.Operation == OperationOwnerNodePairTrustStatus && r.Context.Mode == NodePairTrustInitial {
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

func nodePairResponseLimits(op string) (int, int) {
	if op == OperationNodePairTrustReconcile {
		return MaxNodePairTrustReconcileResponseBodyBytes, MaxNodePairTrustReconcileResponsePacketBytes
	}
	return MaxNodePairTrustResponseBodyBytes, MaxNodePairTrustResponsePacketBytes
}

func SealNodePairTrustResponse(hubKey *e2ee.Identity, hub HubIdentity, original []byte, requestBody any, r NodePairTrustResult) ([]byte, error) {
	var q NodePairTrustPacket
	if hubKey == nil || !reflect.DeepEqual(hubKey.Public(), hub.Public) || decodeCanonical(original, MaxNodePairTrustReconcilePacketBytes, &q) != nil {
		return nil, ErrInvalid
	}
	_, limit := nodePairLimits(q.Operation)
	h, err := preflightNodePair(original, q.Operation, limit)
	if err != nil || r.RequestPacketDigest != NodePairTrustPacketDigest(original) || validateNodePairResult(h, r, hub) != nil || matchNodePairResult(h, requestBody, r) != nil {
		return nil, ErrInvalid
	}
	plain, err := json.Marshal(r)
	bodyLimit, packetLimit := nodePairResponseLimits(h.Operation)
	if err != nil || len(plain) > bodyLimit {
		return nil, ErrInvalid
	}
	defer clear(plain)
	response := nodePairHeader(h)
	response.SenderPublic = hub.Public
	response.Packet, err = e2ee.Seal(hubKey, h.SenderPublic, plain, nodePairAAD(response, hub, "RESPONSE", r.RequestPacketDigest), 1)
	if err != nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > packetLimit {
		return nil, ErrInvalid
	}
	return raw, nil
}

func OpenNodePairTrustResponse(receiver *e2ee.Identity, hub HubIdentity, original, response []byte, requestBody any) (NodePairTrustResult, error) {
	var q NodePairTrustPacket
	var out NodePairTrustResult
	if receiver == nil || decodeCanonical(original, MaxNodePairTrustReconcilePacketBytes, &q) != nil || !reflect.DeepEqual(receiver.Public(), q.SenderPublic) {
		return out, ErrInvalid
	}
	_, limit := nodePairLimits(q.Operation)
	h, err := preflightNodePair(original, q.Operation, limit)
	bodyLimit, packetLimit := nodePairResponseLimits(q.Operation)
	r, err2 := preflightNodePair(response, q.Operation, packetLimit)
	if err != nil || err2 != nil || !reflect.DeepEqual(r.SenderPublic, hub.Public) || r.RequestID != h.RequestID || r.AttemptID != h.AttemptID {
		return out, ErrInvalid
	}
	digest := NodePairTrustPacketDigest(original)
	plain, seq, err := e2ee.Open(receiver, hub.Public, r.Packet, nodePairAAD(r, hub, "RESPONSE", digest))
	if err != nil || seq != 1 {
		return out, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, bodyLimit, &out) != nil || out.RequestPacketDigest != digest || validateNodePairResult(h, out, hub) != nil || matchNodePairResult(h, requestBody, out) != nil {
		return NodePairTrustResult{}, ErrInvalid
	}
	return out, nil
}

func matchNodePairResult(h NodePairTrustPacket, body any, r NodePairTrustResult) error {
	if reflect.TypeOf(dereference(body)) != reflect.TypeOf(dereference(nodePairBody(h.Operation))) {
		return ErrInvalid
	}
	if r.ErrorCode != "" {
		return nil
	}
	var c *NodePairTrustContext
	var o string
	switch b := dereference(body).(type) {
	case NodePairTrustOwnerLookup:
		d, e := NodePairTrustContextDigest(*r.Context)
		if e != nil || d != b.ContextDigest || r.Context.Origin != b.Scope.Origin {
			return ErrInvalid
		}
		if r.Context.Mode == NodePairTrustInitial {
			selector, e := AppNodeCodeDigest(r.Context.Hub.HubID, b.Selector)
			if e != nil || selector != r.Context.Candidate.CodeDigest {
				return ErrInvalid
			}
		} else if b.Selector != "" || r.Context.Binding.OwnerID != b.Scope.OwnerID || r.Context.Binding.OwnerKeyID != b.Scope.OwnerPublic.ID {
			return ErrInvalid
		}
		return nil
	case NodePairTrustStart:
		x := r.Context
		n := x.Candidate
		if x.Mode != NodePairTrustInitial || n == nil || x.Origin != b.Origin || x.DescriptorDigest != b.DescriptorDigest || x.NodeNonce != hex.EncodeToString(b.RequestNonce) || n.NodeID != b.NodeID || n.NodeName != b.NodeName || !reflect.DeepEqual(n.HubNodeControlPublic, b.HubNodeControlPublic) || n.HubNodeControlKeyVersion != b.HubNodeControlKeyVersion {
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
	case NodePairTrustExistingStart:
		c = &b.Context
	case NodePairTrustCommit:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustACK:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustOwnerPrepare:
		c = &b.Context
		o = b.OOBCommitment
		if r.Approval != nil && (!reflect.DeepEqual(r.Approval.Scope, b.Scope) || ValidateNodePairTrustInitialAuthorization(*c, *r.Approval, b.GrantProof, b.ConfirmationPacket, time.Time{}) != nil) {
			return ErrInvalid
		}
	case NodePairTrustOwnerComplete:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustOwnerStatus:
		c = &b.Context
		o = b.OOBCommitment
	case NodePairTrustReconcile:
		if r.State == NodePairTrustRecovered && r.OriginalPacketDigest != b.OriginalPacketDigest {
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

// OpenNodePairTrustRecoveredResponse authenticates both envelopes and returns
// the exact original response bytes. The old result remains historical and
// cannot authorize first trust or a fresh business operation.
func OpenNodePairTrustRecoveredResponse(receiver *e2ee.Identity, hub HubIdentity, reconcilePacket, response []byte, q NodePairTrustReconcile, originalBody any) (NodePairTrustResult, []byte, error) {
	var original NodePairTrustPacket
	if decodeCanonical(q.OriginalPacket, MaxNodePairTrustPacketBytes, &original) != nil || original.Operation == OperationNodePairTrustReconcile {
		return NodePairTrustResult{}, nil, ErrInvalid
	}
	r, err := OpenNodePairTrustResponse(receiver, hub, reconcilePacket, response, q)
	if err != nil || r.State != NodePairTrustRecovered || r.OriginalPacketDigest != NodePairTrustPacketDigest(q.OriginalPacket) {
		return NodePairTrustResult{}, nil, ErrInvalid
	}
	old, err := OpenNodePairTrustResponse(receiver, hub, q.OriginalPacket, r.OriginalReceipt, originalBody)
	if err != nil {
		return NodePairTrustResult{}, nil, ErrInvalid
	}
	return old, r.OriginalReceipt, nil
}
