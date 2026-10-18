package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Node management retains its existing SHA-256 over the exact packet bytes.
// App packets use the separate, domain-bound NativePairPacketDigest instead.
func NativePairNodePacketDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// This encodes the same SHA-256 as Fabric's raw-base64url credential digest;
// it does not hash that digest a second time or authenticate a credential.
func NativePairCredentialCommitment(actualToken string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(actualToken)))
	return hex.EncodeToString(sum[:])
}

func nativePairNodeOperation(op string) bool {
	return op == OperationNativePairNodeDescribe || op == OperationNativePairNodeJoin || op == OperationNativePairNodeReconcile
}

// These bounds are specific to the new methods. The nodewire defaults and
// every old operation's decoder remain unchanged.
func DecodeNativePairNodePacket(raw []byte) (nodewire.Packet, error) {
	var p nodewire.Packet
	if decodeCanonical(raw, MaxNativePairNodeReconcilePacketBytes, &p) != nil || !nativePairNodeOperation(p.Route.Operation) || len(p.Envelope) == 0 {
		return nodewire.Packet{}, ErrInvalid
	}
	if p.Route.Direction == nodewire.DirectionRequest {
		if len(raw) > nodewire.MaxRequestPacketBytes {
			return nodewire.Packet{}, ErrInvalid
		}
		if p.Route.Operation != OperationNativePairNodeReconcile && len(raw) > MaxNativePairNodeOriginalBytes {
			return nodewire.Packet{}, ErrInvalid
		}
	} else if p.Route.Direction == nodewire.DirectionResponse {
		if p.Route.Operation != OperationNativePairNodeReconcile && len(raw) > MaxNativePairNodeReceiptBytes {
			return nodewire.Packet{}, ErrInvalid
		}
	} else {
		return nodewire.Packet{}, ErrInvalid
	}
	return p, nil
}

func DecodeNativePairNodeRequest(operation string, raw []byte) (any, error) {
	valid := func(revision, pair string) bool {
		return revision == NativePairContractRevision && isHex(pair, RequestIDBytes)
	}
	switch operation {
	case OperationNativePairNodeDescribe:
		var q NativePairNodeDescribe
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || !valid(q.ContractRevision, q.PairID) {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationNativePairNodeJoin:
		var q NativePairNodeJoin
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || !valid(q.ContractRevision, q.PairID) || (q.Slot != "A" && q.Slot != "B") ||
			q.ExpectedGeneration == 0 || q.ExpectedGeneration > MaxNativePairSlotGenerations || !isHex(q.BootstrapProofDigest, 32) || q.Runtime != "codex" ||
			!nativePairToken(q.NativeSessionID) || !utf8.ValidString(q.EndpointName) || len(q.EndpointName) > 128 || strings.TrimSpace(q.EndpointName) != q.EndpointName ||
			strings.IndexFunc(q.EndpointName, unicode.IsControl) >= 0 || q.Workspace == "" || !utf8.ValidString(q.Workspace) || len(q.Workspace) > 1024 || strings.ContainsRune(q.Workspace, 0) {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationNativePairNodeReconcile:
		var q NativePairNodeReconcile
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || !valid(q.ContractRevision, q.PairID) || len(q.Nonce) != NonceBytes || validateCanonicalTime(q.IssuedAt) != nil {
			return nil, ErrInvalid
		}
		p, err := DecodeNativePairNodePacket(q.OriginalPacket)
		if err != nil || p.Route.Direction != nodewire.DirectionRequest || p.Route.Operation == OperationNativePairNodeReconcile {
			return nil, ErrInvalid
		}
		return q, nil
	}
	return nil, ErrInvalid
}

func nativePairNodeDescriptionShape(d NativePairNodeDescription) error {
	if d.ContractRevision != NativePairContractRevision || !isHex(d.PairID, RequestIDBytes) || len(d.BootstrapOwnerProof) == 0 || len(d.BootstrapOwnerProof) > e2ee.MaxOwnerNativePairProofBytes ||
		d.SlotAGeneration == 0 || d.SlotAGeneration > MaxNativePairSlotGenerations || d.SlotBGeneration == 0 || d.SlotBGeneration > MaxNativePairSlotGenerations {
		return ErrInvalid
	}
	_, err := HubFingerprint(d.HubIdentity)
	return err
}

// raw is the normal Node RPC result JSON, not the complete response wrapper.
func DecodeNativePairNodeDescription(raw []byte) (NativePairNodeDescription, error) {
	var d NativePairNodeDescription
	if decodeCanonical(raw, MaxNativePairNodeReceiptBytes, &d) != nil || nativePairNodeDescriptionShape(d) != nil {
		return NativePairNodeDescription{}, ErrInvalid
	}
	return d, nil
}

// Local callers must additionally compare their pinned Hub origin, complete
// original Node-Control tuple and actual credential before persisting policy.
// The committed bootstrap is verified historically: its short administration
// proof expiry does not replace the signed absolute Join/peer deadlines.
func VerifyNativePairNodeDescription(d NativePairNodeDescription, trustedOwner e2ee.PublicIdentity, expectedPairID string, now time.Time) (e2ee.OwnerNativePairClaims, error) {
	if now.IsZero() || d.PairID != expectedPairID || nativePairNodeDescriptionShape(d) != nil {
		return e2ee.OwnerNativePairClaims{}, ErrInvalid
	}
	c, err := e2ee.VerifyOwnerNativePair(trustedOwner, d.BootstrapOwnerProof, e2ee.OwnerNativePairBootstrapCommit, time.Time{})
	if err != nil || c.Bootstrap.PairID != d.PairID || ValidateNativePairScope(c.Scope, d.HubIdentity) != nil {
		return e2ee.OwnerNativePairClaims{}, ErrInvalid
	}
	end, err := parseCanonicalUTC(c.Bootstrap.JoinUntil)
	if err != nil || !now.Before(end) {
		return e2ee.OwnerNativePairClaims{}, ErrInvalid
	}
	return c, nil
}

func ValidateNativePairNodeReconcileTarget(r NativePairNodeReconciled, pairID string, original []byte) error {
	p, err := DecodeNativePairNodePacket(original)
	if err != nil || p.Route.Direction != nodewire.DirectionRequest || p.Route.Operation == OperationNativePairNodeReconcile || r.ContractRevision != NativePairContractRevision ||
		!isHex(pairID, RequestIDBytes) || r.PairID != pairID || r.OriginalOperation != p.Route.Operation || r.OriginalOperationID != p.Route.OperationID ||
		r.OriginalSequence != p.Route.Sequence || r.OriginalPacketDigest != NativePairNodePacketDigest(original) || validateCanonicalTime(r.ObservedAt) != nil {
		return ErrInvalid
	}
	if r.State == "READ_EXPIRED" {
		if p.Route.Operation != OperationNativePairNodeDescribe || len(r.ReceiptPacket) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if r.State != "COMPLETED" && r.State != "REJECTED_FENCED" || r.State == "REJECTED_FENCED" && p.Route.Operation != OperationNativePairNodeJoin || len(r.ReceiptPacket) == 0 || len(r.ReceiptPacket) > MaxNativePairNodeReceiptBytes {
		return ErrInvalid
	}
	receipt, err := DecodeNativePairNodePacket(r.ReceiptPacket)
	wanted := p.Route
	wanted.Direction = nodewire.DirectionResponse
	wanted.SenderKeyID, wanted.ReceiverKeyID = wanted.ReceiverKeyID, wanted.SenderKeyID
	wanted.SenderKeyVersion, wanted.ReceiverKeyVersion = wanted.ReceiverKeyVersion, wanted.SenderKeyVersion
	if err != nil || receipt.Route != wanted {
		return ErrInvalid
	}
	return nil
}

// The outer Node response is authenticated with the diagnostic route. Callers
// then open ReceiptPacket against the retained original route before durably
// applying any settlement; this structural target check is not a signature.
func DecodeNativePairNodeReconciled(raw []byte) (NativePairNodeReconciled, error) {
	var r NativePairNodeReconciled
	if decodeCanonical(raw, MaxNativePairNodeReconcileBodyBytes, &r) != nil || r.ContractRevision != NativePairContractRevision ||
		!isHex(r.PairID, RequestIDBytes) || !isHex(r.OriginalPacketDigest, 32) || !nativePairPositive(r.OriginalSequence) ||
		validateCanonicalTime(r.ObservedAt) != nil || len(r.ReceiptPacket) > MaxNativePairNodeReceiptBytes {
		return NativePairNodeReconciled{}, ErrInvalid
	}
	if r.OriginalOperation != OperationNativePairNodeDescribe && r.OriginalOperation != OperationNativePairNodeJoin ||
		r.OriginalOperationID == "" || len(r.OriginalOperationID) > 256 || (r.State != "COMPLETED" && r.State != "REJECTED_FENCED" && r.State != "READ_EXPIRED") ||
		(r.State == "READ_EXPIRED" && (r.OriginalOperation != OperationNativePairNodeDescribe || len(r.ReceiptPacket) != 0)) ||
		(r.State != "READ_EXPIRED" && len(r.ReceiptPacket) == 0) || (r.State == "REJECTED_FENCED" && r.OriginalOperation != OperationNativePairNodeJoin) {
		return NativePairNodeReconciled{}, ErrInvalid
	}
	return r, nil
}
