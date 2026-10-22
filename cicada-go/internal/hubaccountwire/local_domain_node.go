package hubaccountwire

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func localDomainNodeOperation(op string) bool {
	for _, allowed := range LocalDomainNodeOperations() {
		if op == allowed {
			return true
		}
	}
	return false
}

func ValidateLocalDomainSelection(s LocalDomainSelection) error {
	if !isHex(s.PolicyID, RequestIDBytes) || s.PolicyEpoch == 0 || s.PolicyEpoch >= 1<<63 || !isHex(s.PolicyDigest, 32) {
		return ErrInvalid
	}
	return nil
}

func DecodeLocalDomainNodePacket(raw []byte) (nodewire.Packet, error) {
	var p nodewire.Packet
	if decodeCanonical(raw, MaxLocalDomainNodeReconcilePacketBytes, &p) != nil || !localDomainNodeOperation(p.Route.Operation) || len(p.Envelope) == 0 {
		return nodewire.Packet{}, ErrInvalid
	}
	if p.Route.Direction == nodewire.DirectionRequest {
		if p.Route.Operation != OperationLocalDomainNodeReconcile && len(raw) > MaxLocalDomainNodeOriginalBytes {
			return nodewire.Packet{}, ErrInvalid
		}
	} else if p.Route.Direction == nodewire.DirectionResponse {
		if p.Route.Operation != OperationLocalDomainNodeReconcile && len(raw) > MaxLocalDomainNodeReceiptBytes {
			return nodewire.Packet{}, ErrInvalid
		}
	} else {
		return nodewire.Packet{}, ErrInvalid
	}
	return p, nil
}

func DecodeLocalDomainNodeRequest(operation string, raw []byte) (any, error) {
	switch operation {
	case OperationLocalDomainNodeAvailable:
		var q LocalDomainNodeAvailable
		var proof e2ee.LocalDomainUserReportProof
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || q.ContractRevision != LocalDomainContractRevision || !e2ee.ValidLocalDomainUserScope(q.LocalUserScope) ||
			decodeCanonical(q.LocalUserReport, e2ee.MaxLocalDomainProofBytes, &proof) != nil || proof.Report.LocalUserScope != q.LocalUserScope {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationLocalDomainNodeJoin:
		var q LocalDomainNodeJoin
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || q.ContractRevision != LocalDomainContractRevision || ValidateLocalDomainSelection(q.Selection) != nil ||
			!e2ee.ValidLocalDomainUserScope(q.LocalUserScope) || !isHex(q.AttemptID, RequestIDBytes) || q.Runtime != "codex" || !nativePairToken(q.NativeSessionID) ||
			!utf8.ValidString(q.Workspace) || q.Workspace == "" || len(q.Workspace) > 1024 || strings.ContainsRune(q.Workspace, 0) ||
			!utf8.ValidString(q.EndpointName) || len(q.EndpointName) > 128 || strings.TrimSpace(q.EndpointName) != q.EndpointName || strings.IndexFunc(q.EndpointName, unicode.IsControl) >= 0 {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationLocalDomainNodeKeyPrepare:
		var q LocalDomainNodeKeyPrepare
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || q.ContractRevision != LocalDomainContractRevision || ValidateLocalDomainSelection(q.Selection) != nil ||
			!validID(q.MemberID) || q.ExpectedRevision == 0 || q.ExpectedRevision >= 1<<63-1 {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationLocalDomainNodeKeyComplete:
		var q LocalDomainNodeKeyComplete
		var proof e2ee.LocalDomainEndpointKeyProof
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || q.ContractRevision != LocalDomainContractRevision || ValidateLocalDomainSelection(q.Selection) != nil ||
			!isHex(q.ChallengeID, RequestIDBytes) || !validID(q.MemberID) || q.ExpectedRevision == 0 || q.ExpectedRevision >= 1<<63-1 ||
			decodeCanonical(q.NodeProof, e2ee.MaxLocalDomainProofBytes, &proof) != nil || proof.Claims.PolicyID != q.Selection.PolicyID || proof.Claims.PolicyEpoch != q.Selection.PolicyEpoch ||
			proof.Claims.PolicyDigest != q.Selection.PolicyDigest || proof.Claims.MemberID != q.MemberID || proof.Claims.MemberRevision != q.ExpectedRevision+1 {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationLocalDomainNodeDescribe:
		var q LocalDomainNodeDescribe
		if decodeCanonical(raw, nodewire.MaxRequestPlaintextBytes, &q) != nil || q.ContractRevision != LocalDomainContractRevision || ValidateLocalDomainSelection(q.Selection) != nil || !e2ee.ValidLocalDomainUserScope(q.LocalUserScope) {
			return nil, ErrInvalid
		}
		return q, nil
	case OperationLocalDomainNodeReconcile:
		var q LocalDomainNodeReconcile
		if decodeCanonical(raw, MaxLocalDomainNodeReconcileBodyBytes, &q) != nil || q.ContractRevision != LocalDomainContractRevision || len(q.Nonce) != NonceBytes || validateCanonicalTime(q.IssuedAt) != nil {
			return nil, ErrInvalid
		}
		p, err := DecodeLocalDomainNodePacket(q.OriginalPacket)
		if err != nil || p.Route.Direction != nodewire.DirectionRequest || p.Route.Operation == OperationLocalDomainNodeReconcile {
			return nil, ErrInvalid
		}
		return q, nil
	}
	return nil, ErrInvalid
}

func DecodeLocalDomainNodeAvailable(raw []byte, hub HubIdentity, node e2ee.OwnerAppNodeBinding, userScope string, now time.Time) (LocalDomainNodeAvailableResult, error) {
	var result LocalDomainNodeAvailableResult
	if decodeCanonical(raw, MaxLocalDomainNodeReceiptBytes, &result) != nil || result.ContractRevision != LocalDomainContractRevision || result.LocalUserScope != userScope ||
		!e2ee.ValidLocalDomainUserScope(userScope) || len(result.Policies) > 1 || validateRecent(result.ObservedAt, now, 30*time.Second) != nil {
		return LocalDomainNodeAvailableResult{}, ErrInvalid
	}
	for _, d := range result.Policies {
		if ValidateLocalDomainDescription(d, hub, now) != nil || d.State != LocalDomainActive || d.Policy.Node.NodeID != node.NodeID || d.Policy.Node.OwnerBindingID != node.OwnerBindingID ||
			d.Policy.Node.NodeKeyEpoch != node.NodeKeyEpoch || d.Policy.Node.NodeKeyFingerprint != node.NodeKeyFingerprint || d.Policy.LocalUserScope != userScope {
			return LocalDomainNodeAvailableResult{}, ErrInvalid
		}
	}
	return result, nil
}

func LocalDomainSelectionForPolicy(p e2ee.LocalDomainPolicy) (LocalDomainSelection, error) {
	digest, err := e2ee.LocalDomainPolicyDigest(p)
	if err != nil {
		return LocalDomainSelection{}, ErrInvalid
	}
	return LocalDomainSelection{PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, PolicyDigest: digest}, nil
}

// CanonicalLocalDomainNodeRequest encodes only a validated profile-specific DTO.
func CanonicalLocalDomainNodeRequest(operation string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = DecodeLocalDomainNodeRequest(operation, raw); err != nil {
		return nil, err
	}
	return raw, nil
}
