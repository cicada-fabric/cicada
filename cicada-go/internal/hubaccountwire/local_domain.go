package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func localDomainOperation(op string) bool { return LocalDomainHTTPPath(op) != "" }

func LocalDomainPacketDigest(raw []byte) string {
	sum := sha256.Sum256(append([]byte("cicada/local-domain-packet/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func LocalDomainProofDigest(raw []byte) string {
	sum := sha256.Sum256(append([]byte("cicada/local-domain-proof/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func localDomainParts(body any) (op, format string, c AppNodeRequestContext, token, proof []byte) {
	switch v := dereference(body).(type) {
	case LocalDomainPrepare:
		return OperationLocalDomainPrepare, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case LocalDomainActivate:
		return OperationLocalDomainActivate, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case LocalDomainStatusRequest:
		return OperationLocalDomainStatus, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case LocalDomainRevoke:
		return OperationLocalDomainRevoke, v.Format, v.Context, v.SessionToken, v.OwnerProof
	case LocalDomainReconcileRequest:
		return OperationLocalDomainReconcile, v.Format, v.Context, nil, nil
	}
	return
}

func localDomainMetadata(body any) (op, id, owner, device string, epoch uint64, err error) {
	op, _, c, _, _ := localDomainParts(body)
	if op == "" {
		return "", "", "", "", 0, ErrInvalid
	}
	return op, c.RequestID, c.OwnerID, c.DeviceID, HandshakeEpoch, nil
}

func ValidateLocalDomainPolicy(p e2ee.LocalDomainPolicy, hub HubIdentity, now time.Time) error {
	fp, err := HubFingerprint(hub)
	if err != nil || e2ee.ValidateLocalDomainPolicy(p, now) != nil || p.HubID != hub.HubID || p.HubFingerprint != fp ||
		p.Node.NodeKeyFingerprint != nodewire.IdentityFingerprint(p.Node.NodePublic) || p.Node.HubNodeControlFingerprint != nodewire.IdentityFingerprint(p.Node.HubNodeControlPublic) {
		return ErrInvalid
	}
	return nil
}

func validateLocalDomainRequest(body any, hub HubIdentity, now time.Time) error {
	op, format, c, token, raw := localDomainParts(body)
	if !localDomainOperation(op) || format != LocalDomainFormat || !appNodeContextValid(c, hub, now) {
		return ErrInvalid
	}
	if op == OperationLocalDomainReconcile {
		q := dereference(body).(LocalDomainReconcileRequest)
		p, err := DecodeLocalDomainPacket(q.OriginalPacket)
		if err != nil || len(q.OriginalPacket) > MaxLocalDomainOriginalBytes || p.Packet.Route.Direction != clientwire.DirectionRequest ||
			p.Packet.Route.Operation == OperationLocalDomainReconcile || p.Packet.Route.HubID != c.HubID || p.Packet.Route.OwnerID != c.OwnerID || p.Packet.Route.DeviceID != c.DeviceID {
			return ErrInvalid
		}
		return nil
	}
	var proof e2ee.OwnerLocalDomainRequestProof
	if len(token) != MaxSessionTokenBytes || decodeCanonical(raw, e2ee.MaxLocalDomainProofBytes, &proof) != nil ||
		ValidateAppNodeScope(proof.Claims.Scope, hub) != nil || !appNodeContextScope(c, proof.Claims.Scope) || proof.Claims.RequestID != c.RequestID || proof.Claims.Nonce != hex.EncodeToString(c.ClientNonce) || proof.Claims.IssuedAt != c.IssuedAt {
		return ErrInvalid
	}
	if _, err := e2ee.VerifyOwnerLocalDomainRequest(proof.Claims.Scope.OwnerPublic, raw, LocalDomainOwnerPurpose(op), now); err != nil {
		return ErrInvalid
	}
	if q, ok := dereference(body).(LocalDomainActivate); ok {
		policy, err := e2ee.VerifyOwnerLocalDomainPolicy(proof.Claims.Scope.OwnerPublic, q.PolicyProof, now)
		digest, de := e2ee.LocalDomainPolicyDigest(policy)
		if err != nil || de != nil || ValidateLocalDomainPolicy(policy, hub, now) != nil || digest != proof.Claims.PolicyDigest || policy.PolicyID != proof.Claims.PolicyID || policy.Epoch != proof.Claims.PolicyEpoch ||
			policy.Origin != c.Origin || policy.OwnerID != c.OwnerID || policy.OwnerKeyVersion != proof.Claims.Scope.OwnerKeyVersion {
			return ErrInvalid
		}
	}
	return nil
}

func localDomainRequest(s AppNodeSession, scope e2ee.OwnerAppNodeScope, purpose string, owner *e2ee.Identity, now time.Time) (LocalDomainPrepare, e2ee.OwnerLocalDomainRequestClaims, error) {
	c, err := s.context(now, true)
	if err != nil || ValidateAppNodeScope(scope, s.Hub) != nil || !appNodeContextScope(c, scope) || owner == nil || !reflect.DeepEqual(owner.Public(), scope.OwnerPublic) {
		return LocalDomainPrepare{}, e2ee.OwnerLocalDomainRequestClaims{}, ErrInvalid
	}
	end := now.Add(e2ee.LocalDomainRequestLifetime)
	sessionEnd, _ := parseCanonicalUTC(scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	claims := e2ee.OwnerLocalDomainRequestClaims{Version: 1, Purpose: purpose, Scope: scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: formatUTC(end)}
	return LocalDomainPrepare{Format: LocalDomainFormat, Context: c, SessionToken: append([]byte(nil), s.Token...)}, claims, nil
}

func NewLocalDomainPrepare(s AppNodeSession, scope e2ee.OwnerAppNodeScope, target e2ee.LocalDomainTarget, owner *e2ee.Identity, now time.Time) (LocalDomainPrepare, error) {
	q, claims, err := localDomainRequest(s, scope, e2ee.OwnerLocalDomainPreparePurpose, owner, now)
	if err != nil {
		return LocalDomainPrepare{}, err
	}
	claims.Target = &target
	q.OwnerProof, err = e2ee.SignOwnerLocalDomainRequest(owner, claims)
	if err != nil || validateLocalDomainRequest(q, s.Hub, now) != nil {
		return LocalDomainPrepare{}, ErrInvalid
	}
	return q, nil
}

// ValidateLocalDomainChallenge compares the exact local request and encrypted
// packet with every server-derived authority coordinate before Owner signing.
func ValidateLocalDomainChallenge(prepare LocalDomainPrepare, original []byte, ch LocalDomainChallenge, hub HubIdentity, now time.Time) error {
	var intent e2ee.OwnerLocalDomainRequestProof
	if validateLocalDomainRequest(prepare, hub, time.Time{}) != nil || decodeCanonical(prepare.OwnerProof, e2ee.MaxLocalDomainProofBytes, &intent) != nil || intent.Claims.Target == nil ||
		ch.Format != LocalDomainFormat || ch.RequestID != prepare.Context.RequestID || ch.RequestPacketDigest != LocalDomainPacketDigest(original) || ch.PrepareProofDigest != LocalDomainProofDigest(prepare.OwnerProof) ||
		ch.Revision != 1 || ValidateLocalDomainPolicy(ch.Policy, hub, now) != nil || validateTimeWindowNow(ch.ObservedAt, ch.ProofExpiresAt, e2ee.LocalDomainRequestLifetime, now) != nil {
		return ErrInvalid
	}
	p, err := DecodeLocalDomainPacket(original)
	target, policy := *intent.Claims.Target, ch.Policy
	report, reportErr := e2ee.VerifyLocalDomainUserReport(target.Node, ch.LocalUserReport, now)
	if err != nil || p.Packet.Route.Operation != OperationLocalDomainPrepare || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.OperationID != ch.RequestID ||
		p.Packet.Route.HubID != hub.HubID || p.Packet.Route.OwnerID != policy.OwnerID || p.Packet.Route.DeviceID != prepare.Context.DeviceID || !reflect.DeepEqual(p.SenderPublicIdentity, intent.Claims.Scope.DevicePublic) ||
		policy.Origin != intent.Claims.Scope.Origin || policy.OwnerID != intent.Claims.Scope.OwnerID || !reflect.DeepEqual(policy.OwnerPublic, intent.Claims.Scope.OwnerPublic) || policy.OwnerKeyVersion != intent.Claims.Scope.OwnerKeyVersion ||
		!reflect.DeepEqual(policy.Node, target.Node) || reportErr != nil || policy.LocalUserScope != report.LocalUserScope || (target.LocalUserScope != "" && policy.LocalUserScope != target.LocalUserScope) || policy.GroupName != target.GroupName || policy.ExpiresAt != target.ExpiresAt ||
		policy.PrepareRequestID != ch.RequestID || policy.PreparePacketDigest != ch.RequestPacketDigest || policy.IssuedAt != ch.ObservedAt {
		return ErrInvalid
	}
	if target.NetworkID != "" {
		if policy.CreateNetwork || policy.NetworkID != target.NetworkID {
			return ErrInvalid
		}
	} else if !policy.CreateNetwork || policy.NetworkName != target.NewNetworkName {
		return ErrInvalid
	}
	end, _ := parseCanonicalUTC(ch.ProofExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(intent.Claims.Scope.AccountSessionExpiresAt)
	reportEnd, _ := parseCanonicalUTC(report.ExpiresAt)
	intentEnd, _ := parseCanonicalUTC(intent.Claims.ExpiresAt)
	reportIssued, _ := parseCanonicalUTC(report.IssuedAt)
	preparedAt, _ := parseCanonicalUTC(ch.ObservedAt)
	if end.After(sessionEnd) || end.After(reportEnd) || end.After(intentEnd) || reportIssued.After(preparedAt) {
		return ErrInvalid
	}
	return nil
}

func NewLocalDomainActivate(s AppNodeSession, scope e2ee.OwnerAppNodeScope, prepare LocalDomainPrepare, original []byte, ch LocalDomainChallenge, owner *e2ee.Identity, now time.Time) (LocalDomainActivate, error) {
	q, claims, err := localDomainRequest(s, scope, e2ee.OwnerLocalDomainActivatePurpose, owner, now)
	if err != nil || ValidateLocalDomainChallenge(prepare, original, ch, s.Hub, now) != nil || !bytes.Equal(s.Token, prepare.SessionToken) || !reflect.DeepEqual(owner.Public(), ch.Policy.OwnerPublic) ||
		ch.Policy.Origin != scope.Origin || ch.Policy.OwnerID != scope.OwnerID || ch.Policy.OwnerKeyVersion != scope.OwnerKeyVersion {
		return LocalDomainActivate{}, ErrInvalid
	}
	claims.PolicyID, claims.PolicyEpoch, claims.ExpectedRevision = ch.Policy.PolicyID, ch.Policy.Epoch, ch.Revision
	claims.PolicyDigest, err = e2ee.LocalDomainPolicyDigest(ch.Policy)
	if err != nil {
		return LocalDomainActivate{}, err
	}
	end, _ := parseCanonicalUTC(claims.ExpiresAt)
	challengeEnd, _ := parseCanonicalUTC(ch.ProofExpiresAt)
	if challengeEnd.Before(end) {
		claims.ExpiresAt = ch.ProofExpiresAt
	}
	proof, err := e2ee.SignOwnerLocalDomainPolicy(owner, ch.Policy)
	if err != nil {
		return LocalDomainActivate{}, err
	}
	q.OwnerProof, err = e2ee.SignOwnerLocalDomainRequest(owner, claims)
	out := LocalDomainActivate{q.Format, q.Context, q.SessionToken, q.OwnerProof, proof}
	if err != nil || validateLocalDomainRequest(out, s.Hub, now) != nil {
		return LocalDomainActivate{}, ErrInvalid
	}
	return out, nil
}

func NewLocalDomainStatus(s AppNodeSession, scope e2ee.OwnerAppNodeScope, policyID string, owner *e2ee.Identity, now time.Time) (LocalDomainStatusRequest, error) {
	q, claims, err := localDomainRequest(s, scope, e2ee.OwnerLocalDomainStatusPurpose, owner, now)
	if err != nil {
		return LocalDomainStatusRequest{}, err
	}
	claims.PolicyID = policyID
	q.OwnerProof, err = e2ee.SignOwnerLocalDomainRequest(owner, claims)
	if err != nil {
		return LocalDomainStatusRequest{}, ErrInvalid
	}
	return LocalDomainStatusRequest(q), nil
}

// NewLocalDomainStatusForNode recovers Hub-held policy history independently of
// the original App files and of Node availability/user-report freshness. Pages
// contain at most 64 policies in ascending policy-ID order; pass NextCursor.
func NewLocalDomainStatusForNode(s AppNodeSession, scope e2ee.OwnerAppNodeScope, nodeID, cursor string, owner *e2ee.Identity, now time.Time) (LocalDomainStatusRequest, error) {
	q, claims, err := localDomainRequest(s, scope, e2ee.OwnerLocalDomainStatusPurpose, owner, now)
	if err != nil {
		return LocalDomainStatusRequest{}, err
	}
	claims.NodeID, claims.Cursor = nodeID, cursor
	q.OwnerProof, err = e2ee.SignOwnerLocalDomainRequest(owner, claims)
	if err != nil {
		return LocalDomainStatusRequest{}, ErrInvalid
	}
	return LocalDomainStatusRequest(q), nil
}

func NewLocalDomainRevoke(s AppNodeSession, scope e2ee.OwnerAppNodeScope, current LocalDomainDescription, owner *e2ee.Identity, now time.Time) (LocalDomainRevoke, error) {
	q, claims, err := localDomainRequest(s, scope, e2ee.OwnerLocalDomainRevokePurpose, owner, now)
	if err != nil || ValidateLocalDomainPolicy(current.Policy, s.Hub, time.Time{}) != nil || current.Policy.OwnerID != scope.OwnerID || !reflect.DeepEqual(current.Policy.OwnerPublic, scope.OwnerPublic) {
		return LocalDomainRevoke{}, ErrInvalid
	}
	claims.PolicyID, claims.PolicyEpoch, claims.ExpectedRevision = current.Policy.PolicyID, current.Policy.Epoch, current.Revision
	claims.PolicyDigest, err = e2ee.LocalDomainPolicyDigest(current.Policy)
	if err != nil {
		return LocalDomainRevoke{}, err
	}
	q.OwnerProof, err = e2ee.SignOwnerLocalDomainRequest(owner, claims)
	if err != nil {
		return LocalDomainRevoke{}, ErrInvalid
	}
	return LocalDomainRevoke(q), nil
}

func NewLocalDomainReconcile(s AppNodeSession, original []byte, now time.Time) (LocalDomainReconcileRequest, error) {
	c, err := s.context(now, false)
	q := LocalDomainReconcileRequest{Format: LocalDomainFormat, Context: c, OriginalPacket: append([]byte(nil), original...)}
	if err != nil || validateLocalDomainRequest(q, s.Hub, now) != nil {
		return LocalDomainReconcileRequest{}, ErrInvalid
	}
	return q, nil
}

func DecodeLocalDomainPacket(raw []byte) (Packet, error) {
	var p Packet
	if decodeCanonical(raw, MaxLocalDomainReconcilePacketBytes, &p) != nil || !localDomainOperation(p.Packet.Route.Operation) || p.Format != PacketFormat || p.Version != PacketVersion ||
		e2ee.ValidatePublicIdentity(p.SenderPublicIdentity) != nil || validateRouteHeader(p.Packet.Route, p.SenderPublicIdentity) != nil {
		return Packet{}, ErrInvalid
	}
	limit := MaxLocalDomainPacketBytes
	if p.Packet.Route.Operation == OperationLocalDomainReconcile {
		limit = MaxLocalDomainReconcilePacketBytes
	} else if p.Packet.Route.Direction == clientwire.DirectionRequest {
		limit = MaxLocalDomainOriginalBytes
	}
	inner, err := json.Marshal(p.Packet)
	if err != nil || len(raw) > limit || len(inner) > innerLimitForOperation(p.Packet.Route.Operation) {
		return Packet{}, ErrInvalid
	}
	return p, nil
}

func DecodeLocalDomainCapabilities(raw []byte) (LocalDomainCapabilities, error) {
	var c LocalDomainCapabilities
	if decodeCanonical(bytes.TrimSpace(raw), MaxLocalDomainCapabilitiesBytes, &c) != nil || c.Format != LocalDomainFormat || c.ContractRevision != LocalDomainContractRevision ||
		c.ServeMode != "--hub-nodes-only" || (c.TransportPolicy != AppNodeTransportHTTPS && c.TransportPolicy != AppNodeTransportLoopbackTest) ||
		!reflect.DeepEqual(c.HTTPOperations, LocalDomainHTTPOperations()) || !reflect.DeepEqual(c.NodeOperations, LocalDomainNodeOperations()) || !reflect.DeepEqual(c.Rights, e2ee.LocalDomainRights()) ||
		c.MaxActivePoliciesPerNodeUser != 1 || !c.OptionalPolicyExpiry {
		return LocalDomainCapabilities{}, ErrInvalid
	}
	return c, nil
}

func localDomainDescriptionShape(d LocalDomainDescription) error {
	if d.ContractRevision != LocalDomainContractRevision || e2ee.ValidateLocalDomainPolicy(d.Policy, time.Time{}) != nil || d.Revision == 0 || d.Revision >= 1<<63 || validateCanonicalTime(d.ObservedAt) != nil {
		return ErrInvalid
	}
	switch d.State {
	case LocalDomainPrepared:
		if d.Revision != 1 || len(d.PolicyProof) != 0 || d.MemberCount != 0 {
			return ErrInvalid
		}
	case LocalDomainActive, LocalDomainRevoked, LocalDomainExpired:
		if len(d.PolicyProof) != 0 {
			p, err := e2ee.VerifyOwnerLocalDomainPolicy(d.Policy.OwnerPublic, d.PolicyProof, time.Time{})
			if err != nil || !reflect.DeepEqual(p, d.Policy) {
				return ErrInvalid
			}
		} else if d.State != LocalDomainExpired {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateLocalDomainDescription(d LocalDomainDescription, hub HubIdentity, now time.Time) error {
	if localDomainDescriptionShape(d) != nil || ValidateLocalDomainPolicy(d.Policy, hub, time.Time{}) != nil {
		return ErrInvalid
	}
	if d.State == LocalDomainActive && e2ee.ValidateLocalDomainPolicy(d.Policy, now) != nil {
		return ErrInvalid
	}
	return nil
}

func validateLocalDomainResponse(body any, r clientwire.Route) error {
	switch v := dereference(body).(type) {
	case LocalDomainChallenge:
		if r.Operation != OperationLocalDomainPrepare || v.Format != LocalDomainFormat || v.RequestID != r.OperationID || !isHex(v.RequestPacketDigest, 32) || !isHex(v.PrepareProofDigest, 32) ||
			v.Revision != 1 || v.Policy.HubID != r.HubID || v.Policy.OwnerID != r.OwnerID || v.Policy.PrepareRequestID != r.OperationID || v.Policy.PreparePacketDigest != v.RequestPacketDigest ||
			e2ee.ValidateLocalDomainPolicy(v.Policy, time.Time{}) != nil || v.Policy.IssuedAt != v.ObservedAt || validateTimeWindow(v.ObservedAt, v.ProofExpiresAt, e2ee.LocalDomainRequestLifetime) != nil {
			return ErrInvalid
		}
		report, err := e2ee.VerifyLocalDomainUserReport(v.Policy.Node, v.LocalUserReport, time.Time{})
		if err != nil || report.LocalUserScope != v.Policy.LocalUserScope {
			return ErrInvalid
		}
	case LocalDomainResult:
		if !localDomainOperation(r.Operation) || r.Operation == OperationLocalDomainReconcile || v.Format != LocalDomainFormat || v.Operation != r.Operation || v.RequestID != r.OperationID ||
			v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || !isHex(v.RequestPacketDigest, 32) || validateCanonicalTime(v.ObservedAt) != nil {
			return ErrInvalid
		}
		if v.State != AppNodeCompleted && v.State != AppNodeRejectedFenced && v.State != AppNodeReadExpired {
			return ErrInvalid
		}
		if v.State == AppNodeCompleted {
			if v.NoEffect || v.ErrorCode != "" {
				return ErrInvalid
			}
			if v.Operation == OperationLocalDomainStatus && v.NodeID != "" {
				if !validID(v.NodeID) || v.PolicyID != "" || v.PolicyEpoch != 0 || v.Description != nil || len(v.Policies) > 64 || (v.NextCursor != "" && !isHex(v.NextCursor, RequestIDBytes)) {
					return ErrInvalid
				}
				previous := ""
				for _, d := range v.Policies {
					if localDomainDescriptionShape(d) != nil || d.Policy.Node.NodeID != v.NodeID || d.Policy.HubID != v.HubID || d.Policy.OwnerID != v.OwnerID || d.Policy.PolicyID <= previous {
						return ErrInvalid
					}
					previous = d.Policy.PolicyID
				}
				if v.NextCursor != "" && (len(v.Policies) == 0 || v.NextCursor != previous) {
					return ErrInvalid
				}
				encoded, err := json.Marshal(v)
				if err != nil || len(encoded) > MaxLocalDomainPageBytes {
					return ErrInvalid
				}
			} else if v.Description == nil || localDomainDescriptionShape(*v.Description) != nil || v.PolicyID != v.Description.Policy.PolicyID ||
				v.PolicyEpoch != v.Description.Policy.Epoch || v.OwnerID != v.Description.Policy.OwnerID || v.HubID != v.Description.Policy.HubID || v.NodeID != "" || len(v.Policies) != 0 || v.NextCursor != "" {
				return ErrInvalid
			}
		} else if !v.NoEffect || v.Description != nil || v.ErrorCode == "" || len(v.Policies) != 0 || v.NextCursor != "" {
			return ErrInvalid
		}
	case LocalDomainReconciled:
		if r.Operation != OperationLocalDomainReconcile || v.Format != LocalDomainFormat || v.RequestID != r.OperationID || v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID ||
			!isHex(v.RequestPacketDigest, 32) ||
			!localDomainOperation(v.OriginalOperation) || v.OriginalOperation == OperationLocalDomainReconcile || !isHex(v.OriginalRequestID, RequestIDBytes) || !isHex(v.OriginalPacketDigest, 32) ||
			(v.State != AppNodeCompleted && v.State != AppNodeRejectedFenced && v.State != AppNodeReadExpired) || validateCanonicalTime(v.ObservedAt) != nil || len(v.ReceiptPacket) == 0 || len(v.ReceiptPacket) > MaxLocalDomainPacketBytes {
			return ErrInvalid
		}
		p, err := DecodeLocalDomainPacket(v.ReceiptPacket)
		if err != nil || p.Packet.Route.Direction != clientwire.DirectionResponse || p.Packet.Route.Operation != v.OriginalOperation || p.Packet.Route.OperationID != v.OriginalRequestID ||
			p.Packet.Route.HubID != v.HubID || p.Packet.Route.OwnerID != v.OwnerID || p.Packet.Route.DeviceID != v.DeviceID {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
