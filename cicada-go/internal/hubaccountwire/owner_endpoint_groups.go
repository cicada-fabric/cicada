package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func OwnerEndpointGroupsHTTPOperations() []string {
	return []string{OperationOwnerEndpointGroupsRead, OperationOwnerEndpointGroupsPrepare, OperationOwnerEndpointGroupsApply, OperationOwnerEndpointGroupsStatus, OperationOwnerEndpointGroupsReconcile}
}

func OwnerEndpointGroupsHTTPPath(op string) string {
	switch op {
	case OperationOwnerEndpointGroupsRead:
		return "/v2/owner/endpoint-groups/read"
	case OperationOwnerEndpointGroupsPrepare:
		return "/v2/owner/endpoint-groups/prepare"
	case OperationOwnerEndpointGroupsApply:
		return "/v2/owner/endpoint-groups/apply"
	case OperationOwnerEndpointGroupsStatus:
		return "/v2/owner/endpoint-groups/status"
	case OperationOwnerEndpointGroupsReconcile:
		return "/v2/owner/endpoint-groups/reconcile"
	}
	return ""
}

func OwnerEndpointGroupsOwnerPurpose(op string) string {
	switch op {
	case OperationOwnerEndpointGroupsRead:
		return "owner-endpoint-groups-read:v1"
	case OperationOwnerEndpointGroupsPrepare:
		return "owner-endpoint-groups-prepare:v1"
	case OperationOwnerEndpointGroupsApply:
		return "owner-endpoint-groups-apply:v1"
	case OperationOwnerEndpointGroupsStatus:
		return "owner-endpoint-groups-status:v1"
	case OperationOwnerEndpointGroupsReconcile:
		return "owner-endpoint-groups-reconcile:v1"
	}
	return ""
}

func ownerEndpointGroupsOperation(op string) bool { return OwnerEndpointGroupsHTTPPath(op) != "" }

func EndpointGroupDurationValues() []string { return []string{"until_revoked", "1d", "7d", "30d"} }

// Expiry is anchored to the original server review, never to a retry or renewal.
func EndpointGroupDurationExpiry(duration string, observed time.Time) (string, error) {
	if observed.IsZero() {
		return "", ErrInvalid
	}
	switch duration {
	case "until_revoked":
		return "", nil
	case "1d":
		return formatUTC(observed.Add(24 * time.Hour)), nil
	case "7d":
		return formatUTC(observed.Add(7 * 24 * time.Hour)), nil
	case "30d":
		return formatUTC(observed.Add(30 * 24 * time.Hour)), nil
	}
	return "", ErrInvalid
}

func ownerEndpointGroupsName(s string) bool {
	return ownerEndpointGroupsText(s, 128)
}

func ownerEndpointGroupsText(s string, max int) bool {
	return s != "" && len(s) <= max && strings.TrimSpace(s) == s && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

func ownerEndpointGroupsCursor(s string) bool {
	return s == "" || (len(s) <= 256 && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0)
}

func validateOwnerEndpointGroupsBody(body any) error {
	switch b := dereference(body).(type) {
	case OwnerEndpointGroupsReadBody:
		if !validID(b.NodeID) || !validID(b.NetworkID) || !ownerEndpointGroupsCursor(b.Cursor) || b.Limit < 0 || b.Limit > 64 {
			return ErrInvalid
		}
		switch b.View {
		case "THREADS":
			if b.EndpointID != "" && !validID(b.EndpointID) {
				return ErrInvalid
			}
		case "CANDIDATE_GROUPS", "RELATIONS":
			if !validID(b.EndpointID) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case OwnerEndpointGroupsPrepareBody:
		if !validID(b.NodeID) || !validID(b.NetworkID) {
			return ErrInvalid
		}
		switch b.Action {
		case OwnerEndpointGroupsCreateGroup:
			if !ownerEndpointGroupsName(b.Name) || b.GroupID != "" || b.EndpointID != "" || b.Duration != "" {
				return ErrInvalid
			}
		case OwnerEndpointGroupsAddEndpoint:
			if b.Name != "" || !validID(b.GroupID) || !validID(b.EndpointID) {
				return ErrInvalid
			}
			if _, err := EndpointGroupDurationExpiry(b.Duration, time.Unix(1, 0)); err != nil {
				return ErrInvalid
			}
		case OwnerEndpointGroupsRemoveEndpoint:
			if b.Name != "" || b.Duration != "" || !validID(b.GroupID) || !validID(b.EndpointID) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case OwnerEndpointGroupsApplyBody:
		if !isHex(b.ReviewID, 16) || !isHex(b.ReviewDigest, 32) || !isHex(b.PreparePacketDigest, 32) || len(b.PolicyProof) > e2ee.MaxEndpointGroupProofBytes {
			return ErrInvalid
		}
	case OwnerEndpointGroupsStatusBody:
		if !isHex(b.OperationID, 16) || !isHex(b.OriginalPacketDigest, 32) {
			return ErrInvalid
		}
	case OwnerEndpointGroupsReconcileBody:
		p, err := DecodeOwnerEndpointGroupsPacket(b.OriginalPacket)
		if err != nil || len(b.OriginalPacket) > MaxOwnerEndpointGroupsOriginalBytes || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.Operation == OperationOwnerEndpointGroupsReconcile {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ownerEndpointGroupsDigest(domain string, body any) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func OwnerEndpointGroupsBodyDigest(body any) (string, error) {
	if validateOwnerEndpointGroupsBody(body) != nil {
		return "", ErrInvalid
	}
	return ownerEndpointGroupsDigest("cicada/owner/endpoint-groups/body/v1\x00", dereference(body))
}

func OwnerEndpointGroupsPacketDigest(raw []byte) string {
	sum := sha256.Sum256(append([]byte("cicada/owner/endpoint-groups/packet/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func ownerEndpointGroupsParts(request any) (op, format string, c AppNodeRequestContext, token, proof []byte, body any) {
	switch q := dereference(request).(type) {
	case OwnerEndpointGroupsReadRequest:
		return OperationOwnerEndpointGroupsRead, q.Format, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case OwnerEndpointGroupsPrepareRequest:
		return OperationOwnerEndpointGroupsPrepare, q.Format, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case OwnerEndpointGroupsApplyRequest:
		return OperationOwnerEndpointGroupsApply, q.Format, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case OwnerEndpointGroupsStatusRequest:
		return OperationOwnerEndpointGroupsStatus, q.Format, q.Context, q.SessionToken, q.OwnerProof, q.Body
	case OwnerEndpointGroupsReconcileRequest:
		return OperationOwnerEndpointGroupsReconcile, q.Format, q.Context, q.SessionToken, q.OwnerProof, q.Body
	}
	return
}

func ownerEndpointGroupsMetadata(q any) (op, id, owner, device string, epoch uint64, err error) {
	op, _, c, _, _, _ := ownerEndpointGroupsParts(q)
	if op == "" {
		return "", "", "", "", 0, ErrInvalid
	}
	return op, c.RequestID, c.OwnerID, c.DeviceID, HandshakeEpoch, nil
}

func ValidateOwnerEndpointGroupsPolicy(p e2ee.EndpointGroupPolicy, hub HubIdentity, now time.Time) error {
	fp, err := HubFingerprint(hub)
	if err != nil || e2ee.ValidateEndpointGroupPolicy(p, now) != nil || p.HubID != hub.HubID || p.HubFingerprint != fp ||
		p.Node.NodeKeyFingerprint != nodewire.IdentityFingerprint(p.Node.NodePublic) || p.Node.HubNodeControlFingerprint != nodewire.IdentityFingerprint(p.Node.HubNodeControlPublic) {
		return ErrInvalid
	}
	return nil
}

func ValidateOwnerEndpointGroupsRequest(q any, hub HubIdentity, now time.Time) error {
	op, format, c, token, raw, body := ownerEndpointGroupsParts(q)
	digest, err := OwnerEndpointGroupsBodyDigest(body)
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if err != nil || format != OwnerEndpointGroupsFormat || !appNodeContextValid(c, hub, now) || len(token) != MaxSessionTokenBytes ||
		decodeCanonical(raw, e2ee.MaxEndpointGroupProofBytes, &proof) != nil || ValidateAppNodeScope(proof.Claims.Scope, hub) != nil ||
		!appNodeContextScope(c, proof.Claims.Scope) || proof.Claims.RequestID != c.RequestID || proof.Claims.Nonce != hex.EncodeToString(c.ClientNonce) || proof.Claims.IssuedAt != c.IssuedAt || proof.Claims.BodyDigest != digest {
		return ErrInvalid
	}
	if _, err := e2ee.VerifyOwnerEndpointGroupsRequest(proof.Claims.Scope.OwnerPublic, raw, OwnerEndpointGroupsOwnerPurpose(op), now); err != nil {
		return ErrInvalid
	}
	if b, ok := body.(OwnerEndpointGroupsApplyBody); ok && len(b.PolicyProof) != 0 {
		p, err := e2ee.VerifyOwnerEndpointGroupPolicy(proof.Claims.Scope.OwnerPublic, b.PolicyProof, now)
		if err != nil || ValidateOwnerEndpointGroupsPolicy(p, hub, now) != nil || p.OwnerID != c.OwnerID || p.Origin != c.Origin || p.OwnerKeyVersion != proof.Claims.Scope.OwnerKeyVersion || p.ReviewID != b.ReviewID || p.ReviewDigest != b.ReviewDigest {
			return ErrInvalid
		}
	}
	if b, ok := body.(OwnerEndpointGroupsReconcileBody); ok {
		p, err := DecodeOwnerEndpointGroupsPacket(b.OriginalPacket)
		if err != nil || p.Packet.Route.HubID != c.HubID || p.Packet.Route.OwnerID != c.OwnerID || p.Packet.Route.DeviceID != c.DeviceID || !reflect.DeepEqual(p.SenderPublicIdentity, proof.Claims.Scope.DevicePublic) {
			return ErrInvalid
		}
	}
	return nil
}

func newOwnerEndpointGroupsRequest(s AppNodeSession, scope e2ee.OwnerAppNodeScope, op string, body any, owner *e2ee.Identity, now time.Time) (AppNodeRequestContext, []byte, []byte, error) {
	c, err := s.context(now, true)
	digest, de := OwnerEndpointGroupsBodyDigest(body)
	if err != nil || de != nil || ValidateAppNodeScope(scope, s.Hub) != nil || !appNodeContextScope(c, scope) || !ownerEndpointGroupsOperation(op) {
		return AppNodeRequestContext{}, nil, nil, ErrInvalid
	}
	end := now.Add(e2ee.EndpointGroupsRequestLifetime)
	sessionEnd, _ := parseCanonicalUTC(scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	claims := e2ee.OwnerEndpointGroupsRequestClaims{Version: 1, Purpose: OwnerEndpointGroupsOwnerPurpose(op), Scope: scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: formatUTC(end), BodyDigest: digest}
	if e2ee.ValidateOwnerEndpointGroupsRequest(claims, now) != nil {
		return AppNodeRequestContext{}, nil, nil, ErrInvalid
	}
	proof, err := e2ee.SignOwnerEndpointGroupsRequest(owner, claims)
	if err != nil {
		return AppNodeRequestContext{}, nil, nil, err
	}
	return c, append([]byte(nil), s.Token...), proof, nil
}

func NewOwnerEndpointGroupsRead(s AppNodeSession, scope e2ee.OwnerAppNodeScope, body OwnerEndpointGroupsReadBody, owner *e2ee.Identity, now time.Time) (OwnerEndpointGroupsReadRequest, error) {
	if body.Limit == 0 {
		body.Limit = 64
	}
	c, token, proof, err := newOwnerEndpointGroupsRequest(s, scope, OperationOwnerEndpointGroupsRead, body, owner, now)
	return OwnerEndpointGroupsReadRequest{OwnerEndpointGroupsFormat, c, token, proof, body}, err
}

func NewOwnerEndpointGroupsPrepare(s AppNodeSession, scope e2ee.OwnerAppNodeScope, body OwnerEndpointGroupsPrepareBody, owner *e2ee.Identity, now time.Time) (OwnerEndpointGroupsPrepareRequest, error) {
	c, token, proof, err := newOwnerEndpointGroupsRequest(s, scope, OperationOwnerEndpointGroupsPrepare, body, owner, now)
	return OwnerEndpointGroupsPrepareRequest{OwnerEndpointGroupsFormat, c, token, proof, body}, err
}

// Status derives the original apply ID and digest before any response exists.
func NewOwnerEndpointGroupsStatus(s AppNodeSession, scope e2ee.OwnerAppNodeScope, original []byte, owner *e2ee.Identity, now time.Time) (OwnerEndpointGroupsStatusRequest, error) {
	p, err := DecodeOwnerEndpointGroupsPacket(original)
	if err != nil || p.Packet.Route.Operation != OperationOwnerEndpointGroupsApply || p.Packet.Route.Direction != clientwire.DirectionRequest || p.Packet.Route.HubID != s.Hub.HubID || p.Packet.Route.OwnerID != s.OwnerID || p.Packet.Route.DeviceID != s.DeviceID || !reflect.DeepEqual(p.SenderPublicIdentity, scope.DevicePublic) {
		return OwnerEndpointGroupsStatusRequest{}, ErrInvalid
	}
	body := OwnerEndpointGroupsStatusBody{p.Packet.Route.OperationID, OwnerEndpointGroupsPacketDigest(original)}
	c, token, proof, err := newOwnerEndpointGroupsRequest(s, scope, OperationOwnerEndpointGroupsStatus, body, owner, now)
	return OwnerEndpointGroupsStatusRequest{OwnerEndpointGroupsFormat, c, token, proof, body}, err
}

func NewOwnerEndpointGroupsReconcile(s AppNodeSession, scope e2ee.OwnerAppNodeScope, original []byte, owner *e2ee.Identity, now time.Time) (OwnerEndpointGroupsReconcileRequest, error) {
	body := OwnerEndpointGroupsReconcileBody{append([]byte(nil), original...)}
	c, token, proof, err := newOwnerEndpointGroupsRequest(s, scope, OperationOwnerEndpointGroupsReconcile, body, owner, now)
	q := OwnerEndpointGroupsReconcileRequest{OwnerEndpointGroupsFormat, c, token, proof, body}
	if err != nil || ValidateOwnerEndpointGroupsRequest(q, s.Hub, now) != nil {
		return OwnerEndpointGroupsReconcileRequest{}, ErrInvalid
	}
	return q, nil
}

func DecodeOwnerEndpointGroupsCapabilities(raw []byte, hub HubIdentity) (OwnerEndpointGroupsCapabilities, error) {
	var c OwnerEndpointGroupsCapabilities
	fp, err := HubFingerprint(hub)
	if err != nil || decodeCanonical(raw, 4096, &c) != nil || c.Format != OwnerEndpointGroupsCapabilitiesFormat || c.ContractRevision != OwnerEndpointGroupsContractRevision || c.HubID != hub.HubID || c.HubFingerprint != fp ||
		c.MaxPageRows != 64 || c.MaxPageCanonicalBytes != MaxOwnerEndpointGroupsPageBytes || c.MaxActiveGroupsPerEndpoint != 32 || !reflect.DeepEqual(c.DurationValues, EndpointGroupDurationValues()) || c.NativeSelfGroups && !c.Available {
		return OwnerEndpointGroupsCapabilities{}, ErrInvalid
	}
	return c, nil
}

// Availability remains false until the complete Store/Node/Guard integration
// has passed its source-specific gates. This factory does not install a route.
func NewOwnerEndpointGroupsCapabilities(hub HubIdentity) (OwnerEndpointGroupsCapabilities, error) {
	fp, err := HubFingerprint(hub)
	if err != nil {
		return OwnerEndpointGroupsCapabilities{}, ErrInvalid
	}
	return OwnerEndpointGroupsCapabilities{Format: OwnerEndpointGroupsCapabilitiesFormat, ContractRevision: OwnerEndpointGroupsContractRevision, HubID: hub.HubID, HubFingerprint: fp, MaxPageRows: 64, MaxPageCanonicalBytes: MaxOwnerEndpointGroupsPageBytes, MaxActiveGroupsPerEndpoint: 32, DurationValues: EndpointGroupDurationValues()}, nil
}

func DecodeOwnerEndpointGroupsRequest(op string, raw []byte, hub HubIdentity, now time.Time) (any, error) {
	var out any
	switch op {
	case OperationOwnerEndpointGroupsRead:
		out = &OwnerEndpointGroupsReadRequest{}
	case OperationOwnerEndpointGroupsPrepare:
		out = &OwnerEndpointGroupsPrepareRequest{}
	case OperationOwnerEndpointGroupsApply:
		out = &OwnerEndpointGroupsApplyRequest{}
	case OperationOwnerEndpointGroupsStatus:
		out = &OwnerEndpointGroupsStatusRequest{}
	case OperationOwnerEndpointGroupsReconcile:
		out = &OwnerEndpointGroupsReconcileRequest{}
	default:
		return nil, ErrInvalid
	}
	if decodeCanonical(raw, maxBodyForOperation(op), out) != nil || ValidateOwnerEndpointGroupsRequest(out, hub, now) != nil {
		return nil, ErrInvalid
	}
	return dereference(out), nil
}

func DecodeOwnerEndpointGroupsPacket(raw []byte) (Packet, error) {
	p, err := decodePacketWithLimit(raw, MaxOwnerEndpointGroupsReconcilePacketBytes)
	if err != nil || !ownerEndpointGroupsOperation(p.Packet.Route.Operation) {
		return Packet{}, ErrInvalid
	}
	return p, nil
}

func OpenOwnerEndpointGroupsResponse(device *e2ee.Identity, hub HubIdentity, original, response []byte, out any) error {
	p, err := DecodeOwnerEndpointGroupsPacket(original)
	if err != nil {
		return ErrInvalid
	}
	return openClientResponsePacket(device, hub, p, original, response, out)
}
