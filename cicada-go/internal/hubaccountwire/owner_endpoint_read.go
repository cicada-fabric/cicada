package hubaccountwire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

const OperationOwnerEndpointRead = "owner.endpoints.read"
const OwnerEndpointReadPath = "/v2/owner/endpoints/read"
const OwnerEndpointReadContractRevision = "native-endpoint-directory-v1"
const OwnerEndpointReadCapabilitiesFormat = "cicada.owner-endpoints-capabilities.v1"
const MaxOwnerEndpointCapabilitiesBytes = 4096
const OwnerEndpointReadFormat = "cicada.owner-endpoints-read.v1"
const OwnerEndpointReadResultFormat = "cicada.owner-endpoints-result.v1"
const MaxOwnerEndpointPageBytes = 48 << 10

// Public availability only. This carries no caller authority or settlement.
type OwnerEndpointReadCapabilities struct {
	Format           string `json:"format"`
	ContractRevision string `json:"contract_revision"`
	Available        bool   `json:"available"`
	HubID            string `json:"hub_id"`
	HubFingerprint   string `json:"hub_fingerprint"`
	MaxPageRows      int    `json:"max_page_rows"`
	MaxPageBytes     int    `json:"max_page_bytes"`
	MaxProofSeconds  int    `json:"max_proof_seconds"`
}

func ParseOwnerEndpointReadCapabilities(raw []byte, hub HubIdentity) (OwnerEndpointReadCapabilities, error) {
	var c OwnerEndpointReadCapabilities
	fp, err := HubFingerprint(hub)
	if len(raw) > MaxOwnerEndpointCapabilitiesBytes {
		return OwnerEndpointReadCapabilities{}, ErrInvalid
	}
	if err != nil || decodeCanonical(bytes.TrimSpace(raw), MaxOwnerEndpointCapabilitiesBytes, &c) != nil || c.Format != OwnerEndpointReadCapabilitiesFormat ||
		c.ContractRevision != OwnerEndpointReadContractRevision || c.HubID != hub.HubID || c.HubFingerprint != fp ||
		c.MaxPageRows != 64 || c.MaxPageBytes != MaxOwnerEndpointPageBytes || c.MaxProofSeconds != 60 {
		return OwnerEndpointReadCapabilities{}, ErrInvalid
	}
	return c, nil
}

type OwnerEndpointReadRequest struct {
	Format       string                `json:"format"`
	Context      AppNodeRequestContext `json:"context"`
	SessionToken []byte                `json:"session_token"`
	OwnerProof   []byte                `json:"owner_proof"`
}

type OwnerEndpointCard struct {
	EndpointID string `json:"endpoint_id"`
	Name       string `json:"name"`
	Workspace  string `json:"workspace"`
	Harness    string `json:"harness"`
	Presence   string `json:"presence"`
}

type OwnerEndpointReadResult struct {
	Format              string              `json:"format"`
	RequestID           string              `json:"request_id"`
	RequestPacketDigest string              `json:"request_packet_digest"`
	HubID               string              `json:"hub_id"`
	OwnerID             string              `json:"owner_id"`
	DeviceID            string              `json:"device_id"`
	NodeID              string              `json:"node_id"`
	State               string              `json:"state"`
	CapturedAt          string              `json:"captured_at"`
	Freshness           string              `json:"freshness"`
	Endpoints           []OwnerEndpointCard `json:"endpoints"`
	NextCursor          string              `json:"next_cursor"`
}

func NewOwnerEndpointRead(s AppNodeSession, scope e2ee.OwnerAppNodeScope, node e2ee.OwnerAppNodeBinding, cursor string, limit int, owner *e2ee.Identity, now time.Time) (OwnerEndpointReadRequest, error) {
	c, err := s.context(now, true)
	if err != nil || ValidateAppNodeScope(scope, s.Hub) != nil || !appNodeContextScope(c, scope) {
		return OwnerEndpointReadRequest{}, ErrInvalid
	}
	end := now.Add(e2ee.OwnerEndpointReadLifetime)
	sessionEnd, _ := parseCanonicalUTC(scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	claims := e2ee.OwnerEndpointReadClaims{Purpose: e2ee.OwnerEndpointReadPurpose, Scope: scope, Node: node, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), Cursor: cursor, Limit: limit, IssuedAt: c.IssuedAt, ExpiresAt: formatUTC(end)}
	proof, err := e2ee.SignOwnerEndpointRead(owner, claims)
	if err != nil {
		return OwnerEndpointReadRequest{}, err
	}
	return OwnerEndpointReadRequest{Format: OwnerEndpointReadFormat, Context: c, SessionToken: append([]byte(nil), s.Token...), OwnerProof: proof}, nil
}

func validateOwnerEndpointReadRequest(q OwnerEndpointReadRequest, hub HubIdentity, at time.Time) error {
	var proof e2ee.OwnerEndpointReadProof
	if q.Format != OwnerEndpointReadFormat || len(q.SessionToken) != MaxSessionTokenBytes || len(q.OwnerProof) == 0 || len(q.OwnerProof) > MaxAppNodeProofBytes ||
		decodeCanonical(q.OwnerProof, MaxAppNodeProofBytes, &proof) != nil || ValidateAppNodeScope(proof.Claims.Scope, hub) != nil ||
		e2ee.ValidateOwnerEndpointReadClaims(proof.Claims, at) != nil || !appNodeContextScope(q.Context, proof.Claims.Scope) ||
		q.Context.RequestID != proof.Claims.RequestID || hex.EncodeToString(q.Context.ClientNonce) != proof.Claims.Nonce || q.Context.IssuedAt != proof.Claims.IssuedAt {
		return ErrInvalid
	}
	return nil
}

func validateOwnerEndpointReadResponse(body any, r clientwire.Route) error {
	v, ok := dereference(body).(OwnerEndpointReadResult)
	if !ok || r.Operation != OperationOwnerEndpointRead || v.Format != OwnerEndpointReadResultFormat || v.RequestID != r.OperationID ||
		v.HubID != r.HubID || v.OwnerID != r.OwnerID || v.DeviceID != r.DeviceID || !validID(v.NodeID) || !isHex(v.RequestPacketDigest, 32) ||
		(v.State != AppNodeCompleted && v.State != AppNodeReadExpired) || validateCanonicalTime(v.CapturedAt) != nil || v.Freshness != "SNAPSHOT_ONLY" ||
		len(v.Endpoints) > 64 || len(v.NextCursor) > 256 || (v.State == AppNodeReadExpired && (len(v.Endpoints) != 0 || v.NextCursor != "")) {
		return ErrInvalid
	}
	previous := ""
	for _, card := range v.Endpoints {
		if !validID(card.EndpointID) || card.EndpointID <= previous || len(card.Name) > 256 || len(card.Workspace) > 4096 || len(card.Harness) > 64 ||
			(card.Presence != "offline" && card.Presence != "left" && card.Presence != "LEASE_RECENT" && card.Presence != "UNKNOWN") {
			return ErrInvalid
		}
		previous = card.EndpointID
	}
	if v.NextCursor != "" && (len(v.Endpoints) == 0 || v.NextCursor != previous) {
		return ErrInvalid
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxOwnerEndpointPageBytes {
		return ErrInvalid
	}
	return nil
}

// VerifyOwnerEndpointReadResult binds a cached snapshot to its exact original
// request. It is not evidence of current communication authority.
func VerifyOwnerEndpointReadResult(v OwnerEndpointReadResult, q OwnerEndpointReadRequest, original []byte) error {
	var proof e2ee.OwnerEndpointReadProof
	if decodeCanonical(q.OwnerProof, MaxAppNodeProofBytes, &proof) != nil || v.RequestID != q.Context.RequestID || v.RequestPacketDigest != AppNodePacketDigest(original) ||
		v.OwnerID != q.Context.OwnerID || v.DeviceID != q.Context.DeviceID || v.HubID != q.Context.HubID || v.NodeID != proof.Claims.Node.NodeID {
		return ErrInvalid
	}
	if _, err := e2ee.VerifyOwnerEndpointRead(proof.Claims.Scope.OwnerPublic, q.OwnerProof, time.Time{}); err != nil {
		return ErrInvalid
	}
	p, err := PreflightRequest(original, OperationOwnerEndpointRead)
	if err != nil || !reflect.DeepEqual(p.SenderPublicIdentity, proof.Claims.Scope.DevicePublic) {
		return ErrInvalid
	}
	if len(v.Endpoints) > proof.Claims.Limit {
		return ErrInvalid
	}
	for _, card := range v.Endpoints {
		if card.EndpointID <= proof.Claims.Cursor {
			return ErrInvalid
		}
	}
	captured, e := parseCanonicalUTC(v.CapturedAt)
	issued, _ := parseCanonicalUTC(proof.Claims.IssuedAt)
	expiry, _ := parseCanonicalUTC(proof.Claims.ExpiresAt)
	if e != nil || (v.State == AppNodeCompleted && (captured.Before(issued.Add(-30*time.Second)) || !captured.Before(expiry))) {
		return ErrInvalid
	}
	return validateOwnerEndpointReadResponse(v, p.Packet.Route)
}
