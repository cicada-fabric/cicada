package e2ee

import (
	"reflect"
	"strings"
	"time"
	"unicode"
)

const OwnerEndpointReadPurpose = "OWNER_ENDPOINT_DIRECTORY_READ"
const OwnerEndpointReadDomain = "cicada/owner/endpoint-directory-read/v1\x00"
const OwnerEndpointReadLifetime = time.Minute

type OwnerEndpointReadClaims struct {
	Purpose   string              `json:"purpose"`
	Scope     OwnerAppNodeScope   `json:"scope"`
	Node      OwnerAppNodeBinding `json:"node"`
	RequestID string              `json:"request_id"`
	Nonce     string              `json:"nonce"`
	Cursor    string              `json:"cursor"`
	Limit     int                 `json:"limit"`
	IssuedAt  string              `json:"issued_at"`
	ExpiresAt string              `json:"expires_at"`
}

type OwnerEndpointReadProof struct {
	Claims    OwnerEndpointReadClaims `json:"claims"`
	Signature []byte                  `json:"signature"`
}

func ValidateOwnerEndpointReadClaims(c OwnerEndpointReadClaims, at time.Time) error {
	if c.Purpose != OwnerEndpointReadPurpose || appNodeProofScope(c.Scope) != nil || !appNodeProofID(c.RequestID) || !appNodeHex(c.Nonce, 32) ||
		c.Limit < 1 || c.Limit > 64 || len(c.Cursor) > 256 || strings.TrimSpace(c.Cursor) != c.Cursor || strings.ContainsFunc(c.Cursor, unicode.IsControl) ||
		appNodeProofWindow(c.IssuedAt, c.ExpiresAt, OwnerEndpointReadLifetime, at) != nil {
		return ErrInvalidEnvelope
	}
	b := c.Node
	if b.OwnerID != c.Scope.OwnerID || b.HubID != c.Scope.HubID || b.ClientDeviceID != c.Scope.DeviceID || b.OwnerKeyID != c.Scope.OwnerPublic.ID ||
		!tlsGrantToken(b.OwnerBindingID) || !tlsGrantToken(b.NodeID) || b.BindingVersion == 0 || b.NodeKeyEpoch == 0 || b.State != "ACTIVE" ||
		ValidatePublicIdentity(b.NodePublic) != nil || ValidatePublicIdentity(b.HubNodeControlPublic) != nil {
		return ErrInvalidEnvelope
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if end.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	return nil
}

func SignOwnerEndpointRead(owner *Identity, c OwnerEndpointReadClaims) ([]byte, error) {
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) || ValidateOwnerEndpointReadClaims(c, time.Time{}) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, c.Scope.OwnerPublic.ID, OwnerEndpointReadDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalOwnerAppNodeProof(OwnerEndpointReadProof{Claims: c, Signature: sig})
}

func VerifyOwnerEndpointRead(trusted PublicIdentity, raw []byte, at time.Time) (OwnerEndpointReadClaims, error) {
	var p OwnerEndpointReadProof
	if tlsProofRead(raw, &p) != nil || !reflect.DeepEqual(trusted, p.Claims.Scope.OwnerPublic) || ValidateOwnerEndpointReadClaims(p.Claims, at) != nil ||
		verifyAppNodeSignature(trusted, OwnerEndpointReadDomain, p.Claims, p.Signature) != nil {
		return OwnerEndpointReadClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}
