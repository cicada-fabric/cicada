package e2ee

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const ownerNetworkJoinDomain = "cicada/network/join-consent/v1\x00"

// OwnerNetworkJoinGrant is an exact, one-use human approval for a native
// session to be exposed in one Network. The Node credential proves which
// machine proposes the session; only this separately held owner key approves
// its disclosure and grant set.
type OwnerNetworkJoinGrant struct {
	Version          int      `json:"version"`
	HubID            string   `json:"hub_id"`
	NetworkID        string   `json:"network_id"`
	OwnerID          string   `json:"owner_id"`
	NodeID           string   `json:"node_id"`
	NativeSessionID  string   `json:"native_session_id"`
	InvitationDigest string   `json:"invitation_digest"`
	Grants           []string `json:"grants"`
	Discoverable     bool     `json:"discoverable"`
	OwnerKeyID       string   `json:"owner_key_id"`
	IssuedAt         string   `json:"issued_at"`
	ExpiresAt        string   `json:"expires_at"`
	Nonce            string   `json:"nonce"`
	Signature        []byte   `json:"signature"`
}

type ownerNetworkJoinClaims struct {
	Version          int      `json:"version"`
	HubID            string   `json:"hub_id"`
	NetworkID        string   `json:"network_id"`
	OwnerID          string   `json:"owner_id"`
	NodeID           string   `json:"node_id"`
	NativeSessionID  string   `json:"native_session_id"`
	InvitationDigest string   `json:"invitation_digest"`
	Grants           []string `json:"grants"`
	Discoverable     bool     `json:"discoverable"`
	OwnerKeyID       string   `json:"owner_key_id"`
	IssuedAt         string   `json:"issued_at"`
	ExpiresAt        string   `json:"expires_at"`
	Nonce            string   `json:"nonce"`
}

func (g OwnerNetworkJoinGrant) claims() ownerNetworkJoinClaims {
	return ownerNetworkJoinClaims{g.Version, g.HubID, g.NetworkID, g.OwnerID, g.NodeID, g.NativeSessionID, g.InvitationDigest, g.Grants, g.Discoverable, g.OwnerKeyID, g.IssuedAt, g.ExpiresAt, g.Nonce}
}

func (g OwnerNetworkJoinGrant) signedBytes() ([]byte, error) {
	data, err := json.Marshal(g.claims())
	if err != nil {
		return nil, err
	}
	return append([]byte(ownerNetworkJoinDomain), data...), nil
}

func validNetworkJoinGrant(g OwnerNetworkJoinGrant) bool {
	if g.Version != 1 || g.HubID == "" || g.NetworkID == "" || g.OwnerID == "" || g.NodeID == "" || g.NativeSessionID == "" || g.OwnerKeyID == "" || !canonicalSHA256Hex(g.InvitationDigest) || !canonicalSHA256Hex(g.Nonce) || len(g.Grants) > 32 {
		return false
	}
	for i, v := range g.Grants {
		if v == "" || (i > 0 && g.Grants[i-1] >= v) {
			return false
		}
	}
	return true
}

func (identity *Identity) SignOwnerNetworkJoinGrant(ownerID, hubID, networkID, nodeID, nativeSessionID, invitationDigest, ownerKeyID string, grants []string, discoverable bool, issuedAt, expiresAt time.Time) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil || identity.Public().ID != ownerKeyID || !expiresAt.After(issuedAt) {
		return nil, ErrInvalidEnvelope
	}
	grants = slices.Clone(grants)
	slices.Sort(grants)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	g := OwnerNetworkJoinGrant{Version: 1, HubID: hubID, NetworkID: networkID, OwnerID: ownerID, NodeID: nodeID, NativeSessionID: nativeSessionID, InvitationDigest: invitationDigest, Grants: grants, Discoverable: discoverable, OwnerKeyID: ownerKeyID, IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	if !validNetworkJoinGrant(g) {
		return nil, ErrInvalidEnvelope
	}
	message, err := g.signedBytes()
	if err != nil {
		return nil, err
	}
	g.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, message, nil, true, g.Signature); err != nil {
		return nil, err
	}
	data, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	if len(data) > 16*1024 {
		return nil, ErrInvalidEnvelope
	}
	return data, nil
}

func VerifyOwnerNetworkJoinGrant(data []byte, trustedOwner PublicIdentity, expected OwnerNetworkJoinGrant, at time.Time) (OwnerNetworkJoinGrant, error) {
	if len(data) == 0 || len(data) > 16*1024 || at.IsZero() {
		return OwnerNetworkJoinGrant{}, ErrInvalidEnvelope
	}
	if err := ValidatePublicIdentity(trustedOwner); err != nil {
		return OwnerNetworkJoinGrant{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var g OwnerNetworkJoinGrant
	if err := decoder.Decode(&g); err != nil {
		return OwnerNetworkJoinGrant{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OwnerNetworkJoinGrant{}, ErrInvalidEnvelope
	}
	canonical, _ := json.Marshal(g)
	if !bytes.Equal(canonical, data) || !validNetworkJoinGrant(g) || len(g.Signature) != mldsa65.SignatureSize {
		return OwnerNetworkJoinGrant{}, ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(g.IssuedAt)
	if err != nil {
		return OwnerNetworkJoinGrant{}, err
	}
	expires, err := parseCanonicalUTC(g.ExpiresAt)
	if err != nil || issued.After(at) || !at.Before(expires) {
		return OwnerNetworkJoinGrant{}, ErrInvalidEnvelope
	}
	if g.HubID != expected.HubID || g.NetworkID != expected.NetworkID || g.OwnerID != expected.OwnerID || g.NodeID != expected.NodeID || g.NativeSessionID != expected.NativeSessionID || g.InvitationDigest != expected.InvitationDigest || g.Discoverable != expected.Discoverable || g.OwnerKeyID != trustedOwner.ID || !slices.Equal(g.Grants, expected.Grants) {
		return OwnerNetworkJoinGrant{}, ErrInvalidEnvelope
	}
	_, public, err := validatePublic(trustedOwner)
	if err != nil {
		return OwnerNetworkJoinGrant{}, err
	}
	message, err := g.signedBytes()
	if err != nil || !mldsa65.Verify(public, message, nil, g.Signature) {
		return OwnerNetworkJoinGrant{}, ErrInvalidEnvelope
	}
	return g, nil
}
