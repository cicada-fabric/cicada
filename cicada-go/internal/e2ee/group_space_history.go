package e2ee

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const groupSpaceHistoryGrantDomain = "cicada/group-space/history-owner-grant/v1\x00"

// GroupSpaceHistoryGrant is an explicit Owner decision for one old record and
// one current recipient key generation. It conveys no decryption key itself.
type GroupSpaceHistoryGrant struct {
	Version                     int    `json:"version"`
	ManifestID                  string `json:"manifest_id"`
	HubID                       string `json:"hub_id"`
	NetworkID                   string `json:"network_id"`
	GroupID                     string `json:"group_id"`
	RecordID                    string `json:"record_id"`
	OriginalCiphertextDigest    string `json:"original_ciphertext_digest"`
	RecipientEndpointID         string `json:"recipient_endpoint_id"`
	RecipientKeyID              string `json:"recipient_key_id"`
	RecipientBindingID          string `json:"recipient_binding_id"`
	RecipientBindingEpoch       uint64 `json:"recipient_binding_epoch"`
	RecipientMembershipRevision int64  `json:"recipient_membership_revision"`
	RecipientEvidenceDigest     string `json:"recipient_evidence_digest"`
	RecipientJoinRevision       int64  `json:"recipient_join_revision"`
	RecipientNetworkRevision    int64  `json:"recipient_network_revision"`
	OwnerID                     string `json:"owner_id"`
	OwnerKeyID                  string `json:"owner_key_id"`
	IssuedAt                    string `json:"issued_at"`
	ExpiresAt                   string `json:"expires_at"`
	Nonce                       string `json:"nonce"`
	Signature                   []byte `json:"signature"`
}

func (g GroupSpaceHistoryGrant) validate() error {
	for _, value := range []string{g.ManifestID, g.HubID, g.NetworkID, g.GroupID,
		g.RecordID, g.RecipientEndpointID, g.RecipientKeyID,
		g.RecipientBindingID, g.OwnerID, g.OwnerKeyID} {
		if !canonicalEndpointToken(value, true) {
			return ErrInvalidEnvelope
		}
	}
	if g.Version != 1 || !canonicalSHA256Hex(g.OriginalCiphertextDigest) ||
		!canonicalSHA256Hex(g.RecipientEvidenceDigest) ||
		g.RecipientBindingEpoch == 0 || g.RecipientMembershipRevision <= 0 ||
		g.RecipientJoinRevision <= 0 || g.RecipientNetworkRevision <= 0 ||
		!canonicalSHA256Hex(g.Nonce) {
		return ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(g.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parseCanonicalUTC(g.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return ErrInvalidEnvelope
	}
	return nil
}

func (g GroupSpaceHistoryGrant) signedBytes() ([]byte, error) {
	g.Signature = nil
	encoded, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	return append([]byte(groupSpaceHistoryGrantDomain), encoded...), nil
}

// SignGroupSpaceHistoryGrant signs a reviewed Hub manifest with a separately
// enrolled Owner key. It fills the nonce and issued time; expiry is supplied
// by the manifest and must not exceed the original record's retention.
func (identity *Identity) SignGroupSpaceHistoryGrant(grant GroupSpaceHistoryGrant) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil || identity.Public().ID != grant.OwnerKeyID {
		return nil, ErrInvalidEnvelope
	}
	if grant.Nonce == "" {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		grant.Nonce = hex.EncodeToString(nonce[:])
	}
	if grant.IssuedAt == "" {
		grant.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := grant.validate(); err != nil {
		return nil, err
	}
	unsigned, err := grant.signedBytes()
	if err != nil {
		return nil, err
	}
	grant.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, unsigned, nil, true, grant.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(grant)
}

func VerifyGroupSpaceHistoryGrant(wire []byte, owner PublicIdentity,
	expected GroupSpaceHistoryGrant, at time.Time) (GroupSpaceHistoryGrant, error) {
	if len(wire) == 0 || len(wire) > 16*1024 || at.IsZero() ||
		ValidatePublicIdentity(owner) != nil || owner.ID != expected.OwnerKeyID {
		return GroupSpaceHistoryGrant{}, ErrInvalidEnvelope
	}
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.DisallowUnknownFields()
	var grant GroupSpaceHistoryGrant
	if err := dec.Decode(&grant); err != nil {
		return GroupSpaceHistoryGrant{}, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return GroupSpaceHistoryGrant{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(canonical, wire) || grant.validate() != nil ||
		len(grant.Signature) != mldsa65.SignatureSize {
		return GroupSpaceHistoryGrant{}, ErrInvalidEnvelope
	}
	if grant.ManifestID != expected.ManifestID || grant.HubID != expected.HubID ||
		grant.NetworkID != expected.NetworkID || grant.GroupID != expected.GroupID ||
		grant.RecordID != expected.RecordID ||
		grant.OriginalCiphertextDigest != expected.OriginalCiphertextDigest ||
		grant.RecipientEndpointID != expected.RecipientEndpointID ||
		grant.RecipientKeyID != expected.RecipientKeyID ||
		grant.RecipientBindingID != expected.RecipientBindingID ||
		grant.RecipientBindingEpoch != expected.RecipientBindingEpoch ||
		grant.RecipientMembershipRevision != expected.RecipientMembershipRevision ||
		grant.RecipientEvidenceDigest != expected.RecipientEvidenceDigest ||
		grant.RecipientJoinRevision != expected.RecipientJoinRevision ||
		grant.RecipientNetworkRevision != expected.RecipientNetworkRevision ||
		grant.OwnerID != expected.OwnerID || grant.OwnerKeyID != expected.OwnerKeyID ||
		grant.ExpiresAt != expected.ExpiresAt {
		return GroupSpaceHistoryGrant{}, ErrInvalidEnvelope
	}
	issued, _ := parseCanonicalUTC(grant.IssuedAt)
	expires, _ := parseCanonicalUTC(grant.ExpiresAt)
	if issued.After(at) || !expires.After(at) {
		return GroupSpaceHistoryGrant{}, ErrInvalidEnvelope
	}
	_, public, err := validatePublic(owner)
	if err != nil {
		return GroupSpaceHistoryGrant{}, err
	}
	sig := grant.Signature
	unsigned, err := grant.signedBytes()
	if err != nil || !mldsa65.Verify(public, unsigned, nil, sig) {
		return GroupSpaceHistoryGrant{}, ErrInvalidEnvelope
	}
	return grant, nil
}
