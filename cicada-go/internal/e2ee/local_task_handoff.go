package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const localTaskHandoffProofDomain = "cicada/fabric/local-task-handoff/v1\x00"

// LocalTaskHandoffProofClaims binds an already sealed Node-local SEND to one
// exact Task responsibility transition. It contains only route/CAS metadata;
// the encrypted Endpoint envelope and Task prose never leave the Node.
type LocalTaskHandoffProofClaims struct {
	Version                  int    `json:"version"`
	Purpose                  string `json:"purpose"`
	HandoffID                string `json:"handoff_id"`
	TaskID                   string `json:"task_id"`
	HubID                    string `json:"hub_id"`
	GroupID                  string `json:"group_id"`
	FromPrincipalID          string `json:"from_principal_id"`
	FromOwnerID              string `json:"from_owner_id"`
	FromEndpointID           string `json:"from_endpoint_id"`
	FromBindingID            string `json:"from_binding_id"`
	FromBindingEpoch         uint64 `json:"from_binding_epoch"`
	FromMembershipRevision   int64  `json:"from_membership_revision"`
	FromJoinRevision         int64  `json:"from_join_revision"`
	FromKeyID                string `json:"from_key_id"`
	FromKeyVersion           int64  `json:"from_key_version"`
	ToPrincipalID            string `json:"to_principal_id"`
	ToOwnerID                string `json:"to_owner_id"`
	ToEndpointID             string `json:"to_endpoint_id"`
	ToBindingID              string `json:"to_binding_id"`
	ToBindingEpoch           uint64 `json:"to_binding_epoch"`
	ToMembershipRevision     int64  `json:"to_membership_revision"`
	ToJoinRevision           int64  `json:"to_join_revision"`
	ToKeyID                  string `json:"to_key_id"`
	ToKeyVersion             int64  `json:"to_key_version"`
	TaskRevision             int64  `json:"task_revision"`
	FromOwnerEpoch           int64  `json:"from_owner_epoch"`
	MessageID                string `json:"message_id"`
	MessageDigest            string `json:"message_digest"`
	ExpiresAt                string `json:"expires_at"`
	RequiredArtifactRefsHash string `json:"required_artifact_refs_hash"`
	IssuedAt                 string `json:"issued_at"`
}

// LocalTaskHandoffProof is a detached signature over only the route/CAS
// claims. The Endpoint identity is the same one that signs the sealed local
// Endpoint envelope; this signature lets the Hub bind its metadata row to the
// opaque ciphertext digest without receiving those ciphertext bytes.
type LocalTaskHandoffProof struct {
	Claims    LocalTaskHandoffProofClaims `json:"claims"`
	KeyID     string                      `json:"key_id"`
	Signature []byte                      `json:"signature"`
}

func (proof LocalTaskHandoffProof) signedBytes() ([]byte, error) {
	proof.Signature = nil
	encoded, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return append([]byte(localTaskHandoffProofDomain), encoded...), nil
}

func (claims LocalTaskHandoffProofClaims) valid() bool {
	if claims.Version != 1 || claims.Purpose != "LOCAL_NODE" ||
		claims.TaskRevision <= 0 || claims.FromOwnerEpoch <= 0 || claims.FromBindingEpoch == 0 ||
		claims.ToBindingEpoch == 0 || claims.FromMembershipRevision <= 0 ||
		claims.ToMembershipRevision <= 0 || claims.FromJoinRevision <= 0 || claims.ToJoinRevision <= 0 ||
		claims.FromKeyVersion <= 0 || claims.ToKeyVersion <= 0 ||
		!canonicalSHA256Hex(claims.MessageDigest) || !canonicalSHA256Hex(claims.RequiredArtifactRefsHash) {
		return false
	}
	for _, value := range []string{claims.HandoffID, claims.TaskID, claims.HubID, claims.GroupID,
		claims.FromPrincipalID, claims.FromOwnerID, claims.FromEndpointID, claims.FromBindingID,
		claims.FromKeyID, claims.ToPrincipalID, claims.ToOwnerID, claims.ToEndpointID,
		claims.ToBindingID, claims.ToKeyID, claims.MessageID} {
		if !canonicalEndpointToken(value, true) {
			return false
		}
	}
	expires, err := parseCanonicalUTC(claims.ExpiresAt)
	if err != nil {
		return false
	}
	issued, err := parseCanonicalUTC(claims.IssuedAt)
	return err == nil && expires.After(issued) && expires.Sub(issued) <= 24*time.Hour
}

// SignLocalTaskHandoffProof uses the already trusted source Endpoint
// signature key. Call it only after the exact local sealed envelope has been
// durably accepted by the Node-local ledger.
func (identity *Identity) SignLocalTaskHandoffProof(claims LocalTaskHandoffProofClaims) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil || !claims.valid() ||
		claims.FromKeyID != identity.Public().ID {
		return nil, ErrInvalidEnvelope
	}
	proof := LocalTaskHandoffProof{Claims: claims, KeyID: identity.Public().ID}
	signed, err := proof.signedBytes()
	if err != nil {
		return nil, err
	}
	proof.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, signed, nil, true, proof.Signature); err != nil {
		return nil, err
	}
	return json.Marshal(proof)
}

// VerifyLocalTaskHandoffProof verifies canonical claims against the exact
// current route derived by Store. The expected value includes the Store's
// canonical issuance time only when needed by the caller; use an empty
// IssuedAt there to accept any still-valid signed issuance time.
func VerifyLocalTaskHandoffProof(data []byte, trustedSender PublicIdentity,
	expected LocalTaskHandoffProofClaims, at time.Time) (LocalTaskHandoffProof, error) {
	if len(data) == 0 || len(data) > 16*1024 || at.IsZero() ||
		ValidatePublicIdentity(trustedSender) != nil {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var proof LocalTaskHandoffProof
	if err := decoder.Decode(&proof); err != nil {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || !proof.Claims.valid() ||
		proof.KeyID != trustedSender.ID || len(proof.Signature) != mldsa65.SignatureSize {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(data, canonical) {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	if expected.IssuedAt == "" {
		expected.IssuedAt = proof.Claims.IssuedAt
	}
	if proof.Claims != expected {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	issued, err := parseCanonicalUTC(proof.Claims.IssuedAt)
	if err != nil || issued.After(at) || !at.Before(mustParseCanonicalUTC(proof.Claims.ExpiresAt)) {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	_, signingPublic, err := validatePublic(trustedSender)
	if err != nil {
		return LocalTaskHandoffProof{}, err
	}
	signed, err := proof.signedBytes()
	if err != nil || !mldsa65.Verify(signingPublic, signed, nil, proof.Signature) {
		return LocalTaskHandoffProof{}, ErrInvalidEnvelope
	}
	return proof, nil
}

func mustParseCanonicalUTC(raw string) time.Time {
	value, _ := parseCanonicalUTC(raw)
	return value
}
