package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func nodePairHash(domain string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	h.Write(n[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func nodePairDigest(domain string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxNodePairTrustProofBytes {
		return "", ErrInvalid
	}
	return nodePairHash(domain, raw), nil
}
func nodePairNonce(domain, digest string, nonce []byte) (string, error) {
	d, err := hex.DecodeString(digest)
	if err != nil || !isHex(digest, 32) || len(nonce) != 32 {
		return "", ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(d)
	h.Write(nonce)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func NodePairTrustPacketDigest(raw []byte) string {
	return nodePairHash("cicada/node-pair-trust/packet/v1\x00", raw)
}
func NodePairTrustDescriptorDigest(text string) string {
	return nodePairHash("cicada/node-pair-trust/descriptor/v1\x00", []byte(text))
}
func NodePairTrustCapsuleDigest(raw []byte) string {
	return nodePairHash("cicada/node-pair-trust/capsule/v1\x00", raw)
}
func NodePairTrustProofDigest(raw []byte) string {
	return nodePairHash("cicada/node-pair-trust/proof/v1\x00", raw)
}
func NodePairTrustContextDigest(c NodePairTrustContext) (string, error) {
	if ValidateNodePairTrustContext(c, time.Time{}) != nil {
		return "", ErrInvalid
	}
	return nodePairDigest("cicada/node-pair-trust/context/v1\x00", c)
}
func NodePairTrustOOBCommitment(contextDigest string, secret []byte) (string, error) {
	return nodePairNonce("cicada/node-pair-trust/oob/v1\x00", contextDigest, secret)
}
func NodePairTrustApprovalDigest(a NodePairTrustApproval) (string, error) {
	return nodePairDigest("cicada/node-pair-trust/approval/v1\x00", a)
}
func NodePairTrustACKCommitment(a NodePairTrustApproval, nonce []byte) (string, error) {
	d, err := NodePairTrustApprovalDigest(a)
	if err != nil {
		return "", err
	}
	return nodePairNonce("cicada/node-pair-trust/ack/v1\x00", d, nonce)
}
func nodePairClaimsCommitment(c NodePairTrustOwnerClaims) [32]byte {
	raw, _ := json.Marshal(c)
	d := nodePairHash("cicada/node-pair-trust/owner-claims/v1\x00", raw)
	b, _ := hex.DecodeString(d)
	var out [32]byte
	copy(out[:], b)
	return out
}
func nodePairCapsuleAAD(a NodePairTrustApproval) ([]byte, error) {
	d, err := NodePairTrustApprovalDigest(a)
	if err != nil {
		return nil, err
	}
	b, _ := hex.DecodeString(d)
	return append([]byte("cicada/node-pair-trust/capsule-aad/v1\x00"), b...), nil
}

// Only the independently transferred S makes a first Owner key trustworthy.
// The signed capsule binds the original Node key, approval and raw ciphertext.
func SealNodePairTrustApproval(owner *e2ee.Identity, c NodePairTrustContext, o string, a NodePairTrustApproval, secret, ackNonce []byte, now time.Time) ([]byte, []byte, error) {
	d, err := NodePairTrustContextDigest(c)
	want, oe := NodePairTrustOOBCommitment(d, secret)
	if owner == nil || now.IsZero() || err != nil || oe != nil || want != o || len(ackNonce) != 32 || bytes.Equal(secret, ackNonce) || !reflect.DeepEqual(owner.Public(), a.Scope.OwnerPublic) || ValidateNodePairTrustApproval(a, c, o, now) != nil {
		return nil, nil, ErrInvalid
	}
	plain, err := json.Marshal(NodePairTrustCapsule{NodePairTrustFormat, a, owner.Public(), secret, ackNonce})
	if err != nil || len(plain) > MaxNodePairTrustProofBytes {
		return nil, nil, ErrInvalid
	}
	defer clear(plain)
	aad, _ := nodePairCapsuleAAD(a)
	capsule, err := e2ee.Seal(owner, nodePairPublic(c), plain, aad, 1)
	if err != nil || len(capsule) > MaxNodePairTrustCapsuleBytes {
		return nil, nil, ErrInvalid
	}
	ack, _ := NodePairTrustACKCommitment(a, ackNonce)
	claims := NodePairTrustOwnerClaims{1, NodePairTrustOwnerPurpose, a, NodePairTrustCapsuleDigest(capsule), ack}
	sig, err := e2ee.SignNodePairTrustOwner(owner, nodePairClaimsCommitment(claims))
	if err != nil {
		return nil, nil, ErrInvalid
	}
	proof, err := json.Marshal(NodePairTrustOwnerProof{claims, sig})
	if err != nil || len(proof) > MaxNodePairTrustProofBytes {
		return nil, nil, ErrInvalid
	}
	return proof, capsule, nil
}

// This checks the signature against the supplied public key only. First trust
// MUST use OpenNodePairTrustCapsule with retained local context/S afterward.
func VerifyNodePairTrustOwnerProof(owner e2ee.PublicIdentity, c NodePairTrustContext, o string, raw []byte, now time.Time) (NodePairTrustOwnerClaims, error) {
	var p NodePairTrustOwnerProof
	if now.IsZero() || decodeCanonical(raw, MaxNodePairTrustProofBytes, &p) != nil || p.Claims.Version != 1 || p.Claims.Purpose != NodePairTrustOwnerPurpose || !reflect.DeepEqual(owner, p.Claims.Approval.Scope.OwnerPublic) || ValidateNodePairTrustApproval(p.Claims.Approval, c, o, now) != nil || !isHex(p.Claims.CapsuleDigest, 32) || !isHex(p.Claims.ACKCommitment, 32) || e2ee.VerifyNodePairTrustOwner(owner, nodePairClaimsCommitment(p.Claims), p.Signature) != nil {
		return NodePairTrustOwnerClaims{}, ErrInvalid
	}
	return p.Claims, nil
}

func OpenNodePairTrustCapsule(node *e2ee.Identity, c NodePairTrustContext, o string, proof, capsule, localSecret []byte, now time.Time) (NodePairTrustCapsule, error) {
	var p NodePairTrustOwnerProof
	var out NodePairTrustCapsule
	if node == nil || !reflect.DeepEqual(node.Public(), nodePairPublic(c)) || decodeCanonical(proof, MaxNodePairTrustProofBytes, &p) != nil || len(capsule) == 0 || len(capsule) > MaxNodePairTrustCapsuleBytes {
		return out, ErrInvalid
	}
	claims, err := VerifyNodePairTrustOwnerProof(p.Claims.Approval.Scope.OwnerPublic, c, o, proof, now)
	if err != nil || claims.CapsuleDigest != NodePairTrustCapsuleDigest(capsule) {
		return out, ErrInvalid
	}
	aad, _ := nodePairCapsuleAAD(claims.Approval)
	plain, seq, err := e2ee.Open(node, claims.Approval.Scope.OwnerPublic, capsule, aad)
	if err != nil || seq != 1 {
		return out, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, MaxNodePairTrustProofBytes, &out) != nil {
		return NodePairTrustCapsule{}, ErrInvalid
	}
	d, _ := NodePairTrustContextDigest(c)
	want, oe := NodePairTrustOOBCommitment(d, localSecret)
	ack, ae := NodePairTrustACKCommitment(claims.Approval, out.ACKNonce)
	if oe != nil || want != o || out.Format != NodePairTrustFormat || !reflect.DeepEqual(out.Approval, claims.Approval) || !reflect.DeepEqual(out.OwnerPublic, claims.Approval.Scope.OwnerPublic) || len(out.OOBSecret) != 32 || subtle.ConstantTimeCompare(localSecret, out.OOBSecret) != 1 || bytes.Equal(out.OOBSecret, out.ACKNonce) || ae != nil || ack != claims.ACKCommitment {
		clear(out.OOBSecret)
		clear(out.ACKNonce)
		return NodePairTrustCapsule{}, ErrInvalid
	}
	return out, nil
}

// The current Store and original poll delivery must also be checked by the
// service. A public digest or a server-selected historical clock is insufficient.
func VerifyNodePairTrustACK(c NodePairTrustContext, o string, proof, capsule []byte, ack NodePairTrustACK, now time.Time) error {
	var p NodePairTrustOwnerProof
	if decodeCanonical(proof, MaxNodePairTrustProofBytes, &p) != nil {
		return ErrInvalid
	}
	claims, err := VerifyNodePairTrustOwnerProof(p.Claims.Approval.Scope.OwnerPublic, c, o, proof, now)
	a, ae := NodePairTrustACKCommitment(claims.Approval, ack.ACKNonce)
	if err != nil || ae != nil || a != claims.ACKCommitment || claims.CapsuleDigest != NodePairTrustCapsuleDigest(capsule) || ack.CapsuleDigest != claims.CapsuleDigest || ack.OwnerProofDigest != NodePairTrustProofDigest(proof) || ack.OOBCommitment != o || !reflect.DeepEqual(ack.Context, c) || ack.Format != NodePairTrustFormat || !isHex(ack.PollPacketDigest, 32) || !isHex(ack.PollReceiptDigest, 32) || validateRecent(ack.IssuedAt, now, time.Minute) != nil {
		return ErrInvalid
	}
	return nil
}
