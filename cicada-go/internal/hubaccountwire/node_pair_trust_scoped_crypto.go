package hubaccountwire

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func NodePairTrustScopedPacketDigest(raw []byte) string {
	return nodePairHash("cicada/node-pair-trust-scoped/packet/v1\x00", raw)
}
func NodePairTrustScopedDescriptorDigest(text string) string {
	return nodePairHash("cicada/node-pair-trust-scoped/descriptor/v1\x00", []byte(text))
}
func NodePairTrustScopedCapsuleDigest(raw []byte) string {
	return nodePairHash("cicada/node-pair-trust-scoped/capsule/v1\x00", raw)
}
func NodePairTrustScopedProofDigest(raw []byte) string {
	return nodePairHash("cicada/node-pair-trust-scoped/proof/v1\x00", raw)
}
func NodePairTrustScopedContextDigest(c NodePairTrustScopedContext) (string, error) {
	if ValidateNodePairTrustScopedContext(c, time.Time{}) != nil {
		return "", ErrInvalid
	}
	return nodePairDigest("cicada/node-pair-trust-scoped/context/v1\x00", c)
}
func NodePairTrustScopedOOBCommitment(contextDigest string, secret []byte) (string, error) {
	return nodePairNonce("cicada/node-pair-trust-scoped/oob/v1\x00", contextDigest, secret)
}
func NodePairTrustScopedApprovalDigest(a NodePairTrustScopedApproval) (string, error) {
	return nodePairDigest("cicada/node-pair-trust-scoped/approval/v1\x00", a)
}
func NodePairTrustScopedACKCommitment(a NodePairTrustScopedApproval, nonce []byte) (string, error) {
	d, err := NodePairTrustScopedApprovalDigest(a)
	if err != nil {
		return "", err
	}
	return nodePairNonce("cicada/node-pair-trust-scoped/ack/v1\x00", d, nonce)
}
func nodePairScopedClaimsCommitment(c NodePairTrustScopedOwnerClaims) [32]byte {
	raw, _ := json.Marshal(c)
	d := nodePairHash("cicada/node-pair-trust-scoped/owner-claims/v1\x00", raw)
	b, _ := hex.DecodeString(d)
	var out [32]byte
	copy(out[:], b)
	return out
}
func nodePairScopedCapsuleAAD(a NodePairTrustScopedApproval) ([]byte, error) {
	d, err := NodePairTrustScopedApprovalDigest(a)
	if err != nil {
		return nil, err
	}
	b, _ := hex.DecodeString(d)
	return append([]byte("cicada/node-pair-trust-scoped/capsule-aad/v1\x00"), b...), nil
}

// Only the independently transferred S makes a first Owner key trustworthy.
// The signed capsule binds the original Node key, approval and raw ciphertext.
func SealNodePairTrustScopedApproval(owner *e2ee.Identity, c NodePairTrustScopedContext, o string, a NodePairTrustScopedApproval, secret, ackNonce []byte, now time.Time) ([]byte, []byte, error) {
	d, err := NodePairTrustScopedContextDigest(c)
	want, oe := NodePairTrustScopedOOBCommitment(d, secret)
	if owner == nil || now.IsZero() || err != nil || oe != nil || want != o || len(ackNonce) != 32 || bytes.Equal(secret, ackNonce) || !reflect.DeepEqual(owner.Public(), a.Scope.OwnerPublic) || ValidateNodePairTrustScopedApproval(a, c, o, now) != nil {
		return nil, nil, ErrInvalid
	}
	plain, err := json.Marshal(NodePairTrustScopedCapsule{NodePairTrustScopedFormat, a, owner.Public(), secret, ackNonce})
	if err != nil || len(plain) > MaxNodePairTrustScopedProofBytes {
		return nil, nil, ErrInvalid
	}
	defer clear(plain)
	aad, _ := nodePairScopedCapsuleAAD(a)
	capsule, err := e2ee.Seal(owner, nodePairScopedPublic(c), plain, aad, 1)
	if err != nil || len(capsule) > MaxNodePairTrustScopedCapsuleBytes {
		return nil, nil, ErrInvalid
	}
	ack, _ := NodePairTrustScopedACKCommitment(a, ackNonce)
	claims := NodePairTrustScopedOwnerClaims{2, NodePairTrustScopedOwnerPurpose, a, NodePairTrustScopedCapsuleDigest(capsule), ack}
	sig, err := e2ee.SignNodePairTrustScopedOwner(owner, nodePairScopedClaimsCommitment(claims))
	if err != nil {
		return nil, nil, ErrInvalid
	}
	proof, err := json.Marshal(NodePairTrustScopedOwnerProof{claims, sig})
	if err != nil || len(proof) > MaxNodePairTrustScopedProofBytes {
		return nil, nil, ErrInvalid
	}
	return proof, capsule, nil
}

// This checks the signature against the supplied public key only. First trust
// MUST use OpenNodePairTrustScopedCapsule with retained local context/S afterward.
func VerifyNodePairTrustScopedOwnerProof(owner e2ee.PublicIdentity, c NodePairTrustScopedContext, o string, raw []byte, now time.Time) (NodePairTrustScopedOwnerClaims, error) {
	var p NodePairTrustScopedOwnerProof
	if now.IsZero() || decodeCanonical(raw, MaxNodePairTrustScopedProofBytes, &p) != nil || p.Claims.Version != 2 || p.Claims.Purpose != NodePairTrustScopedOwnerPurpose || !reflect.DeepEqual(owner, p.Claims.Approval.Scope.OwnerPublic) || ValidateNodePairTrustScopedApproval(p.Claims.Approval, c, o, now) != nil || !isHex(p.Claims.CapsuleDigest, 32) || !isHex(p.Claims.ACKCommitment, 32) || e2ee.VerifyNodePairTrustScopedOwner(owner, nodePairScopedClaimsCommitment(p.Claims), p.Signature) != nil {
		return NodePairTrustScopedOwnerClaims{}, ErrInvalid
	}
	return p.Claims, nil
}

func OpenNodePairTrustScopedCapsule(node *e2ee.Identity, c NodePairTrustScopedContext, o string, proof, capsule, localSecret []byte, now time.Time) (NodePairTrustScopedCapsule, error) {
	var p NodePairTrustScopedOwnerProof
	var out NodePairTrustScopedCapsule
	if node == nil || !reflect.DeepEqual(node.Public(), nodePairScopedPublic(c)) || decodeCanonical(proof, MaxNodePairTrustScopedProofBytes, &p) != nil || len(capsule) == 0 || len(capsule) > MaxNodePairTrustScopedCapsuleBytes {
		return out, ErrInvalid
	}
	claims, err := VerifyNodePairTrustScopedOwnerProof(p.Claims.Approval.Scope.OwnerPublic, c, o, proof, now)
	if err != nil || claims.CapsuleDigest != NodePairTrustScopedCapsuleDigest(capsule) {
		return out, ErrInvalid
	}
	aad, _ := nodePairScopedCapsuleAAD(claims.Approval)
	plain, seq, err := e2ee.Open(node, claims.Approval.Scope.OwnerPublic, capsule, aad)
	if err != nil || seq != 1 {
		return out, ErrInvalid
	}
	defer clear(plain)
	if decodeCanonical(plain, MaxNodePairTrustScopedProofBytes, &out) != nil {
		return NodePairTrustScopedCapsule{}, ErrInvalid
	}
	d, _ := NodePairTrustScopedContextDigest(c)
	want, oe := NodePairTrustScopedOOBCommitment(d, localSecret)
	ack, ae := NodePairTrustScopedACKCommitment(claims.Approval, out.ACKNonce)
	if oe != nil || want != o || out.Format != NodePairTrustScopedFormat || !reflect.DeepEqual(out.Approval, claims.Approval) || !reflect.DeepEqual(out.OwnerPublic, claims.Approval.Scope.OwnerPublic) || len(out.OOBSecret) != 32 || subtle.ConstantTimeCompare(localSecret, out.OOBSecret) != 1 || bytes.Equal(out.OOBSecret, out.ACKNonce) || ae != nil || ack != claims.ACKCommitment {
		clear(out.OOBSecret)
		clear(out.ACKNonce)
		return NodePairTrustScopedCapsule{}, ErrInvalid
	}
	return out, nil
}

// The current Store and original poll delivery must also be checked by the
// service. A public digest or a server-selected historical clock is insufficient.
func VerifyNodePairTrustScopedACK(c NodePairTrustScopedContext, o string, proof, capsule []byte, ack NodePairTrustScopedACK, now time.Time) error {
	var p NodePairTrustScopedOwnerProof
	if decodeCanonical(proof, MaxNodePairTrustScopedProofBytes, &p) != nil {
		return ErrInvalid
	}
	claims, err := VerifyNodePairTrustScopedOwnerProof(p.Claims.Approval.Scope.OwnerPublic, c, o, proof, now)
	a, ae := NodePairTrustScopedACKCommitment(claims.Approval, ack.ACKNonce)
	if err != nil || ae != nil || a != claims.ACKCommitment || claims.CapsuleDigest != NodePairTrustScopedCapsuleDigest(capsule) || ack.CapsuleDigest != claims.CapsuleDigest || ack.OwnerProofDigest != NodePairTrustScopedProofDigest(proof) || ack.OOBCommitment != o || !reflect.DeepEqual(ack.Context, c) || ack.Format != NodePairTrustScopedFormat || !isHex(ack.PollPacketDigest, 32) || !isHex(ack.PollReceiptDigest, 32) || validateRecent(ack.IssuedAt, now, time.Minute) != nil {
		return ErrInvalid
	}
	return nil
}
