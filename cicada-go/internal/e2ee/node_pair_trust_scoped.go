package e2ee

const nodePairTrustScopedOwnerDomain = "cicada/owner/node-pair-trust-scoped/v1\x00"

// Node pairing trust uses the existing ML-DSA signer over a purpose-specific
// canonical commitment. A valid signature is not an independent Owner pin.
func SignNodePairTrustScopedOwner(owner *Identity, digest [32]byte) ([]byte, error) {
	if owner == nil || digest == [32]byte{} {
		return nil, ErrInvalidEnvelope
	}
	return tlsProofSignature(owner, owner.Public().ID, nodePairTrustScopedOwnerDomain, digest)
}

func VerifyNodePairTrustScopedOwner(owner PublicIdentity, digest [32]byte, signature []byte) error {
	if digest == [32]byte{} {
		return ErrInvalidEnvelope
	}
	return verifyAppNodeSignature(owner, nodePairTrustScopedOwnerDomain, digest, signature)
}
