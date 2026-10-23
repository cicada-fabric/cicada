package e2ee

const hubTransportBindingDomain = "cicada/hub/transport-binding/v1\x00"

// SignHubTransportBinding signs the canonical descriptor's SHA-256 commitment.
// It establishes no Owner, account, device or Node authority. The descriptor
// owner must validate the claims and independently establish the signing pin.
func SignHubTransportBinding(hub *Identity, digest [32]byte) ([]byte, error) {
	if hub == nil || digest == [32]byte{} {
		return nil, ErrInvalidEnvelope
	}
	return tlsProofSignature(hub, hub.Public().ID, hubTransportBindingDomain, digest)
}

func VerifyHubTransportBinding(hub PublicIdentity, digest [32]byte, signature []byte) error {
	if digest == [32]byte{} {
		return ErrInvalidEnvelope
	}
	return verifyAppNodeSignature(hub, hubTransportBindingDomain, digest, signature)
}
