package e2ee

// NewPublicIdentity constructs the existing Cicada public identity from raw
// ML-KEM-768 and ML-DSA-65 public keys. It copies the input and uses the same
// identity derivation and validation as generated Node and Client identities.
// This does not establish trust or prove possession of either private key.
func NewPublicIdentity(kemPublic, signingPublic []byte) (PublicIdentity, error) {
	public := PublicIdentity{
		ID:            identityID(kemPublic, signingPublic),
		KEMPublic:     append([]byte(nil), kemPublic...),
		SigningPublic: append([]byte(nil), signingPublic...),
	}
	if err := ValidatePublicIdentity(public); err != nil {
		return PublicIdentity{}, err
	}
	return public, nil
}
