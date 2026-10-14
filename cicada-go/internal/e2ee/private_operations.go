package e2ee

import (
	"errors"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// PrivateOperations leaves private-key custody with a local provider. Sign
// must perform Pure ML-DSA-65 with an empty context over the exact message;
// MLKEMDecapsulate must perform ML-KEM-768 and return its 32-byte shared secret.
// Expected public identity and authorization are supplied separately by the
// caller. Providers must not log input, private material, or shared secrets.
// The caller owns and clears the returned shared-secret buffer after use.
type PrivateOperations interface {
	Sign(message []byte) ([]byte, error)
	MLKEMDecapsulate(ciphertext []byte) ([]byte, error)
}

var ErrPrivateOperation = errors.New("private cryptographic operation failed")

// Sign and MLKEMDecapsulate adapt an existing opaque in-process Identity to
// the same operations as an external provider without exporting private keys.
func (identity *Identity) Sign(message []byte) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, ErrPrivateOperation
	}
	signature := make([]byte, mldsa65.SignatureSize)
	if e := mldsa65.SignTo(identity.signingPrivate, message, nil, true, signature); e != nil {
		return nil, ErrPrivateOperation
	}
	return signature, nil
}

func (identity *Identity) MLKEMDecapsulate(ciphertext []byte) ([]byte, error) {
	if identity == nil || identity.kemPrivate == nil || len(ciphertext) != mlkem768.CiphertextSize {
		return nil, ErrPrivateOperation
	}
	secret := make([]byte, mlkem768.SharedKeySize)
	identity.kemPrivate.DecapsulateTo(secret, ciphertext)
	return secret, nil
}
