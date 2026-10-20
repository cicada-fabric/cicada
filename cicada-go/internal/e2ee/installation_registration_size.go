package e2ee

import (
	"encoding/base64"
	"encoding/json"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// InstallationSealedEnvelopeSize predicts this contract's one-shot Seal packet
// without KEM/signing work or a plaintext-sized allocation. This is a size model
// only, never a packet/proof. Tests compare it with the actual production Seal.
func InstallationSealedEnvelopeSize(sender PublicIdentity, plaintextBytes int) (int, error) {
	if ValidatePublicIdentity(sender) != nil || plaintextBytes < 0 || plaintextBytes > 1024*1024 {
		return 0, ErrInvalidEnvelope
	}
	e := Envelope{Version: ProtocolVersion, Algorithm: Algorithm, Sequence: 1, KEMCiphertext: make([]byte, mlkem768.CiphertextSize), Nonce: make([]byte, 12), SenderID: sender.ID, SenderSigningPublic: sender.SigningPublic, Signature: make([]byte, mldsa65.SignatureSize)}
	b, err := json.Marshal(e)
	if err != nil {
		return 0, ErrInvalidEnvelope
	}
	// Ciphertext:null becomes a JSON base64 string, including the GCM tag.
	return len(b) - len("null") + 2 + base64.StdEncoding.EncodedLen(plaintextBytes+16), nil
}
