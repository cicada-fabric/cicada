package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func validInstallationNodeCredential(raw []byte) bool {
	const prefix = "cicada_node_"
	if len(raw) != len(prefix)+43 || !bytes.HasPrefix(raw, []byte(prefix)) {
		return false
	}
	tail := strings.TrimPrefix(string(raw), prefix)
	b, err := base64.RawURLEncoding.Strict().DecodeString(tail)
	defer clear(b)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == tail
}

// Only current Store data can supply expected. A public credential commitment
// and an old Node key do not prove possession of its current original bearer.
// H1 must call this inside its current writer/epoch/binding checks.
func ValidateInstallationLegacyCredential(c InstallationCandidate, raw []byte, expected InstallationLegacyCurrent) error {
	if e2ee.ValidateInstallationCandidate(c) != nil || c.Base.Subject.Kind != e2ee.InstallationNodeSubject || c.Base.Subject.Mode != e2ee.InstallationAdoptExisting ||
		!validInstallationNodeCredential(raw) || expected.OwnerID == "" || expected.BindingState != "ACTIVE" || expected.CredentialState != "active" || expected.CredentialDigest == "" {
		return ErrInvalid
	}
	if e := c.Base.Trust.Existing; e != nil && e.OwnerID != expected.OwnerID {
		return ErrInvalid
	}
	a, _ := json.Marshal(c.Base.Subject.Node)
	b, _ := json.Marshal(expected.Node)
	if !bytes.Equal(a, b) || NativePairCredentialCommitment(string(raw)) != expected.Node.CredentialCommitment {
		return ErrInvalid
	}
	// Exact existing fabric.HashSessionCredential framing: SHA-256 of the
	// canonical token, encoded unpadded base64url. Never persist raw here.
	digest := sha256.Sum256(raw)
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected.CredentialDigest)) != 1 {
		return ErrInvalid
	}
	return nil
}

func ClearInstallationRequestSecrets(body any) {
	switch v := installationBodyValue(body).(type) {
	case InstallationStart:
		clear(v.NodeCredential)
	case InstallationAccept:
		clear(v.ACKNonce)
	case InstallationOwnerPrepare:
		clear(v.SessionToken)
	case InstallationOwnerComplete:
		clear(v.SessionToken)
	case InstallationOwnerRevoke:
		clear(v.SessionToken)
	case InstallationAccessPrepare:
		clear(v.SessionToken)
	case InstallationAccessComplete:
		clear(v.SessionToken)
	case InstallationAccessRevoke:
		clear(v.SessionToken)
	case InstallationConnectionsRead:
		clear(v.SessionToken)
	}
}
