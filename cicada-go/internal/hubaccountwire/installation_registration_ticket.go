package hubaccountwire

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const installationTicketPrefix = "cicada-ir1."

// Secret, not a diagnostic/card summary. Only FIRST_OOB uses a ticket;
// EXISTING_LOCAL_PIN uses the authenticated registered installation instead.
type InstallationTicket struct {
	Origin                 string
	HubID                  string
	HubFingerprint         string
	NodeControlFingerprint string
	InstallationID         string
	AttemptID              string
	CandidateDigest        string
	OOBSecret              []byte
	ExpiresAt              string
}

func installationTicketArray(t InstallationTicket) []any {
	return []any{1, t.Origin, t.HubID, t.HubFingerprint, t.NodeControlFingerprint, t.InstallationID, t.AttemptID, t.CandidateDigest, base64.RawURLEncoding.EncodeToString(t.OOBSecret), t.ExpiresAt}
}

func validateInstallationTicket(t InstallationTicket) error {
	policy := AppNodeTransportHTTPS
	if strings.HasPrefix(t.Origin, "http://") {
		policy = AppNodeTransportLoopbackTest
	}
	if e2ee.ValidateInstallationOrigin(t.Origin, policy) != nil {
		return ErrInvalid
	}
	if len(t.HubID) > e2ee.MaxInstallationHubIDBytes || !nativePairToken(t.HubID) || !isHex(t.HubFingerprint, 32) ||
		t.NodeControlFingerprint != "" && !isHex(t.NodeControlFingerprint, 32) || !isHex(t.InstallationID, RequestIDBytes) || !isHex(t.AttemptID, RequestIDBytes) || !isHex(t.CandidateDigest, 32) || len(t.OOBSecret) != 32 || validateCanonicalTime(t.ExpiresAt) != nil {
		return ErrInvalid
	}
	return nil
}

func EncodeInstallationTicket(c InstallationCandidate, secret []byte) (string, error) {
	if e2ee.ValidateInstallationCandidate(c) != nil || c.Base.Trust.Kind != e2ee.InstallationFirstOOB {
		return "", ErrInvalid
	}
	o, err := e2ee.InstallationOOBCommitment(c.CandidateDigest, secret)
	if err != nil || o != c.OOBCommitment {
		return "", ErrInvalid
	}
	t := InstallationTicket{Origin: c.Base.Hub.Origin, HubID: c.Base.Hub.HubID, HubFingerprint: c.Base.Hub.Fingerprint, InstallationID: c.Base.InstallationID, AttemptID: c.Base.AttemptID, CandidateDigest: c.CandidateDigest, OOBSecret: secret, ExpiresAt: c.Base.ExpiresAt}
	if n := c.Base.Subject.Node; n != nil {
		t.NodeControlFingerprint = n.HubNodeControlFingerprint
	}
	if validateInstallationTicket(t) != nil {
		return "", ErrInvalid
	}
	b, err := json.Marshal(installationTicketArray(t))
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(b)
	out := installationTicketPrefix + base64.RawURLEncoding.EncodeToString(b)
	if len(out) > MaxInstallationTicketBytes {
		return "", ErrInvalid
	}
	return out, nil
}

func DecodeInstallationTicket(token string, now time.Time) (InstallationTicket, error) {
	var out InstallationTicket
	if len(token) > MaxInstallationTicketBytes || !strings.HasPrefix(token, installationTicketPrefix) || now.IsZero() {
		return out, ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, installationTicketPrefix))
	if err != nil {
		return out, ErrInvalid
	}
	defer clear(b)
	var fields []json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 10 || !bytes.Equal(fields[0], []byte("1")) {
		return out, ErrInvalid
	}
	values := make([]string, 9)
	for i := range values {
		if json.Unmarshal(fields[i+1], &values[i]) != nil {
			return out, ErrInvalid
		}
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(values[7])
	if err != nil {
		return out, ErrInvalid
	}
	out = InstallationTicket{Origin: values[0], HubID: values[1], HubFingerprint: values[2], NodeControlFingerprint: values[3], InstallationID: values[4], AttemptID: values[5], CandidateDigest: values[6], OOBSecret: secret, ExpiresAt: values[8]}
	canonical, ce := json.Marshal(installationTicketArray(out))
	defer clear(canonical)
	end, ee := parseCanonicalUTC(out.ExpiresAt)
	if validateInstallationTicket(out) != nil || ce != nil || !bytes.Equal(canonical, b) || ee != nil || !now.Before(end) {
		clear(out.OOBSecret)
		return InstallationTicket{}, ErrInvalid
	}
	return out, nil
}

func MatchInstallationTicket(t InstallationTicket, c InstallationCandidate, trusted HubIdentity, now time.Time) error {
	if validateInstallationTicket(t) != nil || ValidateInstallationCandidate(c, trusted) != nil || c.Base.Trust.Kind != e2ee.InstallationFirstOOB ||
		t.Origin != c.Base.Hub.Origin || t.HubID != c.Base.Hub.HubID || t.HubFingerprint != c.Base.Hub.Fingerprint || t.InstallationID != c.Base.InstallationID || t.AttemptID != c.Base.AttemptID || t.CandidateDigest != c.CandidateDigest || t.ExpiresAt != c.Base.ExpiresAt {
		return ErrInvalid
	}
	start, _ := parseCanonicalUTC(c.Base.IssuedAt)
	end, _ := parseCanonicalUTC(c.Base.ExpiresAt)
	if now.IsZero() || now.Before(start.Add(-e2ee.InstallationIssuanceSkew)) || !now.Before(end) {
		return ErrInvalid
	}
	want := ""
	if n := c.Base.Subject.Node; n != nil {
		want = n.HubNodeControlFingerprint
	}
	o, err := e2ee.InstallationOOBCommitment(c.CandidateDigest, t.OOBSecret)
	if err != nil || subtle.ConstantTimeCompare([]byte(o), []byte(c.OOBCommitment)) != 1 || want != t.NodeControlFingerprint {
		return ErrInvalid
	}
	return nil
}
