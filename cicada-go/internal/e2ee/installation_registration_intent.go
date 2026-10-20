package e2ee

import "time"

const (
	InstallationPreviewPurpose       = "OWNER_INSTALLATION_PREVIEW"
	InstallationRevokePurpose        = "OWNER_INSTALLATION_REVOKE"
	InstallationAccessPreviewPurpose = "OWNER_APP_ACCESS_PREVIEW"
	InstallationAccessRevokePurpose  = "OWNER_APP_ACCESS_REVOKE"
	installationIntentDomain         = "cicada/owner/installation-intent/v1\x00"
)

// These four exact purposes have no business action list or delegation. A
// preview resolves only one exact target; a revoke names its immutable revision.
type InstallationOwnerIntentClaims struct {
	Version          int               `json:"version"`
	Purpose          string            `json:"purpose"`
	Scope            OwnerAppNodeScope `json:"scope"`
	RequestID        string            `json:"request_id"`
	Nonce            string            `json:"nonce"`
	TargetID         string            `json:"target_id"`
	TargetDigest     string            `json:"target_digest"`
	ExpectedRevision uint64            `json:"expected_revision"`
	IssuedAt         string            `json:"issued_at"`
	ExpiresAt        string            `json:"expires_at"`
}

type InstallationOwnerIntentProof struct {
	Claims    InstallationOwnerIntentClaims `json:"claims"`
	Signature []byte                        `json:"signature"`
}

func validateInstallationIntent(c InstallationOwnerIntentClaims) error {
	if c.Version != 1 || appNodeProofScope(c.Scope) != nil || !appNodeProofID(c.RequestID) || !canonicalSHA256Hex(c.Nonce) ||
		!appNodeProofID(c.TargetID) || !canonicalSHA256Hex(c.TargetDigest) || !installationPositive(c.ExpectedRevision) {
		return ErrInvalidEnvelope
	}
	switch c.Purpose {
	case InstallationPreviewPurpose, InstallationRevokePurpose, InstallationAccessPreviewPurpose, InstallationAccessRevokePurpose:
	default:
		return ErrInvalidEnvelope
	}
	_, e, err := installationWindow(c.IssuedAt, c.ExpiresAt, time.Minute)
	session, se := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if err != nil || se != nil || e.After(session) {
		return ErrInvalidEnvelope
	}
	return nil
}

func SignInstallationOwnerIntent(owner *Identity, claims InstallationOwnerIntentClaims) ([]byte, error) {
	if owner == nil || validateInstallationIntent(claims) != nil || !installationSamePublic(owner.Public(), claims.Scope.OwnerPublic) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, installationIntentDomain, claims)
	if err != nil {
		return nil, err
	}
	return installationProofBytes(InstallationOwnerIntentProof{Claims: claims, Signature: sig})
}

func VerifyInstallationOwnerIntent(trusted PublicIdentity, raw []byte, purpose, targetID, targetDigest string, revision uint64, now time.Time) (InstallationOwnerIntentClaims, error) {
	var p InstallationOwnerIntentProof
	if installationReadCanonical(raw, &p, MaxInstallationProofBytes) != nil || validateInstallationIntent(p.Claims) != nil || !installationSamePublic(trusted, p.Claims.Scope.OwnerPublic) ||
		p.Claims.Purpose != purpose || p.Claims.TargetID != targetID || p.Claims.TargetDigest != targetDigest || p.Claims.ExpectedRevision != revision ||
		verifyAppNodeSignature(trusted, installationIntentDomain, p.Claims, p.Signature) != nil {
		return InstallationOwnerIntentClaims{}, ErrInvalidEnvelope
	}
	i, e, _ := installationWindow(p.Claims.IssuedAt, p.Claims.ExpiresAt, time.Minute)
	if installationCurrent(i, e, now) != nil {
		return InstallationOwnerIntentClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}
