package e2ee

// InstallationAccountScope contains actual account-session and signing-key
// coordinates. It claims no legacy Client enrollment, N2 lease or N3 head.
// Discovery of this public context conveys no Owner or business authority.
type InstallationAccountScope struct {
	Version                 int            `json:"version"`
	Origin                  string         `json:"origin"`
	HubID                   string         `json:"hub_id"`
	HubFingerprint          string         `json:"hub_fingerprint"`
	AccountID               string         `json:"account_id"`
	AccountSessionID        string         `json:"account_session_id"`
	AccountSessionExpiresAt string         `json:"account_session_expires_at"`
	OwnerID                 string         `json:"owner_id"`
	OwnerPublic             PublicIdentity `json:"owner_public_identity"`
	OwnerKeyVersion         uint64         `json:"owner_key_version"`
	DeviceID                string         `json:"device_id"`
	DevicePublic            PublicIdentity `json:"device_public_identity"`
	AccountEpoch            uint64         `json:"account_epoch"`
	DeviceEpoch             uint64         `json:"device_epoch"`
	TransportPolicy         string         `json:"transport_policy"`
}

func ValidateInstallationAccountScope(s InstallationAccountScope) error {
	if s.Version != 1 || ValidatePublicIdentity(s.OwnerPublic) != nil || ValidatePublicIdentity(s.DevicePublic) != nil || !installationDistinct(s.OwnerPublic, s.DevicePublic) ||
		!canonicalSHA256Hex(s.HubFingerprint) || !tlsGrantToken(s.HubID) || !tlsGrantToken(s.AccountID) || !tlsGrantToken(s.AccountSessionID) || !tlsGrantToken(s.OwnerID) || !tlsGrantToken(s.DeviceID) ||
		!installationPositive(s.OwnerKeyVersion) || !installationPositive(s.AccountEpoch) || !installationPositive(s.DeviceEpoch) || ValidateInstallationOrigin(s.Origin, s.TransportPolicy) != nil {
		return ErrInvalidEnvelope
	}
	if _, err := parseCanonicalUTC(s.AccountSessionExpiresAt); err != nil {
		return ErrInvalidEnvelope
	}
	return nil
}
