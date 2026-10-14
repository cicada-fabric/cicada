package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// HubFingerprint hashes the canonical complete public Hub identity. A short
// key ID or URL is not a substitute for this independently delivered pin.
func HubFingerprint(hub HubIdentity) (string, error) {
	if err := validateHubIdentity(hub); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(hub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(hubFingerprintDomain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func ValidateClaimCard(card ClaimCard, hub HubIdentity, now time.Time) error {
	if validateClaimCardShape(card, now) != nil || card.HubID != hub.HubID {
		return ErrInvalid
	}
	fingerprint, err := HubFingerprint(hub)
	if err != nil || fingerprint != card.HubFingerprint {
		return ErrInvalid
	}
	return nil
}

// DecodeClaimCard strictly decodes the original public claim-card bytes. It
// rejects unknown fields, duplicate keys, noncanonical JSON, and oversized
// input before callers display or send the one-time code.
func DecodeClaimCard(raw []byte) (ClaimCard, error) {
	var card ClaimCard
	if err := decodeCanonical(raw, MaxClaimCardBytes, &card); err != nil || validateClaimCardShape(card, time.Time{}) != nil {
		return ClaimCard{}, ErrInvalid
	}
	return card, nil
}

// ValidateClaimCardForPage binds a locally delivered card to both the actual
// page origin and the independently observed full Hub identity. It returns no
// code or other claim secret for UI display.
func ValidateClaimCardForPage(card ClaimCard, pageOrigin string, hub HubIdentity, now time.Time) (ClaimCardSummary, error) {
	if ValidateClaimCard(card, hub, now) != nil || validateOrigin(pageOrigin) != nil || pageOrigin != card.Origin {
		return ClaimCardSummary{}, ErrInvalid
	}
	return ClaimCardSummary{Origin: card.Origin, HubID: card.HubID, HubFingerprint: card.HubFingerprint,
		AccountID: card.AccountID, OwnerID: card.OwnerID, ExpiresAt: card.ExpiresAt}, nil
}

func validateClaimCardShape(card ClaimCard, now time.Time) error {
	if card.Format != ClaimCardFormat || card.Version != 1 || card.Purpose != PurposeInitialClaim ||
		!validID(card.HubID) || !validID(card.AccountID) || !validID(card.OwnerID) || !isHex(card.ClaimID, 16) ||
		!isHex(card.HubFingerprint, 32) {
		return ErrInvalid
	}
	origin, err := ownerbootstrap.CanonicalOrigin(card.Origin, card.AllowLoopbackHTTP)
	if err != nil || origin != card.Origin {
		return ErrInvalid
	}
	if _, err := decodeCode(card.Code); err != nil {
		return ErrInvalid
	}
	issued, err := parseCanonicalUTC(card.IssuedAt)
	if err != nil {
		return ErrInvalid
	}
	expires, err := parseCanonicalUTC(card.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > MaxClaimLifetime {
		return ErrInvalid
	}
	if !now.IsZero() && (!now.Before(expires) || now.Before(issued.Add(-30*time.Second))) {
		return ErrInvalid
	}
	return nil
}

// NewClaimPrepare creates a fresh account-device ID, 128-bit request ID, and
// 256-bit challenge nonce without exposing private-key bytes.
func NewClaimPrepare(card ClaimCard, hub HubIdentity, device e2ee.PublicIdentity, now time.Time) (ClaimPrepare, error) {
	if err := ValidateClaimCard(card, hub, now); err != nil || e2ee.ValidatePublicIdentity(device) != nil {
		return ClaimPrepare{}, ErrInvalid
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if err != nil {
		return ClaimPrepare{}, ErrInvalid
	}
	deviceSuffix, err := randomHex(RequestIDBytes)
	if err != nil {
		return ClaimPrepare{}, err
	}
	requestID, err := randomHex(RequestIDBytes)
	if err != nil {
		return ClaimPrepare{}, err
	}
	nonce, err := randomBytes(NonceBytes)
	if err != nil {
		return ClaimPrepare{}, err
	}
	return ClaimPrepare{Format: ClaimPrepareFormat, Purpose: PurposeInitialClaim, Claim: card,
		DeviceID: AccountDeviceIDPrefix + deviceSuffix, DeviceKeyFingerprint: fingerprint, RequestID: requestID,
		ClientNonce: nonce, IssuedAt: formatUTC(now)}, nil
}

func NewClaimComplete(card ClaimCard, hub HubIdentity, challenge ClaimChallenge, device e2ee.PublicIdentity, username, password string, ownerPublic e2ee.PublicIdentity, now time.Time) (ClaimComplete, error) {
	if ValidateClaimCard(card, hub, now) != nil || challenge.Origin != card.Origin || challenge.HubID != card.HubID ||
		challenge.AccountID != card.AccountID || challenge.OwnerID != card.OwnerID || challenge.ClaimID != card.ClaimID {
		return ClaimComplete{}, ErrInvalid
	}
	challengeExpires, err := parseCanonicalUTC(challenge.ExpiresAt)
	cardExpiry, cardErr := parseCanonicalUTC(card.ExpiresAt)
	if err != nil || cardErr != nil || challengeExpires.After(cardExpiry) {
		return ClaimComplete{}, ErrInvalid
	}
	return NewClaimCompleteFromChallenge(hub, challenge, device, username, password, ownerPublic, now)
}

// NewClaimCompleteFromChallenge resumes an already authenticated claim after
// page reload without retaining or re-entering the one-time claim code. The
// caller must obtain challenge from OpenClientResponse for this Hub and the
// exact persisted prepare packet before calling this constructor.
func NewClaimCompleteFromChallenge(hub HubIdentity, challenge ClaimChallenge, device e2ee.PublicIdentity, username, password string, ownerPublic e2ee.PublicIdentity, now time.Time) (ClaimComplete, error) {
	if validateHubIdentity(hub) != nil || challenge.Format != ClaimChallengeFormat || challenge.Purpose != PurposeInitialClaim ||
		validateOrigin(challenge.Origin) != nil || challenge.HubID != hub.HubID ||
		!validID(challenge.AccountID) || !validID(challenge.OwnerID) || !isHex(challenge.ClaimID, 16) ||
		!validDeviceID(challenge.DeviceID) || !isHex(challenge.AttemptID, 16) || !isHex(challenge.PrepareRequestID, 16) ||
		len(challenge.ClientNonce) != NonceBytes || len(challenge.ServerNonce) != NonceBytes ||
		challenge.AccountEpoch == 0 || challenge.DeviceEpoch != 1 ||
		!validUsername(username) || !validPassword(password) || e2ee.ValidatePublicIdentity(device) != nil ||
		e2ee.ValidatePublicIdentity(ownerPublic) != nil || reflect.DeepEqual(device, ownerPublic) || ownerPublic.ID == hub.Public.ID {
		return ClaimComplete{}, ErrInvalid
	}
	deviceFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if err != nil || deviceFingerprint != challenge.DeviceKeyFingerprint || device.ID != challenge.DeviceKeyID {
		return ClaimComplete{}, ErrInvalid
	}
	issued, err := parseCanonicalUTC(challenge.IssuedAt)
	if err != nil {
		return ClaimComplete{}, ErrInvalid
	}
	expires, err := parseCanonicalUTC(challenge.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > MaxClaimChallengeLifetime ||
		issued.After(now.Add(30*time.Second)) || !now.Before(expires) {
		return ClaimComplete{}, ErrInvalid
	}
	requestID, err := randomHex(RequestIDBytes)
	if err != nil {
		return ClaimComplete{}, err
	}
	nonce, err := randomBytes(NonceBytes)
	if err != nil {
		return ClaimComplete{}, err
	}
	return ClaimComplete{Format: ClaimCompleteFormat, Purpose: PurposeInitialClaim, Origin: challenge.Origin,
		HubID: challenge.HubID, AccountID: challenge.AccountID, OwnerID: challenge.OwnerID, ClaimID: challenge.ClaimID,
		AttemptID: challenge.AttemptID, DeviceID: challenge.DeviceID, DeviceKeyID: challenge.DeviceKeyID,
		DeviceKeyFingerprint: challenge.DeviceKeyFingerprint, PrepareRequestID: challenge.PrepareRequestID,
		PrepareClientNonce: append([]byte(nil), challenge.ClientNonce...), ServerNonce: append([]byte(nil), challenge.ServerNonce...),
		AccountEpoch: challenge.AccountEpoch, DeviceEpoch: challenge.DeviceEpoch, ChallengeIssuedAt: challenge.IssuedAt,
		ChallengeExpiresAt: challenge.ExpiresAt, RequestID: requestID, ClientNonce: nonce, Username: username,
		Password: password, OwnerPublicIdentity: ownerPublic, IssuedAt: formatUTC(now)}, nil
}

func NewLoginPrepare(hub HubIdentity, origin, accountID, ownerID, deviceID, username string, device e2ee.PublicIdentity, now time.Time) (LoginPrepare, error) {
	if validateHubIdentity(hub) != nil || validateOrigin(origin) != nil || !validID(accountID) || !validID(ownerID) ||
		!validDeviceID(deviceID) || !validUsername(username) || e2ee.ValidatePublicIdentity(device) != nil {
		return LoginPrepare{}, ErrInvalid
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device)
	if err != nil {
		return LoginPrepare{}, ErrInvalid
	}
	requestID, err := randomHex(RequestIDBytes)
	if err != nil {
		return LoginPrepare{}, err
	}
	nonce, err := randomBytes(NonceBytes)
	if err != nil {
		return LoginPrepare{}, err
	}
	return LoginPrepare{Format: LoginPrepareFormat, Purpose: PurposeAccountLogin, Origin: origin, HubID: hub.HubID,
		AccountID: accountID, OwnerID: ownerID, DeviceID: deviceID, DeviceKeyID: device.ID,
		DeviceKeyFingerprint: fingerprint, Username: username, RequestID: requestID, ClientNonce: nonce,
		IssuedAt: formatUTC(now)}, nil
}

func NewLoginComplete(hub HubIdentity, challenge LoginChallenge, password string, now time.Time) (LoginComplete, error) {
	if challenge.Format != LoginChallengeFormat || challenge.Purpose != PurposeAccountLogin || validateOrigin(challenge.Origin) != nil ||
		validateHubIdentity(hub) != nil || challenge.HubID != hub.HubID ||
		!validID(challenge.HubID) || !validID(challenge.AccountID) || !validID(challenge.OwnerID) || !validDeviceID(challenge.DeviceID) ||
		!validID(challenge.DeviceKeyID) || !isHex(challenge.DeviceKeyFingerprint, 32) || !isHex(challenge.AttemptID, 16) ||
		!isHex(challenge.PrepareRequestID, 16) || len(challenge.ClientNonce) != NonceBytes || len(challenge.ServerNonce) != NonceBytes ||
		challenge.AccountEpoch == 0 || challenge.DeviceEpoch == 0 || !validUsername(challenge.Username) || !validPassword(password) {
		return LoginComplete{}, ErrInvalid
	}
	issued, err := parseCanonicalUTC(challenge.IssuedAt)
	if err != nil {
		return LoginComplete{}, ErrInvalid
	}
	expires, err := parseCanonicalUTC(challenge.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > MaxLoginChallengeLifetime || !now.Before(expires) {
		return LoginComplete{}, ErrInvalid
	}
	requestID, err := randomHex(RequestIDBytes)
	if err != nil {
		return LoginComplete{}, err
	}
	nonce, err := randomBytes(NonceBytes)
	if err != nil {
		return LoginComplete{}, err
	}
	return LoginComplete{Format: LoginCompleteFormat, Purpose: PurposeAccountLogin, Origin: challenge.Origin,
		HubID: challenge.HubID, AccountID: challenge.AccountID, OwnerID: challenge.OwnerID, AttemptID: challenge.AttemptID,
		DeviceID: challenge.DeviceID, DeviceKeyID: challenge.DeviceKeyID, DeviceKeyFingerprint: challenge.DeviceKeyFingerprint,
		PrepareRequestID: challenge.PrepareRequestID, PrepareClientNonce: append([]byte(nil), challenge.ClientNonce...),
		ServerNonce: append([]byte(nil), challenge.ServerNonce...), AccountEpoch: challenge.AccountEpoch,
		DeviceEpoch: challenge.DeviceEpoch, ChallengeIssuedAt: challenge.IssuedAt, ChallengeExpiresAt: challenge.ExpiresAt,
		RequestID: requestID, ClientNonce: nonce, Username: challenge.Username, Password: password, IssuedAt: formatUTC(now)}, nil
}

func NewSessionInspectRequest(session SessionContext, now time.Time) (SessionInspectRequest, error) {
	if validateSessionContext(session, now) != nil {
		return SessionInspectRequest{}, ErrInvalid
	}
	requestID, err := randomHex(RequestIDBytes)
	if err != nil {
		return SessionInspectRequest{}, err
	}
	nonce, err := randomBytes(NonceBytes)
	if err != nil {
		return SessionInspectRequest{}, err
	}
	return SessionInspectRequest{Format: SessionInspectFormat, Purpose: PurposeAccountSession, Origin: session.Origin,
		HubID: session.HubID, AccountID: session.AccountID, OwnerID: session.OwnerID, DeviceID: session.DeviceID,
		DeviceKeyID: session.DeviceKeyID, DeviceKeyFingerprint: session.DeviceKeyFingerprint,
		SessionToken: append([]byte(nil), session.SessionToken...), AccountEpoch: session.AccountEpoch,
		DeviceEpoch: session.DeviceEpoch, RequestID: requestID, ClientNonce: nonce,
		IssuedAt: formatUTC(now), ExpiresAt: formatUTC(now.Add(MaxSessionRequestLifetime))}, nil
}

func NewLogoutRequest(session SessionContext, now time.Time) (LogoutRequest, error) {
	if validateSessionContext(session, now) != nil {
		return LogoutRequest{}, ErrInvalid
	}
	requestID, err := randomHex(RequestIDBytes)
	if err != nil {
		return LogoutRequest{}, err
	}
	nonce, err := randomBytes(NonceBytes)
	if err != nil {
		return LogoutRequest{}, err
	}
	return LogoutRequest{Format: LogoutFormat, Purpose: PurposeAccountSession, Origin: session.Origin,
		HubID: session.HubID, AccountID: session.AccountID, OwnerID: session.OwnerID, DeviceID: session.DeviceID,
		DeviceKeyID: session.DeviceKeyID, DeviceKeyFingerprint: session.DeviceKeyFingerprint,
		SessionToken: append([]byte(nil), session.SessionToken...), AccountEpoch: session.AccountEpoch,
		DeviceEpoch: session.DeviceEpoch, RequestID: requestID, ClientNonce: nonce,
		IssuedAt: formatUTC(now), ExpiresAt: formatUTC(now.Add(MaxSessionRequestLifetime))}, nil
}
