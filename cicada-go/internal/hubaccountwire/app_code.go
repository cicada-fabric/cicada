package hubaccountwire

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// OwnerAccountClaimCodePrefix frames an existing one-use initial Owner
// account ClaimCard for deliberate local App entry. It is not a URL and does
// not grant Root or Manager authority.
const OwnerAccountClaimCodePrefix = "cicada-owner-account-claim-v1:"

const MaxOwnerAccountClaimCodeText = len(OwnerAccountClaimCodePrefix) + (MaxClaimCardBytes/3)*4 + ((MaxClaimCardBytes%3)*4+2)/3

// MaxAppClaimCodeBytes bounds UI editors to the largest accepted local code.
const MaxAppClaimCodeBytes = MaxOwnerAccountClaimCodeText

// EncodeOwnerAccountClaimCode returns a compact, canonical representation of
// the existing initial-account ClaimCard. The card remains secret-bearing.
func EncodeOwnerAccountClaimCode(card ClaimCard) (string, error) {
	raw, err := json.Marshal(card)
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(raw)
	canonical, err := DecodeClaimCard(raw)
	if err != nil || canonical != card {
		return "", ErrInvalid
	}
	return OwnerAccountClaimCodePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeOwnerAccountClaimCode accepts only the canonical compact local code.
// It deliberately does not apply expiry or Hub-pin checks; callers must bind
// the decoded card to a verified live Hub with ValidateClaimCard.
func DecodeOwnerAccountClaimCode(value string) (ClaimCard, error) {
	if len(value) <= len(OwnerAccountClaimCodePrefix) || len(value) > MaxOwnerAccountClaimCodeText ||
		!strings.HasPrefix(value, OwnerAccountClaimCodePrefix) || strings.ContainsAny(value, " \t\r\n?#") ||
		strings.Contains(value, "://") {
		return ClaimCard{}, ErrInvalid
	}
	encoded := strings.TrimPrefix(value, OwnerAccountClaimCodePrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		clear(raw)
		return ClaimCard{}, ErrInvalid
	}
	defer clear(raw)
	return DecodeClaimCard(raw)
}
