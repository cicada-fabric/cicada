package appcore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

const (
	connectionCardFormat  = "cicada.hub-connection.v1"
	connectionCardPurpose = "EXISTING_OWNER_ACCOUNT_CONTINUATION"
	connectionCardPrefix  = "cicada-hub-connection-v1:"
	maxConnectionLifetime = 30 * 24 * time.Hour
	maxConnectionText     = 24 * 1024
)

var (
	ErrInvalidCard       = errors.New("invalid CICADA connection material")
	ErrActivationExpired = errors.New("activation code is expired or invalid")
)

// HubConnectionCard identifies a Hub and an existing account scope. It is
// public routing metadata and grants no authority. The identity fingerprint is
// over the full canonical Hub identity; it is not a shortened key ID.
type HubConnectionCard struct {
	Format            string `json:"format"`
	Version           int    `json:"version"`
	Purpose           string `json:"purpose"`
	Origin            string `json:"origin"`
	AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
	HubID             string `json:"hub_id"`
	HubFingerprint    string `json:"hub_fingerprint"`
	AccountID         string `json:"account_id"`
	OwnerID           string `json:"owner_id"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
}

// ActivationCode wraps the existing one-use Hub account ClaimCard. It is a
// secret-bearing local code, never a URL or a Manager/Root grant.
type ActivationCode struct {
	card wire.ClaimCard
}

func (ActivationCode) String() string   { return "ActivationCode([REDACTED])" }
func (ActivationCode) GoString() string { return "ActivationCode([REDACTED])" }
func (*ActivationCode) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "ActivationCode([REDACTED])")
}

func ParseActivationCode(text string) (ActivationCode, error) {
	card, err := wire.DecodeOwnerAccountClaimCode(text)
	if err != nil {
		return ActivationCode{}, ErrActivationExpired
	}
	return ActivationCode{card: card}, nil
}

func NewActivationCode(card wire.ClaimCard) (ActivationCode, error) {
	encoded, err := wire.EncodeOwnerAccountClaimCode(card)
	if err != nil {
		return ActivationCode{}, ErrInvalidCard
	}
	parsed, err := wire.DecodeOwnerAccountClaimCode(encoded)
	if err != nil {
		return ActivationCode{}, ErrInvalidCard
	}
	return ActivationCode{card: parsed}, nil
}

func (c ActivationCode) Encode() string {
	encoded, err := wire.EncodeOwnerAccountClaimCode(c.card)
	if err != nil {
		return ""
	}
	return encoded
}

func (c ActivationCode) Summary() wire.ClaimCardSummary {
	return wire.ClaimCardSummary{Origin: c.card.Origin, HubID: c.card.HubID,
		HubFingerprint: c.card.HubFingerprint, AccountID: c.card.AccountID,
		OwnerID: c.card.OwnerID, ExpiresAt: c.card.ExpiresAt}
}

func ParseHubConnectionCard(text string, now time.Time) (HubConnectionCard, error) {
	if len(text) <= len(connectionCardPrefix) || len(text) > maxConnectionText ||
		!strings.HasPrefix(text, connectionCardPrefix) || strings.ContainsAny(text, " \t\r\n?#") ||
		strings.Contains(text, "://") {
		return HubConnectionCard{}, ErrInvalidCard
	}
	payload := strings.TrimPrefix(text, connectionCardPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != payload {
		return HubConnectionCard{}, ErrInvalidCard
	}
	defer clear(raw)
	var card HubConnectionCard
	if decodeStrictCanonical(raw, &card) != nil || validateConnectionCard(card, now) != nil {
		return HubConnectionCard{}, ErrInvalidCard
	}
	return card, nil
}

func (c HubConnectionCard) Encode() (string, error) {
	if validateConnectionCard(c, time.Time{}) != nil {
		return "", ErrInvalidCard
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", ErrInvalidCard
	}
	defer clear(raw)
	return connectionCardPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validateConnectionCard(c HubConnectionCard, now time.Time) error {
	if c.Format != connectionCardFormat || c.Version != 1 || c.Purpose != connectionCardPurpose ||
		!validIdentifier(c.HubID) || !validIdentifier(c.AccountID) || !validIdentifier(c.OwnerID) ||
		!lowerHex(c.HubFingerprint, 32) {
		return ErrInvalidCard
	}
	origin, err := ownerbootstrap.CanonicalOrigin(c.Origin, c.AllowLoopbackHTTP)
	if err != nil || origin != c.Origin {
		return ErrInvalidCard
	}
	issued, err := time.Parse(time.RFC3339Nano, c.IssuedAt)
	if err != nil || issued.UTC().Format(time.RFC3339Nano) != c.IssuedAt {
		return ErrInvalidCard
	}
	expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != c.ExpiresAt || !expires.After(issued) || expires.Sub(issued) > maxConnectionLifetime {
		return ErrInvalidCard
	}
	if !now.IsZero() && (!now.Before(expires) || now.Before(issued.Add(-30*time.Second))) {
		return ErrInvalidCard
	}
	return nil
}

func decodeStrictCanonical(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalidCard
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidCard
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalidCard
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == '/' || r == '\\' || r == 0x7f {
			return false
		}
	}
	return true
}

func lowerHex(value string, bytes int) bool {
	if len(value) != bytes*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
