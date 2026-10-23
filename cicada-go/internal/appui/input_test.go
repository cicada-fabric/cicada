package appui

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func TestActivationCodeInputLimitCoversRealWireCode(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	card := hubaccountwire.ClaimCard{
		Format:         hubaccountwire.ClaimCardFormat,
		Version:        1,
		Purpose:        hubaccountwire.PurposeInitialClaim,
		Origin:         "https://hub.example",
		HubID:          "hub_test",
		HubFingerprint: strings.Repeat("a", 64),
		AccountID:      "account_test",
		OwnerID:        "owner_test",
		ClaimID:        strings.Repeat("b", 32),
		Code:           base64.RawURLEncoding.EncodeToString(make([]byte, hubaccountwire.CodeBytes)),
		IssuedAt:       now.Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	code, err := hubaccountwire.EncodeOwnerAccountClaimCode(card)
	if err != nil {
		t.Fatalf("EncodeOwnerAccountClaimCode() error = %v", err)
	}
	if len(code) <= 512 {
		t.Fatalf("fixture code length = %d; expected a value longer than the former editor limit", len(code))
	}
	if len(code) > ActivationCodeInputLimit() {
		t.Fatalf("wire code length %d exceeds editor limit %d", len(code), ActivationCodeInputLimit())
	}
	if ActivationCodeInputLimit() < hubaccountwire.MaxAppClaimCodeBytes || ActivationCodeInputLimit() < hubtransport.MaxBootstrapText || ActivationCodeInputLimit() < 32*1024 {
		t.Fatalf("editor limit = %d, protocol limit = %d", ActivationCodeInputLimit(), hubaccountwire.MaxAppClaimCodeBytes)
	}
}
