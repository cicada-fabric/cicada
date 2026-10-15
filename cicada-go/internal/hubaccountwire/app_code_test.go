package hubaccountwire

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestOwnerAccountClaimCodeRoundTripAndStrictFraming(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	card := ClaimCard{Format: ClaimCardFormat, Version: 1, Purpose: PurposeInitialClaim,
		Origin: "https://hub.synthetic.invalid", HubID: "hub_synthetic", HubFingerprint: strings.Repeat("a", 64),
		AccountID: "account_synthetic", OwnerID: "human_synthetic", ClaimID: strings.Repeat("b", 32),
		Code:     base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	code, err := EncodeOwnerAccountClaimCode(card)
	if err != nil {
		t.Fatalf("EncodeOwnerAccountClaimCode: %v", err)
	}
	if !strings.HasPrefix(code, OwnerAccountClaimCodePrefix) || strings.Contains(code, "://") || strings.ContainsAny(code, "?# \r\n") {
		t.Fatal("encoded code has URL or whitespace framing")
	}
	decoded, err := DecodeOwnerAccountClaimCode(code)
	if err != nil || decoded != card {
		t.Fatalf("DecodeOwnerAccountClaimCode = (%+v, %v)", decoded, err)
	}
	for _, malformed := range []string{
		code + "=", code + "x", code + "?next=https://attacker.invalid", code + "\n",
		"https://hub.synthetic.invalid/" + code, strings.Replace(code, OwnerAccountClaimCodePrefix, "", 1),
	} {
		if _, err := DecodeOwnerAccountClaimCode(malformed); err == nil {
			t.Fatal("accepted malformed activation code framing")
		}
	}
}
