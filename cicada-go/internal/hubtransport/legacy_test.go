package hubtransport_test

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

func TestLegacyConnectionCardAndNativeDescriptorAreDistinct(t *testing.T) {
	d := hubtransport.SyntheticDescriptorForTest(t)
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	card := appcore.HubConnectionCard{Format: "cicada.hub-connection.v1", Version: 1, Purpose: "EXISTING_OWNER_ACCOUNT_CONTINUATION",
		Origin: d.Claims.Origin, HubID: d.Claims.Hub.HubID, HubFingerprint: d.Claims.HubFingerprint,
		AccountID: "account_SYNTHETIC", OwnerID: "human_SYNTHETIC", IssuedAt: at.Format(time.RFC3339Nano), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339Nano)}
	oldText, err := card.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = appcore.ParseHubConnectionCard(oldText, at.Add(time.Minute)); err != nil {
		t.Fatal("existing card rejected")
	}
	if _, err = hubtransport.DecodeDescriptor(oldText); err == nil {
		t.Fatal("legacy account card accepted as TLS descriptor")
	}
	text, err := hubtransport.EncodeDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = appcore.ParseHubConnectionCard(text, at.Add(time.Minute)); err == nil {
		t.Fatal("TLS descriptor accepted as legacy account card")
	}
}
