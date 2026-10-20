package appui

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestPublicFieldsKeepFullValuesWithoutCopyingOtherSnapshotData(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	s := accountDisplayFixture(now)
	s.Account.LocalOwnerKeyID = "pq1-" + strings.Repeat("a", 300)
	s.Account.OwnerPeerFingerprint = "sha256:" + strings.Repeat("b", 64)
	s.Account.Username = "SYNTHETIC_DO_NOT_COPY_USERNAME"
	s.Setup.ExpectedOwnerKeyID = "SYNTHETIC_DO_NOT_COPY_UNCONFIRMED_KEY"
	s.Node.Candidate = &appcore.NodeCandidateSnapshot{NodeID: "synthetic-node", NodeFingerprint: strings.Repeat("c", 64),
		HubControlFingerprint: strings.Repeat("d", 64), ReviewID: "SYNTHETIC_DO_NOT_COPY_REVIEW"}
	s.Pair.Slots[0].CandidateKeyID, s.Pair.Slots[0].TargetDigest = "pq1-"+strings.Repeat("e", 200), strings.Repeat("f", 64)
	account := AccountPublicFields(s, now)
	values := make(map[string]string)
	for _, field := range account {
		values[field.Key] = field.Value
	}
	if values["account.owner_key_id"] != s.Account.LocalOwnerKeyID || values["account.owner_peer_fingerprint"] != s.Account.OwnerPeerFingerprint ||
		values["account.device_id"] != s.Account.DeviceID || values["hub.origin"] != s.Hub.Origin {
		t.Fatal("public copy fields shortened or reformatted an original value")
	}
	all := append(account, NodePublicFields(s, now)...)
	all = append(all, PairPublicFields(s, now)...)
	all = append(all, PairSlotPublicFields(s, 0, true, now)...)
	for _, field := range all {
		if strings.Contains(field.Value, "SYNTHETIC_DO_NOT_COPY") || field.Value == "" {
			t.Fatal("copy projection included unrelated snapshot data")
		}
		for _, locale := range []Locale{English, Chinese} {
			if Text(locale, field.Key) == field.Key || Text(locale, field.Key) == "" {
				t.Fatalf("copy caption %q missing in %s", field.Key, locale)
			}
		}
	}
	fields := PairSlotPublicFields(s, 0, true, now)
	if fields[len(fields)-2].Value != s.Pair.Slots[0].CandidateKeyID || fields[len(fields)-1].Value != s.Pair.Slots[0].TargetDigest {
		t.Fatal("slot key or target copy did not retain the full reviewed value")
	}
	if len(PairSlotPublicFields(s, 0, false, now)) != 2 || PairSlotPublicFields(s, -1, true, now) != nil || PairSlotPublicFields(s, 2, true, now) != nil {
		t.Fatal("copy projection exposed review-only metadata or an invalid slot")
	}
	before := s
	_ = AccountPublicFields(s, now)
	_ = NodePublicFields(s, now)
	if !reflect.DeepEqual(before, s) {
		t.Fatal("copy projection changed core state")
	}
}

func TestPublicFieldsFollowCurrentAccountVisibility(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"signed-out", "unverified", "expired", "session-check", "recovery", "hidden-presentation"} {
		t.Run(mode, func(t *testing.T) {
			s := accountDisplayFixture(now)
			switch mode {
			case "signed-out":
				s.Account.State = appcore.AccountStateLoginRequired
			case "unverified":
				s.Hub.Verified = false
			case "expired":
				s.Account.SessionExpiresAt = now.Format(time.RFC3339Nano)
			case "session-check":
				s.Account.State = appcore.AccountStateSessionCheck
			case "recovery":
				s.AvailableActions = []appcore.ActionKind{appcore.ActionRecover}
			case "hidden-presentation":
				s.Account.State = appcore.AccountStateLoginRequired
				s = PresentScreen(s, now).Snapshot
			}
			if AccountPublicFields(s, now) != nil || NodePublicFields(s, now) != nil || PairPublicFields(s, now) != nil || PairSlotPublicFields(s, 0, true, now) != nil {
				t.Fatal("copy target remained available while its account data was hidden")
			}
		})
	}
}
