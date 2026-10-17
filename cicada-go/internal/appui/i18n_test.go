package appui

import (
	"strings"
	"testing"
)

func TestCatalogParityAndFallback(t *testing.T) {
	if translationCount(English) == 0 || translationCount(English) != translationCount(Chinese) {
		t.Fatalf("catalog sizes differ: en=%d zh=%d", translationCount(English), translationCount(Chinese))
	}
	for id := range catalog[English] {
		if strings.TrimSpace(catalog[Chinese][id]) == "" {
			t.Fatalf("Chinese translation missing for %q", id)
		}
	}
	if got := NormalizeLocale("zh-CN"); got != Chinese {
		t.Fatalf("zh-CN normalized to %q", got)
	}
	if got := NormalizeLocale("zh-Hans"); got != Chinese {
		t.Fatalf("zh-Hans normalized to %q", got)
	}
	if got := NormalizeLocale("fr"); got != English {
		t.Fatalf("unknown locale normalized to %q", got)
	}
}

func TestCatalogDoesNotContainMarkupOrTemplateTokens(t *testing.T) {
	for locale, entries := range catalog {
		for id, value := range entries {
			if strings.ContainsAny(value, "<>") || strings.Contains(value, "{{") || strings.Contains(value, "}}") {
				t.Fatalf("catalog %s %q contains markup or an unreviewed template: %q", locale, id, value)
			}
		}
	}
}

func TestNodeExpiryCopyKeepsStatusReviewSeparateFromPairing(t *testing.T) {
	for _, tt := range []struct {
		locale           Locale
		codeWord, status string
	}{{English, "code", "status"}, {Chinese, "连接码", "状态"}} {
		t.Run(string(tt.locale), func(t *testing.T) {
			initial := Text(tt.locale, "node.initial_review_expired")
			status := Text(tt.locale, "node.status_review_expired")
			if !strings.Contains(initial, tt.codeWord) || strings.Contains(status, tt.codeWord) || !strings.Contains(status, tt.status) {
				t.Fatal("status-only expiry instructed the user to pair again or initial expiry lost its code guidance")
			}
			// A generic protocol error has no profile context. Its copy must
			// remain safe when shown above either kind of expired review.
			if strings.Contains(ErrorText(tt.locale, "APP_NODE_PROOF_EXPIRED"), tt.codeWord) {
				t.Fatal("generic proof-expiry error instructed status-only pairing")
			}
			if Text(tt.locale, "node.unbound_session_ended") == Text(tt.locale, "node.session_ended") {
				t.Fatal("unfinished connection inherited the confirmed Node's reauthorization instructions")
			}
		})
	}
}

func TestSavedNodeCopySeparatesStatusAccessFromPersistentConnection(t *testing.T) {
	for _, tt := range []struct {
		locale                                           Locale
		continueLabel, accessLabel, savedWord, staleWord string
	}{
		{English, "Continue viewing status", "Status access valid until", "saved connection", "status"},
		{Chinese, "继续查看状态", "状态访问有效至", "已保存连接", "状态记录"},
	} {
		t.Run(string(tt.locale), func(t *testing.T) {
			if Text(tt.locale, "node.reauthorize_status") != tt.continueLabel || Text(tt.locale, "node.access_until") != tt.accessLabel {
				t.Fatal("status access was presented as installing or expiring the saved Node")
			}
			if !strings.Contains(Text(tt.locale, "node.saved_connection_body"), tt.savedWord) ||
				!strings.Contains(Text(tt.locale, "node.stale"), tt.staleWord) {
				t.Fatal("copy lost the persistent connection or confused cached status with current Node failure")
			}
		})
	}
}
