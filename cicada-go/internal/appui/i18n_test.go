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
