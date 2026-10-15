package appui

import (
	"strings"
	"testing"
)

func TestOwnerFormatFeedbackIsExplicitAndHasNoExternalToolWorkaround(t *testing.T) {
	for _, locale := range []Locale{English, Chinese} {
		text := ErrorText(locale, "ENCRYPTED_OWNER_PEM_UNSUPPORTED")
		if text == "" || strings.Contains(text, "OpenSSL") || strings.Contains(text, "ENCRYPTED_OWNER_PEM_UNSUPPORTED") {
			t.Fatal("unsupported Owner input exposed technical error or external-tool workaround")
		}
	}
	if !strings.Contains(ErrorText(English, "ENCRYPTED_OWNER_PEM_UNSUPPORTED"), "not supported") {
		t.Fatal("unsupported format was not clearly disclosed")
	}
}
