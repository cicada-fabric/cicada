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

func TestBusyProfileFeedbackUsesExistingWindowWithoutRekeyInstructions(t *testing.T) {
	for _, locale := range []Locale{English, Chinese} {
		message := ErrorText(locale, "APP_PROFILE_IN_USE")
		if message == ErrorText(locale, "APP_PROFILE_UNLOCK_FAILED") || !strings.Contains(message, "Cicada") {
			t.Fatal("busy profile was presented as a failed unlock rather than an existing window")
		}
		for _, forbidden := range []string{"APP_PROFILE_IN_USE", "vault", "device code", "OpenSSL", ".lock", "新密钥", "设备码"} {
			if strings.Contains(message, forbidden) {
				t.Fatal("busy-profile feedback exposed internals or suggested new setup")
			}
		}
	}
}
