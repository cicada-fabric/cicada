package hubauth

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"unicode/utf8"
)

const PasswordAlgorithm = "PBKDF2-SHA256-600000-v1"
const PasswordIterations = 600000
const PasswordSaltSize = 32
const PasswordVerifierSize = 32

var ErrAuthentication = errors.New("Hub account authentication rejected")

// This small versioned blocklist is maintained with the account contract. It
// supplements device PQC on every login; it imposes no composition rule.
var commonPasswords = map[string]bool{
	"1234567890": true, "12345678901": true, "123456789012": true,
	"password123": true, "password1234": true, "password12345": true,
	"qwertyuiop": true, "qwerty12345": true, "iloveyou123": true,
	"administrator": true, "letmein1234": true, "cicada12345": true,
}

func ValidatePassword(username, label, password string) error {
	if !utf8.ValidString(password) || len(password) > 1024 || utf8.RuneCountInString(password) < 10 {
		return ErrAuthentication
	}
	folded := strings.ToLower(strings.TrimSpace(password))
	if commonPasswords[folded] {
		return ErrAuthentication
	}
	for _, context := range []string{username, label, "cicada"} {
		context = strings.ToLower(strings.TrimSpace(context))
		if context == "" {
			continue
		}
		for _, suffix := range []string{"", "123", "1234", "12345", "2026", "2025"} {
			if folded == context+suffix {
				return ErrAuthentication
			}
		}
	}
	return nil
}

func DerivePassword(password string, salt []byte) ([]byte, error) {
	if len(salt) != PasswordSaltSize || !utf8.ValidString(password) || len(password) > 1024 {
		return nil, ErrAuthentication
	}
	// Purpose separation from browser vault keys, with a server-generated salt.
	purposeSalt := append([]byte("cicada/hub-account/password/v1\x00"), salt...)
	defer clear(purposeSalt)
	return pbkdf2.Key(sha256.New, password, purposeSalt, PasswordIterations, PasswordVerifierSize)
}
func CheckPassword(password string, salt, expected []byte) bool {
	if len(expected) != PasswordVerifierSize {
		return false
	}
	actual, err := DerivePassword(password, salt)
	if err != nil {
		return false
	}
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
