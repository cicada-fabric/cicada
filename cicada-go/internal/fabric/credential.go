package fabric

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	sessionTokenPrefix = "cicada_session_"
	nodeTokenPrefix    = "cicada_node_"
)

// NewSessionCredential returns a bearer credential and the only form that may
// be persisted. The plaintext token is returned once by Join and stays in the
// MCP process that owns the verified native session.
func NewSessionCredential() (token, digest string, err error) {
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return "", "", err
	}
	token = sessionTokenPrefix + base64.RawURLEncoding.EncodeToString(random)
	return token, HashSessionCredential(token), nil
}

func HashSessionCredential(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ValidateSessionCredential(token, expectedDigest string) error {
	token = strings.TrimSpace(token)
	expectedDigest = strings.TrimSpace(expectedDigest)
	if !strings.HasPrefix(token, sessionTokenPrefix) || expectedDigest == "" {
		return ErrUnauthenticated
	}
	actual := HashSessionCredential(token)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedDigest)) != 1 {
		return ErrUnauthenticated
	}
	return nil
}

func SessionCredentialFromAuthorization(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "CicadaSession") ||
		!strings.HasPrefix(parts[1], sessionTokenPrefix) {
		return "", errors.New("expected Authorization: CicadaSession <session-token>")
	}
	return parts[1], nil
}

func NewNodeCredential() (token, digest string, err error) {
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return "", "", err
	}
	token = nodeTokenPrefix + base64.RawURLEncoding.EncodeToString(random)
	return token, HashSessionCredential(token), nil
}

func NodeCredentialFromAuthorization(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "CicadaNode") ||
		!strings.HasPrefix(parts[1], nodeTokenPrefix) {
		return "", errors.New("expected Authorization: CicadaNode <node-token>")
	}
	return parts[1], nil
}
