package e2ee

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// DirectoryAnnouncement is a signed public rendezvous record. It carries no
// private key, token, or message plaintext and does not imply trust.
type DirectoryAnnouncement struct {
	Version   int            `json:"version"`
	Identity  PublicIdentity `json:"identity"`
	Label     string         `json:"label"`
	Endpoints []string       `json:"endpoints"`
	ExpiresAt string         `json:"expires_at"`
	Signature []byte         `json:"signature"`
}

func (identity *Identity) SignDirectoryAnnouncement(label string, endpoints []string, expiresAt time.Time) ([]byte, error) {
	if identity == nil || identity.signingPrivate == nil {
		return nil, errors.New("nil E2EE identity")
	}
	announcement, err := makeDirectoryAnnouncement(identity.Public(), label, endpoints, expiresAt)
	if err != nil {
		return nil, err
	}
	unsigned, err := json.Marshal(announcement)
	if err != nil {
		return nil, err
	}
	announcement.Signature = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(identity.signingPrivate, unsigned, nil, true, announcement.Signature); err != nil {
		return nil, fmt.Errorf("sign directory announcement: %w", err)
	}
	return json.Marshal(announcement)
}

func VerifyDirectoryAnnouncement(data []byte) (PublicIdentity, string, []string, time.Time, error) {
	var announcement DirectoryAnnouncement
	if err := json.Unmarshal(data, &announcement); err != nil {
		return PublicIdentity{}, "", nil, time.Time{}, fmt.Errorf("decode directory announcement: %w", err)
	}
	if announcement.Version != ProtocolVersion || len(announcement.Signature) != mldsa65.SignatureSize {
		return PublicIdentity{}, "", nil, time.Time{}, ErrInvalidEnvelope
	}
	valid, err := makeDirectoryAnnouncement(announcement.Identity, announcement.Label, announcement.Endpoints, parseExpiry(announcement.ExpiresAt))
	if err != nil {
		return PublicIdentity{}, "", nil, time.Time{}, err
	}
	valid.ExpiresAt = announcement.ExpiresAt
	if err := ValidatePublicIdentity(announcement.Identity); err != nil {
		return PublicIdentity{}, "", nil, time.Time{}, err
	}
	_, signingPublic, err := validatePublic(announcement.Identity)
	if err != nil {
		return PublicIdentity{}, "", nil, time.Time{}, err
	}
	signature := announcement.Signature
	announcement.Signature = nil
	unsigned, err := json.Marshal(announcement)
	if err != nil || !mldsa65.Verify(signingPublic, unsigned, nil, signature) {
		return PublicIdentity{}, "", nil, time.Time{}, errors.New("directory announcement signature verification failed")
	}
	expires, err := time.Parse(time.RFC3339, announcement.ExpiresAt)
	if err != nil || !expires.After(time.Now().UTC()) {
		return PublicIdentity{}, "", nil, time.Time{}, errors.New("directory announcement has expired")
	}
	return announcement.Identity, announcement.Label, append([]string(nil), announcement.Endpoints...), expires, nil
}

func makeDirectoryAnnouncement(identity PublicIdentity, label string, endpoints []string, expiresAt time.Time) (DirectoryAnnouncement, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 200 {
		return DirectoryAnnouncement{}, errors.New("directory label must be 1-200 characters")
	}
	if err := ValidatePublicIdentity(identity); err != nil {
		return DirectoryAnnouncement{}, err
	}
	if len(endpoints) == 0 || len(endpoints) > 8 {
		return DirectoryAnnouncement{}, errors.New("directory requires 1-8 endpoints")
	}
	clean := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return DirectoryAnnouncement{}, errors.New("directory endpoints must be credential-free HTTPS URLs")
		}
		if len(endpoint) > 2048 {
			return DirectoryAnnouncement{}, errors.New("directory endpoint is too long")
		}
		clean = append(clean, endpoint)
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now().UTC()) || expiresAt.Sub(time.Now().UTC()) > 30*24*time.Hour {
		return DirectoryAnnouncement{}, errors.New("directory expiry must be within 30 days")
	}
	return DirectoryAnnouncement{Version: ProtocolVersion, Identity: identity, Label: label, Endpoints: clean, ExpiresAt: expiresAt.UTC().Format(time.RFC3339)}, nil
}

func parseExpiry(value string) time.Time {
	expires, _ := time.Parse(time.RFC3339, value)
	return expires
}
