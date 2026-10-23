package hubtransport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

func EncodeDescriptor(d Descriptor) (string, error) {
	if ValidateDescriptor(d, time.Time{}) != nil {
		return "", ErrInvalid
	}
	return encode(DescriptorPrefix, d, MaxDescriptorBytes)
}

func DecodeDescriptor(text string) (Descriptor, error) {
	var d Descriptor
	if decode(text, DescriptorPrefix, MaxDescriptorBytes, &d) != nil || ValidateDescriptor(d, time.Time{}) != nil {
		return Descriptor{}, ErrInvalid
	}
	return d, nil
}

func EncodeBootstrap(d Descriptor, activationCode string) (string, error) {
	b := Bootstrap{Format: BootstrapFormat, Version: Version, Descriptor: d, ActivationCode: activationCode}
	if _, err := ValidateBootstrap(b, time.Time{}); err != nil {
		return "", ErrInvalid
	}
	return encode(BootstrapPrefix, b, MaxBootstrapBytes)
}

func DecodeBootstrap(text string) (Bootstrap, error) {
	var b Bootstrap
	if decode(text, BootstrapPrefix, MaxBootstrapBytes, &b) != nil {
		return Bootstrap{}, ErrInvalid
	}
	if _, err := ValidateBootstrap(b, time.Time{}); err != nil {
		return Bootstrap{}, ErrInvalid
	}
	return b, nil
}

func encode(prefix string, v any, limit int) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > limit {
		return "", ErrInvalid
	}
	defer clear(raw)
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func decode(text, prefix string, limit int, v any) error {
	if len(text) <= len(prefix) || len(text) > len(prefix)+(limit*8+5)/6 || !strings.HasPrefix(text, prefix) || strings.ContainsAny(text, " \t\r\n?#") {
		return ErrInvalid
	}
	encoded := strings.TrimPrefix(text, prefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	defer clear(raw)
	if err != nil || len(raw) > limit || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(v)
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalid
	}
	return nil
}
