package hubaccountwire

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func marshalPacket(packet Packet) ([]byte, error) {
	if packet.Format != PacketFormat || packet.Version != PacketVersion ||
		e2ee.ValidatePublicIdentity(packet.SenderPublicIdentity) != nil || validateRouteHeader(packet.Packet.Route, packet.SenderPublicIdentity) != nil {
		return nil, ErrInvalid
	}
	inner, err := json.Marshal(packet.Packet)
	if err != nil || len(inner) > MaxInnerPacketBytes {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(packet)
	if err != nil || len(data) > MaxPacketBytes {
		return nil, ErrInvalid
	}
	return data, nil
}

func decodeCanonical(data []byte, max int, out any) error {
	if len(data) == 0 || len(data) > max || out == nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return ErrInvalid
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrInvalid
	}
	return nil
}

func dereference(value any) any {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil
	}
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if !rv.CanInterface() {
		return nil
	}
	return rv.Interface()
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func validDeviceID(value string) bool {
	return validID(value) && len(value) == len(AccountDeviceIDPrefix)+2*RequestIDBytes &&
		strings.HasPrefix(value, AccountDeviceIDPrefix) && isHex(strings.TrimPrefix(value, AccountDeviceIDPrefix), RequestIDBytes)
}

func validUsername(value string) bool {
	if value == "" || len(value) > MaxUsernameBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validPassword(value string) bool {
	return value != "" && len(value) <= MaxPasswordBytes && utf8.ValidString(value)
}

func isHex(value string, bytes int) bool {
	if len(value) != bytes*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes
}

func randomBytes(count int) ([]byte, error) {
	if count <= 0 || count > 1024 {
		return nil, ErrInvalid
	}
	value := make([]byte, count)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func randomHex(count int) (string, error) {
	value, err := randomBytes(count)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func decodeCode(value string) ([]byte, error) {
	decoded, err := decodeRawURLBase64(value)
	if err != nil || len(decoded) != CodeBytes {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func decodeRawURLBase64(value string) ([]byte, error) {
	// Implement via the standard decoder while enforcing a canonical unpadded form.
	decoded, err := rawURL.DecodeString(value)
	if err != nil || rawURL.EncodeToString(decoded) != value {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func formatUTC(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseCanonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed.UTC(), nil
}

func validateCanonicalTime(value string) error {
	_, err := parseCanonicalUTC(value)
	return err
}

func validateRecent(value string, now time.Time, maxAge time.Duration) error {
	if now.IsZero() {
		return validateCanonicalTime(value)
	}
	issued, err := parseCanonicalUTC(value)
	if err != nil || issued.After(now.Add(30*time.Second)) || now.Sub(issued) > maxAge {
		return ErrInvalid
	}
	return nil
}

func validateTimeWindow(issuedText, expiresText string, max time.Duration) error {
	issued, err := parseCanonicalUTC(issuedText)
	if err != nil {
		return ErrInvalid
	}
	expires, err := parseCanonicalUTC(expiresText)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > max {
		return ErrInvalid
	}
	return nil
}

func validateTimeWindowNow(issuedText, expiresText string, max time.Duration, now time.Time) error {
	if err := validateTimeWindow(issuedText, expiresText, max); err != nil {
		return err
	}
	issued, _ := parseCanonicalUTC(issuedText)
	expires, _ := parseCanonicalUTC(expiresText)
	if now.IsZero() {
		return nil
	}
	if issued.After(now.Add(30*time.Second)) || !now.Before(expires) {
		return ErrInvalid
	}
	return nil
}

func decodeBody[T any](plaintext []byte, max int) (T, error) {
	var value T
	err := decodeCanonical(plaintext, max, &value)
	return value, err
}

func requireOperation(route clientwire.Route, operation string) error {
	if route.Direction != clientwire.DirectionRequest || route.Operation != operation || route.Sequence != PacketSequence ||
		!isHex(route.OperationID, RequestIDBytes) || route.SessionEpoch == 0 {
		return fmt.Errorf("%w: route scope", ErrInvalid)
	}
	return nil
}
