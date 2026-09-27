package fabric

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

func normalizeName(value string) string {
	value = strings.TrimSpace(value)
	var result strings.Builder
	lastDash := false
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '.' {
			result.WriteRune(character)
			lastDash = false
			continue
		}
		if !lastDash {
			result.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(strings.ToLower(result.String()), "-.")
}

func endpointDefaultName(workspace, harnessName, sessionID string) string {
	if workspace != "" {
		name := normalizeName(filepath.Base(strings.TrimSuffix(workspace, string(filepath.Separator))))
		if name != "" && name != "." {
			return name
		}
	}
	if name := normalizeName(harnessName); name != "" {
		return name
	}
	if len(sessionID) > 12 {
		sessionID = sessionID[:12]
	}
	if name := normalizeName(sessionID); name != "" {
		return name
	}
	return "endpoint"
}

func normalizeTags(tags []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || len(tag) > 64 {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
		if len(result) == 32 {
			break
		}
	}
	sort.Strings(result)
	return result
}

func sanitizeCapabilities(input map[string]any) (map[string]any, error) {
	if input == nil {
		return map[string]any{}, nil
	}
	if len(input) > 64 {
		return nil, errors.New("endpoint capabilities contain too many keys")
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 128 {
			return nil, errors.New("endpoint capability keys must be non-empty and at most 128 bytes")
		}
		if err := rejectSensitiveCapability(key, value, 0); err != nil {
			return nil, err
		}
		result[key] = value
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode endpoint capabilities: %w", err)
	}
	if len(encoded) > 32*1024 {
		return nil, errors.New("endpoint capabilities are limited to 32 KiB")
	}
	return result, nil
}

func rejectSensitiveCapability(key string, value any, depth int) error {
	if depth > 8 {
		return errors.New("endpoint capabilities are nested too deeply")
	}
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, forbidden := range []string{"token", "secret", "password", "credential", "private_key", "api_key"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("endpoint capability %q may expose a credential", key)
		}
	}
	switch nested := value.(type) {
	case map[string]any:
		for nestedKey, nestedValue := range nested {
			if err := rejectSensitiveCapability(nestedKey, nestedValue, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, nestedValue := range nested {
			if err := rejectSensitiveCapability(key, nestedValue, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
