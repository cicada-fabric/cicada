package fabric

import "testing"

func TestCapabilitiesRejectCredentials(t *testing.T) {
	for _, capabilities := range []map[string]any{
		{"api_token": "value"},
		{"runtime": map[string]any{"private_key": "value"}},
		{"headers": []any{map[string]any{"password": "value"}}},
	} {
		if _, err := sanitizeCapabilities(capabilities); err == nil {
			t.Fatalf("accepted credential-shaped capability: %#v", capabilities)
		}
	}
}

func TestNormalizeNameDoesNotLeakPathSyntax(t *testing.T) {
	if got := normalizeName(" Benchmark @ GPU 2:/srv/private "); got != "benchmark-gpu-2-srv-private" {
		t.Fatalf("normalizeName() = %q", got)
	}
}
