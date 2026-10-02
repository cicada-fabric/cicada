//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

import (
	"errors"
	"testing"
)

func TestTLSCSRUnavailableFailsClosed(t *testing.T) {
	key, profile, generated := GenerateTLSCSR(TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"})
	inspected, inspection := InspectTLSCSR([]byte("synthetic unavailable input"), TLSCSRParameters{})
	for _, err := range []error{generated, inspection} {
		var typed *Error
		if !errors.Is(err, ErrUnavailable) || !errors.As(err, &typed) {
			t.Fatal("CSR stub did not return typed unavailable")
		}
	}
	if key.state != nil || len(profile.CSRPEM) != 0 || len(inspected.SPKIDER) != 0 {
		t.Fatal("CSR stub produced material")
	}
}
