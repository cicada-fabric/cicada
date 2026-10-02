//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

import (
	"errors"
	"testing"
	"time"
)

func TestTLSCertificateUnavailableFailsClosed(t *testing.T) {
	issuer, profile, a := ImportTLSIssuer(nil, nil, nil, "node", time.Time{})
	leaf, b := issuer.IssueTLSLeaf(nil, TLSLeafParameters{}, time.Time{})
	inspected, c := InspectTLSLeaf(nil, nil, nil, TLSLeafParameters{}, time.Time{})
	for _, err := range []error{a, b, c} {
		var typed *Error
		if !errors.Is(err, ErrUnavailable) || !errors.As(err, &typed) {
			t.Fatal("certificate stub did not fail closed")
		}
	}
	if issuer.state != nil || profile.Role != "" || len(leaf.CertificatePEM) != 0 || len(inspected.CertificatePEM) != 0 {
		t.Fatal("unavailable issuer produced material")
	}
}
