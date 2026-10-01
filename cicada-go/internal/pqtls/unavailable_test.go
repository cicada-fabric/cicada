//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

import (
	"errors"
	"testing"
)

func TestUnavailableFailsClosed(t *testing.T) {
	for _, err := range []error{Available(), func() error { _, e := NewClient(Config{}); return e }(), func() error { _, e := Listen("tcp", "127.0.0.1:0", Config{}); return e }()} {
		var typed *Error
		if !errors.Is(err, ErrUnavailable) || !errors.As(err, &typed) {
			t.Fatalf("expected typed unavailable, got %v", err)
		}
	}
}
