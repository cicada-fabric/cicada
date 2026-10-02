package pqtls

import (
	"testing"
	"time"
)

func TestCertificateValidity(t *testing.T) {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := State{VerifiedNotBefore: start, VerifiedNotAfter: start.Add(time.Minute)}
	for _, tc := range []struct {
		name  string
		state State
		now   time.Time
		want  bool
	}{
		{"before", s, start.Add(-time.Nanosecond), false},
		{"start", s, start, true},
		{"valid", s, start.Add(time.Second), true},
		{"expiry", s, s.VerifiedNotAfter, false},
		{"after", s, s.VerifiedNotAfter.Add(time.Nanosecond), false},
		{"missing", State{}, start, false},
		{"missing_start", State{VerifiedNotAfter: start.Add(time.Minute)}, start, false},
		{"missing_end", State{VerifiedNotBefore: start}, start, false},
		{"inverted", State{VerifiedNotBefore: start.Add(time.Minute), VerifiedNotAfter: start}, start, false},
		{"empty", State{VerifiedNotBefore: start, VerifiedNotAfter: start}, start, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.ValidAt(tc.now); got != tc.want {
				t.Fatalf("ValidAt=%v want %v", got, tc.want)
			}
		})
	}
}
