package store

import (
	"errors"
	"testing"
	"time"
)

func TestSessionBindingLeaseChecksFractionalExpiryByInstant(t *testing.T) {
	fixture := newEndpointKeyCandidateFixture(t)
	current := fixture.binding
	// Keep the old deadline in this very second. A lexical comparison of
	// RFC3339 and RFC3339Nano would treat the fractional future as expired.
	for time.Now().UTC().Nanosecond() > 300_000_000 {
		time.Sleep(10 * time.Millisecond)
	}
	expiresAt := time.Now().UTC().Truncate(time.Second).Add(800 * time.Millisecond)
	if _, err := fixture.store.db.Exec(`UPDATE session_bindings SET lease_expires_at=?,
version=version+1 WHERE id=?`, expiresAt.Format(time.RFC3339Nano), current.ID); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if err := fixture.store.ValidateSessionBindingLease(current.ID, current.LeaseOwner,
		current.Epoch); err != nil {
		t.Fatalf("fractional future lease rejected: %v", err)
	}
	if _, err := fixture.store.AcquireSessionBindingLease(current.ID, "other-owner",
		current.Epoch, future); !errors.Is(err, ErrSessionBindingLeaseHeld) {
		t.Fatalf("fractional future lease was stolen: %v", err)
	}
	if _, err := fixture.store.RotateSessionBindingCredential(current.ID, current.Epoch,
		HashCredential([]byte("replacement")), "other-owner", future); !errors.Is(err, ErrSessionBindingLeaseHeld) {
		t.Fatalf("fractional future lease was rotated by another owner: %v", err)
	}
	renewed, err := fixture.store.RenewSessionBindingLease(current.ID, current.LeaseOwner,
		current.Epoch, future)
	if err != nil || renewed.Epoch != current.Epoch {
		t.Fatalf("same owner could not renew fractional future lease: %#v %v", renewed, err)
	}
	if _, err := fixture.store.AcquireSessionBindingLease(current.ID, "other-owner",
		renewed.Epoch, "not-a-date"); err == nil {
		t.Fatal("malformed replacement lease expiry accepted")
	}
	if _, err := fixture.store.RenewSessionBindingLease(current.ID, current.LeaseOwner,
		renewed.Epoch, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); !errors.Is(err, ErrSessionBindingLeaseExpired) {
		t.Fatalf("expired replacement lease was accepted: %v", err)
	}
}

func TestSessionBindingLeaseExpiryParsesOffsetsAndRejectsInvalid(t *testing.T) {
	at := time.Date(2026, 9, 28, 3, 0, 0, 500_000_000, time.UTC)
	if err := validFutureLeaseExpiry("2026-09-28T04:00:00.6+01:00", at); err != nil {
		t.Fatalf("future offset lease rejected: %v", err)
	}
	if err := validFutureLeaseExpiry("2026-09-28T04:00:00+01:00", at); !errors.Is(err, ErrSessionBindingLeaseExpired) {
		t.Fatalf("expired offset lease accepted: %v", err)
	}
	if _, err := parseSessionBindingLeaseExpiry("2026-09-28T03:00:00.notvalidZ"); err == nil {
		t.Fatal("invalid lease expiry parsed")
	}
}
