package hubnodes

import (
	"context"
	"errors"
	"testing"
)

func TestHubNodesAdmissionBusyPreservesBoundAndCancellation(t *testing.T) {
	s := &Service{workers: make(chan struct{}, 2)}
	first, err := s.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("capacity was confused with credential rejection", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.acquire(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled admission changed semantics", err)
	}
	first()
	again, err := s.acquire(context.Background())
	if err != nil {
		t.Fatal("temporary busy permanently blocked valid caller", err)
	}
	again()
	second()
	if len(s.workers) != 0 || cap(s.workers) != 2 {
		t.Fatal("admission capacity changed or leaked")
	}
}
