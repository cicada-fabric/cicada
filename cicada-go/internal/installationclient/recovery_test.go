package installationclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestClientReconcileCommittedOriginalWithoutHistoricalClock(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.drop = wire.OperationInstallationStart
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	original := bytes.Clone(f.client.state.Pending.Original)
	candidate := f.client.state.Candidate
	f.mu.Lock()
	f.now = f.now.Add(20 * time.Minute)
	f.mu.Unlock()
	f.reopen(t)
	if err := f.client.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.client.state.Pending != nil || f.client.state.Recovery != nil || !bytes.Equal(f.client.state.Last.Original, original) || !reflect.DeepEqual(candidate, f.client.state.Candidate) {
		t.Fatal("reconciliation rewrote the old original, candidate or deadline")
	}
	if err := f.client.Prove(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("historical reconciliation revived a fresh expired challenge")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || bytes.Equal(f.requests[0], f.requests[1]) || len(f.replies) != 2 {
		t.Fatal("reconciliation did not use one distinct durable request")
	}
}

func TestClientReconcileUnadmittedMutationRetainsPermanentExactFence(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.errorStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	original := bytes.Clone(f.client.state.Pending.Original)
	f.mu.Lock()
	f.errorStatus = 0
	f.now = f.now.Add(20 * time.Minute)
	f.mu.Unlock()
	if err := f.client.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.client.state.Result == nil || f.client.state.Result.Outcome != wire.InstallationRejectedFenced || f.client.state.Pending != nil || f.client.state.Recovery != nil || !bytes.Equal(f.client.state.Last.Original, original) {
		t.Fatal("no-effect settlement did not retain the exact original and fence")
	}
	var result wire.InstallationResult
	admission, _ := f.client.admission.E2EE()
	if wire.OpenInstallationResponse(admission, f.hub, original, f.client.state.Last.Response, &result) != nil || result.RequestPacketDigest != e2ee.InstallationPacketDigest(original) {
		t.Fatal("stored fence is not an authentic receipt of the exact old original")
	}
}

func TestClientLostReconciliationResponseRestoresSameRecoveryPacket(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.errorStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	original := bytes.Clone(f.client.state.Pending.Original)
	f.mu.Lock()
	f.errorStatus, f.drop = 0, wire.OperationInstallationReconcile
	f.mu.Unlock()
	if err := f.client.Recover(context.Background()); !errors.Is(err, ErrUnknown) {
		t.Fatal("lost recovery response did not remain uncertain", err)
	}
	recovery := bytes.Clone(f.client.state.Recovery.Original)
	f.reopen(t)
	if err := f.client.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 3 || !bytes.Equal(f.requests[1], recovery) || !bytes.Equal(f.requests[2], recovery) || !bytes.Equal(f.client.state.Last.Original, original) || len(f.replies) != 2 {
		t.Fatal("restart changed the recovery nonce, target original or effect/fence receipt")
	}
}

func TestClientUnauthenticatedRecoveryCannotClearEitherOriginal(t *testing.T) {
	f := newClientFixture(t)
	f.mu.Lock()
	f.errorStatus = http.StatusGone
	f.mu.Unlock()
	if err := f.client.Start(context.Background(), f.draft()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	original := bytes.Clone(f.client.state.Pending.Original)
	if err := f.client.Recover(context.Background()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	recovery := bytes.Clone(f.client.state.Recovery.Original)
	f.reopen(t)
	if !bytes.Equal(f.client.state.Pending.Original, original) || !bytes.Equal(f.client.state.Recovery.Original, recovery) || f.client.state.Pending.Response != nil || f.client.state.Recovery.Response != nil {
		t.Fatal("HTTP 410 discarded an unsettled target or reconciliation original")
	}
}

func TestClientOnlyAuthenticatedReadExpiredDischargesPureRead(t *testing.T) {
	f := newClientFixture(t)
	if err := f.client.Start(context.Background(), f.draft()); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Prove(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.errorStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	if err := f.client.Poll(context.Background()); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.errorStatus = 0
	f.now = f.now.Add(3 * time.Minute)
	f.mu.Unlock()
	if err := f.client.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.client.state.Pending != nil || f.client.state.Recovery != nil || f.client.state.Possession == nil || f.client.state.Last.Operation != wire.OperationInstallationReconcile {
		t.Fatal("authenticated pure-read expiry changed a mutation or discarded proof state")
	}
	if err := f.client.Poll(context.Background()); err != nil {
		t.Fatal("new explicit read was blocked after authenticated read expiry", err)
	}
}
