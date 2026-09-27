package nodekeys

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

func TestCryptoStateSequenceSurvivesRestartAndScopesByEndpointKey(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := state.ReserveOutboundSequence(ctx, "ep_alpha", "pq-key-a")
	if err != nil || first != 1 {
		t.Fatalf("first sequence = %d, err = %v", first, err)
	}
	second, err := state.ReserveOutboundSequence(ctx, "ep_alpha", "pq-key-a")
	if err != nil || second != 2 {
		t.Fatalf("second sequence = %d, err = %v", second, err)
	}
	otherKey, err := state.ReserveOutboundSequence(ctx, "ep_alpha", "pq-key-b")
	if err != nil || otherKey != 1 {
		t.Fatalf("other key sequence = %d, err = %v", otherKey, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	third, err := state.ReserveOutboundSequence(ctx, "ep_alpha", "pq-key-a")
	if err != nil || third != 3 {
		t.Fatalf("sequence after restart = %d, err = %v", third, err)
	}
	otherEndpoint, err := state.ReserveOutboundSequence(ctx, "ep_beta", "pq-key-a")
	if err != nil || otherEndpoint != 1 {
		t.Fatalf("other endpoint sequence = %d, err = %v", otherEndpoint, err)
	}

	dirInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %04o, want 0700", dirInfo.Mode().Perm())
	}
	dbInfo, err := os.Stat(filepath.Join(stateDir, cryptoStateDBName))
	if err != nil {
		t.Fatal(err)
	}
	if dbInfo.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %04o, want 0600", dbInfo.Mode().Perm())
	}
}

func TestCryptoStateOutboundEnvelopeIsImmutableAndIdempotent(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ctx := context.Background()
	wire := []byte(`{"ciphertext":"opaque"}`)
	record, created, err := state.StoreOutbound(ctx, "op_123", "ep_sender", "pq-key-a", wire)
	if err != nil || !created {
		t.Fatalf("store outbound: created=%v err=%v", created, err)
	}
	if record.Digest == "" || !bytes.Equal(record.Envelope, wire) {
		t.Fatalf("stored record does not preserve exact envelope: %+v", record)
	}
	wire[0] = 'x'

	retried, created, err := state.StoreOutbound(ctx, "op_123", "ep_sender", "pq-key-a", []byte(`{"ciphertext":"opaque"}`))
	if err != nil || created || !bytes.Equal(retried.Envelope, []byte(`{"ciphertext":"opaque"}`)) {
		t.Fatalf("idempotent retry: created=%v envelope=%q err=%v", created, retried.Envelope, err)
	}
	loaded, err := state.GetOutbound(ctx, "op_123", "pq-key-a")
	if err != nil || loaded.Digest != record.Digest || !bytes.Equal(loaded.Envelope, record.Envelope) {
		t.Fatalf("load outbound: record=%+v err=%v", loaded, err)
	}
	if _, _, err := state.StoreOutbound(ctx, "op_123", "ep_sender", "pq-key-a", []byte(`different ciphertext`)); !errors.Is(err, ErrOutboundConflict) {
		t.Fatalf("conflicting operation retry error = %v", err)
	}
	if _, _, err := state.StoreOutbound(ctx, "op_123", "ep_other", "pq-key-a", []byte(`{"ciphertext":"opaque"}`)); !errors.Is(err, ErrOutboundConflict) {
		t.Fatalf("reused operation/key under another endpoint error = %v", err)
	}
	if _, err := state.GetOutbound(ctx, "missing", "pq-key-a"); !errors.Is(err, ErrCryptoStateNotFound) {
		t.Fatalf("missing envelope error = %v", err)
	}
}

func TestCryptoStateInboundReplayDedupeIsScopedAndDurable(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	wire := []byte("opaque ciphertext 1")
	duplicate, err := state.AcceptInbound(ctx, "ep_receiver", "pq-pinned-a", "msg_1", 10, wire)
	if err != nil || duplicate {
		t.Fatalf("first inbound: duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = state.AcceptInbound(ctx, "ep_receiver", "pq-pinned-a", "msg_1", 10, wire)
	if err != nil || !duplicate {
		t.Fatalf("same ciphertext retry: duplicate=%v err=%v", duplicate, err)
	}
	if _, err := state.AcceptInbound(ctx, "ep_receiver", "pq-pinned-a", "msg_1", 10, []byte("different ciphertext")); !errors.Is(err, ErrInboundReplayConflict) {
		t.Fatalf("same message ID with different digest error = %v", err)
	}
	if _, err := state.AcceptInbound(ctx, "ep_receiver", "pq-pinned-a", "msg_2", 10, []byte("opaque ciphertext 2")); !errors.Is(err, ErrInboundReplayConflict) {
		t.Fatalf("same sequence with another message error = %v", err)
	}
	if duplicate, err := state.AcceptInbound(ctx, "ep_receiver_2", "pq-pinned-a", "msg_2", 10, []byte("opaque ciphertext 2")); err != nil || duplicate {
		t.Fatalf("other receiver scope: duplicate=%v err=%v", duplicate, err)
	}
	if duplicate, err := state.AcceptInbound(ctx, "ep_receiver", "pq-pinned-b", "msg_2", 10, []byte("opaque ciphertext 2")); err != nil || duplicate {
		t.Fatalf("other pinned sender scope: duplicate=%v err=%v", duplicate, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	duplicate, err = state.AcceptInbound(ctx, "ep_receiver", "pq-pinned-a", "msg_1", 10, wire)
	if err != nil || !duplicate {
		t.Fatalf("same ciphertext after restart: duplicate=%v err=%v", duplicate, err)
	}
	stored, err := state.GetInbound(ctx, "ep_receiver", "pq-pinned-a", "msg_1")
	if err != nil || stored.Sequence != 10 || !bytes.Equal(stored.Envelope, wire) {
		t.Fatalf("inbound ciphertext not recovered after restart: record=%+v err=%v", stored, err)
	}
	if _, err := state.GetInbound(ctx, "ep_receiver", "pq-pinned-a", "missing"); !errors.Is(err, ErrCryptoStateNotFound) {
		t.Fatalf("missing inbound ciphertext error = %v", err)
	}
}

func TestCryptoStateInboundCiphertextAndReplayCommitAtomically(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ctx := context.Background()
	if _, err := state.db.Exec(`CREATE TRIGGER fail_inbound_ciphertext BEFORE INSERT ON node_crypto_inbox
BEGIN SELECT RAISE(ABORT, 'inbox storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AcceptInbound(ctx, "ep_receiver", "sender_key", "msg_atomic", 1, []byte("opaque ciphertext")); err == nil {
		t.Fatal("inbox failure was accepted")
	}
	var replayRows int
	if err := state.db.QueryRow(`SELECT count(*) FROM node_crypto_replay WHERE message_id = 'msg_atomic'`).Scan(&replayRows); err != nil || replayRows != 0 {
		t.Fatalf("failed inbox left replay tombstone: count=%d err=%v", replayRows, err)
	}
	if _, err := state.db.Exec(`DROP TRIGGER fail_inbound_ciphertext`); err != nil {
		t.Fatal(err)
	}
	duplicate, err := state.AcceptInbound(ctx, "ep_receiver", "sender_key", "msg_atomic", 1, []byte("opaque ciphertext"))
	if err != nil || duplicate {
		t.Fatalf("retry after rollback: duplicate=%v err=%v", duplicate, err)
	}
}

func TestCryptoStateConcurrentHandlesReserveUniqueSequences(t *testing.T) {
	stateDir := t.TempDir()
	const handlesCount = 3
	handles := make([]*CryptoState, 0, handlesCount)
	for i := 0; i < handlesCount; i++ {
		state, err := OpenCryptoState(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, state)
	}
	defer func() {
		for _, state := range handles {
			_ = state.Close()
		}
	}()

	const workers = 12
	const perWorker = 20
	sequences := make(chan uint64, workers*perWorker)
	errs := make(chan error, workers*perWorker)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			state := handles[worker%len(handles)]
			for i := 0; i < perWorker; i++ {
				sequence, err := state.ReserveOutboundSequence(context.Background(), "ep_concurrent", "pq-key-concurrent")
				if err != nil {
					errs <- err
					return
				}
				sequences <- sequence
			}
		}()
	}
	wait.Wait()
	close(sequences)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent reservation failed: %v", err)
	}
	all := make([]uint64, 0, workers*perWorker)
	for sequence := range sequences {
		all = append(all, sequence)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	if len(all) != workers*perWorker {
		t.Fatalf("reserved %d sequences, want %d", len(all), workers*perWorker)
	}
	for i, sequence := range all {
		want := uint64(i + 1)
		if sequence != want {
			t.Fatalf("sorted sequence[%d] = %d, want %d", i, sequence, want)
		}
	}
}

func TestCryptoStateConcurrentOutboundRetryStoresOneRecord(t *testing.T) {
	stateDir := t.TempDir()
	states := make([]*CryptoState, 2)
	for i := range states {
		state, err := OpenCryptoState(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		states[i] = state
	}
	defer states[0].Close()
	defer states[1].Close()

	const attempts = 16
	createdCount := 0
	var resultMu sync.Mutex
	var wait sync.WaitGroup
	errCh := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			state := states[i%len(states)]
			_, created, err := state.StoreOutbound(context.Background(), "op_shared", "ep_sender", "pq-key-a", []byte("one immutable envelope"))
			if err != nil {
				errCh <- err
				return
			}
			if created {
				resultMu.Lock()
				createdCount++
				resultMu.Unlock()
			}
		}(i)
	}
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent outbox retry failed: %v", err)
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly one", createdCount)
	}
	record, err := states[0].GetOutbound(context.Background(), "op_shared", "pq-key-a")
	if err != nil || !bytes.Equal(record.Envelope, []byte("one immutable envelope")) {
		t.Fatalf("shared outbox record = %q, err = %v", record.Envelope, err)
	}
}
