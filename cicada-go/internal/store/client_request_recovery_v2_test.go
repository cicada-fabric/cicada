package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func syntheticClientRequest(t *testing.T, s *Store, operationID string) AcceptClientRequestInput {
	t.Helper()
	device, err := s.GetClientDevice("owner_a", "phone_a")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic encrypted request: " + operationID))
	return AcceptClientRequestInput{
		OwnerID: "owner_a", DeviceID: "phone_a", SessionEpoch: device.SessionEpoch,
		Sequence: device.LastRequestSeq + 1, OperationID: operationID,
		CiphertextDigest: hex.EncodeToString(digest[:]),
	}
}

func TestClientRecoveryReservesOneResponseAcrossRestart(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	input := syntheticClientRequest(t, s, "recovery-reserve")
	if _, err := s.AcceptClientRequest(input); err != nil {
		t.Fatal(err)
	}
	first, err := s.ReserveClientRequestResponseSequence(input)
	if err != nil || first != 1 {
		t.Fatalf("first reservation=%d err=%v", first, err)
	}
	var path string
	var databaseSequence int
	var databaseName string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&databaseSequence, &databaseName, &path); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if count, err := restarted.MarkInterruptedClientRequestsUncertain(); err != nil || count != 1 {
		t.Fatalf("restart fence=%d err=%v", count, err)
	}
	recovery, err := restarted.LookupClientRequestRecovery(input)
	if err != nil || recovery.Request.Status != ClientRequestUncertain ||
		!recovery.Supported || recovery.ReservedResponseSequence != first {
		t.Fatalf("recovery lookup=%+v err=%v", recovery, err)
	}

	const parallel = 8
	sequences := make(chan uint64, parallel)
	errorsFound := make(chan error, parallel)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sequence, err := restarted.ReserveClientRequestResponseSequence(input)
			sequences <- sequence
			errorsFound <- err
		}()
	}
	wg.Wait()
	close(sequences)
	close(errorsFound)
	for sequence := range sequences {
		if sequence != first {
			t.Fatalf("parallel retry reserved sequence %d, want %d", sequence, first)
		}
	}
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	sealed := []byte(`{"synthetic":"sealed recovery response"}`)
	cached, err := restarted.CacheClientRequestRecoveryPacket(input, first, sealed)
	if err != nil || !bytes.Equal(cached, sealed) {
		t.Fatalf("cache uncertain response=%s err=%v", cached, err)
	}
	// A second concurrent sealing attempt must serve the first durable bytes.
	cached, err = restarted.CacheClientRequestRecoveryPacket(input, first, []byte("different envelope"))
	if err != nil || !bytes.Equal(cached, sealed) {
		t.Fatalf("recovery packet changed: packet=%s err=%v", cached, err)
	}
	again, err := restarted.LookupClientRequestRecovery(input)
	if err != nil || again.Request.Status != ClientRequestUncertain || !bytes.Equal(again.RecoveryPacket, sealed) {
		t.Fatalf("original outcome overwritten: recovery=%+v err=%v", again, err)
	}
	device, err := restarted.GetClientDevice(input.OwnerID, input.DeviceID)
	if err != nil || device.NextResponseSeq != 2 || device.LastRequestSeq != 1 {
		t.Fatalf("recovery changed counters: device=%+v err=%v", device, err)
	}
}

func TestClientRecoveryGuardsOldBindingWrongPacketAndLegacyRows(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	input := syntheticClientRequest(t, s, "recovery-guards")
	if _, err := s.AcceptClientRequest(input); err != nil {
		t.Fatal(err)
	}
	wrong := input
	wrong.CiphertextDigest = hex.EncodeToString(sha256.New().Sum(nil))
	if _, err := s.LookupClientRequestRecovery(wrong); !errors.Is(err, ErrClientRequestConflict) {
		t.Fatalf("wrong ciphertext accessed pending request: %v", err)
	}
	wrong = input
	wrong.OwnerID = "other-owner"
	if _, err := s.LookupClientRequestRecovery(wrong); err == nil {
		t.Fatal("cross-owner recovery was permitted")
	}
	wrong = input
	wrong.Sequence++
	if _, err := s.LookupClientRequestRecovery(wrong); !errors.Is(err, ErrClientRequestConflict) {
		t.Fatalf("wrong request sequence accessed pending request: %v", err)
	}
	if _, err := s.MarkInterruptedClientRequestsUncertain(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM client_device_request_recovery_v2 WHERE request_id IN
(SELECT id FROM client_device_requests_v2 WHERE operation_id=?)`, input.OperationID); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.LookupClientRequestRecovery(input)
	if err != nil || legacy.Supported || legacy.Request.Status != ClientRequestUncertain {
		t.Fatalf("old request was inferred as recoverable: recovery=%+v err=%v", legacy, err)
	}
	if _, err := s.ReserveClientRequestResponseSequence(input); !errors.Is(err, ErrClientRequestRecoveryUnavailable) {
		t.Fatalf("legacy response sequence was guessed: %v", err)
	}
	if _, err := s.RevokeClientDevice(input.OwnerID, input.DeviceID, device.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupClientRequestRecovery(input); !errors.Is(err, ErrClientDeviceRevoked) {
		t.Fatalf("revoked Client retained recovery authority: %v", err)
	}
}

func TestClientRecoveryReservesAfterCrashBeforeResponseAllocation(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	input := syntheticClientRequest(t, s, "crash-before-reserve")
	if _, err := s.AcceptClientRequest(input); err != nil {
		t.Fatal(err)
	}
	if count, err := s.MarkInterruptedClientRequestsUncertain(); err != nil || count != 1 {
		t.Fatalf("interrupted request fence=%d err=%v", count, err)
	}
	first, err := s.ReserveClientRequestResponseSequence(input)
	if err != nil || first != 1 {
		t.Fatalf("recovery allocation=%d err=%v", first, err)
	}
	second, err := s.ReserveClientRequestResponseSequence(input)
	if err != nil || second != first {
		t.Fatalf("retry allocated another response sequence=%d err=%v", second, err)
	}
}

func TestClientRecoveryMigrationPreservesOldRequestsWithoutInventingMarkers(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	input := syntheticClientRequest(t, s, "pre-upgrade")
	if _, err := s.AcceptClientRequest(input); err != nil {
		t.Fatal(err)
	}
	var path string
	var databaseSequence int
	var databaseName string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&databaseSequence, &databaseName, &path); err != nil {
		t.Fatal(err)
	}
	// This isolated fixture reproduces a v28 database with the accepted v18
	// request row but without a v29 response reservation.
	if _, err := s.db.Exec(`DROP TABLE client_device_request_recovery_v2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations_v2 WHERE version=29`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := New(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if _, err := upgraded.MarkInterruptedClientRequestsUncertain(); err != nil {
		t.Fatal(err)
	}
	legacy, err := upgraded.LookupClientRequestRecovery(input)
	if err != nil || legacy.Request.ID == "" || legacy.Supported {
		t.Fatalf("migration lost or silently upgraded old request: recovery=%+v err=%v", legacy, err)
	}
	device, err := upgraded.GetClientDevice(input.OwnerID, input.DeviceID)
	if err != nil || device.LastRequestSeq != input.Sequence {
		t.Fatalf("migration changed replay counter: device=%+v err=%v", device, err)
	}
}
