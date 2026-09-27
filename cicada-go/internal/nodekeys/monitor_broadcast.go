package nodekeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

var (
	ErrUserMonitorBroadcastTrust  = errors.New("Client-to-Monitor broadcast lacks Node-local Owner trust")
	ErrUserMonitorBroadcastExpiry = errors.New("Client-to-Monitor broadcast has expired")
)

// OpenedUserMonitorBroadcast contains the exact decrypted UTF-8 body bytes.
// Duplicate means the same ciphertext was already saved in the Node crypto
// inbox; it does not mean that a native session consumed or acted on the body.
type OpenedUserMonitorBroadcast struct {
	Plaintext []byte
	Sequence  uint64
	Duplicate bool
}

// PreviewedUserMonitorBroadcast is verified plaintext for the original
// Monitor Endpoint. Preview never reserves a dispatch or records replay.
type PreviewedUserMonitorBroadcast struct {
	Plaintext []byte
	Sequence  uint64
}

// PreviewUserMonitorBroadcast verifies the same Owner trust, enrollment and
// signed Client envelope as OpenUserMonitorBroadcast without writing the
// inbound replay ledger. Current Hub and Session authorization must be checked
// independently before this local-only decryption.
func (s *CryptoState) PreviewUserMonitorBroadcast(ctx context.Context, monitor *e2ee.Identity,
	expected e2ee.MonitorBroadcastContext, clientPublic e2ee.PublicIdentity,
	ownerKeyID string, ownerDeviceGrant []byte, enrolledAt time.Time,
	envelope []byte) (PreviewedUserMonitorBroadcast, error) {
	plaintext, sequence, trust, err := s.verifyUserMonitorBroadcast(ctx, monitor, expected,
		clientPublic, ownerKeyID, ownerDeviceGrant, enrolledAt, envelope)
	if err != nil {
		return PreviewedUserMonitorBroadcast{}, err
	}
	if err := s.currentMonitorOwnerTrust(expected.OwnerID, ownerKeyID, trust); err != nil {
		return PreviewedUserMonitorBroadcast{}, err
	}
	return PreviewedUserMonitorBroadcast{Plaintext: plaintext, Sequence: sequence}, nil
}

// OpenUserMonitorBroadcast verifies historical device enrollment against this
// Node's independently installed Owner key, then opens an exact Guard-derived
// Client-to-Monitor envelope. The caller must derive expected, clientPublic,
// ownerKeyID, ownerDeviceGrant and enrolledAt from a fresh authenticated Hub
// delivery, and must separately enforce current device, Group, Monitor role,
// approval and SessionBinding authorization before native delivery.
//
// A device enrollment grant is checked at its original enrollment time; its
// later expiry does not undo a valid enrollment. The broadcast's own expiry
// must still be future. The exact authenticated ciphertext is durably saved
// with a separate replay namespace before plaintext is returned.
func (s *CryptoState) OpenUserMonitorBroadcast(ctx context.Context, monitor *e2ee.Identity,
	expected e2ee.MonitorBroadcastContext, clientPublic e2ee.PublicIdentity,
	ownerKeyID string, ownerDeviceGrant []byte, enrolledAt time.Time,
	envelope []byte) (OpenedUserMonitorBroadcast, error) {
	plaintext, sequence, trust, err := s.verifyUserMonitorBroadcast(ctx, monitor, expected,
		clientPublic, ownerKeyID, ownerDeviceGrant, enrolledAt, envelope)
	if err != nil {
		return OpenedUserMonitorBroadcast{}, err
	}
	receiverReplayID := monitorBroadcastReplayID("receiver", expected.MonitorEndpointID, expected.MonitorKeyID)
	messageReplayID := monitorBroadcastReplayID("message", expected.ApprovalID, expected.BroadcastID)
	duplicate, err := s.AcceptInbound(ctx, receiverReplayID, clientPublic.ID, messageReplayID, sequence, envelope)
	if err != nil {
		return OpenedUserMonitorBroadcast{}, err
	}
	// A local revocation racing with ciphertext persistence must not release
	// plaintext. Persisted ciphertext alone grants no native delivery rights.
	if err := s.currentMonitorOwnerTrust(expected.OwnerID, ownerKeyID, trust); err != nil {
		return OpenedUserMonitorBroadcast{}, err
	}
	return OpenedUserMonitorBroadcast{Plaintext: plaintext, Sequence: sequence, Duplicate: duplicate}, nil
}

func (s *CryptoState) verifyUserMonitorBroadcast(ctx context.Context, monitor *e2ee.Identity,
	expected e2ee.MonitorBroadcastContext, clientPublic e2ee.PublicIdentity,
	ownerKeyID string, ownerDeviceGrant []byte, enrolledAt time.Time,
	envelope []byte) ([]byte, uint64, OwnerKeyTrust, error) {
	if ctx == nil || monitor == nil || s == nil || enrolledAt.IsZero() {
		return nil, 0, OwnerKeyTrust{}, ErrUserMonitorBroadcastTrust
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, OwnerKeyTrust{}, err
	}
	now := time.Now().UTC()
	if enrolledAt.After(now) {
		return nil, 0, OwnerKeyTrust{}, ErrUserMonitorBroadcastTrust
	}
	expires, err := time.Parse(time.RFC3339Nano, expected.ExpiresAt)
	if err != nil || !expires.After(now) {
		return nil, 0, OwnerKeyTrust{}, ErrUserMonitorBroadcastExpiry
	}
	if expected.MonitorKeyID != monitor.Public().ID || ownerKeyID == "" {
		return nil, 0, OwnerKeyTrust{}, ErrUserMonitorBroadcastTrust
	}
	trust, err := s.GetNodeOwnerKeyTrustLocal(expected.OwnerID, ownerKeyID)
	if err != nil {
		return nil, 0, OwnerKeyTrust{}, fmt.Errorf("load Node-local Owner trust: %w", err)
	}
	if trust.State != NodeOwnerKeyTrustActive || trust.KeyID != ownerKeyID ||
		trust.OwnerID != expected.OwnerID || trust.PublicIdentity.ID != ownerKeyID {
		return nil, 0, OwnerKeyTrust{}, ErrUserMonitorBroadcastTrust
	}
	if _, err := e2ee.VerifyOwnerDeviceGrantAtRecordedEnrollment(ownerDeviceGrant, trust.PublicIdentity, clientPublic,
		expected.OwnerID, ownerKeyID, expected.ClientDeviceID, expected.HubID,
		e2ee.OwnerDevicePurposeControl, enrolledAt); err != nil {
		return nil, 0, OwnerKeyTrust{}, fmt.Errorf("verify Owner-approved Client enrollment: %w", err)
	}
	plaintext, sequence, err := e2ee.OpenMonitorBroadcast(monitor, clientPublic, expected, envelope)
	if err != nil {
		return nil, 0, OwnerKeyTrust{}, err
	}
	return plaintext, sequence, *trust, nil
}

func (s *CryptoState) currentMonitorOwnerTrust(ownerID, ownerKeyID string, trust OwnerKeyTrust) error {
	currentTrust, err := s.GetNodeOwnerKeyTrustLocal(ownerID, ownerKeyID)
	if err != nil || currentTrust.State != NodeOwnerKeyTrustActive || !compareOwnerKeyTrust(trust, *currentTrust) {
		return ErrUserMonitorBroadcastTrust
	}
	return nil
}

func monitorBroadcastReplayID(domain, first, second string) string {
	sum := sha256.Sum256([]byte("cicada/node/monitor-broadcast-replay/v1\x00" + domain + "\x00" + first + "\x00" + second))
	return "umb_" + hex.EncodeToString(sum[:])
}
