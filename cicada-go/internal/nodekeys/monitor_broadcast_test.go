package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type userMonitorCryptoFixture struct {
	state      *CryptoState
	stateDir   string
	owner      *e2ee.Identity
	client     *e2ee.Identity
	monitor    *e2ee.Identity
	context    e2ee.MonitorBroadcastContext
	grant      []byte
	enrolledAt time.Time
	body       []byte
	envelope   []byte
	ownerKeyID string
}

func newUserMonitorCryptoFixture(t *testing.T) userMonitorCryptoFixture {
	t.Helper()
	var f userMonitorCryptoFixture
	var err error
	f.owner, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.monitor, err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.ownerKeyID = f.owner.Public().ID
	f.stateDir = t.TempDir()
	f.state, err = OpenCryptoState(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.state.Close() })
	f.body = []byte("  synthetic exact body ☃\n")
	bodyDigest := sha256.Sum256(f.body)
	snapshotDigest := sha256.Sum256([]byte("synthetic fixed recipient snapshot"))
	f.context = e2ee.MonitorBroadcastContext{
		HubID: "hub_synthetic", OwnerID: "owner_synthetic", ClientDeviceID: "device_synthetic",
		ClientSessionEpoch: 4, ClientKeyVersion: 2,
		ApprovalID: "approval_synthetic", BroadcastID: "broadcast_synthetic", GroupID: "group_synthetic",
		MonitorEndpointID: "monitor_synthetic", MonitorKeyID: f.monitor.Public().ID,
		MonitorBindingID: "binding_synthetic", MonitorBindingEpoch: 3,
		BodySHA256: hex.EncodeToString(bodyDigest[:]), RecipientSnapshotSHA256: hex.EncodeToString(snapshotDigest[:]),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}
	// The enrollment grant is already expired at opening time, but it was
	// valid at the Store's original enrollment timestamp.
	f.enrolledAt = time.Now().UTC().Add(-3 * time.Hour)
	f.grant, err = f.owner.SignOwnerDeviceGrant(f.context.OwnerID, f.context.ClientDeviceID,
		f.client.Public(), f.context.HubID, e2ee.OwnerDevicePurposeControl,
		f.enrolledAt.Add(-time.Minute), f.enrolledAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	f.envelope, err = e2ee.SealMonitorBroadcast(f.client, f.monitor.Public(), f.context, f.body, 73)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f userMonitorCryptoFixture) installTrust(t *testing.T) {
	t.Helper()
	fingerprint, err := PeerKeyFingerprint(f.owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.TrustOwnerApprovalKeyLocal(f.context.OwnerID, f.ownerKeyID,
		f.owner.Public(), fingerprint); err != nil {
		t.Fatal(err)
	}
}

func (f userMonitorCryptoFixture) open(envelope []byte) (OpenedUserMonitorBroadcast, error) {
	return f.state.OpenUserMonitorBroadcast(context.Background(), f.monitor, f.context,
		f.client.Public(), f.ownerKeyID, f.grant, f.enrolledAt, envelope)
}

func (f userMonitorCryptoFixture) preview(envelope []byte) (PreviewedUserMonitorBroadcast, error) {
	return f.state.PreviewUserMonitorBroadcast(context.Background(), f.monitor, f.context,
		f.client.Public(), f.ownerKeyID, f.grant, f.enrolledAt, envelope)
}

func TestPreviewUserMonitorBroadcastVerifiesWithoutConsumingReplay(t *testing.T) {
	f := newUserMonitorCryptoFixture(t)
	f.installTrust(t)
	for range 2 {
		preview, err := f.preview(f.envelope)
		if err != nil || preview.Sequence != 73 || !bytes.Equal(preview.Plaintext, f.body) {
			t.Fatalf("read-only preview changed the signed body or sequence: %v", err)
		}
	}
	first, err := f.open(f.envelope)
	if err != nil || first.Duplicate {
		t.Fatalf("preview consumed the dispatch replay slot: duplicate=%v err=%v", first.Duplicate, err)
	}
	second, err := f.open(f.envelope)
	if err != nil || !second.Duplicate {
		t.Fatalf("dispatch lost its durable replay behavior: duplicate=%v err=%v", second.Duplicate, err)
	}
}

func TestOpenUserMonitorBroadcastRequiresLocalOwnerTrustAndDurableReplay(t *testing.T) {
	f := newUserMonitorCryptoFixture(t)
	if _, err := f.open(f.envelope); !errors.Is(err, ErrNodeOwnerKeyTrustNotFound) {
		t.Fatalf("missing independently installed Owner trust: %v", err)
	}
	f.installTrust(t)
	first, err := f.open(f.envelope)
	if err != nil || first.Duplicate || first.Sequence != 73 || !bytes.Equal(first.Plaintext, f.body) {
		t.Fatalf("open exact synthetic body: duplicate=%v sequence=%d err=%v", first.Duplicate, first.Sequence, err)
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	f.state, err = OpenCryptoState(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.open(f.envelope)
	if err != nil || !second.Duplicate || second.Sequence != first.Sequence || !bytes.Equal(second.Plaintext, f.body) {
		t.Fatalf("restart retry changed result: duplicate=%v sequence=%d err=%v", second.Duplicate, second.Sequence, err)
	}
	changedWire, err := e2ee.SealMonitorBroadcast(f.client, f.monitor.Public(), f.context, f.body, 73)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.open(changedWire); !errors.Is(err, ErrInboundReplayConflict) {
		t.Fatalf("same sequence, changed envelope: %v", err)
	}
	f.context.ApprovalID = "approval_other"
	f.context.BroadcastID = "broadcast_other"
	changedApproval, err := e2ee.SealMonitorBroadcast(f.client, f.monitor.Public(), f.context, f.body, 73)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.open(changedApproval); !errors.Is(err, ErrInboundReplayConflict) {
		t.Fatalf("same sequence, changed approval: %v", err)
	}
}

func TestOpenUserMonitorBroadcastAcceptsLegacySecondPrecisionEnrollment(t *testing.T) {
	f := newUserMonitorCryptoFixture(t)
	f.installTrust(t)
	// Legacy Client-device rows dropped subsecond precision. A valid signed
	// grant can start later in the recorded second; the Store's timestamp is
	// enrollment evidence, not a request to broaden the signed grant window.
	f.enrolledAt = time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	issuedAt := f.enrolledAt.Add(350 * time.Millisecond)
	grant, err := f.owner.SignOwnerDeviceGrant(f.context.OwnerID, f.context.ClientDeviceID,
		f.client.Public(), f.context.HubID, e2ee.OwnerDevicePurposeControl,
		issuedAt, f.enrolledAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	f.grant = grant
	if _, err := e2ee.VerifyOwnerDeviceGrant(f.grant, f.owner.Public(), f.client.Public(),
		f.context.OwnerID, f.ownerKeyID, f.context.ClientDeviceID, f.context.HubID,
		e2ee.OwnerDevicePurposeControl, f.enrolledAt); err == nil {
		t.Fatal("legacy test grant unexpectedly validates at truncated timestamp")
	}
	opened, err := f.open(f.envelope)
	if err != nil || opened.Duplicate || !bytes.Equal(opened.Plaintext, f.body) {
		t.Fatalf("legacy second-precision enrollment rejected: %+v %v", opened, err)
	}
	f.enrolledAt = f.enrolledAt.Add(200 * time.Millisecond)
	if _, err := f.open(f.envelope); err == nil {
		t.Fatal("exact nanosecond enrollment before signed issue time was accepted")
	}
}

func TestOpenUserMonitorBroadcastRejectsUntrustedEnrollmentAndContext(t *testing.T) {
	for _, scenario := range []string{"wrong Owner key", "revoked Owner key", "wrong Hub", "wrong device", "wrong Client key", "tampered grant", "tampered envelope", "late enrollment", "future enrollment", "expired broadcast", "wrong Monitor key", "wrong Monitor endpoint", "wrong binding", "wrong snapshot digest", "wrong body digest"} {
		t.Run(scenario, func(t *testing.T) {
			f := newUserMonitorCryptoFixture(t)
			f.installTrust(t)
			switch scenario {
			case "wrong Owner key":
				other, err := e2ee.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				f.ownerKeyID = other.Public().ID
			case "revoked Owner key":
				trust, err := f.state.GetNodeOwnerKeyTrustLocal(f.context.OwnerID, f.ownerKeyID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.state.RevokeNodeOwnerKeyTrustLocal(f.context.OwnerID, f.ownerKeyID, trust.Version); err != nil {
					t.Fatal(err)
				}
			case "wrong Hub":
				f.context.HubID = "hub_other"
			case "wrong device":
				f.context.ClientDeviceID = "device_other"
			case "wrong Client key":
				other, err := e2ee.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				f.client = other
			case "tampered grant":
				f.grant = append([]byte(nil), f.grant...)
				f.grant[len(f.grant)-2] ^= 1
			case "tampered envelope":
				f.envelope = append([]byte(nil), f.envelope...)
				f.envelope[len(f.envelope)-2] ^= 1
			case "late enrollment":
				f.enrolledAt = time.Now().UTC()
			case "future enrollment":
				f.enrolledAt = time.Now().UTC().Add(time.Minute)
			case "expired broadcast":
				f.context.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
			case "wrong Monitor key":
				other, err := e2ee.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				f.monitor = other
			case "wrong Monitor endpoint":
				f.context.MonitorEndpointID = "monitor_other"
			case "wrong binding":
				f.context.MonitorBindingID = "binding_other"
			case "wrong snapshot digest":
				f.context.RecipientSnapshotSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
			case "wrong body digest":
				f.context.BodySHA256 = hex.EncodeToString(make([]byte, sha256.Size))
			}
			if _, err := f.preview(f.envelope); err == nil {
				t.Fatal("untrusted broadcast previewed")
			}
			if _, err := f.open(f.envelope); err == nil {
				t.Fatal("untrusted broadcast opened")
			}
		})
	}
}
