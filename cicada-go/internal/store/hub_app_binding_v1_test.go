package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func appBindingInput(t *testing.T, f *n3StoreFixture, device *e2ee.Identity, body any, at time.Time) HubAppBindingInput {
	t.Helper()
	raw, err := wire.SealClientRequest(device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	binding, route, err := wire.NewClientRoute(f.hub, body, device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened any
	switch body.(type) {
	case wire.AppUnbindPrepare:
		opened = &wire.AppUnbindPrepare{}
	case wire.AppRebindPrepare:
		opened = &wire.AppRebindPrepare{}
	case wire.AppBindingComplete:
		opened = &wire.AppBindingComplete{}
	}
	public := device.Public()
	if err = wire.OpenRequestAt(f.hubPrivate, &public, binding, route, raw, opened, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reflect.ValueOf(opened).Elem().Interface(), body) {
		t.Fatal("authenticated body changed")
	}
	return HubAppBindingInput{Hub: f.hub, DevicePublic: public, Operation: route.Operation, Body: body, Packet: raw, At: at,
		Seal: func(v any) ([]byte, error) { return wire.SealResponse(f.hubPrivate, public, route, v) },
		VerifyProof: func(p ownerbootstrap.PairingFile, proof []byte, at time.Time) (string, error) {
			return ownerbootstrap.VerifyProof(f.hubPrivate, p, proof, at)
		},
		Challenge: func(b wire.AppBinding, client []byte, at time.Time) (wire.AppBindingChallenge, string, error) {
			pair, nonce, err := ownerbootstrap.CreateChallenge(f.hubPrivate, appBindingPair(b, f.hub, false), at)
			if err != nil {
				return wire.AppBindingChallenge{}, "", err
			}
			server, err := wire.NewNonce()
			return wire.AppBindingChallenge{Format: wire.AppBindingChallengeFormat, Operation: route.Operation, RequestID: b.PrepareRequestID, RequestPacketDigest: b.PreparePacketDigest, Binding: b, ClientNonce: client, ServerNonce: server, Proof: pair}, nonce, err
		},
	}
}

func appBindingPrepareUnbind(t *testing.T, f *n3StoreFixture) (HubAppBindingInput, wire.AppBindingChallenge) {
	t.Helper()
	fp, err := e2ee.OwnerDevicePublicKeyFingerprint(f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	s := wire.SessionContext{Origin: f.session.Origin, HubID: f.session.Hub.HubID, AccountID: f.session.AccountID, OwnerID: f.session.OwnerID, DeviceID: f.session.DeviceID, DeviceKeyID: f.device.Public().ID, DeviceKeyFingerprint: fp, SessionToken: f.session.Token, AccountEpoch: 1, DeviceEpoch: 1, ExpiresAt: f.scope.AccountSessionExpiresAt}
	q, err := wire.NewAppUnbindPrepare(s, f.owner.Public(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	in := appBindingInput(t, f, f.device, q, f.now)
	packet, err := f.db.ProcessHubAppBinding(in)
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.AppBindingChallenge
	if err = wire.OpenClientResponse(f.device, f.hub, in.Packet, packet, &challenge); err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateAppBindingPreparedResponse(q, in.Packet, challenge, f.hub, f.now); err != nil {
		t.Fatal(err)
	}
	return in, challenge
}

func appBindingCompletion(t *testing.T, f *n3StoreFixture, device *e2ee.Identity, prepare HubAppBindingInput, ch wire.AppBindingChallenge) HubAppBindingInput {
	t.Helper()
	proof, err := ownerbootstrap.CreateProof(f.owner, ch.Proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewAppBindingComplete(prepare.Packet, ch, proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return appBindingInput(t, f, device, q, f.now)
}
func appBindingResult(t *testing.T, f *n3StoreFixture, device *e2ee.Identity, in HubAppBindingInput, packet []byte) wire.AppBindingResult {
	t.Helper()
	var result wire.AppBindingResult
	if err := wire.OpenClientResponse(device, f.hub, in.Packet, packet, &result); err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateAppBindingResultTarget(result, in.Packet, in.Body.(wire.AppBindingComplete).Binding); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAppBindingStoreAtomicSelfFenceRestartAndSecurityRevoke(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	if _, err := f.db.ProcessHubAppNodeClient(f.client(t, g, 1, f.now.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, err := f.db.NodeControlKeyForCredential(credential, "synthetic-n3-node"); err != nil {
		t.Fatal("original Node binding unavailable", err)
	}
	prepare, ch := appBindingPrepareUnbind(t, f)
	in := appBindingCompletion(t, f, f.device, prepare, ch)
	seal := in.Seal
	in.Seal = func(any) ([]byte, error) { return nil, errors.New("synthetic seal failure") }
	if _, err := f.db.ProcessHubAppBinding(in); err == nil {
		t.Fatal("failed seal committed")
	}
	d, _ := f.db.GetClientDevice(f.scope.OwnerID, f.scope.DeviceID)
	if d.State != ClientDeviceActive || d.Version != 1 || d.SessionEpoch != 1 {
		t.Fatal("seal failure fenced App")
	}
	in.Seal = seal
	packet, err := f.db.ProcessHubAppBinding(in)
	if err != nil {
		t.Fatal(err)
	}
	result := appBindingResult(t, f, f.device, in, packet)
	if result.State != wire.AppBindingUnbound || result.DeviceEpoch != 2 || result.ClientSessionEpoch != 2 {
		t.Fatal("missing self fence")
	}
	if _, err = f.db.HubAccountSession(f.scope.AccountSessionID); err == nil {
		t.Fatal("unbound account session survived")
	}
	if _, err = f.db.NodeControlKeyForCredential(credential, "synthetic-n3-node"); err != nil {
		t.Fatal("voluntary unbind broke independent Node", err)
	}
	d, _ = f.db.GetClientDevice(f.scope.OwnerID, f.scope.DeviceID)
	if d.State != ClientDeviceRevoked || d.Version != 2 || d.SessionEpoch != 2 {
		t.Fatal("Client coordinates not fenced")
	}
	if _, err = f.db.ProcessHubAppNodeClient(f.client(t, g, 2, f.now.Add(3*time.Second))); err == nil {
		t.Fatal("late old App mutation survived")
	}
	if err = f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.db, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.db.ProcessHubAppBinding(in)
	if err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("restart lost exact completion receipt", err)
	}
	other := in.Body.(wire.AppBindingComplete)
	other.RequestID, _ = wire.NewRequestID()
	other.ClientNonce, _ = wire.NewNonce()
	freshID := appBindingInput(t, f, f.device, other, f.now)
	if _, err = f.db.ProcessHubAppBinding(freshID); err == nil {
		t.Fatal("new ID reused terminal Owner proof")
	}
	var floorCount int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_binding_operations_v1`).Scan(&floorCount); err != nil || floorCount != 1 {
		t.Fatal("new ID amplified permanent floors", err)
	}
	q := in.Body.(wire.AppBindingComplete)
	q.ClientNonce = bytes.Repeat([]byte{5}, wire.NonceBytes)
	changed := appBindingInput(t, f, f.device, q, f.now)
	if _, err = f.db.ProcessHubAppBinding(changed); err == nil {
		t.Fatal("same ID changed bytes borrowed receipt")
	}
	if _, err = f.db.RevokeClientDevice(f.scope.OwnerID, f.scope.DeviceID, 2); err != nil {
		t.Fatal("security revoke of detached provenance failed", err)
	}
	d, _ = f.db.GetClientDevice(f.scope.OwnerID, f.scope.DeviceID)
	if d.Version != 3 || d.SessionEpoch != 3 {
		t.Fatal("security revoke did not advance fence again")
	}
	if _, err = f.db.NodeControlKeyForCredential(credential, "synthetic-n3-node"); err == nil {
		t.Fatal("security revoked historical source still authorized Node")
	}
	retry, err = f.db.ProcessHubAppBinding(in)
	if err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("security revoke changed historical diagnostic receipt", err)
	}
}

func TestAppBindingStoreForgedMissingPrepareCannotAllocateFloor(t *testing.T) {
	f := n3Fixture(t, true)
	p, ch := appBindingPrepareUnbind(t, f)
	if _, err := f.db.db.Exec(`DELETE FROM hub_app_binding_prepares_v1`); err != nil {
		t.Fatal(err)
	}
	fake, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ch.Binding.OwnerPublic = fake.Public()
	pair := appBindingPair(ch.Binding, f.hub, false)
	// This attacker has no Hub secret and never opened an admitted challenge.
	// VerifyProof alone accepts a self-signed arbitrary possession under the
	// caller's fake Owner; the trusted retained Root check must stop allocation.
	possession, _ := json.Marshal(ownerbootstrap.Possession{Format: ownerbootstrap.Format, Manifest: pair.Manifest, Nonce: bytes.Repeat([]byte{9}, 32)})
	proof, err := ownerbootstrap.CreateProofFromPossessionWithPrivateOperations(fake.Public(), fake, pair, possession, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ownerbootstrap.VerifyProof(f.hubPrivate, pair, proof, f.now); err != nil {
		t.Fatal("attack does not reach standalone proof verification", err)
	}
	q := wire.AppBindingComplete{Format: wire.AppBindingCompleteFormat, Binding: ch.Binding, PreparePacket: p.Packet, ServerNonce: bytes.Repeat([]byte{3}, 32), OwnerProof: proof, IssuedAt: appNodeStamp(f.now)}
	q.RequestID, _ = wire.NewRequestID()
	q.ClientNonce, _ = wire.NewNonce()
	in := appBindingInput(t, f, f.device, q, f.now)
	if _, err = f.db.ProcessHubAppBinding(in); err == nil {
		t.Fatal("self-signed fake Root allocated refusal")
	}
	var count int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_binding_operations_v1`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unauthenticated permanent floor", err)
	}
}

func TestAppBindingStoreCacheTimeParsingAndExactDeadline(t *testing.T) {
	f := n3Fixture(t, true)
	p, _ := appBindingPrepareUnbind(t, f)
	r, _ := appBindingFields(p.Body)
	// Only the cache expiry column is varied here. These are parser/GC cases,
	// not claims that altered challenge bytes would authorize a completion.
	for _, c := range []struct {
		end, at string
		expired bool
	}{
		{"2026-11-04T00:00:00Z", "2026-11-04T00:00:00.1Z", true},
		{"2026-11-04T00:00:00.1Z", "2026-11-04T00:00:00.15Z", true},
		{"2026-11-04T00:00:00.15Z", "2026-11-04T00:00:00.1Z", false},
		{"2026-11-04T00:00:00.1Z", "2026-11-04T00:00:00.1Z", true},
	} {
		t.Run(c.end+"/"+c.at, func(t *testing.T) {
			tx, err := f.db.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.Exec(`UPDATE hub_app_binding_prepares_v1 SET expires_at=?`, c.end); err != nil {
				t.Fatal(err)
			}
			at, err := time.Parse(time.RFC3339Nano, c.at)
			if err != nil {
				t.Fatal(err)
			}
			if err = appBindingCollectPrepares(tx, at); err != nil {
				t.Fatal(err)
			}
			var count int
			if err = tx.QueryRow(`SELECT count(*) FROM hub_app_binding_prepares_v1 WHERE owner_id=? AND device_id=? AND prepare_id=?`, r.owner, r.device, r.id).Scan(&count); err != nil || (count == 0) != c.expired {
				t.Fatal("incorrect parsed deadline", err)
			}
		})
	}
}

func TestAppBindingStoreRestoreRetainedPendingVersusMissingFloor(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained", true: "missing"}[missing], func(t *testing.T) {
			f := n3Fixture(t, true)
			p, ch := appBindingPrepareUnbind(t, f)
			in := appBindingCompletion(t, f, f.device, p, ch)
			if missing {
				if _, err := f.db.db.Exec(`DELETE FROM hub_app_binding_prepares_v1`); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.db.fenceHubAccountRestore(strings.Repeat("9", 64)); err != nil {
				t.Fatal(err)
			}
			packet, err := f.db.ProcessHubAppBinding(in)
			if missing {
				if err == nil {
					t.Fatal("restore missing evidence fabricated no-effect proof")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result := appBindingResult(t, f, f.device, in, packet)
			if result.State != wire.AppBindingRejected || result.ErrorCode != "RESTORE_FENCED" {
				t.Fatal("retained pending restore did not authenticate fence")
			}
		})
	}
}

func TestAppBindingStoreConcurrentOneReplacementZeroAuthority(t *testing.T) {
	f := n3Fixture(t, true)
	p, ch := appBindingPrepareUnbind(t, f)
	in := appBindingCompletion(t, f, f.device, p, ch)
	var wg sync.WaitGroup
	packets := make([][]byte, 4)
	errs := make([]error, 4)
	for i := range packets {
		wg.Add(1)
		go func(i int) { defer wg.Done(); packets[i], errs[i] = f.db.ProcessHubAppBinding(in) }(i)
	}
	wg.Wait()
	for i := range packets {
		if errs[i] != nil || !bytes.Equal(packets[0], packets[i]) {
			t.Fatal("same-original concurrency diverged", errs[i])
		}
	}
	reused, err := wire.NewAppRebindPrepare(f.hub, f.scope.Origin, f.scope.AccountID, f.scope.OwnerID, f.scope.DeviceID, ch.Binding.Digest(), wire.AccountDeviceIDPrefix+strings.Repeat("f", 32), f.owner.Public(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ProcessHubAppBinding(appBindingInput(t, f, f.device, reused, f.now)); err == nil {
		t.Fatal("retired public key enrolled under new ID")
	}
	candidates := make([]*e2ee.Identity, 2)
	completes := make([]HubAppBindingInput, 2)
	for i := range candidates {
		var err error
		candidates[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		q, err := wire.NewAppRebindPrepare(f.hub, f.scope.Origin, f.scope.AccountID, f.scope.OwnerID, f.scope.DeviceID, ch.Binding.Digest(), wire.AccountDeviceIDPrefix+strings.Repeat(string(rune('b'+i)), 32), f.owner.Public(), f.now)
		if err != nil {
			t.Fatal(err)
		}
		prepare := appBindingInput(t, f, candidates[i], q, f.now)
		packet, err := f.db.ProcessHubAppBinding(prepare)
		if err != nil {
			t.Fatal(err)
		}
		var challenge wire.AppBindingChallenge
		if err = wire.OpenClientResponse(candidates[i], f.hub, prepare.Packet, packet, &challenge); err != nil {
			t.Fatal(err)
		}
		completes[i] = appBindingCompletion(t, f, candidates[i], prepare, challenge)
	}
	for i := range completes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); packets[i], errs[i] = f.db.ProcessHubAppBinding(completes[i]) }(i)
	}
	wg.Wait()
	winner := -1
	for i := range completes {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		result := appBindingResult(t, f, candidates[i], completes[i], packets[i])
		if result.State == wire.AppBindingBoundZero {
			if winner != -1 {
				t.Fatal("tombstone fanned out")
			}
			winner = i
		} else if result.State != wire.AppBindingRejected || result.ErrorCode != "ALREADY_REPLACED" {
			t.Fatal("loser lacks permanent authenticated refusal")
		}
	}
	if winner < 0 {
		t.Fatal("no replacement")
	}
	q := completes[winner].Body.(wire.AppBindingComplete)
	var sessions, leases, grants int
	f.db.db.QueryRow(`SELECT count(*) FROM hub_account_sessions_v1 WHERE device_id=?`, q.Binding.DeviceID).Scan(&sessions)
	f.db.db.QueryRow(`SELECT count(*) FROM hub_app_leases_v1 WHERE device_id=?`, q.Binding.DeviceID).Scan(&leases)
	f.db.db.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1 WHERE device_id=?`, q.Binding.DeviceID).Scan(&grants)
	if sessions+leases+grants != 0 {
		t.Fatal("replacement silently granted authority")
	}
	if err := f.db.CheckAppLease(f.scope.OwnerID, q.Binding.DeviceID, "nodes.list"); err == nil {
		t.Fatal("zero source escaped legacy nil-lease path")
	}
	tx, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	a, err := appNodeActor(tx, f.hub, q.Binding.DeviceID, candidates[winner].Public(), nil, f.now)
	tx.Rollback()
	if err != nil || !a.source || a.session != nil {
		t.Fatal("replacement cannot enter separate Owner management bootstrap", err)
	}
	for i := range completes {
		retry, err := f.db.ProcessHubAppBinding(completes[i])
		if err != nil || !bytes.Equal(packets[i], retry) {
			t.Fatal("replacement/refusal retry changed", err)
		}
	}
}

func TestAppBindingStoreExpiredAndMissingPrepareAreDurableNoEffect(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "EXPIRED", true: "NOT_ADMITTED"}[missing], func(t *testing.T) {
			f := n3Fixture(t, true)
			p, ch := appBindingPrepareUnbind(t, f)
			in := appBindingCompletion(t, f, f.device, p, ch)
			if missing {
				if _, err := f.db.db.Exec(`DELETE FROM hub_app_binding_prepares_v1`); err != nil {
					t.Fatal(err)
				}
			} else {
				in.Now = func() time.Time { return f.now.Add(3 * time.Minute) }
			}
			packet, err := f.db.ProcessHubAppBinding(in)
			if err != nil {
				t.Fatal(err)
			}
			r := appBindingResult(t, f, f.device, in, packet)
			if r.State != wire.AppBindingRejected || r.ErrorCode != map[bool]string{false: "EXPIRED", true: "NOT_ADMITTED"}[missing] {
				t.Fatal("missing typed refusal")
			}
			d, _ := f.db.GetClientDevice(f.scope.OwnerID, f.scope.DeviceID)
			if d.State != ClientDeviceActive || d.Version != 1 || d.SessionEpoch != 1 {
				t.Fatal("refusal changed App")
			}
			in.Now = nil
			retry, err := f.db.ProcessHubAppBinding(in)
			if err != nil || !bytes.Equal(packet, retry) {
				t.Fatal("refused original was later readmitted", err)
			}
		})
	}
}

func TestAppBindingStoreCurrentRootAndDeviceEpochRemainAuthoritative(t *testing.T) {
	for _, kind := range []string{"Root", "DeviceEpoch"} {
		t.Run(kind, func(t *testing.T) {
			f := n3Fixture(t, true)
			p, ch := appBindingPrepareUnbind(t, f)
			in := appBindingCompletion(t, f, f.device, p, ch)
			want := "OWNER_REVOKED"
			if kind == "Root" {
				if _, err := f.db.RevokeOwnerApprovalKeyLocal(f.scope.OwnerID, f.owner.Public().ID, 1); err != nil {
					t.Fatal(err)
				}
			} else {
				want = "DEVICE_INACTIVE"
				if _, err := f.db.AdvanceClientDeviceSessionEpoch(f.scope.OwnerID, f.scope.DeviceID, 1); err != nil {
					t.Fatal(err)
				}
			}
			packet, err := f.db.ProcessHubAppBinding(in)
			if err != nil {
				t.Fatal(err)
			}
			result := appBindingResult(t, f, f.device, in, packet)
			if result.State != wire.AppBindingRejected || result.ErrorCode != want {
				t.Fatal("old challenge adopted changed security scope")
			}
		})
	}
}

func TestAppBindingStoreAnonymousCacheQuotaExpiresWithoutPermanentFloor(t *testing.T) {
	f := n3Fixture(t, true)
	p, ch := appBindingPrepareUnbind(t, f)
	unbinding := appBindingCompletion(t, f, f.device, p, ch)
	if _, err := f.db.ProcessHubAppBinding(unbinding); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		device, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		q, err := wire.NewAppRebindPrepare(f.hub, f.scope.Origin, f.scope.AccountID, f.scope.OwnerID, f.scope.DeviceID, ch.Binding.Digest(), wire.AccountDeviceIDPrefix+strings.Repeat(string(rune('1'+i)), 32), f.owner.Public(), f.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.db.ProcessHubAppBinding(appBindingInput(t, f, device, q, f.now))
		if i < 8 && err != nil {
			t.Fatal(err)
		}
		if i == 8 && !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
			t.Fatal("per-tombstone cache quota did not bound candidates", err)
		}
	}
	at := f.now.Add(wire.MaxAppBindingChallengeLifetime)
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewAppRebindPrepare(f.hub, f.scope.Origin, f.scope.AccountID, f.scope.OwnerID, f.scope.DeviceID, ch.Binding.Digest(), wire.AccountDeviceIDPrefix+strings.Repeat("e", 32), f.owner.Public(), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ProcessHubAppBinding(appBindingInput(t, f, device, q, at)); err != nil {
		t.Fatal("expired anonymous slots stranded Owner", err)
	}
	var cache, floors int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_binding_prepares_v1`).Scan(&cache); err != nil {
		t.Fatal(err)
	}
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_binding_operations_v1`).Scan(&floors); err != nil {
		t.Fatal(err)
	}
	if cache != 1 || floors != 1 {
		t.Fatal("expired unproved candidates left permanent storage")
	}
}

func TestAppBindingStoreMissingWriterGuardDoesNotSampleClock(t *testing.T) {
	f := n3Fixture(t, true)
	p, ch := appBindingPrepareUnbind(t, f)
	in := appBindingCompletion(t, f, f.device, p, ch)
	if _, err := f.db.db.Exec(`DELETE FROM hub_app_binding_guard_v1`); err != nil {
		t.Fatal(err)
	}
	sampled := false
	in.Now = func() time.Time { sampled = true; return f.now }
	if _, err := f.db.ProcessHubAppBinding(in); err == nil || sampled {
		t.Fatal("missing writer guard continued or sampled time")
	}
	d, err := f.db.GetClientDevice(f.scope.OwnerID, f.scope.DeviceID)
	if err != nil || d.State != ClientDeviceActive {
		t.Fatal("missing guard changed authority", err)
	}
}

func TestAppBindingMigrationMissingPermanentObjectsFailClosed(t *testing.T) {
	for _, object := range []struct{ kind, name string }{
		{"TABLE", "hub_app_binding_operations_v1"},
		{"TABLE", "hub_app_unbound_v1"},
		{"TABLE", "hub_app_rebound_v1"},
		{"INDEX", "hub_app_binding_operations_v1_binding"},
		{"TRIGGER", "hub_app_binding_operations_v1_no_update"},
	} {
		t.Run(object.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "synthetic.sqlite3")
			db, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.db.Exec("DROP " + object.kind + " " + object.name); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(path)
			if reopened != nil {
				reopened.Close()
			}
			if err == nil || !strings.Contains(err.Error(), object.name) {
				t.Fatal("missing permanent object silently regenerated", err)
			}
		})
	}
}

func TestAppBindingStoreLocalDomainSurvivesUnbindAndSecurityRevokeStopsIt(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	join, _ := f.join(t, d, "synthetic-app-unbind-domain")
	base := f.f.f
	p, ch := appBindingPrepareUnbind(t, base)
	in := appBindingCompletion(t, base, base.device, p, ch)
	if _, err := base.db.ProcessHubAppBinding(in); err != nil {
		t.Fatal(err)
	}
	q := wire.LocalDomainNodeDescribe{ContractRevision: wire.LocalDomainContractRevision, Selection: join.Member.Selection, LocalUserScope: d.Policy.LocalUserScope}
	request, seal := f.nodeInput(t, wire.OperationLocalDomainNodeDescribe, q, f.f.at.Add(20*time.Second))
	var current wire.LocalDomainDescription
	f.nodeResult(t, request, seal, &current)
	if current.State != wire.LocalDomainActive || current.Policy.PolicyID != d.Policy.PolicyID {
		t.Fatal("voluntary unbind revoked persistent policy")
	}
	if _, err := base.db.RevokeClientDevice(base.scope.OwnerID, base.scope.DeviceID, 2); err != nil {
		t.Fatal(err)
	}
	request, seal = f.nodeInput(t, wire.OperationLocalDomainNodeDescribe, q, f.f.at.Add(21*time.Second))
	packet, err := base.db.ProcessHubLocalDomainNode(request, seal)
	if err != nil && !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatal("unexpected security refusal", err)
	}
	if err == nil {
		// Typed business rejection is authenticated by the real Node envelope.
		n := f.f.scope.Node
		binding := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
		opened, e := nodewire.OpenResponse(base.node, n.HubNodeControlPublic, binding, packet)
		if e != nil {
			t.Fatal("security refusal lacks authentic Node envelope", e)
		}
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error_code"`
		}
		if json.Unmarshal(opened.Plaintext, &out) != nil || out.OK || out.Error != "LOCAL_DOMAIN_REJECTED" {
			t.Fatal("security revoked provenance retained policy access")
		}
	}
}

func TestAppBindingStoreHeartbeatWritersFenceOnlyRevokedVoluntarySource(t *testing.T) {
	for _, machineWriter := range []bool{false, true} {
		t.Run(map[bool]string{false: "liveness", true: "machine"}[machineWriter], func(t *testing.T) {
			f := n3Fixture(t, true)
			g := f.activate(t)
			if _, err := f.db.ProcessHubAppNodeClient(f.client(t, g, 1, f.now.Add(2*time.Second))); err != nil {
				t.Fatal(err)
			}
			credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			sampled := 0
			write := func() error {
				clock := func() time.Time { sampled++; return f.now.Add(time.Duration(2+sampled) * time.Second) }
				if machineWriter {
					return f.db.recordBoundNodeMachineHeartbeat(credential, "busy", map[string]any{"synthetic": sampled}, nil, clock)
				}
				return f.db.recordBoundNodeHeartbeat(credential, clock)
			}
			if err := write(); err != nil {
				t.Fatal("bound heartbeat", err)
			}
			before, err := f.db.GetMachine(g.Candidate.NodeID)
			if err != nil {
				t.Fatal(err)
			}
			p, ch := appBindingPrepareUnbind(t, f)
			if _, err = f.db.ProcessHubAppBinding(appBindingCompletion(t, f, f.device, p, ch)); err != nil {
				t.Fatal(err)
			}
			if err = write(); err != nil {
				t.Fatal("voluntary unbind broke real heartbeat writer", err)
			}
			after, err := f.db.GetMachine(g.Candidate.NodeID)
			if err != nil || after.LastSeen == before.LastSeen {
				t.Fatal("voluntary heartbeat did not update liveness", err)
			}
			if _, err = f.db.RevokeClientDevice(f.scope.OwnerID, f.scope.DeviceID, 2); err != nil {
				t.Fatal(err)
			}
			wantErr := ErrNodeCredentialNotFound
			if machineWriter {
				wantErr = ErrNodeWorkerNotAuthorized
			}
			if err = write(); !errors.Is(err, wantErr) {
				t.Fatal("security revoked heartbeat remained writable", err)
			}
			current, err := f.db.GetMachine(g.Candidate.NodeID)
			if err != nil || sampled != 2 || !reflect.DeepEqual(after, current) {
				t.Fatal("refused heartbeat sampled time or changed projection", err)
			}
		})
	}
}

func TestAppBindingStoreHeartbeatWithoutTombstoneKeepsLegacyIndependence(t *testing.T) {
	f := n3Fixture(t, true)
	g := f.activate(t)
	if _, err := f.db.ProcessHubAppNodeClient(f.client(t, g, 1, f.now.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.RevokeClientDevice(f.scope.OwnerID, f.scope.DeviceID, 1); err != nil {
		t.Fatal(err)
	}
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if err := f.db.RecordBoundNodeHeartbeat(credential); err != nil {
		t.Fatal("legacy liveness writer acquired new App prerequisite", err)
	}
	if err := f.db.RecordBoundNodeMachineHeartbeat(credential, "idle", nil); err != nil {
		t.Fatal("legacy machine writer acquired new App prerequisite", err)
	}
}
