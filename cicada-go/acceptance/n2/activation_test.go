package n2_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

func newActivationFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	origin := "http://" + listener.Addr().String()
	listener.Close()
	db := must(store.New(filepath.Join(dir, "hub", "synthetic.sqlite3")))
	setup := must(db.InitializeHubOwnerLocal("Synthetic independent N2 Owner", origin, true))
	ids := must(hubidentity.LoadOrCreate(filepath.Join(dir, "hub"), ""))
	auth := must(hubauth.NewService(db, ids))
	material := must(auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false))
	cfg := fixtureConfig{Origin: origin, Hub: must(auth.HubIdentity()), Activation: material,
		Card: wire.ClaimCard{Origin: origin, AccountID: setup.AccountID, OwnerID: setup.OwnerID, HubID: setup.HubID, HubFingerprint: material.HubFingerprint}}
	db.Close()
	writeJSON(t, filepath.Join(dir, "synthetic-config.json"), cfg)
	f := &fixture{owner: t, dir: dir, cfg: cfg}
	f.start(t)
	f.proxy = newFaultProxy(t, origin)
	return f
}
func issueContinuation(t *testing.T, f *fixture, key *e2ee.Identity) {
	t.Helper()
	f.hub.kill(t)
	db := f.db(t)
	ids := must(hubidentity.LoadOrCreate(filepath.Join(f.dir, "hub"), ""))
	auth := must(hubauth.NewService(db, ids))
	f.cfg.Activation = must(auth.IssueActivationLocal(wire.PurposeLegacyContinuation, key.Public().ID, ownerbootstrap.Fingerprint(key.Public()), false))
	db.Close()
	writeJSON(t, filepath.Join(f.dir, "synthetic-config.json"), f.cfg)
	f.start(t)
}
func openWire(t *testing.T, f *fixture, key *e2ee.Identity, packet, response []byte, out any) {
	t.Helper()
	if wire.OpenClientResponse(key, f.cfg.Hub, packet, response, out) != nil {
		t.Fatal("Hub response failed PQ authentication/target binding")
	}
}
func activationRoundTrip(t *testing.T, f *fixture, key *e2ee.Identity, operation string, body, out any) ([]byte, []byte) {
	t.Helper()
	packet := seal(t, f, key, body)
	code, response := post(t, f, wire.ActivationHTTPPath(operation), packet)
	if code != 200 {
		t.Fatalf("N2 HTTP operation=%s status=%d", operation, code)
	}
	openWire(t, f, key, packet, response, out)
	return packet, response
}
func prepareActivation(t *testing.T, f *fixture, device, owner *e2ee.Identity, ttl time.Duration) (wire.ActivationPrepare, wire.ActivationChallenge, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	id := wire.AccountDeviceIDPrefix + must(wire.NewRequestID())
	grant := must(owner.SignOwnerDeviceGrant(f.cfg.Card.OwnerID, id, device.Public(), f.cfg.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(ttl)))
	req := must(wire.NewActivationPrepare(*f.cfg.Activation, f.cfg.Hub, device.Public(), owner.Public(), id, grant, now))
	var challenge wire.ActivationChallenge
	packet, response := activationRoundTrip(t, f, device, wire.OperationActivationPrepare, req, &challenge)
	if wire.ValidateActivationPreparedResponse(challenge, req, packet, f.cfg.Hub, device.Public(), time.Now().UTC()) != nil {
		t.Fatal("challenge changed the exact candidate, grant, epoch or original packet")
	}
	issued := must(time.Parse(time.RFC3339Nano, challenge.IssuedAt))
	expires := must(time.Parse(time.RFC3339Nano, challenge.Binding.LeaseExpiresAt))
	if expires.Sub(issued) != 15*time.Minute || !reflect.DeepEqual(challenge.Binding.AllowedOperations, wire.ActivationAllowedOperations()) {
		t.Fatal("lease is not exactly the nonrenewable 15-minute two-operation scope")
	}
	return req, challenge, packet, response
}
func completeActivation(t *testing.T, f *fixture, device, owner *e2ee.Identity, ch wire.ActivationChallenge) (wire.ActivationComplete, []byte, []byte) {
	t.Helper()
	username, password := "synthetic-user", syntheticPassword
	if ch.Binding.Purpose == wire.PurposeLegacyContinuation {
		username, password = "", ""
	}
	req := must(wire.NewActivationComplete(ch, f.cfg.Hub, device.Public(), owner, username, password, time.Now().UTC()))
	var result wire.ActivationResult
	packet, response := activationRoundTrip(t, f, device, wire.OperationActivationComplete, req, &result)
	if result.State != wire.ActivationCompleted || result.RootState != wire.RootActiveState || result.LeaseState != wire.ActivationLeaseActive || !result.LoginRequired {
		t.Fatal("real Owner proof did not atomically install Root and finite login-required lease")
	}
	return req, packet, response
}
func activationStatus(t *testing.T, f *fixture, device *e2ee.Identity, original []byte) wire.ActivationResult {
	t.Helper()
	decoded := must(wire.DecodePacket(original))
	r := decoded.Packet.Route
	req := must(wire.NewActivationStatusRequest(f.cfg.Hub, f.cfg.Origin, f.cfg.Card.AccountID, f.cfg.Card.OwnerID, f.cfg.Activation.ActivationID, r.DeviceID, r.Operation, r.OperationID, wire.ActivationPacketDigest(original), time.Now().UTC()))
	var result wire.ActivationResult
	activationRoundTrip(t, f, device, wire.OperationActivationStatus, req, &result)
	if wire.ValidateActivationStatusTarget(result, original) != nil {
		t.Fatal("status settled a different operation or packet digest")
	}
	return result
}
func refuseActivation(t *testing.T, f *fixture, device *e2ee.Identity, op string, body any) {
	t.Helper()
	var packet []byte
	switch value := body.(type) {
	case wire.ActivationPrepare:
		packet = rawActivationPacket(t, f, device, op, value.Material.OwnerID, value.DeviceID, value.RequestID, body)
	case wire.ActivationComplete:
		packet = rawActivationPacket(t, f, device, op, value.Binding.OwnerID, value.Binding.DeviceID, value.RequestID, body)
	default:
		t.Fatal("unsupported negative fixture request")
	}
	refuseActivationPacket(t, f, device, op, packet)
}
func refuseActivationPacket(t *testing.T, f *fixture, device *e2ee.Identity, op string, packet []byte) {
	t.Helper()
	code, response := post(t, f, wire.ActivationHTTPPath(op), packet)
	if code == 403 {
		return
	}
	if code != 200 {
		t.Fatalf("negative operation returned unavailable status=%d", code)
	}
	var result wire.ActivationResult
	openWire(t, f, device, packet, response, &result)
	if result.State != wire.ActivationRejected && result.State != wire.ActivationCancelled {
		t.Fatal("invalid activation was not rejected/fenced")
	}
}

// Use the existing bounded wire sealer to test server checks independently of
// the App/wire constructor's local identity preflight. No crypto is replaced.
func rawActivationPacket(t *testing.T, f *fixture, key *e2ee.Identity, op, owner, device, id string, body any) []byte {
	t.Helper()
	binding, route, err := wire.RequestRoute(f.cfg.Hub, owner, device, id, op, wire.HandshakeEpoch, key.Public())
	if err != nil {
		t.Fatal("negative request route invalid")
	}
	sealed := must(clientwire.SealRequestWithBodyLimit(key, f.cfg.Hub.Public, binding, route, must(json.Marshal(body)), wire.MaxActivationBodyBytes))
	var inner clientwire.Packet
	if json.Unmarshal(sealed, &inner) != nil {
		t.Fatal("negative wire packet decode failed")
	}
	return must(json.Marshal(wire.Packet{Format: wire.PacketFormat, Version: wire.PacketVersion, SenderPublicIdentity: key.Public(), Packet: inner}))
}
func assertPristineAuthority(t *testing.T, f *fixture) {
	t.Helper()
	f.hub.kill(t)
	db := f.db(t)
	setup, _, err := db.HubAccountSetup()
	if err != nil || setup.RootEverEstablished {
		t.Fatal("rejected request created permanent Root history")
	}
	if _, err := db.HubAccountCredential(setup.AccountID); err == nil {
		t.Fatal("rejected request left account credentials")
	}
	authority := must(db.HubActivation(f.cfg.Activation.ActivationID))
	if authority.State == wire.ActivationCompleted {
		t.Fatal("rejected request consumed finite authority")
	}
	if authority.Binding != nil {
		id := authority.Binding.DeviceID
		if _, err := db.GetOwnerApprovalKey(setup.OwnerID, authority.Binding.OwnerPublic.ID); err == nil {
			t.Fatal("rolled-back completion left an Owner approval key")
		}
		if _, err := db.GetClientDevice(setup.OwnerID, id); err == nil {
			t.Fatal("rolled-back completion left an enrolled Client device")
		}
		if _, err := db.HubAccountDevice(setup.AccountID, id); err == nil {
			t.Fatal("rolled-back completion left an account device")
		}
		lease, err := db.HubAppLease(setup.OwnerID, id)
		if err != nil || lease != nil {
			t.Fatal("rolled-back completion left a finite runtime lease")
		}
	}
	db.Close()
	f.start(t)
}
func reconcile(t *testing.T, f *fixture, device *e2ee.Identity, id string, original []byte) wire.AccountReconcileResult {
	t.Helper()
	req := must(wire.NewAccountReconcileRequest(f.cfg.Hub, f.cfg.Origin, f.cfg.Card.AccountID, f.cfg.Card.OwnerID, id, original, time.Now().UTC()))
	var result wire.AccountReconcileResult
	activationRoundTrip(t, f, device, wire.OperationAccountReconcile, req, &result)
	if wire.ValidateAccountReconcileTarget(result, original) != nil {
		t.Fatal("account reconciliation targeted a different packet")
	}
	return result
}
func loginPrepare(t *testing.T, f *fixture, device *e2ee.Identity, id string) wire.LoginChallenge {
	t.Helper()
	req := must(wire.NewLoginPrepare(f.cfg.Hub, f.cfg.Origin, f.cfg.Card.AccountID, f.cfg.Card.OwnerID, id, "synthetic-user", device.Public(), time.Now().UTC()))
	packet := seal(t, f, device, req)
	code, response := post(t, f, "/v2/owner/account/login/prepare", packet)
	if code != 200 {
		t.Fatal("registered device login prepare rejected")
	}
	var ch wire.LoginChallenge
	openWire(t, f, device, packet, response, &ch)
	return ch
}
func wireLogin(t *testing.T, f *fixture, device *e2ee.Identity, id string) wire.SessionReceipt {
	t.Helper()
	ch := loginPrepare(t, f, device, id)
	req := must(wire.NewLoginComplete(f.cfg.Hub, ch, syntheticPassword, time.Now().UTC()))
	packet := seal(t, f, device, req)
	code, response := post(t, f, "/v2/owner/account/login/complete", packet)
	if code != 200 {
		t.Fatal("ordinary account login rejected")
	}
	var result wire.SessionReceipt
	openWire(t, f, device, packet, response, &result)
	return result
}

func TestN2ActivationCryptographicNegativeGuards(t *testing.T) {
	for _, kind := range []string{"missing-kem", "missing-owner-signature", "wrong-owner-signature", "reused-nonce", "stale-account-epoch", "wrong-owner-scope", "wrong-app-key", "forged-grant", "wrong-grant-purpose"} {
		t.Run(kind, func(t *testing.T) {
			f := newActivationFixture(t)
			device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
			if kind == "forged-grant" || kind == "wrong-grant-purpose" {
				now := time.Now().UTC()
				id := wire.AccountDeviceIDPrefix + must(wire.NewRequestID())
				good := must(owner.SignOwnerDeviceGrant(f.cfg.Card.OwnerID, id, device.Public(), f.cfg.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(5*time.Minute)))
				req := must(wire.NewActivationPrepare(*f.cfg.Activation, f.cfg.Hub, device.Public(), owner.Public(), id, good, now))
				var grant e2ee.OwnerDeviceGrant
				if json.Unmarshal(good, &grant) != nil {
					t.Fatal("grant fixture decode failed")
				}
				if kind == "forged-grant" {
					grant.Signature[0] ^= 1
				} else {
					grant.Purpose = "SYNTHETIC_UNAUTHORIZED_ADMIN"
					// Preserve canonical v1 claims and make a genuine Owner signature
					// over the unsupported purpose. This must exercise the purpose
					// guard independently from the forged-signature case above.
					encoded := must(json.Marshal(grant))
					end := bytes.LastIndex(encoded, []byte(`,"signature":`))
					if end < 0 {
						t.Fatal("synthetic grant claims framing unavailable")
					}
					claims := append(bytes.Clone(encoded[:end]), '}')
					signed := append([]byte("cicada/client/owner-device-grant/v1\x00"), claims...)
					grant.Signature = must(owner.Sign(signed))
					var signer mldsa65.PublicKey
					if signer.UnmarshalBinary(owner.Public().SigningPublic) != nil || !mldsa65.Verify(&signer, signed, nil, grant.Signature) {
						t.Fatal("unsupported-purpose fixture lacks a valid real Owner signature")
					}
				}
				req.OwnerDeviceGrant = must(json.Marshal(grant))
				refuseActivation(t, f, device, wire.OperationActivationPrepare, req)
				assertPristineAuthority(t, f)
				return
			}
			prep, ch, _, _ := prepareActivation(t, f, device, owner, 5*time.Minute)
			req := must(wire.NewActivationComplete(ch, f.cfg.Hub, device.Public(), owner, "synthetic-user", syntheticPassword, time.Now().UTC()))
			switch kind {
			case "missing-kem":
				possession := must(json.Marshal(ownerbootstrap.Possession{Format: ownerbootstrap.Format, Manifest: ch.Proof.Manifest, Nonce: make([]byte, 32)}))
				req.OwnerProof = must(ownerbootstrap.CreateProofFromPossessionWithPrivateOperations(owner.Public(), owner, ch.Proof, possession, time.Now().UTC()))
				clear(possession)
			case "missing-owner-signature":
				var inner clientwire.Packet
				if json.Unmarshal(req.OwnerProof, &inner) != nil {
					t.Fatal("proof packet decode failed")
				}
				var envelope map[string]json.RawMessage
				if json.Unmarshal(inner.Envelope, &envelope) != nil {
					t.Fatal("proof envelope decode failed")
				}
				delete(envelope, "signature")
				inner.Envelope = must(json.Marshal(envelope))
				req.OwnerProof = must(json.Marshal(inner))
			case "wrong-owner-signature":
				impostor := must(e2ee.NewIdentity())
				var inner clientwire.Packet
				if json.Unmarshal(req.OwnerProof, &inner) != nil {
					t.Fatal("proof packet decode failed")
				}
				var envelope e2ee.Envelope
				if json.Unmarshal(inner.Envelope, &envelope) != nil {
					t.Fatal("proof envelope decode failed")
				}
				envelope.Signature = must(impostor.Sign([]byte("SYNTHETIC other Owner signature")))
				inner.Envelope = must(json.Marshal(envelope))
				req.OwnerProof = must(json.Marshal(inner))
			case "reused-nonce":
				req.ClientNonce = bytes.Clone(prep.ClientNonce)
			case "stale-account-epoch":
				// Keep the genuinely issued epoch-1 packet intact while advancing
				// only this owned Hub's persisted epoch. This is a stale request,
				// rather than a malformed zero or a future-epoch substitution.
				f.hub.kill(t)
				db := must(sql.Open("sqlite", filepath.Join(f.dir, "hub", "synthetic.sqlite3")))
				if _, err := db.Exec(`UPDATE hub_account_config_v1 SET epoch=epoch+1 WHERE id=1`); err != nil {
					t.Fatal("owned stale-epoch fault failed")
				}
				db.Close()
				f.start(t)
			case "wrong-owner-scope":
				req.Binding.OwnerID = "synthetic-foreign-owner"
			case "wrong-app-key":
				impostor := must(e2ee.NewIdentity())
				packet := rawActivationPacket(t, f, impostor, wire.OperationActivationComplete, req.Binding.OwnerID, req.Binding.DeviceID, req.RequestID, req)
				refuseActivationPacket(t, f, impostor, wire.OperationActivationComplete, packet)
				assertPristineAuthority(t, f)
				return
			}
			refuseActivation(t, f, device, wire.OperationActivationComplete, req)
			assertPristineAuthority(t, f)
		})
	}
}

func TestN2ActivationConcurrentDistinctClaimsAndExactCompletion(t *testing.T) {
	f := newActivationFixture(t)
	devices := []*e2ee.Identity{must(e2ee.NewIdentity()), must(e2ee.NewIdentity())}
	owners := []*e2ee.Identity{must(e2ee.NewIdentity()), must(e2ee.NewIdentity())}
	requests := make([]wire.ActivationPrepare, 2)
	packets := make([][]byte, 2)
	for i := range devices {
		now := time.Now().UTC()
		id := wire.AccountDeviceIDPrefix + must(wire.NewRequestID())
		grant := must(owners[i].SignOwnerDeviceGrant(f.cfg.Card.OwnerID, id, devices[i].Public(), f.cfg.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(5*time.Minute)))
		requests[i] = must(wire.NewActivationPrepare(*f.cfg.Activation, f.cfg.Hub, devices[i].Public(), owners[i].Public(), id, grant, now))
		packets[i] = seal(t, f, devices[i], requests[i])
	}
	codes := make([]int, 2)
	responses := make([][]byte, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i], responses[i] = post(t, f, wire.ActivationHTTPPath(wire.OperationActivationPrepare), packets[i])
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	var challenge wire.ActivationChallenge
	for i := range devices {
		var ch wire.ActivationChallenge
		if codes[i] == 200 && wire.OpenClientResponse(devices[i], f.cfg.Hub, packets[i], responses[i], &ch) == nil {
			if winner != -1 {
				t.Fatal("two distinct Owner/App tuples won one material")
			}
			winner = i
			challenge = ch
		} else if codes[i] == 200 {
			var result wire.ActivationResult
			openWire(t, f, devices[i], packets[i], responses[i], &result)
			if result.State != wire.ActivationRejected && result.State != wire.ActivationCancelled {
				t.Fatal("loser was not durably rejected")
			}
		} else if codes[i] != 403 {
			t.Fatal("claim race failed at transport rather than authorization")
		}
	}
	if winner < 0 {
		t.Fatal("claim race had no winner")
	}
	f.restart(t)
	code, response := post(t, f, wire.ActivationHTTPPath(wire.OperationActivationPrepare), packets[winner])
	if code != 200 || !bytes.Equal(response, responses[winner]) {
		t.Fatal("winner exact challenge changed after SIGKILL")
	}
	req := must(wire.NewActivationComplete(challenge, f.cfg.Hub, devices[winner].Public(), owners[winner], "synthetic-user", syntheticPassword, time.Now().UTC()))
	packet := seal(t, f, devices[winner], req)
	accepted := make([][]byte, 2)
	for i := range accepted {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, raw := post(t, f, wire.ActivationHTTPPath(wire.OperationActivationComplete), packet)
			if code != 200 {
				t.Error("exact concurrent completion rejected")
			}
			accepted[i] = raw
		}(i)
	}
	wg.Wait()
	if !bytes.Equal(accepted[0], accepted[1]) {
		t.Fatal("exact duplicate completed twice with different receipts")
	}
	var result wire.ActivationResult
	openWire(t, f, devices[winner], packet, accepted[0], &result)
	if result.State != wire.ActivationCompleted {
		t.Fatal("winning completion did not commit")
	}
	if code, _ := post(t, f, wire.ActivationHTTPPath(wire.OperationActivationComplete), seal(t, f, devices[winner], req)); code != 403 {
		t.Fatal("same ID under different ciphertext replaced the committed result")
	}
	f.hub.kill(t)
	db := f.db(t)
	defer db.Close()
	status := must(db.HubAccountStatus(f.cfg.Card.AccountID))
	if !status.RootActive || status.OwnerPublic.ID != owners[winner].Public().ID || len(status.Devices) != 1 || status.Devices[0].DeviceID != requests[winner].DeviceID {
		t.Fatal("race failed atomic exact Root/account/device ownership")
	}
	if db.CheckAppLease(f.cfg.Card.OwnerID, requests[winner].DeviceID, "nodes.list") == nil {
		t.Fatal("activation alone bypassed ordinary account login")
	}
}

func TestN2ActivationExpiredProofAndCancelledMaterial(t *testing.T) {
	t.Run("expired-real-credential", func(t *testing.T) {
		f := newActivationFixture(t)
		f.hub.kill(t)
		// The public trusted-local Store API permits a shorter lifetime than the
		// CLI's one-hour default. Construct while valid, then wait for real expiry
		// before sending to the real Hub; client preflight is not the oracle.
		material := *f.cfg.Activation
		material.ActivationID = must(wire.NewRequestID())
		material.Code = base64.RawURLEncoding.EncodeToString(must(wire.NewNonce()))
		at := time.Now().UTC()
		expiry := at.Add(5 * time.Second)
		material.IssuedAt, material.ExpiresAt = at.Format(time.RFC3339Nano), expiry.Format(time.RFC3339Nano)
		db := f.db(t)
		if err := db.IssueHubActivationLocal(material, store.AccountDigest("activation-code", must(json.Marshal(material))), true); err != nil {
			t.Fatal("short synthetic credential issuance failed")
		}
		db.Close()
		f.cfg.Activation = &material
		device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
		id := wire.AccountDeviceIDPrefix + must(wire.NewRequestID())
		grant := must(owner.SignOwnerDeviceGrant(material.OwnerID, id, device.Public(), material.HubID, e2ee.OwnerDevicePurposeControl, at, at.Add(5*time.Minute)))
		request := must(wire.NewActivationPrepare(material, f.cfg.Hub, device.Public(), owner.Public(), id, grant, at))
		packet := rawActivationPacket(t, f, device, wire.OperationActivationPrepare, material.OwnerID, id, request.RequestID, request)
		f.start(t)
		time.Sleep(time.Until(expiry) + 30*time.Millisecond)
		refuseActivationPacket(t, f, device, wire.OperationActivationPrepare, packet)
		assertPristineAuthority(t, f)
	})
	t.Run("expired-real-proof-window", func(t *testing.T) {
		f := newActivationFixture(t)
		device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
		_, ch, _, _ := prepareActivation(t, f, device, owner, 5*time.Second)
		complete := must(wire.NewActivationComplete(ch, f.cfg.Hub, device.Public(), owner, "synthetic-user", syntheticPassword, time.Now().UTC()))
		expiry := must(time.Parse(time.RFC3339Nano, ch.ExpiresAt))
		time.Sleep(time.Until(expiry) + 30*time.Millisecond)
		refuseActivation(t, f, device, wire.OperationActivationComplete, complete)
		assertPristineAuthority(t, f)
	})
	t.Run("cancelled-material-and-late-request", func(t *testing.T) {
		f := newActivationFixture(t)
		device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
		_, ch, packet, _ := prepareActivation(t, f, device, owner, 5*time.Minute)
		complete := must(wire.NewActivationComplete(ch, f.cfg.Hub, device.Public(), owner, "synthetic-user", syntheticPassword, time.Now().UTC()))
		f.hub.kill(t)
		db := f.db(t)
		ids := must(hubidentity.LoadOrCreate(filepath.Join(f.dir, "hub"), ""))
		auth := must(hubauth.NewService(db, ids))
		must(auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true))
		db.Close()
		f.start(t)
		refuseActivation(t, f, device, wire.OperationActivationComplete, complete)
		code, response := post(t, f, wire.ActivationHTTPPath(wire.OperationActivationPrepare), packet)
		if code != 200 {
			t.Fatal("cancelled exact request lacks authenticated diagnostic")
		}
		var result wire.ActivationResult
		openWire(t, f, device, packet, response, &result)
		if result.State != wire.ActivationCancelled {
			t.Fatal("cancelled old material resumed authority")
		}
		assertPristineAuthority(t, f)
	})
}

func TestN2AccountReconcileFencesLateCorrectRequestAcrossRestart(t *testing.T) {
	f := newActivationFixture(t)
	device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	prep, ch, _, _ := prepareActivation(t, f, device, owner, 5*time.Minute)
	completeActivation(t, f, device, owner, ch)
	login := loginPrepare(t, f, device, prep.DeviceID)
	correct := must(wire.NewLoginComplete(f.cfg.Hub, login, syntheticPassword, time.Now().UTC()))
	held := seal(t, f, device, correct)
	// The original is intentionally still unsent: reconciliation must serialize
	// its rejection with a possible later original, rather than treating ABSENT as final.
	result := reconcile(t, f, device, prep.DeviceID, held)
	if result.State != wire.ActivationRejected {
		t.Fatal("uncommitted original did not acquire a durable operation+digest fence")
	}
	f.restart(t)
	if code, _ := post(t, f, "/v2/owner/account/login/complete", held); code != 403 {
		t.Fatal("late correct original committed after durable rejection")
	}
	fresh := must(wire.NewLoginComplete(f.cfg.Hub, login, syntheticPassword, time.Now().UTC()))
	packet := seal(t, f, device, fresh)
	code, response := post(t, f, "/v2/owner/account/login/complete", packet)
	if code != 200 {
		t.Fatal("fenced operation prevented a new correct login")
	}
	var session wire.SessionReceipt
	openWire(t, f, device, packet, response, &session)
	if result := reconcile(t, f, device, prep.DeviceID, packet); result.State != wire.ActivationCompleted || !bytes.Equal(result.ReceiptPacket, response) {
		t.Fatal("accepted new login did not reconcile to its exact original receipt")
	}
}

func TestN2ActivationHistoricalReceiptNeverRevivesCurrentAuthority(t *testing.T) {
	for _, kind := range []string{"root-revoked", "account-epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := newActivationFixture(t)
			device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
			prep, ch, _, _ := prepareActivation(t, f, device, owner, 5*time.Minute)
			_, packet, accepted := completeActivation(t, f, device, owner, ch)
			session := wireLogin(t, f, device, prep.DeviceID)
			f.hub.kill(t)
			db := f.db(t)
			if kind == "root-revoked" {
				must(db.RevokeOwnerApprovalKeyLocal(f.cfg.Card.OwnerID, owner.Public().ID, 1))
				db.Close()
			} else {
				db.Close()
				raw := must(sql.Open("sqlite", filepath.Join(f.dir, "hub", "synthetic.sqlite3")))
				_, err := raw.Exec(`UPDATE hub_account_config_v1 SET epoch=epoch+1,restore_receipt=? WHERE id=1`, strings.Repeat("a", 64))
				if err != nil {
					t.Fatal("owned epoch fault failed")
				}
				raw.Close()
			}
			f.start(t)
			status := activationStatus(t, f, device, packet)
			if status.LeaseState == wire.ActivationLeaseActive || status.RootState == wire.RootActiveState && kind == "root-revoked" || len(status.AllowedOperations) != 0 {
				t.Fatal("historical activation receipt revived current authority")
			}
			if kind == "root-revoked" && (!bytes.Equal(status.ReceiptPacket, accepted) || status.TargetState != wire.ActivationCompleted) {
				t.Fatal("revocation lost the diagnostic original receipt")
			}
			req := must(wire.NewSessionInspectRequest(session.Context(), time.Now().UTC()))
			code, _ := post(t, f, "/v2/owner/account/session/inspect", seal(t, f, device, req))
			if kind == "account-epoch" && code != 403 {
				t.Fatal("old account epoch authorized a fresh request")
			}
		})
	}
}

func syntheticOwnerImport(t *testing.T) *appcore.OwnerImport {
	t.Helper()
	root := os.Getenv("CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR")
	if root == "" {
		t.Skip("NOT_RUN: explicit fresh synthetic OpenSSL four-PEM fixture is required")
	}
	if !strings.Contains(root, "synthetic") {
		t.Fatal("Owner fixture path must be visibly synthetic")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal("synthetic Owner PEM unavailable")
		}
		t.Cleanup(func() { clear(b) })
		return b
	}
	return &appcore.OwnerImport{KEMPrivatePKCS8: read("kem-private.pem"), SigningPrivatePKCS8: read("signing-private.pem"), KEMPublicSPKI: read("kem-public.pem"), SigningPublicSPKI: read("signing-public.pem")}
}
func fixtureDevice(t *testing.T, f *fixture) *e2ee.Identity {
	return fixtureIdentity(t, f, appvault.PurposeAppDevice)
}
func fixtureIdentity(t *testing.T, f *fixture, purpose appvault.Purpose) *e2ee.Identity {
	t.Helper()
	m := f.cfg.Activation
	scope := appvault.Scope{HubID: m.HubID, HubFingerprint: m.HubFingerprint, Origin: m.Origin, AccountID: m.AccountID, OwnerID: m.OwnerID}
	raw := must(json.Marshal(scope))
	path := filepath.Join(f.dir, "n2-client", "app", digest(raw)+".vault")
	vault := must(appvault.Open(path, scope, must(appvault.NewPasswordProtector([]byte("Synthetic acceptance vault passphrase")))))
	defer vault.Close()
	for _, entry := range must(vault.List()) {
		if entry.Purpose == purpose {
			id := must(vault.Get(entry.Purpose, entry.KeyID))
			t.Cleanup(id.Close)
			return must(id.E2EE())
		}
	}
	t.Fatal("durable scoped key missing")
	return nil
}
func n2App(t *testing.T, f *fixture, step string, uncertain bool, expect string) appcore.Snapshot {
	t.Helper()
	// Reopen from the authenticated local profile with no installer material,
	// even though the parent retains its private issuer fixture for assertions.
	childConfig := f.cfg
	if step != "activate" {
		childConfig.Activation = nil
	}
	writeJSON(t, filepath.Join(f.dir, "synthetic-config.json"), childConfig)
	extra := []string{"CICADA_N2_PROXY=" + f.proxy.server.URL, "CICADA_N2_STEP=" + step, "CICADA_N2_EXPECT=" + expect}
	if uncertain {
		extra = append(extra, "CICADA_N2_UNCERTAIN=1")
	}
	marker := filepath.Join(f.dir, "app-n2-ready")
	process := spawn(t, f.dir, "app-n2", marker, extra...)
	process.kill(t)
	var snapshot appcore.Snapshot
	readJSON(t, marker, &snapshot)
	return snapshot
}
func runActivationAppProcess(t *testing.T, dir string, cfg fixtureConfig, marker string) {
	var clockOffset time.Duration
	transport := &countDoer{base: proxyDoer{os.Getenv("CICADA_N2_PROXY"), appcore.NewHTTPClient()}}
	c := newControllerWithClock(t, filepath.Join(dir, "n2-client"), transport, func() time.Time { return time.Now().UTC().Add(clockOffset) })
	defer c.Close()
	ctx := context.Background()
	step := os.Getenv("CICADA_N2_STEP")
	var err error
	if step == "activate" {
		if cfg.Activation == nil {
			t.Fatal("N2 material missing on first activation")
		}
		err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionConnect, ActivationCode: must(wire.EncodeActivationCode(*cfg.Activation))})
		if err != nil {
			t.Fatal("N2 App connect failed")
		}
		if !c.Snapshot().Setup.OwnerKeyStored {
			if cfg.Activation.Purpose == wire.PurposeLegacyContinuation {
				err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionImportOwner, OwnerImport: syntheticOwnerImport(t)})
			} else {
				err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionGenerateOwner})
			}
		}
		if err != nil {
			t.Fatal("N2 local Owner identity creation/import failed")
		}
		action := appcore.Action{Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true}
		if cfg.Activation.Purpose == wire.PurposeInitialActivation {
			action.Username, action.Password = "synthetic-user", syntheticPassword
		}
		err = c.Dispatch(ctx, action)
	} else {
		if c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionDiscoverProfiles}) != nil || len(c.Snapshot().Profiles) != 1 {
			t.Fatal("trusted encrypted profile discovery failed")
		}
		profile := c.Snapshot().Profiles[0]
		err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profile.ID})
		if step == "recover_status" || step == "recover" {
			if err != nil {
				err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionRecover})
			}
		} else if err != nil {
			t.Fatal("trusted profile resume failed")
		}
		if step == "continue" {
			action := appcore.Action{Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true}
			if c.Snapshot().Setup.Purpose == wire.PurposeInitialActivation {
				action.Username, action.Password = "synthetic-user", syntheticPassword
			}
			err = c.Dispatch(ctx, action)
		}
		if step == "login" || step == "wrong_password" {
			password := syntheticPassword
			if step == "wrong_password" {
				password = "Synthetic incorrect password 995!"
			}
			err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-user", Password: password})
		}
		if step == "logout" {
			err = c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionLogout})
		}
		if step == "deadline" {
			if err != nil || !c.Snapshot().Authorization.Confirmed {
				t.Fatal("clock test did not start from current authenticated authorization")
			}
			before := transport.calls.Load()
			clockOffset = 16 * time.Minute
			view := c.Snapshot()
			if view.Authorization.State != "EXPIRED" || view.Authorization.Confirmed || transport.calls.Load() != before {
				t.Fatal("local expiry renewed authority, used network or remained confirmed")
			}
		}
	}
	s := c.Snapshot()
	uncertain := os.Getenv("CICADA_N2_UNCERTAIN") == "1"
	if uncertain {
		if err == nil || (!hasAction(s, appcore.ActionRecover) && !hasAction(s, appcore.ActionRetry)) {
			t.Fatal("unsigned or missing response settled N2 pending operation")
		}
		if c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-user", Password: syntheticPassword}) == nil {
			t.Fatal("uncertainty permitted a replacement login")
		}
	} else if err != nil {
		t.Fatal("N2 native core operation or authenticated recovery failed")
	}
	s = c.Snapshot()
	if s.Management != appcore.ManagementUnavailable {
		t.Fatal("N2 finite enrollment fabricated general Manager authority")
	}
	switch os.Getenv("CICADA_N2_EXPECT") {
	case "root":
		if s.Account.RootState != appcore.RootStateActive || s.Authorization.Confirmed {
			t.Fatal("Root proof and account login were conflated")
		}
	case "active":
		if s.Account.RootState != appcore.RootStateActive || s.Authorization.State != "ACTIVE" || !s.Authorization.Confirmed || !reflect.DeepEqual(s.Authorization.AllowedOperations, wire.ActivationAllowedOperations()) {
			t.Fatal("native App did not verify current exact finite authorization")
		}
	case "pending":
		if s.Account.RootState == appcore.RootStateActive || s.Authorization.Confirmed {
			t.Fatal("unconfirmed prepare activated authority")
		}
	case "login":
		if !hasAction(s, appcore.ActionLogin) || s.Authorization.Confirmed {
			t.Fatal("authenticated fence did not permit safe re-login")
		}
	case "expired":
		if s.Authorization.State != "EXPIRED" || s.Authorization.Confirmed {
			t.Fatal("App clock expiry retained finite authority")
		}
	case "uncertain":
		if (!hasAction(s, appcore.ActionRecover) && !hasAction(s, appcore.ActionRetry)) || hasAction(s, appcore.ActionActivateApp) || hasAction(s, appcore.ActionLogin) || s.Authorization.Confirmed {
			t.Fatal("ABSENT status cleared or replaced the uncertain original")
		}
	case "no-revival":
		if s.Authorization.Confirmed {
			t.Fatal("obsolete epoch session was published as confirmed authority")
		}
		if hasAction(s, appcore.ActionSessionInspect) {
			t.Fatalf("obsolete session remained present: account=%s root=%s authorization=%s actions=%v", s.Account.State, s.Account.RootState, s.Authorization.State, s.AvailableActions)
		}
		if !hasAction(s, appcore.ActionLogin) {
			t.Fatalf("settled old receipt did not allow account re-login: account=%s root=%s authorization=%s confirmed=%t actions=%v", s.Account.State, s.Account.RootState, s.Authorization.State, s.Authorization.Confirmed, s.AvailableActions)
		}
	case "revoked":
		if s.Authorization.Confirmed || s.Authorization.State != wire.ActivationLeaseRevoked {
			t.Fatal("new account login renewed a restored/revoked N2 lease")
		}
	case "terminal":
		if hasAction(s, appcore.ActionRecover) || hasAction(s, appcore.ActionRetry) || s.Authorization.Confirmed {
			t.Fatal("authenticated cancellation left an uncertain operation or active authority")
		}
	}
	writeJSON(t, marker, s)
}

type countDoer struct {
	base  appcore.HTTPDoer
	calls atomic.Int32
}

func (d *countDoer) Do(r *http.Request) (*http.Response, error) { d.calls.Add(1); return d.base.Do(r) }

func TestN2ActivationPinAndConsentBeforeSecrets(t *testing.T) {
	f := newActivationFixture(t)
	for _, kind := range []string{"wrong-full-pin", "expired", "missing-finite-consent"} {
		t.Run(kind, func(t *testing.T) {
			material := *f.cfg.Activation
			if kind == "wrong-full-pin" {
				other := f.cfg.Hub
				other.Public = must(e2ee.NewIdentity()).Public()
				material.HubFingerprint = must(wire.HubFingerprint(other))
			}
			if kind == "expired" {
				at := time.Now().UTC()
				material.IssuedAt = at.Add(-2 * time.Hour).Format(time.RFC3339Nano)
				material.ExpiresAt = at.Add(-time.Hour).Format(time.RFC3339Nano)
			}
			if kind == "missing-finite-consent" {
				c := newController(t, t.TempDir(), proxyDoer{f.proxy.server.URL, appcore.NewHTTPClient()})
				defer c.Close()
				if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionConnect, ActivationCode: must(wire.EncodeActivationCode(material))}) != nil || c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionGenerateOwner}) != nil {
					t.Fatal("consent fixture could not connect/store Owner")
				}
				if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionActivateApp, Username: "synthetic-user", Password: syntheticPassword}) == nil {
					t.Fatal("activation proceeded without exact finite-scope consent")
				}
			} else {
				opened := 0
				opener := func(context.Context, appvault.Scope, bool) (*appvault.Vault, error) {
					opened++
					return nil, appvault.ErrStateNotFound
				}
				c := must(appcore.NewController(appcore.Config{HTTP: proxyDoer{f.proxy.server.URL, appcore.NewHTTPClient()}, OpenVault: opener, AllowLoopbackHTTP: true}))
				defer c.Close()
				if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionConnect, ActivationCode: must(wire.EncodeActivationCode(material))}) == nil || opened != 0 || c.Snapshot().Hub.Verified {
					t.Fatal("untrusted activation material sent secrets or opened the vault")
				}
			}
			if len(f.proxy.snapshot()) != 0 {
				t.Fatal("pin/expiry/consent rejection sent a secret-bearing POST")
			}
		})
	}
}

func TestN2ActivationAppClockExpiryDoesNotRenewLease(t *testing.T) {
	f := newActivationFixture(t)
	n2App(t, f, "activate", false, "root")
	n2App(t, f, "login", false, "active")
	n2App(t, f, "deadline", false, "expired")
}

func TestN2ActivationVaultFailureBeforeSend(t *testing.T) {
	f := newActivationFixture(t)
	actor := t.TempDir()
	c := newController(t, actor, proxyDoer{f.proxy.server.URL, appcore.NewHTTPClient()})
	defer c.Close()
	if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionConnect, ActivationCode: must(wire.EncodeActivationCode(*f.cfg.Activation))}) != nil || c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionGenerateOwner}) != nil {
		t.Fatal("persistent vault fault setup failed")
	}
	directory := filepath.Join(actor, "app")
	held := directory + "-held"
	if os.Rename(directory, held) != nil {
		t.Fatal("owned vault directory could not be faulted")
	}
	if os.WriteFile(directory, []byte("SYNTHETIC non-directory persistence fault"), 0600) != nil {
		t.Fatal("owned persistence fault write failed")
	}
	t.Cleanup(func() { _ = os.Remove(directory); _ = os.Rename(held, directory) })
	if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: syntheticPassword}) == nil {
		t.Fatal("activation succeeded without durable packet storage")
	}
	if len(f.proxy.snapshot()) != 0 || c.Snapshot().Authorization.Confirmed {
		t.Fatal("memory-only activation packet escaped failed vault commit")
	}
	assertPristineAuthority(t, f)
}

func TestN2ActivationTwoHubVaultScopesRemainIndependent(t *testing.T) {
	one, two := newActivationFixture(t), newActivationFixture(t)
	actor := t.TempDir()
	activate := func(f *fixture) appcore.Snapshot {
		c := newController(t, actor, appcore.NewHTTPClient())
		defer c.Close()
		ctx := context.Background()
		if c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionConnect, ActivationCode: must(wire.EncodeActivationCode(*f.cfg.Activation))}) != nil {
			t.Fatal("Hub-scoped connect failed")
		}
		if c.Snapshot().Account.LocalOwnerKeyPresent || c.Snapshot().Authorization.Confirmed {
			t.Fatal("second Hub inherited the first Hub's Owner/session authorization")
		}
		if c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionGenerateOwner}) != nil || c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "synthetic-user", Password: syntheticPassword}) != nil || c.Dispatch(ctx, appcore.Action{Kind: appcore.ActionLogin, Username: "synthetic-user", Password: syntheticPassword}) != nil {
			t.Fatal("independent Hub activation/login failed")
		}
		return c.Snapshot()
	}
	first, second := activate(one), activate(two)
	if first.Hub.Fingerprint == second.Hub.Fingerprint || first.Account.DeviceID == second.Account.DeviceID || first.Account.OwnerFingerprint == second.Account.OwnerFingerprint {
		t.Fatal("Hub scopes reused device/Owner identities")
	}
	c := newController(t, actor, appcore.NewHTTPClient())
	defer c.Close()
	if c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionDiscoverProfiles}) != nil || len(c.Snapshot().Profiles) != 2 {
		t.Fatal("two encrypted Hub profiles were collapsed")
	}
	var selected string
	for _, p := range c.Snapshot().Profiles {
		if p.Origin == one.cfg.Origin {
			selected = p.ID
		}
	}
	if selected == "" || c.Dispatch(context.Background(), appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: selected}) != nil || c.Snapshot().Account.DeviceID != first.Account.DeviceID || c.Snapshot().Hub.Fingerprint != first.Hub.Fingerprint {
		t.Fatal("profile selection crossed Hub identity/session scope")
	}
}

func TestN2ActivationAppProcessesAndLargeStatusRecovery(t *testing.T) {
	for _, mode := range []string{"drop", "unsigned403", "corrupt"} {
		for _, target := range []string{"prepare", "complete", "status"} {
			t.Run(mode+"/"+target, func(t *testing.T) {
				f := newActivationFixture(t)
				path := wire.ActivationHTTPPath(map[string]string{"prepare": wire.OperationActivationPrepare, "complete": wire.OperationActivationComplete, "status": wire.OperationActivationStatus}[target])
				f.proxy.arm(mode, path)
				first := n2App(t, f, "activate", true, "")
				trace := f.proxy.snapshot()
				var original exchange
				for _, ex := range trace {
					if ex.Path == path {
						original = ex
						break
					}
				}
				if original.Status != 200 {
					t.Fatal("response fault did not occur after actual Hub commit")
				}
				f.restart(t)
				if target != "status" {
					f.proxy.armCount("before", path, 2)
				}
				expected := "root"
				if target == "prepare" {
					expected = "pending"
				}
				reopened := n2App(t, f, "recover_status", false, expected)
				if reopened.Account.DeviceID != first.Account.DeviceID || reopened.Account.AccountID != first.Account.AccountID || reopened.Account.OwnerID != first.Account.OwnerID {
					t.Fatal("restart changed stable account/Owner/App identity")
				}
				device := fixtureDevice(t, f)
				after := f.proxy.snapshot()
				found := false
				for _, ex := range after[len(trace):] {
					if ex.Path == wire.ActivationHTTPPath(wire.OperationActivationStatus) && ex.Status == 200 {
						var status wire.ActivationResult
						openWire(t, f, device, ex.request, ex.response, &status)
						if status.TargetPacketDigest == wire.ActivationPacketDigest(original.request) && status.TargetState == wire.ActivationCompleted {
							if !bytes.Equal(status.ReceiptPacket, original.response) {
								t.Fatal("status did not carry byte-identical original authenticated response")
							}
							found = true
						}
					}
				}
				if target != "status" && !found {
					t.Fatal("recovery did not traverse actual status with nested original receipt")
				}
				if target == "status" {
					exact := false
					for _, ex := range after[len(trace):] {
						if ex.Path == path && bytes.Equal(ex.request, original.request) && bytes.Equal(ex.response, original.response) {
							exact = true
						}
					}
					if !exact {
						t.Fatal("uncertain status query was replaced before exact recovery")
					}
				}
				if target == "prepare" {
					if len(original.response) <= 96*1024 {
						t.Fatal("prepare fixture did not exercise the real large PQ challenge regression")
					}
					n2App(t, f, "continue", false, "root")
				}
				n2App(t, f, "login", false, "active")
				f.restart(t)
				n2App(t, f, "resume", false, "active")
			})
		}
	}
}

func TestN2ActivationAppWrongPasswordFenceAndRelogin(t *testing.T) {
	f := newActivationFixture(t)
	n2App(t, f, "activate", false, "root")
	n2App(t, f, "wrong_password", true, "")
	before := f.proxy.snapshot()
	var failed exchange
	for _, ex := range before {
		if ex.Path == "/v2/owner/account/login/complete" {
			failed = ex
		}
	}
	if failed.Status != 403 {
		t.Fatal("wrong password did not reach real Hub rejection")
	}
	f.restart(t)
	n2App(t, f, "recover", false, "login")
	found := false
	for _, ex := range f.proxy.snapshot()[len(before):] {
		if ex.Path == wire.ActivationHTTPPath(wire.OperationAccountReconcile) && ex.Status == 200 {
			found = true
		}
	}
	if !found {
		t.Fatal("native App cleared rejected login without authenticated reconciliation")
	}
	n2App(t, f, "login", false, "active")
	if code, _ := post(t, f, "/v2/owner/account/login/complete", failed.request); code != 403 {
		t.Fatal("new login revived the fenced old operation")
	}
	// Session revocation is an isolated persisted fault; no epoch/key/credential changes.
	f.hub.kill(t)
	raw := must(sql.Open("sqlite", filepath.Join(f.dir, "hub", "synthetic.sqlite3")))
	if _, err := raw.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE state='ACTIVE'`); err != nil {
		t.Fatal("fixture session revocation failed")
	}
	raw.Close()
	f.start(t)
	n2App(t, f, "recover", false, "login")
	n2App(t, f, "login", false, "active")
}

func TestN2ActivationAbsentStatusKeepsPendingUntilLateOriginal(t *testing.T) {
	f := newActivationFixture(t)
	path := wire.ActivationHTTPPath(wire.OperationActivationComplete)
	f.proxy.arm("before", path)
	n2App(t, f, "activate", true, "pending")
	var original exchange
	for _, ex := range f.proxy.snapshot() {
		if ex.Path == path {
			original = ex
		}
	}
	if original.Forwarded || len(original.request) == 0 {
		t.Fatal("ABSENT fixture accidentally committed original completion")
	}
	f.restart(t)
	f.proxy.armCount("before", path, 2)
	n2App(t, f, "recover_status", false, "uncertain")
	device := fixtureDevice(t, f)
	observed := false
	for _, ex := range f.proxy.snapshot() {
		if ex.Path == wire.ActivationHTTPPath(wire.OperationActivationStatus) && ex.Status == 200 {
			var result wire.ActivationResult
			openWire(t, f, device, ex.request, ex.response, &result)
			if result.TargetPacketDigest == wire.ActivationPacketDigest(original.request) && result.TargetState == wire.ActivationAbsent && len(result.ReceiptPacket) == 0 {
				observed = true
			}
		}
	}
	if !observed {
		t.Fatal("actual signed ABSENT status was not exercised")
	}
	assertPristineAuthority(t, f)
	code, response := post(t, f, path, original.request)
	if code != 200 {
		t.Fatal("late unfenced original could not commit")
	}
	var result wire.ActivationResult
	openWire(t, f, device, original.request, response, &result)
	if result.State != wire.ActivationCompleted {
		t.Fatal("late original did not finish the single reserved activation")
	}
	n2App(t, f, "recover_status", false, "root")
	n2App(t, f, "login", false, "active")
}

func TestN2ActivationAppRestoreEpochSettlesOldReceiptWithoutRevival(t *testing.T) {
	f := newActivationFixture(t)
	n2App(t, f, "activate", false, "root")
	f.proxy.arm("drop", "/v2/owner/account/login/complete")
	n2App(t, f, "login", true, "")
	var original exchange
	for _, ex := range f.proxy.snapshot() {
		if ex.Path == "/v2/owner/account/login/complete" {
			original = ex
		}
	}
	if original.Status != 200 {
		t.Fatal("restore fixture did not lose a genuinely accepted session receipt")
	}
	f.hub.kill(t)
	raw := must(sql.Open("sqlite", filepath.Join(f.dir, "hub", "synthetic.sqlite3")))
	tx := must(raw.Begin())
	for _, statement := range []string{`UPDATE hub_account_config_v1 SET epoch=epoch+1,restore_receipt='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' WHERE id=1`, `UPDATE hub_account_sessions_v1 SET state='REVOKED' WHERE state='ACTIVE'`, `UPDATE hub_app_leases_v1 SET state='REVOKED' WHERE state='ACTIVE'`} {
		if _, err := tx.Exec(statement); err != nil {
			t.Fatal("owned restore epoch fault failed")
		}
	}
	if tx.Commit() != nil {
		t.Fatal("owned restore epoch fault commit failed")
	}
	raw.Close()
	f.start(t)
	n2App(t, f, "recover", false, "no-revival")
	device := fixtureDevice(t, f)
	found := false
	for _, ex := range f.proxy.snapshot() {
		if ex.Path == wire.ActivationHTTPPath(wire.OperationAccountReconcile) && ex.Status == 200 {
			var observed wire.AccountReconcileResult
			openWire(t, f, device, ex.request, ex.response, &observed)
			if observed.OriginalPacketDigest == wire.ActivationPacketDigest(original.request) && observed.State == wire.ActivationCompleted {
				var cached wire.SessionReceipt
				openWire(t, f, device, original.request, observed.ReceiptPacket, &cached)
				if !bytes.Equal(observed.ReceiptPacket, original.response) || observed.AccountEpoch <= cached.AccountEpoch {
					t.Fatal("restore fixture lacked authenticated current epoch plus exact old receipt")
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("current-epoch reconciliation did not exercise an old COMPLETED session receipt")
	}
	n2App(t, f, "login", false, "revoked")
}

func TestN2ActivationLegacyImportedOwnerKeepsCredentialAndIDs(t *testing.T) {
	input := syntheticOwnerImport(t)
	identity := must(appkeys.ImportOwner(appkeys.ImportOwnerPEM{KEMPrivatePKCS8: input.KEMPrivatePKCS8, SigningPrivatePKCS8: input.SigningPrivatePKCS8, KEMPublicSPKI: input.KEMPublicSPKI, SigningPublicSPKI: input.SigningPublicSPKI}))
	defer identity.Close()
	owner := must(identity.E2EE())
	f := newFixture(t)
	device := must(e2ee.NewIdentity())
	prepare := must(wire.NewClaimPrepare(f.cfg.Card, f.cfg.Hub, device.Public(), time.Now().UTC()))
	packet := seal(t, f, device, prepare)
	code, response := post(t, f, "/v2/owner/account/claim/prepare", packet)
	if code != 200 {
		t.Fatal("legacy account prepare failed")
	}
	var ch wire.ClaimChallenge
	openWire(t, f, device, packet, response, &ch)
	complete := must(wire.NewClaimCompleteFromChallenge(f.cfg.Hub, ch, device.Public(), "synthetic-user", syntheticPassword, owner.Public(), time.Now().UTC()))
	packet = seal(t, f, device, complete)
	code, response = post(t, f, "/v2/owner/account/claim/complete", packet)
	if code != 200 {
		t.Fatal("legacy pending account claim failed")
	}
	var receipt wire.ClaimReceipt
	openWire(t, f, device, packet, response, &receipt)
	if receipt.RootActive || receipt.RootState != wire.RootPendingState {
		t.Fatal("legacy account claim already activated Root")
	}
	f.hub.kill(t)
	db := f.db(t)
	before := must(db.HubAccountCredential(f.cfg.Card.AccountID))
	beforeSetup, _, err := db.HubAccountSetup()
	if err != nil {
		t.Fatal("legacy setup unavailable")
	}
	db.Close()
	f.start(t)
	issueContinuation(t, f, owner)
	// Bypass the App constructor's local expected-key check using the existing
	// lower-level wire sealer, so this is a genuine Hub negative test.
	attacker, otherApp := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	now := time.Now().UTC()
	id := wire.AccountDeviceIDPrefix + must(wire.NewRequestID())
	grant := must(owner.SignOwnerDeviceGrant(f.cfg.Card.OwnerID, id, otherApp.Public(), f.cfg.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(5*time.Minute)))
	request := must(wire.NewActivationPrepare(*f.cfg.Activation, f.cfg.Hub, otherApp.Public(), owner.Public(), id, grant, now))
	request.OwnerPublic = attacker.Public()
	request.OwnerDeviceGrant = must(attacker.SignOwnerDeviceGrant(f.cfg.Card.OwnerID, id, otherApp.Public(), f.cfg.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(5*time.Minute)))
	binding, route, err := wire.RequestRoute(f.cfg.Hub, f.cfg.Card.OwnerID, id, request.RequestID, wire.OperationActivationPrepare, wire.HandshakeEpoch, otherApp.Public())
	if err != nil {
		t.Fatal("legacy negative wire route invalid")
	}
	sealed := must(clientwire.SealRequest(otherApp, f.cfg.Hub.Public, binding, route, must(json.Marshal(request))))
	var inner clientwire.Packet
	if json.Unmarshal(sealed, &inner) != nil {
		t.Fatal("legacy wire packet decode failed")
	}
	outer := must(json.Marshal(wire.Packet{Format: wire.PacketFormat, Version: wire.PacketVersion, SenderPublicIdentity: otherApp.Public(), Packet: inner}))
	statusCode, _ := post(t, f, wire.ActivationHTTPPath(wire.OperationActivationPrepare), outer)
	if statusCode != 403 {
		t.Fatal("Hub accepted an unknown replacement Owner under exact legacy continuation")
	}
	result := n2App(t, f, "activate", false, "root")
	n2App(t, f, "login", false, "active")
	f.hub.kill(t)
	db = f.db(t)
	defer db.Close()
	after := must(db.HubAccountCredential(f.cfg.Card.AccountID))
	status := must(db.HubAccountStatus(f.cfg.Card.AccountID))
	oldDevice := must(db.HubAccountDevice(f.cfg.Card.AccountID, prepare.DeviceID))
	afterSetup, _, err := db.HubAccountSetup()
	if err != nil || !reflect.DeepEqual(before, after) || beforeSetup.OwnerID != afterSetup.OwnerID || beforeSetup.AccountID != afterSetup.AccountID || status.OwnerPublic.ID != owner.Public().ID || len(status.Devices) != 2 || result.Account.OwnerFingerprint != ownerbootstrap.Fingerprint(owner.Public()) || !reflect.DeepEqual(oldDevice.Public, device.Public()) || oldDevice.Epoch != 1 {
		t.Fatal("legacy continuation changed existing Owner/account/key/credential or replaced prior device")
	}
}

func TestN2ActivationReplacementAfterFencedCancellationPreservesKeys(t *testing.T) {
	f := newActivationFixture(t)
	f.proxy.arm("drop", wire.ActivationHTTPPath(wire.OperationActivationPrepare))
	first := n2App(t, f, "activate", true, "")
	oldOwner, oldDevice := fixtureIdentity(t, f, appvault.PurposeOwnerSigner), fixtureDevice(t, f)
	f.hub.kill(t)
	db := f.db(t)
	ids := must(hubidentity.LoadOrCreate(filepath.Join(f.dir, "hub"), ""))
	auth := must(hubauth.NewService(db, ids))
	f.cfg.Activation = must(auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true))
	db.Close()
	f.start(t)
	n2App(t, f, "recover", false, "terminal")
	replaced := n2App(t, f, "activate", false, "root")
	n2App(t, f, "login", false, "active")
	if replaced.Account.DeviceID != first.Account.DeviceID || !reflect.DeepEqual(fixtureDevice(t, f).Public(), oldDevice.Public()) || !reflect.DeepEqual(fixtureIdentity(t, f, appvault.PurposeOwnerSigner).Public(), oldOwner.Public()) {
		t.Fatal("trusted operator replacement changed existing Owner/App key or device identity")
	}
}
