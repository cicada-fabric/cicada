package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

type appBindingFixture struct {
	hubKey, device, owner *e2ee.Identity
	hub                   HubIdentity
	now                   time.Time
	prepare               any
	packet                []byte
	challenge             AppBindingChallenge
	nonceDigest           string
}

func newAppBindingFixture(t *testing.T, purpose string) appBindingFixture {
	t.Helper()
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	h, d, o, card := accountFixture(t, now)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: h.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	fp, _ := e2ee.OwnerDevicePublicKeyFingerprint(d.Public())
	session := SessionContext{Origin: card.Origin, HubID: hub.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID, DeviceID: AccountDeviceIDPrefix + strings.Repeat("a", 32), DeviceKeyID: d.Public().ID, DeviceKeyFingerprint: fp, SessionToken: bytes.Repeat([]byte{0x43}, 32), AccountEpoch: 1, DeviceEpoch: 1, ExpiresAt: formatUTC(now.Add(15 * time.Minute))}
	var q any
	var err error
	if purpose == AppBindingPurposeUnbind {
		q, err = NewAppUnbindPrepare(session, o.Public(), now)
	} else {
		q, err = NewAppRebindPrepare(hub, card.Origin, card.AccountID, card.OwnerID, session.DeviceID, strings.Repeat("cd", 32), AccountDeviceIDPrefix+strings.Repeat("b", 32), o.Public(), now)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealClientRequest(d, hub, q)
	if err != nil {
		t.Fatal(err)
	}
	op, id, owner, device, _, _ := appBindingMetadata(q)
	nonce := []byte(nil)
	switch v := q.(type) {
	case AppUnbindPrepare:
		nonce = v.ClientNonce
	case AppRebindPrepare:
		nonce = v.ClientNonce
	}
	b := AppBinding{Format: AppBindingFormat, Purpose: purpose, Origin: card.Origin, HubID: hub.HubID, HubFingerprint: card.HubFingerprint, AccountID: card.AccountID, OwnerID: owner, OwnerPublic: o.Public(), OwnerKeyVersion: 1, AccountEpoch: 1, CredentialVersion: 1, DeviceID: device, DevicePublic: d.Public(), DeviceEpoch: 1, ClientDeviceVersion: 1, ClientSessionEpoch: 1, PrepareRequestID: id, PreparePacketDigest: AppBindingPacketDigest(raw), IssuedAt: formatUTC(now), ExpiresAt: formatUTC(now.Add(MaxAppBindingChallengeLifetime))}
	if purpose == AppBindingPurposeUnbind {
		b.SessionID = "synthetic-account-session"
	} else {
		v := q.(AppRebindPrepare)
		b.PreviousDeviceID, b.UnbindBindingDigest = v.PreviousDeviceID, v.UnbindBindingDigest
	}
	p := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: b.Origin, AllowLoopbackHTTP: card.AllowLoopbackHTTP, Hub: hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: b.AccountID, OwnerID: b.OwnerID, HubID: b.HubID, AuthorityID: id, OperationID: b.Digest(), CandidatePublic: o.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(o.Public()), ExpiresAt: b.ExpiresAt}}
	p, digest, err := ownerbootstrap.CreateChallenge(h, p, now)
	if err != nil {
		t.Fatal(err)
	}
	serverNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	ch := AppBindingChallenge{Format: AppBindingChallengeFormat, Operation: op, RequestID: id, RequestPacketDigest: b.PreparePacketDigest, Binding: b, ClientNonce: nonce, ServerNonce: serverNonce, Proof: p}
	return appBindingFixture{h, d, o, hub, now, q, raw, ch, digest}
}

func TestAppBindingWireOwnerProofAndExactResponse(t *testing.T) {
	for _, purpose := range []string{AppBindingPurposeUnbind, AppBindingPurposeRebind} {
		t.Run(purpose, func(t *testing.T) {
			f := newAppBindingFixture(t, purpose)
			if err := ValidateAppBindingPreparedResponse(f.prepare, f.packet, f.challenge, f.hub, f.now); err != nil {
				t.Fatal(err)
			}
			_, route, err := NewClientRoute(f.hub, f.prepare, f.device.Public())
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := SealResponse(f.hubKey, f.device.Public(), route, f.challenge)
			if err != nil {
				t.Fatal(err)
			}
			var ch AppBindingChallenge
			if err = OpenClientResponse(f.device, f.hub, f.packet, sealed, &ch); err != nil {
				t.Fatal(err)
			}
			proof, err := ownerbootstrap.CreateProof(f.owner, ch.Proof, f.now)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(proof)
			if digest, e := ownerbootstrap.VerifyProof(f.hubKey, ch.Proof, proof, f.now); e != nil || digest != f.nonceDigest {
				t.Fatal("actual current Owner KEM/signing proof", e)
			}
			complete, err := NewAppBindingComplete(f.packet, ch, proof, f.now)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := SealClientRequest(f.device, f.hub, complete)
			if err != nil {
				t.Fatal(err)
			}
			binding, route, err := NewClientRoute(f.hub, complete, f.device.Public())
			if err != nil {
				t.Fatal(err)
			}
			var opened AppBindingComplete
			if err = OpenRequestAt(f.hubKey, &ch.Binding.DevicePublic, binding, route, raw, &opened, f.now); err != nil {
				t.Fatal(err)
			}
			result := AppBindingResult{Format: AppBindingResultFormat, Operation: route.Operation, RequestID: complete.RequestID, RequestPacketDigest: AppBindingPacketDigest(raw), State: AppBindingUnbound, BindingDigest: complete.Binding.Digest(), DeviceID: complete.Binding.DeviceID, DeviceEpoch: 2, ClientDeviceVersion: 2, ClientSessionEpoch: 2, ObservedAt: formatUTC(f.now)}
			if purpose == AppBindingPurposeRebind {
				result.State = AppBindingBoundZero
				result.DeviceEpoch, result.ClientDeviceVersion, result.ClientSessionEpoch = 1, 1, 1
			}
			receipt, err := SealResponse(f.hubKey, f.device.Public(), route, result)
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < 2; n++ {
				var got AppBindingResult
				if err = OpenClientResponse(f.device, f.hub, raw, receipt, &got); err != nil || ValidateAppBindingResultTarget(got, raw, complete.Binding) != nil {
					t.Fatal("exact sealed receipt", err)
				}
			}
			late := f.now.Add(3 * time.Minute)
			if OpenRequestAt(f.hubKey, &ch.Binding.DevicePublic, binding, route, raw, &opened, late) == nil {
				t.Fatal("late original admitted as fresh")
			}
			if err = OpenRequestAt(f.hubKey, &ch.Binding.DevicePublic, binding, route, raw, &opened, time.Time{}); err != nil {
				t.Fatal("historical authentication unavailable", err)
			}
			result.State, result.ErrorCode = AppBindingRejected, "EXPIRED"
			receipt, err = SealResponse(f.hubKey, f.device.Public(), route, result)
			if err != nil {
				t.Fatal(err)
			}
			var rejected AppBindingResult
			if err = OpenClientResponse(f.device, f.hub, raw, receipt, &rejected); err != nil || ValidateAppBindingResultTarget(rejected, raw, complete.Binding) != nil {
				t.Fatal("typed expired/no-effect original cannot settle", err)
			}
			bad := rejected
			bad.RequestPacketDigest = strings.Repeat("0", 64)
			receipt, err = SealResponse(f.hubKey, f.device.Public(), route, bad)
			if err != nil {
				t.Fatal(err)
			}
			if OpenClientResponse(f.device, f.hub, raw, receipt, &rejected) == nil {
				t.Fatal("another ciphertext's result accepted")
			}
		})
	}
}

func TestAppBindingScopeAndPurposeRefuseChanges(t *testing.T) {
	f := newAppBindingFixture(t, AppBindingPurposeRebind)
	for name, mutate := range map[string]func(*AppBindingChallenge){
		"previous_device": func(c *AppBindingChallenge) {
			c.Binding.PreviousDeviceID = AccountDeviceIDPrefix + strings.Repeat("c", 32)
		},
		"old_unbind":    func(c *AppBindingChallenge) { c.Binding.UnbindBindingDigest = strings.Repeat("ab", 32) },
		"account_epoch": func(c *AppBindingChallenge) { c.Binding.AccountEpoch++ },
		"owner":         func(c *AppBindingChallenge) { c.Binding.OwnerPublic = f.device.Public() },
		"purpose":       func(c *AppBindingChallenge) { c.Binding.Purpose = AppBindingPurposeUnbind },
		"prepare":       func(c *AppBindingChallenge) { c.RequestPacketDigest = strings.Repeat("0", 64) },
		"nonce":         func(c *AppBindingChallenge) { c.ClientNonce = bytes.Repeat([]byte{0x21}, 32) },
		"deadline":      func(c *AppBindingChallenge) { c.Binding.ExpiresAt = formatUTC(f.now.Add(time.Hour)) },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(f.challenge)
			var bad AppBindingChallenge
			if json.Unmarshal(raw, &bad) != nil {
				t.Fatal("fixture clone")
			}
			mutate(&bad)
			if ValidateAppBindingPreparedResponse(f.prepare, f.packet, bad, f.hub, f.now) == nil {
				t.Fatal("changed proof scope accepted")
			}
		})
	}
	q := f.prepare.(AppRebindPrepare)
	q.DeviceID = q.PreviousDeviceID
	if _, err := SealClientRequest(f.device, f.hub, q); err == nil {
		t.Fatal("same retired device ID allowed")
	}
	if _, err := NewAppBindingComplete(f.packet, f.challenge, []byte("synthetic"), f.now.Add(3*time.Minute)); err == nil {
		t.Fatal("new complete prepared beyond original deadline")
	}
}

func TestAppBindingManifestClosesPublicFieldsAndOps(t *testing.T) {
	raw, err := os.ReadFile("app-hub-binding-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Contract   string `json:"contract"`
		Operations []struct{ Operation, Path string }
		Fields     map[string][]string `json:"fields"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Contract != AppBindingContract || len(m.Operations) != 4 {
		t.Fatal("contract inventory")
	}
	for _, op := range m.Operations {
		if op.Path != AppBindingHTTPPath(op.Operation) || !knownOperation(op.Operation) {
			t.Fatal("operation drift")
		}
	}
	for name, value := range map[string]any{"AppUnbindPrepare": AppUnbindPrepare{}, "AppRebindPrepare": AppRebindPrepare{}, "AppBinding": AppBinding{}, "AppBindingChallenge": AppBindingChallenge{}, "AppBindingComplete": AppBindingComplete{}, "AppBindingResult": AppBindingResult{}, "AppBindingCapabilities": AppBindingCapabilities{}} {
		typeOf := reflect.TypeOf(value)
		fields := []string{}
		for i := 0; i < typeOf.NumField(); i++ {
			fields = append(fields, typeOf.Field(i).Tag.Get("json"))
		}
		if !reflect.DeepEqual(fields, m.Fields[name]) {
			t.Fatal("public fields drift", name)
		}
	}
	if got := AppBindingContractCapabilities(); len(got.Operations) != 4 || got.Recovery != "BYTE_IDENTICAL_ORIGINAL_ONLY" {
		t.Fatal("capability drift")
	}
}
