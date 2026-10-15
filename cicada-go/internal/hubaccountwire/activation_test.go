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

func TestActivationManifestMatchesWire(t *testing.T) {
	raw, err := os.ReadFile("activation-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		PacketFormat         string                                                        `json:"packet_format"`
		WireVersion          int                                                           `json:"wire_version"`
		Operations           []struct{ Operation, Method, Path, Request, Response string } `json:"operations"`
		ActivationMaxSeconds int                                                           `json:"activation_max_seconds"`
		ProofMaxSeconds      int                                                           `json:"proof_max_seconds"`
		LeaseSeconds         int                                                           `json:"runtime_lease_seconds"`
		ReceiptBytes         int                                                           `json:"max_activation_receipt_bytes"`
		AllowedOperations    []string                                                      `json:"allowed_operations"`
		LeaseRenewable       bool                                                          `json:"runtime_lease_renewable"`
		AbsentSettles        bool                                                          `json:"absent_settles_pending"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ReceiptBytes != MaxActivationReceiptBytes {
		t.Fatal("published activation receipt limit differs from wire")
	}
	if manifest.PacketFormat != PacketFormat || manifest.WireVersion != PacketVersion || time.Duration(manifest.ActivationMaxSeconds)*time.Second != MaxActivationLifetime || time.Duration(manifest.ProofMaxSeconds)*time.Second != MaxActivationProofLifetime || time.Duration(manifest.LeaseSeconds)*time.Second != MaxAppLeaseLifetime || !reflect.DeepEqual(manifest.AllowedOperations, ActivationAllowedOperations()) || manifest.LeaseRenewable || manifest.AbsentSettles || len(manifest.Operations) != 4 {
		t.Fatal("published manifest differs from wire policy")
	}
	for _, op := range manifest.Operations {
		if op.Path != ActivationHTTPPath(op.Operation) || op.Method != "POST" || !knownOperation(op.Operation) {
			t.Fatal("published operation differs from wire mapping")
		}
	}
}

type activationWireFixture struct {
	hubPrivate, device, owner *e2ee.Identity
	hub                       HubIdentity
	material                  ActivationMaterial
	prepare                   ActivationPrepare
	packet                    []byte
	challenge                 ActivationChallenge
	nonceDigest               string
	now                       time.Time
}

func activationFixture(t *testing.T) activationWireFixture {
	t.Helper()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	h, d, o, card := accountFixture(t, now)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: h.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	m := ActivationMaterial{Format: ActivationFormat, Version: 1, Purpose: PurposeInitialActivation, Origin: card.Origin, AllowLoopbackHTTP: card.AllowLoopbackHTTP, HubID: card.HubID, HubFingerprint: card.HubFingerprint, AccountID: card.AccountID, OwnerID: card.OwnerID, ActivationID: card.ClaimID, SetupEpoch: 1, AccountEpoch: 1, Code: card.Code, IssuedAt: formatUTC(now), ExpiresAt: formatUTC(now.Add(time.Hour))}
	deviceID := AccountDeviceIDPrefix + strings.Repeat("a", 32)
	grant, err := o.SignOwnerDeviceGrant(m.OwnerID, deviceID, d.Public(), m.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := NewActivationPrepare(m, hub, d.Public(), o.Public(), deviceID, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealClientRequest(d, hub, prepare)
	if err != nil {
		t.Fatal(err)
	}
	b := ActivationBinding{Format: ActivationFormat, Purpose: m.Purpose, Origin: m.Origin, HubID: m.HubID, HubFingerprint: m.HubFingerprint, AccountID: m.AccountID, OwnerID: m.OwnerID, ActivationID: m.ActivationID, SetupEpoch: 1, AccountEpoch: 1, DeviceEpoch: 1, OwnerPublic: o.Public(), DeviceID: deviceID, DevicePublic: d.Public(), PrepareRequestID: prepare.RequestID, PreparePacketDigest: ActivationPacketDigest(raw), GrantDigest: ActivationGrantDigest(grant), AllowedOperations: ActivationAllowedOperations(), LeaseExpiresAt: formatUTC(now.Add(MaxAppLeaseLifetime))}
	p := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: m.Origin, AllowLoopbackHTTP: m.AllowLoopbackHTTP, Hub: hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: m.AccountID, OwnerID: m.OwnerID, HubID: m.HubID, AuthorityID: m.ActivationID, OperationID: b.Digest(), CandidatePublic: o.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(o.Public()), ExpiresAt: formatUTC(now.Add(10 * time.Minute))}}
	p, nonce, err := ownerbootstrap.CreateChallenge(h, p, now)
	if err != nil {
		t.Fatal(err)
	}
	serverNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	ch := ActivationChallenge{Format: ActivationChallengeFormat, Binding: b, ClientNonce: prepare.ClientNonce, ServerNonce: serverNonce, Proof: p, IssuedAt: formatUTC(now), ExpiresAt: p.Manifest.ExpiresAt}
	return activationWireFixture{h, d, o, hub, m, prepare, raw, ch, nonce, now}
}
func TestActivationProofAndExactPacketRoundTrip(t *testing.T) {
	f := activationFixture(t)
	binding, route, err := NewClientRoute(f.hub, f.prepare, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var prepare ActivationPrepare
	if err = OpenRequestAt(f.hubPrivate, nil, binding, route, f.packet, &prepare, f.now); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prepare, f.prepare) {
		t.Fatal("prepare changed")
	}
	chRaw, err := SealResponse(f.hubPrivate, f.device.Public(), route, f.challenge)
	if err != nil {
		t.Fatal(err)
	}
	var ch ActivationChallenge
	if err = OpenClientResponse(f.device, f.hub, f.packet, chRaw, &ch); err != nil {
		t.Fatal(err)
	}
	if err = ValidateActivationPreparedResponse(ch, f.prepare, f.packet, f.hub, f.device.Public(), f.now); err != nil {
		t.Fatal(err)
	}
	complete, err := NewActivationComplete(ch, f.hub, f.device.Public(), f.owner, "synthetic-user", "synthetic strong password", f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ownerbootstrap.VerifyProof(f.hubPrivate, ch.Proof, complete.OwnerProof, f.now)
	if err != nil || digest != f.nonceDigest {
		t.Fatal("Owner private-key proof mismatch")
	}
	packet, err := SealClientRequest(f.device, f.hub, complete)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, complete, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var out ActivationComplete
	pub := f.device.Public()
	if err = OpenRequestAt(f.hubPrivate, &pub, b, r, packet, &out, f.now); err != nil {
		t.Fatal(err)
	}
	if out.Username != complete.Username || !bytes.Equal(out.OwnerProof, complete.OwnerProof) {
		t.Fatal("complete changed")
	}
	result := ActivationResult{Format: ActivationResultFormat, Operation: r.Operation, RequestID: r.OperationID, RequestPacketDigest: ActivationPacketDigest(packet), Origin: f.material.Origin, HubID: r.HubID, AccountID: f.material.AccountID, OwnerID: r.OwnerID, ActivationID: f.material.ActivationID, DeviceID: r.DeviceID, AccountEpoch: 1, DeviceEpoch: 1, State: ActivationCompleted, RootState: RootActiveState, LeaseState: ActivationLeaseActive, LeaseExpiresAt: ch.Binding.LeaseExpiresAt, AllowedOperations: ActivationAllowedOperations(), LoginRequired: true, ObservedAt: formatUTC(f.now)}
	response, err := SealResponse(f.hubPrivate, pub, r, result)
	if err != nil {
		t.Fatal(err)
	}
	var received ActivationResult
	if err = OpenClientResponse(f.device, f.hub, packet, response, &received); err != nil {
		t.Fatal(err)
	}
	result.RequestPacketDigest = strings.Repeat("b", 64)
	response, err = SealResponse(f.hubPrivate, pub, r, result)
	if err != nil {
		t.Fatal(err)
	}
	if OpenClientResponse(f.device, f.hub, packet, response, &received) == nil {
		t.Fatal("wrong exact request digest settled")
	}
}
func TestActivationCodeAndLegacyExactIdentity(t *testing.T) {
	f := activationFixture(t)
	code, err := EncodeActivationCode(f.material)
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeActivationCode(code)
	if err != nil || !reflect.DeepEqual(m, f.material) {
		t.Fatal("code round trip")
	}
	for _, bad := range []string{code + "\n", code + "=", "https://example.invalid/" + code, code + "#x", strings.Repeat("a", 32769)} {
		if _, err = DecodeActivationCode(bad); err == nil {
			t.Fatal("malformed code accepted")
		}
	}
	raw, _ := json.Marshal(m)
	bad := bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if _, err = DecodeActivationCode(ActivationCodePrefix + rawURL.EncodeToString(bad)); err == nil {
		t.Fatal("duplicate code fields accepted")
	}
	if ValidateActivationHub(m, f.hub, f.now.Add(2*time.Hour)) == nil {
		t.Fatal("expired code accepted")
	}
	m.HubFingerprint = strings.Repeat("f", 64)
	if ValidateActivationHub(m, f.hub, f.now) == nil {
		t.Fatal("wrong Hub pin accepted")
	}
	m = f.material
	m.Purpose = PurposeLegacyContinuation
	if _, err = EncodeActivationCode(m); err == nil {
		t.Fatal("legacy without exact key accepted")
	}
	pub := f.owner.Public()
	m.ExpectedOwnerPublic = &pub
	if _, err = NewActivationPrepare(m, f.hub, f.device.Public(), pub, f.prepare.DeviceID, f.prepare.OwnerDeviceGrant, f.now); err != nil {
		t.Fatal(err)
	}
	wrong, _ := e2ee.NewIdentity()
	if _, err = NewActivationPrepare(m, f.hub, f.device.Public(), wrong.Public(), f.prepare.DeviceID, f.prepare.OwnerDeviceGrant, f.now); err == nil {
		t.Fatal("legacy rekey accepted")
	}
}
func TestActivationRejectsBindingNonceGrantAndLeaseSubstitution(t *testing.T) {
	f := activationFixture(t)
	cases := map[string]func(*ActivationChallenge){
		"account":                      func(ch *ActivationChallenge) { ch.Binding.AccountID = "account_other" },
		"owner":                        func(ch *ActivationChallenge) { ch.Binding.OwnerID = "owner_other" },
		"epoch":                        func(ch *ActivationChallenge) { ch.Binding.AccountEpoch++ },
		"device":                       func(ch *ActivationChallenge) { ch.Binding.DevicePublic = f.owner.Public() },
		"prepare digest":               func(ch *ActivationChallenge) { ch.Binding.PreparePacketDigest = strings.Repeat("d", 64) },
		"grant digest":                 func(ch *ActivationChallenge) { ch.Binding.GrantDigest = strings.Repeat("e", 64) },
		"allowlist":                    func(ch *ActivationChallenge) { ch.Binding.AllowedOperations = []string{"intent.submit", "nodes.list"} },
		"lease expiry":                 func(ch *ActivationChallenge) { ch.Binding.LeaseExpiresAt = formatUTC(f.now.Add(time.Hour)) },
		"shortened inconsistent lease": func(ch *ActivationChallenge) { ch.Binding.LeaseExpiresAt = formatUTC(f.now.Add(time.Minute)) },
		"client nonce":                 func(ch *ActivationChallenge) { ch.ClientNonce = bytes.Repeat([]byte{1}, 32) },
		"origin policy":                func(ch *ActivationChallenge) { ch.Proof.AllowLoopbackHTTP = !ch.Proof.AllowLoopbackHTTP },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(f.challenge)
			var ch ActivationChallenge
			_ = json.Unmarshal(raw, &ch)
			mutate(&ch)
			if ValidateActivationPreparedResponse(ch, f.prepare, f.packet, f.hub, f.device.Public(), f.now) == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	grant, err := f.owner.SignOwnerDeviceGrant(f.material.OwnerID, f.prepare.DeviceID, f.device.Public(), f.hub.HubID, e2ee.OwnerDevicePurposeControl, f.now, f.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewActivationPrepare(f.material, f.hub, f.device.Public(), f.owner.Public(), f.prepare.DeviceID, grant, f.now); err == nil {
		t.Fatal("unbounded enrollment window accepted")
	}
	wrong, _ := e2ee.NewIdentity()
	if _, err = NewActivationComplete(f.challenge, f.hub, f.device.Public(), wrong, "u", "password synthetic", f.now); err == nil {
		t.Fatal("different Owner private key accepted")
	}
	ch := f.challenge
	ch.Proof.Challenge = bytes.Clone(ch.Proof.Challenge)
	ch.Proof.Challenge[len(ch.Proof.Challenge)/2] ^= 1
	if _, err = NewActivationComplete(ch, f.hub, f.device.Public(), f.owner, "u", "password synthetic", f.now); err == nil {
		t.Fatal("tampered Owner KEM challenge accepted")
	}
	prepare := f.prepare
	prepare.OwnerDeviceGrant = bytes.Clone(prepare.OwnerDeviceGrant)
	prepare.OwnerDeviceGrant[len(prepare.OwnerDeviceGrant)/2] ^= 1
	if _, err = SealClientRequest(f.device, f.hub, prepare); err == nil {
		t.Fatal("tampered independent grant accepted")
	}
}
func TestActivationChallengeCannotSettleAnotherExactPacket(t *testing.T) {
	f := activationFixture(t)
	_, r, _ := NewClientRoute(f.hub, f.prepare, f.device.Public())
	other, err := SealClientRequest(f.device, f.hub, f.prepare)
	if err != nil {
		t.Fatal(err)
	}
	response, err := SealResponse(f.hubPrivate, f.device.Public(), r, f.challenge)
	if err != nil {
		t.Fatal(err)
	}
	var ch ActivationChallenge
	if OpenClientResponse(f.device, f.hub, other, response, &ch) == nil {
		t.Fatal("same request ID, different encrypted packet accepted")
	}
}
func TestAccountReconcileAndStatusBindExactTarget(t *testing.T) {
	f := activationFixture(t)
	login, err := NewLoginPrepare(f.hub, f.material.Origin, f.material.AccountID, f.material.OwnerID, f.prepare.DeviceID, "synthetic-user", f.device.Public(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, login)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewAccountReconcileRequest(f.hub, f.material.Origin, f.material.AccountID, f.material.OwnerID, f.prepare.DeviceID, original, f.now)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := SealClientRequest(f.device, f.hub, req)
	if err != nil {
		t.Fatal(err)
	}
	b, r, _ := NewClientRoute(f.hub, req, f.device.Public())
	var opened AccountReconcileRequest
	pub := f.device.Public()
	if err = OpenRequestAt(f.hubPrivate, &pub, b, r, packet, &opened, f.now); err != nil {
		t.Fatal(err)
	}
	result := AccountReconcileResult{Format: AccountReconciledFormat, Origin: req.Origin, HubID: req.HubID, AccountID: req.AccountID, OwnerID: req.OwnerID, DeviceID: req.DeviceID, RequestID: req.RequestID, OriginalOperation: OperationLoginPrepare, OriginalRequestID: login.RequestID, OriginalPacketDigest: ActivationPacketDigest(original), State: ActivationRejected, AccountEpoch: 1, DeviceEpoch: 1, ObservedAt: formatUTC(f.now)}
	resp, err := SealResponse(f.hubPrivate, pub, r, result)
	if err != nil {
		t.Fatal(err)
	}
	var out AccountReconcileResult
	if err = OpenClientResponse(f.device, f.hub, packet, resp, &out); err != nil {
		t.Fatal(err)
	}
	if ValidateAccountReconcileTarget(out, original) != nil {
		t.Fatal("matching target rejected")
	}
	out.OriginalPacketDigest = strings.Repeat("f", 64)
	if ValidateAccountReconcileTarget(out, original) == nil {
		t.Fatal("wrong target digest accepted")
	}
	status, err := NewActivationStatusRequest(f.hub, f.material.Origin, f.material.AccountID, f.material.OwnerID, f.material.ActivationID, f.prepare.DeviceID, OperationActivationPrepare, f.prepare.RequestID, ActivationPacketDigest(f.packet), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SealClientRequest(f.device, f.hub, status); err != nil {
		t.Fatal(err)
	}
	s := ActivationResult{Operation: OperationActivationStatus, HubID: f.hub.HubID, OwnerID: f.material.OwnerID, DeviceID: f.prepare.DeviceID, TargetOperation: OperationActivationPrepare, TargetRequestID: f.prepare.RequestID, TargetPacketDigest: ActivationPacketDigest(f.packet), TargetState: ActivationAbsent}
	if ValidateActivationStatusTarget(s, f.packet) != nil {
		t.Fatal("matching absent target rejected")
	}
	s.TargetRequestID = strings.Repeat("e", 32)
	if ValidateActivationStatusTarget(s, f.packet) == nil {
		t.Fatal("wrong target ID accepted")
	}
}

func TestActivationStatusCarriesFullPQChallengeWithMaximumScopeIDs(t *testing.T) {
	f := activationFixture(t)
	f.hub.HubID = strings.Repeat("h", 128)
	fp, err := HubFingerprint(f.hub)
	if err != nil {
		t.Fatal(err)
	}
	f.material.HubID = f.hub.HubID
	f.material.HubFingerprint = fp
	f.material.OwnerID = strings.Repeat("o", 128)
	f.material.AccountID = strings.Repeat("a", 128)
	grant, err := f.owner.SignOwnerDeviceGrant(f.material.OwnerID, f.prepare.DeviceID, f.device.Public(), f.hub.HubID, e2ee.OwnerDevicePurposeControl, f.now, f.now.Add(9*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := NewActivationPrepare(f.material, f.hub, f.device.Public(), f.owner.Public(), f.prepare.DeviceID, grant, f.now)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := SealClientRequest(f.device, f.hub, prepare)
	if err != nil {
		t.Fatal(err)
	}
	b := f.challenge.Binding
	b.HubID = f.hub.HubID
	b.HubFingerprint = fp
	b.OwnerID = f.material.OwnerID
	b.AccountID = f.material.AccountID
	b.PrepareRequestID = prepare.RequestID
	b.PreparePacketDigest = ActivationPacketDigest(packet)
	b.GrantDigest = ActivationGrantDigest(grant)
	p := f.challenge.Proof
	p.Hub = f.hub
	p.Manifest.HubID = b.HubID
	p.Manifest.OwnerID = b.OwnerID
	p.Manifest.AccountID = b.AccountID
	p.Manifest.OperationID = b.Digest()
	p, _, err = ownerbootstrap.CreateChallenge(f.hubPrivate, p, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ch := f.challenge
	ch.Binding = b
	ch.Proof = p
	ch.ClientNonce = prepare.ClientNonce
	_, route, _ := NewClientRoute(f.hub, prepare, f.device.Public())
	challengePacket, err := SealResponse(f.hubPrivate, f.device.Public(), route, ch)
	if err != nil {
		t.Fatal(err)
	}
	if len(challengePacket) > MaxActivationReceiptBytes {
		t.Fatal("maximum-scope challenge exceeds receipt limit")
	}
	status, err := NewActivationStatusRequest(f.hub, b.Origin, b.AccountID, b.OwnerID, b.ActivationID, b.DeviceID, OperationActivationPrepare, prepare.RequestID, ActivationPacketDigest(packet), f.now)
	if err != nil {
		t.Fatal(err)
	}
	statusPacket, err := SealClientRequest(f.device, f.hub, status)
	if err != nil {
		t.Fatal(err)
	}
	_, statusRoute, _ := NewClientRoute(f.hub, status, f.device.Public())
	result := ActivationResult{Format: ActivationResultFormat, Operation: OperationActivationStatus, RequestID: status.RequestID, RequestPacketDigest: ActivationPacketDigest(statusPacket), Origin: b.Origin, HubID: b.HubID, AccountID: b.AccountID, OwnerID: b.OwnerID, ActivationID: b.ActivationID, DeviceID: b.DeviceID, AccountEpoch: 1, DeviceEpoch: 1, State: ActivationPrepared, RootState: RootPendingState, LeaseState: ActivationLeaseUnavailable, AllowedOperations: []string{}, LoginRequired: true, TargetOperation: OperationActivationPrepare, TargetRequestID: prepare.RequestID, TargetPacketDigest: ActivationPacketDigest(packet), TargetState: ActivationCompleted, ReceiptPacket: challengePacket, ObservedAt: formatUTC(f.now)}
	response, err := SealResponse(f.hubPrivate, f.device.Public(), statusRoute, result)
	if err != nil {
		t.Fatal(err)
	}
	var out ActivationResult
	if OpenClientResponse(f.device, f.hub, statusPacket, response, &out) != nil || ValidateActivationStatusTarget(out, packet) != nil || !bytes.Equal(out.ReceiptPacket, challengePacket) {
		t.Fatal("maximum-scope nested challenge did not round trip within packet limits")
	}
}
