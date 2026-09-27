package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestMonitorBroadcastSyntheticSigningByteVector(t *testing.T) {
	data, err := os.ReadFile("testdata/monitor-broadcast-signing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SyntheticFixture bool                    `json:"synthetic_fixture"`
		NeverDeploy      bool                    `json:"never_deploy"`
		Context          MonitorBroadcastContext `json:"context"`
		Sealed           json.RawMessage         `json:"sealed"`
		SignedBytesHex   string                  `json:"signed_bytes_hex"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.SyntheticFixture || !fixture.NeverDeploy {
		t.Fatal("public signing vector must be visibly synthetic and never deployable")
	}
	if err := fixture.Context.validate(); err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(fixture.SignedBytesHex)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := monitorBroadcastSignedBytes(MonitorBroadcastEnvelope{
		Type: MonitorBroadcastType, Version: MonitorBroadcastVersion, Suite: Algorithm,
		Context: fixture.Context, Sealed: fixture.Sealed,
	})
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatal("synthetic signing-byte vector changed")
	}
}

func TestMonitorBroadcastSyntheticPublicVerificationVector(t *testing.T) {
	data, err := os.ReadFile("testdata/monitor-broadcast-verification-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SyntheticFixture  bool                    `json:"synthetic_fixture"`
		NeverDeploy       bool                    `json:"never_deploy"`
		ClientPublic      PublicIdentity          `json:"client_public_identity"`
		MonitorPublic     PublicIdentity          `json:"monitor_public_identity"`
		Context           MonitorBroadcastContext `json:"context"`
		Envelope          []byte                  `json:"envelope"`
		OuterSigningBytes string                  `json:"outer_signing_bytes_hex"`
		AAD               string                  `json:"aad_hex"`
		Sequence          uint64                  `json:"sequence"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.SyntheticFixture || !fixture.NeverDeploy ||
		!strings.Contains(fixture.Context.HubID, "synthetic_never_deploy") ||
		bytes.Contains(data, []byte("kem_private")) || bytes.Contains(data, []byte("signing_private")) {
		t.Fatal("public verification vector must be synthetic and contain no private keys")
	}
	if err := ValidatePublicIdentity(fixture.ClientPublic); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicIdentity(fixture.MonitorPublic); err != nil {
		t.Fatal(err)
	}
	if fixture.Context.MonitorKeyID != fixture.MonitorPublic.ID || fixture.Sequence == 0 {
		t.Fatal("verification vector has inconsistent Monitor identity or sequence")
	}
	sequence, err := VerifyMonitorBroadcast(fixture.Envelope, fixture.ClientPublic, fixture.MonitorPublic, fixture.Context)
	if err != nil || sequence != fixture.Sequence {
		t.Fatalf("verify frozen public vector: sequence=%d err=%v", sequence, err)
	}
	var envelope MonitorBroadcastEnvelope
	if err := json.Unmarshal(fixture.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	signed, err := monitorBroadcastSignedBytes(envelope)
	if err != nil || hex.EncodeToString(signed) != fixture.OuterSigningBytes {
		t.Fatal("frozen outer signing preimage changed")
	}
	aad, err := monitorBroadcastAADBytes(fixture.Context)
	if err != nil || hex.EncodeToString(aad) != fixture.AAD {
		t.Fatal("frozen authenticated context bytes changed")
	}
	wrongContext := fixture.Context
	wrongContext.GroupID = "group_changed"
	if _, err := VerifyMonitorBroadcast(fixture.Envelope, fixture.ClientPublic, fixture.MonitorPublic, wrongContext); err == nil {
		t.Fatal("changed trusted context verified")
	}
	envelope.Signature[0] ^= 1
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMonitorBroadcast(tampered, fixture.ClientPublic, fixture.MonitorPublic, fixture.Context); err == nil {
		t.Fatal("tampered outer signature verified")
	}
	if _, err := VerifyMonitorBroadcast(fixture.Envelope, fixture.ClientPublic, fixture.ClientPublic, fixture.Context); err == nil {
		t.Fatal("wrong pinned Monitor receiver verified")
	}
}

func monitorBroadcastTestContext(monitor PublicIdentity, body []byte) MonitorBroadcastContext {
	digest := sha256.Sum256(body)
	snapshot := sha256.Sum256([]byte("synthetic fixed recipient snapshot"))
	return MonitorBroadcastContext{
		HubID: "hub_test", OwnerID: "owner_test", ClientDeviceID: "device_test",
		ClientSessionEpoch: 7, ClientKeyVersion: 3,
		ApprovalID: "approval_test", BroadcastID: "broadcast_test", GroupID: "group_test",
		MonitorEndpointID: "monitor_test", MonitorKeyID: monitor.ID,
		MonitorBindingID: "binding_test", MonitorBindingEpoch: 5,
		BodySHA256: hex.EncodeToString(digest[:]), RecipientSnapshotSHA256: hex.EncodeToString(snapshot[:]),
		ExpiresAt: "2030-01-02T03:04:05.123Z",
	}
}

func TestMonitorBroadcastSealsAndBindsExactContext(t *testing.T) {
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("  exact UTF-8 body ☃\n")
	context := monitorBroadcastTestContext(monitor.Public(), body)
	wire, err := SealMonitorBroadcast(client, monitor.Public(), context, body, 41)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, body) {
		t.Fatal("ciphertext exposed broadcast body")
	}
	sequence, err := VerifyMonitorBroadcast(wire, client.Public(), monitor.Public(), context)
	if err != nil || sequence != 41 {
		t.Fatalf("verify opaque frame: sequence=%d err=%v", sequence, err)
	}
	opened, openedSequence, err := OpenMonitorBroadcast(monitor, client.Public(), context, wire)
	if err != nil || openedSequence != 41 || !bytes.Equal(opened, body) {
		t.Fatalf("open exact body: sequence=%d err=%v", openedSequence, err)
	}
	if _, err := VerifyMonitorBroadcast(wire, other.Public(), monitor.Public(), context); err == nil {
		t.Fatal("wrong Client signer verified")
	}
	if _, err := VerifyMonitorBroadcast(wire, client.Public(), other.Public(), context); err == nil {
		t.Fatal("wrong Monitor public identity verified")
	}
	if _, _, err := OpenMonitorBroadcast(other, client.Public(), context, wire); err == nil {
		t.Fatal("wrong Monitor private identity opened")
	}
	changes := map[string]func(*MonitorBroadcastContext){
		"Hub":                func(c *MonitorBroadcastContext) { c.HubID = "other_hub" },
		"Owner":              func(c *MonitorBroadcastContext) { c.OwnerID = "other_owner" },
		"Client device":      func(c *MonitorBroadcastContext) { c.ClientDeviceID = "other_device" },
		"Client epoch":       func(c *MonitorBroadcastContext) { c.ClientSessionEpoch++ },
		"Client key version": func(c *MonitorBroadcastContext) { c.ClientKeyVersion++ },
		"Approval":           func(c *MonitorBroadcastContext) { c.ApprovalID = "other_approval" },
		"Broadcast":          func(c *MonitorBroadcastContext) { c.BroadcastID = "other_broadcast" },
		"Group":              func(c *MonitorBroadcastContext) { c.GroupID = "other_group" },
		"Monitor endpoint":   func(c *MonitorBroadcastContext) { c.MonitorEndpointID = "other_monitor" },
		"Monitor binding":    func(c *MonitorBroadcastContext) { c.MonitorBindingID = "other_binding" },
		"Monitor epoch":      func(c *MonitorBroadcastContext) { c.MonitorBindingEpoch++ },
		"Body digest":        func(c *MonitorBroadcastContext) { c.BodySHA256 = strings.Repeat("0", 64) },
		"Snapshot":           func(c *MonitorBroadcastContext) { c.RecipientSnapshotSHA256 = strings.Repeat("0", 64) },
		"Expiry":             func(c *MonitorBroadcastContext) { c.ExpiresAt = "2030-01-02T03:04:06Z" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			wrong := context
			change(&wrong)
			if _, err := VerifyMonitorBroadcast(wire, client.Public(), monitor.Public(), wrong); err == nil {
				t.Fatal("changed trusted context verified")
			}
		})
	}
}

func TestMonitorBroadcastRejectsMalformedBodiesAndFrames(t *testing.T) {
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("private body")
	context := monitorBroadcastTestContext(monitor.Public(), body)
	wire, err := SealMonitorBroadcast(client, monitor.Public(), context, body, 1)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string][]byte{
		"trailing":      append(append([]byte(nil), wire...), []byte("{}")...),
		"oversize":      make([]byte, maxMonitorBroadcastWire+1),
		"unknown outer": append(append([]byte(nil), bytes.TrimSuffix(wire, []byte("}"))...), []byte(",\"approved\":true}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyMonitorBroadcast(mutated, client.Public(), monitor.Public(), context); err == nil {
				t.Fatal("malformed frame verified")
			}
		})
	}
	var envelope MonitorBroadcastEnvelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature[0] ^= 1
	badSignature, _ := json.Marshal(envelope)
	if _, err := VerifyMonitorBroadcast(badSignature, client.Public(), monitor.Public(), context); err == nil {
		t.Fatal("bad outer signature verified")
	}
	envelope.Signature[0] ^= 1
	var inner map[string]any
	if err := json.Unmarshal(envelope.Sealed, &inner); err != nil {
		t.Fatal(err)
	}
	inner["future_cipher_field"] = true
	envelope.Sealed, _ = json.Marshal(inner)
	signed, _ := monitorBroadcastSignedBytes(envelope)
	if err := mldsa65.SignTo(client.signingPrivate, signed, nil, true, envelope.Signature); err != nil {
		t.Fatal(err)
	}
	badInner, _ := json.Marshal(envelope)
	if _, err := VerifyMonitorBroadcast(badInner, client.Public(), monitor.Public(), context); err == nil {
		t.Fatal("unknown inner field verified")
	}
	if _, err := SealMonitorBroadcast(client, monitor.Public(), context, body, 0); err == nil {
		t.Fatal("zero sequence sealed")
	}
	if _, err := SealMonitorBroadcast(client, monitor.Public(), context, []byte{0xff}, 2); err == nil {
		t.Fatal("invalid UTF-8 sealed")
	}
	if _, err := SealMonitorBroadcast(client, monitor.Public(), context, make([]byte, maxMonitorBroadcastBody+1), 2); err == nil {
		t.Fatal("oversize body sealed")
	}
	if _, err := SealMonitorBroadcast(client, monitor.Public(), context, []byte("private body "), 2); err == nil {
		t.Fatal("changed exact body sealed under old digest")
	}
	for name, change := range map[string]func(*MonitorBroadcastContext){
		"non ASCII ID":        func(c *MonitorBroadcastContext) { c.GroupID = "组" },
		"slash ID":            func(c *MonitorBroadcastContext) { c.GroupID = "grp/path" },
		"uppercase digest":    func(c *MonitorBroadcastContext) { c.BodySHA256 = strings.ToUpper(c.BodySHA256) },
		"offset expiry":       func(c *MonitorBroadcastContext) { c.ExpiresAt = "2030-01-02T04:04:05.123+01:00" },
		"noncanonical expiry": func(c *MonitorBroadcastContext) { c.ExpiresAt = "2030-01-02T03:04:05.1230Z" },
		"zero key version":    func(c *MonitorBroadcastContext) { c.ClientKeyVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := context
			change(&bad)
			if _, err := SealMonitorBroadcast(client, monitor.Public(), bad, body, 2); err == nil {
				t.Fatal("invalid context sealed")
			}
		})
	}
}

func TestMonitorBroadcastOpenChecksDecryptedExactBodyDigest(t *testing.T) {
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	context := monitorBroadcastTestContext(monitor.Public(), []byte("accepted"))
	aad, err := monitorBroadcastAADBytes(context)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"wrong digest":  []byte("accepted "),
		"invalid UTF-8": {0xff},
		"empty":         {},
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := Seal(client, monitor.Public(), body, aad, 7)
			if err != nil {
				t.Fatal(err)
			}
			envelope := MonitorBroadcastEnvelope{Type: MonitorBroadcastType, Version: MonitorBroadcastVersion,
				Suite: Algorithm, Context: context, Sealed: sealed}
			signed, err := monitorBroadcastSignedBytes(envelope)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Signature = make([]byte, mldsa65.SignatureSize)
			if err := mldsa65.SignTo(client.signingPrivate, signed, nil, true, envelope.Signature); err != nil {
				t.Fatal(err)
			}
			wire, _ := json.Marshal(envelope)
			if _, err := VerifyMonitorBroadcast(wire, client.Public(), monitor.Public(), context); err != nil && name != "empty" {
				t.Fatalf("public opaque verification should succeed: %v", err)
			}
			if _, _, err := OpenMonitorBroadcast(monitor, client.Public(), context, wire); err == nil {
				t.Fatal("invalid exact plaintext accepted")
			}
		})
	}
}
