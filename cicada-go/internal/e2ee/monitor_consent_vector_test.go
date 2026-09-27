package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const monitorConsentVectorPath = "testdata/monitor-broadcast-consent-v2.json"

type monitorConsentVector struct {
	SyntheticFixture     bool                         `json:"synthetic_fixture"`
	NeverDeploy          bool                         `json:"never_deploy"`
	Warning              string                       `json:"warning"`
	ConsentScope         MonitorBroadcastConsentScope `json:"consent_scope"`
	ConsentSHA256        string                       `json:"consent_sha256"`
	Context              MonitorBroadcastContext      `json:"context"`
	ClientPublic         PublicIdentity               `json:"client_public_identity"`
	MonitorPublic        PublicIdentity               `json:"monitor_public_identity"`
	Envelope             []byte                       `json:"envelope"`
	OuterSigningBytesHex string                       `json:"outer_signing_bytes_hex"`
	AADHex               string                       `json:"aad_hex"`
	Sequence             uint64                       `json:"sequence"`
}

func TestPublishedMonitorConsentVector(t *testing.T) {
	if os.Getenv("CICADA_UPDATE_MONITOR_CONSENT_VECTOR") == "1" {
		writeMonitorConsentVector(t)
	}
	data, err := os.ReadFile(monitorConsentVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector monitorConsentVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if !vector.SyntheticFixture || !vector.NeverDeploy ||
		!strings.Contains(vector.Warning, "SYNTHETIC") || !strings.Contains(vector.Context.HubID, "synthetic_never_deploy") ||
		strings.Contains(string(data), "private") {
		t.Fatal("vector is not visibly synthetic and public")
	}
	digest, err := MonitorBroadcastConsentDigest(vector.ConsentScope)
	if err != nil || digest != vector.ConsentSHA256 || vector.Context.ConsentSHA256 != digest ||
		vector.Sequence != vector.Context.ConfirmRequestSequence {
		t.Fatal("vector consent scope differs from signed context")
	}
	if vector.ConsentScope.BroadcastID != vector.Context.BroadcastID ||
		vector.ConsentScope.GroupID != vector.Context.GroupID ||
		vector.ConsentScope.Source.EndpointID != vector.Context.MonitorEndpointID ||
		vector.ConsentScope.Source.OwnerID != vector.Context.OwnerID ||
		vector.ConsentScope.Source.BindingID != vector.Context.MonitorBindingID ||
		vector.ConsentScope.Source.BindingEpoch != vector.Context.MonitorBindingEpoch ||
		vector.ConsentScope.Source.KeyID != vector.Context.MonitorKeyID ||
		vector.ConsentScope.Source.KeyFingerprint != vectorPeerFingerprint(vector.MonitorPublic) {
		t.Fatal("vector Monitor consent source does not match the sealed receiver")
	}
	sequence, err := VerifyMonitorBroadcast(vector.Envelope, vector.ClientPublic, vector.MonitorPublic, vector.Context)
	if err != nil || sequence != vector.Sequence {
		t.Fatalf("verify published vector: %d %v", sequence, err)
	}
	var envelope MonitorBroadcastEnvelope
	if err := json.Unmarshal(vector.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	signed, err := monitorBroadcastSignedBytes(envelope)
	if err != nil || hex.EncodeToString(signed) != vector.OuterSigningBytesHex {
		t.Fatal("published signing bytes changed")
	}
	aad, err := monitorBroadcastAADBytes(vector.Context)
	if err != nil || hex.EncodeToString(aad) != vector.AADHex {
		t.Fatal("published AAD changed")
	}
}

func writeMonitorConsentVector(t *testing.T) {
	t.Helper()
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("PUBLIC SYNTHETIC MONITOR BODY — NEVER DEPLOY")
	context := monitorBroadcastTestContext(monitor.Public(), body)
	context.HubID = "hub_synthetic_never_deploy"
	context.ConfirmRequestSequence = 7
	scope := syntheticMonitorConsentScope()
	scope.BroadcastID, scope.GroupID = context.BroadcastID, context.GroupID
	scope.Source.EndpointID, scope.Source.OwnerID = context.MonitorEndpointID, context.OwnerID
	scope.Source.BindingID, scope.Source.BindingEpoch = context.MonitorBindingID, context.MonitorBindingEpoch
	scope.Source.KeyID, scope.Source.KeyFingerprint = monitor.Public().ID, vectorPeerFingerprint(monitor.Public())
	for i := range scope.Recipients {
		scope.Recipients[i].OwnerID = context.OwnerID
	}
	digest, err := MonitorBroadcastConsentDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	context.ConsentSHA256 = digest
	wire, err := SealMonitorBroadcast(client, monitor.Public(), context, body, 7)
	if err != nil {
		t.Fatal(err)
	}
	var envelope MonitorBroadcastEnvelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	signed, err := monitorBroadcastSignedBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := monitorBroadcastAADBytes(context)
	if err != nil {
		t.Fatal(err)
	}
	vector := monitorConsentVector{SyntheticFixture: true, NeverDeploy: true,
		Warning:      "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT",
		ConsentScope: scope, ConsentSHA256: digest, Context: context,
		ClientPublic: client.Public(), MonitorPublic: monitor.Public(), Envelope: wire,
		OuterSigningBytesHex: hex.EncodeToString(signed), AADHex: hex.EncodeToString(aad), Sequence: 7}
	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(monitorConsentVectorPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(monitorConsentVectorPath, append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	// Keep the generator's body digest visibly tied to synthetic content.
	sum := sha256.Sum256(body)
	if context.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong synthetic body digest")
	}
}

func vectorPeerFingerprint(public PublicIdentity) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cicada/nodekeys/peer-key-fingerprint/v1\x00"))
	_, _ = hash.Write(public.KEMPublic)
	_, _ = hash.Write(public.SigningPublic)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
