package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublishedNetworkCollaborationKeyConsentVector(t *testing.T) {
	path := filepath.Join("testdata", "network-collaboration-key-consent-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		FixtureVersion              int            `json:"fixture_version"`
		SyntheticOnly               bool           `json:"synthetic_only"`
		Warning                     string         `json:"warning"`
		Purpose                     string         `json:"purpose"`
		SyntheticNativeSessionID    string         `json:"synthetic_native_session_id"`
		NativeSessionDigest         string         `json:"native_session_digest"`
		ManifestCanonicalJSON       string         `json:"manifest_canonical_json"`
		CollaborationManifestDigest string         `json:"collaboration_manifest_digest"`
		OwnerPublicIdentity         PublicIdentity `json:"owner_public_identity"`
		OwnerGrantJSON              string         `json:"owner_grant_json"`
		CanonicalUnsignedJSON       string         `json:"canonical_unsigned_json"`
		SignedInputBase64           string         `json:"signed_input_base64"`
		SignedInputHex              string         `json:"signed_input_hex"`
		SignedInputSHA256           string         `json:"signed_input_sha256"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.FixtureVersion != 1 || !vector.SyntheticOnly ||
		vector.Warning != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT" ||
		vector.Purpose != NetworkCollaborationPurposeTask ||
		vector.NativeSessionDigest != NetworkDirectNativeSessionDigest(vector.SyntheticNativeSessionID) {
		t.Fatal("public Network collaboration vector is not clearly synthetic or has invalid native-session binding")
	}
	wantDigest := NetworkCollaborationManifestDigest(vector.Purpose, []byte(vector.ManifestCanonicalJSON))
	if vector.CollaborationManifestDigest != wantDigest {
		t.Fatal("collaboration manifest digest differs from its exact canonical key manifest")
	}
	var grant OwnerNetworkCollaborationKeyGrant
	if err := json.Unmarshal([]byte(vector.OwnerGrantJSON), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.Purpose != vector.Purpose || grant.ManifestDigest != vector.CollaborationManifestDigest {
		t.Fatal("published collaboration proof does not name its exact purpose and manifest")
	}
	signed, err := grant.signedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte(`"signature":null`)) ||
		string(signed[len(networkCollaborationKeyGrantDomain):]) != vector.CanonicalUnsignedJSON {
		t.Fatal("collaboration proof signing bytes do not preserve signature:null canonical field order")
	}
	base64Bytes, err := base64.StdEncoding.DecodeString(vector.SignedInputBase64)
	if err != nil {
		t.Fatal(err)
	}
	hexBytes, err := hex.DecodeString(vector.SignedInputHex)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	if !bytes.Equal(signed, base64Bytes) || !bytes.Equal(signed, hexBytes) ||
		hex.EncodeToString(sum[:]) != vector.SignedInputSHA256 {
		t.Fatal("published Network collaboration proof signing bytes or digest differ")
	}
	claim := OwnerNetworkCollaborationKeyGrant{Purpose: vector.Purpose,
		HubID: grant.HubID, NetworkID: grant.NetworkID, EndpointID: grant.EndpointID,
		OwnerID: grant.OwnerID, ManifestDigest: vector.CollaborationManifestDigest}
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant([]byte(vector.OwnerGrantJSON),
		vector.OwnerPublicIdentity, claim, time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("published synthetic Owner collaboration proof was rejected: %v", err)
	}
	claim.Purpose = NetworkCollaborationPurposeBroadcast
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant([]byte(vector.OwnerGrantJSON),
		vector.OwnerPublicIdentity, claim, time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("TASK vector was accepted as a BROADCAST grant")
	}
}

func TestPublishedNetworkCollaborationBroadcastConsentVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "network-collaboration-broadcast-consent-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		FixtureVersion              int            `json:"fixture_version"`
		SyntheticOnly               bool           `json:"synthetic_only"`
		Warning                     string         `json:"warning"`
		Purpose                     string         `json:"purpose"`
		SigningDomain               string         `json:"signing_domain"`
		ClaimsFieldOrder            []string       `json:"claims_field_order"`
		ManifestCanonicalJSON       string         `json:"manifest_canonical_json"`
		CollaborationManifestDigest string         `json:"collaboration_manifest_digest"`
		OwnerPublicIdentity         PublicIdentity `json:"owner_public_identity"`
		OwnerGrantJSON              string         `json:"owner_grant_json"`
		CanonicalUnsignedJSON       string         `json:"canonical_unsigned_json"`
		SignedInputBase64           string         `json:"signed_input_base64"`
		SignedInputHex              string         `json:"signed_input_hex"`
		SignedInputSHA256           string         `json:"signed_input_sha256"`
		SignatureBase64             string         `json:"signature_base64"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.FixtureVersion != 1 || !vector.SyntheticOnly ||
		vector.Warning != "PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT" ||
		vector.Purpose != NetworkCollaborationPurposeBroadcast ||
		vector.SigningDomain != `cicada/network/collaboration-key-grant/v1\x00` {
		t.Fatal("published Network collaboration vector is not clearly synthetic or names the wrong purpose")
	}
	if err := ValidatePublicIdentity(vector.OwnerPublicIdentity); err != nil {
		t.Fatalf("published synthetic Broadcast Owner identity is invalid: %v", err)
	}
	wantOrder := []string{"version", "purpose", "hub_id", "network_id", "endpoint_id", "owner_id",
		"owner_key_id", "manifest_digest", "issued_at", "expires_at", "nonce", "signature"}
	if len(vector.ClaimsFieldOrder) != len(wantOrder) {
		t.Fatalf("Broadcast claims field count=%d, want %d", len(vector.ClaimsFieldOrder), len(wantOrder))
	}
	for i := range wantOrder {
		if vector.ClaimsFieldOrder[i] != wantOrder[i] {
			t.Fatalf("Broadcast claims field order[%d]=%q, want %q", i, vector.ClaimsFieldOrder[i], wantOrder[i])
		}
	}
	var grant OwnerNetworkCollaborationKeyGrant
	grantWire := []byte(vector.OwnerGrantJSON)
	if err := json.Unmarshal(grantWire, &grant); err != nil {
		t.Fatal(err)
	}
	canonicalGrant, err := json.Marshal(grant)
	if err != nil || !bytes.Equal(canonicalGrant, grantWire) {
		t.Fatal("published Broadcast Owner grant is not canonical wire JSON")
	}
	if grant.Purpose != NetworkCollaborationPurposeBroadcast ||
		grant.OwnerKeyID != vector.OwnerPublicIdentity.ID ||
		grant.ManifestDigest != vector.CollaborationManifestDigest {
		t.Fatal("Broadcast grant claims do not match the purpose-bound manifest and trusted key")
	}
	manifestDigest := NetworkCollaborationManifestDigest(vector.Purpose, []byte(vector.ManifestCanonicalJSON))
	if manifestDigest != vector.CollaborationManifestDigest {
		t.Fatal("Broadcast manifest digest differs from its exact canonical key manifest")
	}
	signed, err := grant.signedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte(`"signature":null`)) ||
		string(signed[len(networkCollaborationKeyGrantDomain):]) != vector.CanonicalUnsignedJSON {
		t.Fatal("Broadcast grant signing input does not preserve signature:null and ordered production claims")
	}
	base64Bytes, err := base64.StdEncoding.DecodeString(vector.SignedInputBase64)
	if err != nil {
		t.Fatal(err)
	}
	hexBytes, err := hex.DecodeString(vector.SignedInputHex)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	if !bytes.Equal(signed, base64Bytes) || !bytes.Equal(signed, hexBytes) ||
		hex.EncodeToString(sum[:]) != vector.SignedInputSHA256 ||
		!bytes.Equal(grant.Signature, mustDecodeVectorBase64(t, vector.SignatureBase64)) {
		t.Fatal("published Broadcast grant signing bytes, digest, or signature differs")
	}
	if !bytes.HasPrefix(signed, []byte(networkCollaborationKeyGrantDomain)) {
		t.Fatal("Broadcast grant signature domain differs")
	}
	expected := OwnerNetworkCollaborationKeyGrant{Purpose: vector.Purpose,
		HubID: grant.HubID, NetworkID: grant.NetworkID, EndpointID: grant.EndpointID,
		OwnerID: grant.OwnerID, ManifestDigest: vector.CollaborationManifestDigest}
	now := time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant(grantWire, vector.OwnerPublicIdentity, expected, now); err != nil {
		t.Fatalf("published synthetic Broadcast Owner proof was rejected: %v", err)
	}

	taskData, err := os.ReadFile(filepath.Join("testdata", "network-collaboration-key-consent-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var taskVector struct {
		Purpose                     string         `json:"purpose"`
		OwnerPublicIdentity         PublicIdentity `json:"owner_public_identity"`
		ManifestCanonicalJSON       string         `json:"manifest_canonical_json"`
		CollaborationManifestDigest string         `json:"collaboration_manifest_digest"`
		OwnerGrantJSON              string         `json:"owner_grant_json"`
	}
	if err := json.Unmarshal(taskData, &taskVector); err != nil {
		t.Fatal(err)
	}
	var taskGrant OwnerNetworkCollaborationKeyGrant
	if err := json.Unmarshal([]byte(taskVector.OwnerGrantJSON), &taskGrant); err != nil {
		t.Fatal(err)
	}
	if taskVector.Purpose != NetworkCollaborationPurposeTask || taskGrant.Purpose != NetworkCollaborationPurposeTask ||
		taskVector.CollaborationManifestDigest == vector.CollaborationManifestDigest ||
		taskVector.ManifestCanonicalJSON != vector.ManifestCanonicalJSON ||
		bytes.Equal(taskGrant.Signature, grant.Signature) {
		t.Fatal("Broadcast vector reused TASK purpose, digest, or signature")
	}
	taskNow := time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)
	taskExpected := OwnerNetworkCollaborationKeyGrant{Purpose: NetworkCollaborationPurposeTask,
		HubID: taskGrant.HubID, NetworkID: taskGrant.NetworkID, EndpointID: taskGrant.EndpointID,
		OwnerID: taskGrant.OwnerID, ManifestDigest: taskVector.CollaborationManifestDigest}
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant([]byte(taskVector.OwnerGrantJSON),
		taskVector.OwnerPublicIdentity, taskExpected, taskNow); err != nil {
		t.Fatalf("original TASK proof no longer verifies: %v", err)
	}
	taskAsBroadcast := taskExpected
	taskAsBroadcast.Purpose = NetworkCollaborationPurposeBroadcast
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant([]byte(taskVector.OwnerGrantJSON),
		taskVector.OwnerPublicIdentity, taskAsBroadcast, taskNow); err == nil {
		t.Fatal("TASK vector was accepted under BROADCAST purpose")
	}
	broadcastAsTask := expected
	broadcastAsTask.Purpose = NetworkCollaborationPurposeTask
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant(grantWire,
		vector.OwnerPublicIdentity, broadcastAsTask, now); err == nil {
		t.Fatal("BROADCAST vector was accepted under TASK purpose")
	}

	for _, test := range []struct {
		name   string
		mutate func(*OwnerNetworkCollaborationKeyGrant)
	}{
		{name: "hub", mutate: func(value *OwnerNetworkCollaborationKeyGrant) { value.HubID = "hub_synthetic_other" }},
		{name: "network", mutate: func(value *OwnerNetworkCollaborationKeyGrant) { value.NetworkID = "net_synthetic_other" }},
		{name: "endpoint", mutate: func(value *OwnerNetworkCollaborationKeyGrant) { value.EndpointID = "ep_synthetic_other" }},
		{name: "owner", mutate: func(value *OwnerNetworkCollaborationKeyGrant) { value.OwnerID = "owner_synthetic_other" }},
		{name: "manifest", mutate: func(value *OwnerNetworkCollaborationKeyGrant) { value.ManifestDigest = strings.Repeat("0", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			tampered := grant
			test.mutate(&tampered)
			tamperedWire, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			expectedTampered := OwnerNetworkCollaborationKeyGrant{Purpose: tampered.Purpose,
				HubID: tampered.HubID, NetworkID: tampered.NetworkID, EndpointID: tampered.EndpointID,
				OwnerID: tampered.OwnerID, ManifestDigest: tampered.ManifestDigest}
			if _, err := VerifyOwnerNetworkCollaborationKeyGrant(tamperedWire,
				vector.OwnerPublicIdentity, expectedTampered, now); err == nil {
				t.Fatal("tampered Broadcast claim was accepted")
			}
		})
	}
	var wireObject map[string]json.RawMessage
	if err := json.Unmarshal(grantWire, &wireObject); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(wireObject)
	if err != nil || bytes.Equal(reordered, grantWire) {
		t.Fatal("ordering negative did not change canonical JSON")
	}
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant(reordered, vector.OwnerPublicIdentity, expected, now); err == nil {
		t.Fatal("reordered Broadcast proof was accepted")
	}
	tampered := grant
	tampered.Signature = append([]byte(nil), grant.Signature...)
	tampered.Signature[0] ^= 1
	tamperedWire, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant(tamperedWire, vector.OwnerPublicIdentity, expected, now); err == nil {
		t.Fatal("tampered Broadcast ML-DSA signature was accepted")
	}
}

func TestNetworkCollaborationOwnerProofPurposesAreSeparateFromDirect(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	digest := bytes.Repeat([]byte("c"), 64)
	proof, err := owner.SignOwnerNetworkCollaborationKeyGrant(NetworkCollaborationPurposeTask,
		"hub_synthetic", "net_synthetic", "ep_synthetic", "owner_synthetic", string(digest),
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claim := OwnerNetworkCollaborationKeyGrant{Purpose: NetworkCollaborationPurposeTask,
		HubID: "hub_synthetic", NetworkID: "net_synthetic", EndpointID: "ep_synthetic",
		OwnerID: "owner_synthetic", ManifestDigest: string(digest)}
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant(proof, owner.Public(), claim, now); err != nil {
		t.Fatalf("valid typed Owner proof rejected: %v", err)
	}
	claim.Purpose = NetworkCollaborationPurposeBroadcast
	if _, err := VerifyOwnerNetworkCollaborationKeyGrant(proof, owner.Public(), claim, now); err == nil {
		t.Fatal("TASK proof authorized BROADCAST key use")
	}
	var direct OwnerNetworkDirectKeyGrant
	if err := json.Unmarshal(proof, &direct); err != nil {
		t.Fatal(err)
	}
	directClaim := OwnerNetworkDirectKeyGrant{HubID: claim.HubID, NetworkID: claim.NetworkID,
		EndpointID: claim.EndpointID, OwnerID: claim.OwnerID, ManifestDigest: claim.ManifestDigest}
	if _, err := VerifyOwnerNetworkDirectKeyGrant(proof, owner.Public(), directClaim, now); err == nil {
		t.Fatal("typed collaboration proof was accepted as the legacy direct v1 consent")
	}
	if NetworkCollaborationManifestDigest(NetworkCollaborationPurposeTask, []byte(`{"key":"same"}`)) ==
		NetworkCollaborationManifestDigest(NetworkCollaborationPurposeBroadcast, []byte(`{"key":"same"}`)) {
		t.Fatal("purpose omitted from collaboration manifest digest")
	}
}

func TestNetworkCollaborationEnvelopeBindsPurposeAndPreservesDirectV1(t *testing.T) {
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	route := NetworkDirectContext{HubID: "hub_synthetic", NetworkID: "net_synthetic",
		MessageID: "ntask_synthetic_offer", Kind: "SEND",
		SenderEndpointID: "ep_sender", SenderPrincipalID: "principal_sender", SenderOwnerID: "owner_sender",
		SenderMembershipRevision: 1, SenderEnrollmentRevision: 1, SenderBindingEpoch: 1,
		SenderKeyID:        sender.Public().ID,
		ReceiverEndpointID: "ep_receiver", ReceiverPrincipalID: "principal_receiver", ReceiverOwnerID: "owner_receiver",
		ReceiverMembershipRevision: 1, ReceiverEnrollmentRevision: 1, ReceiverBindingEpoch: 1,
		ReceiverKeyID: receiver.Public().ID}
	context := NetworkCollaborationMessageContext{Purpose: NetworkCollaborationPurposeTask, Route: route}
	wire, err := SealNetworkCollaborationMessage(sender, receiver.Public(), context,
		[]byte("synthetic task offer"), 1)
	if err != nil {
		t.Fatal(err)
	}
	opened, sequence, err := OpenNetworkCollaborationMessage(receiver, sender.Public(), context, wire)
	if err != nil || sequence != 1 || string(opened) != "synthetic task offer" {
		t.Fatalf("open exact TASK context: sequence=%d err=%v", sequence, err)
	}
	changed := context
	changed.Purpose = NetworkCollaborationPurposeBroadcast
	if _, _, err := OpenNetworkCollaborationMessage(receiver, sender.Public(), changed, wire); err == nil {
		t.Fatal("TASK ciphertext opened under BROADCAST purpose")
	}
	if err := VerifyNetworkCollaborationMessage(sender.Public(), changed, wire); err == nil {
		t.Fatal("TASK signature verified as BROADCAST")
	}
	if _, err := SealNetworkCollaborationMessage(sender, receiver.Public(),
		NetworkCollaborationMessageContext{Purpose: NetworkCollaborationPurposeTask,
			Route: NetworkDirectContext{Kind: "REQUEST"}}, []byte("no ask"), 1); err == nil {
		t.Fatal("collaboration purpose accepted REQUEST instead of SEND")
	}
}
