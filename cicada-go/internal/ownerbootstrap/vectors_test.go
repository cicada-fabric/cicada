package ownerbootstrap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

const publishedVectorPath = "testdata/owner-bootstrap-v1.json"
const publishedVectorWarning = "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT"

type bootstrapVectorPrivate struct {
	Public  e2ee.PublicIdentity `json:"public_identity"`
	Private json.RawMessage     `json:"private_identity_PRIVATE_TEST_ONLY"`
}

type publishedBootstrapVector struct {
	Version              int                    `json:"fixture_version"`
	Warning              string                 `json:"warning"`
	At                   string                 `json:"verification_time"`
	Hub                  bootstrapVectorPrivate `json:"hub_PRIVATE_TEST_ONLY"`
	Owner                bootstrapVectorPrivate `json:"owner_PRIVATE_TEST_ONLY"`
	Pairing              PairingFile            `json:"pairing_file"`
	CanonicalManifest    string                 `json:"manifest_canonical_utf8"`
	ManifestDigest       string                 `json:"manifest_digest"`
	CandidateFingerprint string                 `json:"candidate_fingerprint"`
	Nonce                []byte                 `json:"nonce_base64"`
	NonceDigest          string                 `json:"nonce_digest"`
	Challenge            string                 `json:"challenge_packet_utf8"`
	ChallengePlaintext   string                 `json:"challenge_plaintext_utf8"`
	ChallengeAAD         []byte                 `json:"challenge_aad_base64"`
	Proof                string                 `json:"request_proof_packet_utf8"`
	ProofPlaintext       string                 `json:"proof_plaintext_utf8"`
	ProofAAD             []byte                 `json:"proof_aad_base64"`
	Receipt              string                 `json:"receipt_packet_utf8"`
	ReceiptPlaintext     string                 `json:"receipt_plaintext_utf8"`
	ReceiptAAD           []byte                 `json:"receipt_aad_base64"`
	ExpectedReceipt      Receipt                `json:"expected_receipt"`
}

// Regeneration requires explicit opt-in. Ordinary tests only consume frozen
// public synthetic material and never produce or initialize deployment keys.
func TestPublishedOwnerBootstrapVector(t *testing.T) {
	if os.Getenv("CICADA_UPDATE_OWNER_BOOTSTRAP_VECTOR") == "1" {
		writePublishedBootstrapVector(t)
	}
	raw, e := os.ReadFile(publishedVectorPath)
	if e != nil {
		t.Fatal(e)
	}
	var v publishedBootstrapVector
	if json.Unmarshal(raw, &v) != nil || v.Version != 1 || v.Warning != publishedVectorWarning {
		t.Fatal("unlabelled synthetic Owner bootstrap vector")
	}
	at, e := time.Parse(time.RFC3339Nano, v.At)
	if e != nil {
		t.Fatal(e)
	}
	hub, e := e2ee.UnmarshalIdentity(v.Hub.Private)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.UnmarshalIdentity(v.Owner.Private)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(hub.Public(), v.Hub.Public) || !reflect.DeepEqual(owner.Public(), v.Owner.Public) || !reflect.DeepEqual(v.Pairing.Hub.Public, v.Hub.Public) || !reflect.DeepEqual(v.Pairing.Manifest.CandidatePublic, v.Owner.Public) {
		t.Fatal("published synthetic private/public keys differ")
	}
	manifest, e := json.Marshal(v.Pairing.Manifest)
	if e != nil || string(manifest) != v.CanonicalManifest || v.Pairing.Manifest.Digest() != v.ManifestDigest || v.Pairing.Manifest.CandidateFingerprint != v.CandidateFingerprint || Fingerprint(owner.Public()) != v.CandidateFingerprint {
		t.Fatal("manifest canonical bytes or full fingerprint changed")
	}
	if v.Pairing.Validate(at) != nil || v.Pairing.Origin != "https://synthetic.invalid" || v.Pairing.AllowLoopbackHTTP || len(v.Nonce) != 32 || nonceDigest(v.Pairing, v.Nonce) != v.NonceDigest || string(v.Pairing.Challenge) != v.Challenge {
		t.Fatal("published exact scope or nonce changed")
	}
	possession, _ := json.Marshal(Possession{Format: Format, Manifest: v.Pairing.Manifest, Nonce: v.Nonce})
	if string(possession) != v.ChallengePlaintext || v.ProofPlaintext != v.ChallengePlaintext {
		t.Fatal("proof does not echo canonical challenge bytes")
	}
	for _, packet := range []struct {
		raw       string
		direction string
		sequence  uint64
		plaintext string
		aad       []byte
	}{
		{v.Challenge, clientwire.DirectionResponse, 1, v.ChallengePlaintext, v.ChallengeAAD},
		{v.Proof, clientwire.DirectionRequest, 1, v.ProofPlaintext, v.ProofAAD},
		{v.Receipt, clientwire.DirectionResponse, 2, v.ReceiptPlaintext, v.ReceiptAAD},
	} {
		var opened clientwire.Opened
		if packet.direction == clientwire.DirectionRequest {
			opened, e = clientwire.OpenRequest(hub, owner.Public(), v.Pairing.Manifest.Binding(), []byte(packet.raw))
		} else {
			opened, e = clientwire.OpenResponse(owner, hub.Public(), v.Pairing.Manifest.Binding(), []byte(packet.raw))
		}
		if e != nil || opened.Route != v.Pairing.Route(packet.direction, packet.sequence) || string(opened.Plaintext) != packet.plaintext {
			t.Fatalf("published encrypted packet did not verify: %v", e)
		}
		if !bytes.Equal(vectorAAD(opened.Route), packet.aad) {
			t.Fatal("published clientwire canonical AAD changed")
		}
	}
	nonce, e := VerifyProof(hub, v.Pairing, []byte(v.Proof), at)
	if e != nil || nonce != v.NonceDigest {
		t.Fatal("published possession proof failed")
	}
	receipt, e := VerifyReceipt(owner, v.Pairing, []byte(v.Receipt))
	if e != nil || !reflect.DeepEqual(*receipt, v.ExpectedReceipt) {
		t.Fatal("published exact receipt failed")
	}
	receiptBody, _ := json.Marshal(v.ExpectedReceipt)
	if string(receiptBody) != v.ReceiptPlaintext {
		t.Fatal("published receipt canonical bytes changed")
	}
	for _, mutate := range []func(*PairingFile){
		func(p *PairingFile) { p.Manifest.AccountID = "account_synthetic_other" },
		func(p *PairingFile) { p.Manifest.OwnerID = "human_synthetic_other" },
		func(p *PairingFile) { p.Manifest.HubID = "hub_synthetic_other" },
		func(p *PairingFile) { p.Manifest.AuthorityID = "root_synthetic_other" },
		func(p *PairingFile) { p.Manifest.OperationID = "bootstrap_synthetic_other" },
		func(p *PairingFile) { p.Manifest.Purpose = "CLIENT_ENROLL" },
		func(p *PairingFile) { p.Manifest.CandidateFingerprint = "synthetic-wrong-full-fingerprint" },
		func(p *PairingFile) { p.Manifest.ExpiresAt = "2026-10-12T00:00:00Z" },
	} {
		wrong := v.Pairing
		mutate(&wrong)
		if _, e = VerifyProof(hub, wrong, []byte(v.Proof), at); e == nil {
			t.Fatal("published proof accepted changed scope")
		}
		if _, e = CreateProof(owner, wrong, at); e == nil {
			t.Fatal("published challenge accepted changed scope")
		}
	}
}

func vectorAAD(route clientwire.Route) []byte {
	b, _ := json.Marshal(route)
	return append([]byte("cicada/client-control/packet/v1\x00"), b...)
}

func writePublishedBootstrapVector(t *testing.T) {
	t.Helper()
	// Reuse keys that were already published in the Client wire fixture.
	raw, e := os.ReadFile("../clientwire/testdata/client-control-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var source struct {
		Warning string `json:"warning"`
		Hub     struct {
			Public  e2ee.PublicIdentity `json:"public"`
			Private json.RawMessage     `json:"private_TEST_ONLY"`
		} `json:"hub_TEST_ONLY"`
		Owner struct {
			Public  e2ee.PublicIdentity `json:"public"`
			Private json.RawMessage     `json:"private_TEST_ONLY"`
		} `json:"device_TEST_ONLY"`
	}
	if json.Unmarshal(raw, &source) != nil || source.Warning != publishedVectorWarning {
		t.Fatal("source keys are not explicitly public synthetic material")
	}
	hub, e := e2ee.UnmarshalIdentity(source.Hub.Private)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.UnmarshalIdentity(source.Owner.Private)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	p := PairingFile{Format: Format, Origin: "https://synthetic.invalid", Hub: HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic_owner_bootstrap", Public: hub.Public(), KeyVersion: 1, Suite: Suite}, Manifest: Manifest{Version: 1, Purpose: Purpose, AccountID: "account_synthetic_owner_bootstrap", OwnerID: "human_synthetic_owner_bootstrap", HubID: "hub_synthetic_owner_bootstrap", AuthorityID: "root_synthetic_owner_bootstrap", OperationID: "bootstrap_synthetic_owner_bootstrap", CandidatePublic: owner.Public(), CandidateFingerprint: Fingerprint(owner.Public()), ExpiresAt: at.Add(MaxLifetime).Format(time.RFC3339Nano)}}
	p, digest, e := CreateChallenge(hub, p, at)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := clientwire.OpenResponse(owner, hub.Public(), p.Manifest.Binding(), p.Challenge)
	if e != nil {
		t.Fatal(e)
	}
	var possession Possession
	if json.Unmarshal(opened.Plaintext, &possession) != nil {
		t.Fatal("generated challenge could not be decoded")
	}
	proof, e := CreateProof(owner, p, at)
	if e != nil {
		t.Fatal(e)
	}
	r := Receipt{Format: Format, ManifestDigest: p.Manifest.Digest(), AuthorityID: p.Manifest.AuthorityID, AccountID: p.Manifest.AccountID, OwnerID: p.Manifest.OwnerID, KeyID: owner.Public().ID, State: "ACTIVE", Version: 1}
	receipt, e := CreateReceipt(hub, p, r)
	if e != nil {
		t.Fatal(e)
	}
	manifest, _ := json.Marshal(p.Manifest)
	receiptBody, _ := json.Marshal(r)
	v := publishedBootstrapVector{Version: 1, Warning: publishedVectorWarning, At: at.Format(time.RFC3339Nano), Hub: bootstrapVectorPrivate{Public: hub.Public(), Private: source.Hub.Private}, Owner: bootstrapVectorPrivate{Public: owner.Public(), Private: source.Owner.Private}, Pairing: p, CanonicalManifest: string(manifest), ManifestDigest: p.Manifest.Digest(), CandidateFingerprint: Fingerprint(owner.Public()), Nonce: possession.Nonce, NonceDigest: digest, Challenge: string(p.Challenge), ChallengePlaintext: string(opened.Plaintext), ChallengeAAD: vectorAAD(p.Route(clientwire.DirectionResponse, 1)), Proof: string(proof), ProofPlaintext: string(opened.Plaintext), ProofAAD: vectorAAD(p.Route(clientwire.DirectionRequest, 1)), Receipt: string(receipt), ReceiptPlaintext: string(receiptBody), ReceiptAAD: vectorAAD(p.Route(clientwire.DirectionResponse, 2)), ExpectedReceipt: r}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Dir(publishedVectorPath), 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(publishedVectorPath, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
