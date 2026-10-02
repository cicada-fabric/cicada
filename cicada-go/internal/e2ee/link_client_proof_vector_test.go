package e2ee_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func orderedProofJSON(t *testing.T, data []byte, fields ...string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.WriteByte('{')
	for i, k := range fields {
		raw, ok := object[k]
		if !ok {
			t.Fatalf("missing vector claim %s", k)
		}
		value, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			out.WriteByte(',')
		}
		name, _ := json.Marshal(k)
		out.Write(name)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes()
}

func TestLinkClientProofPublicSyntheticVector(t *testing.T) {
	data, err := os.ReadFile("testdata/link-client-proof-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Synthetic               bool            `json:"synthetic"`
		Warning                 string          `json:"warning"`
		ContractDomain          string          `json:"contract_domain"`
		ManifestDomain          string          `json:"manifest_domain"`
		AttestationDomain       string          `json:"attestation_domain"`
		GrantDomain             string          `json:"grant_domain"`
		Manifest                json.RawMessage `json:"manifest"`
		ManifestClaimsCanonical []byte          `json:"manifest_claims_canonical"`
		ContractSignedInput     []byte          `json:"contract_signed_input"`
		ManifestSignedInput     []byte          `json:"manifest_signed_input"`
		AttestationSignedInputs [][]byte        `json:"attestation_signed_inputs"`
		GrantSignedInputs       [][]byte        `json:"grant_signed_inputs"`
		VerificationTime        string          `json:"verification_time"`
		Statuses                []struct {
			LinkID   string                  `json:"link_id"`
			OwnerID  string                  `json:"owner_id"`
			Side     e2ee.OwnerLinkGrantSide `json:"side"`
			Evidence struct {
				LinkVersion    uint64              `json:"link_version"`
				ContractDigest string              `json:"contract_digest"`
				ManifestDigest string              `json:"manifest_digest"`
				OwnerKeyID     string              `json:"owner_key_id"`
				Public         e2ee.PublicIdentity `json:"owner_public_identity"`
				State          string              `json:"owner_key_state"`
				Version        int64               `json:"owner_key_version"`
				Proof          []byte              `json:"signed_proof"`
				VerifiedAt     string              `json:"verified_at"`
			} `json:"evidence"`
		} `json:"statuses"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if !vector.Synthetic || vector.Warning != "PUBLIC TEST FIXTURE ONLY; NEVER INITIALIZE A DEPLOYMENT" || len(vector.Statuses) != 2 || len(vector.AttestationSignedInputs) != 2 || len(vector.GrantSignedInputs) != 2 {
		t.Fatal("not complete public synthetic bilateral vector")
	}
	if vector.ContractDomain != "cicada/communication-link/proposal/v1\x00" || vector.ManifestDomain != "cicada/communication-link/key-manifest/v2\x00" || vector.AttestationDomain != "cicada/fabric/endpoint-key-attestation/v1\x00" || vector.GrantDomain != "cicada/communication-link/owner-key-grant/v2\x00" {
		t.Fatal("production domain drift")
	}
	var manifest struct {
		LinkID            string          `json:"link_id"`
		LinkVersion       uint64          `json:"link_version"`
		ContractDigest    string          `json:"contract_digest"`
		ContractCanonical []byte          `json:"contract_canonical"`
		Digest            string          `json:"digest"`
		Source            json.RawMessage `json:"source"`
		Target            json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(vector.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	canonical := orderedProofJSON(t, vector.Manifest, "version", "link_id", "link_version", "contract_digest", "contract_canonical", "source", "target")
	if !bytes.Equal(canonical, vector.ManifestClaimsCanonical) || !bytes.Equal(append([]byte(vector.ManifestDomain), canonical...), vector.ManifestSignedInput) || !bytes.Equal(append([]byte(vector.ContractDomain), manifest.ContractCanonical...), vector.ContractSignedInput) {
		t.Fatal("canonical bytes drift")
	}
	for _, check := range []struct {
		input  []byte
		digest string
	}{{vector.ContractSignedInput, manifest.ContractDigest}, {vector.ManifestSignedInput, manifest.Digest}} {
		sum := sha256.Sum256(check.input)
		if hex.EncodeToString(sum[:]) != check.digest {
			t.Fatal("manifest or contract digest drift")
		}
	}
	at, err := time.Parse(time.RFC3339Nano, vector.VerificationTime)
	if err != nil {
		t.Fatal(err)
	}
	for i, sideJSON := range []json.RawMessage{manifest.Source, manifest.Target} {
		var side struct {
			Endpoint    string              `json:"endpoint_id"`
			Principal   string              `json:"principal_id"`
			Node        string              `json:"node_id"`
			Binding     string              `json:"binding_id"`
			Epoch       uint64              `json:"binding_epoch"`
			Owner       string              `json:"owner_id"`
			Key         string              `json:"key_id"`
			Fingerprint string              `json:"key_fingerprint"`
			ProofDigest string              `json:"proof_digest"`
			Public      e2ee.PublicIdentity `json:"public_identity"`
			Attestation []byte              `json:"attestation"`
		}
		if err := json.Unmarshal(sideJSON, &side); err != nil {
			t.Fatal(err)
		}
		public, err := e2ee.VerifyEndpointKeyAttestation(side.Attestation, side.Endpoint, side.Principal, side.Node, side.Binding, side.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(public)
		want, _ := json.Marshal(side.Public)
		if !bytes.Equal(got, want) || side.Key != public.ID {
			t.Fatal("attested public identity mismatch")
		}
		fingerprint, err := nodekeys.PeerKeyFingerprint(public)
		if err != nil || fingerprint != side.Fingerprint {
			t.Fatal("Endpoint fingerprint mismatch")
		}
		hash := sha256.Sum256(side.Attestation)
		if hex.EncodeToString(hash[:]) != side.ProofDigest {
			t.Fatal("attestation digest mismatch")
		}
		var attestation e2ee.EndpointKeyAttestation
		if err := json.Unmarshal(side.Attestation, &attestation); err != nil {
			t.Fatal(err)
		}
		attestation.Signature = nil
		claims, err := json.Marshal(attestation)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append([]byte(vector.AttestationDomain), claims...), vector.AttestationSignedInputs[i]) {
			t.Fatal("attestation signed bytes drift")
		}
		s := vector.Statuses[i]
		e := s.Evidence
		expectedSide := []e2ee.OwnerLinkGrantSide{e2ee.OwnerLinkGrantSideSource, e2ee.OwnerLinkGrantSideTarget}[i]
		if s.Side != expectedSide || s.LinkID != manifest.LinkID || s.OwnerID != side.Owner || e.Public.ID != e.OwnerKeyID || e.State != "ACTIVE" || e.Version != 1 || e.LinkVersion != manifest.LinkVersion || e.ContractDigest != manifest.ContractDigest || e.ManifestDigest != manifest.Digest || e.VerifiedAt != vector.VerificationTime {
			t.Fatal("exact bilateral correlation mismatch")
		}
		grantClaims := orderedProofJSON(t, e.Proof, "version", "owner_id", "link_id", "contract_digest", "key_binding_digest", "expected_link_version", "side", "issued_at", "expires_at", "nonce")
		if !bytes.Equal(append([]byte(vector.GrantDomain), grantClaims...), vector.GrantSignedInputs[i]) {
			t.Fatal("Owner signed bytes drift")
		}
		verify := func(proof []byte, version uint64, side e2ee.OwnerLinkGrantSide, now time.Time) error {
			_, err := e2ee.VerifyOwnerLinkKeyGrant(proof, e.Public, s.OwnerID, s.LinkID, e.ContractDigest, e.ManifestDigest, version, side, now)
			return err
		}
		if err := verify(e.Proof, e.LinkVersion, s.Side, at); err != nil {
			t.Fatal(err)
		}
		if verify(e.Proof, e.LinkVersion+1, s.Side, at) == nil || verify(e.Proof, e.LinkVersion, []e2ee.OwnerLinkGrantSide{e2ee.OwnerLinkGrantSideTarget, e2ee.OwnerLinkGrantSideSource}[i], at) == nil || verify(e.Proof, e.LinkVersion, s.Side, at.Add(24*time.Hour)) == nil {
			t.Fatal("wrong version/side/expired vector accepted")
		}
		var proof e2ee.OwnerLinkKeyGrant
		if err := json.Unmarshal(e.Proof, &proof); err != nil {
			t.Fatal(err)
		}
		proof.Signature[0] ^= 1
		tampered, _ := json.Marshal(proof)
		if verify(tampered, e.LinkVersion, s.Side, at) == nil {
			t.Fatal("tampered Owner proof accepted")
		}
		bad := append([]byte(nil), side.Attestation...)
		bad[len(bad)/2] ^= 1
		if _, err := e2ee.VerifyEndpointKeyAttestation(bad, side.Endpoint, side.Principal, side.Node, side.Binding, side.Epoch); err == nil {
			t.Fatal("tampered Endpoint proof accepted")
		}
	}
}
