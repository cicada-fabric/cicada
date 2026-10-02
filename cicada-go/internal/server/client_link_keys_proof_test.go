package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestClientLinkProofEncryptedHTTPBilateralEvidence(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	for _, ep := range []string{f.link.SourceEndpointID, f.link.TargetEndpointID} {
		b, err := f.store.GetSessionBindingForEndpoint(ep)
		if err != nil {
			t.Fatal(err)
		}
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := key.SignEndpointKeyAttestation(ep, b.PrincipalID, b.NodeID, b.ID, b.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.RegisterEndpointKeyCandidate(ep, b.PrincipalID, b.ID, b.Epoch, proof); err != nil {
			t.Fatal(err)
		}
	}
	reply := f.call(t, f.source, "link.key_manifest", map[string]any{"link_id": f.link.ID})
	var manifest store.CommunicationLinkKeyManifest
	if !reply.OK || json.Unmarshal(reply.Result, &manifest) != nil {
		t.Fatal("manifest rejected")
	}
	expiry, err := time.Parse(time.RFC3339, f.link.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proofs := make([][]byte, 2)
	for i, a := range []*reviewPolicyHTTPActor{f.source, f.target} {
		side := []string{"SOURCE", "TARGET"}[i]
		proofs[i], err = a.ownerKey.SignOwnerLinkKeyGrant(a.ownerID, f.link.ID, manifest.ContractDigest, manifest.Digest, uint64(manifest.LinkVersion), e2ee.OwnerLinkGrantSide(side), time.Now().UTC().Add(-time.Minute), expiry)
		if err != nil {
			t.Fatal(err)
		}
		r := f.call(t, a, "link.key_grant", map[string]any{"link_id": f.link.ID, "side": side, "owner_key_id": a.ownerKey.Public().ID, "signed_proof": proofs[i]})
		var status store.CommunicationLinkKeyGrantStatus
		if !r.OK || json.Unmarshal(r.Result, &status) != nil || status.Evidence == nil || !bytes.Equal(status.Evidence.SignedProof, proofs[i]) {
			t.Fatal("accepted grant omitted exact evidence")
		}
	}
	for _, a := range []*reviewPolicyHTTPActor{f.source, f.target} {
		r := f.call(t, a, "link.key_grants", map[string]any{"link_id": f.link.ID})
		var statuses []store.CommunicationLinkKeyGrantStatus
		if !r.OK || json.Unmarshal(r.Result, &statuses) != nil || len(statuses) != 2 {
			t.Fatal("participating owner could not read both sides")
		}
		for i, status := range statuses {
			e := status.Evidence
			trusted := []*reviewPolicyHTTPActor{f.source, f.target}[i].ownerKey.Public()
			if e == nil || e.OwnerPublicIdentity.ID != trusted.ID || e.ManifestDigest != manifest.Digest || !bytes.Equal(e.SignedProof, proofs[i]) {
				t.Fatal("evidence not correlated to trusted Owner and manifest")
			}
			at, err := time.Parse(time.RFC3339Nano, e.VerifiedAt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e2ee.VerifyOwnerLinkKeyGrant(e.SignedProof, trusted, status.OwnerID, status.LinkID, e.ContractDigest, e.ManifestDigest, uint64(e.LinkVersion), e2ee.OwnerLinkGrantSide(status.Side), at); err != nil {
				t.Fatal(err)
			}
		}
		if statuses[0].Evidence.VerifiedAt != statuses[1].Evidence.VerifiedAt {
			t.Fatal("two sides not one snapshot")
		}
	}
	for _, op := range []string{"link.key_grants", "link.key_manifest", "link.key_grant"} {
		input := map[string]any{"link_id": f.link.ID}
		if op == "link.key_grant" {
			input["side"] = "SOURCE"
			input["owner_key_id"] = f.source.ownerKey.Public().ID
			input["signed_proof"] = proofs[0]
		}
		r := f.call(t, f.foreign, op, input)
		if r.OK || len(r.Result) != 0 {
			t.Fatal("third Owner read or submitted unrelated evidence")
		}
	}
	// Neither plaintext manager bearer nor a Client device can use Node authorization.
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/v2/relay/nodes/"+f.link.SourceNodeID+"/links/"+f.link.ID+"/authorization", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer synthetic-review-policy-management")
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("Client acquired Node authorization via bearer fallback")
	}
	if _, err := f.store.RevokeOwnerApprovalKeyLocal(f.target.ownerID, f.target.ownerKey.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	r := f.call(t, f.source, "link.key_grants", map[string]any{"link_id": f.link.ID})
	var revoked []store.CommunicationLinkKeyGrantStatus
	if !r.OK || json.Unmarshal(r.Result, &revoked) != nil || revoked[1].CurrentStatus != store.CommunicationLinkKeyGrantOwnerKeyRevoked || revoked[1].Evidence != nil {
		t.Fatal("revoked peer proof not omitted")
	}
}
