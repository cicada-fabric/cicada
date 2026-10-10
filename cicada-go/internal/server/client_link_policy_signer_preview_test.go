package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func reviewPolicyHTTPFreshSigner(t *testing.T, f *reviewPolicyHTTPFixture, ownerID string) *e2ee.Identity {
	t.Helper()
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RegisterOwnerApprovalKeyLocal(ownerID, key.Public()); err != nil {
		t.Fatal(err)
	}
	return key
}

func reviewPolicyHTTPSignerPreview(t *testing.T, f *reviewPolicyHTTPFixture, a *reviewPolicyHTTPActor, key *e2ee.Identity) store.CommunicationLinkReviewPolicyPreview {
	t.Helper()
	policy := store.CommunicationLinkReviewPolicy{Mode: store.CommunicationLinkReviewNone, Reviewers: []store.CommunicationLinkReviewer{}}
	reply := f.call(t, a, "link.review_policy_preview", map[string]any{"link_id": f.link.ID, "policy": policy, "owner_key_id": key.Public().ID})
	var preview store.CommunicationLinkReviewPolicyPreview
	if !reply.OK || json.Unmarshal(reply.Result, &preview) != nil || preview.SigningOwnerKey == nil {
		t.Fatal("explicit current signer preview rejected")
	}
	signer := preview.SigningOwnerKey
	if preview.OwnerID != a.ownerID || signer.OwnerID != a.ownerID || signer.KeyID != key.Public().ID || signer.State != store.OwnerApprovalKeyActive || signer.Version != 1 || !reflect.DeepEqual(signer.Public, key.Public()) || e2ee.ValidatePublicIdentity(signer.Public) != nil {
		t.Fatal("preview did not bind the complete independent signer identity")
	}
	return preview
}

func TestClientLinkPolicySignerPreviewFreshNONEWithoutKeyGrant(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	db, err := sql.Open("sqlite", f.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	assertNoKeyGrant := func() {
		t.Helper()
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM communication_link_key_grants_v2 WHERE link_id=?`, f.link.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("fresh NONE fixture acquired a Link KEY grant")
		}
	}
	assertNoKeyGrant()
	for _, actor := range []*reviewPolicyHTTPActor{f.source, f.target} {
		key := reviewPolicyHTTPFreshSigner(t, f, actor.ownerID)
		preview := reviewPolicyHTTPSignerPreview(t, f, actor, key)
		if preview.ExpectedPolicyVersion != 0 || preview.PolicyVersion != 1 || preview.Policy.Mode != store.CommunicationLinkReviewNone {
			t.Fatal("fresh NONE preview changed current/candidate coordinates")
		}
		expiry, err := time.Parse(time.RFC3339Nano, preview.MaximumProofExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := key.SignOwnerLinkReviewPolicy(actor.ownerID, preview.LinkID, preview.ContractDigest, preview.PolicyDigest, uint64(preview.LinkVersion), uint64(preview.PolicyVersion), e2ee.OwnerLinkGrantSide(preview.Side), time.Now().Add(-time.Minute), expiry)
		if err != nil {
			t.Fatal(err)
		}
		if !f.call(t, actor, "link.review_policy_grant", reviewPolicyGrantInput(f.link.ID, key.Public().ID, 0, preview.Policy, proof)).OK {
			t.Fatal("fresh NONE proof required a preexisting KEY grant")
		}
	}
	state, err := f.store.GetCommunicationLinkReviewPolicyForOwner(f.link.ID, f.source.ownerID)
	if err != nil || !state.Current || state.PolicyVersion != 1 || len(state.AcceptedSides) != 2 {
		t.Fatal("bilateral signed NONE did not advance the policy head")
	}
	assertNoKeyGrant()
}

func TestClientLinkPolicySignerPreviewRejectsUntrustedInputs(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	policy := store.CommunicationLinkReviewPolicy{Mode: store.CommunicationLinkReviewNone, Reviewers: []store.CommunicationLinkReviewer{}}
	for _, test := range []struct {
		name  string
		actor *reviewPolicyHTTPActor
		input map[string]any
	}{
		{"unregistered-key", f.source, map[string]any{"owner_key_id": "synthetic-missing-key"}},
		{"peer-key", f.source, map[string]any{"owner_key_id": f.target.ownerKey.Public().ID}},
		{"foreign-owner", f.foreign, map[string]any{"owner_key_id": f.foreign.ownerKey.Public().ID}},
		{"claimed-owner", f.source, map[string]any{"owner_key_id": f.source.ownerKey.Public().ID, "owner_id": f.target.ownerID}},
		{"empty-key", f.source, map[string]any{"owner_key_id": ""}},
		{"null-key", f.source, map[string]any{"owner_key_id": nil}},
		{"numeric-key", f.source, map[string]any{"owner_key_id": 7}},
		{"oversized-key", f.source, map[string]any{"owner_key_id": strings.Repeat("a", 257)}},
		{"padded-key", f.source, map[string]any{"owner_key_id": " " + f.source.ownerKey.Public().ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.input["link_id"], test.input["policy"] = f.link.ID, policy
			reply := f.call(t, test.actor, "link.review_policy_preview", test.input)
			if reply.OK || len(reply.Result) > 0 && !bytes.Equal(reply.Result, []byte("null")) {
				t.Fatal("untrusted request disclosed positive signer evidence")
			}
		})
	}
}

func TestClientLinkPolicySignerPreviewLegacyOmitsAuthority(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	preview := reviewPolicyHTTPPreview(t, f, f.source, store.CommunicationLinkReviewPolicy{Mode: store.CommunicationLinkReviewNone, Reviewers: []store.CommunicationLinkReviewer{}})
	encoded, err := json.Marshal(preview)
	if err != nil || preview.SigningOwnerKey != nil || bytes.Contains(encoded, []byte("signing_owner_key")) {
		t.Fatal("legacy preview silently provided signing authority")
	}
}

func TestClientLinkPolicySignerPreviewRevocationRecheckedAtGrant(t *testing.T) {
	f := newReviewPolicyHTTPFixture(t)
	// The signing key is independent of the authenticated device bootstrap key.
	// Revoking it leaves the encrypted session usable and exercises grant recheck.
	key := reviewPolicyHTTPFreshSigner(t, f, f.source.ownerID)
	preview := reviewPolicyHTTPSignerPreview(t, f, f.source, key)
	expiry, err := time.Parse(time.RFC3339Nano, preview.MaximumProofExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := key.SignOwnerLinkReviewPolicy(f.source.ownerID, preview.LinkID, preview.ContractDigest, preview.PolicyDigest, uint64(preview.LinkVersion), uint64(preview.PolicyVersion), e2ee.OwnerLinkGrantSideSource, time.Now().Add(-time.Minute), expiry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeOwnerApprovalKeyLocal(f.source.ownerID, key.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"link.review_policy_preview", "link.review_policy_grant"} {
		t.Run(op, func(t *testing.T) {
			input := map[string]any{"link_id": f.link.ID, "policy": preview.Policy, "owner_key_id": key.Public().ID}
			if op == "link.review_policy_grant" {
				input = reviewPolicyGrantInput(f.link.ID, key.Public().ID, 0, preview.Policy, proof)
			}
			reply := f.call(t, f.source, op, input)
			if reply.OK || len(reply.Result) > 0 && string(reply.Result) != "null" {
				t.Fatal("revoked signer returned current evidence or accepted a proof")
			}
		})
	}
	state, err := f.store.GetCommunicationLinkReviewPolicyForOwner(f.link.ID, f.source.ownerID)
	if err != nil || state.PolicyVersion != 0 || len(state.AcceptedSides) != 0 {
		t.Fatal("revocation after preview changed policy state")
	}
}
