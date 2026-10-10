package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestCommunicationLinkPolicySignerPreviewExactRegisteredKey(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, false)
	s := f.base.store
	policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewNone, Reviewers: []CommunicationLinkReviewer{}}
	preview, err := s.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy, f.sourceOwner.ownerKeyID)
	if err != nil || preview.SigningOwnerKey == nil || preview.SigningOwnerKey.OwnerID != f.link.SourceOwnerID || preview.SigningOwnerKey.KeyID != f.sourceOwner.ownerKeyID || !reflect.DeepEqual(preview.SigningOwnerKey.Public, f.sourceOwner.identity.Public()) {
		t.Fatalf("exact signer snapshot failed: %v", err)
	}
	legacy, err := s.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy)
	if err != nil || legacy.SigningOwnerKey != nil {
		t.Fatal("omitted key returned authority")
	}
	for _, key := range []string{"", "synthetic-missing", f.targetOwner.ownerKeyID} {
		if got, err := s.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy, key); got != nil || err == nil {
			t.Fatal("unregistered or other-side key disclosed evidence")
		}
	}
	if got, err := s.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, "synthetic-unrelated-owner", policy, f.sourceOwner.ownerKeyID); got != nil || !errors.Is(err, ErrCommunicationLinkNotFound) {
		t.Fatal("foreign owner discovered signer evidence")
	}
}

func TestCommunicationLinkPolicySignerPreviewRejectsCorruptLifecycle(t *testing.T) {
	for _, name := range []string{"revoked", "zero-version", "substituted-identity", "expired-link", "exhausted-policy-version"} {
		t.Run(name, func(t *testing.T) {
			f := newLinkSealedSendTestFixture(t, false)
			s := f.base.store
			policy := CommunicationLinkReviewPolicy{Mode: CommunicationLinkReviewNone, Reviewers: []CommunicationLinkReviewer{}}
			var err error
			switch name {
			case "revoked":
				_, err = s.RevokeOwnerApprovalKeyLocal(f.link.SourceOwnerID, f.sourceOwner.ownerKeyID, 1)
			case "zero-version":
				// Fixture-only corrupt storage; production schema forbids this state.
				if _, err = s.db.Exec(`PRAGMA ignore_check_constraints=ON`); err == nil {
					_, err = s.db.Exec(`UPDATE owner_approval_keys_v2 SET version=0 WHERE owner_id=? AND key_id=?`, f.link.SourceOwnerID, f.sourceOwner.ownerKeyID)
				}
			case "substituted-identity":
				data, marshalErr := json.Marshal(f.targetOwner.identity.Public())
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				_, err = s.db.Exec(`UPDATE owner_approval_keys_v2 SET public_identity_json=? WHERE owner_id=? AND key_id=?`, data, f.link.SourceOwnerID, f.sourceOwner.ownerKeyID)
			case "expired-link":
				_, err = s.db.Exec(`UPDATE communication_links_v2 SET expires_at='2000-01-01T00:00:00Z' WHERE id=?`, f.link.ID)
			case "exhausted-policy-version":
				_, err = s.db.Exec(`INSERT INTO communication_link_review_policy_heads_v2(link_id,policy_version,policy_digest,updated_at) VALUES (?,9223372036854775807,?,'2000-01-01T00:00:00Z')`, f.link.ID, f.link.ContractDigest)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := s.PreviewCommunicationLinkReviewPolicyForOwner(f.link.ID, f.link.SourceOwnerID, policy, f.sourceOwner.ownerKeyID); got != nil || err == nil {
				t.Fatal("invalid lifecycle/scope returned signer material")
			}
		})
	}
}
