package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func acceptedLinkProofFixture(t *testing.T) (*communicationLinkGrantFixture, *CommunicationLinkKeyManifest, [][]byte) {
	t.Helper()
	f := newCommunicationLinkGrantFixture(t)
	registerLinkEndpointKey(t, f.store, "ep_source")
	registerLinkEndpointKey(t, f.store, "ep_target")
	m, err := f.store.GetCommunicationLinkKeyManifest(f.link.ID, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	proofs := [][]byte{signLinkKeyGrant(t, f.sourceKey, f.link, m, e2ee.OwnerLinkGrantSideSource), signLinkKeyGrant(t, f.targetKey, f.link, m, e2ee.OwnerLinkGrantSideTarget)}
	for i, side := range []string{"SOURCE", "TARGET"} {
		key := []string{f.sourceKeyID, f.targetKeyID}[i]
		for retry := 0; retry < 2; retry++ {
			status, err := f.store.RecordCommunicationLinkKeyGrant("owner_a", f.link.ID, side, key, proofs[i])
			if err != nil || status.Evidence == nil || !bytes.Equal(status.Evidence.SignedProof, proofs[i]) {
				t.Fatal("grant response omitted exact verified proof", err)
			}
		}
	}
	return f, m, proofs
}

func TestCommunicationLinkClientProofEvidence(t *testing.T) {
	f, m, proofs := acceptedLinkProofFixture(t)
	statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || len(statuses) != 2 {
		t.Fatal(err)
	}
	for i, status := range statuses {
		e := status.Evidence
		if e == nil || e.ManifestDigest != m.Digest || e.ContractDigest != m.ContractDigest || e.LinkVersion != m.LinkVersion || e.OwnerKeyState != "ACTIVE" || e.OwnerKeyVersion != 1 || e.OwnerKeyID != status.KeyID || e.OwnerPublicIdentity.ID != status.KeyID || !bytes.Equal(e.SignedProof, proofs[i]) {
			t.Fatal("incomplete evidence")
		}
		at, err := time.Parse(time.RFC3339Nano, e.VerifiedAt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e2ee.VerifyOwnerLinkKeyGrant(e.SignedProof, e.OwnerPublicIdentity, status.OwnerID, status.LinkID, e.ContractDigest, e.ManifestDigest, uint64(e.LinkVersion), e2ee.OwnerLinkGrantSide(status.Side), at); err != nil {
			t.Fatal(err)
		}
	}
	if statuses[0].Evidence.VerifiedAt != statuses[1].Evidence.VerifiedAt {
		t.Fatal("sides used different snapshots")
	}
	if got, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "third_owner"); !errors.Is(err, ErrCommunicationLinkNotFound) || got != nil {
		t.Fatal("unauthorized evidence enumeration")
	}
	// A caller mutation cannot alter the historical bytes held by Store.
	statuses[0].Evidence.SignedProof[0] ^= 1
	got, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
	if err != nil || !bytes.Equal(got[0].Evidence.SignedProof, proofs[0]) {
		t.Fatal("response alias modified stored proof")
	}
}

func TestCommunicationLinkClientProofEvidenceOmittedWhenInvalidated(t *testing.T) {
	for _, kind := range []string{"signature", "wrong_side", "nonce", "owner", "version", "revoke", "expiry", "unjoined", "old_binding", "link_revoked", "key_corrupt", "key_json"} {
		t.Run(kind, func(t *testing.T) {
			f, m, proofs := acceptedLinkProofFixture(t)
			want := CommunicationLinkKeyGrantInvalid
			switch kind {
			case "signature", "wrong_side", "expiry":
				var proof e2ee.OwnerLinkKeyGrant
				if err := json.Unmarshal(proofs[0], &proof); err != nil {
					t.Fatal(err)
				}
				if kind == "signature" {
					proof.Signature[0] ^= 1
				}
				if kind == "wrong_side" {
					proof.Side = e2ee.OwnerLinkGrantSideTarget
				}
				if kind == "expiry" {
					proof.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
					want = CommunicationLinkKeyGrantProofExpired
				}
				data, _ := json.Marshal(proof)
				if _, err := f.store.db.Exec(`UPDATE communication_link_key_grants_v2 SET signed_proof=? WHERE link_id=? AND side='SOURCE'`, data, f.link.ID); err != nil {
					t.Fatal(err)
				}
			case "nonce":
				if _, err := f.store.db.Exec(`UPDATE communication_link_key_grants_v2 SET nonce=? WHERE link_id=? AND side='SOURCE'`, "synthetic_corrupt_nonce", f.link.ID); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if _, err := f.store.db.Exec(`UPDATE communication_link_key_grants_v2 SET owner_id=?,key_id=? WHERE link_id=? AND side='SOURCE'`, "owner_a", f.targetKeyID, f.link.ID); err != nil {
					t.Fatal(err)
				}
			case "version":
				if _, err := f.store.db.Exec(`UPDATE communication_links_v2 SET version=version+1 WHERE id=?`, f.link.ID); err != nil {
					t.Fatal(err)
				}
				want = CommunicationLinkKeyGrantBindingStale
			case "revoke":
				if _, err := f.store.RevokeOwnerApprovalKeyLocal("owner_a", f.sourceKeyID, 1); err != nil {
					t.Fatal(err)
				}
				want = CommunicationLinkKeyGrantOwnerKeyRevoked
			case "key_corrupt", "key_json":
				data := "{}"
				if kind == "key_json" {
					data = "{"
				}
				if _, err := f.store.db.Exec(`UPDATE owner_approval_keys_v2 SET public_identity_json=? WHERE owner_id=? AND key_id=?`, data, "owner_a", f.sourceKeyID); err != nil {
					t.Fatal(err)
				}
			case "unjoined":
				if _, err := f.store.db.Exec(`UPDATE memberships SET status='revoked' WHERE principal_id=?`, m.Source.PrincipalID); err != nil {
					t.Fatal(err)
				}
				want = CommunicationLinkKeyGrantBindingStale
			case "old_binding":
				if _, err := f.store.ReleaseSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner, m.Source.BindingEpoch); err != nil {
					t.Fatal(err)
				}
				want = CommunicationLinkKeyGrantBindingStale
			case "link_revoked":
				if _, err := f.store.db.Exec(`UPDATE communication_links_v2 SET state='REVOKED' WHERE id=?`, f.link.ID); err != nil {
					t.Fatal(err)
				}
				want = CommunicationLinkKeyGrantBindingStale
			}
			statuses, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
			if err != nil || statuses[0].CurrentStatus != want || statuses[0].Evidence != nil {
				t.Fatalf("invalidated %s evidence not omitted with %s: err=%v", kind, want, err)
			}
			data, _ := json.Marshal(statuses[0])
			if bytes.Contains(data, []byte(`"signed_proof"`)) || bytes.Contains(data, []byte(`"owner_public_identity"`)) {
				t.Fatal("invalidated proof leaked")
			}
		})
	}
}

func TestCommunicationLinkClientProofSnapshotRace(t *testing.T) {
	f, m, _ := acceptedLinkProofFixture(t)
	// Separate Store/connection bypasses the reader's mutex: consistency must
	// come from the SQLite transaction rather than in-process serialization.
	writer, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := f.store.GetCommunicationLinkKeyGrantStatuses(f.link.ID, "owner_a")
			if err != nil {
				t.Error(err)
				return
			}
			for _, s := range got {
				if s.CurrentStatus == CommunicationLinkKeyGrantAccepted {
					if s.Evidence == nil || s.Evidence.ManifestDigest != m.Digest {
						t.Error("accepted snapshot missing evidence")
					}
				} else if s.Evidence != nil {
					t.Error("stale snapshot exposed evidence")
				}
			}
			if (got[0].Evidence == nil) != (got[1].Evidence == nil) {
				t.Error("snapshot mixed two binding epochs")
			}
			if got[0].Evidence != nil && got[0].Evidence.VerifiedAt != got[1].Evidence.VerifiedAt {
				t.Error("snapshot times differ")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := writer.ReleaseSessionBindingLease(f.sourceBindingID, f.sourceLeaseOwner, m.Source.BindingEpoch); err != nil {
			t.Error(err)
		}
	}()
	close(start)
	wg.Wait()
}
