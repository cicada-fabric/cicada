package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func TestHubOwnerSetupConcurrentInitializationSingleHuman(t *testing.T) {
	s, e := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var wg sync.WaitGroup
	results := make(chan *HubOwnerSetup, 8)
	errorsFound := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.InitializeHubOwnerLocal("Synthetic owner", "https://synthetic.invalid", false)
			results <- r
			errorsFound <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errorsFound)
	for e := range errorsFound {
		if e != nil {
			t.Fatal(e)
		}
	}
	var account, owner string
	for r := range results {
		if account == "" {
			account, owner = r.AccountID, r.OwnerID
		}
		if r.AccountID != account || r.OwnerID != owner {
			t.Fatal("concurrent setup created competing accounts")
		}
	}
	var n int
	if e = s.db.QueryRow(`SELECT count(*) FROM principals`).Scan(&n); e != nil || n != 1 {
		t.Fatal("setup created duplicate humans")
	}
	if _, e = s.InitializeHubOwnerLocal("Another", "https://synthetic.invalid", false); !errors.Is(e, ErrHubOwnerSetupConflict) {
		t.Fatal("setup overwrite accepted")
	}
	if _, e = s.InitializeHubOwnerLocal("Synthetic owner", "http://public.invalid", true); e == nil {
		t.Fatal("nonloopback plaintext origin accepted")
	}
}

type ownerPreflightFixture struct {
	s                  *Store
	hub, owner         *e2ee.Identity
	p                  ownerbootstrap.PairingFile
	nonce, proofDigest string
	receipt            []byte
}

func newOwnerPreflightFixture(t *testing.T) ownerPreflightFixture {
	t.Helper()
	s, e := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	setup, e := s.InitializeHubOwnerLocal("Synthetic preflight owner", "https://synthetic.invalid", false)
	if e != nil {
		t.Fatal(e)
	}
	hub, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC()
	p := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: setup.Origin, Hub: ownerbootstrap.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: hub.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: setup.AccountID, OwnerID: setup.OwnerID, HubID: setup.HubID, AuthorityID: NewID("root"), OperationID: NewID("bootstrap"), CandidatePublic: owner.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(owner.Public()), ExpiresAt: at.Add(time.Minute).Format(time.RFC3339Nano)}}
	p, nonce, e := ownerbootstrap.CreateChallenge(hub, p, at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.IssueOwnerBootstrapLocal(p, nonce); e != nil {
		t.Fatal(e)
	}
	proof, e := ownerbootstrap.CreateProof(owner, p, at)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(proof)
	receipt, e := ownerbootstrap.CreateReceipt(hub, p, ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: p.Manifest.Digest(), AuthorityID: p.Manifest.AuthorityID, AccountID: p.Manifest.AccountID, OwnerID: p.Manifest.OwnerID, KeyID: owner.Public().ID, State: OwnerApprovalKeyActive, Version: 1})
	if e != nil {
		t.Fatal(e)
	}
	return ownerPreflightFixture{s: s, hub: hub, owner: owner, p: p, nonce: nonce, proofDigest: hex.EncodeToString(digest[:]), receipt: receipt}
}

func TestOwnerBootstrapPreflightRejectsEveryChangedRouteAndRecoversExactCache(t *testing.T) {
	f := newOwnerPreflightFixture(t)
	route := f.p.Route(clientwire.DirectionRequest, 1)
	r, e := f.s.PreflightOwnerBootstrap(route, f.proofDigest)
	if e != nil || len(r.CachedReceipt) != 0 || r.Pairing.Manifest.Digest() != f.p.Manifest.Digest() {
		t.Fatalf("pending preflight failed: %v", e)
	}
	for _, change := range []func(*clientwire.Route){
		func(r *clientwire.Route) { r.Version++ }, func(r *clientwire.Route) { r.Direction = clientwire.DirectionResponse },
		func(r *clientwire.Route) { r.HubID = "synthetic-other" }, func(r *clientwire.Route) { r.OwnerID = "synthetic-other" },
		func(r *clientwire.Route) { r.DeviceID = "bootstrap_unknown" }, func(r *clientwire.Route) { r.SessionEpoch++ },
		func(r *clientwire.Route) { r.Sequence++ }, func(r *clientwire.Route) { r.OperationID = "synthetic-other" },
		func(r *clientwire.Route) { r.Operation = "status.snapshot" }, func(r *clientwire.Route) { r.SenderKeyID = "synthetic-other" },
		func(r *clientwire.Route) { r.ReceiverKeyID = "synthetic-other" }, func(r *clientwire.Route) { r.SenderKeyVersion++ },
		func(r *clientwire.Route) { r.ReceiverKeyVersion++ },
	} {
		changed := route
		change(&changed)
		if _, e = f.s.PreflightOwnerBootstrap(changed, f.proofDigest); !errors.Is(e, ErrOwnerBootstrapRejected) {
			t.Fatal("changed route passed cheap preflight")
		}
	}
	if _, e = f.s.CompleteOwnerBootstrap(f.p.Manifest.AuthorityID, f.nonce, f.proofDigest, f.receipt); e != nil {
		t.Fatal(e)
	}
	r, e = f.s.PreflightOwnerBootstrap(route, f.proofDigest)
	if e != nil || !bytes.Equal(r.CachedReceipt, f.receipt) {
		t.Fatalf("exact committed receipt not recovered: %v", e)
	}
	if _, e = f.s.PreflightOwnerBootstrap(route, strings.Repeat("0", 64)); !errors.Is(e, ErrOwnerBootstrapRejected) {
		t.Fatal("nonexact consumed proof passed cheap preflight")
	}
	if _, e = f.s.RevokeOwnerApprovalKeyLocal(f.p.Manifest.OwnerID, f.p.Manifest.CandidatePublic.ID, 1); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.PreflightOwnerBootstrap(route, f.proofDigest); !errors.Is(e, ErrOwnerBootstrapRejected) {
		t.Fatal("revoked Root released cached receipt")
	}
}

func TestOwnerBootstrapPreflightCannotAuthorizeAcrossRootOrOwnerRevocation(t *testing.T) {
	for _, kind := range []string{"root-established", "owner-revoked"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerPreflightFixture(t)
			if _, e := f.s.PreflightOwnerBootstrap(f.p.Route(clientwire.DirectionRequest, 1), f.proofDigest); e != nil {
				t.Fatal(e)
			}
			if kind == "root-established" {
				if _, e := f.s.RegisterOwnerApprovalKeyLocal(f.p.Manifest.OwnerID, f.p.Manifest.CandidatePublic); e != nil {
					t.Fatal(e)
				}
			} else {
				if _, e := f.s.RevokePrincipal(f.p.Manifest.OwnerID, "synthetic revocation after preflight"); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.s.PreflightOwnerBootstrap(f.p.Route(clientwire.DirectionRequest, 1), f.proofDigest); !errors.Is(e, ErrOwnerBootstrapRejected) {
				t.Fatal("ineligible state passed cheap preflight")
			}
			if _, e := f.s.CompleteOwnerBootstrap(f.p.Manifest.AuthorityID, f.nonce, f.proofDigest, f.receipt); !errors.Is(e, ErrOwnerBootstrapRejected) {
				t.Fatal("preflight bypassed final transaction guard")
			}
		})
	}
}

func TestOwnerBootstrapPreflightCachedReceiptRequiresCurrentExactKeyAndOwner(t *testing.T) {
	for _, kind := range []string{"key-version", "key-public", "owner-revoked"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerPreflightFixture(t)
			if _, e := f.s.CompleteOwnerBootstrap(f.p.Manifest.AuthorityID, f.nonce, f.proofDigest, f.receipt); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "key-version":
				_, e = f.s.db.Exec(`UPDATE owner_approval_keys_v2 SET version=2 WHERE owner_id=? AND key_id=?`, f.p.Manifest.OwnerID, f.p.Manifest.CandidatePublic.ID)
			case "key-public":
				_, e = f.s.db.Exec(`UPDATE owner_approval_keys_v2 SET public_identity_json='{}' WHERE owner_id=? AND key_id=?`, f.p.Manifest.OwnerID, f.p.Manifest.CandidatePublic.ID)
			case "owner-revoked":
				_, e = f.s.RevokePrincipal(f.p.Manifest.OwnerID, "synthetic revocation after consumption")
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.s.PreflightOwnerBootstrap(f.p.Route(clientwire.DirectionRequest, 1), f.proofDigest); !errors.Is(e, ErrOwnerBootstrapRejected) {
				t.Fatal("changed current key or Owner released cached receipt")
			}
		})
	}
}

func TestOwnerBootstrapPreflightRejectsExpiredPendingButAllowsHistoricalExactCache(t *testing.T) {
	f := newOwnerPreflightFixture(t)
	// Synthetic history represents an authority issued and consumed before
	// the current clock; no production expiry or immutable row is rewritten.
	p := f.p
	p.Manifest.AuthorityID = NewID("root")
	p.Manifest.OperationID = NewID("bootstrap")
	p.Manifest.ExpiresAt = "2025-01-01T00:00:00Z"
	at := time.Date(2024, 12, 31, 23, 55, 0, 0, time.UTC)
	p, nonce, e := ownerbootstrap.CreateChallenge(f.hub, p, at)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := ownerbootstrap.CreateProof(f.owner, p, at)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(proof)
	proofDigest := hex.EncodeToString(digest[:])
	receipt, e := ownerbootstrap.CreateReceipt(f.hub, p, ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: p.Manifest.Digest(), AuthorityID: p.Manifest.AuthorityID, AccountID: p.Manifest.AccountID, OwnerID: p.Manifest.OwnerID, KeyID: p.Manifest.CandidatePublic.ID, State: OwnerApprovalKeyActive, Version: 1})
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.s.db.Exec(`UPDATE owner_bootstrap_authority_v1 SET state='CANCELLED' WHERE authority_id=?`, f.p.Manifest.AuthorityID)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.s.db.Exec(`INSERT INTO owner_bootstrap_authority_v1(authority_id,account_id,owner_id,manifest_digest,pairing_json,nonce_digest,state,expires_at,proof_digest,receipt_packet,created_at,consumed_at) VALUES(?,?,?,?,?,?,'PENDING',?,'',NULL,'2024-12-31T23:50:00Z','')`, p.Manifest.AuthorityID, p.Manifest.AccountID, p.Manifest.OwnerID, p.Manifest.Digest(), string(encoded), nonce, p.Manifest.ExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.PreflightOwnerBootstrap(p.Route(clientwire.DirectionRequest, 1), proofDigest); !errors.Is(e, ErrOwnerBootstrapRejected) {
		t.Fatal("expired pending authority passed cheap preflight")
	}
	if _, e = f.s.CompleteOwnerBootstrap(p.Manifest.AuthorityID, nonce, proofDigest, receipt); !errors.Is(e, ErrOwnerBootstrapRejected) {
		t.Fatal("expired pending authority bypassed final transaction")
	}
	// Populate a separate synthetic, already committed historical authority.
	_, e = f.s.db.Exec(`UPDATE owner_bootstrap_authority_v1 SET state='EXPIRED' WHERE authority_id=?`, p.Manifest.AuthorityID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.RegisterOwnerApprovalKeyLocal(p.Manifest.OwnerID, p.Manifest.CandidatePublic); e != nil {
		t.Fatal(e)
	}
	p.Manifest.AuthorityID = NewID("root")
	p.Manifest.OperationID = NewID("bootstrap")
	p, nonce, e = ownerbootstrap.CreateChallenge(f.hub, p, at)
	if e != nil {
		t.Fatal(e)
	}
	proof, e = ownerbootstrap.CreateProof(f.owner, p, at)
	if e != nil {
		t.Fatal(e)
	}
	digest = sha256.Sum256(proof)
	proofDigest = hex.EncodeToString(digest[:])
	receipt, e = ownerbootstrap.CreateReceipt(f.hub, p, ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: p.Manifest.Digest(), AuthorityID: p.Manifest.AuthorityID, AccountID: p.Manifest.AccountID, OwnerID: p.Manifest.OwnerID, KeyID: p.Manifest.CandidatePublic.ID, State: OwnerApprovalKeyActive, Version: 1})
	if e != nil {
		t.Fatal(e)
	}
	encoded, e = json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.s.db.Exec(`INSERT INTO owner_bootstrap_authority_v1(authority_id,account_id,owner_id,manifest_digest,pairing_json,nonce_digest,state,expires_at,proof_digest,receipt_packet,created_at,consumed_at) VALUES(?,?,?,?,?,?,'CONSUMED',?,?,?,'2024-12-31T23:50:00Z','2024-12-31T23:55:00Z')`, p.Manifest.AuthorityID, p.Manifest.AccountID, p.Manifest.OwnerID, p.Manifest.Digest(), string(encoded), nonce, p.Manifest.ExpiresAt, proofDigest, receipt)
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.s.PreflightOwnerBootstrap(p.Route(clientwire.DirectionRequest, 1), proofDigest)
	if e != nil || !bytes.Equal(r.CachedReceipt, receipt) {
		t.Fatalf("expired committed exact receipt was denied: %v", e)
	}
	if _, e = ownerbootstrap.VerifyReceipt(f.owner, p, r.CachedReceipt); e != nil {
		t.Fatal("historical cached receipt did not bind the exact stored manifest")
	}
}

func TestHubOwnerLegacyAdoptionPreservesExactHumanAndGuests(t *testing.T) {
	s, e := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.EnsureLocalOwnerPrincipal("synthetic-original-manager"); e != nil {
		t.Fatal(e)
	}
	if e = s.EnsureLocalOwnerPrincipal("synthetic-external-guest"); e != nil {
		t.Fatal(e)
	}
	root, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RegisterOwnerApprovalKeyLocal("synthetic-original-manager", root.Public()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RevokeOwnerApprovalKeyLocal("synthetic-original-manager", root.Public().ID, 1); e != nil {
		t.Fatal(e)
	}
	if _, e = s.InitializeHubOwnerLocal("Wrong signup", "https://synthetic.invalid", false); e == nil {
		t.Fatal("old state overwritten by fresh signup")
	}
	legacy, e := s.EnsureHubManagerLocal("synthetic-original-manager")
	if e != nil || legacy.State != HubOwnerLegacyCompat || legacy.Provenance != "EXISTING_LEGACY" || !legacy.RootEverEstablished {
		t.Fatalf("legacy association lost: %v", e)
	}
	if _, e = s.AdoptLegacyHubOwnerLocal("synthetic-external-guest", "Guest", "https://synthetic.invalid", false); e == nil {
		t.Fatal("guest promoted to manager")
	}
	adopted, e := s.AdoptLegacyHubOwnerLocal(legacy.OwnerID, "Synthetic upgraded owner", "https://synthetic.invalid", false)
	if e != nil || adopted.State != HubOwnerReady || adopted.OwnerID != legacy.OwnerID || adopted.AccountID != legacy.AccountID || !adopted.RootEverEstablished {
		t.Fatalf("legacy adoption replaced authority: %v", e)
	}
	key, e := s.GetOwnerApprovalKey(legacy.OwnerID, root.Public().ID)
	if e != nil || key.State != OwnerApprovalKeyRevoked || key.Version != 2 {
		t.Fatal("adoption rewrote prior root")
	}
	if _, e = s.GetPrincipal("synthetic-external-guest"); e != nil {
		t.Fatal("adoption removed external human")
	}
}

func TestHubOwnerGeneratedCompatibilityCannotEstablishSetup(t *testing.T) {
	s, e := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.CheckHubServeSetupLocal("") == nil {
		t.Fatal("fresh production serve admitted")
	}
	r, e := s.EnsureHubManagerLocal("synthetic-newly-generated-hub-key")
	if e != nil || r.Provenance != "GENERATED_COMPAT" {
		t.Fatal("fresh compatibility provenance absent")
	}
	if _, e = s.AdoptLegacyHubOwnerLocal(r.OwnerID, "Wrong", "https://synthetic.invalid", false); e == nil {
		t.Fatal("newly fabricated legacy evidence adopted")
	}
	if s.CheckHubServeSetupLocal(r.OwnerID) == nil {
		t.Fatal("generated compatibility permitted production serve")
	}
}

func TestHubOwnerMigrationBackfillsRevokedRootAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	injected := errors.New("synthetic interrupted owner setup migration")
	failed, e := openStoreWithMigrationHook(path, func(id, phase string) error {
		if id == "v1.hub.owner_setup_bootstrap" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(e, injected) {
		t.Fatal("migration interruption not observed")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	public, e := json.Marshal(owner.Public())
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`INSERT INTO owner_approval_keys_v2(owner_id,key_id,public_identity_json,state,version,created_at,updated_at,revoked_at) VALUES('synthetic-old-manager',?,?,'REVOKED',2,'2026-10-01T00:00:00Z','2026-10-02T00:00:00Z','2026-10-02T00:00:00Z')`, owner.Public().ID, string(public))
	if e != nil {
		t.Fatal(e)
	}
	before := sqliteRowsForTest(t, db, `SELECT * FROM owner_approval_keys_v2`)
	_ = db.Close()
	s, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var n int
	if e = s.db.QueryRow(`SELECT count(*) FROM owner_root_history_v1 WHERE owner_id='synthetic-old-manager'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("revoked root history was not backfilled")
	}
	if after := sqliteRowsForTest(t, s.db, `SELECT * FROM owner_approval_keys_v2`); !reflect.DeepEqual(before, after) {
		t.Fatal("migration changed historical root bytes")
	}
	if _, e = s.db.Exec(`DELETE FROM owner_root_history_v1`); e == nil {
		t.Fatal("permanent root history deleted")
	}
	entry, e := s.readV2Migration(60)
	if e != nil || entry.Attempts != 2 || entry.State != v2MigrationApplied {
		t.Fatal("migration did not resume exactly")
	}
}
