package control

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

func configuredOwnerHub(t *testing.T) (*Control, Config, *store.HubOwnerSetup) {
	t.Helper()
	root := t.TempDir()
	config := Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")}
	db, e := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	setup, e := db.InitializeHubOwnerLocal("Synthetic human", "https://synthetic.invalid", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	c, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })
	return c, config, setup
}

func TestHubOwnerAccountSeparatesHumanFromCryptoAuthority(t *testing.T) {
	c, _, setup := configuredOwnerHub(t)
	if setup.State != store.HubOwnerReady || setup.SignerState != "NEEDS_OWNER_SIGNER" || setup.RootEverEstablished {
		t.Fatalf("unexpected setup state: %s/%s", setup.State, setup.SignerState)
	}
	if c.ManagerOwnerID() != setup.OwnerID || c.ManagerOwnerID() == c.Identity().ID || setup.AccountID == setup.OwnerID {
		t.Fatal("human/account/crypto identities remain coupled")
	}
	if c.ValidateClientOwnerScope(setup.OwnerID) != nil {
		t.Fatal("configured manager denied")
	}
	if e := c.store.EnsureLocalOwnerPrincipal(c.Identity().ID); e != nil {
		t.Fatal(e)
	}
	if c.ValidateClientOwnerScope(c.Identity().ID) == nil {
		t.Fatal("crypto ID gained management authority")
	}
	group, e := c.CreateGroup(GroupCreateInput{Name: "synthetic group"})
	if e != nil || group.OwnerPrincipalID != setup.OwnerID {
		t.Fatalf("group owner mapping failed: %v", e)
	}
	principal, e := c.AddGroupMember(group.ID, GroupMemberInput{Name: "synthetic peer"})
	if e != nil {
		t.Fatal(e)
	}
	human, e := c.store.GetPrincipal(principal.PrincipalID)
	if e != nil || human.OwnerID != setup.OwnerID {
		t.Fatalf("new role object uses crypto owner: %v", e)
	}
	if _, e = c.BuildClientStatusSnapshot(setup.OwnerID); e != nil {
		t.Fatal(e)
	}
}

func TestOwnerBootstrapPossessionAtomicRecoveryAndPermanentHistory(t *testing.T) {
	c, config, setup := configuredOwnerHub(t)
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	p, e := c.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public()))
	if e != nil {
		t.Fatal(e)
	}
	repeated, e := c.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public()))
	if e != nil || !bytes.Equal(p.Challenge, repeated.Challenge) || p.Manifest.AuthorityID != repeated.Manifest.AuthorityID {
		t.Fatal("local issuance retry replaced challenge")
	}
	other, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.IssueOwnerBootstrapLocal(other.Public(), ownerbootstrap.Fingerprint(other.Public())); e == nil {
		t.Fatal("pending candidate replacement accepted")
	}
	if _, e = ownerbootstrap.CreateProof(other, *p, time.Now()); e == nil {
		t.Fatal("wrong candidate private keys accepted")
	}
	proof, e := ownerbootstrap.CreateProof(owner, *p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	modified := append([]byte{}, proof...)
	modified[len(modified)/2] ^= 1
	if _, e = c.AcceptOwnerBootstrap(modified); e == nil {
		t.Fatal("tampered proof accepted")
	}
	before, e := c.HubOwnerSetup()
	if e != nil || before.RootEverEstablished {
		t.Fatal("failed proof changed root history")
	}
	receipt, e := c.AcceptOwnerBootstrap(proof)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ownerbootstrap.VerifyReceipt(owner, *p, receipt); e != nil {
		t.Fatal(e)
	}
	if e = c.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	restarted, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Shutdown(context.Background())
	if restarted.ManagerOwnerID() != setup.OwnerID || restarted.Identity().ID != c.Identity().ID {
		t.Fatal("restart changed identities")
	}
	exact, e := restarted.AcceptOwnerBootstrap(proof)
	if e != nil || !bytes.Equal(receipt, exact) {
		t.Fatalf("receipt recovery changed bytes: %v", e)
	}
	newProof, e := ownerbootstrap.CreateProof(owner, *p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.AcceptOwnerBootstrap(newProof); e == nil {
		t.Fatal("different signed packet bypassed exact recovery")
	}
	if _, e = restarted.store.RevokeOwnerApprovalKeyLocal(setup.OwnerID, owner.Public().ID, 1); e != nil {
		t.Fatal(e)
	}
	state, e := restarted.HubOwnerSetup()
	if e != nil || !state.RootEverEstablished || state.SignerState != "NEEDS_OWNER_SIGNER" || state.State != store.HubOwnerReady {
		t.Fatal("revocation lost independent readiness/history")
	}
	if _, e = restarted.AcceptOwnerBootstrap(proof); e == nil {
		t.Fatal("revoked root receipt recovered")
	}
	if _, e = restarted.IssueOwnerBootstrapLocal(other.Public(), ownerbootstrap.Fingerprint(other.Public())); e == nil {
		t.Fatal("all-root-revoked reopened first bootstrap")
	}
}

func TestOwnerBootstrapRejectsHubKeysAndWrongFingerprint(t *testing.T) {
	c, _, _ := configuredOwnerHub(t)
	for _, key := range []e2ee.PublicIdentity{c.Identity(), c.ClientControlPublicIdentity(), c.nodeControlIdentity.Public()} {
		if _, e := c.IssueOwnerBootstrapLocal(key, ownerbootstrap.Fingerprint(key)); e == nil {
			t.Fatal("Hub-owned key became Owner root")
		}
	}
	key, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.IssueOwnerBootstrapLocal(key.Public(), "synthetic-wrong-fingerprint"); e == nil {
		t.Fatal("unverified exact candidate accepted")
	}
}

func TestOwnerBootstrapRejectsMissingKEMPossessionAndWrongPurpose(t *testing.T) {
	c, _, _ := configuredOwnerHub(t)
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	p, e := c.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public()))
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(ownerbootstrap.Possession{Format: ownerbootstrap.Format, Manifest: p.Manifest, Nonce: make([]byte, 32)})
	guess, e := clientwire.SealRequest(owner, p.Hub.Public, p.Manifest.Binding(), p.Route(clientwire.DirectionRequest, 1), body)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.AcceptOwnerBootstrap(guess); e == nil {
		t.Fatal("signing key without recovered KEM nonce was accepted")
	}
	opened, e := clientwire.OpenResponse(owner, p.Hub.Public, p.Manifest.Binding(), p.Challenge)
	if e != nil {
		t.Fatal(e)
	}
	for _, operation := range []string{"status.snapshot", "nodes.confirm", "CLIENT_ENROLL"} {
		route := p.Route(clientwire.DirectionRequest, 1)
		route.Operation = operation
		wrong, e := clientwire.SealRequest(owner, p.Hub.Public, p.Manifest.Binding(), route, opened.Plaintext)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.AcceptOwnerBootstrap(wrong); e == nil {
			t.Fatal("wrong-purpose packet accepted")
		}
	}
	r, e := c.HubOwnerSetup()
	if e != nil || r.RootEverEstablished {
		t.Fatal("failed possession created root")
	}
}

func TestHubOwnerConcurrentStartupPreservesAllHubIdentities(t *testing.T) {
	root := t.TempDir()
	config := Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")}
	db, e := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	setup, e := db.InitializeHubOwnerLocal("Synthetic concurrent owner", "https://synthetic.invalid", false)
	if e != nil {
		t.Fatal(e)
	}
	_ = db.Close()
	var wg sync.WaitGroup
	results := make(chan *Control, 4)
	errorsFound := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c, e := New(config); results <- c; errorsFound <- e }()
	}
	wg.Wait()
	close(results)
	close(errorsFound)
	for e := range errorsFound {
		if e != nil {
			t.Fatal(e)
		}
	}
	var expected []string
	for c := range results {
		defer c.Shutdown(context.Background())
		identities := []string{c.Identity().ID, c.ClientControlPublicIdentity().ID, c.nodeControlIdentity.Public().ID}
		if expected == nil {
			expected = identities
		}
		if c.ManagerOwnerID() != setup.OwnerID || strings.Join(expected, ",") != strings.Join(identities, ",") {
			t.Fatal("concurrent startup replaced Hub identity")
		}
	}
	files, e := filepath.Glob(filepath.Join(config.StateDir, "e2ee", "*.tmp"))
	if e != nil || len(files) != 0 {
		t.Fatal("identity creation left temporary private files")
	}
}

// A Hub can complete first-Owner proof before any Control exists. Starting
// managed mode later must preserve all keys, human/account IDs and receipt.
func TestHubOwnerControlCompositionPreservesHubOnlyRoot(t *testing.T) {
	root := t.TempDir()
	config := Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")}
	startup, err := store.AcquireStateStartup(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	db, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setup, err := db.InitializeHubOwnerLocal("Synthetic Owner", "https://synthetic.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(config.StateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	hub, err := hubowner.NewService(db, ids)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := hub.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public()))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerbootstrap.CreateProof(owner, *pair, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := hub.AcceptOwnerBootstrap(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown(context.Background())
	if !reflect.DeepEqual(c.identity.Public(), ids.Peer.Public()) ||
		!reflect.DeepEqual(c.clientIdentity.Public(), ids.ClientControl.Public()) ||
		!reflect.DeepEqual(c.nodeControlIdentity.Public(), ids.NodeControl.Public()) {
		t.Fatal("Control composition changed Hub keys")
	}
	after, err := c.HubOwnerSetup()
	if err != nil || after.OwnerID != setup.OwnerID || after.AccountID != setup.AccountID || !after.RootEverEstablished || after.SignerState != "OWNER_SIGNER_READY" {
		t.Fatalf("Control composition changed established Root/account: %v", err)
	}
	recovered, err := c.AcceptOwnerBootstrap(proof)
	if err != nil || !bytes.Equal(receipt, recovered) {
		t.Fatalf("Control composition lost exact receipt: %v", err)
	}
}
