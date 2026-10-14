package hubowner

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestHubOwnerWithoutControlProvesKeysAndPreservesPermanentHistory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	db, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setup, err := db.InitializeHubOwnerLocal("Synthetic Owner", "https://synthetic.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(db, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []*e2ee.Identity{ids.Peer, ids.ClientControl, ids.NodeControl} {
		if _, err := service.IssueOwnerBootstrapLocal(key.Public(), ownerbootstrap.Fingerprint(key.Public())); err == nil {
			t.Fatal("Hub-owned key became external Owner candidate")
		}
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := service.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public()))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerbootstrap.CreateProof(owner, *pair, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := service.AcceptOwnerBootstrap(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerbootstrap.VerifyReceipt(owner, *pair, receipt); err != nil {
		t.Fatal(err)
	}
	same, err := service.AcceptOwnerBootstrap(proof)
	if err != nil || !bytes.Equal(same, receipt) {
		t.Fatalf("exact cached receipt recovery: %v", err)
	}
	changed := append(append([]byte(nil), proof...), byte(' '))
	if _, err := service.AcceptOwnerBootstrap(changed); err == nil {
		t.Fatal("nonexact consumed proof accepted")
	}
	if _, err := db.RevokeOwnerApprovalKeyLocal(setup.OwnerID, owner.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptOwnerBootstrap(proof); err == nil {
		t.Fatal("revoked Root recovered cached authority")
	}
	if _, err := service.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public())); err == nil {
		t.Fatal("revocation reopened first Root")
	}
	after, err := service.HubOwnerSetup()
	if err != nil || !after.RootEverEstablished || after.OwnerID != setup.OwnerID || after.AccountID != setup.AccountID {
		t.Fatal("Root history or stable account was changed")
	}
	machines, err := db.ListMachines()
	if err != nil || len(machines) != 0 {
		t.Fatal("Hub service created business Machine")
	}
}
