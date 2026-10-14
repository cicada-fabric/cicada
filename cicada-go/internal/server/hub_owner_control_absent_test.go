package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestHubOwnerIdentityAndBootstrapWithoutControl(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	persistence, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	setup, err := persistence.InitializeHubOwnerLocal("Synthetic Owner", "https://synthetic.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := hubidentity.LoadOrCreate(stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	ownerService, err := hubowner.NewService(persistence, identities)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHubHandler(ownerService)
	if handler.(*Handler).control != nil || handler.(*Handler).fabricService != nil {
		t.Fatal("Hub handler started a business object")
	}
	hub := httptest.NewServer(handler)
	defer hub.Close()
	response, err := http.Get(hub.URL + "/v2/client/identity")
	if err != nil {
		t.Fatal(err)
	}
	var published clientoperator.HubIdentity
	err = json.NewDecoder(response.Body).Decode(&published)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || published.HubID != setup.HubID || published.KeyVersion != 1 || published.Contract != "android-hub-v1" || published.Suite != ownerbootstrap.Suite || !reflect.DeepEqual(published.Public, identities.ClientControl.Public()) {
		t.Fatal("pure Hub public identity drifted from existing wire shape")
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ownerService.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public()))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ownerbootstrap.CreateProof(owner, *pair, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string, body []byte) (int, []byte) {
		t.Helper()
		res, err := http.Post(hub.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, data
	}
	status, receipt := post("/v2/owner/bootstrap/accept", proof)
	if status != http.StatusOK {
		t.Fatalf("Control-absent finite proof status=%d", status)
	}
	verified, err := ownerbootstrap.VerifyReceipt(owner, *pair, receipt)
	if err != nil || verified.OwnerID != setup.OwnerID {
		t.Fatal("pure Hub receipt did not bind the configured Owner")
	}
	status, retried := post("/v2/owner/bootstrap/accept", proof)
	if status != http.StatusOK || !bytes.Equal(receipt, retried) {
		t.Fatal("pure Hub exact receipt retry changed")
	}
	if status, _ := post("/v2/client/devices/enroll", []byte(`{}`)); status != http.StatusServiceUnavailable {
		t.Fatal("Hub handler enabled management Client enrollment")
	}
	if status, _ := post("/v2/client/rpc", []byte(`{}`)); status != http.StatusServiceUnavailable {
		t.Fatal("Hub handler enabled Control dispatch")
	}
	if status, _ := post("/v2/owner/bootstrap/issue", []byte(`{}`)); status >= 200 && status < 300 {
		t.Fatal("public route issued authority")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "workspace-snapshots")); !os.IsNotExist(err) {
		t.Fatal("pure Hub setup created workspace snapshots")
	}
	machines, err := persistence.ListMachines()
	if err != nil || len(machines) != 0 {
		t.Fatal("pure Hub setup created business Machines")
	}
	if _, err := persistence.RevokeOwnerApprovalKeyLocal(setup.OwnerID, owner.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	if status, _ := post("/v2/owner/bootstrap/accept", proof); status != http.StatusForbidden {
		t.Fatal("revoked Root recovered cached receipt without Control")
	}
}
