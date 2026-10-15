package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This is an explicitly synthetic guard fixture, not an activation or private
// key custody test. HTTP tests separately exercise the real activation proof.
func n2LeaseFixture(t *testing.T, expired bool) (*Store, *HubOwnerSetup, *ClientDevice, *e2ee.Identity) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	setup, err := s.InitializeHubOwnerLocal("Synthetic lease guard", "https://lease.synthetic.invalid", false)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := e2ee.NewIdentity()
	device, _ := e2ee.NewIdentity()
	if _, err = s.RegisterOwnerApprovalKeyLocal(setup.OwnerID, owner.Public()); err != nil {
		t.Fatal(err)
	}
	id := wire.AccountDeviceIDPrefix + strings.Repeat("a", 32)
	at := time.Now().UTC()
	grant, err := owner.SignOwnerDeviceGrant(setup.OwnerID, id, device.Public(), setup.HubID, e2ee.OwnerDevicePurposeControl, at, at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{OwnerID: setup.OwnerID, OwnerKeyID: owner.Public().ID, DeviceID: id, DevicePublic: device.Public(), OwnerDeviceGrant: grant})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := json.Marshal(device.Public())
	if _, err = s.db.Exec(`INSERT INTO hub_account_credentials_v1 VALUES(?,?,?,'PBKDF2-SHA256-600000-v1',?,?,1)`, setup.AccountID, setup.OwnerID, "synthetic-lease", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO hub_account_devices_v1 VALUES(?,?,?,?,1,'ACTIVE',?)`, setup.AccountID, setup.OwnerID, id, string(pub), now()); err != nil {
		t.Fatal(err)
	}
	expiry := at.Add(wire.MaxAppLeaseLifetime)
	if expired {
		expiry = at.Add(-time.Second)
	}
	b := wire.ActivationBinding{Format: wire.ActivationFormat, Purpose: wire.PurposeInitialActivation, Origin: setup.Origin, HubID: setup.HubID, AccountID: setup.AccountID, OwnerID: setup.OwnerID, ActivationID: strings.Repeat("b", 32), AccountEpoch: 1, DeviceEpoch: 1, OwnerPublic: owner.Public(), DeviceID: id, DevicePublic: device.Public(), AllowedOperations: wire.ActivationAllowedOperations(), LeaseExpiresAt: expiry.Format(time.RFC3339Nano)}
	bind, _ := json.Marshal(b)
	if _, err = s.db.Exec(`INSERT INTO hub_app_leases_v1 VALUES(?,?,?,?,?,1,1,?,?,'ACTIVE')`, setup.OwnerID, id, setup.AccountID, b.ActivationID, string(bind), owner.Public().ID, b.LeaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	return s, setup, d, owner
}
func n2InsertLogin(t *testing.T, s *Store, setup *HubOwnerSetup, device *ClientDevice) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO hub_account_sessions_v1 VALUES(?,?,?,?,1,1,1,?,'ACTIVE',?)`, strings.Repeat("c", 32), setup.AccountID, setup.OwnerID, device.DeviceID, strings.Repeat("d", 64), time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}
func TestN2LeaseGuardExpiryScopeAndExactHistoricalRecovery(t *testing.T) {
	s, setup, d, _ := n2LeaseFixture(t, false)
	if s.CheckAppLease(setup.OwnerID, d.DeviceID, "nodes.list") == nil {
		t.Fatal("lease bypassed account login")
	}
	n2InsertLogin(t, s, setup, d)
	for _, op := range wire.ActivationAllowedOperations() {
		if err := s.CheckAppLease(setup.OwnerID, d.DeviceID, op); err != nil {
			t.Fatal(err)
		}
	}
	if s.CheckAppLease(setup.OwnerID, d.DeviceID, "devices.revoke") == nil {
		t.Fatal("lease authorized a mutation")
	}
	ops, err := s.FilterAppLeaseOperations(setup.OwnerID, d.DeviceID, []string{"devices.revoke", "nodes.list", "session.capabilities"})
	if err != nil || !reflect.DeepEqual(ops, wire.ActivationAllowedOperations()) {
		t.Fatal("capabilities exceeded lease")
	}
	input := AcceptClientRequestInput{OwnerID: setup.OwnerID, DeviceID: d.DeviceID, SessionEpoch: 1, Sequence: 1, OperationID: "synthetic-n2-read", RouteOperation: "nodes.list", CiphertextDigest: strings.Repeat("e", 64)}
	if _, err = s.AcceptClientRequest(input); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompleteClientRequestWithSealedResponse(setup.OwnerID, d.DeviceID, input.OperationID, []byte("SYNTHETIC OPAQUE RESPONSE")); err != nil {
		t.Fatal(err)
	}
	input.Sequence = 2
	input.OperationID = "synthetic-n2-write"
	input.RouteOperation = "devices.revoke"
	if _, err = s.AcceptClientRequest(input); err == nil {
		t.Fatal("transaction allowed forbidden operation")
	}
	future, err := appLeaseAt(s.db, setup.OwnerID, d.DeviceID, time.Now().UTC().Add(time.Hour))
	if err != nil || future.State != wire.ActivationLeaseExpired {
		t.Fatal("finite lease did not expire")
	}
	if _, err = s.db.Exec(`UPDATE hub_app_leases_v1 SET expires_at=?`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err == nil {
		t.Fatal("runtime lease was extendable")
	}
	if _, err = s.db.Exec(`DELETE FROM hub_app_leases_v1`); err == nil {
		t.Fatal("lease could be deleted to bypass finite scope")
	}
	expired, oldSetup, oldDevice, _ := n2LeaseFixture(t, true)
	n2InsertLogin(t, expired, oldSetup, oldDevice)
	input = AcceptClientRequestInput{OwnerID: oldSetup.OwnerID, DeviceID: oldDevice.DeviceID, SessionEpoch: 1, Sequence: 1, OperationID: "synthetic-old-read", RouteOperation: "nodes.list", CiphertextDigest: strings.Repeat("f", 64)}
	if _, err = expired.AcceptClientRequest(input); err == nil {
		t.Fatal("expired runtime lease admitted fresh read")
	}
	// A committed row may be recovered, but never dispatched a second time.
	_, err = expired.db.Exec(`INSERT INTO client_device_requests_v2(id,owner_id,device_id,session_epoch,sequence,operation_id,route_operation,ciphertext_digest,status,response_packet,created_at,updated_at) VALUES('synthetic-history',?,?,1,1,?,?,?,'COMPLETED',?,?,?)`, input.OwnerID, input.DeviceID, input.OperationID, input.RouteOperation, input.CiphertextDigest, []byte("SYNTHETIC HISTORICAL RESPONSE"), now(), now())
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := expired.AcceptClientRequest(input)
	if err != nil || recovered.Outcome != ClientRequestOutcomeExactRetry {
		t.Fatal("expired lease could not recover historical receipt")
	}
}
func TestN2RestoreFencesLeaseAndPreservesCredentialAndRoot(t *testing.T) {
	s, setup, d, owner := n2LeaseFixture(t, false)
	n2InsertLogin(t, s, setup, d)
	before, err := s.HubAccountCredential(setup.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.fenceHubAccountRestore(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	after, epoch, err := s.HubAccountSetup()
	if err != nil || epoch != 2 || after.AccountID != setup.AccountID || after.OwnerID != setup.OwnerID || !after.RootEverEstablished {
		t.Fatal("restore altered durable Owner scope")
	}
	c, err := s.HubAccountCredential(setup.AccountID)
	if err != nil || !reflect.DeepEqual(c, before) {
		t.Fatal("restore changed credential")
	}
	key, err := s.GetOwnerApprovalKey(setup.OwnerID, owner.Public().ID)
	if err != nil || !reflect.DeepEqual(key.Public, owner.Public()) {
		t.Fatal("restore changed Root public identity")
	}
	if s.CheckAppLease(setup.OwnerID, d.DeviceID, "nodes.list") == nil {
		t.Fatal("restored lease remained authorized")
	}
}
func TestN2DiagnosticReceiptLimitKeepsExactRetryAndTerminalFences(t *testing.T) {
	s, setup, d, _ := n2LeaseFixture(t, false)
	var first HubOwnerOperation
	for i := 0; i < 128; i++ {
		o := HubOwnerOperation{AccountID: setup.AccountID, OwnerID: setup.OwnerID, DeviceID: d.DeviceID, Operation: wire.OperationActivationStatus, ID: fmt.Sprintf("%032x", i+1), Digest: fmt.Sprintf("%064x", i+1), State: wire.ActivationCompleted, Epoch: 1, Response: []byte("SYNTHETIC DIAGNOSTIC")}
		if _, err := s.RejectHubOwnerOperation(o); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = o
		}
	}
	extra := first
	extra.ID = strings.Repeat("b", 32)
	extra.Digest = strings.Repeat("b", 64)
	if _, err := s.RejectHubOwnerOperation(extra); !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
		t.Fatal("diagnostic ledger unbounded")
	}
	if response, err := s.RejectHubOwnerOperation(first); err != nil || !bytes.Equal(response, first.Response) {
		t.Fatal("receipt limit blocked exact retry")
	}
	extra.Operation = wire.OperationActivationComplete
	extra.State = wire.ActivationRejected
	if _, err := s.RejectHubOwnerOperation(extra); err != nil {
		t.Fatal("receipt limit blocked terminal fence")
	}
}
