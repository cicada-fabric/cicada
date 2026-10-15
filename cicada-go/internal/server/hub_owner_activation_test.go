package server

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

func n2Post(t *testing.T, f *hubAccountTCPFixture, op string, packet []byte) (int, []byte) {
	t.Helper()
	for i := 0; i < 80; i++ {
		status, response := postHubAccount(t, f, op, packet)
		if status != http.StatusTooManyRequests {
			return status, response
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("fixture admission did not recover")
	return 0, nil
}

func n2AccountFixture(t *testing.T) (*hubAccountTCPFixture, *e2ee.Identity, *e2ee.Identity, string) {
	t.Helper()
	f := newHubAccountTCPFixture(t)
	device, _ := e2ee.NewIdentity()
	owner, _ := e2ee.NewIdentity()
	card, err := f.auth.IssueClaimLocal(false)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := wire.NewClaimPrepare(*card, f.hub, device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.ClaimChallenge
	n2RoundTrip(t, f, wire.OperationClaimPrepare, device, prepare, &challenge)
	complete, err := wire.NewClaimCompleteFromChallenge(f.hub, challenge, device.Public(), "synthetic-existing", "retained synthetic account password", owner.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationClaimComplete, device, complete, &wire.ClaimReceipt{})
	return f, device, owner, prepare.DeviceID
}

func TestN2LegacyContinuationRetainsPendingOwnerCredentialAndDevices(t *testing.T) {
	f, oldDevice, owner, oldID := n2AccountFixture(t)
	setup := *f.setup
	before, err := f.db.HubAccountCredential(setup.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	beforeStatus, err := f.db.HubAccountStatus(setup.AccountID)
	if err != nil || beforeStatus.RootActive {
		t.Fatal("N1 account login activated Root")
	}
	if _, err = f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false); err == nil {
		t.Fatal("pending Owner replaced by INITIAL")
	}
	if _, err = f.auth.IssueActivationLocal(wire.PurposeLegacyContinuation, owner.Public().ID, "bad", false); err == nil {
		t.Fatal("unchecked legacy fingerprint accepted")
	}
	material, err := f.auth.IssueActivationLocal(wire.PurposeLegacyContinuation, owner.Public().ID, ownerbootstrap.Fingerprint(owner.Public()), false)
	if err != nil {
		t.Fatal(err)
	}
	if material.ExpectedOwnerPublic == nil || !reflect.DeepEqual(*material.ExpectedOwnerPublic, owner.Public()) {
		t.Fatal("issuer lost exact pending identity")
	}
	device, _ := e2ee.NewIdentity()
	prepare, ch, _, _ := n2Prepare(t, f, *material, device, owner)
	if _, err = wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "replacement", "replacement credential password", time.Now().UTC()); err == nil {
		t.Fatal("continuation allowed credential reset")
	}
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &wire.ActivationResult{})
	after, err := f.db.HubAccountCredential(setup.AccountID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("continuation changed retained credential")
	}
	status, err := f.db.HubAccountStatus(setup.AccountID)
	if err != nil || status.OwnerID != setup.OwnerID || !status.RootActive || status.OwnerPublic.ID != owner.Public().ID || len(status.Devices) != 2 {
		t.Fatal("continuation changed retained scope/keys")
	}
	if d, err := f.db.HubAccountDevice(setup.AccountID, oldID); err != nil || !reflect.DeepEqual(d.Public, oldDevice.Public()) || d.Epoch != 1 {
		t.Fatal("continuation changed prior account device")
	}
	f.restart(t)
	n2Login(t, f, device, prepare.DeviceID, before.Username, "retained synthetic account password")
	if err = f.db.CheckAppLease(setup.OwnerID, prepare.DeviceID, "nodes.list"); err != nil {
		t.Fatal(err)
	}
}

func n2Reconcile(t *testing.T, f *hubAccountTCPFixture, device *e2ee.Identity, id string, original []byte) wire.AccountReconcileResult {
	t.Helper()
	request, err := wire.NewAccountReconcileRequest(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, id, original, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var result wire.AccountReconcileResult
	n2RoundTrip(t, f, wire.OperationAccountReconcile, device, request, &result)
	if wire.ValidateAccountReconcileTarget(result, original) != nil {
		t.Fatal("reconcile target mismatch")
	}
	return result
}

func TestN2AccountWrongPasswordAndExpiredSessionRecoverWithDurableFence(t *testing.T) {
	f, device, _, id := n2AccountFixture(t)
	prepare, err := wire.NewLoginPrepare(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, id, "synthetic-existing", device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.LoginChallenge
	n2RoundTrip(t, f, wire.OperationLoginPrepare, device, prepare, &challenge)
	wrong, err := wire.NewLoginComplete(f.hub, challenge, "incorrect synthetic password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, err := wire.SealClientRequest(device, f.hub, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := n2Post(t, f, wire.OperationLoginComplete, original); status != 403 {
		t.Fatal("wrong password accepted")
	}
	if result := n2Reconcile(t, f, device, id, original); result.State != wire.ActivationRejected {
		t.Fatal("wrong password did not settle via authenticated rejection")
	}
	f.restart(t)
	if status, _ := n2Post(t, f, wire.OperationLoginComplete, original); status != 403 {
		t.Fatal("rejected exact packet later committed")
	}
	correct, err := wire.NewLoginComplete(f.hub, challenge, "retained synthetic account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var session wire.SessionReceipt
	accepted, _ := n2RoundTrip(t, f, wire.OperationLoginComplete, device, correct, &session)
	if result := n2Reconcile(t, f, device, id, accepted); result.State != wire.ActivationCompleted || len(result.ReceiptPacket) == 0 {
		t.Fatal("accepted login response not recovered")
	}
	inspect, err := wire.NewSessionInspectRequest(session.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	pending, err := wire.SealClientRequest(device, f.hub, inspect)
	if err != nil {
		t.Fatal(err)
	}
	// Disposable fault fixture advances session expiry without changing its key,
	// account/device epochs or stored exact pending packet.
	stopHubAccountFixtureForMutation(t, f)
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`UPDATE hub_account_sessions_v1 SET expires_at=? WHERE state='ACTIVE'`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	restartHubAccountFixtureAfterMutation(t, f)
	if status, _ := n2Post(t, f, wire.OperationSessionInspect, pending); status != 403 {
		t.Fatal("expired session accepted")
	}
	if result := n2Reconcile(t, f, device, id, pending); result.State != wire.ActivationRejected {
		t.Fatal("expired session request did not settle")
	}
	n2Login(t, f, device, id, "synthetic-existing", "retained synthetic account password")
	if status, _ := n2Post(t, f, wire.OperationSessionInspect, pending); status != 403 {
		t.Fatal("new login resurrected rejected old request")
	}
}

func TestN2AccountReconcileRacesOriginalWithoutLateCommit(t *testing.T) {
	for _, sendOriginal := range []bool{false, true} {
		t.Run(map[bool]string{false: "fence first", true: "race"}[sendOriginal], func(t *testing.T) {
			f, device, _, id := n2AccountFixture(t)
			prepare, err := wire.NewLoginPrepare(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, id, "synthetic-existing", device.Public(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			var challenge wire.LoginChallenge
			n2RoundTrip(t, f, wire.OperationLoginPrepare, device, prepare, &challenge)
			complete, err := wire.NewLoginComplete(f.hub, challenge, "retained synthetic account password", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			original, err := wire.SealClientRequest(device, f.hub, complete)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			if sendOriginal {
				wg.Add(1)
				go func() { defer wg.Done(); n2Post(t, f, wire.OperationLoginComplete, original) }()
			}
			result := n2Reconcile(t, f, device, id, original)
			wg.Wait()
			status, response := n2Post(t, f, wire.OperationLoginComplete, original)
			if result.State == wire.ActivationRejected {
				if status != 403 {
					t.Fatal("fenced in-flight original committed later")
				}
			} else if result.State == wire.ActivationCompleted {
				if status != 200 || !bytes.Equal(response, result.ReceiptPacket) {
					t.Fatal("winning original receipt changed")
				}
			} else {
				t.Fatal("reconcile returned nonterminal state")
			}
		})
	}
}
func n2RoundTrip(t *testing.T, f *hubAccountTCPFixture, op string, device *e2ee.Identity, request, response any) ([]byte, []byte) {
	t.Helper()
	packet, err := wire.SealClientRequest(device, f.hub, request)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := n2Post(t, f, op, packet)
	if status != http.StatusOK {
		t.Fatalf("%s HTTP %d", op, status)
	}
	if err = wire.OpenClientResponse(device, f.hub, packet, raw, response); err != nil {
		t.Fatalf("%s response: %v", op, err)
	}
	return packet, raw
}
func n2Prepare(t *testing.T, f *hubAccountTCPFixture, material wire.ActivationMaterial, device, owner *e2ee.Identity) (wire.ActivationPrepare, wire.ActivationChallenge, []byte, []byte) {
	t.Helper()
	at := time.Now().UTC()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := wire.AccountDeviceIDPrefix + id
	grant, err := owner.SignOwnerDeviceGrant(material.OwnerID, deviceID, device.Public(), material.HubID, e2ee.OwnerDevicePurposeControl, at, at.Add(9*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	request, err := wire.NewActivationPrepare(material, f.hub, device.Public(), owner.Public(), deviceID, grant, at)
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.ActivationChallenge
	packet, response := n2RoundTrip(t, f, wire.OperationActivationPrepare, device, request, &challenge)
	if err = wire.ValidateActivationPreparedResponse(challenge, request, packet, f.hub, device.Public(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return request, challenge, packet, response
}
func n2Login(t *testing.T, f *hubAccountTCPFixture, device *e2ee.Identity, id, username, password string) wire.SessionReceipt {
	t.Helper()
	request, err := wire.NewLoginPrepare(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, id, username, device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.LoginChallenge
	n2RoundTrip(t, f, wire.OperationLoginPrepare, device, request, &challenge)
	complete, err := wire.NewLoginComplete(f.hub, challenge, password, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var session wire.SessionReceipt
	n2RoundTrip(t, f, wire.OperationLoginComplete, device, complete, &session)
	return session
}

func TestN2ActivationAtomicProofLeaseAndRestart(t *testing.T) {
	f := newHubAccountTCPFixture(t)
	device, _ := e2ee.NewIdentity()
	owner, _ := e2ee.NewIdentity()
	before := f.hub
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.auth.IssueClaimLocal(false); err == nil {
		t.Fatal("old claim issuer bypassed N2 authority")
	}
	if _, err = f.owner.IssueOwnerBootstrapLocal(owner.Public(), ownerbootstrap.Fingerprint(owner.Public())); err == nil {
		t.Fatal("old bootstrap issuer bypassed active N2 authority")
	}
	prepare, ch, prepPacket, prepResponse := n2Prepare(t, f, *material, device, owner)
	query, err := wire.NewActivationStatusRequest(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, material.ActivationID, prepare.DeviceID, wire.OperationActivationPrepare, prepare.RequestID, wire.ActivationPacketDigest(prepPacket), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var observed wire.ActivationResult
	n2RoundTrip(t, f, wire.OperationActivationStatus, device, query, &observed)
	if observed.TargetState != wire.ActivationCompleted || !bytes.Equal(observed.ReceiptPacket, prepResponse) || wire.ValidateActivationStatusTarget(observed, prepPacket) != nil {
		t.Fatal("status could not carry real PQ prepare challenge")
	}
	f.restart(t)
	status, response := n2Post(t, f, wire.OperationActivationPrepare, prepPacket)
	if status != 200 || !bytes.Equal(response, prepResponse) {
		t.Fatal("lost prepare response did not recover exactly")
	}
	if !reflect.DeepEqual(f.hub, before) {
		t.Fatal("Hub identity changed across restart")
	}
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-n2", "durable synthetic account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var receipt wire.ActivationResult
	packet, accepted := n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &receipt)
	if receipt.State != wire.ActivationCompleted || receipt.RootState != wire.RootActiveState || receipt.LeaseState != wire.ActivationLeaseActive || !receipt.LoginRequired || !reflect.DeepEqual(receipt.AllowedOperations, wire.ActivationAllowedOperations()) {
		t.Fatal("completion authority differs from finite contract")
	}
	if err = f.db.CheckAppLease(f.setup.OwnerID, prepare.DeviceID, "nodes.list"); err == nil {
		t.Fatal("N2 skipped ordinary account login")
	}
	f.restart(t)
	status, response = n2Post(t, f, wire.OperationActivationComplete, packet)
	if status != 200 || !bytes.Equal(response, accepted) {
		t.Fatal("lost complete response did not recover exactly")
	}
	if _, err = f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true); err == nil {
		t.Fatal("established Root reopened")
	}
	n2Login(t, f, device, prepare.DeviceID, "synthetic-n2", "durable synthetic account password")
	if err = f.db.CheckAppLease(f.setup.OwnerID, prepare.DeviceID, "nodes.list"); err != nil {
		t.Fatal(err)
	}
	if err = f.db.CheckAppLease(f.setup.OwnerID, prepare.DeviceID, "intent.submit"); err == nil {
		t.Fatal("finite N2 lease authorized a mutation")
	}
	lease, err := f.db.HubAppLease(f.setup.OwnerID, prepare.DeviceID)
	if err != nil || lease == nil || lease.LoginRequired {
		t.Fatal("finite lease absent after login")
	}
	if _, err = f.db.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: f.setup.OwnerID, OwnerKeyID: owner.Public().ID, DeviceID: prepare.DeviceID, DevicePublic: device.Public(), OwnerDeviceGrant: prepare.OwnerDeviceGrant}); err != nil {
		t.Fatal(err)
	}
	after, err := f.db.HubAppLease(f.setup.OwnerID, prepare.DeviceID)
	if err != nil || after.Binding.LeaseExpiresAt != lease.Binding.LeaseExpiresAt {
		t.Fatal("old registration extended finite lease")
	}
	if _, err = f.db.RevokeOwnerApprovalKeyLocal(f.setup.OwnerID, owner.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	status, response = n2Post(t, f, wire.OperationActivationComplete, packet)
	if status != 200 {
		t.Fatal("revoked diagnostic response absent")
	}
	var revoked wire.ActivationResult
	if wire.OpenClientResponse(device, f.hub, packet, response, &revoked) != nil || revoked.RootState != wire.RootUnavailableState || revoked.LeaseState != wire.ActivationLeaseRevoked || revoked.State != wire.ActivationCancelled {
		t.Fatal("revoked Root replay returned active authority")
	}
	query, err = wire.NewActivationStatusRequest(f.hub, f.setup.Origin, f.setup.AccountID, f.setup.OwnerID, material.ActivationID, prepare.DeviceID, wire.OperationActivationComplete, complete.RequestID, wire.ActivationPacketDigest(packet), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationStatus, device, query, &observed)
	if observed.RootState != wire.RootUnavailableState || observed.LeaseState != wire.ActivationLeaseRevoked || len(observed.AllowedOperations) != 0 || observed.TargetState != wire.ActivationCompleted || !bytes.Equal(observed.ReceiptPacket, accepted) {
		t.Fatal("historical receipt overrode current revocation status")
	}
}

func TestN2ConcurrentPrepareAndCompleteReserveOneTuple(t *testing.T) {
	f := newHubAccountTCPFixture(t)
	device, _ := e2ee.NewIdentity()
	owner, _ := e2ee.NewIdentity()
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	prepare, ch, packet, response := n2Prepare(t, f, *material, device, owner)
	var wg sync.WaitGroup
	results := make(chan []byte, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, raw := n2Post(t, f, wire.OperationActivationPrepare, packet)
			if status != 200 {
				t.Errorf("prepare HTTP %d", status)
			}
			results <- raw
		}()
	}
	wg.Wait()
	close(results)
	for raw := range results {
		if !bytes.Equal(raw, response) {
			t.Fatal("concurrent prepare issued a second challenge")
		}
	}
	otherDevice, _ := e2ee.NewIdentity()
	otherOwner, _ := e2ee.NewIdentity()
	at := time.Now().UTC()
	id, _ := wire.NewRequestID()
	id = wire.AccountDeviceIDPrefix + id
	grant, _ := otherOwner.SignOwnerDeviceGrant(f.setup.OwnerID, id, otherDevice.Public(), f.hub.HubID, e2ee.OwnerDevicePurposeControl, at, at.Add(time.Minute))
	other, err := wire.NewActivationPrepare(*material, f.hub, otherDevice.Public(), otherOwner.Public(), id, grant, at)
	if err != nil {
		t.Fatal(err)
	}
	var refused wire.ActivationResult
	n2RoundTrip(t, f, wire.OperationActivationPrepare, otherDevice, other, &refused)
	if refused.State != wire.ActivationCancelled && refused.State != wire.ActivationRejected {
		t.Fatal("changed tuple replaced reservation")
	}
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-concurrent", "parallel synthetic account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	completePacket, err := wire.SealClientRequest(device, f.hub, complete)
	if err != nil {
		t.Fatal(err)
	}
	results = make(chan []byte, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, raw := n2Post(t, f, wire.OperationActivationComplete, completePacket)
			if status != 200 {
				t.Errorf("complete HTTP %d", status)
			}
			results <- raw
		}()
	}
	wg.Wait()
	close(results)
	var first []byte
	for raw := range results {
		if first == nil {
			first = raw
		} else if !bytes.Equal(first, raw) {
			t.Fatal("concurrent complete receipts differ")
		}
	}
	status, err := f.db.HubAccountStatus(f.setup.AccountID)
	if err != nil || !status.RootActive || status.OwnerPublic.ID != owner.Public().ID || len(status.Devices) != 1 || status.Devices[0].DeviceID != prepare.DeviceID {
		t.Fatal("concurrent completion changed exact candidate")
	}
}

func TestN2MissingProofReusedNonceRollbackAndCancelledEpoch(t *testing.T) {
	f := newHubAccountTCPFixture(t)
	device, _ := e2ee.NewIdentity()
	owner, _ := e2ee.NewIdentity()
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	prepare, ch, prepPacket, _ := n2Prepare(t, f, *material, device, owner)
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-negative", "rollback synthetic account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bad := complete
	bad.OwnerProof = []byte("SYNTHETIC missing KEM/signature possession proof")
	var rejected wire.ActivationResult
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, bad, &rejected)
	if rejected.State != wire.ActivationRejected {
		t.Fatal("missing Owner private-key proof did not reject")
	}
	// Reusing prepare's nonce fails at the last operation-ledger insertion,
	// after the transaction has staged Root, account, grant and lease writes.
	complete.RequestID, _ = wire.NewRequestID()
	complete.ClientNonce = bytes.Clone(prepare.ClientNonce)
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &rejected)
	if rejected.State != wire.ActivationRejected {
		t.Fatal("reused nonce did not reject")
	}
	setup, _, err := f.db.HubAccountSetup()
	if err != nil || setup.RootEverEstablished {
		t.Fatal("failed completion left Root history")
	}
	if _, err = f.db.HubAccountCredential(setup.AccountID); err == nil {
		t.Fatal("failed completion left credential")
	}
	if _, err = f.db.GetClientDevice(setup.OwnerID, prepare.DeviceID); err == nil {
		t.Fatal("failed completion left Client grant")
	}
	if lease, err := f.db.HubAppLease(setup.OwnerID, prepare.DeviceID); err != nil || lease != nil {
		t.Fatal("failed completion left runtime lease")
	}
	if _, err = f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true); err != nil {
		t.Fatal(err)
	}
	status, raw := n2Post(t, f, wire.OperationActivationPrepare, prepPacket)
	if status != 200 {
		t.Fatal("cancelled prepare lacked authenticated diagnostic")
	}
	var cancelled wire.ActivationResult
	if wire.OpenClientResponse(device, f.hub, prepPacket, raw, &cancelled) != nil || cancelled.State != wire.ActivationCancelled {
		t.Fatal("cancelled authority replay returned challenge")
	}
}

func TestN2ExpiredGrantChallengeCannotActivateRoot(t *testing.T) {
	f := newHubAccountTCPFixture(t)
	device, _ := e2ee.NewIdentity()
	owner, _ := e2ee.NewIdentity()
	material, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	expiry := at.Add(2 * time.Second)
	id, _ := wire.NewRequestID()
	id = wire.AccountDeviceIDPrefix + id
	grant, err := owner.SignOwnerDeviceGrant(f.setup.OwnerID, id, device.Public(), f.hub.HubID, e2ee.OwnerDevicePurposeControl, at, expiry)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := wire.NewActivationPrepare(*material, f.hub, device.Public(), owner.Public(), id, grant, at)
	if err != nil {
		t.Fatal(err)
	}
	var ch wire.ActivationChallenge
	n2RoundTrip(t, f, wire.OperationActivationPrepare, device, prepare, &ch)
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-expiry", "expiry synthetic account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(expiry) + 20*time.Millisecond)
	var result wire.ActivationResult
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &result)
	if result.State != wire.ActivationRejected {
		t.Fatal("expired challenge activated Root")
	}
	setup, _, err := f.db.HubAccountSetup()
	if err != nil || setup.RootEverEstablished {
		t.Fatal("expired completion left Root history")
	}
}

func TestN2ClientDispatchAndCapabilitiesIntersectFiniteLease(t *testing.T) {
	f := newHubAccountTCPFixture(t)
	device, _ := e2ee.NewIdentity()
	owner, _ := e2ee.NewIdentity()
	m, err := f.auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	prepare, ch, _, _ := n2Prepare(t, f, *m, device, owner)
	complete, err := wire.NewActivationComplete(ch, f.hub, device.Public(), owner, "synthetic-dispatch", "dispatch synthetic account password", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	n2RoundTrip(t, f, wire.OperationActivationComplete, device, complete, &wire.ActivationResult{})
	c, err := control.New(control.Config{StateDir: f.stateDir, WorkspaceRoot: filepath.Join(t.TempDir(), "workspace"), APIToken: "SYNTHETIC fixture-only token"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown(context.Background())
	h := NewHandler(c).(*Handler)
	if _, err = h.dispatchClientRPC(f.setup.OwnerID, prepare.DeviceID, "", "session.capabilities", []byte(`{}`)); err == nil {
		t.Fatal("dispatch skipped ordinary account login")
	}
	n2Login(t, f, device, prepare.DeviceID, "synthetic-dispatch", "dispatch synthetic account password")
	result, err := h.dispatchClientRPC(f.setup.OwnerID, prepare.DeviceID, "", "session.capabilities", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	capabilities, ok := result.(map[string]any)
	if !ok || !reflect.DeepEqual(capabilities["available_rpc_operations"], wire.ActivationAllowedOperations()) {
		t.Fatal("session capabilities exceeded runtime lease")
	}
	if _, err = h.dispatchClientRPC(f.setup.OwnerID, prepare.DeviceID, "", "devices.list", []byte(`{}`)); err == nil {
		t.Fatal("direct dispatch bypassed finite operation scope")
	}
}
