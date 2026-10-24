package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/store"
)

type hubAccountTCPFixture struct {
	stateDir string
	dbPath   string
	db       *store.Store
	setup    *store.HubOwnerSetup
	ids      hubidentity.Set
	owner    *hubowner.Service
	auth     *hubauth.Service
	hub      wire.HubIdentity
	http     *httptest.Server
	client   *http.Client
}

func newHubAccountTCPFixture(t *testing.T) *hubAccountTCPFixture {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	dbPath := filepath.Join(stateDir, "cicada.sqlite3")
	db, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := db.InitializeHubOwnerLocal("Synthetic account owner", "https://hub.synthetic.invalid", false)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	f := &hubAccountTCPFixture{stateDir: stateDir, dbPath: dbPath, db: db, setup: setup}
	t.Cleanup(func() {
		if f.http != nil {
			f.http.Close()
		}
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	f.start(t)
	return f
}

func (f *hubAccountTCPFixture) start(t *testing.T) {
	t.Helper()
	var err error
	f.ids, err = hubidentity.LoadOrCreate(f.stateDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = hubowner.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.auth, err = hubauth.NewService(f.db, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	f.hub, err = f.auth.HubIdentity()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHubHandlerWithAccount(f.owner, f.auth)
	composed := handler.(*Handler)
	if composed.control != nil || composed.fabricService != nil {
		t.Fatal("account Hub composition initialized Control or Fabric business")
	}
	f.http = httptest.NewServer(handler)
}

func (f *hubAccountTCPFixture) restart(t *testing.T) {
	t.Helper()
	if f.http != nil {
		f.http.Close()
		f.http = nil
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		f.db = nil
	}
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.setup, _, err = f.db.HubAccountSetup()
	if err != nil {
		t.Fatal(err)
	}
	f.start(t)
}

func accountPath(operation string) string {
	if path := wire.ActivationHTTPPath(operation); path != "" {
		return path
	}
	switch operation {
	case wire.OperationClaimPrepare:
		return "/v2/owner/account/claim/prepare"
	case wire.OperationClaimComplete:
		return "/v2/owner/account/claim/complete"
	case wire.OperationLoginPrepare:
		return "/v2/owner/account/login/prepare"
	case wire.OperationLoginComplete:
		return "/v2/owner/account/login/complete"
	case wire.OperationSessionInspect:
		return "/v2/owner/account/session/inspect"
	case wire.OperationSessionLogout:
		return "/v2/owner/account/session/logout"
	default:
		return "/v2/owner/account/unknown"
	}
}

func postHubAccount(t *testing.T, f *hubAccountTCPFixture, operation string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.http.URL+accountPath(operation), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.setup.Origin)
	client := f.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func hubAccountRoundTrip(t *testing.T, f *hubAccountTCPFixture, operation string, device *e2ee.Identity, request any, response any) ([]byte, []byte) {
	t.Helper()
	packet, err := wire.SealClientRequest(device, f.hub, request)
	if err != nil {
		t.Fatal(err)
	}
	status, result := postHubAccount(t, f, operation, packet)
	if status != http.StatusOK {
		t.Fatalf("%s status=%d", operation, status)
	}
	if err := wire.OpenClientResponse(device, f.hub, packet, result, response); err != nil {
		t.Fatalf("%s response did not verify: %v", operation, err)
	}
	return packet, result
}

func alterHubAccountCiphertext(t *testing.T, packet []byte) []byte {
	t.Helper()
	parsed, err := wire.DecodePacket(packet)
	if err != nil || len(parsed.Packet.Envelope) == 0 {
		t.Fatalf("could not decode synthetic test packet: %v", err)
	}
	parsed.Packet.Envelope[0] ^= 0x80
	altered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wire.DecodePacket(altered); err != nil {
		t.Fatalf("altered ciphertext changed the outer packet shape: %v", err)
	}
	return altered
}

func mutateHubAccountAttemptRequestDigest(t *testing.T, path, attemptID, digest string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`DROP TRIGGER hub_account_attempts_v1_coordinates`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE hub_account_attempts_v1 SET request_digest=? WHERE attempt_id=? AND state='CONSUMED'`, digest, attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER hub_account_attempts_v1_coordinates BEFORE UPDATE ON hub_account_attempts_v1 WHEN NEW.attempt_id!=OLD.attempt_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.public_identity_json!=OLD.public_identity_json OR NEW.epoch!=OLD.epoch OR NEW.device_epoch!=OLD.device_epoch OR NEW.prepare_id!=OLD.prepare_id OR NEW.prepare_digest!=OLD.prepare_digest OR NEW.challenge_digest!=OLD.challenge_digest OR NEW.challenge_packet!=OLD.challenge_packet OR NEW.expires_at!=OLD.expires_at OR NEW.prepare_nonce_digest!=OLD.prepare_nonce_digest OR (OLD.complete_nonce_digest!='' AND NEW.complete_nonce_digest!=OLD.complete_nonce_digest) OR OLD.state!='PENDING' BEGIN SELECT RAISE(ABORT,'Account challenge is immutable'); END`); err != nil {
		t.Fatal(err)
	}
}

func mutateHubAccountRequestDigest(t *testing.T, path, sessionID, operationID, digest string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`DROP TRIGGER hub_account_requests_v1_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE hub_account_requests_v1 SET request_digest=? WHERE session_id=? AND operation_id=?`, digest, sessionID, operationID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER hub_account_requests_v1_no_update BEFORE UPDATE ON hub_account_requests_v1 BEGIN SELECT RAISE(ABORT,'Account response is immutable'); END`); err != nil {
		t.Fatal(err)
	}
}

func stopHubAccountFixtureForMutation(t *testing.T, f *hubAccountTCPFixture) {
	t.Helper()
	if f.http != nil {
		f.http.Close()
		f.http = nil
	}
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		f.db = nil
	}
}

func restartHubAccountFixtureAfterMutation(t *testing.T, f *hubAccountTCPFixture) {
	t.Helper()
	var err error
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.setup, _, err = f.db.HubAccountSetup()
	if err != nil {
		t.Fatal(err)
	}
	f.start(t)
}

func TestHubAccountPQHTTPFlowSurvivesRestartAndRecoversRevokedLogout(t *testing.T) {
	f := newHubAccountTCPFixture(t)
	initialHub := f.hub
	initialSetup, _, err := f.db.HubAccountSetup()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerCandidate, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	card, err := f.auth.IssueClaimLocal(false)
	if err != nil {
		t.Fatal(err)
	}
	// Oversized input is rejected by the HTTP bound before packet parsing.
	if status, _ := postHubAccount(t, f, wire.OperationClaimPrepare, bytes.Repeat([]byte("x"), wire.MaxPacketBytes+1)); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-size status=%d", status)
	}

	// A public identity and an otherwise well-formed request do not select an
	// account; the protected body still has to match the configured account.
	wrongScope, err := wire.NewLoginPrepare(f.hub, initialSetup.Origin, initialSetup.AccountID, initialSetup.OwnerID,
		wire.AccountDeviceIDPrefix+strings.Repeat("a", 2*wire.RequestIDBytes), "synthetic-owner", device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrongScope.AccountID = "synthetic-other-account"
	wrongScopePacket, err := wire.SealClientRequest(device, f.hub, wrongScope)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postHubAccount(t, f, wire.OperationLoginPrepare, wrongScopePacket); status != http.StatusForbidden {
		t.Fatalf("wrong account scope status=%d", status)
	}
	unknownDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	unknownPrepare, err := wire.NewLoginPrepare(f.hub, initialSetup.Origin, initialSetup.AccountID, initialSetup.OwnerID,
		wire.AccountDeviceIDPrefix+strings.Repeat("b", 2*wire.RequestIDBytes), "synthetic-owner", unknownDevice.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	unknownPacket, err := wire.SealClientRequest(unknownDevice, f.hub, unknownPrepare)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postHubAccount(t, f, wire.OperationLoginPrepare, unknownPacket); status != http.StatusForbidden {
		t.Fatalf("unregistered device status=%d", status)
	}

	claimPrepare, err := wire.NewClaimPrepare(*card, f.hub, device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	claimPreparePacket, claimChallengePacket := hubAccountRoundTrip(t, f, wire.OperationClaimPrepare, device, claimPrepare, &wire.ClaimChallenge{})
	var claimChallenge wire.ClaimChallenge
	if err = wire.OpenClientResponse(device, f.hub, claimPreparePacket, claimChallengePacket, &claimChallenge); err != nil {
		t.Fatal(err)
	}
	if claimChallenge.AccountID != initialSetup.AccountID || claimChallenge.OwnerID != initialSetup.OwnerID || claimChallenge.DeviceID != claimPrepare.DeviceID {
		t.Fatal("claim challenge changed the configured account/Owner/device binding")
	}
	// Continue the same pending challenge after a real Store and HTTP process
	// restart. Stable Hub, Owner and account coordinates must survive.
	f.restart(t)
	if !reflect.DeepEqual(f.hub, initialHub) || f.setup.OwnerID != initialSetup.OwnerID || f.setup.AccountID != initialSetup.AccountID {
		t.Fatal("restart changed the durable Hub, Owner or account identity")
	}
	claimComplete, err := wire.NewClaimCompleteFromChallenge(f.hub, claimChallenge, device.Public(), "synthetic-owner",
		"Synthetic account password 2026", ownerCandidate.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	claimCompletePacket, claimReceiptPacket := hubAccountRoundTrip(t, f, wire.OperationClaimComplete, device, claimComplete, &wire.ClaimReceipt{})
	var claimReceipt wire.ClaimReceipt
	if err = wire.OpenClientResponse(device, f.hub, claimCompletePacket, claimReceiptPacket, &claimReceipt); err != nil {
		t.Fatal(err)
	}
	if claimReceipt.State != wire.ClaimPendingState || claimReceipt.RootState != wire.RootPendingState || claimReceipt.RootActive || claimReceipt.OwnerKeyID != ownerCandidate.Public().ID {
		t.Fatal("claim made a pending public Owner candidate an active Root")
	}
	if status, again := postHubAccount(t, f, wire.OperationClaimComplete, claimCompletePacket); status != http.StatusOK || !bytes.Equal(again, claimReceiptPacket) {
		t.Fatal("claim completion exact retry did not return the durable original receipt")
	}
	if status, _ := postHubAccount(t, f, wire.OperationClaimComplete, alterHubAccountCiphertext(t, claimCompletePacket)); status != http.StatusForbidden {
		t.Fatal("altered claim completion ciphertext was accepted")
	}
	ownerStatus, err := f.db.HubAccountStatus(initialSetup.AccountID)
	if err != nil || ownerStatus.OwnerID != initialSetup.OwnerID || ownerStatus.RootActive || ownerStatus.RootState != wire.RootPendingState || ownerStatus.OwnerPublic.ID != ownerCandidate.Public().ID || len(ownerStatus.Devices) != 1 || ownerStatus.Devices[0].DeviceID != claimPrepare.DeviceID {
		t.Fatalf("durable account status lost pending candidate/device: status=%+v err=%v", ownerStatus, err)
	}

	// A saved login challenge expires server-side even if a client still has its
	// original authenticated bytes. This is a test-only clock transition on the
	// disposable database; the migration trigger is restored immediately.
	firstLoginPrepare, err := wire.NewLoginPrepare(f.hub, initialSetup.Origin, initialSetup.AccountID, initialSetup.OwnerID,
		claimPrepare.DeviceID, "synthetic-owner", device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	firstPreparePacket, firstChallengePacket := hubAccountRoundTrip(t, f, wire.OperationLoginPrepare, device, firstLoginPrepare, &wire.LoginChallenge{})
	var firstChallenge wire.LoginChallenge
	if err = wire.OpenClientResponse(device, f.hub, firstPreparePacket, firstChallengePacket, &firstChallenge); err != nil {
		t.Fatal(err)
	}
	f.http.Close()
	f.http = nil
	if err = f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.db = nil
	mutateHubAccountAttemptExpiry(t, f.dbPath, firstChallenge.AttemptID)
	f.db, err = store.New(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t)
	firstComplete, err := wire.NewLoginComplete(f.hub, firstChallenge, "Synthetic account password 2026", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	firstCompletePacket, err := wire.SealClientRequest(device, f.hub, firstComplete)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postHubAccount(t, f, wire.OperationLoginComplete, firstCompletePacket); status != http.StatusForbidden {
		t.Fatalf("expired login challenge status=%d", status)
	}

	// Unknown devices and wrong account scopes were rejected before password
	// work. A registered device with a wrong password is rejected, then may
	// complete the same challenge with a fresh request ID and client nonce.
	loginPrepare, err := wire.NewLoginPrepare(f.hub, initialSetup.Origin, initialSetup.AccountID, initialSetup.OwnerID,
		claimPrepare.DeviceID, "synthetic-owner", device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	preparePacket, challengePacket := hubAccountRoundTrip(t, f, wire.OperationLoginPrepare, device, loginPrepare, &wire.LoginChallenge{})
	var loginChallenge wire.LoginChallenge
	if err = wire.OpenClientResponse(device, f.hub, preparePacket, challengePacket, &loginChallenge); err != nil {
		t.Fatal(err)
	}
	wrongPassword, err := wire.NewLoginComplete(f.hub, loginChallenge, "Synthetic account password 2025", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrongPasswordPacket, err := wire.SealClientRequest(device, f.hub, wrongPassword)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postHubAccount(t, f, wire.OperationLoginComplete, wrongPasswordPacket); status != http.StatusForbidden {
		t.Fatal("wrong account password was accepted")
	}
	loginComplete, err := wire.NewLoginComplete(f.hub, loginChallenge, "Synthetic account password 2026", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	loginProbePacket, err := wire.SealClientRequest(device, f.hub, loginComplete)
	if err != nil {
		t.Fatal(err)
	}
	loginCandidate, candidateErr := f.db.HubAccountLoginCompletionReplayCandidate(initialSetup.AccountID, claimPrepare.DeviceID,
		loginComplete.RequestID, store.AccountDigest("packet", loginProbePacket), 1, 1)
	if candidateErr != nil || loginCandidate {
		t.Fatalf("fresh login completion was classified as an accepted replay: candidate=%v err=%v", loginCandidate, candidateErr)
	}
	loginCompletePacket, sessionPacket := hubAccountRoundTrip(t, f, wire.OperationLoginComplete, device, loginComplete, &wire.SessionReceipt{})
	var session wire.SessionReceipt
	if err = wire.OpenClientResponse(device, f.hub, loginCompletePacket, sessionPacket, &session); err != nil {
		t.Fatal(err)
	}
	if len(session.SessionToken) != wire.MaxSessionTokenBytes || session.AccountID != initialSetup.AccountID || session.OwnerID != initialSetup.OwnerID {
		t.Fatal("login receipt did not carry the scoped account session")
	}
	if status, again := postHubAccount(t, f, wire.OperationLoginComplete, loginCompletePacket); status != http.StatusOK || !bytes.Equal(again, sessionPacket) {
		t.Fatal("login completion exact retry did not return the original receipt")
	}
	if status, _ := postHubAccount(t, f, wire.OperationLoginComplete, alterHubAccountCiphertext(t, loginCompletePacket)); status != http.StatusForbidden {
		t.Fatal("altered login completion ciphertext was accepted")
	}
	// Fixture-seed the accepted durable receipt as if its original signed packet
	// had arrived earlier. The old packet is exact, but its request timestamp is
	// now outside the ordinary freshness window.
	staleLoginComplete := loginComplete
	staleLoginComplete.IssuedAt = time.Now().UTC().Add(-61 * time.Second).Format(time.RFC3339Nano)
	staleLoginCompletePacket, err := wire.SealClientRequest(device, f.hub, staleLoginComplete)
	if err != nil {
		t.Fatal(err)
	}
	stopHubAccountFixtureForMutation(t, f)
	mutateHubAccountAttemptRequestDigest(t, f.dbPath, loginChallenge.AttemptID, store.AccountDigest("packet", staleLoginCompletePacket))
	restartHubAccountFixtureAfterMutation(t, f)

	inspect, err := wire.NewSessionInspectRequest(session.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	inspectPacket, inspectReceiptPacket := hubAccountRoundTrip(t, f, wire.OperationSessionInspect, device, inspect, &wire.SessionInspection{})
	var inspection wire.SessionInspection
	if err = wire.OpenClientResponse(device, f.hub, inspectPacket, inspectReceiptPacket, &inspection); err != nil {
		t.Fatal(err)
	}
	if inspection.RootActive || inspection.RootState != wire.RootPendingState || inspection.OwnerKeyID != ownerCandidate.Public().ID || inspection.ActorDeviceID != claimPrepare.DeviceID {
		t.Fatal("session inspection misreported pending Owner or device state")
	}
	if status, again := postHubAccount(t, f, wire.OperationSessionInspect, inspectPacket); status != http.StatusOK || !bytes.Equal(again, inspectReceiptPacket) {
		t.Fatal("session-inspect exact retry changed its durable response")
	}
	if status, _ := postHubAccount(t, f, wire.OperationSessionInspect, alterHubAccountCiphertext(t, inspectPacket)); status != http.StatusForbidden {
		t.Fatal("altered session-inspection ciphertext was accepted")
	}
	// The same nonce under a newly sealed request and operation ID is a replay;
	// the exact original bytes above remain the only permitted retry.
	replayedNonce := inspect
	replayedNonce.RequestID, err = wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	replayedNonce.ClientNonce = append([]byte(nil), loginComplete.ClientNonce...)
	replayedPacket, err := wire.SealClientRequest(device, f.hub, replayedNonce)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postHubAccount(t, f, wire.OperationSessionInspect, replayedPacket); status != http.StatusForbidden {
		t.Fatalf("reused client nonce with a new operation ID status=%d", status)
	}
	// A later accepted login revokes the first session. The exact original
	// login-complete packet may still recover its already-committed receipt,
	// while that receipt's token remains revoked and cannot authorize work.
	secondPrepare, err := wire.NewLoginPrepare(f.hub, initialSetup.Origin, initialSetup.AccountID, initialSetup.OwnerID,
		claimPrepare.DeviceID, "synthetic-owner", device.Public(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	secondPreparePacket, secondChallengePacket := hubAccountRoundTrip(t, f, wire.OperationLoginPrepare, device, secondPrepare, &wire.LoginChallenge{})
	var secondChallenge wire.LoginChallenge
	if err = wire.OpenClientResponse(device, f.hub, secondPreparePacket, secondChallengePacket, &secondChallenge); err != nil {
		t.Fatal(err)
	}
	secondComplete, err := wire.NewLoginComplete(f.hub, secondChallenge, "Synthetic account password 2026", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	secondCompletePacket, secondSessionPacket := hubAccountRoundTrip(t, f, wire.OperationLoginComplete, device, secondComplete, &wire.SessionReceipt{})
	var secondSession wire.SessionReceipt
	if err = wire.OpenClientResponse(device, f.hub, secondCompletePacket, secondSessionPacket, &secondSession); err != nil {
		t.Fatal(err)
	}
	// Restart with the first receipt's expired request timestamp. A fresh
	// operation ID and nonce cannot borrow the saved receipt's freshness bypass.
	f.restart(t)
	freshStaleLoginComplete := staleLoginComplete
	freshStaleLoginComplete.RequestID, err = wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	freshStaleLoginComplete.ClientNonce, err = wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	freshStaleLoginCompletePacket, err := wire.SealClientRequest(device, f.hub, freshStaleLoginComplete)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := postHubAccount(t, f, wire.OperationLoginComplete, freshStaleLoginCompletePacket); status != http.StatusForbidden {
		t.Fatalf("fresh stale login completion status=%d", status)
	}
	if status, recovered := postHubAccount(t, f, wire.OperationLoginComplete, staleLoginCompletePacket); status != http.StatusOK || !bytes.Equal(recovered, sessionPacket) {
		t.Fatal("exact stale consumed login retry lost its receipt after restart and a later login revoked that session")
	}

	// Logout returns an encrypted receipt and commits revocation atomically.
	// Simulate a lost response and restart both the handler and durable Store;
	// only the exact old request may then recover the cached receipt.
	logout, err := wire.NewLogoutRequest(secondSession.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	logoutSession, err := f.db.HubAccountSessionByTokenDigest(store.AccountDigest("session-token", secondSession.SessionToken))
	if err != nil {
		t.Fatal(err)
	}
	logoutPacket, lostLogoutResponse := hubAccountRoundTrip(t, f, wire.OperationSessionLogout, device, logout, &wire.LogoutReceipt{})
	staleLogout := logout
	staleIssuedAt := time.Now().UTC().Add(-61 * time.Second)
	staleLogout.IssuedAt = staleIssuedAt.Format(time.RFC3339Nano)
	staleLogout.ExpiresAt = staleIssuedAt.Add(wire.MaxSessionRequestLifetime).Format(time.RFC3339Nano)
	staleLogoutPacket, err := wire.SealClientRequest(device, f.hub, staleLogout)
	if err != nil {
		t.Fatal(err)
	}
	stopHubAccountFixtureForMutation(t, f)
	mutateHubAccountRequestDigest(t, f.dbPath, logoutSession.ID, logout.RequestID, store.AccountDigest("packet", staleLogoutPacket))
	restartHubAccountFixtureAfterMutation(t, f)
	logoutPacket = staleLogoutPacket
	status, recoveredLogoutResponse := postHubAccount(t, f, wire.OperationSessionLogout, logoutPacket)
	if status != http.StatusOK || !bytes.Equal(recoveredLogoutResponse, lostLogoutResponse) {
		t.Fatal("exact signed logout retry did not recover its saved response after restart")
	}
	var logoutReceipt wire.LogoutReceipt
	if err = wire.OpenClientResponse(device, f.hub, logoutPacket, recoveredLogoutResponse, &logoutReceipt); err != nil || logoutReceipt.State != wire.SessionRevokedState {
		t.Fatal("recovered logout receipt was not valid")
	}
	if status, _ = postHubAccount(t, f, wire.OperationSessionLogout, alterHubAccountCiphertext(t, logoutPacket)); status != http.StatusForbidden {
		t.Fatal("altered logout ciphertext recovered a revoked session response")
	}
	newLogout, err := wire.NewLogoutRequest(secondSession.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	newLogoutPacket, err := wire.SealClientRequest(device, f.hub, newLogout)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ = postHubAccount(t, f, wire.OperationSessionLogout, newLogoutPacket); status != http.StatusForbidden {
		t.Fatal("new logout operation was accepted after session revocation")
	}
	if status, _ = postHubAccount(t, f, wire.OperationSessionInspect, inspectPacket); status != http.StatusForbidden {
		t.Fatal("revoked session authorized a new inspect operation")
	}
	freshStaleLogout := staleLogout
	freshStaleLogout.RequestID, err = wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	freshStaleLogout.ClientNonce, err = wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	freshStaleLogoutPacket, err := wire.SealClientRequest(device, f.hub, freshStaleLogout)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ = postHubAccount(t, f, wire.OperationSessionLogout, freshStaleLogoutPacket); status != http.StatusForbidden {
		t.Fatalf("fresh stale logout operation status=%d", status)
	}
	if status, _ = postHubAccount(t, f, wire.OperationSessionLogout, alterHubAccountCiphertext(t, logoutPacket)); status != http.StatusForbidden {
		t.Fatal("altered stale logout ciphertext recovered a revoked session response")
	}
	loginReplay, err := f.db.HubAccountLoginCompletionReplayCandidate(initialSetup.AccountID, claimPrepare.DeviceID,
		staleLoginComplete.RequestID, store.AccountDigest("packet", staleLoginCompletePacket), 1, 1)
	if err != nil || !loginReplay {
		t.Fatalf("current consumed login receipt was not an exact replay candidate: candidate=%v err=%v", loginReplay, err)
	}
	logoutReplay, err := f.db.HubAccountSessionRequestReplayCandidate(initialSetup.AccountID, claimPrepare.DeviceID,
		wire.OperationSessionLogout, staleLogout.RequestID, store.AccountDigest("packet", staleLogoutPacket), 1, 1)
	if err != nil || !logoutReplay {
		t.Fatalf("current revoked logout receipt was not an exact replay candidate: candidate=%v err=%v", logoutReplay, err)
	}
	// The real restore reconciler advances this durable account epoch and
	// revokes live authority. Simulate its epoch transition on this disposable
	// fixture to prove the replay preflight stops matching old accepted bytes.
	stopHubAccountFixtureForMutation(t, f)
	raw, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE hub_account_config_v1 SET epoch=epoch+1,restore_receipt=? WHERE id=1`, strings.Repeat("f", 64)); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	restartHubAccountFixtureAfterMutation(t, f)
	loginReplay, err = f.db.HubAccountLoginCompletionReplayCandidate(initialSetup.AccountID, claimPrepare.DeviceID,
		staleLoginComplete.RequestID, store.AccountDigest("packet", staleLoginCompletePacket), 2, 1)
	if err == nil && loginReplay {
		t.Fatal("restore epoch change kept a prior login response recoverable")
	}
	if status, _ = postHubAccount(t, f, wire.OperationLoginComplete, staleLoginCompletePacket); status != http.StatusForbidden {
		t.Fatalf("pre-restore login receipt status=%d", status)
	}
	if status, _ = postHubAccount(t, f, wire.OperationSessionLogout, staleLogoutPacket); status != http.StatusForbidden {
		t.Fatalf("pre-restore logout receipt status=%d", status)
	}
	stopHubAccountFixtureForMutation(t, f)
	raw, err = sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE hub_account_devices_v1 SET status='REVOKED',epoch=epoch+1 WHERE account_id=? AND device_id=?`, initialSetup.AccountID, claimPrepare.DeviceID); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	restartHubAccountFixtureAfterMutation(t, f)
	loginReplay, err = f.db.HubAccountLoginCompletionReplayCandidate(initialSetup.AccountID, claimPrepare.DeviceID,
		staleLoginComplete.RequestID, store.AccountDigest("packet", staleLoginCompletePacket), 2, 1)
	if err == nil && loginReplay {
		t.Fatal("revoked device kept a prior login response recoverable")
	}
	if status, _ = postHubAccount(t, f, wire.OperationLoginComplete, staleLoginCompletePacket); status != http.StatusForbidden {
		t.Fatalf("revoked-device login receipt status=%d", status)
	}

	// Restore fencing is exercised with the actual Store reconciliation
	// transition in the Store package. This HTTP test ends by checking that the
	// six operations used only this durable account and its original keys.
	if f.setup.AccountID != initialSetup.AccountID || f.setup.OwnerID != initialSetup.OwnerID || !reflect.DeepEqual(f.hub, initialHub) {
		t.Fatal("account flow changed durable identity coordinates")
	}
}

func mutateHubAccountAttemptExpiry(t *testing.T, path, attemptID string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`DROP TRIGGER hub_account_attempts_v1_coordinates`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE hub_account_attempts_v1 SET expires_at=? WHERE attempt_id=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER hub_account_attempts_v1_coordinates BEFORE UPDATE ON hub_account_attempts_v1 WHEN NEW.attempt_id!=OLD.attempt_id OR NEW.account_id!=OLD.account_id OR NEW.owner_id!=OLD.owner_id OR NEW.device_id!=OLD.device_id OR NEW.public_identity_json!=OLD.public_identity_json OR NEW.epoch!=OLD.epoch OR NEW.device_epoch!=OLD.device_epoch OR NEW.prepare_id!=OLD.prepare_id OR NEW.prepare_digest!=OLD.prepare_digest OR NEW.challenge_digest!=OLD.challenge_digest OR NEW.challenge_packet!=OLD.challenge_packet OR NEW.expires_at!=OLD.expires_at OR NEW.prepare_nonce_digest!=OLD.prepare_nonce_digest OR (OLD.complete_nonce_digest!='' AND NEW.complete_nonce_digest!=OLD.complete_nonce_digest) OR OLD.state!='PENDING' BEGIN SELECT RAISE(ABORT,'Account challenge is immutable'); END`); err != nil {
		t.Fatal(err)
	}
}
