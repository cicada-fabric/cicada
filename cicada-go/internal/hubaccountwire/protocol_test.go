package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func TestDecodeClaimCardRejectsAmbiguousAndUnknownJSON(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	hubPrivate, _, _, card := accountFixture(t, now)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: hubPrivate.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	canonical, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeClaimCard(canonical)
	if err != nil || decoded != card {
		t.Fatalf("DecodeClaimCard(canonical) = (%+v, %v)", decoded, err)
	}
	duplicate := bytes.Replace(canonical, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if _, err := DecodeClaimCard(duplicate); err == nil {
		t.Fatal("duplicate claim-card field accepted")
	}
	unknown := bytes.TrimSuffix(canonical, []byte("}"))
	unknown = append(unknown, []byte(`,"unexpected":"field"}`)...)
	if _, err := DecodeClaimCard(unknown); err == nil {
		t.Fatal("unknown claim-card field accepted")
	}
	if _, err := DecodeClaimCard(append(bytes.Clone(canonical), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := DecodeClaimCard(bytes.Repeat([]byte(" "), MaxClaimCardBytes+1)); err == nil {
		t.Fatal("oversized claim card accepted")
	}
	if err := ValidateClaimCard(card, hub, now); err != nil {
		t.Fatalf("valid card rejected: %v", err)
	}
}

func TestClaimPrepareCompleteAndResponseRouteBinding(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	hubPrivate, devicePrivate, ownerPrivate, card := accountFixture(t, now)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: hubPrivate.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	devicePublic, ownerPublic := devicePrivate.Public(), ownerPrivate.Public()
	prepare, err := NewClaimPrepare(card, hub, devicePublic, now)
	if err != nil {
		t.Fatal(err)
	}
	preparePacket, err := SealClientRequest(devicePrivate, hub, prepare)
	if err != nil {
		t.Fatalf("seal claim prepare: %v", err)
	}
	prepareBinding, prepareRoute, err := NewClientRoute(hub, prepare, devicePublic)
	if err != nil {
		t.Fatal(err)
	}
	var openedPrepare ClaimPrepare
	if err := OpenRequestAt(hubPrivate, nil, prepareBinding, prepareRoute, preparePacket, &openedPrepare, now); err != nil {
		t.Fatalf("open claim prepare: %v", err)
	}
	if openedPrepare.Claim.Code != card.Code || openedPrepare.DeviceID != prepare.DeviceID {
		t.Fatal("claim prepare fields changed in authenticated envelope")
	}
	serverNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	challenge := ClaimChallenge{Format: ClaimChallengeFormat, Purpose: PurposeInitialClaim, Origin: card.Origin,
		HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID, ClaimID: card.ClaimID,
		AttemptID: "0123456789abcdef0123456789abcdef", DeviceID: prepare.DeviceID,
		DeviceKeyID: devicePublic.ID, DeviceKeyFingerprint: prepare.DeviceKeyFingerprint,
		PrepareRequestID: prepare.RequestID, ClientNonce: bytes.Clone(prepare.ClientNonce), ServerNonce: serverNonce,
		AccountEpoch: 1, DeviceEpoch: 1, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	challengePacket, err := SealResponse(hubPrivate, devicePublic, prepareRoute, challenge)
	if err != nil {
		t.Fatalf("seal claim challenge: %v", err)
	}
	var openedChallenge ClaimChallenge
	if err := OpenClientResponse(devicePrivate, hub, preparePacket, challengePacket, &openedChallenge); err != nil {
		t.Fatalf("open claim challenge: %v", err)
	}
	complete, err := NewClaimCompleteFromChallenge(hub, openedChallenge, devicePublic, "alice", "correct horse battery staple", ownerPublic, now.Add(time.Second))
	if err != nil {
		t.Fatalf("construct complete without claim card: %v", err)
	}
	if _, err := NewClaimCompleteFromChallenge(hub, openedChallenge, devicePublic, "alice", "correct horse battery staple", hub.Public, now.Add(time.Second)); err == nil {
		t.Fatal("Hub Client-Control identity accepted as the Owner candidate")
	}
	if complete.ClaimID != card.ClaimID || complete.AccountID != card.AccountID || complete.OwnerID != card.OwnerID {
		t.Fatal("claim complete did not retain authenticated challenge scope")
	}
	completePacket, err := SealClientRequest(devicePrivate, hub, complete)
	if err != nil {
		t.Fatalf("seal claim complete: %v", err)
	}
	completeBinding, completeRoute, err := NewClientRoute(hub, complete, devicePublic)
	if err != nil {
		t.Fatal(err)
	}
	var openedComplete ClaimComplete
	if err := OpenRequestAt(hubPrivate, &devicePublic, completeBinding, completeRoute, completePacket, &openedComplete, now.Add(time.Second)); err != nil {
		t.Fatalf("open claim complete: %v", err)
	}
	if openedComplete.Password != complete.Password || openedComplete.OwnerPublicIdentity.ID != ownerPublic.ID {
		t.Fatal("claim complete fields changed in authenticated envelope")
	}
	ownerFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(ownerPublic)
	if err != nil {
		t.Fatal(err)
	}
	receipt := ClaimReceipt{Format: ClaimReceiptFormat, Purpose: PurposeInitialClaim, Origin: card.Origin,
		HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID, ClaimID: card.ClaimID,
		AttemptID: challenge.AttemptID, RequestID: complete.RequestID, DeviceID: prepare.DeviceID,
		DeviceKeyID: devicePublic.ID, DeviceKeyFingerprint: prepare.DeviceKeyFingerprint,
		AccountEpoch: 1, DeviceEpoch: 1, State: ClaimPendingState, OwnerKeyID: ownerPublic.ID,
		OwnerFingerprint: ownerFingerprint, RootState: RootPendingState, RootActive: false,
		CompletedAt: now.Add(2 * time.Second).Format(time.RFC3339Nano)}
	receiptPacket, err := SealResponse(hubPrivate, devicePublic, completeRoute, receipt)
	if err != nil {
		t.Fatalf("seal claim receipt: %v", err)
	}
	var openedReceipt ClaimReceipt
	if err := OpenClientResponse(devicePrivate, hub, completePacket, receiptPacket, &openedReceipt); err != nil {
		t.Fatalf("open claim receipt: %v", err)
	}
	if openedReceipt.RootActive || openedReceipt.RootState != RootPendingState {
		t.Fatal("account claim falsely activated Root")
	}

	badReceipt := receipt
	badReceipt.RequestID = "ffffffffffffffffffffffffffffffff"
	badPacket, err := maliciousResponse(hubPrivate, devicePublic, completeRoute, badReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := OpenClientResponse(devicePrivate, hub, completePacket, badPacket, &openedReceipt); err == nil {
		t.Fatal("Hub-signed response with wrong inner request ID accepted")
	}
}

func TestValidateClaimCardForPageRequiresOriginAndFullHubPin(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	hubPrivate, _, _, card := accountFixture(t, now)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: hubPrivate.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	summary, err := ValidateClaimCardForPage(card, card.Origin, hub, now)
	if err != nil || summary.HubFingerprint != card.HubFingerprint {
		t.Fatalf("valid card summary: %+v, %v", summary, err)
	}
	if _, err := ValidateClaimCardForPage(card, "https://other.example", hub, now); err == nil {
		t.Fatal("claim card accepted for different page origin")
	}
	wrongHub := hub
	wrongHub.HubID = "hub_other"
	if _, err := ValidateClaimCardForPage(card, card.Origin, wrongHub, now); err == nil {
		t.Fatal("claim card accepted for a different Hub identity")
	}
}

func TestSessionInspectionAllowsPendingAndUnavailableCandidateWithoutActivatingRoot(t *testing.T) {
	ownerID := "pq1-" + strings.Repeat("a", 32)
	fingerprint := strings.Repeat("b", 64)
	for _, state := range []string{RootPendingState, RootUnavailableState} {
		inspection := SessionInspection{Format: SessionInspectionFormat, Purpose: PurposeAccountSession,
			Origin: "https://hub.example", HubID: "hub_test", AccountID: "account_test", OwnerID: "owner_test",
			Username: "alice", ActorDeviceID: "accountdev_0123456789abcdef0123456789abcdef",
			ActorDeviceEpoch: 1, RequestID: "0123456789abcdef0123456789abcdef", State: SessionActiveState,
			RootState: state, OwnerKeyID: ownerID, OwnerFingerprint: fingerprint, RootActive: false,
			InspectedAt: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)}
		if err := validateResponseBody(inspection); err != nil {
			t.Fatalf("candidate metadata rejected for %s: %v", state, err)
		}
	}
	active := SessionInspection{Format: SessionInspectionFormat, Purpose: PurposeAccountSession,
		Origin: "https://hub.example", HubID: "hub_test", AccountID: "account_test", OwnerID: "owner_test",
		Username: "alice", ActorDeviceID: "accountdev_0123456789abcdef0123456789abcdef",
		ActorDeviceEpoch: 1, RequestID: "0123456789abcdef0123456789abcdef", State: SessionActiveState,
		RootState: RootActiveState, OwnerKeyID: ownerID, OwnerFingerprint: fingerprint, RootActive: true,
		InspectedAt: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)}
	if err := validateResponseBody(active); err != nil {
		t.Fatalf("active root metadata rejected: %v", err)
	}
	active.RootActive = false
	if validateResponseBody(active) == nil {
		t.Fatal("inconsistent Root active flag accepted")
	}
}

func TestAccountDeviceIDRequiresRandomHexSuffix(t *testing.T) {
	if !validDeviceID(AccountDeviceIDPrefix + "0123456789abcdef0123456789abcdef") {
		t.Fatal("canonical account-device ID rejected")
	}
	for _, invalid := range []string{
		AccountDeviceIDPrefix,
		AccountDeviceIDPrefix + "short",
		AccountDeviceIDPrefix + strings.Repeat("A", 32),
		AccountDeviceIDPrefix + strings.Repeat("g", 32),
		AccountDeviceIDPrefix + strings.Repeat("0", 34),
	} {
		if validDeviceID(invalid) {
			t.Fatalf("invalid account-device ID accepted: %q", invalid)
		}
	}
}

func TestLoginSessionInspectAndLogoutUseTheirSeparateTypedRoutes(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	hubPrivate, devicePrivate, ownerPrivate, card := accountFixture(t, now)
	hub := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: hubPrivate.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	device := devicePrivate.Public()
	deviceID := AccountDeviceIDPrefix + "0123456789abcdef0123456789abcdef"

	loginPrepare, err := NewLoginPrepare(hub, card.Origin, card.AccountID, card.OwnerID, deviceID, "alice", device, now)
	if err != nil {
		t.Fatal(err)
	}
	preparePacket, err := SealClientRequest(devicePrivate, hub, loginPrepare)
	if err != nil {
		t.Fatal(err)
	}
	prepareBinding, prepareRoute, err := NewClientRoute(hub, loginPrepare, device)
	if err != nil {
		t.Fatal(err)
	}
	var openedPrepare LoginPrepare
	if err := OpenRequestAt(hubPrivate, &device, prepareBinding, prepareRoute, preparePacket, &openedPrepare, now); err != nil {
		t.Fatalf("open login prepare: %v", err)
	}
	serverNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	challenge := LoginChallenge{Format: LoginChallengeFormat, Purpose: PurposeAccountLogin, Origin: card.Origin,
		HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID,
		AttemptID: "0123456789abcdef0123456789abcdef", DeviceID: deviceID, DeviceKeyID: device.ID,
		DeviceKeyFingerprint: loginPrepare.DeviceKeyFingerprint, Username: loginPrepare.Username,
		PrepareRequestID: loginPrepare.RequestID, ClientNonce: bytes.Clone(loginPrepare.ClientNonce), ServerNonce: serverNonce,
		AccountEpoch: 4, DeviceEpoch: 2, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	challengePacket, err := SealResponse(hubPrivate, device, prepareRoute, challenge)
	if err != nil {
		t.Fatal(err)
	}
	var openedChallenge LoginChallenge
	if err := OpenClientResponse(devicePrivate, hub, preparePacket, challengePacket, &openedChallenge); err != nil {
		t.Fatalf("open login challenge: %v", err)
	}
	complete, err := NewLoginComplete(hub, openedChallenge, "correct horse battery staple", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	completePacket, err := SealClientRequest(devicePrivate, hub, complete)
	if err != nil {
		t.Fatal(err)
	}
	completeBinding, completeRoute, err := NewClientRoute(hub, complete, device)
	if err != nil {
		t.Fatal(err)
	}
	var openedComplete LoginComplete
	if err := OpenRequestAt(hubPrivate, &device, completeBinding, completeRoute, completePacket, &openedComplete, now.Add(time.Second)); err != nil {
		t.Fatalf("open login complete: %v", err)
	}
	sessionReceipt := SessionReceipt{Format: SessionReceiptFormat, Purpose: PurposeAccountSession, Origin: card.Origin,
		HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID, DeviceID: deviceID,
		DeviceKeyID: device.ID, DeviceKeyFingerprint: loginPrepare.DeviceKeyFingerprint,
		SessionToken: bytes.Repeat([]byte{0x42}, MaxSessionTokenBytes), AccountEpoch: 4, DeviceEpoch: 2,
		RequestID: complete.RequestID, IssuedAt: now.Add(2 * time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	sessionPacket, err := SealResponse(hubPrivate, device, completeRoute, sessionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	var openedSession SessionReceipt
	if err := OpenClientResponse(devicePrivate, hub, completePacket, sessionPacket, &openedSession); err != nil {
		t.Fatalf("open session receipt: %v", err)
	}
	if !bytes.Equal(openedSession.SessionToken, sessionReceipt.SessionToken) {
		t.Fatal("session token changed inside sealed receipt")
	}
	session := openedSession.Context()
	inspect, err := NewSessionInspectRequest(session, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	inspectPacket, err := SealClientRequest(devicePrivate, hub, inspect)
	if err != nil {
		t.Fatal(err)
	}
	inspectBinding, inspectRoute, err := NewClientRoute(hub, inspect, device)
	if err != nil || inspectRoute.SessionEpoch != session.AccountEpoch {
		t.Fatalf("session inspection route epoch = %d, %v", inspectRoute.SessionEpoch, err)
	}
	var openedInspect SessionInspectRequest
	if err := OpenRequestAt(hubPrivate, &device, inspectBinding, inspectRoute, inspectPacket, &openedInspect, now.Add(3*time.Second)); err != nil {
		t.Fatalf("open session inspection request: %v", err)
	}
	ownerFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(ownerPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	inspection := SessionInspection{Format: SessionInspectionFormat, Purpose: PurposeAccountSession, Origin: card.Origin,
		HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID, Username: "alice",
		ActorDeviceID: deviceID, ActorDeviceEpoch: session.DeviceEpoch, RequestID: inspect.RequestID,
		State: SessionActiveState, RootState: RootPendingState, RootActive: false,
		OwnerKeyID: ownerPrivate.Public().ID, OwnerFingerprint: ownerFingerprint,
		Devices: []LoginDeviceSummary{{DeviceID: deviceID, DeviceKeyID: device.ID,
			DeviceKeyFingerprint: loginPrepare.DeviceKeyFingerprint, State: DeviceActiveState, DeviceEpoch: session.DeviceEpoch,
			CreatedAt: now.Format(time.RFC3339Nano)}}, InspectedAt: now.Add(4 * time.Second).Format(time.RFC3339Nano)}
	inspectionPacket, err := SealResponse(hubPrivate, device, inspectRoute, inspection)
	if err != nil {
		t.Fatal(err)
	}
	var openedInspection SessionInspection
	if err := OpenClientResponse(devicePrivate, hub, inspectPacket, inspectionPacket, &openedInspection); err != nil {
		t.Fatalf("open session inspection: %v", err)
	}
	if openedInspection.RootActive || openedInspection.OwnerFingerprint != ownerFingerprint {
		t.Fatal("session inspection misreported pending Root candidate")
	}
	logout, err := NewLogoutRequest(session, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	logoutPacket, err := SealClientRequest(devicePrivate, hub, logout)
	if err != nil {
		t.Fatal(err)
	}
	logoutBinding, logoutRoute, err := NewClientRoute(hub, logout, device)
	if err != nil || logoutRoute.SessionEpoch != session.AccountEpoch {
		t.Fatalf("logout route epoch = %d, %v", logoutRoute.SessionEpoch, err)
	}
	var openedLogout LogoutRequest
	if err := OpenRequestAt(hubPrivate, &device, logoutBinding, logoutRoute, logoutPacket, &openedLogout, now.Add(5*time.Second)); err != nil {
		t.Fatalf("open logout request: %v", err)
	}
	logoutReceipt := LogoutReceipt{Format: LogoutReceiptFormat, Purpose: PurposeAccountSession, Origin: card.Origin,
		HubID: card.HubID, AccountID: card.AccountID, OwnerID: card.OwnerID, DeviceID: deviceID,
		AccountEpoch: session.AccountEpoch, DeviceEpoch: session.DeviceEpoch, RequestID: logout.RequestID,
		State: SessionRevokedState, LoggedOutAt: now.Add(6 * time.Second).Format(time.RFC3339Nano)}
	logoutResponse, err := SealResponse(hubPrivate, device, logoutRoute, logoutReceipt)
	if err != nil {
		t.Fatal(err)
	}
	var openedLogoutReceipt LogoutReceipt
	if err := OpenClientResponse(devicePrivate, hub, logoutPacket, logoutResponse, &openedLogoutReceipt); err != nil {
		t.Fatalf("open logout receipt: %v", err)
	}
}

func accountFixture(t *testing.T, now time.Time) (*e2ee.Identity, *e2ee.Identity, *e2ee.Identity, ClaimCard) {
	t.Helper()
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubIdentity := HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic_account_test",
		Public: hub.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	fingerprint, err := HubFingerprint(hubIdentity)
	if err != nil {
		t.Fatal(err)
	}
	card := ClaimCard{Format: ClaimCardFormat, Version: 1, Purpose: PurposeInitialClaim, Origin: "https://hub.example",
		HubID: hubIdentity.HubID, HubFingerprint: fingerprint, AccountID: "account_synthetic_account_test",
		OwnerID: "human_synthetic_account_test", ClaimID: strings.Repeat("1", 32),
		Code:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, CodeBytes)),
		IssuedAt: now.Add(-time.Minute).UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour - time.Minute).UTC().Format(time.RFC3339Nano)}
	return hub, device, owner, card
}

func maliciousResponse(hub *e2ee.Identity, device e2ee.PublicIdentity, request clientwire.Route, body ClaimReceipt) ([]byte, error) {
	route := responseRoute(request)
	binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID,
		SessionEpoch: route.SessionEpoch, HubKeyVersion: route.SenderKeyVersion, DeviceKeyVersion: route.ReceiverKeyVersion}
	plaintext, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	inner, err := clientwire.SealResponse(hub, device, binding, route, plaintext)
	clear(plaintext)
	if err != nil {
		return nil, err
	}
	var packet clientwire.Packet
	if err := decodeCanonical(inner, MaxInnerPacketBytes, &packet); err != nil {
		return nil, err
	}
	return marshalPacket(Packet{Format: PacketFormat, Version: PacketVersion, SenderPublicIdentity: hub.Public(), Packet: packet})
}

func TestClaimCardFingerprintIsFullDomainSeparatedIdentity(t *testing.T) {
	now := time.Now().UTC()
	hub, _, _, card := accountFixture(t, now)
	identity := HubIdentity{Contract: "android-hub-v1", HubID: card.HubID, Public: hub.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	fingerprint, err := HubFingerprint(identity)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(hubFingerprintDomain), canonical...)
	expected := sha256.Sum256(input)
	if fingerprint != hex.EncodeToString(expected[:]) || fingerprint != card.HubFingerprint {
		t.Fatal("claim card fingerprint is not the full domain-separated Hub identity digest")
	}
}

func TestPublishedClaimCardVector(t *testing.T) {
	var vector struct {
		Warning                string `json:"warning"`
		ExpectedHubFingerprint string `json:"expected_hub_fingerprint"`
		ClaimCardCanonicalUTF8 string `json:"claim_card_canonical_utf8"`
	}
	vectorBytes, err := os.ReadFile("testdata/claim-card-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(vectorBytes, &vector); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vector.Warning, "NEVER USE") {
		t.Fatal("synthetic claim vector is missing its deployment warning")
	}
	var bootstrapFixture struct {
		Hub struct {
			Public e2ee.PublicIdentity `json:"public_identity"`
		} `json:"hub_PRIVATE_TEST_ONLY"`
	}
	fixtureBytes, err := os.ReadFile("../ownerbootstrap/testdata/owner-bootstrap-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixtureBytes, &bootstrapFixture); err != nil {
		t.Fatal(err)
	}
	hub := HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic_owner_bootstrap",
		Public: bootstrapFixture.Hub.Public, KeyVersion: 1, Suite: ownerbootstrap.Suite}
	fingerprint, err := HubFingerprint(hub)
	if err != nil || fingerprint != vector.ExpectedHubFingerprint {
		t.Fatalf("Hub fingerprint = %q, %v", fingerprint, err)
	}
	card, err := DecodeClaimCard([]byte(vector.ClaimCardCanonicalUTF8))
	if err != nil {
		t.Fatalf("decode published card: %v", err)
	}
	if card.HubFingerprint != vector.ExpectedHubFingerprint || ValidateClaimCard(card, hub, time.Date(2026, 10, 14, 0, 5, 0, 0, time.UTC)) != nil {
		t.Fatal("published claim card does not verify against synthetic full Hub identity")
	}
}
