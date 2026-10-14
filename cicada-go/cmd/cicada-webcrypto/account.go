//go:build js && wasm

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"syscall/js"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/publicidentity"
)

// Account session handles deliberately share the lifetime of this WASM
// instance. The session token is never returned to JavaScript or persisted.
var ownerAccountSessions = map[string]hubaccountwire.SessionContext{}

func registerOwnerAccount(api js.Value) {
	register(api, "validateOwnerClaimCard", validateOwnerClaimCard)
	register(api, "parseOwnerPublicSPKI", parseOwnerPublicSPKI)
	register(api, "sealOwnerClaimPrepare", sealOwnerClaimPrepare)
	register(api, "sealOwnerClaimComplete", sealOwnerClaimComplete)
	register(api, "openOwnerClaimReceipt", openOwnerClaimReceipt)
	register(api, "sealOwnerLoginPrepare", sealOwnerLoginPrepare)
	register(api, "sealOwnerLoginComplete", sealOwnerLoginComplete)
	register(api, "openOwnerLoginReceipt", openOwnerLoginReceipt)
	register(api, "sealOwnerSessionInspect", sealOwnerSessionInspect)
	register(api, "openOwnerSessionInspection", openOwnerSessionInspection)
	register(api, "sealOwnerLogout", sealOwnerLogout)
	register(api, "openOwnerLogoutReceipt", openOwnerLogoutReceipt)
	register(api, "forgetOwnerAccountSession", forgetOwnerAccountSession)
}

func ownerHubFromInput(value js.Value) (hubaccountwire.HubIdentity, error) {
	var hub hubaccountwire.HubIdentity
	if err := decodeValue(value.Get("hub_identity"), &hub); err != nil || hub.HubID == "" || hub.Public.ID == "" {
		return hubaccountwire.HubIdentity{}, errors.New("pinned Hub identity is invalid")
	}
	return hub, nil
}

func ownerDeviceFromInput(value js.Value) (*e2ee.Identity, error) {
	handle, err := stringField(value, "handle")
	if err != nil {
		return nil, err
	}
	return identityFor(handle)
}

func decodeAccountPacket(value string, label string) ([]byte, error) {
	if value == "" || len(value) > hubaccountwire.MaxPacketBytes*2 {
		return nil, errors.New(label + " is missing or oversized")
	}
	packet, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(packet) > hubaccountwire.MaxPacketBytes {
		return nil, errors.New(label + " encoding is invalid")
	}
	return packet, nil
}

func cardAndSummary(value js.Value, hub hubaccountwire.HubIdentity) (hubaccountwire.ClaimCard, hubaccountwire.ClaimCardSummary, error) {
	cardText, err := stringField(value, "claim_card_json")
	if err != nil || len(cardText) > hubaccountwire.MaxClaimCardBytes {
		return hubaccountwire.ClaimCard{}, hubaccountwire.ClaimCardSummary{}, errors.New("claim card is missing or oversized")
	}
	card, err := hubaccountwire.DecodeClaimCard([]byte(cardText))
	if err != nil {
		return hubaccountwire.ClaimCard{}, hubaccountwire.ClaimCardSummary{}, errors.New("claim card is invalid")
	}
	origin, err := stringField(value, "page_origin")
	if err != nil {
		return hubaccountwire.ClaimCard{}, hubaccountwire.ClaimCardSummary{}, errors.New("page origin is required")
	}
	summary, err := hubaccountwire.ValidateClaimCardForPage(card, origin, hub, time.Now().UTC())
	if err != nil {
		return hubaccountwire.ClaimCard{}, hubaccountwire.ClaimCardSummary{}, errors.New("claim card does not match this page and pinned Hub")
	}
	return card, summary, nil
}

func validateOwnerClaimCard(input js.Value) (any, error) {
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	card, summary, err := cardAndSummary(input, hub)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "summary": claimCardSummaryForUI(summary), "allow_loopback_http": card.AllowLoopbackHTTP}, nil
}

// The UI adapter uses camelCase for non-wire display metadata. Keep that
// contract explicit rather than exposing Go's wire JSON tags to browser code.
func claimCardSummaryForUI(summary hubaccountwire.ClaimCardSummary) map[string]any {
	return map[string]any{"origin": summary.Origin, "hubId": summary.HubID,
		"hubFingerprint": summary.HubFingerprint, "accountId": summary.AccountID,
		"ownerId": summary.OwnerID, "expiresAt": summary.ExpiresAt}
}

func parseOwnerPublicSPKI(input js.Value) (any, error) {
	kemText, err := stringField(input, "kem_public_pem")
	if err != nil {
		return nil, errors.New("ML-KEM public SPKI is required")
	}
	signingText, err := stringField(input, "signing_public_pem")
	if err != nil {
		return nil, errors.New("ML-DSA public SPKI is required")
	}
	if len(kemText) > 16*1024 || len(signingText) > 16*1024 {
		return nil, errors.New("public SPKI PEM exceeds the size limit")
	}
	identity, err := publicidentity.ParseOpenSSLIdentity([]byte(kemText), []byte(signingText))
	if err != nil {
		return nil, errors.New("public SPKI PEM is not a valid ML-KEM-768 and ML-DSA-65 pair")
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(identity)
	if err != nil {
		return nil, errors.New("Owner public-key fingerprint failed")
	}
	return map[string]any{"ok": true, "owner_public_identity": identity, "owner_key_id": identity.ID,
		"owner_fingerprint": fingerprint}, nil
}

func sealOwnerClaimPrepare(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	card, summary, err := cardAndSummary(input, hub)
	if err != nil {
		return nil, err
	}
	body, err := hubaccountwire.NewClaimPrepare(card, hub, device.Public(), time.Now().UTC())
	if err != nil {
		return nil, errors.New("claim request could not be prepared")
	}
	existingDeviceID := input.Get("existing_device_id")
	expectedPublicValue := input.Get("expected_public_identity")
	if existingDeviceID.Type() != js.TypeUndefined || expectedPublicValue.Type() != js.TypeUndefined {
		if existingDeviceID.Type() != js.TypeString || !validExistingAccountDeviceID(existingDeviceID.String()) ||
			expectedPublicValue.Type() != js.TypeObject || expectedPublicValue.IsNull() {
			return nil, errors.New("saved Owner account device binding is invalid")
		}
		var expectedPublic e2ee.PublicIdentity
		if err := decodeValue(expectedPublicValue, &expectedPublic); err != nil ||
			e2ee.ValidatePublicIdentity(expectedPublic) != nil || !sameAccountPublicIdentity(expectedPublic, device.Public()) {
			return nil, errors.New("saved Owner account device does not match the local key")
		}
		body.DeviceID = existingDeviceID.String()
	}
	packet, err := hubaccountwire.SealClientRequest(device, hub, body)
	if err != nil {
		return nil, errors.New("claim request could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet),
		"request_id": body.RequestID, "device_id": body.DeviceID,
		"device_key_fingerprint": body.DeviceKeyFingerprint, "claim": claimCardSummaryForUI(summary),
		"allow_loopback_http": card.AllowLoopbackHTTP, "public_identity": device.Public()}, nil
}

func validExistingAccountDeviceID(value string) bool {
	if !strings.HasPrefix(value, hubaccountwire.AccountDeviceIDPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(value, hubaccountwire.AccountDeviceIDPrefix)
	if len(suffix) != 32 || strings.ToLower(suffix) != suffix {
		return false
	}
	decoded, err := hex.DecodeString(suffix)
	return err == nil && len(decoded) == 16
}

func sameAccountPublicIdentity(left, right e2ee.PublicIdentity) bool {
	return left.ID == right.ID && bytes.Equal(left.KEMPublic, right.KEMPublic) &&
		bytes.Equal(left.SigningPublic, right.SigningPublic)
}

func sealOwnerClaimComplete(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	prepareText, err := stringField(input, "prepare_packet")
	if err != nil {
		return nil, err
	}
	preparePacket, err := decodeAccountPacket(prepareText, "saved claim prepare packet")
	if err != nil {
		return nil, err
	}
	challengeText, err := stringField(input, "challenge_packet")
	if err != nil {
		return nil, err
	}
	challengePacket, err := decodeAccountPacket(challengeText, "saved claim challenge packet")
	if err != nil {
		return nil, err
	}
	var challenge hubaccountwire.ClaimChallenge
	if err := hubaccountwire.OpenClientResponse(device, hub, preparePacket, challengePacket, &challenge); err != nil {
		return nil, errors.New("saved claim challenge did not authenticate for this pinned Hub and device")
	}
	expectedOrigin, _ := stringField(input, "origin")
	expectedAccountID, _ := stringField(input, "account_id")
	expectedOwnerID, _ := stringField(input, "owner_id")
	expectedDeviceID, _ := stringField(input, "device_id")
	if challenge.Origin != expectedOrigin || challenge.AccountID != expectedAccountID ||
		challenge.OwnerID != expectedOwnerID || challenge.DeviceID != expectedDeviceID || challenge.HubID != hub.HubID {
		return nil, errors.New("saved claim challenge does not match the local account profile")
	}
	username, err := stringField(input, "username")
	if err != nil {
		return nil, errors.New("Owner username is required")
	}
	password, err := stringField(input, "password")
	if err != nil {
		return nil, errors.New("Owner password is required")
	}
	var ownerPublic e2ee.PublicIdentity
	if err := decodeValue(input.Get("owner_public_identity"), &ownerPublic); err != nil || e2ee.ValidatePublicIdentity(ownerPublic) != nil {
		return nil, errors.New("Owner public identity is invalid")
	}
	body, err := hubaccountwire.NewClaimCompleteFromChallenge(hub, challenge, device.Public(), username, password, ownerPublic, time.Now().UTC())
	if err != nil {
		return nil, errors.New("Owner claim completion could not be prepared; verify the account fields and challenge expiry")
	}
	packet, err := hubaccountwire.SealClientRequest(device, hub, body)
	body.Password = ""
	if err != nil {
		return nil, errors.New("Owner claim completion could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet),
		"request_id": body.RequestID, "device_id": body.DeviceID}, nil
}

func openOwnerClaimReceipt(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	requestText, err := stringField(input, "request_packet")
	if err != nil {
		return nil, err
	}
	request, err := decodeAccountPacket(requestText, "saved claim completion packet")
	if err != nil {
		return nil, err
	}
	responseText, err := stringField(input, "response_packet")
	if err != nil {
		return nil, err
	}
	response, err := decodeAccountPacket(responseText, "claim receipt packet")
	if err != nil {
		return nil, err
	}
	var receipt hubaccountwire.ClaimReceipt
	if err := hubaccountwire.OpenClientResponse(device, hub, request, response, &receipt); err != nil {
		return nil, errors.New("claim receipt did not authenticate for the saved request")
	}
	accountID, _ := stringField(input, "account_id")
	ownerID, _ := stringField(input, "owner_id")
	origin, _ := stringField(input, "origin")
	ownerKeyID, _ := stringField(input, "owner_key_id")
	ownerFingerprint, _ := stringField(input, "owner_fingerprint")
	var ownerPublic e2ee.PublicIdentity
	if err := decodeValue(input.Get("owner_public_identity"), &ownerPublic); err != nil ||
		e2ee.ValidatePublicIdentity(ownerPublic) != nil || ownerPublic.ID != ownerKeyID {
		return nil, errors.New("saved Owner public identity is invalid")
	}
	actualFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(ownerPublic)
	if err != nil || actualFingerprint != ownerFingerprint {
		return nil, errors.New("saved Owner public-key fingerprint is invalid")
	}
	if receipt.State != hubaccountwire.ClaimPendingState || receipt.RootActive || receipt.RootState != hubaccountwire.RootPendingState ||
		receipt.AccountID != accountID || receipt.OwnerID != ownerID || receipt.Origin != origin ||
		receipt.OwnerKeyID != ownerPublic.ID || receipt.OwnerFingerprint != actualFingerprint {
		return nil, errors.New("Hub returned an unexpected Owner account state")
	}
	return map[string]any{"ok": true, "receipt": receipt}, nil
}

func sealOwnerLoginPrepare(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	origin, err := stringField(input, "origin")
	if err != nil {
		return nil, err
	}
	accountID, err := stringField(input, "account_id")
	if err != nil {
		return nil, err
	}
	ownerID, err := stringField(input, "owner_id")
	if err != nil {
		return nil, err
	}
	deviceID, err := stringField(input, "device_id")
	if err != nil {
		return nil, err
	}
	username, err := stringField(input, "username")
	if err != nil {
		return nil, err
	}
	body, err := hubaccountwire.NewLoginPrepare(hub, origin, accountID, ownerID, deviceID, username, device.Public(), time.Now().UTC())
	if err != nil {
		return nil, errors.New("Owner login request is invalid")
	}
	packet, err := hubaccountwire.SealClientRequest(device, hub, body)
	if err != nil {
		return nil, errors.New("Owner login request could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet), "request_id": body.RequestID}, nil
}

func sealOwnerLoginComplete(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	prepareText, err := stringField(input, "prepare_packet")
	if err != nil {
		return nil, err
	}
	preparePacket, err := decodeAccountPacket(prepareText, "saved Owner login prepare packet")
	if err != nil {
		return nil, err
	}
	challengeText, err := stringField(input, "challenge_packet")
	if err != nil {
		return nil, err
	}
	challengePacket, err := decodeAccountPacket(challengeText, "saved Owner login challenge packet")
	if err != nil {
		return nil, err
	}
	var challenge hubaccountwire.LoginChallenge
	if err := hubaccountwire.OpenClientResponse(device, hub, preparePacket, challengePacket, &challenge); err != nil {
		return nil, errors.New("Owner login challenge did not authenticate for this pinned Hub and device")
	}
	expectedOrigin, _ := stringField(input, "origin")
	expectedAccountID, _ := stringField(input, "account_id")
	expectedOwnerID, _ := stringField(input, "owner_id")
	expectedDeviceID, _ := stringField(input, "device_id")
	expectedUsername, _ := stringField(input, "username")
	if challenge.Origin != expectedOrigin || challenge.AccountID != expectedAccountID ||
		challenge.OwnerID != expectedOwnerID || challenge.DeviceID != expectedDeviceID ||
		challenge.Username != expectedUsername || challenge.HubID != hub.HubID {
		return nil, errors.New("Owner login challenge does not match the local account profile")
	}
	password, err := stringField(input, "password")
	if err != nil {
		return nil, errors.New("Owner password is required")
	}
	body, err := hubaccountwire.NewLoginComplete(hub, challenge, password, time.Now().UTC())
	if err != nil {
		return nil, errors.New("Owner login challenge is expired or invalid")
	}
	packet, err := hubaccountwire.SealClientRequest(device, hub, body)
	body.Password = ""
	if err != nil {
		return nil, errors.New("Owner login completion could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet), "request_id": body.RequestID}, nil
}

func openOwnerLoginReceipt(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	requestText, err := stringField(input, "request_packet")
	if err != nil {
		return nil, err
	}
	request, err := decodeAccountPacket(requestText, "saved Owner login completion packet")
	if err != nil {
		return nil, err
	}
	responseText, err := stringField(input, "response_packet")
	if err != nil {
		return nil, err
	}
	response, err := decodeAccountPacket(responseText, "Owner session receipt packet")
	if err != nil {
		return nil, err
	}
	var receipt hubaccountwire.SessionReceipt
	if err := hubaccountwire.OpenClientResponse(device, hub, request, response, &receipt); err != nil {
		return nil, errors.New("Owner session receipt did not authenticate for the saved request")
	}
	deviceFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		clear(receipt.SessionToken)
		return nil, errors.New("Owner account device fingerprint could not be checked")
	}
	expectedOrigin, _ := stringField(input, "origin")
	expectedAccountID, _ := stringField(input, "account_id")
	expectedOwnerID, _ := stringField(input, "owner_id")
	expectedDeviceID, _ := stringField(input, "device_id")
	if receipt.Origin != expectedOrigin || receipt.AccountID != expectedAccountID ||
		receipt.OwnerID != expectedOwnerID || receipt.DeviceID != expectedDeviceID ||
		receipt.HubID != hub.HubID || receipt.DeviceKeyID != device.Public().ID ||
		receipt.DeviceKeyFingerprint != deviceFingerprint {
		clear(receipt.SessionToken)
		return nil, errors.New("Owner session receipt did not match this account device")
	}
	context := receipt.Context()
	clear(receipt.SessionToken)
	handle, err := newOwnerAccountSessionHandle(context)
	clear(context.SessionToken)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "session_handle": handle, "origin": receipt.Origin,
		"hub_id": receipt.HubID, "account_id": receipt.AccountID, "owner_id": receipt.OwnerID,
		"device_id": receipt.DeviceID, "account_epoch": receipt.AccountEpoch,
		"device_epoch": receipt.DeviceEpoch, "expires_at": receipt.ExpiresAt}, nil
}

func newOwnerAccountSessionHandle(session hubaccountwire.SessionContext) (string, error) {
	var bytes [24]byte
	if _, err := io.ReadFull(rand.Reader, bytes[:]); err != nil {
		return "", errors.New("secure session handle generation failed")
	}
	handle := base64.RawURLEncoding.EncodeToString(bytes[:])
	session.SessionToken = append([]byte(nil), session.SessionToken...)
	ownerAccountSessions[handle] = session
	return handle, nil
}

func ownerAccountSession(input js.Value) (string, hubaccountwire.SessionContext, error) {
	handle, err := stringField(input, "session_handle")
	if err != nil {
		return "", hubaccountwire.SessionContext{}, err
	}
	session, ok := ownerAccountSessions[handle]
	if !ok {
		return "", hubaccountwire.SessionContext{}, errors.New("Owner account session is unavailable; log in again")
	}
	return handle, session, nil
}

func sealOwnerSessionInspect(input js.Value) (any, error) {
	_, session, err := ownerAccountSession(input)
	if err != nil {
		return nil, err
	}
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	if session.HubID != hub.HubID || session.DeviceID == "" || session.DeviceKeyID != device.Public().ID {
		return nil, errors.New("Owner session does not match this pinned Hub device")
	}
	body, err := hubaccountwire.NewSessionInspectRequest(session, time.Now().UTC())
	if err != nil {
		return nil, errors.New("Owner session is expired; log in again")
	}
	packet, err := hubaccountwire.SealClientRequest(device, hub, body)
	clear(body.SessionToken)
	if err != nil {
		return nil, errors.New("Owner session inspection could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet), "request_id": body.RequestID}, nil
}

func openOwnerSessionInspection(input js.Value) (any, error) {
	_, session, err := ownerAccountSession(input)
	if err != nil {
		return nil, err
	}
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	requestText, err := stringField(input, "request_packet")
	if err != nil {
		return nil, err
	}
	request, err := decodeAccountPacket(requestText, "saved Owner session inspection packet")
	if err != nil {
		return nil, err
	}
	responseText, err := stringField(input, "response_packet")
	if err != nil {
		return nil, err
	}
	response, err := decodeAccountPacket(responseText, "Owner account status packet")
	if err != nil {
		return nil, err
	}
	var status hubaccountwire.SessionInspection
	if err := hubaccountwire.OpenClientResponse(device, hub, request, response, &status); err != nil {
		return nil, errors.New("Owner account status did not authenticate for the saved request")
	}
	if status.Origin != session.Origin || status.HubID != session.HubID ||
		status.AccountID != session.AccountID || status.OwnerID != session.OwnerID ||
		status.ActorDeviceID != session.DeviceID || status.ActorDeviceEpoch != session.DeviceEpoch {
		return nil, errors.New("Owner account status did not match this session")
	}
	return map[string]any{"ok": true, "status": status}, nil
}

func sealOwnerLogout(input js.Value) (any, error) {
	_, session, err := ownerAccountSession(input)
	if err != nil {
		return nil, err
	}
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	if session.HubID != hub.HubID || session.DeviceKeyID != device.Public().ID {
		return nil, errors.New("Owner session does not match this pinned Hub device")
	}
	body, err := hubaccountwire.NewLogoutRequest(session, time.Now().UTC())
	if err != nil {
		return nil, errors.New("Owner session is expired; log in again")
	}
	packet, err := hubaccountwire.SealClientRequest(device, hub, body)
	clear(body.SessionToken)
	if err != nil {
		return nil, errors.New("Owner logout could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet), "request_id": body.RequestID}, nil
}

func openOwnerLogoutReceipt(input js.Value) (any, error) {
	device, err := ownerDeviceFromInput(input)
	if err != nil {
		return nil, err
	}
	hub, err := ownerHubFromInput(input)
	if err != nil {
		return nil, err
	}
	requestText, err := stringField(input, "request_packet")
	if err != nil {
		return nil, err
	}
	request, err := decodeAccountPacket(requestText, "saved Owner logout packet")
	if err != nil {
		return nil, err
	}
	responseText, err := stringField(input, "response_packet")
	if err != nil {
		return nil, err
	}
	response, err := decodeAccountPacket(responseText, "Owner logout receipt")
	if err != nil {
		return nil, err
	}
	var receipt hubaccountwire.LogoutReceipt
	if err := hubaccountwire.OpenClientResponse(device, hub, request, response, &receipt); err != nil {
		return nil, errors.New("Owner logout receipt did not authenticate for the saved request")
	}
	var expected struct {
		Origin       string `json:"origin"`
		HubID        string `json:"hub_id"`
		AccountID    string `json:"account_id"`
		OwnerID      string `json:"owner_id"`
		DeviceID     string `json:"device_id"`
		AccountEpoch uint64 `json:"account_epoch"`
		DeviceEpoch  uint64 `json:"device_epoch"`
	}
	if err := decodeValue(input, &expected); err != nil || expected.Origin == "" || expected.HubID != hub.HubID ||
		expected.AccountID == "" || expected.OwnerID == "" || expected.DeviceID == "" ||
		expected.AccountEpoch == 0 || expected.DeviceEpoch == 0 {
		return nil, errors.New("saved Owner logout binding is invalid")
	}
	handle := ""
	if value := input.Get("session_handle"); value.Type() == js.TypeString && value.String() != "" {
		handle = value.String()
		_, session, err := ownerAccountSession(input)
		if err != nil || session.Origin != expected.Origin || session.HubID != expected.HubID ||
			session.AccountID != expected.AccountID || session.OwnerID != expected.OwnerID ||
			session.DeviceID != expected.DeviceID || session.AccountEpoch != expected.AccountEpoch ||
			session.DeviceEpoch != expected.DeviceEpoch {
			return nil, errors.New("saved Owner logout binding does not match the active session")
		}
	}
	if receipt.State != hubaccountwire.SessionRevokedState || receipt.Origin != expected.Origin ||
		receipt.HubID != expected.HubID || receipt.AccountID != expected.AccountID ||
		receipt.OwnerID != expected.OwnerID || receipt.DeviceID != expected.DeviceID ||
		receipt.AccountEpoch != expected.AccountEpoch || receipt.DeviceEpoch != expected.DeviceEpoch {
		return nil, errors.New("Hub returned an unexpected logout state")
	}
	if handle != "" {
		forgetOwnerSessionHandle(handle)
	}
	return map[string]any{"ok": true, "receipt": receipt}, nil
}

func forgetOwnerAccountSession(input js.Value) (any, error) {
	handle, err := stringField(input, "session_handle")
	if err != nil {
		return nil, err
	}
	forgetOwnerSessionHandle(handle)
	return map[string]any{"ok": true}, nil
}

func forgetOwnerSessionHandle(handle string) {
	if session, ok := ownerAccountSessions[handle]; ok {
		clear(session.SessionToken)
		delete(ownerAccountSessions, handle)
	}
}

func forgetOwnerAccountSessionsForDeviceID(deviceKeyID string) {
	for handle, session := range ownerAccountSessions {
		if session.DeviceKeyID == deviceKeyID {
			clear(session.SessionToken)
			delete(ownerAccountSessions, handle)
		}
	}
}
