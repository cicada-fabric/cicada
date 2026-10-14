//go:build js && wasm && cicada_interop_test

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"syscall/js"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

func registerInterop(api js.Value) {
	register(api, "openRequestForInteropTest", openRequestForInteropTest)
	register(api, "sealResponseForInteropTest", sealResponseForInteropTest)
	register(api, "makeGrantVectorForInteropTest", makeGrantVectorForInteropTest)
	register(api, "makeOwnerClaimFixtureForInteropTest", makeOwnerClaimFixtureForInteropTest)
	register(api, "sealOwnerClaimChallengeForInteropTest", sealOwnerClaimChallengeForInteropTest)
	register(api, "sealOwnerClaimReceiptForInteropTest", sealOwnerClaimReceiptForInteropTest)
	register(api, "sealOwnerLoginChallengeForInteropTest", sealOwnerLoginChallengeForInteropTest)
	register(api, "sealOwnerLoginReceiptForInteropTest", sealOwnerLoginReceiptForInteropTest)
	register(api, "sealOwnerSessionInspectionForInteropTest", sealOwnerSessionInspectionForInteropTest)
	register(api, "sealOwnerLogoutReceiptForInteropTest", sealOwnerLogoutReceiptForInteropTest)
}

func makeOwnerClaimFixtureForInteropTest(value js.Value) (any, error) {
	handle, err := stringField(value, "hub_handle")
	if err != nil {
		return nil, err
	}
	hub, err := identityFor(handle)
	if err != nil {
		return nil, err
	}
	identity := hubaccountwire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_wasm_owner_account",
		Public: hub.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite}
	fingerprint, err := hubaccountwire.HubFingerprint(identity)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	card := hubaccountwire.ClaimCard{Format: hubaccountwire.ClaimCardFormat, Version: 1,
		Purpose: hubaccountwire.PurposeInitialClaim, Origin: "https://synthetic.invalid",
		HubID: identity.HubID, HubFingerprint: fingerprint, AccountID: "account_wasm_owner_account",
		OwnerID: "human_wasm_owner_account", ClaimID: strings.Repeat("a", 32),
		Code:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, hubaccountwire.CodeBytes)),
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(59 * time.Minute).Format(time.RFC3339Nano)}
	cardJSON, err := json.Marshal(card)
	if err != nil {
		return nil, err
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "hub_identity": identity, "claim_card_json": string(cardJSON),
		"page_origin": card.Origin, "owner_public_identity": owner.Public()}, nil
}

func interopHubAndRequest(value js.Value, operation string) (*e2ee.Identity, hubaccountwire.HubIdentity,
	hubaccountwire.Packet, []byte, clientwire.Binding, clientwire.Route, error) {
	hubHandle, err := stringField(value, "hub_handle")
	if err != nil {
		return nil, hubaccountwire.HubIdentity{}, hubaccountwire.Packet{}, nil, clientwire.Binding{}, clientwire.Route{}, err
	}
	hub, err := identityFor(hubHandle)
	if err != nil {
		return nil, hubaccountwire.HubIdentity{}, hubaccountwire.Packet{}, nil, clientwire.Binding{}, clientwire.Route{}, err
	}
	var publicHub hubaccountwire.HubIdentity
	if err := decodeValue(value.Get("hub_identity"), &publicHub); err != nil {
		return nil, hubaccountwire.HubIdentity{}, hubaccountwire.Packet{}, nil, clientwire.Binding{}, clientwire.Route{}, err
	}
	encoded, err := stringField(value, "request_packet")
	if err != nil {
		return nil, hubaccountwire.HubIdentity{}, hubaccountwire.Packet{}, nil, clientwire.Binding{}, clientwire.Route{}, err
	}
	request, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(request) > hubaccountwire.MaxPacketBytes {
		return nil, hubaccountwire.HubIdentity{}, hubaccountwire.Packet{}, nil, clientwire.Binding{}, clientwire.Route{}, errors.New("test request packet is invalid")
	}
	outer, err := hubaccountwire.PreflightRequest(request, operation)
	if err != nil {
		return nil, hubaccountwire.HubIdentity{}, hubaccountwire.Packet{}, nil, clientwire.Binding{}, clientwire.Route{}, err
	}
	route := outer.Packet.Route
	binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID,
		SessionEpoch: route.SessionEpoch, HubKeyVersion: route.ReceiverKeyVersion,
		DeviceKeyVersion: route.SenderKeyVersion}
	return hub, publicHub, outer, request, binding, route, nil
}

func sealOwnerClaimChallengeForInteropTest(value js.Value) (any, error) {
	hub, publicHub, outer, request, binding, route, err := interopHubAndRequest(value, hubaccountwire.OperationClaimPrepare)
	if err != nil {
		return nil, err
	}
	var prepare hubaccountwire.ClaimPrepare
	if err := hubaccountwire.OpenRequestAt(hub, nil, binding, route, request, &prepare, time.Now().UTC()); err != nil {
		return nil, err
	}
	serverNonce, err := hubaccountwire.NewNonce()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	challenge := hubaccountwire.ClaimChallenge{Format: hubaccountwire.ClaimChallengeFormat,
		Purpose: hubaccountwire.PurposeInitialClaim, Origin: prepare.Claim.Origin, HubID: prepare.Claim.HubID,
		AccountID: prepare.Claim.AccountID, OwnerID: prepare.Claim.OwnerID, ClaimID: prepare.Claim.ClaimID,
		AttemptID: strings.Repeat("b", 32), DeviceID: prepare.DeviceID, DeviceKeyID: outer.SenderPublicIdentity.ID,
		DeviceKeyFingerprint: prepare.DeviceKeyFingerprint, PrepareRequestID: prepare.RequestID,
		ClientNonce: bytes.Clone(prepare.ClientNonce), ServerNonce: serverNonce, AccountEpoch: 1, DeviceEpoch: 1,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	if publicHub.Public.ID != hub.Public().ID {
		return nil, errors.New("test Hub identity does not match")
	}
	packet, err := hubaccountwire.SealResponse(hub, outer.SenderPublicIdentity, route, challenge)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet),
		"device_id": prepare.DeviceID, "request_id": prepare.RequestID,
		"client_nonce": base64.StdEncoding.EncodeToString(prepare.ClientNonce)}, nil
}

func sealOwnerClaimReceiptForInteropTest(value js.Value) (any, error) {
	prepareText, err := stringField(value, "prepare_packet")
	if err != nil {
		return nil, err
	}
	challengeText, err := stringField(value, "challenge_packet")
	if err != nil {
		return nil, err
	}
	deviceHandle, err := stringField(value, "device_handle")
	if err != nil {
		return nil, err
	}
	device, err := identityFor(deviceHandle)
	if err != nil {
		return nil, err
	}
	preparePacket, err := base64.StdEncoding.DecodeString(prepareText)
	if err != nil {
		return nil, err
	}
	challengePacket, err := base64.StdEncoding.DecodeString(challengeText)
	if err != nil {
		return nil, err
	}
	var publicHub hubaccountwire.HubIdentity
	if err := decodeValue(value.Get("hub_identity"), &publicHub); err != nil {
		return nil, err
	}
	var challenge hubaccountwire.ClaimChallenge
	if err := hubaccountwire.OpenClientResponse(device, publicHub, preparePacket, challengePacket, &challenge); err != nil {
		return nil, err
	}
	hubHandle, err := stringField(value, "hub_handle")
	if err != nil {
		return nil, err
	}
	hub, err := identityFor(hubHandle)
	if err != nil {
		return nil, err
	}
	completeText, err := stringField(value, "complete_packet")
	if err != nil {
		return nil, err
	}
	completePacket, err := base64.StdEncoding.DecodeString(completeText)
	if err != nil || len(completePacket) > hubaccountwire.MaxPacketBytes {
		return nil, errors.New("test completion packet is invalid")
	}
	outer, err := hubaccountwire.PreflightRequest(completePacket, hubaccountwire.OperationClaimComplete)
	if err != nil {
		return nil, err
	}
	route := outer.Packet.Route
	binding := clientwire.Binding{HubID: route.HubID, OwnerID: route.OwnerID, DeviceID: route.DeviceID,
		SessionEpoch: route.SessionEpoch, HubKeyVersion: route.ReceiverKeyVersion,
		DeviceKeyVersion: route.SenderKeyVersion}
	var complete hubaccountwire.ClaimComplete
	if err := hubaccountwire.OpenRequestAt(hub, &outer.SenderPublicIdentity, binding, route, completePacket, &complete, time.Now().UTC()); err != nil {
		return nil, err
	}
	var ownerPublic e2ee.PublicIdentity
	if err := decodeValue(value.Get("owner_public_identity"), &ownerPublic); err != nil {
		return nil, err
	}
	ownerFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(ownerPublic)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	receipt := hubaccountwire.ClaimReceipt{Format: hubaccountwire.ClaimReceiptFormat,
		Purpose: hubaccountwire.PurposeInitialClaim, Origin: complete.Origin, HubID: complete.HubID,
		AccountID: complete.AccountID, OwnerID: complete.OwnerID, ClaimID: complete.ClaimID,
		AttemptID: challenge.AttemptID, RequestID: complete.RequestID, DeviceID: complete.DeviceID,
		DeviceKeyID: complete.DeviceKeyID, DeviceKeyFingerprint: complete.DeviceKeyFingerprint,
		AccountEpoch: complete.AccountEpoch, DeviceEpoch: complete.DeviceEpoch,
		State: hubaccountwire.ClaimPendingState, OwnerKeyID: ownerPublic.ID, OwnerFingerprint: ownerFingerprint,
		RootState: hubaccountwire.RootPendingState, RootActive: false, CompletedAt: now.Format(time.RFC3339Nano)}
	packet, err := hubaccountwire.SealResponse(hub, outer.SenderPublicIdentity, route, receipt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func sealOwnerLoginChallengeForInteropTest(value js.Value) (any, error) {
	hub, _, outer, request, binding, route, err := interopHubAndRequest(value, hubaccountwire.OperationLoginPrepare)
	if err != nil {
		return nil, err
	}
	var prepare hubaccountwire.LoginPrepare
	if err := hubaccountwire.OpenRequestAt(hub, &outer.SenderPublicIdentity, binding, route, request, &prepare, time.Now().UTC()); err != nil {
		return nil, err
	}
	serverNonce, err := hubaccountwire.NewNonce()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	challenge := hubaccountwire.LoginChallenge{Format: hubaccountwire.LoginChallengeFormat,
		Purpose: hubaccountwire.PurposeAccountLogin, Origin: prepare.Origin, HubID: prepare.HubID,
		AccountID: prepare.AccountID, OwnerID: prepare.OwnerID, AttemptID: strings.Repeat("c", 32),
		DeviceID: prepare.DeviceID, DeviceKeyID: outer.SenderPublicIdentity.ID,
		DeviceKeyFingerprint: prepare.DeviceKeyFingerprint, Username: prepare.Username,
		PrepareRequestID: prepare.RequestID, ClientNonce: bytes.Clone(prepare.ClientNonce), ServerNonce: serverNonce,
		AccountEpoch: 1, DeviceEpoch: 1, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	packet, err := hubaccountwire.SealResponse(hub, outer.SenderPublicIdentity, route, challenge)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func sealOwnerLoginReceiptForInteropTest(value js.Value) (any, error) {
	preparePacket, err := testPacketBytes(value, "prepare_packet")
	if err != nil {
		return nil, err
	}
	challengePacket, err := testPacketBytes(value, "challenge_packet")
	if err != nil {
		return nil, err
	}
	deviceHandle, err := stringField(value, "device_handle")
	if err != nil {
		return nil, err
	}
	device, err := identityFor(deviceHandle)
	if err != nil {
		return nil, err
	}
	var publicHub hubaccountwire.HubIdentity
	if err := decodeValue(value.Get("hub_identity"), &publicHub); err != nil {
		return nil, err
	}
	var challenge hubaccountwire.LoginChallenge
	if err := hubaccountwire.OpenClientResponse(device, publicHub, preparePacket, challengePacket, &challenge); err != nil {
		return nil, err
	}
	hub, _, outer, completePacket, binding, route, err := interopHubAndRequest(value, hubaccountwire.OperationLoginComplete)
	if err != nil {
		return nil, err
	}
	var complete hubaccountwire.LoginComplete
	if err := hubaccountwire.OpenRequestAt(hub, &outer.SenderPublicIdentity, binding, route, completePacket, &complete, time.Now().UTC()); err != nil {
		return nil, err
	}
	if complete.AttemptID != challenge.AttemptID || complete.PrepareRequestID != challenge.PrepareRequestID ||
		complete.DeviceID != challenge.DeviceID || complete.AccountID != challenge.AccountID || complete.OwnerID != challenge.OwnerID {
		return nil, errors.New("test Owner login challenge did not match completion")
	}
	now := time.Now().UTC()
	receipt := hubaccountwire.SessionReceipt{Format: hubaccountwire.SessionReceiptFormat,
		Purpose: hubaccountwire.PurposeAccountSession, Origin: complete.Origin, HubID: complete.HubID,
		AccountID: complete.AccountID, OwnerID: complete.OwnerID, DeviceID: complete.DeviceID,
		DeviceKeyID: complete.DeviceKeyID, DeviceKeyFingerprint: complete.DeviceKeyFingerprint,
		SessionToken: bytes.Repeat([]byte{0x42}, hubaccountwire.MaxSessionTokenBytes),
		AccountEpoch: complete.AccountEpoch, DeviceEpoch: complete.DeviceEpoch,
		RequestID: complete.RequestID, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	packet, err := hubaccountwire.SealResponse(hub, outer.SenderPublicIdentity, route, receipt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func sealOwnerSessionInspectionForInteropTest(value js.Value) (any, error) {
	hub, _, outer, request, binding, route, err := interopHubAndRequest(value, hubaccountwire.OperationSessionInspect)
	if err != nil {
		return nil, err
	}
	var inspect hubaccountwire.SessionInspectRequest
	if err := hubaccountwire.OpenRequestAt(hub, &outer.SenderPublicIdentity, binding, route, request, &inspect, time.Now().UTC()); err != nil {
		return nil, err
	}
	if !bytes.Equal(inspect.SessionToken, bytes.Repeat([]byte{0x42}, hubaccountwire.MaxSessionTokenBytes)) {
		return nil, errors.New("test account session token changed in the protected request")
	}
	var ownerPublic e2ee.PublicIdentity
	if err := decodeValue(value.Get("owner_public_identity"), &ownerPublic); err != nil {
		return nil, err
	}
	ownerFingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(ownerPublic)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	inspection := hubaccountwire.SessionInspection{Format: hubaccountwire.SessionInspectionFormat,
		Purpose: hubaccountwire.PurposeAccountSession, Origin: inspect.Origin, HubID: inspect.HubID,
		AccountID: inspect.AccountID, OwnerID: inspect.OwnerID, Username: "synthetic-owner",
		ActorDeviceID: inspect.DeviceID, ActorDeviceEpoch: inspect.DeviceEpoch, RequestID: inspect.RequestID,
		State: hubaccountwire.SessionActiveState, RootState: hubaccountwire.RootPendingState,
		RootActive: false, OwnerKeyID: ownerPublic.ID, OwnerFingerprint: ownerFingerprint,
		Devices: []hubaccountwire.LoginDeviceSummary{{DeviceID: inspect.DeviceID, DeviceKeyID: inspect.DeviceKeyID,
			DeviceKeyFingerprint: inspect.DeviceKeyFingerprint, State: hubaccountwire.DeviceActiveState,
			DeviceEpoch: inspect.DeviceEpoch, CreatedAt: now.Format(time.RFC3339Nano),
			LastSeenAt: now.Format(time.RFC3339Nano)}}, InspectedAt: now.Format(time.RFC3339Nano)}
	packet, err := hubaccountwire.SealResponse(hub, outer.SenderPublicIdentity, route, inspection)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func sealOwnerLogoutReceiptForInteropTest(value js.Value) (any, error) {
	hub, _, outer, request, binding, route, err := interopHubAndRequest(value, hubaccountwire.OperationSessionLogout)
	if err != nil {
		return nil, err
	}
	var logout hubaccountwire.LogoutRequest
	if err := hubaccountwire.OpenRequestAt(hub, &outer.SenderPublicIdentity, binding, route, request, &logout, time.Now().UTC()); err != nil {
		return nil, err
	}
	if !bytes.Equal(logout.SessionToken, bytes.Repeat([]byte{0x42}, hubaccountwire.MaxSessionTokenBytes)) {
		return nil, errors.New("test logout token changed in the protected request")
	}
	now := time.Now().UTC()
	receipt := hubaccountwire.LogoutReceipt{Format: hubaccountwire.LogoutReceiptFormat,
		Purpose: hubaccountwire.PurposeAccountSession, Origin: logout.Origin, HubID: logout.HubID,
		AccountID: logout.AccountID, OwnerID: logout.OwnerID, DeviceID: logout.DeviceID,
		AccountEpoch: logout.AccountEpoch, DeviceEpoch: logout.DeviceEpoch, RequestID: logout.RequestID,
		State: hubaccountwire.SessionRevokedState, LoggedOutAt: now.Format(time.RFC3339Nano)}
	packet, err := hubaccountwire.SealResponse(hub, outer.SenderPublicIdentity, route, receipt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func testPacketBytes(value js.Value, name string) ([]byte, error) {
	encoded, err := stringField(value, name)
	if err != nil {
		return nil, err
	}
	packet, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(packet) > hubaccountwire.MaxPacketBytes {
		return nil, errors.New("test account packet is invalid")
	}
	return packet, nil
}

func openRequestForInteropTest(value js.Value) (any, error) {
	input, err := parseWireInput(value)
	if err != nil {
		return nil, err
	}
	identity, err := identityFor(input.Handle)
	if err != nil {
		return nil, err
	}
	packet, err := base64.StdEncoding.DecodeString(input.Packet)
	if err != nil {
		return nil, errors.New("request packet encoding is invalid")
	}
	opened, err := clientwire.OpenRequest(identity, input.Peer, input.Binding, packet)
	if err != nil {
		return nil, errors.New("Client Wire request authentication failed")
	}
	return map[string]any{"ok": true, "route": opened.Route, "plaintext": string(opened.Plaintext)}, nil
}

func sealResponseForInteropTest(value js.Value) (any, error) {
	input, err := parseWireInput(value)
	if err != nil {
		return nil, err
	}
	identity, err := identityFor(input.Handle)
	if err != nil {
		return nil, err
	}
	var responseRoute clientwire.Route
	if err := decodeValue(value.Get("response_route"), &responseRoute); err != nil {
		return nil, errors.New("test response route is invalid")
	}
	packet, err := clientwire.SealResponse(identity, input.Peer, input.Binding, responseRoute, input.Plaintext)
	if err != nil {
		return nil, errors.New("test Client Wire response could not be sealed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func makeGrantVectorForInteropTest(value js.Value) (any, error) {
	handle, err := stringField(value, "handle")
	if err != nil {
		return nil, err
	}
	device, err := identityFor(handle)
	if err != nil {
		return nil, err
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	issued := time.Now().UTC().Add(-time.Minute)
	expires := time.Now().UTC().Add(time.Hour)
	grant, err := owner.SignOwnerDeviceGrant("synthetic-owner", "synthetic-browser", device.Public(),
		"synthetic-hub", e2ee.OwnerDevicePurposeControl, issued, expires)
	if err != nil {
		return nil, err
	}
	var strictGrant e2ee.OwnerDeviceGrant
	if err := json.Unmarshal(grant, &strictGrant); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "owner_public_identity": owner.Public(),
		"device_public_identity": device.Public(), "grant": base64.StdEncoding.EncodeToString(grant),
		"owner_id": "synthetic-owner", "device_id": "synthetic-browser", "hub_id": "synthetic-hub"}, nil
}
