//go:build js && wasm && cicada_interop_test

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"syscall/js"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func registerInterop(api js.Value) {
	register(api, "openRequestForInteropTest", openRequestForInteropTest)
	register(api, "sealResponseForInteropTest", sealResponseForInteropTest)
	register(api, "makeGrantVectorForInteropTest", makeGrantVectorForInteropTest)
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
