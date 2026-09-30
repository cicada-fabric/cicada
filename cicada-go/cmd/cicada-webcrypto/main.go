//go:build js && wasm

// cicada-webcrypto is the browser-side facade over CICADA's existing Go PQ
// identity and Client Wire v1 packages. It owns identities only in WASM memory.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"syscall/js"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

var identities = map[string]*e2ee.Identity{}
var callbacks []js.Func

func main() {
	api := js.Global().Get("Object").New()
	register(api, "generateIdentity", generateIdentity)
	register(api, "importIdentity", importIdentity)
	register(api, "forgetIdentity", forgetIdentity)
	register(api, "publicIdentity", publicIdentity)
	register(api, "validatePublicIdentity", validatePublicIdentity)
	register(api, "fingerprint", fingerprint)
	register(api, "verifyOwnerDeviceGrant", verifyOwnerDeviceGrant)
	register(api, "sealRequest", sealRequest)
	register(api, "openResponse", openResponse)
	registerInterop(api)
	js.Global().Set("cicadaWebCrypto", api)
	js.Global().Set("cicadaWebCryptoReady", true)
	select {}
}

type handler func(js.Value) (any, error)

func register(api js.Value, name string, call handler) {
	fn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 {
			return failure("one object argument is required")
		}
		result, err := call(args[0])
		if err != nil {
			return failure(err.Error())
		}
		return encodeResult(result)
	})
	callbacks = append(callbacks, fn)
	api.Set(name, fn)
}

func failure(message string) js.Value {
	return encodeResult(map[string]any{"ok": false, "error": message})
}

func encodeResult(value any) js.Value {
	data, err := json.Marshal(value)
	if err != nil {
		return failure("could not encode result")
	}
	return js.Global().Get("JSON").Call("parse", string(data))
}

func decodeValue(value js.Value, out any) error {
	if value.Type() != js.TypeObject || value.IsNull() {
		return errors.New("expected JSON object")
	}
	encoded := js.Global().Get("JSON").Call("stringify", value)
	if encoded.Type() != js.TypeString || encoded.String() == "undefined" {
		return errors.New("could not encode argument")
	}
	return json.Unmarshal([]byte(encoded.String()), out)
}

func stringField(value js.Value, name string) (string, error) {
	field := value.Get(name)
	if field.Type() != js.TypeString || field.String() == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return field.String(), nil
}

func identityFor(handle string) (*e2ee.Identity, error) {
	identity := identities[handle]
	if identity == nil {
		return nil, errors.New("device identity handle is unavailable")
	}
	return identity, nil
}

func makeHandle(identity *e2ee.Identity, exposeIdentityBlob bool) (map[string]any, error) {
	var random [24]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return nil, errors.New("secure browser randomness is unavailable")
	}
	handle := base64.RawURLEncoding.EncodeToString(random[:])
	identities[handle] = identity
	result := map[string]any{"ok": true, "handle": handle, "public_identity": identity.Public()}
	if exposeIdentityBlob {
		blob, err := identity.MarshalBinary()
		if err != nil {
			delete(identities, handle)
			return nil, err
		}
		// The app passes this value directly to WebCrypto for encrypted vault
		// storage and drops the temporary string. It is never persisted raw.
		result["identity_blob"] = base64.StdEncoding.EncodeToString(blob)
	}
	return result, nil
}

func generateIdentity(_ js.Value) (any, error) {
	identity, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	return makeHandle(identity, true)
}

func importIdentity(input js.Value) (any, error) {
	encoded, err := stringField(input, "identity_blob")
	if err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(blob) > 32*1024 {
		return nil, errors.New("encrypted device identity payload is invalid")
	}
	identity, err := e2ee.UnmarshalIdentity(blob)
	if err != nil {
		return nil, errors.New("device identity restore failed")
	}
	return makeHandle(identity, false)
}

func forgetIdentity(input js.Value) (any, error) {
	handle, err := stringField(input, "handle")
	if err != nil {
		return nil, err
	}
	delete(identities, handle)
	return map[string]any{"ok": true}, nil
}

func publicIdentity(input js.Value) (any, error) {
	handle, err := stringField(input, "handle")
	if err != nil {
		return nil, err
	}
	identity, err := identityFor(handle)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "public_identity": identity.Public()}, nil
}

func validatePublicIdentity(input js.Value) (any, error) {
	var public e2ee.PublicIdentity
	if err := decodeValue(input.Get("public_identity"), &public); err != nil {
		return nil, errors.New("public identity is invalid")
	}
	if err := e2ee.ValidatePublicIdentity(public); err != nil {
		return nil, errors.New("public identity validation failed")
	}
	return map[string]any{"ok": true, "public_identity": public}, nil
}

func fingerprint(input js.Value) (any, error) {
	var public e2ee.PublicIdentity
	if err := decodeValue(input.Get("public_identity"), &public); err != nil {
		return nil, errors.New("public identity is invalid")
	}
	value, err := e2ee.OwnerDevicePublicKeyFingerprint(public)
	if err != nil {
		return nil, errors.New("public identity fingerprint failed")
	}
	return map[string]any{"ok": true, "fingerprint": value}, nil
}

func verifyOwnerDeviceGrant(input js.Value) (any, error) {
	var owner, device e2ee.PublicIdentity
	if err := decodeValue(input.Get("owner_public_identity"), &owner); err != nil {
		return nil, errors.New("Owner public identity is invalid")
	}
	if err := decodeValue(input.Get("device_public_identity"), &device); err != nil {
		return nil, errors.New("device public identity is invalid")
	}
	grantText, err := stringField(input, "grant")
	if err != nil {
		return nil, err
	}
	grant, err := base64.StdEncoding.DecodeString(grantText)
	if err != nil {
		return nil, errors.New("Owner grant encoding is invalid")
	}
	ownerID, err := stringField(input, "owner_id")
	if err != nil {
		return nil, err
	}
	deviceID, err := stringField(input, "device_id")
	if err != nil {
		return nil, err
	}
	hubID, err := stringField(input, "hub_id")
	if err != nil {
		return nil, err
	}
	verified, err := e2ee.VerifyOwnerDeviceGrant(grant, owner, device,
		ownerID, owner.ID, deviceID, hubID, e2ee.OwnerDevicePurposeControl, time.Now().UTC())
	if err != nil {
		return nil, errors.New("Owner-signed device grant failed scope or signature verification")
	}
	return map[string]any{"ok": true, "owner_id": verified.OwnerID, "owner_key_id": verified.OwnerKeyID,
		"device_id": verified.DeviceID, "device_key_id": verified.DeviceKeyID,
		"hub_id": verified.HubID, "purpose": verified.Purpose,
		"expires_at": verified.ExpiresAt}, nil
}

type wireInput struct {
	Handle                   string              `json:"handle"`
	Peer                     e2ee.PublicIdentity `json:"peer_public_identity"`
	Binding                  clientwire.Binding  `json:"binding"`
	Route                    clientwire.Route    `json:"route"`
	Plaintext                json.RawMessage     `json:"plaintext"`
	Packet                   string              `json:"packet"`
	ExpectedID               string              `json:"expected_operation_id"`
	ExpectedOp               string              `json:"expected_operation"`
	ExpectedResponseSequence uint64              `json:"expected_response_sequence"`
}

func parseWireInput(value js.Value) (wireInput, error) {
	var input wireInput
	if err := decodeValue(value, &input); err != nil {
		return input, errors.New("wire arguments are invalid")
	}
	if input.Handle == "" || input.Peer.ID == "" || input.Route.Sequence == 0 ||
		len(input.Plaintext) == 0 && input.Packet == "" {
		return input, errors.New("wire identity, route, and packet content are required")
	}
	if err := e2ee.ValidatePublicIdentity(input.Peer); err != nil {
		return input, errors.New("peer public identity is invalid")
	}
	return input, nil
}

func sealRequest(value js.Value) (any, error) {
	input, err := parseWireInput(value)
	if err != nil {
		return nil, err
	}
	identity, err := identityFor(input.Handle)
	if err != nil {
		return nil, err
	}
	packet, err := clientwire.SealRequest(identity, input.Peer, input.Binding, input.Route, input.Plaintext)
	if err != nil {
		return nil, errors.New("Client Wire request sealing failed")
	}
	return map[string]any{"ok": true, "packet": base64.StdEncoding.EncodeToString(packet)}, nil
}

func openResponse(value js.Value) (any, error) {
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
		return nil, errors.New("response packet encoding is invalid")
	}
	opened, err := clientwire.OpenResponse(identity, input.Peer, input.Binding, packet)
	if err != nil || opened.Route.OperationID != input.ExpectedID || opened.Route.Operation != input.ExpectedOp ||
		opened.Route.Sequence != input.ExpectedResponseSequence || opened.Route.SessionEpoch != input.Binding.SessionEpoch {
		return nil, errors.New("Client Wire response authentication or route check failed")
	}
	return map[string]any{"ok": true, "route": opened.Route, "plaintext": string(opened.Plaintext)}, nil
}
