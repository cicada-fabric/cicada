package clientwire

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// This fixture intentionally publishes disposable synthetic private keys so an
// independent implementation can decrypt both directions. Never use these keys
// for enrollment, a running Hub, or any non-test identity.
type publicTestIdentity struct {
	Public  e2ee.PublicIdentity `json:"public"`
	Private json.RawMessage     `json:"private_TEST_ONLY"`
}

type publicWireVector struct {
	Direction string `json:"direction"`
	Packet    string `json:"packet_utf8"`
	Plaintext string `json:"plaintext_utf8"`
	AAD       []byte `json:"aad_base64"`
}

type publicWireVectors struct {
	Schema  int                `json:"fixture_version"`
	Warning string             `json:"warning"`
	Version int                `json:"wire_version"`
	Binding Binding            `json:"binding"`
	Hub     publicTestIdentity `json:"hub_TEST_ONLY"`
	Device  publicTestIdentity `json:"device_TEST_ONLY"`
	Vectors []publicWireVector `json:"vectors"`
}

const vectorPath = "testdata/client-control-v1.json"

func TestPublishedClientWireVectors(t *testing.T) {
	if os.Getenv("CICADA_UPDATE_CLIENT_WIRE_VECTORS") == "1" {
		writePublicWireVectors(t)
	}
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture publicWireVectors
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != 1 || fixture.Version != Version || len(fixture.Vectors) != 2 ||
		fixture.Warning != "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT" {
		t.Fatal("unsupported or unlabelled public test fixture")
	}
	hub, err := e2ee.UnmarshalIdentity(fixture.Hub.Private)
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.UnmarshalIdentity(fixture.Device.Private)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		identity *e2ee.Identity
		public   e2ee.PublicIdentity
	}{{hub, fixture.Hub.Public}, {device, fixture.Device.Public}} {
		actual, _ := json.Marshal(pair.identity.Public())
		expected, _ := json.Marshal(pair.public)
		if !bytes.Equal(actual, expected) {
			t.Fatal("fixture public identity differs from its test private key")
		}
	}
	seen := make(map[string]bool)
	for _, vector := range fixture.Vectors {
		if (vector.Direction != DirectionRequest && vector.Direction != DirectionResponse) || seen[vector.Direction] {
			t.Fatal("fixture must contain one request and one response")
		}
		seen[vector.Direction] = true
		t.Run(vector.Direction, func(t *testing.T) {
			var packet Packet
			if err := json.Unmarshal([]byte(vector.Packet), &packet); err != nil {
				t.Fatal(err)
			}
			associated, err := aad(packet.Route)
			if err != nil || !bytes.Equal(associated, vector.AAD) {
				t.Fatal("canonical route/AAD changed")
			}
			openVector := func(binding Binding, raw []byte) (Opened, error) {
				if vector.Direction == DirectionRequest {
					return OpenRequest(hub, fixture.Device.Public, binding, raw)
				}
				return OpenResponse(device, fixture.Hub.Public, binding, raw)
			}
			opened, err := openVector(fixture.Binding, []byte(vector.Packet))
			if err != nil || string(opened.Plaintext) != vector.Plaintext || opened.Route != packet.Route {
				t.Fatalf("published vector failed: %v", err)
			}
			wrongBinding := fixture.Binding
			wrongBinding.SessionEpoch++
			if _, err := openVector(wrongBinding, []byte(vector.Packet)); err == nil {
				t.Fatal("stale binding accepted")
			}
			changedRoute := packet
			changedRoute.Route.Operation = "devices.revoke"
			raw, _ := json.Marshal(changedRoute)
			if _, err := openVector(fixture.Binding, raw); err == nil {
				t.Fatal("changed authenticated operation accepted")
			}
			for _, field := range []string{"signature", "ciphertext"} {
				var envelope map[string]json.RawMessage
				if err := json.Unmarshal(packet.Envelope, &envelope); err != nil {
					t.Fatal(err)
				}
				var value []byte
				if err := json.Unmarshal(envelope[field], &value); err != nil || len(value) == 0 {
					t.Fatalf("missing vector %s", field)
				}
				value[0] ^= 1
				envelope[field], _ = json.Marshal(value)
				changedEnvelope := packet
				changedEnvelope.Envelope, _ = json.Marshal(envelope)
				raw, _ := json.Marshal(changedEnvelope)
				if _, err := openVector(fixture.Binding, raw); err == nil {
					t.Fatalf("tampered %s accepted", field)
				}
			}
		})
	}
}

func writePublicWireVectors(t *testing.T) {
	t.Helper()
	hub, device, binding, requestRoute := wireFixture(t)
	identity := func(value *e2ee.Identity) publicTestIdentity {
		raw, err := value.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return publicTestIdentity{Public: value.Public(), Private: raw}
	}
	fixture := publicWireVectors{
		Schema: 1, Warning: "PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT",
		Version: Version, Binding: binding, Hub: identity(hub), Device: identity(device),
	}
	for _, direction := range []string{DirectionRequest, DirectionResponse} {
		route := requestRoute
		plaintext := `{}`
		var packet []byte
		var err error
		if direction == DirectionRequest {
			packet, err = SealRequest(device, hub.Public(), binding, route, []byte(plaintext))
		} else {
			route.Direction = DirectionResponse
			route.Sequence = 23
			route.SenderKeyID, route.ReceiverKeyID = hub.Public().ID, device.Public().ID
			route.SenderKeyVersion, route.ReceiverKeyVersion = binding.HubKeyVersion, binding.DeviceKeyVersion
			plaintext = `{"request_id":"test-request","operation_id":"op-one","ok":true,"result":{"note":"公开合成测试 <>&"}}`
			packet, err = SealResponse(hub, device.Public(), binding, route, []byte(plaintext))
		}
		if err != nil {
			t.Fatal(err)
		}
		associated, err := aad(route)
		if err != nil {
			t.Fatal(err)
		}
		fixture.Vectors = append(fixture.Vectors, publicWireVector{
			Direction: direction, Packet: string(packet), Plaintext: plaintext, AAD: associated,
		})
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(vectorPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorPath, append(encoded, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
