package main

import (
	"encoding/json"
	"testing"
)

func TestLANDiscoveryMessageRoundTrip(t *testing.T) {
	original := lanDiscoveryMessage{
		Protocol: lanDiscoveryProtocol, Response: "profile", Nonce: "nonce",
		ID: "gpu2", Name: "GPU 2", Capabilities: map[string]any{"accelerator": "cuda"},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded lanDiscoveryMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Protocol != original.Protocol || decoded.Response != original.Response || decoded.ID != original.ID || decoded.Capabilities["accelerator"] != "cuda" {
		t.Fatalf("LAN discovery message changed across JSON: %#v", decoded)
	}
}

func TestCloneMapDoesNotAliasProfile(t *testing.T) {
	original := map[string]any{"accelerator": "cuda"}
	clone := cloneMap(original)
	clone["accelerator"] = "cpu"
	if original["accelerator"] != "cuda" {
		t.Fatal("LAN profile clone aliases input map")
	}
}
