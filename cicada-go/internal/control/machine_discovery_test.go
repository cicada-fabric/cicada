package control

import (
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestDiscoverLocalCapabilities(t *testing.T) {
	capabilities := discoverLocalCapabilities()
	for _, key := range []string{"os", "arch", "cpu_count", "memory_gb", "load_1m", "toolchains", "accelerator"} {
		if _, ok := capabilities[key]; !ok {
			t.Fatalf("local capability %q is missing: %#v", key, capabilities)
		}
	}
	if capabilities["os"] != "linux" && capabilities["os"] != "darwin" && capabilities["os"] != "windows" {
		t.Fatalf("unexpected local OS: %#v", capabilities["os"])
	}
	if capabilities["cpu_count"].(int) < 1 {
		t.Fatalf("CPU count was not discovered: %#v", capabilities["cpu_count"])
	}
}

func TestMachineLoadConstraint(t *testing.T) {
	machine := store.Machine{Capabilities: map[string]any{"load_1m": 1.5}}
	if !machineMatches(machine, map[string]any{"max_load_1m": 2}) {
		t.Fatal("machine below load limit was rejected")
	}
	if machineMatches(machine, map[string]any{"max_load_1m": 1}) {
		t.Fatal("machine above load limit was accepted")
	}
}

func TestParseNVIDIAOutput(t *testing.T) {
	models, memoryGB := parseNVIDIAOutput("NVIDIA H100, 81920\nNVIDIA H100, 81920\n")
	if len(models) != 2 || models[0] != "NVIDIA H100" || memoryGB != 160 {
		t.Fatalf("unexpected NVIDIA capabilities: models=%#v memory=%v", models, memoryGB)
	}
	models, memoryGB = parseNVIDIAOutput("not a GPU\n")
	if len(models) != 0 || memoryGB != 0 {
		t.Fatalf("invalid NVIDIA output was accepted: models=%#v memory=%v", models, memoryGB)
	}
}
