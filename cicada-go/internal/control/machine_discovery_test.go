package control

import "testing"

func TestDiscoverLocalCapabilities(t *testing.T) {
	capabilities := discoverLocalCapabilities()
	for _, key := range []string{"os", "arch", "cpu_count", "memory_gb", "toolchains", "accelerator"} {
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
