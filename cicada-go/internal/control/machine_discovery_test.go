package control

import (
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestDiscoverLocalCapabilities(t *testing.T) {
	capabilities := discoverLocalCapabilities()
	for _, key := range []string{"os", "arch", "cpu_count", "memory_gb", "load_1m", "toolchains", "containers", "compilers", "disk", "network", "accelerator"} {
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

func TestLocalDiskAndNetworkDoNotExposeAddresses(t *testing.T) {
	disk := localDisk("/")
	if _, ok := disk["free_gb"]; !ok {
		t.Fatalf("disk free space was not discovered: %#v", disk)
	}
	network := localNetwork()
	interfaces, ok := network["interfaces"].([]string)
	if !ok {
		t.Fatalf("network interfaces have an unexpected type: %#v", network)
	}
	for _, name := range interfaces {
		if strings.Contains(name, ".") {
			t.Fatalf("network profile should contain interface names only: %q", name)
		}
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

func TestMachineProfileConstraints(t *testing.T) {
	machine := store.Machine{Capabilities: map[string]any{
		"disk":       map[string]any{"free_gb": 120.0},
		"toolchains": map[string]any{"go": "/usr/bin/go", "git": "/usr/bin/git"},
		"containers": map[string]any{"docker": "/usr/bin/docker"},
		"network":    map[string]any{"online": true},
	}}
	if !machineMatches(machine, map[string]any{"min_disk_free_gb": 100, "required_toolchains": []any{"go", "git"}, "required_container": "docker", "network_required": true}) {
		t.Fatal("machine profile constraints rejected a matching machine")
	}
	if machineMatches(machine, map[string]any{"min_disk_free_gb": 200}) {
		t.Fatal("machine below disk constraint was accepted")
	}
	if machineMatches(machine, map[string]any{"required_toolchains": []any{"python3"}}) {
		t.Fatal("machine missing a toolchain was accepted")
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

func TestParseROCmModels(t *testing.T) {
	models := parseROCmModels("Name:                    gfx1100\nName:                    gfx1100\nName:                    cpu\n")
	if len(models) != 1 || models[0] != "gfx1100" {
		t.Fatalf("unexpected ROCm models: %#v", models)
	}
}

func TestParseAscendOutput(t *testing.T) {
	models, memoryGB := parseAscendOutput("| 910B | Memory Capacity(MB) 32768 |\n| 910B |\n")
	if len(models) != 1 || models[0] != "910B" || memoryGB <= 31 {
		t.Fatalf("unexpected Ascend profile: models=%#v memory_gb=%v", models, memoryGB)
	}
}
