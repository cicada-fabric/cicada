package control

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func discoverLocalCapabilities() map[string]any {
	capabilities := map[string]any{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpu_count":  runtime.NumCPU(),
		"memory_gb":  localMemoryGB(),
		"toolchains": localToolchains(),
	}
	if name, models, memoryGB, ok := discoverNVIDIA(); ok {
		capabilities["accelerator"] = "cuda"
		capabilities["gpu_name"] = name
		capabilities["gpu_models"] = models
		capabilities["gpu_memory_gb"] = memoryGB
	} else {
		capabilities["accelerator"] = "cpu"
	}
	return capabilities
}

func cloneCapabilities(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source)+1)
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func localMemoryGB() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kilobytes, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0
		}
		return kilobytes / (1024 * 1024)
	}
	return 0
}

func localToolchains() map[string]any {
	result := map[string]any{}
	for _, name := range []string{"codex", "git", "python3", "go", "node", "nvidia-smi"} {
		path, err := exec.LookPath(name)
		if err == nil {
			result[name] = path
		}
	}
	return result
}

func discoverNVIDIA() (string, []string, float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return "", nil, 0, false
	}
	models, memoryGB := parseNVIDIAOutput(string(output))
	if len(models) == 0 {
		return "", nil, 0, false
	}
	return models[0], models, memoryGB, true
}

func parseNVIDIAOutput(output string) ([]string, float64) {
	var models []string
	var totalMemory float64
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		memory, err := strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
		if name == "" || err != nil {
			continue
		}
		models = append(models, name)
		totalMemory += memory / 1024
	}
	return models, totalMemory
}
