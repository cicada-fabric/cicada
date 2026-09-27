package control

import (
	"context"
	"net"
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
		"load_1m":    localLoad1m(),
		"toolchains": localToolchains(),
		"containers": localCommands("docker", "podman", "containerd"),
		"compilers":  localCommands("gcc", "clang", "nvcc"),
		"disk":       localDisk("/"),
		"network":    localNetwork(),
	}
	if name, models, memoryGB, ok := discoverNVIDIA(); ok {
		capabilities["accelerator"] = "cuda"
		capabilities["gpu_name"] = name
		capabilities["gpu_models"] = models
		capabilities["gpu_memory_gb"] = memoryGB
	} else if name, models, memoryGB, ok := discoverROCm(); ok {
		capabilities["accelerator"] = "rocm"
		capabilities["gpu_name"] = name
		capabilities["gpu_models"] = models
		capabilities["gpu_memory_gb"] = memoryGB
	} else if name, models, memoryGB, ok := discoverAscend(); ok {
		capabilities["accelerator"] = "cann"
		capabilities["npu_name"] = name
		capabilities["npu_models"] = models
		capabilities["npu_memory_gb"] = memoryGB
	} else {
		capabilities["accelerator"] = "cpu"
	}
	return capabilities
}

// DiscoverMachineCapabilities returns a fresh, non-secret capability profile
// suitable for a remote machine heartbeat.
func DiscoverMachineCapabilities() map[string]any {
	return discoverLocalCapabilities()
}

func localLoad1m() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return load
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

func localCommands(names ...string) map[string]any {
	result := map[string]any{}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			result[name] = path
		}
	}
	return result
}

func localDisk(path string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "df", "-Pk", path).Output()
	if err != nil {
		return map[string]any{}
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return map[string]any{}
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 5 {
		return map[string]any{}
	}
	total, totalErr := strconv.ParseFloat(fields[1], 64)
	free, freeErr := strconv.ParseFloat(fields[3], 64)
	if totalErr != nil || freeErr != nil {
		return map[string]any{}
	}
	return map[string]any{
		"mount": path, "total_gb": total / (1024 * 1024), "free_gb": free / (1024 * 1024),
	}
}

func localNetwork() map[string]any {
	interfaces, err := net.Interfaces()
	if err != nil {
		return map[string]any{"online": false, "interfaces": []string{}}
	}
	names := make([]string, 0, len(interfaces))
	online := false
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		names = append(names, iface.Name)
		if iface.Flags&net.FlagUp != 0 {
			online = true
		}
	}
	return map[string]any{"online": online, "interfaces": names}
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

func discoverROCm() (string, []string, float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exec.LookPath("rocminfo"); err != nil {
		return "", nil, 0, false
	}
	output, err := exec.CommandContext(ctx, "rocminfo").Output()
	if err != nil {
		return "", nil, 0, false
	}
	models := parseROCmModels(string(output))
	if len(models) == 0 {
		return "", nil, 0, false
	}
	return models[0], models, 0, true
}

func parseROCmModels(output string) []string {
	models := make([]string, 0, 2)
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Name:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		if name == "" || seen[name] || strings.Contains(strings.ToLower(name), "cpu") {
			continue
		}
		seen[name] = true
		models = append(models, name)
	}
	return models
}

func discoverAscend() (string, []string, float64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exec.LookPath("npu-smi"); err != nil {
		return "", nil, 0, false
	}
	output, err := exec.CommandContext(ctx, "npu-smi", "info").Output()
	if err != nil {
		return "", nil, 0, false
	}
	models, memoryGB := parseAscendOutput(string(output))
	if len(models) == 0 {
		return "", nil, 0, false
	}
	return models[0], models, memoryGB, true
}

func parseAscendOutput(output string) ([]string, float64) {
	models := make([]string, 0, 2)
	seen := map[string]bool{}
	var memoryGB float64
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "910") || strings.Contains(lower, "310") || strings.Contains(lower, "910b") {
			fields := strings.Fields(line)
			for _, field := range fields {
				field = strings.Trim(field, "|,[]")
				if strings.Contains(field, "910") || strings.Contains(field, "310") {
					if !seen[field] {
						seen[field] = true
						models = append(models, field)
					}
					break
				}
			}
		}
		if strings.Contains(lower, "memory capacity") {
			fields := strings.Fields(strings.ReplaceAll(line, "|", " "))
			for _, field := range fields {
				if value, err := strconv.ParseFloat(strings.TrimSuffix(field, "MB"), 64); err == nil && value > 0 {
					memoryGB = value / 1024
					break
				}
			}
		}
	}
	return models, memoryGB
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
