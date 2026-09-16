package main

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func discoveredMachineHarnesses() []string {
	harnesses := []string{"shell"}
	if _, err := exec.LookPath(envOr("CICADA_CODEX_BIN", "codex")); err == nil {
		harnesses = append(harnesses, "codex")
	}
	return harnesses
}

func machineShellArgv(value any) ([]string, error) {
	values, ok := value.([]any)
	if !ok {
		if stringsValue, stringsOK := value.([]string); stringsOK {
			values = make([]any, len(stringsValue))
			for index, item := range stringsValue {
				values[index] = item
			}
			ok = true
		}
	}
	if !ok {
		return nil, errors.New("shell harness requires resources.argv as a string array")
	}
	if len(values) == 0 || len(values) > 128 {
		return nil, errors.New("shell harness argv must contain 1-128 items")
	}
	argv := make([]string, len(values))
	for i, value := range values {
		item, ok := value.(string)
		if !ok || strings.TrimSpace(item) == "" || len(item) > 4096 {
			return nil, errors.New("shell harness argv items must be non-empty strings under 4 KiB")
		}
		argv[i] = item
	}
	return argv, nil
}

type machineBoundedOutput struct {
	mu        sync.Mutex
	data      bytes.Buffer
	limit     int
	truncated bool
}

func (b *machineBoundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.data.Len()
	if remaining > 0 {
		if len(p) > remaining {
			b.data.Write(p[:remaining])
			b.truncated = true
		} else {
			b.data.Write(p)
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *machineBoundedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

func machineJobTimeout() time.Duration {
	seconds := envInt("CICADA_WORKER_TIMEOUT_SECONDS", 1800)
	if seconds < 1 {
		seconds = 1800
	}
	return time.Duration(seconds) * time.Second
}

func machineWorkerEnvironment(environment []string, allowModelSecrets bool) []string {
	blocked := map[string]bool{
		"CICADA_API_TOKEN":        true,
		"CICADA_PEER_RELAY_TOKEN": true, "CICADA_WEBHOOK_SECRET": true,
	}
	if !allowModelSecrets {
		blocked["API_KEY"] = true
		blocked["OPENAI_API_KEY"] = true
	}
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if ok && !blocked[name] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
