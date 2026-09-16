package main

import (
	"testing"
	"time"
)

func TestNormalizeControlURL(t *testing.T) {
	if got, err := normalizeControlURL(" https://control.example/ "); err != nil || got != "https://control.example" {
		t.Fatalf("normalized URL=%q err=%v", got, err)
	}
	for _, raw := range []string{"control.example", "https://user:pass@control.example", "https://control.example/api"} {
		if _, err := normalizeControlURL(raw); err == nil {
			t.Fatalf("unsafe Control URL was accepted: %q", raw)
		}
	}
}

func TestMachineAgentInterval(t *testing.T) {
	t.Setenv("CICADA_MACHINE_HEARTBEAT_SECONDS", "")
	if got := machineAgentInterval(); got != 30*time.Second {
		t.Fatalf("default interval=%s", got)
	}
}
