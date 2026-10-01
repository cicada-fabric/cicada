//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

func TestMachineNodeResourceStopUnverifiedBlocksAfterSetsidEscape(t *testing.T) {
	stateRoot := t.TempDir()
	manager, err := nodelock.OpenResourceExecutionManager(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(t.TempDir(), "escaped.pid")
	t.Cleanup(func() {
		pidData, err := os.ReadFile(pidPath)
		if err == nil {
			if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidData))); parseErr == nil && pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	ctx := withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-resource-stop-test", NodeID: "node-resource-stop-test",
		WriterRoot: stateRoot, ResourceExecutions: manager,
	})
	job := machineJob{WorkerID: "worker-resource-stop-test", Attempt: 1,
		MachineID: "node-resource-stop-test", executionID: "execution-resource-stop-test",
		providerID: "codex", resourceID: "gpu/9", leaseID: "lease-resource-stop-test", fencingEpoch: 1}
	command := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestMachineNodeResourceStopEscapeHelper$")
	command.Env = append(os.Environ(), "CICADA_RESOURCE_STOP_HELPER_MODE=root",
		"CICADA_RESOURCE_STOP_HELPER_PID="+pidPath)
	runErr, stopErr, started := runMachineNodeResourceCommand(ctx, job, command)
	if !started || runErr != nil || !errors.Is(stopErr, nodelock.ErrResourceStopUnverified) {
		t.Fatalf("escaped descendant result: started=%v runErr=%v stopErr=%v", started, runErr, stopErr)
	}
	var pidData []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pidData, err = os.ReadFile(pidPath)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("escaped descendant did not report its PID: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 0 {
		t.Fatalf("escaped descendant PID is invalid: %q err=%v", pidData, err)
	}
	if !machineResourceTestProcessRunning(pid) {
		t.Fatal("setsid descendant unexpectedly disappeared when the original process group was drained")
	}
	record, err := manager.Inspect(job.resourceID)
	if err != nil || record == nil || record.State != nodelock.ResourceExecutionQuarantined ||
		record.Outcome != "resource_stop_unverified" {
		t.Fatalf("escaped descendant resource record = %#v err=%v", record, err)
	}
	if _, err := manager.Begin(nodelock.ResourceExecutionRequest{ResourceID: job.resourceID,
		LeaseID: "later-lease", FencingEpoch: 2, ExecutionID: "later-execution"}); !errors.Is(err, nodelock.ErrResourceExecutionBusy) {
		t.Fatalf("a higher epoch acquired a resource with a live setsid descendant: %v", err)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && machineResourceTestProcessRunning(pid) {
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMachineNodeResourceStopEscapeHelper(t *testing.T) {
	switch os.Getenv("CICADA_RESOURCE_STOP_HELPER_MODE") {
	case "root":
		pidPath := os.Getenv("CICADA_RESOURCE_STOP_HELPER_PID")
		child := exec.Command(os.Args[0], "-test.run=^TestMachineNodeResourceStopEscapeHelper$")
		child.Env = append(os.Environ(), "CICADA_RESOURCE_STOP_HELPER_MODE=child",
			"CICADA_RESOURCE_STOP_HELPER_PID="+pidPath)
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		_ = child.Process.Release()
	case "child":
		if err := os.WriteFile(os.Getenv("CICADA_RESOURCE_STOP_HELPER_PID"),
			[]byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			os.Exit(31)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
}

func machineResourceTestProcessRunning(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	closing := strings.LastIndexByte(string(data), ')')
	return closing >= 0 && closing+2 < len(data) && data[closing+2] != 'Z'
}
