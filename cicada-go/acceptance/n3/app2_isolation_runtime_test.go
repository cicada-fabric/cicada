package n3_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func awaitApp2File(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal("owned App2 checkpoint unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("owned App2 checkpoint deadline exceeded")
}

// This verifies the container adapter, TCP namespace and an actual empty App
// Controller. It never supplies or simulates Hub registration/permission state.
func TestN3HarnessApp2ContainerIsolation(t *testing.T) {
	if os.Getenv("CICADA_N3_REQUIRE_APP2") != "1" {
		t.Skip("owned App2 isolation is an explicitly selected harness gate")
	}
	if os.Getenv("CICADA_N3_APP2_CONTROL") != "/state/app2-control" {
		t.Fatal("explicit task-owned host App2 supervisor is required")
	}
	const control, own = "/state/app2-control", "/state/app2"
	for _, path := range []string{filepath.Join(own, "profile"), filepath.Join(own, "io")} {
		if os.MkdirAll(path, 0700) != nil {
			t.Fatal("App2 private fixture directory unavailable")
		}
	}
	canary := filepath.Join(t.TempDir(), "synthetic-app1-private-canary")
	private := []byte("SYNTHETIC APP1 PRIVATE CANARY; NOT AN OWNER KEY")
	atomicPrivate(t, canary, private)
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		t.Fatal("owned fixture probe cannot be generated")
	}
	defer clear(probe)
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	defer listener.Close()
	served := make(chan bool, 1)
	go func(payload []byte) {
		defer clear(payload)
		conn, err := listener.Accept()
		if err != nil {
			served <- false
			return
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Write(payload)
		served <- err == nil && n == len(payload)
	}(bytes.Clone(probe))
	id := hex.EncodeToString(probe[:16])
	denied := []string{canary, "/var/run/docker.sock", "/repo", "/out/cicada"}
	writeJSON(t, filepath.Join(own, "io", "start.json"), app2Input{RequestID: id,
		ProbeAddress: listener.Addr().String(), ProbeSHA256: hash(probe), ForbiddenPaths: denied})
	writeJSON(t, filepath.Join(control, "request.json"), map[string]string{"request_id": id})
	t.Cleanup(func() {
		// This private host-control path is never mounted in App2.
		if _, err := os.Stat(filepath.Join(control, "stop")); os.IsNotExist(err) {
			atomicPrivate(t, filepath.Join(control, "stop"), []byte("owned fixture stop\n"))
		}
	})
	awaitApp2File(t, filepath.Join(control, "started.json"))
	var started struct {
		OK bool `json:"ok"`
	}
	readJSON(t, filepath.Join(control, "started.json"), &started)
	if !started.OK {
		t.Fatal("host did not verify actual App2 container isolation")
	}
	awaitApp2File(t, filepath.Join(own, "io", "ready.json"))
	var ready app2Ready
	readJSON(t, filepath.Join(own, "io", "ready.json"), &ready)
	binary := must(os.ReadFile(must(os.Executable())))
	defer clear(binary)
	if ready.RequestID != id || !ready.ProbeVerified || ready.BinarySHA256 != hash(binary) ||
		!reflect.DeepEqual(ready.DeniedPaths, denied) || len(ready.Current.Profiles) != 0 ||
		ready.Current.Account.LocalOwnerKeyPresent || ready.Current.Authorization.Confirmed {
		t.Fatal("actual App2 did not prove its own empty profile/network/binary and denied paths")
	}
	select {
	case ok := <-served:
		if !ok {
			t.Fatal("fixture network probe did not complete")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture network probe was not observed")
	}
	if !bytes.Equal(readPrivate(t, canary), private) {
		t.Fatal("App1 private canary changed")
	}
	writeJSON(t, filepath.Join(own, "io", "command-1.json"), app2Command{Stop: true})
	awaitApp2File(t, filepath.Join(control, "exited.json"))
	var exited struct {
		OK bool `json:"ok"`
	}
	readJSON(t, filepath.Join(control, "exited.json"), &exited)
	if !exited.OK {
		t.Fatal("actual isolated App2 did not exit successfully and cleanly")
	}
	t.Log("APP2_HARNESS_ONLY actual_empty_App_Core=true separate_PID_mount_IPC=true owned_TCP_probe=true App1_state_unreadable=true registration_NOT_RUN=true INST05_NOT_RUN=true")
}
