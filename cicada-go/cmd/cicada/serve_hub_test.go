package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const serveHubOnlyChildEnv = "CICADA_TEST_SERVE_HUB_ONLY_CHILD"

func TestServeHubOnlyProcessChild(t *testing.T) {
	if os.Getenv(serveHubOnlyChildEnv) != "1" {
		return
	}
	err := serve([]string{"--hub-only", "--host", os.Getenv("CICADA_TEST_HUB_HOST"), "--port", os.Getenv("CICADA_TEST_HUB_PORT"), "--state-dir", os.Getenv("CICADA_TEST_HUB_STATE")})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestServeHubOnlySkipsControlWorkspaceAndMachineStartup(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	workspaceRoot := filepath.Join(root, "workspace")
	if err := hubSetupCommand([]string{"--owner-label", "Synthetic account owner", "--origin", "https://hub.synthetic.invalid",
		"--public-config", filepath.Join(root, "connection.json"), "--state-dir", stateDir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestServeHubOnlyProcessChild$")
	var childOutput bytes.Buffer
	cmd.Stdout, cmd.Stderr = &childOutput, &childOutput
	cmd.Env = childTestEnvironment(map[string]string{
		serveHubOnlyChildEnv:           "1",
		"CICADA_TEST_HUB_HOST":         "127.0.0.1",
		"CICADA_TEST_HUB_PORT":         strconv.Itoa(port),
		"CICADA_TEST_HUB_STATE":        stateDir,
		"CICADA_STATE_DIR":             stateDir,
		"CICADA_WORKSPACE_ROOT":        workspaceRoot,
		"CICADA_API_TOKEN":             "",
		"CICADA_HUB_NODE_PQTLS_CONFIG": "",
	})
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	defer func() {
		if !finished && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	client := &http.Client{Timeout: 300 * time.Millisecond}
	deadline := time.Now().Add(8 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, requestErr := client.Get(baseURL + "/healthz")
		if requestErr == nil {
			var health struct {
				Service string `json:"service"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&health)
			_ = response.Body.Close()
			if decodeErr == nil && response.StatusCode == http.StatusOK && health.Service == "cicada-hub" {
				ready = true
				break
			}
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Hub-only process did not become ready: %s", childOutput.String())
	}
	response, err := client.Post(baseURL+"/v2/client/rpc", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Hub-only Client management status=%d, want unavailable without Control", response.StatusCode)
	}
	if _, err = os.Stat(workspaceRoot); !os.IsNotExist(err) {
		t.Fatalf("Hub-only serve created Control's workspace root: %v", err)
	}
	if _, err = os.Stat(filepath.Join(stateDir, "workspace-snapshots")); !os.IsNotExist(err) {
		t.Fatalf("Hub-only serve created Control's snapshot store: %v", err)
	}

	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		t.Fatalf("Hub-only process shutdown failed: %v; output=%s", err, childOutput.String())
	}
	finished = true
	db, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	machines, err := db.ListMachines()
	if err != nil || len(machines) != 0 {
		t.Fatalf("Hub-only serve registered a business Machine: count=%d err=%v", len(machines), err)
	}
}

func childTestEnvironment(overrides map[string]string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replace := overrides[key]; !replace {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}
