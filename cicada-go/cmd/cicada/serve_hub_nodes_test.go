package main

import (
	"bytes"
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

	"github.com/cicada-ai/cicada/internal/control"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

const serveHubNodesChildEnv = "CICADA_TEST_SERVE_HUB_NODES_CHILD"

func TestServeHubNodesProcessChild(t *testing.T) {
	if os.Getenv(serveHubNodesChildEnv) != "1" {
		return
	}
	err := serve([]string{"--hub-nodes-only", "--host", "127.0.0.1", "--port", os.Getenv("CICADA_TEST_HUB_PORT"), "--state-dir", os.Getenv("CICADA_TEST_HUB_STATE")})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestServeHubNodesPureProcessAndBoundedDiscovery(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	workspace := filepath.Join(root, "workspace")
	if err := hubSetupCommand([]string{"--owner-label", "Synthetic Hub Nodes Owner", "--origin", "https://nodes.synthetic.invalid", "--public-config", filepath.Join(root, "connection.json"), "--state-dir", state}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	config := control.DefaultConfig()
	config.StateDir = state
	config.IdentityFile = ""
	before, err := existingHubNodeIdentities(config)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestServeHubNodesProcessChild$")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	cmd.Env = childTestEnvironment(map[string]string{serveHubNodesChildEnv: "1", "CICADA_TEST_HUB_PORT": strconv.Itoa(port), "CICADA_TEST_HUB_STATE": state, "CICADA_STATE_DIR": state, "CICADA_E2EE_IDENTITY_FILE": "", "CICADA_WORKSPACE_ROOT": workspace, "CICADA_API_TOKEN": "", "CICADA_HUB_NODE_PQTLS_CONFIG": ""})
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	defer func() {
		if !finished {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	client := &http.Client{Timeout: time.Second}
	ready := false
	end := time.Now().Add(30 * time.Second)
	for time.Now().Before(end) {
		response, e := client.Get(base + wire.AppNodeCapabilitiesPath)
		if e == nil {
			var raw bytes.Buffer
			_, _ = raw.ReadFrom(response.Body)
			response.Body.Close()
			caps, decodeErr := wire.DecodeAppNodeCapabilities(raw.Bytes())
			if response.StatusCode == 200 && decodeErr == nil && caps.Available {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Hub Nodes child did not become ready")
	}
	for _, path := range []string{"/v1/status", "/v1/workers", "/v2/client/devices/enroll", "/v2/node/control/key-upgrade"} {
		response, e := client.Post(base+path, "application/json", strings.NewReader(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("unexpected business surface", path, response.StatusCode)
		}
	}
	if _, err = os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatal("Hub Nodes created Control workspace", err)
	}
	if _, err = os.Stat(filepath.Join(state, "workspace-snapshots")); !os.IsNotExist(err) {
		t.Fatal("Hub Nodes created snapshot runtime", err)
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		t.Fatal("Hub Nodes shutdown failed", err)
	}
	finished = true
	after, err := existingHubNodeIdentities(config)
	if err != nil {
		t.Fatal(err)
	}
	if before.Peer.Public().ID != after.Peer.Public().ID || before.ClientControl.Public().ID != after.ClientControl.Public().ID || before.NodeControl.Public().ID != after.NodeControl.Public().ID {
		t.Fatal("serve replaced retained identities")
	}
	db, err := store.New(filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	machines, err := db.ListMachines()
	if err != nil || len(machines) != 0 {
		t.Fatal("Hub Nodes registered a local business Machine", err)
	}
}

func TestServeHubNodesRejectsMissingRetainedIdentityAndMixedModes(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := hubSetupCommand([]string{"--owner-label", "Synthetic retained Hub Nodes Owner", "--origin", "https://retained.nodes.synthetic.invalid", "--public-config", filepath.Join(root, "connection.json"), "--state-dir", state}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	config := control.DefaultConfig()
	config.StateDir = state
	config.IdentityFile = ""
	path := filepath.Join(state, "e2ee", "node-control-identity.json")
	held := path + ".synthetic-retained"
	if err := os.Rename(path, held); err != nil {
		t.Fatal(err)
	}
	if _, err := existingHubNodeIdentities(config); err == nil {
		t.Fatal("missing Node identity was accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing identity was regenerated", err)
	}
	for _, extra := range []string{"--hub-only", "--fabric-only", "--node-pqtls-config=synthetic-config"} {
		if err := serve([]string{"--hub-nodes-only", extra, "--state-dir", state}); err == nil {
			t.Fatal("mixed or strict-listener mode silently downgraded", extra)
		}
	}
}
