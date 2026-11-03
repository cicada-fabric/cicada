//go:build linux && cicada_scoped_app_integration

package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Consume the existing real TLS Hub/App SDK fixture and private PTY helper.
// Root owns this explicit host gate; ordinary package tests start no service.
func TestScopedAppActualNodeCLIFirstOnOffOn(t *testing.T) {
	binary := os.Getenv("CICADA_NODE_LIFECYCLE_CLI")
	if binary == "" || os.Getenv("CICADA_NODE_LIFECYCLE_SYSTEMD_ACCEPTANCE") != "1" {
		t.Skip("NOT_RUN: explicit CLI and isolated user-service acceptance required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("acceptance CLI must be an explicit absolute artifact")
	}
	f := newScopedAppHTTPFixture(t)
	home := filepath.Join(f.root, "SYNTHETIC-node-home")
	root := filepath.Join(home, ".cicada")
	state := filepath.Join(root, "state")
	for _, p := range []string{root, state, filepath.Join(root, "mcp"), filepath.Join(home, "tmp"), filepath.Join(home, "codex-unused")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal("synthetic private directory unavailable")
		}
	}
	id := "SYNTHETIC-scoped-first-on"
	environment := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "CODEX_HOME=" + filepath.Join(home, "codex-unused"), "TMPDIR=" + filepath.Join(home, "tmp"), "LANG=C.UTF-8"}
	for _, name := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value := os.Getenv(name); value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	agent := []string{"--user-root", root, "--id", id, "--name", "SYNTHETIC scoped first on", "--state-dir", state,
		"--hub-address", f.dial, "--relay-only", "--interval", "1s", "--mcp-session-state-file", filepath.Join(root, "mcp", "sessions.json"), "--mcp-outbox-state-file", filepath.Join(root, "mcp", "outbox.sqlite3")}
	firstOn := append([]string{"on", "--user-root", root, "--codex-bin", "/usr/bin/true", "--"}, agent...)
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = environment
		return command.CombinedOutput()
	}
	// The unchanged production ownership guard limits cleanup to this root's
	// exact transient unit. No resident installation or Codex process is used.
	t.Cleanup(func() {
		if _, err := os.Stat(filepath.Join(root, "node-service.json")); err == nil {
			raw, err := run("off", "--user-root", root)
			clear(raw)
			if err != nil {
				t.Error("owned synthetic user-service cleanup failed")
			}
		}
	})
	var foreground *exec.Cmd
	var ended chan error
	start := func() {
		log, err := os.OpenFile(filepath.Join(root, "foreground.private.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("private foreground log unavailable")
		}
		foreground = exec.Command(binary, append([]string{"machine", "agent"}, agent...)...)
		foreground.Env, foreground.Stdout, foreground.Stderr = environment, log, log
		if foreground.Start() != nil {
			log.Close()
			t.Fatal("actual Node CLI could not start")
		}
		ended = make(chan error, 1)
		go func(command *exec.Cmd, done chan error) { done <- command.Wait(); log.Close() }(foreground, ended)
	}
	stop := func() {
		if foreground == nil {
			return
		}
		_ = foreground.Process.Signal(os.Interrupt)
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			_ = foreground.Process.Kill()
			<-ended
			t.Error("actual foreground Node did not release its original locks")
		}
		foreground = nil
	}
	t.Cleanup(stop)
	start()
	awaitScopedLifecycle(t, func() bool {
		raw, _ := os.ReadFile(filepath.Join(root, "foreground.private.log"))
		defer clear(raw)
		return bytes.Contains(raw, []byte("Node pairing is pending; use machine pairing-code from a local interactive terminal."))
	}, "actual Node did not commit its original scoped pairing")
	code := scopedLifecyclePrivateCode(t, binary, id, state, root, environment)
	ticket, err := wire.DecodeNodePairTrustScopedCode(code, time.Now().UTC())
	if err != nil {
		t.Fatal("actual private code did not decode as current scoped pairing")
	}
	defer clear(ticket.OOBSecret)
	directory := filepath.Join(state, "nodes", "node-"+id)
	statePath := filepath.Join(directory, "node-control-state.json")
	keyPath, credentialPath := filepath.Join(directory, "node-control-identity.bin"), filepath.Join(directory, "relay.token")
	key, credential := scopedLifecycleDigest(t, keyPath), scopedLifecycleDigest(t, credentialPath)
	stop()
	before := scopedLifecycleDigest(t, statePath)
	raw, onErr := run(firstOn...)
	refused := onErr != nil && bytes.Contains(raw, []byte("NODE_SERVICE_PAIRING_NOT_READY"))
	clear(raw)
	if !refused {
		t.Fatal("first on did not refuse unfinished original local pairing precisely")
	}
	if _, err := os.Lstat(filepath.Join(root, "node-service.json")); !errors.Is(err, os.ErrNotExist) || before != scopedLifecycleDigest(t, statePath) {
		t.Fatal("unfinished pairing created configuration or changed Node state")
	}
	start()
	f.dispatch(Action{Kind: ActionReviewNodePairing, DevicePairingCode: code})
	review := f.c.Snapshot().Node.Pairing
	if review == nil || review.ReviewID == "" {
		t.Fatal("actual App did not review the original CLI code")
	}
	f.dispatch(Action{Kind: ActionApproveNodePairing, NodePairingReviewID: review.ReviewID, ConfirmNodePairing: true})
	var installed scopedLifecycleState
	awaitScopedLifecycle(t, func() bool {
		data, err := os.ReadFile(statePath)
		return err == nil && json.Unmarshal(data, &installed) == nil && installed.ready() && installed.Attempt == ticket.AttemptID
	}, "original Node did not apply its authenticated ACK locally")
	candidate := f.c.scoped.flow.Context.Candidate
	if candidate == nil || installed.NodeKey != candidate.NodePublic.ID || installed.NodeFingerprint != candidate.NodeKeyFingerprint || installed.HubKey != candidate.HubNodeControlPublic.ID || installed.HubFingerprint != candidate.HubNodeControlFingerprint || installed.Descriptor != f.descriptorText || installed.Dial != f.dial {
		t.Fatal("local ready coordinates differ from the original reviewed Node and Hub pins")
	}
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if p := f.c.Snapshot().Node.Pairing; p == nil || p.State != wire.NodePairTrustScopedACKed || p.NodeID != id || f.c.Snapshot().Node.Binding == nil || f.c.Snapshot().Node.Binding.ID != installed.Binding {
		t.Fatal("App ACK and actual local Node binding did not agree")
	}
	stop()
	var firstPID int
	for index, args := range [][]string{firstOn, {"status", "--user-root", root}, {"off", "--user-root", root}, {"on", "--user-root", root}, {"off", "--user-root", root}} {
		result, err := run(args...)
		var status struct {
			State string `json:"state"`
			Hub   string `json:"hub_online"`
			PID   int    `json:"main_pid"`
		}
		decodeErr := json.Unmarshal(bytes.TrimSpace(result), &status)
		errorCode := scopedLifecycleErrorCode(result)
		clear(result)
		want := "running"
		if args[0] == "off" {
			want = "stopped"
		}
		if err != nil || decodeErr != nil || status.State != want || status.Hub != "unknown" {
			t.Fatalf("actual owned user-service phase %d did not reach %s: code=%s", index, want, errorCode)
		}
		if index == 0 {
			firstPID = status.PID
		}
		if status.State == "running" && (status.PID <= 0 || status.PID == os.Getpid() || index == 1 && status.PID != firstPID || index == 3 && status.PID == firstPID) {
			t.Fatal("actual managed process identity or restart was not established")
		}
	}
	var after scopedLifecycleState
	data, err := os.ReadFile(statePath)
	if err != nil || json.Unmarshal(data, &after) != nil || after != installed || key != scopedLifecycleDigest(t, keyPath) || credential != scopedLifecycleDigest(t, credentialPath) {
		t.Fatal("actual lifecycle changed original binding, attempt, key or credential")
	}
	t.Log("SCOPED_FIRST_ON actual_CLI=true real_TLS_Hub=true production_App_SDK=true private_ACK_locally_applied=true actual_user_service_on_off_on=true original_identity_preserved=true native_Runtime_NOT_RUN=true")
}

type scopedLifecycleState struct {
	Binding         string `json:"binding_id"`
	Version         uint64 `json:"binding_version"`
	NodeKey         string `json:"node_key_id"`
	NodeFingerprint string `json:"node_key_fingerprint"`
	NodeVersion     uint64 `json:"node_key_version"`
	Epoch           uint64 `json:"node_key_epoch"`
	HubVersion      uint64 `json:"hub_key_version"`
	HubKey          string `json:"hub_key_id"`
	HubFingerprint  string `json:"hub_fingerprint"`
	Descriptor      string `json:"hub_transport_descriptor"`
	Dial            string `json:"hub_dial_address"`
	Attempt         string `json:"node_pair_trust_attempt_id"`
}

func (s scopedLifecycleState) ready() bool {
	return s.Binding != "" && s.Version != 0 && s.NodeKey != "" && s.NodeFingerprint != "" && s.NodeVersion != 0 && s.Epoch != 0 && s.HubVersion != 0 && s.HubKey != "" && s.HubFingerprint != "" && s.Descriptor != "" && s.Dial != ""
}

func awaitScopedLifecycle(t *testing.T, ready func() bool, failure string) {
	t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); {
		if ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(failure)
}

func scopedLifecycleDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("owned original fixture file unavailable")
	}
	defer clear(raw)
	return sha256.Sum256(raw)
}

// Keep service failures actionable without copying raw process output, paths,
// environment, configuration or any private protocol material into evidence.
func scopedLifecycleErrorCode(raw []byte) string {
	for _, field := range bytes.Fields(raw) {
		code := strings.TrimSuffix(string(field), ":")
		switch code {
		case "NODE_SERVICE_CONFIG_INVALID", "NODE_SERVICE_PAIRING_NOT_READY", "NODE_SERVICE_MANAGER_UNAVAILABLE", "NODE_SERVICE_CONFLICT", "NODE_SERVICE_FAILED", "NODE_SERVICE_BUSY":
			return code
		}
	}
	return "OTHER"
}

func scopedLifecyclePrivateCode(t *testing.T, binary, id, state, root string, environment []string) string {
	t.Helper()
	config, capture := filepath.Join(root, "pty.private.json"), filepath.Join(root, "terminal.private")
	raw, _ := json.Marshal(map[string]any{"argv": []string{binary, "machine", "pairing-code", "--id", id, "--state-dir", state}, "capture_path": capture, "timeout_seconds": 15})
	if os.WriteFile(config, raw, 0600) != nil {
		t.Fatal("private PTY configuration unavailable")
	}
	script, err := filepath.Abs("../../../scripts/fixtures/native-pair/node_pair_private_tty.py")
	if err != nil {
		t.Fatal("existing private PTY fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", script, config)
	command.Env = environment
	metadata, err := command.CombinedOutput()
	defer clear(metadata)
	if err != nil {
		t.Fatal("actual private pairing-code command failed")
	}
	terminal, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal("private PTY capture unavailable")
	}
	defer clear(terminal)
	code := ""
	for _, field := range bytes.Fields(terminal) {
		if strings.HasPrefix(string(field), wire.NodePairTrustScopedCodePrefix) {
			if code != "" {
				t.Fatal("ambiguous private pairing code")
			}
			code = string(field)
		}
	}
	if code == "" {
		t.Fatal("actual private pairing code missing")
	}
	return code
}
