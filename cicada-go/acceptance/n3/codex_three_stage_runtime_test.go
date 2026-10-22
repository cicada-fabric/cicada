package n3_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// One bounded actual-daemon gate. Existing Node approval is a fixture
// precondition; the measured installation/connection stages cannot enroll it.
func TestN3CodexProductThreeStagePersistentDaemon(t *testing.T) {
	v := newCodexProductFixture(t, "1s")
	t.Cleanup(func() { retainColdCLIDiagnostics(t, v) })
	v.actualNode.kill(t)
	originalNode := readPrivate(t, v.actualNode.statePath())
	defer clear(originalNode)
	prefix := filepath.Join(v.root, "selected-root")
	if os.Mkdir(prefix, 0755) != nil || os.Chmod(prefix, 0755) != nil {
		t.Fatal("owned existing root unavailable")
	}
	canary := filepath.Join(prefix, "existing-user-file.txt")
	atomicPrivate(t, canary, []byte("SYNTHETIC existing selected root; preserve original data\n"))
	canaryHash := hash(readPrivate(t, canary))
	checkRoot := func() {
		t.Helper()
		if must(os.Stat(prefix)).Mode().Perm() != 0755 || hash(readPrivate(t, canary)) != canaryHash {
			t.Fatal("installation/connection changed the existing root mode or canary")
		}
	}
	control := filepath.Join(v.root, "three-stage-control")
	config, result := filepath.Join(v.root, "private-three-stage-config.json"), filepath.Join(v.root, "private-three-stage-result.json")
	var clientEnvironment []string
	for _, value := range v.environment {
		name := strings.SplitN(value, "=", 2)[0]
		if strings.HasPrefix(name, "CICADA_") || name == "PATH" {
			continue
		}
		clientEnvironment = append(clientEnvironment, value)
	}
	clientEnvironment = append(clientEnvironment, "PATH=/usr/local/bin:/usr/bin:/bin")
	writeJSON(t, config, map[string]any{"root": v.root, "workspace": v.workspace, "codex_home": v.codexHome,
		"environment": clientEnvironment, "codex_binary": "/tools/codex-package/bin/codex",
		"codex_sha256": "399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215",
		"marketplace":  "/repo", "step": "three-stage", "persistent_daemon": true, "allow_test_termination": true,
		"control": control, "result": result, "require_unique_literal_titles": true, "selected_root": prefix})
	log := must(os.OpenFile(filepath.Join(v.root, "private-three-stage.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/codex_three_stage.py", config)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = clientEnvironment, v.workspace, log, log
	client := startProcess(t, cmd)
	awaitStep := func(step int) map[string]json.RawMessage {
		t.Helper()
		path := filepath.Join(control, strconv.Itoa(step)+".reply.json")
		deadline := time.Now().Add(85 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				var reply map[string]json.RawMessage
				readJSON(t, path, &reply)
				if string(reply["status"]) != `"SCOPED_PASS"` {
					t.Fatal("three-stage child checkpoint refused")
				}
				checkRoot()
				return reply
			}
			if !client.running() {
				var failure struct {
					Failure string `json:"failure_category"`
				}
				if _, err := os.Stat(result); err == nil {
					readJSON(t, result, &failure)
				}
				t.Fatalf("actual persistent daemon driver exited: %s", failure.Failure)
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("actual persistent daemon checkpoint timeout")
		return nil
	}
	sendStep := func(step int, values map[string]any) {
		writeJSON(t, filepath.Join(control, strconv.Itoa(step)+".command.json"), values)
	}
	awaitStep(0) // Actual original daemon is already running before installation.
	if v.actualNode.running() || hash(readPrivate(t, v.actualNode.statePath())) != hash(originalNode) {
		t.Fatal("old-plugin setup started or altered the stopped original Node")
	}
	assetPaths := []string{".agents/plugins/cicada/.codex-plugin/plugin.json", ".agents/plugins/cicada/.mcp.json", ".agents/plugins/cicada/hooks/hooks.json", ".agents/plugins/cicada/skills/cicada-network/SKILL.md", ".agents/plugins/marketplace.json"}
	rows := make([][]string, 0, len(assetPaths))
	for _, path := range assetPaths {
		rows = append(rows, []string{path, hash(readPrivate(t, filepath.Join("/repo", path)))})
	}
	assets := must(json.Marshal(map[string]any{"files": rows, "format": "cicada.codex-plugin-assets.v1"}))
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	install := exec.Command(binary, "components", "install", "--prefix", prefix, "--components", "node", "--binary", binary,
		"--sha256", hash(readPrivateBinary(t, binary)), "--licenses", "/licenses", "--codex-plugin-assets", "/repo", "--codex-plugin-sha256", hash(assets))
	install.Env, install.Stdout, install.Stderr = clientEnvironment, log, log
	if err := install.Run(); err != nil {
		t.Fatal("actual file-only component installation failed")
	}
	checkRoot()
	if v.actualNode.running() || hash(readPrivate(t, v.actualNode.statePath())) != hash(originalNode) {
		t.Fatal("file-only installation started or changed the original Node")
	}
	installed := filepath.Join(prefix, "components/node/bin/cicada")
	if hash(readPrivateBinary(t, installed)) != hash(readPrivateBinary(t, binary)) {
		t.Fatal("installed executable differs from the actual tested CLI")
	}
	sendStep(1, map[string]any{"marketplace": filepath.Join(prefix, "components/node/share/codex")})
	awaitStep(1)
	if v.actualNode.running() || hash(readPrivate(t, v.actualNode.statePath())) != hash(originalNode) {
		t.Fatal("plugin connection auto-started or changed the stopped original Node")
	}
	outbox := filepath.Join(filepath.Dir(v.mcpState), "outbox.sqlite3")
	startNode := func() {
		t.Helper()
		id, state := v.actualNode.id, v.actualNode.state
		nodeLog := must(os.OpenFile(filepath.Join(state, "private-process.log"), os.O_APPEND|os.O_WRONLY, 0600))
		t.Cleanup(func() { nodeLog.Close() })
		process := exec.Command(installed, "machine", "agent", "--relay-only", "--id", id, "--name", id, "--control-url", v.f.cfg.Origin,
			"--state-dir", state, "--interval", "1s", "--user-root", prefix,
			"--mcp-session-state-file", v.mcpState, "--mcp-outbox-state-file", outbox)
		process.Env, process.Stdout, process.Stderr = v.environment, nodeLog, nodeLog
		v.actualNode = &nodeProcess{process: startProcess(t, process), id: id, state: state}
		bound := v.actualNode.awaitState(t, v.f, true)
		if bound.BindingID != v.bound.BindingID || bound.BindingVersion != v.bound.BindingVersion || bound.NodeKeyEpoch != v.bound.NodeKeyEpoch || bound.NodeKeyID != v.bound.NodeKeyID || bound.NodeFingerprint != v.bound.NodeFingerprint {
			t.Fatal("explicit Node start replaced its approved original binding/key")
		}
	}
	startNode()
	pin, instance := threeStageLivePin(t, v, prefix, outbox, "")
	sendStep(2, nil)
	connected := awaitStep(2)
	var sid string
	if json.Unmarshal(connected["native_session_id"], &sid) != nil || sid == "" {
		t.Fatal("actual registered native Thread missing")
	}
	v.requireOwnerDirectory(t, map[string]string{"Synthetic installed-plugin Thread": "offline"})
	v.actualNode.kill(t)
	stoppedNodeHash := hash(readPrivate(t, v.actualNode.statePath()))
	sendStep(3, nil)
	awaitStep(3)
	if v.actualNode.running() || hash(readPrivate(t, v.actualNode.statePath())) != stoppedNodeHash {
		t.Fatal("offline consumer auto-started or modified the Node")
	}
	startNode()
	restartedPin, _ := threeStageLivePin(t, v, prefix, outbox, instance)
	if string(restartedPin) != string(pin) {
		t.Fatal("Node restart changed its original complete public connection pin")
	}
	sendStep(4, nil)
	awaitStep(4)
	select {
	case <-client.done:
	case <-time.After(20 * time.Second):
		t.Fatal("persistent daemon client cleanup timeout")
	}
	var final struct {
		Status string `json:"status"`
		SID    string `json:"native_session_id"`
	}
	readJSON(t, result, &final)
	if client.cmd.ProcessState.ExitCode() != 0 || final.Status != "SCOPED_PASS" || final.SID != sid {
		t.Fatal("actual persistent daemon gate failed")
	}
	checkRoot()
	t.Log("THREE_STAGE_PASS original_persistent_Codex_daemon=true daemon_env5_absent=true installed_old_same_plugin_updated=true normal_Hook_trust=true existing_root0755_and_canary_retained=true Node_absent_and_stop_refuse=true explicit_original_Node_restart=true same_complete_pin=true actual_MCP_and_literal_Hook=true provider_posts=0 Pair_cold_model_queue_Windows=NOT_RUN")
}

// The actual original socket supplies only a public discovery description.
// Parent evidence reads never create an identity, credential or business grant.
func threeStageLivePin(t *testing.T, v *codexProductFixture, root, outbox, oldInstance string) (json.RawMessage, string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		paths := must(filepath.Glob(filepath.Join(root, "run/nodes/*.json")))
		if len(paths) == 1 {
			var locator struct {
				Instance string `json:"instance_id"`
				Socket   string `json:"socket_path"`
			}
			raw := readPrivate(t, paths[0])
			if json.Unmarshal(raw, &locator) == nil && locator.Instance != "" && locator.Instance != oldInstance {
				connection, err := net.DialTimeout("unix", locator.Socket, time.Second)
				if err == nil {
					_ = connection.SetDeadline(time.Now().Add(time.Second))
					var nonce [32]byte
					if _, err = rand.Read(nonce[:]); err != nil {
						t.Fatal("discovery nonce unavailable")
					}
					n := hex.EncodeToString(nonce[:])
					_ = json.NewEncoder(connection).Encode(map[string]any{"version": 1, "operation": "local_node_describe", "nonce": n, "instance_id": locator.Instance, "locator_digest": hash(raw)})
					var reply struct {
						Description *struct {
							Nonce    string          `json:"nonce"`
							Instance string          `json:"instance_id"`
							Digest   string          `json:"locator_digest"`
							Pin      json.RawMessage `json:"connection"`
						} `json:"node_description"`
					}
					err = json.NewDecoder(connection).Decode(&reply)
					_ = connection.Close()
					if err == nil && reply.Description != nil {
						d := reply.Description
						var pin struct {
							Root    string `json:"user_root"`
							Origin  string `json:"api_origin"`
							Node    string `json:"node_id"`
							Session string `json:"mcp_session_state_file"`
							Outbox  string `json:"mcp_outbox_state_file"`
						}
						if json.Unmarshal(d.Pin, &pin) != nil || d.Nonce != n || d.Instance != locator.Instance || d.Digest != hash(raw) || pin.Root != root || pin.Origin != v.f.cfg.Origin || pin.Node != v.actualNode.id || pin.Session != v.mcpState || pin.Outbox != outbox {
							t.Fatal("actual live Node description changed its original selected coordinates")
						}
						if must(os.Stat(filepath.Join(root, "run/nodes"))).Mode().Perm() != 0700 || must(os.Stat(paths[0])).Mode().Perm() != 0600 {
							t.Fatal("discovery material is not private")
						}
						var normalized any
						if json.Unmarshal(d.Pin, &normalized) != nil {
							t.Fatal("public pin JSON invalid")
						}
						return must(json.Marshal(normalized)), locator.Instance
					}
				}
			}
		}
		if !v.actualNode.running() {
			v.actualNode.reportFailure(t)
			t.Fatal("explicit Node exited before live description")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("original Node did not publish a live selected-root description")
	return nil, ""
}

func readPrivateBinary(t *testing.T, path string) []byte {
	t.Helper()
	info := must(os.Stat(path))
	if !info.Mode().IsRegular() || info.Size() > 128<<20 {
		t.Fatal("actual product binary bound exceeded")
	}
	return must(os.ReadFile(path))
}
