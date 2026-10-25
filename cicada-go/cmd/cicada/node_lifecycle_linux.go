package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/apppaths"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

const nodeServiceConfigName = "node-service.json"
const nodeServiceFormat = "cicada.node-service.v1"

var errNodeServiceConfig = errors.New("NODE_SERVICE_CONFIG_INVALID: use one original paired relay Node and exact protected configuration")
var errNodeServiceManager = errors.New("NODE_SERVICE_MANAGER_UNAVAILABLE: systemd user manager version 254 or newer is required")
var errNodeServiceConflict = errors.New("NODE_SERVICE_CONFLICT: another agent or an unowned unit is running; stop it explicitly before on")
var errNodeServiceFailed = errors.New("NODE_SERVICE_FAILED: managed Node did not become ready; inspect its user journal")

// This file owns local process control only. No Hub operation, grant, key
// generation, enrollment, or product-state deletion belongs in this controller.
type nodeServiceConfig struct {
	Format    string   `json:"format"`
	UserRoot  string   `json:"user_root"`
	Binary    string   `json:"binary"`
	CodexBin  string   `json:"codex_bin"`
	Home      string   `json:"home"`
	Path      string   `json:"path"`
	CodexHome string   `json:"codex_home,omitempty"`
	AgentArgs []string `json:"agent_args"`
}

type nodeServiceSelection struct {
	id, state, session, outbox, address, origin string
}

type nodeServiceStatus struct {
	State                 string `json:"state"`
	Unit                  string `json:"unit"`
	Scope                 string `json:"scope"`
	HubOnline             string `json:"hub_online"`
	MainPID               int    `json:"main_pid,omitempty"`
	UnmanagedAgentRunning bool   `json:"unmanaged_agent_running,omitempty"`
}

type nodeServiceRunner func(context.Context, string, ...string) (string, error)

func nodeLifecycleCommand(action string, args []string, out io.Writer) error {
	binary, err := os.Executable()
	if err != nil {
		return errNodeServiceConfig
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return errNodeServiceConfig
	}
	return nodeLifecycle(action, args, out, binary, runNodeServiceCommand)
}

func nodeLifecycle(action string, args []string, out io.Writer, binary string, run nodeServiceRunner) error {
	if action != "on" && action != "off" && action != "status" {
		return errNodeServiceConfig
	}
	outerSeen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if !strings.HasPrefix(args[i], "--") {
			return errNodeServiceConfig
		}
		key, _, inline := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if outerSeen[key] {
			return errNodeServiceConfig
		}
		outerSeen[key] = true
		if !inline {
			i++
		}
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rootArg := flags.String("user-root", "", "installed user root")
	codex := flags.String("codex-bin", "", "exact absolute original Codex executable; first on only")
	if flags.Parse(args) != nil || action != "on" && (*codex != "" || len(flags.Args()) != 0) {
		return errNodeServiceConfig
	}
	rootPath, err := apppaths.ResolveUserRoot(*rootArg)
	if err != nil {
		return errNodeServiceConfig
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, err := openLocalNodeDirectory(ctx, rootPath, false)
	if err != nil {
		return errNodeServiceConfig
	}
	defer root.Close()
	lock, err := lockNodeService(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	data, _, err := readLocalNodeFile(root, nodeServiceConfigName, 32<<10)
	var config nodeServiceConfig
	if errors.Is(err, os.ErrNotExist) && action == "on" {
		home, homeErr := os.UserHomeDir()
		config = nodeServiceConfig{nodeServiceFormat, rootPath, binary, *codex, home, os.Getenv("PATH"), os.Getenv("CODEX_HOME"), nil}
		if homeErr != nil {
			return errNodeServiceConfig
		}
		config.AgentArgs, _, err = canonicalNodeServiceArgs(rootPath, flags.Args())
		if err != nil {
			return err
		}
		selection, err := validateNodeServiceConfig(config, rootPath, binary)
		if err != nil || requireExistingNodeServiceState(config, selection) != nil {
			return errNodeServiceConfig
		}
		// Refuse foreground conflicts before recording a configuration.
		busy, err := nodeServiceAgentBusy(selection)
		if err != nil {
			return err
		}
		if busy {
			return errNodeServiceConflict
		}
		data, err = json.Marshal(config)
		if err != nil {
			return errNodeServiceConfig
		}
		data = append(data, '\n')
		if err := writeNodeServiceConfig(root, data); err != nil {
			return err
		}
	} else if err != nil || decodeLocalNodeJSON(data, &config) != nil {
		return errNodeServiceConfig
	}
	selection, err := validateNodeServiceConfig(config, rootPath, "")
	if err != nil {
		return err
	}
	if action == "on" {
		if config.Binary != binary {
			return errNodeServiceConfig
		}
		if *codex != "" && *codex != config.CodexBin {
			return errNodeServiceConfig
		}
		if len(flags.Args()) != 0 {
			canonical, _, err := canonicalNodeServiceArgs(rootPath, flags.Args())
			if err != nil || !reflect.DeepEqual(canonical, config.AgentArgs) {
				return errNodeServiceConfig
			}
		}
	}
	unit := nodeServiceUnit(config, selection)
	owner := nodeServiceOwner(data)
	version, err := run(ctx, "/usr/bin/systemctl", "--user", "show", "--property=Version", "--value")
	major, parseErr := strconv.Atoi(strings.Split(strings.TrimSpace(version), ".")[0])
	if err != nil || parseErr != nil || major < 254 {
		return errNodeServiceManager
	}
	state, err := inspectNodeService(ctx, run, unit, owner)
	if err != nil {
		return err
	}
	if action == "off" {
		if state["LoadState"] != "not-found" && state["ActiveState"] != "inactive" {
			if _, err := run(ctx, "/usr/bin/systemctl", "--user", "stop", unit); err != nil {
				return errNodeServiceFailed
			}
			state, err = inspectNodeService(ctx, run, unit, owner)
			if err == nil && state["ActiveState"] == "failed" && state["MainPID"] == "0" {
				if _, err = run(ctx, "/usr/bin/systemctl", "--user", "reset-failed", unit); err == nil {
					state, err = inspectNodeService(ctx, run, unit, owner)
				}
			}
			if err != nil || state["MainPID"] != "0" || state["ActiveState"] != "inactive" && state["LoadState"] != "not-found" {
				return errNodeServiceFailed
			}
		}
		busy, err := nodeServiceAgentBusy(selection)
		if err != nil {
			return err
		}
		if err := writeNodeServiceStatus(out, nodeServiceStatus{State: "stopped", Unit: unit, Scope: "managed_node_process", HubOnline: "unknown", UnmanagedAgentRunning: busy}); err != nil {
			return err
		}
		if busy {
			return errNodeServiceConflict
		}
		return nil
	}
	if action == "on" && state["ActiveState"] != "active" && state["ActiveState"] != "activating" {
		if requireExistingNodeServiceState(config, selection) != nil {
			return errNodeServiceConfig
		}
		busy, err := nodeServiceAgentBusy(selection)
		if err != nil {
			return err
		}
		if busy {
			return errNodeServiceConflict
		}
		if state["LoadState"] != "not-found" {
			// A stopped/failed transient unit may remain loaded. Only the exact
			// owned unit may be reset; no wildcard or resident service is touched.
			if _, err := run(ctx, "/usr/bin/systemctl", "--user", "reset-failed", unit); err != nil {
				return errNodeServiceFailed
			}
		}
		command := nodeServiceStartArgs(config, unit, owner)
		if _, err := run(ctx, "/usr/bin/systemd-run", command...); err != nil {
			return errNodeServiceFailed
		}
	}
	// Process readiness is the existing live local bridge, with its exact
	// original coordinates and kernel peer PID. It is never Hub-online proof.
	deadline := time.Now().Add(8 * time.Second)
	for {
		state, err = inspectNodeService(ctx, run, unit, owner)
		if err != nil {
			return err
		}
		pid, _ := strconv.Atoi(state["MainPID"])
		status := nodeServiceStatus{State: "stopped", Unit: unit, Scope: "managed_node_process", HubOnline: "unknown", MainPID: pid}
		if state["ActiveState"] == "failed" || state["ActiveState"] == "active" || state["ActiveState"] == "activating" || state["ActiveState"] == "deactivating" {
			status.State = "failed"
		}
		if state["ActiveState"] == "active" && pid > 0 && readyNodeService(ctx, config, selection, pid) == nil {
			status.State = "running"
		}
		if action == "status" || status.State == "running" || state["ActiveState"] != "active" && state["ActiveState"] != "activating" || time.Now().After(deadline) {
			if status.State == "stopped" {
				status.UnmanagedAgentRunning, err = nodeServiceAgentBusy(selection)
				if err != nil {
					return err
				}
			}
			if err := writeNodeServiceStatus(out, status); err != nil {
				return err
			}
			if action == "on" && status.State != "running" || status.State == "failed" {
				return errNodeServiceFailed
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errNodeServiceFailed
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func canonicalNodeServiceArgs(root string, args []string) ([]string, nodeServiceSelection, error) {
	s := nodeServiceSelection{}
	allowed := map[string]bool{"id": true, "name": true, "user-root": true, "state-dir": true, "control-url": true, "hub-address": true, "interval": true, "relay-only": true, "mcp-session-state-file": true, "mcp-outbox-state-file": true}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || !nodeServiceText(arg, 4096) {
			return nil, s, errNodeServiceConfig
		}
		key, _, inline := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !allowed[key] || seen[key] {
			return nil, s, errNodeServiceConfig
		}
		seen[key] = true
		if key != "relay-only" && !inline {
			i++
			if i >= len(args) || !nodeServiceText(args[i], 4096) {
				return nil, s, errNodeServiceConfig
			}
		}
	}
	f := flag.NewFlagSet("node service agent", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	id := f.String("id", "", "")
	name := f.String("name", "", "")
	userRoot := f.String("user-root", root, "")
	state := f.String("state-dir", "", "")
	origin := f.String("control-url", "", "")
	address := f.String("hub-address", "", "")
	interval := f.Duration("interval", 30*time.Second, "")
	relay := f.Bool("relay-only", false, "")
	session := f.String("mcp-session-state-file", "", "")
	outbox := f.String("mcp-outbox-state-file", "", "")
	if f.Parse(args) != nil || len(f.Args()) != 0 || *userRoot != root || !*relay || *interval < time.Second || *interval > time.Hour || !nodeServiceText(*id, 128) || strings.ContainsAny(*id, "/\\") || !nodeServiceText(*name, 128) || !localNodePath(*state) || !localNodePath(*session) || !localNodePath(*outbox) {
		return nil, s, errNodeServiceConfig
	}
	if *origin == "" {
		// Address-only foreground setup already installed its authenticated
		// logical origin. Reuse that original state; never discover a new pin,
		// borrow a shell default, or ask the operator to copy an identity URL.
		client, _, err := loadMachineRecoveryClient(*state, *id)
		if err != nil {
			return nil, s, errNodeServiceConfig
		}
		*origin = client.state.HubOrigin
	}
	canonicalOrigin, err := normalizeControlURL(*origin)
	if err != nil || canonicalOrigin != *origin {
		return nil, s, errNodeServiceConfig
	}
	if *address != "" {
		if err := pqtls.ValidateIPDialAddress(*address); err != nil {
			return nil, s, errNodeServiceConfig
		}
	}
	s = nodeServiceSelection{*id, *state, *session, *outbox, *address, *origin}
	canonical := []string{"--user-root", root, "--id", *id, "--name", *name, "--state-dir", *state, "--control-url", *origin, "--mcp-session-state-file", *session, "--mcp-outbox-state-file", *outbox, "--interval", interval.String(), "--relay-only"}
	if *address != "" {
		canonical = append(canonical, "--hub-address", *address)
	}
	return canonical, s, nil
}

func nodeServiceText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}

func validateNodeServiceConfig(c nodeServiceConfig, root, binary string) (nodeServiceSelection, error) {
	s := nodeServiceSelection{}
	if c.Format != nodeServiceFormat || c.UserRoot != root || binary != "" && c.Binary != binary || !localNodePath(c.Binary) || !localNodePath(c.CodexBin) || !localNodePath(c.Home) || c.CodexHome != "" && !localNodePath(c.CodexHome) || !nodeServiceText(c.Path, 8192) {
		return s, errNodeServiceConfig
	}
	for _, dir := range strings.Split(c.Path, ":") {
		if !localNodePath(dir) {
			return s, errNodeServiceConfig
		}
	}
	canonical, s, err := canonicalNodeServiceArgs(root, c.AgentArgs)
	if err != nil || !reflect.DeepEqual(canonical, c.AgentArgs) {
		return s, errNodeServiceConfig
	}
	return s, nil
}

func requireExistingNodeServiceState(c nodeServiceConfig, s nodeServiceSelection) error {
	for _, path := range []string{c.Binary, c.CodexBin} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
			return errNodeServiceConfig
		}
	}
	client, token, err := loadMachineRecoveryClient(s.state, s.id)
	// Do not retain or print this existing bearer. The read-only loader never
	// creates keys, repairs permissions, caches clients, or opens databases.
	_ = token
	if err != nil || client.state.HubOrigin != s.origin || client.state.HubTransportDescriptor == "" || s.address != "" && client.state.HubDialAddress != s.address {
		return errNodeServiceConfig
	}
	descriptor, err := hubtransport.DecodeDescriptor(client.state.HubTransportDescriptor)
	if err != nil || descriptor.Claims.Origin != client.state.HubOrigin || hubtransport.MatchNodeControl(descriptor, client.state.HubID, client.state.HubPublicIdentity, client.state.HubKeyVersion, client.state.HubFingerprint) != nil {
		return errNodeServiceConfig
	}
	if s.address != "" {
		pair, err := loadMachineNodePairState(s.state, s.id, client.identity)
		if err != nil {
			return errNodeServiceConfig
		}
		defer clear(pair.Secret)
		if pair.Stage != "ACKED" || pair.Binding == nil || client.state.NodePairTrustAttemptID != pair.AttemptID {
			return errNodeServiceConfig
		}
	}
	return nil
}

func lockNodeService(root *os.Root) (*os.File, error) {
	const name = "node-service.lock"
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		before, statErr := root.Lstat(name)
		if statErr != nil || !localNodePrivate(before, false) {
			return nil, errNodeServiceConfig
		}
		file, err = root.OpenFile(name, os.O_RDWR, 0)
	}
	if err != nil {
		if file != nil {
			file.Close()
		}
		return nil, errNodeServiceConfig
	}
	before, err := root.Lstat(name)
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !localNodePrivate(before, false) || !os.SameFile(before, opened) {
		file.Close()
		return nil, errNodeServiceConfig
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("NODE_SERVICE_BUSY: another lifecycle command is running")
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		file.Close()
		return nil, errNodeServiceConfig
	}
	return file, nil
}

func writeNodeServiceConfig(root *os.Root, data []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errNodeServiceConfig
	}
	temporary := ".node-service-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errNodeServiceConfig
	}
	defer root.Remove(temporary)
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	// Atomic, no-replace publication. A lost response reuses the exact saved
	// configuration; an interrupted write never exposes a partial JSON file.
	if err := root.Link(temporary, nodeServiceConfigName); err != nil {
		return errNodeServiceConfig
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func nodeServiceUnit(c nodeServiceConfig, s nodeServiceSelection) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", os.Geteuid(), c.UserRoot, s.id)))
	return "cicada-node-" + hex.EncodeToString(hash[:16]) + ".service"
}
func nodeServiceOwner(data []byte) string {
	hash := sha256.Sum256(data)
	return "Cicada managed Node " + hex.EncodeToString(hash[:])
}

func inspectNodeService(ctx context.Context, run nodeServiceRunner, unit, owner string) (map[string]string, error) {
	output, err := run(ctx, "/usr/bin/systemctl", "--user", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,Transient,Description")
	state := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || state[key] != "" {
			return nil, errNodeServiceManager
		}
		state[key] = value
	}
	if state["LoadState"] == "not-found" && state["ActiveState"] == "inactive" && state["MainPID"] == "0" {
		return state, nil
	}
	if err != nil || state["LoadState"] != "loaded" || state["ActiveState"] == "" {
		return nil, errNodeServiceManager
	}
	if state["Transient"] != "yes" || state["Description"] != owner {
		return nil, errNodeServiceConflict
	}
	return state, nil
}

func nodeServiceStartArgs(c nodeServiceConfig, unit, owner string) []string {
	unset := "CICADA_MACHINE_ID CICADA_MACHINE_NAME CICADA_CONTROL_URL CICADA_HUB_ID CICADA_NODE_PQTLS_CONFIG CICADA_NODE_STATE_DIR CICADA_STATE_DIR CICADA_NODE_TOKEN CICADA_NODE_TOKEN_FILE CICADA_NODE_RESOURCE_ID CICADA_PQTLS_DIAGNOSTIC_FILE CICADA_NODE_SEALED_PHASE_DEBUG"
	if c.CodexHome == "" {
		unset += " CODEX_HOME"
	}
	args := []string{"--user", "--quiet", "--unit=" + unit, "--description=" + owner,
		"--expand-environment=no", "--property=Type=exec", "--property=Restart=no", "--property=UMask=0077",
		"--property=KillMode=control-group", "--property=TimeoutStopSec=30s", "--property=StandardInput=null",
		"--working-directory=" + c.Home, "--setenv=HOME=" + c.Home, "--setenv=PATH=" + c.Path,
		"--setenv=CICADA_CODEX_BIN=" + c.CodexBin,
		"--property=UnsetEnvironment=" + unset}
	if c.CodexHome != "" {
		args = append(args, "--setenv=CODEX_HOME="+c.CodexHome)
	}
	args = append(args, "--", c.Binary, "machine", "agent")
	return append(args, c.AgentArgs...)
}

func nodeServiceAgentBusy(s nodeServiceSelection) (bool, error) {
	lock, err := nodelock.AcquireAgent(s.state, s.id)
	if errors.Is(err, nodelock.ErrAgentRunning) || errors.Is(err, nodelock.ErrBusy) {
		return true, nil
	}
	if err != nil {
		return false, errNodeServiceConfig
	}
	return false, lock.Close()
}

func readyNodeService(ctx context.Context, c nodeServiceConfig, s nodeServiceSelection, pid int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: c.UserRoot, NodeID: s.id}, nil)
	if err != nil {
		return errNodeServiceFailed
	}
	p := connection.Pin
	if p.StateDir != s.state || p.WriterRoot != s.state || p.MCPSessionStateFile != s.session || p.MCPOutboxStateFile != s.outbox || p.APIOrigin != s.origin {
		return errNodeServiceConfig
	}
	dialer := net.Dialer{}
	socket, err := dialer.DialContext(ctx, "unix", p.SocketPath)
	if err != nil {
		return errNodeServiceFailed
	}
	defer socket.Close()
	unix, ok := socket.(*net.UnixConn)
	if !ok {
		return errNodeServiceFailed
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return errNodeServiceFailed
	}
	var peer *syscall.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) {
		peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || peerErr != nil || peer == nil || int(peer.Pid) != pid || int(peer.Uid) != os.Geteuid() {
		return errNodeServiceFailed
	}
	return nil
}

func writeNodeServiceStatus(out io.Writer, status nodeServiceStatus) error {
	return json.NewEncoder(out).Encode(status)
}

func runNodeServiceCommand(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	command.Stdout = &nodeServiceOutput{buffer: &output}
	command.Stderr = io.Discard // Never echo environment, argv or manager payloads.
	err := command.Run()
	return output.String(), err
}

type nodeServiceOutput struct{ buffer *bytes.Buffer }

func (w *nodeServiceOutput) Write(p []byte) (int, error) {
	if w.buffer.Len()+len(p) > 16<<10 {
		return 0, errors.New("manager output exceeds bound")
	}
	return w.buffer.Write(p)
}
