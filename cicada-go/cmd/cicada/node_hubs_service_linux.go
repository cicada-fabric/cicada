package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

const nodeHubServiceFormat = "cicada.node-manager-service.v1"

type nodeHubServiceConfig struct {
	Format                string             `json:"format"`
	UserRoot              string             `json:"user_root"`
	Binary                string             `json:"binary"`
	CodexBin              string             `json:"codex_bin"`
	Home                  string             `json:"home"`
	Path                  string             `json:"path"`
	CodexHome             string             `json:"codex_home,omitempty"`
	OriginalService       *nodeServiceConfig `json:"original_service,omitempty"`
	OriginalServiceDigest string             `json:"original_service_digest,omitempty"`
}

func validateNodeHubService(c nodeHubServiceConfig, root string) error {
	if c.Format != nodeHubServiceFormat || c.UserRoot != root || !localNodePath(c.Binary) || !localNodePath(c.CodexBin) || !localNodePath(c.Home) || c.CodexHome != "" && !localNodePath(c.CodexHome) || !nodeServiceText(c.Path, 8192) {
		return ErrLocalNodeHubConfig
	}
	for _, p := range strings.Split(c.Path, ":") {
		if !localNodePath(p) {
			return ErrLocalNodeHubConfig
		}
	}
	if validateNodeHubExecutable(c.Binary) != nil || validateNodeHubCodexExecutable(c.CodexBin) != nil {
		return ErrLocalNodeHubConfig
	}
	if (c.OriginalService != nil) != (c.OriginalServiceDigest != "") {
		return ErrLocalNodeHubConfig
	}
	if c.OriginalService != nil {
		if _, err := validateNodeServiceConfig(*c.OriginalService, root, ""); err != nil || !localContextHex(c.OriginalServiceDigest, 64) {
			return ErrLocalNodeHubConfig
		}
	}
	return nil
}

func readNodeHubService(root *os.Root, path string) (nodeHubServiceConfig, []byte, error) {
	b, _, err := readLocalNodeFile(root, nodeServiceConfigName, 64<<10)
	if err != nil {
		return nodeHubServiceConfig{}, nil, err
	}
	var c nodeHubServiceConfig
	if decodeLocalNodeJSON(b, &c) != nil || validateNodeHubService(c, path) != nil {
		return c, b, ErrLocalNodeHubConfig
	}
	return c, b, nil
}

func nodeHubServiceUnit(root string) string {
	h := sha256.Sum256([]byte(strconv.Itoa(os.Geteuid()) + "\x00" + root))
	return "cicada-node-manager-" + hex.EncodeToString(h[:16]) + ".service"
}

func nodeHubServiceOwner(data []byte) string {
	h := sha256.Sum256(data)
	return "Cicada managed Node Hub manager " + hex.EncodeToString(h[:])
}

func nodeHubServiceStartArgs(c nodeHubServiceConfig, owner string) []string {
	// Reuse the established exact environment/ownership policy. Only the
	// executable's fixed internal command differs from the original service.
	legacy := nodeServiceConfig{Format: nodeServiceFormat, UserRoot: c.UserRoot, Binary: c.Binary, CodexBin: c.CodexBin, Home: c.Home, Path: c.Path, CodexHome: c.CodexHome}
	args := nodeServiceStartArgs(legacy, nodeHubServiceUnit(c.UserRoot), owner)
	args = args[:len(args)-3]
	return append(args, c.Binary, "node", "daemon", "--user-root", c.UserRoot)
}

func nodeHubLifecycle(action string, args []string, out io.Writer, binary string, run nodeServiceRunner) error {
	if action != "on" && action != "off" && action != "status" {
		return ErrLocalNodeHubConfig
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--" || !strings.HasPrefix(args[i], "--") {
			break
		}
		key, _, inline := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if seen[key] || key != "user-root" && key != "codex-bin" {
			return ErrLocalNodeHubConfig
		}
		seen[key] = true
		if !inline {
			i++
			if i >= len(args) {
				return ErrLocalNodeHubConfig
			}
		}
	}
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	selected := f.String("user-root", "", "")
	codex := f.String("codex-bin", "", "")
	if f.Parse(args) != nil || action != "on" && (*codex != "" || len(f.Args()) != 0) {
		return ErrLocalNodeHubConfig
	}
	path, err := apppaths.ResolveUserRoot(*selected)
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, _, err := nodeHubRoot(ctx, path, action == "on")
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockNodeService(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	c, raw, err := readNodeHubService(root, path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// The original v1 off/status remain available to prove its stop. New
		// on never replaces or stops that owned service implicitly.
		var old nodeServiceConfig
		if len(raw) > 0 && decodeLocalNodeJSON(raw, &old) == nil && old.Format == nodeServiceFormat {
			lock.Close()
			if action == "off" || action == "status" {
				return nodeLifecycle(action, args, out, binary, run)
			}
			return errNodeHubConflict
		}
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		if action != "on" {
			return errNodeHubNotFound
		}
		if len(f.Args()) > 0 {
			// Preserve the first-on spelling as an explicit import adapter. It
			// must complete the same stopped-original adoption transaction.
			lock.Close()
			return nodeHubAdoptLegacyArguments(ctx, path, binary, *codex, f.Args(), run, out)
		}
		home, e := os.UserHomeDir()
		if e != nil {
			return ErrLocalNodeHubConfig
		}
		c = nodeHubServiceConfig{Format: nodeHubServiceFormat, UserRoot: path, Binary: binary, CodexBin: *codex, Home: home, Path: os.Getenv("PATH"), CodexHome: os.Getenv("CODEX_HOME")}
		if validateNodeHubService(c, path) != nil {
			return ErrLocalNodeHubConfig
		}
		b, _ := json.Marshal(c)
		raw = append(b, '\n')
		if err = initializeNodeHubRegistry(ctx, path); err != nil {
			return err
		}
		if err = writeNodeHubAtomic(root, nodeServiceConfigName, raw, nil); err != nil {
			return err
		}
	} else if len(f.Args()) != 0 || *codex != "" && *codex != c.CodexBin {
		return errNodeHubConflict
	}
	if action == "on" && c.Binary != binary {
		return errNodeHubConflict
	}
	return controlNodeHubService(ctx, action, c, raw, run, out)
}

func controlNodeHubService(ctx context.Context, action string, c nodeHubServiceConfig, raw []byte, run nodeServiceRunner, out io.Writer) error {
	version, err := run(ctx, "/usr/bin/systemctl", "--user", "show", "--property=Version", "--value")
	v, e := strconv.Atoi(strings.Split(strings.TrimSpace(version), ".")[0])
	if err != nil || e != nil || v < 254 {
		return errNodeServiceManager
	}
	unit, owner := nodeHubServiceUnit(c.UserRoot), nodeHubServiceOwner(raw)
	state, err := inspectNodeService(ctx, run, unit, owner)
	if err != nil {
		return err
	}
	if action == "off" {
		if state["LoadState"] != "not-found" && state["ActiveState"] != "inactive" {
			if _, err = run(ctx, "/usr/bin/systemctl", "--user", "stop", unit); err != nil {
				return errNodeServiceFailed
			}
			state, err = inspectNodeService(ctx, run, unit, owner)
			if err != nil {
				return err
			}
		}
		if state["MainPID"] != "0" && state["LoadState"] != "not-found" {
			return errNodeServiceFailed
		}
		if _, ie := nodeHubManagerIPC(ctx, c.UserRoot, "STATUS", 0); ie == nil {
			return errNodeServiceConflict
		} else if !errors.Is(ie, errNodeHubUnavailable) {
			return ie
		}
		if busy, be := nodeHubAnyAgentBusy(ctx, c.UserRoot); be != nil {
			return be
		} else if busy {
			return errNodeHubConflict
		}
		return writeNodeServiceStatus(out, nodeServiceStatus{State: "stopped", Unit: unit, Scope: "managed_node_hub_manager", HubOnline: "unknown"})
	}
	if action == "on" && state["ActiveState"] != "active" && state["ActiveState"] != "activating" {
		if busy, be := nodeHubAnyAgentBusy(ctx, c.UserRoot); be != nil {
			return be
		} else if busy {
			return errNodeHubConflict
		}
		if state["LoadState"] != "not-found" {
			if _, err = run(ctx, "/usr/bin/systemctl", "--user", "reset-failed", unit); err != nil {
				return errNodeServiceFailed
			}
		}
		if _, err = run(ctx, "/usr/bin/systemd-run", nodeHubServiceStartArgs(c, owner)...); err != nil {
			return errNodeServiceFailed
		}
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		state, err = inspectNodeService(ctx, run, unit, owner)
		if err != nil {
			return err
		}
		pid, _ := strconv.Atoi(state["MainPID"])
		status := nodeServiceStatus{State: "stopped", Unit: unit, Scope: "managed_node_hub_manager", HubOnline: "unknown", MainPID: pid}
		if state["ActiveState"] == "active" && pid > 0 {
			if _, e := nodeHubManagerIPCForPID(ctx, c.UserRoot, "STATUS", 0, pid); e == nil {
				status.State = "running"
				return writeNodeServiceStatus(out, status)
			}
			status.State = "starting"
		} else if state["ActiveState"] == "failed" {
			status.State = "failed"
		}
		if status.State == "stopped" {
			if busy, be := nodeHubAnyAgentBusy(ctx, c.UserRoot); be != nil {
				return be
			} else if busy {
				status.State = "unknown"
				status.UnmanagedAgentRunning = true
			}
		}
		if action == "status" {
			return writeNodeServiceStatus(out, status)
		}
		if !time.Now().Before(deadline) || status.State == "failed" {
			return errNodeServiceFailed
		}
		select {
		case <-ctx.Done():
			return errNodeServiceFailed
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func nodeHubManagerDaemonCommand(args []string) error {
	f := flag.NewFlagSet("node daemon", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	selected := f.String("user-root", "", "")
	if f.Parse(args) != nil || len(f.Args()) != 0 || *selected == "" {
		return ErrLocalNodeHubConfig
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	root, path, err := nodeHubRoot(ctx, *selected, false)
	if err != nil {
		return err
	}
	c, _, err := readNodeHubService(root, path)
	root.Close()
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return ErrLocalNodeHubConfig
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil || c.Binary != binary {
		return errNodeHubConflict
	}
	err = serveNodeHubManager(ctx, path, nodeHubProductionDriver(path))
	if errors.Is(err, errNodeHubPending) {
		// serve retains its gate until all workers retire. Keep this daemon
		// process alive as well: returning from main would release the kernel
		// lock even though an asynchronous cleanup still owns the file object.
		retirement, _, openErr := nodeHubRoot(context.Background(), path, false)
		if openErr != nil {
			return err
		}
		defer retirement.Close()
		for {
			held, inspectErr := inspectNodeHubDaemonGate(retirement)
			if inspectErr == nil && !held {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return err
}

func nodeHubAnyAgentBusy(ctx context.Context, userRoot string) (bool, error) {
	root, _, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return false, err
	}
	defer root.Close()
	if held, ge := inspectNodeHubDaemonGate(root); ge != nil {
		return false, ge
	} else if held {
		return true, nil
	}
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return false, err
	}
	for _, e := range r.Connections {
		if _, se := os.Lstat(machineNodeStateDir(e.StateDir, e.NodeID)); errors.Is(se, os.ErrNotExist) {
			continue
		}
		busy, be := nodeServiceAgentBusy(nodeServiceSelection{id: e.NodeID, state: e.StateDir})
		if be != nil {
			return false, be
		}
		if busy {
			return true, nil
		}
	}
	return false, nil
}
