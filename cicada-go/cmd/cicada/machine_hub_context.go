package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodetransport"
)

type machineHubContext struct {
	HubID, Origin, NodeID, StateDir, Token, WriterRoot, WriterScope string
	MultiHub                                                        bool
	RequireNativeContext                                            bool
	ProviderInbox                                                   *nodeinbox.Inbox
	ProviderAdmissions                                              *nodeinbox.ProviderAdmissionLedger
	NativeContexts                                                  *nodeinbox.NativeContextRegistry
	ResourceExecutions                                              *nodelock.ResourceExecutionManager
	NodeTransport                                                   http.RoundTripper
	TLSRuntime                                                      *nodetransport.Runtime
}

type machineHubContextKey struct{}

func withMachineHubContext(ctx context.Context, hub machineHubContext) context.Context {
	return context.WithValue(ctx, machineHubContextKey{}, hub)
}

func machineHubFrom(ctx context.Context) (machineHubContext, bool) {
	hub, ok := ctx.Value(machineHubContextKey{}).(machineHubContext)
	return hub, ok
}

func machinePinnedHubID(ctx context.Context) string {
	if hub, ok := machineHubFrom(ctx); ok {
		return hub.HubID
	}
	return strings.TrimSpace(os.Getenv("CICADA_HUB_ID"))
}

func machineNodeTokenFor(ctx context.Context) string {
	if hub, ok := machineHubFrom(ctx); ok {
		return hub.Token
	}
	return machineNodeToken()
}

func machineHubOriginMatches(ctx context.Context, endpoint string) bool {
	hub, ok := machineHubFrom(ctx)
	if !ok {
		return true
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return parsed.Scheme+"://"+parsed.Host == hub.Origin && parsed.User == nil && parsed.Fragment == ""
}

type machineHubConfig struct {
	HubID       string `json:"hub_id"`
	ControlURL  string `json:"control_url"`
	NodeID      string `json:"node_id"`
	Name        string `json:"name,omitempty"`
	PQTLSConfig string `json:"pqtls_config,omitempty"`
}

type machineHubConfigFile struct {
	Version int                `json:"version"`
	Hubs    []machineHubConfig `json:"hubs"`
}

// Multi-Hub configuration contains public coordinates only. Credentials and
// all replay-bearing state live under one private, Hub-specific directory.
func runMachineMultiHubAgent(configPath, stateRoot string, interval time.Duration, once bool) error {
	entries, err := loadMachineHubConfig(configPath)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(stateRoot)
	if err != nil || strings.TrimSpace(stateRoot) == "" {
		return errors.New("multi-Hub state root is required")
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	return runMachineHubWorkers(ctx, entries, func(ctx context.Context, entry machineHubConfig) error {
		hubState := machineHubStateDir(root, entry)
		hub := machineHubContext{HubID: entry.HubID, Origin: entry.ControlURL,
			NodeID: entry.NodeID, StateDir: hubState, WriterRoot: root,
			WriterScope: machineNativeWriterScope(), MultiHub: true}
		name := entry.Name
		if name == "" {
			name = entry.NodeID
		}
		args := []string{"--id", entry.NodeID, "--name", name, "--control-url", entry.ControlURL,
			"--state-dir", hubState, "--interval", interval.String(), "--relay-only", "--pqtls-config", entry.PQTLSConfig}
		if once {
			args = append(args, "--once")
		}
		return runMachineAgentWithContext(ctx, args, &hub)
	})
}

func machineHubStateDir(root string, entry machineHubConfig) string {
	sum := sha256.Sum256([]byte(entry.HubID + "\x00" + entry.ControlURL))
	return filepath.Join(root, "hubs", hex.EncodeToString(sum[:]))
}

func loadMachineHubConfig(configPath string) ([]machineHubConfig, error) {
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
		return nil, errors.New("multi-Hub config must be a bounded regular file")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config machineHubConfigFile
	if err := decodeStrictBridgeJSON(data, &config); err != nil || config.Version != 1 || len(config.Hubs) < 2 || len(config.Hubs) > 8 {
		return nil, errors.New("multi-Hub config requires version 1 and 2-8 Hubs")
	}
	seenHub, seenOrigin := map[string]bool{}, map[string]bool{}
	for index := range config.Hubs {
		entry := &config.Hubs[index]
		entry.HubID, entry.NodeID, entry.Name = strings.TrimSpace(entry.HubID), strings.TrimSpace(entry.NodeID), strings.TrimSpace(entry.Name)
		origin, err := normalizeControlURL(entry.ControlURL)
		if err != nil {
			return nil, err
		}
		if err := requireSecureNodeEnrollmentTransport(origin); err != nil {
			return nil, err
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.User != nil || entry.HubID == "" || entry.NodeID == "" ||
			seenHub[entry.HubID] || seenOrigin[origin] {
			return nil, errors.New("multi-Hub config has ambiguous or duplicate coordinates")
		}
		entry.ControlURL = origin
		seenHub[entry.HubID], seenOrigin[origin] = true, true
	}
	return config.Hubs, nil
}

func runMachineHubWorkers(ctx context.Context, entries []machineHubConfig,
	run func(context.Context, machineHubConfig) error) error {
	results := make(chan error, len(entries))
	var workers sync.WaitGroup
	for _, entry := range entries {
		entry := entry
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- run(ctx, entry)
		}()
	}
	var firstErr error
	for range entries {
		if err := <-results; err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("multi-Hub Node stopped: %w", err)
			}
			fmt.Fprintln(os.Stderr, "multi-Hub Node context stopped:", err)
		}
	}
	workers.Wait()
	return firstErr
}

func machineNativeWriterScope() string {
	// The local OS user is deliberately a broader lock scope than an account:
	// different Codex homes under this UID cannot write the same native ID at
	// once. It is not proof of an authenticated Codex account.
	return fmt.Sprintf("uid:%d", os.Getuid())
}
