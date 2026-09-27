package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

func runMachineAgent(args []string) error {
	flags := flag.NewFlagSet("machine agent", flag.ContinueOnError)
	id := flags.String("id", envOr("CICADA_MACHINE_ID", ""), "stable machine ID")
	name := flags.String("name", envOr("CICADA_MACHINE_NAME", ""), "machine display name")
	controlURL := flags.String("control-url", envOr("CICADA_CONTROL_URL", "http://127.0.0.1:8787"), "Control base URL")
	stateDir := flags.String("state-dir", machineAgentStateDir(), "durable Node state directory")
	interval := flags.Duration("interval", machineAgentInterval(), "heartbeat interval")
	once := flags.Bool("once", false, "register, heartbeat, and process the current job queue once")
	relayOnly := flags.Bool("relay-only", false, "deliver Fabric messages after owner-confirmed Node binding; do not call Control management")
	lanDiscovery := flags.Bool("lan-discovery", false, "answer unauthenticated LAN capability discovery requests")
	lanPort := flags.Int("lan-port", lanDiscoveryPort, "UDP LAN discovery port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("machine agent requires --id or CICADA_MACHINE_ID")
	}
	if strings.TrimSpace(*name) == "" {
		*name = *id
	}
	base, err := normalizeControlURL(*controlURL)
	if err != nil {
		return err
	}
	if err := requireSecureNodeEnrollmentTransport(base); err != nil {
		return err
	}
	if *interval < time.Second {
		return errors.New("machine agent interval must be at least 1s")
	}
	if strings.TrimSpace(*stateDir) == "" {
		return errors.New("machine agent state directory is required")
	}
	nodeIdentity, credentialDigest, err := loadOrCreateMachineNodeIdentity(*stateDir, *id)
	if err != nil {
		return fmt.Errorf("load local Node identity: %w", err)
	}
	// Relay helpers read the bearer from a mode-0600 file. Keep it out of the
	// process environment so it cannot leak to unrelated child processes.
	if err := os.Setenv("CICADA_NODE_TOKEN", ""); err != nil {
		return fmt.Errorf("clear Node credential environment: %w", err)
	}
	if err := os.Setenv("CICADA_NODE_TOKEN_FILE", machineNodeCredentialPath(*stateDir, *id)); err != nil {
		return fmt.Errorf("configure local Node credential file: %w", err)
	}
	inboxPath := machineNodeInboxPath(*stateDir, *id)
	if err := os.MkdirAll(filepath.Dir(inboxPath), 0o700); err != nil {
		return fmt.Errorf("create machine node state directory: %w", err)
	}
	inbox, err := nodeinbox.Open(inboxPath)
	if err != nil {
		return fmt.Errorf("open machine node inbox: %w", err)
	}
	defer inbox.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *lanDiscovery {
		if *lanPort < 1 || *lanPort > 65535 {
			return errors.New("LAN discovery port must be between 1 and 65535")
		}
		go func() {
			if err := serveLANDiscovery(ctx, *id, *name, *lanPort); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "LAN discovery:", err)
			}
		}()
	}
	send := func() error {
		if *relayOnly {
			return nil
		}
		capabilities := control.DiscoverMachineCapabilities()
		capabilities["role"] = "worker"
		capabilities["harnesses"] = discoveredMachineHarnesses()
		if err := machineAPI(ctx, base+"/v1/machines", http.MethodPost, map[string]any{
			"id": *id, "name": *name, "status": "available", "capabilities": capabilities,
		}); err != nil {
			return fmt.Errorf("register machine: %w", err)
		}
		return machineAPI(ctx, base+"/v1/machines/"+url.PathEscape(*id)+"/heartbeat", http.MethodPost, map[string]any{
			"status": "available", "capabilities": capabilities,
		})
	}
	relayContext, cancelRelay := context.WithCancel(ctx)
	defer cancelRelay()
	relayAuthorized := true
	disableRelay := func(err error) {
		if !relayAuthorized {
			return
		}
		relayAuthorized = false
		cancelRelay()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Node Relay authorization was revoked; Relay delivery is disabled until restart:", err)
		}
	}
	heartbeatRelay := func() {
		if !relayAuthorized {
			return
		}
		if err := sendMachineNodeHeartbeat(ctx, base, *id, nodeIdentity.RelayToken); err != nil {
			if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
				disableRelay(err)
				return
			}
			fmt.Fprintln(os.Stderr, "Node heartbeat:", err)
		}
	}
	processRelay := func() error {
		if !relayAuthorized {
			return nil
		}
		err := processMachineFabricDeliveriesV2(ctx, base, *id, inbox, *stateDir)
		if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
			disableRelay(err)
			return nil
		}
		return err
	}
	processJobs := func() error {
		if *relayOnly {
			return nil
		}
		jobs, err := pollMachineJobs(ctx, base, *id)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			claimed, claimErr := claimMachineJob(ctx, base, job)
			if claimErr != nil {
				// A second agent may have claimed the job between polling and
				// claiming. Continue polling instead of treating that as a
				// machine failure.
				if machineAPIHasStatus(claimErr, http.StatusConflict) {
					continue
				}
				return claimErr
			}
			result := executeMachineJobWithHeartbeats(ctx, base, *id, *interval, claimed)
			if err := reportMachineJobReliably(ctx, base, claimed, result, *interval); err != nil {
				return err
			}
		}
		return nil
	}
	process := func() error {
		if err := processRelay(); err != nil {
			return err
		}
		return processJobs()
	}
	for {
		if err := awaitMachineNodeBinding(ctx, base, *id, *name, nodeIdentity.RelayToken,
			credentialDigest, *once, os.Stderr); err != nil {
			if *once || ctx.Err() != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, err)
			if err := waitMachineNodeBindingPoll(ctx); err != nil {
				return nil
			}
			continue
		}
		break
	}
	heartbeatRelay()
	if err := send(); err != nil {
		if *once {
			return err
		}
		fmt.Fprintln(os.Stderr, err)
	}
	if err := process(); err != nil {
		if *once {
			return fmt.Errorf("process machine jobs: %w", err)
		}
		fmt.Fprintln(os.Stderr, err)
	}
	if *once {
		return nil
	}
	// The Node initiates and maintains this outbound connection. Relay can
	// immediately wake it after durable commit, without an inbound Node port.
	// The ticker below still reconciles missed hints after a disconnect.
	wake := make(chan struct{}, 1)
	relayRevoked := make(chan error, 1)
	if relayAuthorized {
		go runMachineRelayEventStream(relayContext, base, *id, wake, relayRevoked)
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-relayRevoked:
			disableRelay(err)
		case <-wake:
			heartbeatRelay()
			if err := processRelay(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		case <-ticker.C:
			heartbeatRelay()
			if err := send(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			if err := process(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
}

func machineAgentStateDir() string {
	if value := strings.TrimSpace(os.Getenv("CICADA_NODE_STATE_DIR")); value != "" {
		return value
	}
	base := strings.TrimSpace(os.Getenv("CICADA_STATE_DIR"))
	if base == "" {
		base = "/state"
	}
	return base
}

func executeMachineJobWithHeartbeats(ctx context.Context, base, machineID string, interval time.Duration, job machineJob) machineJobResult {
	workspace, _, pathErr := machineJobPaths(job)
	if pathErr != nil {
		return machineJobResult{Status: "failed", Error: pathErr.Error()}
	}
	if job.WorkspaceSnapshotDigest != "" {
		if err := downloadMachineSnapshot(ctx, base, job, workspace); err != nil {
			return machineJobResult{Status: "failed", Error: "restore workspace snapshot: " + err.Error()}
		}
	}
	done := make(chan machineJobResult, 1)
	go func() { done <- executeMachineJob(ctx, job) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case result := <-done:
			if job.WorkspaceID != "" {
				digest, err := uploadMachineSnapshot(ctx, base, job, workspace)
				if err != nil {
					result.Status = "failed"
					result.Error = "store workspace snapshot: " + err.Error()
				} else {
					result.WorkspaceSnapshotDigest = digest
				}
			}
			return result
		case <-ticker.C:
			if err := machineAPI(ctx, base+"/v1/machines/"+url.PathEscape(machineID)+"/heartbeat", http.MethodPost, map[string]any{"status": "busy"}); err != nil {
				fmt.Fprintln(os.Stderr, "machine heartbeat:", err)
			}
		case <-ctx.Done():
			return machineJobResult{Status: "failed", Error: ctx.Err().Error()}
		}
	}
}

func machineAgentInterval() time.Duration {
	seconds := envInt("CICADA_MACHINE_HEARTBEAT_SECONDS", 30)
	if seconds < 1 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

func normalizeControlURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("control URL must be an absolute http or https URL without credentials")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func machineAPI(ctx context.Context, endpoint, method string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	setMachineAuth(request)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Control returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
