package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

const machineNodeRecoveryPendingFileName = "recovery-pending.json"

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
	*id = strings.TrimSpace(*id)
	if strings.TrimSpace(*id) == "" {
		return errors.New("machine agent requires --id or CICADA_MACHINE_ID")
	}
	if strings.TrimSpace(*name) == "" {
		*name = *id
	}
	*stateDir = strings.TrimSpace(*stateDir)
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
	agentLock, err := nodelock.AcquireAgent(*stateDir, *id)
	if err != nil {
		return fmt.Errorf("acquire Node Agent lock: %w", err)
	}
	defer agentLock.Close()
	if err := rejectMachineNodePendingRecovery(*stateDir, *id); err != nil {
		return err
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
	// Local peer delivery has a separate inbox and ledger. The remote Relay
	// journal must never claim its messages or report Hub receipts for them.
	localInbox, err := nodeinbox.Open(machineLocalGroupInboxPath(*stateDir, *id))
	if err != nil {
		return fmt.Errorf("open local Group node inbox: %w", err)
	}
	defer localInbox.Close()
	monitorInboxPath := machineMonitorBroadcastInboxPath(*stateDir, *id)
	monitorInbox, err := openExistingMachineMonitorBroadcastInbox(monitorInboxPath)
	if err != nil {
		return fmt.Errorf("open Monitor management inbox: %w", err)
	}
	defer func() {
		if monitorInbox != nil {
			_ = monitorInbox.Close()
		}
	}()
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
		return sendMachineNodeWorkerHeartbeat(ctx, base, *id, nodeIdentity.RelayToken, "available", capabilities)
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
			fmt.Fprintln(os.Stderr, "Node authorization was rejected; stopping the machine agent:", err)
		}
	}
	heartbeatRelay := func() error {
		if !relayAuthorized {
			return nil
		}
		if err := sendMachineNodeHeartbeat(ctx, base, *id, nodeIdentity.RelayToken); err != nil {
			if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
				disableRelay(err)
				return nodeCredentialRevokedError(err)
			}
			fmt.Fprintln(os.Stderr, "Node heartbeat:", err)
		}
		return nil
	}
	processRelay := func() error {
		if !relayAuthorized {
			return nil
		}
		err := processMachineFabricDeliveriesV2(ctx, base, *id, inbox, *stateDir)
		if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
			disableRelay(err)
			return nodeCredentialRevokedError(err)
		}
		return err
	}
	processJobs := func() error {
		if *relayOnly {
			return nil
		}
		jobs, err := pollMachineJobs(ctx, base, *id, nodeIdentity.RelayToken)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			claimed, claimErr := claimMachineJob(ctx, base, *id, nodeIdentity.RelayToken, job)
			if claimErr != nil {
				// A second agent may have claimed the job between polling and
				// claiming. Continue polling instead of treating that as a
				// machine failure.
				if machineAPIHasStatus(claimErr, http.StatusConflict) {
					continue
				}
				return claimErr
			}
			result := executeMachineJobWithHeartbeats(ctx, base, *id, nodeIdentity.RelayToken, *interval, claimed)
			if err := reportMachineJobReliably(ctx, base, *id, nodeIdentity.RelayToken, claimed, result, *interval); err != nil {
				return err
			}
		}
		return nil
	}
	var localBridge *machineAgentJoinBridge
	var localWake <-chan struct{}
	processMonitor := func() error {
		if *relayOnly || !relayAuthorized || strings.TrimSpace(os.Getenv("CICADA_HUB_ID")) == "" {
			return nil
		}
		bridge := &machineAgentJoinBridge{ctx: ctx, stateDir: *stateDir,
			baseURL: base, nodeID: *id, nodeToken: nodeIdentity.RelayToken}
		return processMachineMonitorBroadcastNotifications(ctx, bridge, &monitorInbox, monitorInboxPath)
	}
	processLocal := func() error {
		if localBridge == nil {
			return nil
		}
		return processMachineLocalGroupDeliveries(ctx, localBridge, localInbox)
	}
	process := func() error {
		// A local Guard outage must not starve remote Relay deliveries or
		// unrelated management jobs on the same Node.
		localErr := processLocal()
		relayErr := processRelay()
		monitorErr := processMonitor()
		jobErr := processJobs()
		return errors.Join(localErr, relayErr, monitorErr, jobErr)
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
	if !*once {
		bridge, err := startMachineAgentJoinBridge(ctx, *stateDir, base, *id, nodeIdentity.RelayToken)
		if err != nil {
			return fmt.Errorf("start trusted local Join bridge: %w", err)
		}
		defer bridge.Close()
		localBridge = bridge
		localWake = bridge.localWake
	}
	if err := heartbeatRelay(); err != nil {
		return err
	}
	if err := send(); err != nil {
		if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
			return nodeCredentialRevokedError(err)
		}
		if *once {
			return err
		}
		fmt.Fprintln(os.Stderr, err)
	}
	if err := process(); err != nil {
		if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
			return nodeCredentialRevokedError(err)
		}
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
			return nodeCredentialRevokedError(err)
		case <-wake:
			if err := heartbeatRelay(); err != nil {
				return err
			}
			if err := processRelay(); err != nil {
				if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
					return nodeCredentialRevokedError(err)
				}
				fmt.Fprintln(os.Stderr, err)
			}
			if err := processMonitor(); err != nil {
				fmt.Fprintln(os.Stderr, "Monitor management delivery:", err)
			}
		case <-localWake:
			if err := processLocal(); err != nil {
				fmt.Fprintln(os.Stderr, "Local Group delivery:", err)
			}
		case <-ticker.C:
			if err := heartbeatRelay(); err != nil {
				return err
			}
			if err := send(); err != nil {
				if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
					return nodeCredentialRevokedError(err)
				}
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			if err := process(); err != nil {
				if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
					return nodeCredentialRevokedError(err)
				}
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
}

// rejectMachineNodePendingRecovery prevents a restored Node from reconnecting
// before its binding, replay watermarks, and uncertain injections are reconciled.
// Recovery marker and registry contents are deliberately not read or included
// in the error.
func rejectMachineNodePendingRecovery(stateDir, nodeID string) error {
	quarantined, err := nodebackup.RecoveryQuarantineActive(stateDir, nodeID)
	if err != nil {
		return fmt.Errorf("inspect Node recovery quarantine: %w", err)
	}
	if quarantined {
		return errors.New("Node recovery is pending reconciliation; refusing to start Agent")
	}
	return nil
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

func executeMachineJobWithHeartbeats(ctx context.Context, base, machineID, nodeToken string, interval time.Duration, job machineJob) machineJobResult {
	workspace, _, pathErr := machineJobPaths(job)
	if pathErr != nil {
		return machineJobResult{Status: "failed", Error: pathErr.Error()}
	}
	executionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	revoked := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-executionCtx.Done():
				return
			case <-ticker.C:
				if err := sendMachineNodeWorkerHeartbeat(executionCtx, base, machineID, nodeToken, "busy", nil); err != nil {
					if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
						revoked <- nodeCredentialRevokedError(err)
						cancel()
						return
					}
					fmt.Fprintln(os.Stderr, "machine heartbeat:", err)
				}
			}
		}
	}()
	finish := func(result machineJobResult) machineJobResult {
		select {
		case err := <-revoked:
			return machineJobResult{Status: "failed", Error: err.Error()}
		default:
			return result
		}
	}
	if job.WorkspaceSnapshotDigest != "" {
		if job.WorkspaceID == "" {
			return machineJobResult{Status: "failed", Error: "workspace snapshot requires a workspace ID"}
		}
		if err := downloadBoundNodeSnapshot(executionCtx, base, machineID, nodeToken, job, workspace); err != nil {
			return finish(machineJobResult{Status: "failed", Error: "restore workspace snapshot: " + err.Error()})
		}
	}
	done := make(chan machineJobResult, 1)
	go func() {
		done <- executeMachineJobWithApproval(executionCtx, job, &machineApprovalBridge{
			BaseURL: base, NodeID: machineID, NodeToken: nodeToken,
		})
	}()
	for {
		select {
		case result := <-done:
			if job.WorkspaceID != "" {
				digest, err := uploadBoundNodeSnapshot(executionCtx, base, machineID, nodeToken, job, workspace)
				if err != nil {
					result.Status = "failed"
					result.Error = "store workspace snapshot: " + err.Error()
				} else {
					result.WorkspaceSnapshotDigest = digest
				}
			}
			return finish(result)
		case err := <-revoked:
			return machineJobResult{Status: "failed", Error: err.Error()}
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
