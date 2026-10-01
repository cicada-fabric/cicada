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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

const machineNodeRecoveryPendingFileName = "recovery-pending.json"

func runMachineAgent(args []string) error {
	return runMachineAgentWithContext(context.Background(), args, nil)
}

func runMachineAgentWithContext(parent context.Context, args []string, pinned *machineHubContext) error {
	flags := flag.NewFlagSet("machine agent", flag.ContinueOnError)
	hubsFile := flags.String("hubs-file", "", "private local multi-Hub registry JSON")
	stateRoot := flags.String("state-root", "", "shared native-writer and Hub state root for multi-Hub mode")
	id := flags.String("id", envOr("CICADA_MACHINE_ID", ""), "stable machine ID")
	name := flags.String("name", envOr("CICADA_MACHINE_NAME", ""), "machine display name")
	controlURL := flags.String("control-url", envOr("CICADA_CONTROL_URL", "http://127.0.0.1:8787"), "Control base URL")
	pqConfig := flags.String("pqtls-config", strings.TrimSpace(os.Getenv("CICADA_NODE_PQTLS_CONFIG")), "private enrolled Node PQ TLS configuration")
	stateDir := flags.String("state-dir", machineAgentStateDir(), "durable Node state directory")
	interval := flags.Duration("interval", machineAgentInterval(), "heartbeat interval")
	once := flags.Bool("once", false, "register, heartbeat, and process the current job queue once")
	relayOnly := flags.Bool("relay-only", false, "deliver Fabric messages after owner-confirmed Node binding; do not call Control management")
	lanDiscovery := flags.Bool("lan-discovery", false, "answer unauthenticated LAN capability discovery requests")
	lanPort := flags.Int("lan-port", lanDiscoveryPort, "UDP LAN discovery port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *hubsFile != "" {
		if pinned != nil || *stateRoot == "" || !*relayOnly || *lanDiscovery || len(flags.Args()) != 0 {
			return errors.New("multi-Hub mode requires --state-root and --relay-only, with no LAN discovery")
		}
		return runMachineMultiHubAgent(*hubsFile, *stateRoot, *interval, *once)
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
	// Hub-specific authority is carried only by this Agent context. No global
	// token/environment mutation can transplant one Hub's bearer to another.
	if pinned == nil {
		pinned = &machineHubContext{HubID: strings.TrimSpace(os.Getenv("CICADA_HUB_ID")),
			Origin: base, NodeID: *id, StateDir: *stateDir, WriterRoot: *stateDir,
			WriterScope: machineNativeWriterScope()}
	}
	if pinned.Origin != base || pinned.NodeID != *id || pinned.StateDir != *stateDir || pinned.WriterScope == "" {
		return errors.New("Node Hub context does not match pinned local coordinates")
	}
	if err := configureMachinePQTransport(pinned, *pqConfig); err != nil {
		return err
	}
	if transport, ok := pinned.NodeTransport.(interface{ CloseIdleConnections() }); ok {
		defer transport.CloseIdleConnections()
	}
	writerRoot := strings.TrimSpace(pinned.WriterRoot)
	if writerRoot == "" {
		writerRoot = *stateDir
	}
	writerRootLock, err := nodelock.AcquireWriterRoot(writerRoot)
	if err != nil {
		return fmt.Errorf("acquire shared Node WriterRoot lock: %w", err)
	}
	defer writerRootLock.Close()
	rootQuarantined, rootErr := nodebackup.WriterRootRecoveryQuarantineActive(writerRoot)
	if rootErr != nil {
		return fmt.Errorf("inspect shared WriterRoot recovery quarantine: %w", rootErr)
	}
	if rootQuarantined {
		return errors.New("shared WriterRoot is quarantined after restore; reconcile shared fences before starting any Hub Agent")
	}
	nodeIdentity, credentialDigest, err := loadOrCreateMachineNodeIdentity(*stateDir, *id)
	if err != nil {
		return fmt.Errorf("load local Node identity: %w", err)
	}
	pinned.RequireNativeContext = true
	pinned.Token = nodeIdentity.RelayToken
	inboxPath := machineNodeInboxPath(*stateDir, *id)
	if err := os.MkdirAll(filepath.Dir(inboxPath), 0o700); err != nil {
		return fmt.Errorf("create machine node state directory: %w", err)
	}
	inbox, err := nodeinbox.Open(inboxPath)
	if err != nil {
		return fmt.Errorf("open machine node inbox: %w", err)
	}
	defer inbox.Close()
	pinned.ProviderInbox = inbox
	providerLedger, providerLedgerErr := nodeinbox.OpenProviderAdmissionLedger(
		filepath.Join(writerRoot, "node-provider-admission.sqlite3"))
	if providerLedgerErr != nil {
		fmt.Fprintln(os.Stderr, "Node provider admission ledger:", providerLedgerErr)
	} else {
		pinned.ProviderAdmissions = providerLedger
		defer providerLedger.Close()
	}
	nativeContexts, nativeContextErr := nodeinbox.OpenNativeContextRegistry(
		filepath.Join(writerRoot, "node-native-context-history.sqlite3"))
	if nativeContextErr != nil {
		// Current native scope cannot be proven without the shared history. The
		// Agent remains alive for independent peer transport and management, while
		// native delivery hooks reject the missing registry.
		fmt.Fprintln(os.Stderr, "Node native-context history:", nativeContextErr)
	} else {
		pinned.NativeContexts = nativeContexts
		defer nativeContexts.Close()
	}
	if !*relayOnly {
		resourceExecutions, resourceErr := nodelock.OpenResourceExecutionManager(writerRoot)
		if resourceErr != nil {
			// Management fails closed at the execution boundary. Keep Relay and
			// peer service alive while an operator repairs the local state root.
			fmt.Fprintln(os.Stderr, "Node resource execution authority:", resourceErr)
		} else {
			pinned.ResourceExecutions = resourceExecutions
		}
	}
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
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var agentWorkers sync.WaitGroup
	ctx = withMachineHubContext(ctx, *pinned)
	if *lanDiscovery {
		if *lanPort < 1 || *lanPort > 65535 {
			return errors.New("LAN discovery port must be between 1 and 65535")
		}
		agentWorkers.Add(1)
		go func() {
			defer agentWorkers.Done()
			if err := serveLANDiscovery(ctx, *id, *name, *lanPort); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "LAN discovery:", err)
			}
		}()
	}
	send := func() error {
		if *relayOnly {
			return nil
		}
		capabilities := machineNodePhysicalResourceCapabilities(control.DiscoverMachineCapabilities())
		capabilities["role"] = "worker"
		capabilities["harnesses"] = discoveredMachineHarnesses()
		return sendMachineNodeWorkerHeartbeat(ctx, base, *id, nodeIdentity.RelayToken, "available", capabilities)
	}
	relayContext, cancelRelay := context.WithCancel(ctx)
	var relayAuthorized atomic.Bool
	relayAuthorized.Store(true)
	var relayBound atomic.Bool
	relayReady := make(chan struct{})
	var relayReadyOnce sync.Once
	markRelayReady := func() {
		relayReadyOnce.Do(func() {
			relayBound.Store(true)
			close(relayReady)
		})
	}
	disableRelay := func(err error) {
		if !relayAuthorized.CompareAndSwap(true, false) {
			return
		}
		cancelRelay()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Node authorization was rejected; stopping the machine agent:", err)
		}
	}
	heartbeatRelay := func() error {
		if !relayAuthorized.Load() || !relayBound.Load() {
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
		if !relayAuthorized.Load() || !relayBound.Load() {
			return nil
		}
		err := processMachineFabricDeliveriesV2(ctx, base, *id, inbox, *stateDir)
		if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
			disableRelay(err)
			return nodeCredentialRevokedError(err)
		}
		return err
	}
	processJobs := func(agentCtx context.Context) error {
		if *relayOnly {
			return nil
		}
		client, err := machineNodeControlClientFromContext(agentCtx, nodeWorkerJobsEndpoint(base, *id), nodeIdentity.RelayToken)
		if err != nil {
			return err
		}
		executionCtx, err := machineNodeExecutionContext(agentCtx, client)
		if err != nil {
			return err
		}
		runClaimed := func(claimed machineJob) error {
			prepared, admission, err := prepareMachineNodeClaimExecution(executionCtx, client, claimed)
			if err != nil {
				if admission != nil && admission.Admitted &&
					(errors.Is(err, nodelock.ErrResourceExecutionBusy) ||
						errors.Is(err, errMachineNodePhysicalResourceClaim)) {
					// This exact Hub claim asked for a physical resource that is
					// quarantined or not mapped by the Node operator. No provider
					// process started; return a truthful terminal result so the
					// single durable claim slot cannot block unrelated Workers.
					claimed = prepared
					if err := client.beginClaimExecution(claimed); err != nil {
						return err
					}
					result := machineJobResult{Status: "failed",
						Error: "physical resource is unavailable or not authorized on this Node; provider was not started"}
					if outcomeErr := recordMachineNodeProviderOutcome(executionCtx, claimed, result); outcomeErr != nil {
						return fmt.Errorf("record non-started physical resource outcome: %w", outcomeErr)
					}
					if err := reportMachineJobReliably(ctx, base, *id, nodeIdentity.RelayToken,
						claimed, result, *interval); err != nil {
						return err
					}
					return client.finishClaimExecution(claimed)
				}
				return err
			}
			claimed = prepared
			if err := client.beginClaimExecution(claimed); err != nil {
				hub, ok := machineHubFrom(executionCtx)
				if ok && hub.ProviderAdmissions != nil {
					_, _ = hub.ProviderAdmissions.RecordProviderAdmissionOutcome(executionCtx, nodeinbox.ProviderAdmissionOutcome{
						ExecutionID: claimed.executionID, ProviderID: claimed.providerID,
						Attempt: claimed.providerAttempt,
						Class:   nodeinbox.ProviderOutcomeFailedNotInjected,
					})
				}
				return err
			}
			result := executeMachineJobWithHeartbeats(executionCtx, base, *id, nodeIdentity.RelayToken, *interval, claimed)
			if result.Status != "completed" && strings.HasPrefix(result.Error, "restore workspace snapshot: ") {
				fmt.Fprintf(os.Stderr, "Node Worker stage=workspace_snapshot_restore cause=%s\n",
					machineNodeSnapshotFailureCause(strings.TrimPrefix(result.Error, "restore workspace snapshot: ")))
			}
			if err := recordMachineNodeProviderOutcome(executionCtx, claimed, result); err != nil {
				result = machineJobResult{Status: "failed", ThreadID: result.ThreadID,
					WorkspaceRevision: result.WorkspaceRevision,
					Error:             "provider outcome could not be durably recorded; execution will not be retried automatically"}
			}
			if result.ResourceStopState == machineResourceStopUnverified {
				if err := client.markClaimResourceStopUnverified(claimed); err != nil {
					return fmt.Errorf("persist resource stop-unverified fence before Worker result: %w", err)
				}
			}
			if err := reportMachineJobReliably(ctx, base, *id, nodeIdentity.RelayToken, claimed, result, *interval); err != nil {
				return err
			}
			return client.finishClaimExecution(claimed)
		}
		if recovered, err := client.claimTicketJob(); err != nil {
			return err
		} else if recovered != nil {
			return runClaimed(*recovered)
		}
		jobs, err := pollMachineJobs(executionCtx, base, *id, nodeIdentity.RelayToken)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			claimed, claimErr := claimMachineJob(executionCtx, base, *id, nodeIdentity.RelayToken, job)
			if claimErr != nil {
				return claimErr
			}
			if err := runClaimed(claimed); err != nil {
				return err
			}
		}
		return nil
	}
	var localBridge *machineAgentJoinBridge
	var localWake <-chan struct{}
	processMonitor := func() error {
		if *relayOnly || !relayAuthorized.Load() || !relayBound.Load() || machinePinnedHubID(ctx) == "" {
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
		// Keep the local peer and Relay path independent from Control management.
		localErr := processLocal()
		relayErr := processRelay()
		monitorErr := processMonitor()
		return errors.Join(localErr, relayErr, monitorErr)
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
	// Cancel child contexts and join all Agent-owned workers before closing the
	// bridge, inbox databases, or releasing the Node singleton lock.
	defer func() {
		stop()
		cancelRelay()
		agentWorkers.Wait()
	}()
	// Relay binding is an existing peer capability. Probe it independently so
	// an Owner waiting on a new Node-Control key does not stop already-approved
	// peer traffic. A fresh Node is enrolled through the PQ candidate flow.
	probeBound, probeErr := probeMachineNodeBinding(ctx, base, *id, nodeIdentity.RelayToken)
	if probeErr != nil {
		if *once {
			return fmt.Errorf("check existing Relay Node binding: %w", probeErr)
		}
		fmt.Fprintln(os.Stderr, "Relay Node binding probe:", probeErr)
	}
	if probeBound {
		markRelayReady()
	}
	if *once {
		if !(*relayOnly && probeBound) {
			if err := awaitMachineNodeControlBinding(ctx, *stateDir, base, *id, *name,
				nodeIdentity.RelayToken, credentialDigest, true, !*relayOnly, os.Stderr); err != nil {
				return err
			}
		}
		markRelayReady()
	} else {
		// One bounded management worker owns pairing, heartbeat, and jobs.
		// It may wait for Owner approval or run a long Worker task without
		// blocking local peer delivery, Relay reconciliation, or event wakes.
		agentWorkers.Add(1)
		go func() {
			defer agentWorkers.Done()
			if !(*relayOnly && probeBound) {
				for {
					err := awaitMachineNodeControlBinding(ctx, *stateDir, base, *id, *name,
						nodeIdentity.RelayToken, credentialDigest, false, !*relayOnly, os.Stderr)
					if err == nil {
						break
					}
					if ctx.Err() != nil {
						return
					}
					fmt.Fprintln(os.Stderr, "Node-Control binding:", err)
					if waitMachineNodeBindingPoll(ctx) != nil {
						return
					}
				}
			}
			markRelayReady()
			if *relayOnly {
				return
			}
			for {
				if err := recoverMachineNodeControlOutbox(ctx, base, *id, nodeIdentity.RelayToken); err != nil {
					fmt.Fprintln(os.Stderr, "Node-Control outbox recovery:", err)
					timer := time.NewTimer(*interval)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
					continue
				}
				if err := send(); err != nil {
					fmt.Fprintln(os.Stderr, "Node-Control heartbeat:", err)
				}
				if err := processJobs(ctx); err != nil {
					fmt.Fprintln(os.Stderr, "Node-Control jobs:", err)
				}
				timer := time.NewTimer(*interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	if err := heartbeatRelay(); err != nil {
		return err
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
		if !*relayOnly {
			if err := send(); err != nil {
				return err
			}
			if err := processJobs(ctx); err != nil {
				return fmt.Errorf("process machine jobs: %w", err)
			}
		}
		return nil
	}
	// The Node initiates and maintains this outbound connection. Relay can
	// immediately wake it after durable commit, without an inbound Node port.
	// The ticker below still reconciles missed hints after a disconnect.
	wake := make(chan struct{}, 1)
	spaceWake := make(chan struct{}, 1)
	relayRevoked := make(chan error, 1)
	agentWorkers.Add(1)
	go func() {
		defer agentWorkers.Done()
		select {
		case <-ctx.Done():
			return
		case <-relayReady:
			if relayAuthorized.Load() {
				runMachineRelayEventStreamWithSpaces(relayContext, base, *id, wake, spaceWake, relayRevoked)
			}
		}
	}()
	agentWorkers.Add(1)
	go func() {
		defer agentWorkers.Done()
		runMachineSpaceSyncWorker(relayContext, localBridge, spaceWake, *interval)
	}()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	var relayReadyCase <-chan struct{} = relayReady
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-relayRevoked:
			disableRelay(err)
			return nodeCredentialRevokedError(err)
		case <-relayReadyCase:
			relayReadyCase = nil
			if err := heartbeatRelay(); err != nil {
				return err
			}
			if err := processRelay(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
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
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
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
		cancel()
		<-heartbeatDone
		select {
		case err := <-revoked:
			return machineJobResult{Status: "failed", Error: err.Error()}
		default:
			return result
		}
	}
	if job.WorkspaceSnapshotDigest != "" {
		if job.WorkspaceID == "" {
			return finish(machineJobResult{Status: "failed", Error: "workspace snapshot requires a workspace ID"})
		}
		if err := downloadBoundNodeSnapshot(executionCtx, base, machineID, nodeToken, job, workspace); err != nil {
			return finish(machineJobResult{Status: "failed", Error: "restore workspace snapshot: " + err.Error()})
		}
	}
	done := make(chan machineJobResult, 1)
	go func() {
		defer close(done)
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
			cancel()
			<-done // Cancellation is not proof that the Runtime has exited.
			<-heartbeatDone
			return machineJobResult{Status: "failed", Error: err.Error()}
		case <-ctx.Done():
			cancel()
			<-done // Keep Node ownership until the child confirms termination.
			<-heartbeatDone
			return machineJobResult{Status: "failed", Error: "Node stopped while the Worker outcome was uncertain"}
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
