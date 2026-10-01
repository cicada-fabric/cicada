package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

var errMachineNodePhysicalResourceClaim = errors.New("Node physical resource claim is invalid or unavailable")

func newMachineNodeControlClaimTicket(ctx context.Context, state machineNodeControlState,
	route nodewire.Route, job machineJob, responsePacket []byte) (machineNodeControlClaimTicket, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" || hub.NodeID == "" || hub.NodeID != job.MachineID ||
		state.NodeID != hub.NodeID || state.HubID != hub.HubID || state.BindingID == "" ||
		state.BindingVersion == 0 || state.NodeKeyEpoch == 0 ||
		route.Direction != nodewire.DirectionRequest || route.Operation != "node.jobs.claim" ||
		route.NodeID != state.NodeID || route.HubID != state.HubID ||
		route.BindingID != state.BindingID || route.BindingVersion != state.BindingVersion ||
		route.NodeKeyEpoch != state.NodeKeyEpoch || route.OperationID == "" || route.Sequence == 0 ||
		job.WorkerID == "" || job.Attempt <= 0 || len(responsePacket) == 0 {
		return machineNodeControlClaimTicket{}, errors.New("Node-Control claim lacks its trusted Hub/Node/binding/Worker identity")
	}
	providerID := harness.Canonical(job.Harness)
	if providerID == "" {
		providerID = "codex"
	}
	executionDigest := sha256.Sum256([]byte(strings.Join([]string{
		"cicada/node-control/provider-execution/v1", state.HubID, state.NodeID,
		state.BindingID, fmt.Sprint(state.BindingVersion), fmt.Sprint(state.NodeKeyEpoch),
		route.OperationID, fmt.Sprint(route.Sequence), job.WorkerID, fmt.Sprint(job.Attempt), providerID,
	}, "\x00")))
	leaseDigest := sha256.Sum256([]byte("cicada/node-control/resource-lease/v1\x00" +
		hex.EncodeToString(executionDigest[:]) + "\x00" + route.OperationID))
	return machineNodeControlClaimTicket{ResponsePacket: append([]byte(nil), responsePacket...),
		WorkerID: job.WorkerID, Attempt: job.Attempt, Phase: "READY",
		ClaimOperationID: route.OperationID, ClaimSequence: route.Sequence,
		BindingID: state.BindingID, BindingVersion: state.BindingVersion, NodeKeyEpoch: state.NodeKeyEpoch,
		ExecutionID: "nodeexec_" + hex.EncodeToString(executionDigest[:]), ProviderID: providerID,
		LeaseID: "nodelease_" + hex.EncodeToString(leaseDigest[:])}, nil
}

func applyMachineNodeControlClaimTicket(job *machineJob, ticket machineNodeControlClaimTicket) {
	if job == nil {
		return
	}
	job.executionID, job.providerID = ticket.ExecutionID, ticket.ProviderID
	job.resourceID, job.leaseID, job.fencingEpoch = ticket.ResourceID, ticket.LeaseID, ticket.FencingEpoch
}

func machineNodeExecutionResourceID(stateRoot string, resources map[string]any) (string, error) {
	requestedValue, requested := resources["physical_resource_id"]
	if !requested {
		return "", nil
	}
	if strings.TrimSpace(stateRoot) == "" {
		return "", errors.New("shared Node execution state root is unavailable")
	}
	requestedID, ok := requestedValue.(string)
	if !ok || !validMachinePhysicalResourceID(strings.TrimSpace(requestedID)) {
		return "", fmt.Errorf("%w: Hub claim physical_resource_id must be canonical gpu/N or physical/<lowercase SHA-256>", errMachineNodePhysicalResourceClaim)
	}
	configured := strings.TrimSpace(envOr("CICADA_NODE_RESOURCE_ID", ""))
	if configured == "" || !validMachinePhysicalResourceID(configured) {
		return "", fmt.Errorf("%w: Hub claim requested a physical resource that is not configured by this Node operator", errMachineNodePhysicalResourceClaim)
	}
	if strings.TrimSpace(requestedID) != configured {
		return "", fmt.Errorf("%w: Hub claim physical resource does not match the Node operator's trusted resource mapping", errMachineNodePhysicalResourceClaim)
	}
	return configured, nil
}

var machinePhysicalResourceDigestPattern = regexp.MustCompile(`^physical/[0-9a-f]{64}$`)

func validMachinePhysicalResourceID(value string) bool {
	if machinePhysicalResourceDigestPattern.MatchString(value) {
		return true
	}
	if !strings.HasPrefix(value, "gpu/") {
		return false
	}
	index := strings.TrimPrefix(value, "gpu/")
	parsed, err := strconv.ParseUint(index, 10, 32)
	return err == nil && strconv.FormatUint(parsed, 10) == index
}

func machineNodePhysicalResourceCapabilities(capabilities map[string]any) map[string]any {
	configured := strings.TrimSpace(envOr("CICADA_NODE_RESOURCE_ID", ""))
	if !validMachinePhysicalResourceID(configured) {
		return capabilities
	}
	projected := make(map[string]any, len(capabilities)+1)
	for key, value := range capabilities {
		projected[key] = value
	}
	projected["physical_resource_id"] = configured
	return projected
}

func machineNativeContextScope(ctx context.Context, harnessName, nativeSessionID,
	endpointID, bindingID string, bindingEpoch uint64, groupID, networkID,
	groupPolicy, networkPolicy string) (nodeinbox.NativeContextScopeInput, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" || hub.NodeID == "" || hub.WriterScope == "" ||
		endpointID == "" || bindingID == "" || bindingEpoch == 0 {
		return nodeinbox.NativeContextScopeInput{}, errors.New("native scope lacks trusted Node and binding identity")
	}
	groupID, networkID = strings.TrimSpace(groupID), strings.TrimSpace(networkID)
	if groupID == "" && networkID == "" {
		return nodeinbox.NativeContextScopeInput{}, errors.New("native scope lacks its authorized Group or Network")
	}
	policy := ""
	if groupPolicy == nodeinbox.NativeContextPolicyDedicatedThread ||
		networkPolicy == nodeinbox.NativeContextPolicyDedicatedThread {
		policy = nodeinbox.NativeContextPolicyDedicatedThread
	} else if networkPolicy == nodeinbox.NativeContextPolicyDedicatedNetwork {
		policy = nodeinbox.NativeContextPolicyDedicatedNetwork
	} else if groupPolicy == nodeinbox.NativeContextPolicyGroupScoped {
		policy = nodeinbox.NativeContextPolicyGroupScoped
	}
	return nodeinbox.NativeContextScopeInput{AccountID: hub.WriterScope, Harness: harnessName,
		NativeSessionID: nativeSessionID, HubID: hub.HubID, NetworkID: networkID,
		GroupID: groupID, ContextPolicy: policy, EndpointID: endpointID,
		BindingID: bindingID, BindingEpoch: bindingEpoch}, nil
}

func machineNativeContextScopeFromMetadata(ctx context.Context, harnessName, nativeSessionID,
	endpointID, bindingID string, bindingEpoch uint64,
	metadata store.NativeContextScopeMetadata) (nodeinbox.NativeContextScopeInput, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || metadata.HubID == "" || metadata.HubID != hub.HubID {
		return nodeinbox.NativeContextScopeInput{}, errors.New("authoritative native scope belongs to a different Hub")
	}
	return machineNativeContextScope(ctx, harnessName, nativeSessionID, endpointID, bindingID,
		bindingEpoch, metadata.GroupID, metadata.NetworkID,
		metadata.GroupContextPolicy, metadata.NetworkContextPolicy)
}

func recordMachineNativeContextMetadata(ctx context.Context, harnessName, nativeSessionID,
	endpointID, bindingID string, bindingEpoch uint64,
	metadata store.NativeContextScopeMetadata) (*nodeinbox.NativeContextScopeDecision, error) {
	if _, managed := machineHubFrom(ctx); !managed {
		return &nodeinbox.NativeContextScopeDecision{Accepted: true,
			NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}, nil
	}
	scope, err := machineNativeContextScopeFromMetadata(ctx, harnessName, nativeSessionID,
		endpointID, bindingID, bindingEpoch, metadata)
	if err != nil {
		return nil, err
	}
	return checkMachineNativeContext(ctx, scope)
}

func machineNativeContextScopeFromLocalAuthorization(ctx context.Context,
	endpoint store.LocalDeliveryEndpointAuthorization, harnessName, nativeSessionID string,
) (nodeinbox.NativeContextScopeInput, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.HubID == "" {
		return nodeinbox.NativeContextScopeInput{}, errors.New("local native scope lacks a pinned Hub")
	}
	return machineNativeContextScope(ctx, harnessName, nativeSessionID,
		endpoint.EndpointID, endpoint.BindingID, endpoint.BindingEpoch,
		endpoint.GroupID, endpoint.NetworkID, endpoint.GroupContextPolicy,
		endpoint.NetworkContextPolicy)
}

func checkMachineNativeContext(ctx context.Context,
	input nodeinbox.NativeContextScopeInput) (*nodeinbox.NativeContextScopeDecision, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok {
		return &nodeinbox.NativeContextScopeDecision{Accepted: true, ContextPolicy: input.ContextPolicy,
			NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}, nil
	}
	if hub.NativeContexts == nil || input.HubID != hub.HubID {
		if !hub.RequireNativeContext && hub.NativeContexts == nil {
			return &nodeinbox.NativeContextScopeDecision{Accepted: true, ContextPolicy: input.ContextPolicy,
				NativeHistoryCoverage: nodeinbox.NativeContextHistoryCoverageNotChecked}, nil
		}
		return nil, errors.New("shared NativeContext registry is unavailable for this Hub")
	}
	decision, err := hub.NativeContexts.CheckAndRecordNativeContext(ctx, input)
	if err != nil {
		return nil, err
	}
	if decision == nil || !decision.Accepted {
		return nil, errors.New("native context scope was not accepted")
	}
	return decision, nil
}

func prepareMachineNodeClaimExecution(ctx context.Context, client *machineNodeControlClient,
	job machineJob) (machineJob, *nodeinbox.ProviderAdmissionDecision, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok ||
		hub.HubID == "" || hub.NodeID == "" || job.MachineID != hub.NodeID ||
		job.WorkerID == "" || job.Attempt <= 0 || job.executionID == "" ||
		job.providerID == "" || job.leaseID == "" {
		return job, nil, errors.New("managed Worker lacks Node-Control provider/resource execution authority")
	}
	providerLedger := hub.ProviderAdmissions
	if providerLedger == nil {
		return job, nil, errors.New("shared Node provider admission ledger is unavailable")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	ticket := client.state.ClaimTicket
	if ticket == nil || ticket.Phase != "READY" || ticket.WorkerID != job.WorkerID ||
		ticket.Attempt != job.Attempt || ticket.ExecutionID != job.executionID ||
		ticket.ProviderID != job.providerID || ticket.LeaseID != job.leaseID ||
		ticket.BindingID != client.state.BindingID || ticket.BindingVersion != client.state.BindingVersion ||
		ticket.NodeKeyEpoch != client.state.NodeKeyEpoch {
		return job, nil, errors.New("managed Worker claim does not match its exact durable Node-Control ticket")
	}
	admit := func() (*nodeinbox.ProviderAdmissionDecision, error) {
		decision, err := providerLedger.AdmitProviderAttempt(ctx, nodeinbox.ProviderAdmissionRequest{
			ExecutionID: ticket.ExecutionID, ProviderID: ticket.ProviderID})
		if err != nil {
			return nil, err
		}
		if decision == nil {
			return nil, errors.New("Node provider admission returned no decision")
		}
		if !decision.Admitted {
			if decision.State == nodeinbox.ProviderAdmissionBackoff && decision.Retryable {
				return decision, fmt.Errorf("provider attempt is held until %s", decision.NextRetryAt)
			}
			return decision, fmt.Errorf("provider attempt requires explicit reconciliation (state %s)", decision.State)
		}
		return decision, nil
	}
	resourceID, err := machineNodeExecutionResourceID(hub.WriterRoot, job.Resources)
	if err != nil {
		decision, admitErr := admit()
		if admitErr != nil {
			return job, decision, admitErr
		}
		return job, decision, err
	}
	if resourceID == "" {
		if ticket.ResourceID != "" || ticket.FencingEpoch != 0 {
			return job, nil, errors.New("Node-Control claim has a stale physical resource fence absent from its authoritative job")
		}
	} else {
		if hub.ResourceExecutions == nil {
			decision, admitErr := admit()
			if admitErr != nil {
				return job, decision, admitErr
			}
			return job, decision, fmt.Errorf("%w: Node physical resource execution authority is unavailable", errMachineNodePhysicalResourceClaim)
		}
		if ticket.ResourceID != "" {
			if ticket.ResourceID != resourceID || ticket.FencingEpoch <= 0 {
				decision, admitErr := admit()
				if admitErr != nil {
					return job, decision, admitErr
				}
				return job, decision, fmt.Errorf("%w: Node-Control physical resource fence differs from the authoritative Hub claim", errMachineNodePhysicalResourceClaim)
			}
		} else {
			previous, inspectErr := hub.ResourceExecutions.Inspect(resourceID)
			nextEpoch := int64(1)
			if inspectErr == nil {
				if previous == nil || (previous.State != nodelock.ResourceExecutionStopConfirmed &&
					previous.State != nodelock.ResourceExecutionStartFailed) || previous.FencingEpoch <= 0 ||
					previous.FencingEpoch == int64(^uint64(0)>>1) {
					decision, admitErr := admit()
					if admitErr != nil {
						return job, decision, admitErr
					}
					return job, decision, nodelock.ErrResourceExecutionBusy
				}
				nextEpoch = previous.FencingEpoch + 1
			} else if !errors.Is(inspectErr, os.ErrNotExist) {
				// A missing marker is the only clean first-use case; Inspect may return
				// os.ErrNotExist for an uninitialized resource slot.
				return job, nil, inspectErr
			}
			previousState := cloneMachineNodeControlState(client.state)
			ticket.ResourceID, ticket.FencingEpoch = resourceID, nextEpoch
			if err := client.persistLocked(); err != nil {
				client.state = previousState
				return job, nil, err
			}
		}
	}
	decision, err := admit()
	if err != nil {
		return job, decision, err
	}
	applyMachineNodeControlClaimTicket(&job, *ticket)
	return job, decision, nil
}

func recordMachineNodeProviderOutcome(ctx context.Context, job machineJob, result machineJobResult) error {
	hub, ok := machineHubFrom(ctx)
	if !ok {
		return nil
	}
	providerLedger := hub.ProviderAdmissions
	if providerLedger == nil && !hub.RequireNativeContext {
		return nil
	}
	if providerLedger == nil {
		return errors.New("shared Node provider admission ledger is unavailable")
	}
	if job.executionID == "" || job.providerID == "" {
		return errors.New("managed provider outcome lacks its durable execution identity")
	}
	class := nodeinbox.ProviderOutcomeFailedNotInjected
	if result.Status == "completed" {
		class = nodeinbox.ProviderOutcomeCompleted
	} else if result.providerStarted {
		class = nodeinbox.ProviderOutcomeInjectionUncertain
	}
	_, err := providerLedger.RecordProviderAdmissionOutcome(ctx, nodeinbox.ProviderAdmissionOutcome{
		ExecutionID: job.executionID, ProviderID: job.providerID, Class: class})
	return err
}

// machineNodeExecutionContext pins a single-Hub Agent context only from the
// durable key binding that the Owner explicitly confirmed. A configured Hub
// ID remains an exact constraint; an empty value is filled from the approved
// local state after pairing so managed execution does not depend on a
// deployment-specific CICADA_HUB_ID environment variable.
func machineNodeExecutionContext(ctx context.Context, client *machineNodeControlClient) (context.Context, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || client == nil {
		return nil, errors.New("managed Node execution lacks its Hub context")
	}
	client.mu.Lock()
	state := cloneMachineNodeControlState(client.state)
	public := client.identity.Public()
	client.mu.Unlock()
	if hub.NodeID == "" || hub.NodeID != state.NodeID || hub.Origin == "" || hub.Origin != state.HubOrigin ||
		state.BindingID == "" || state.BindingVersion == 0 || state.NodeKeyEpoch == 0 ||
		state.HubID == "" || state.HubKeyID == "" || state.HubPublicIdentity.ID != state.HubKeyID ||
		state.NodeKeyID != public.ID || state.NodeKeyFingerprint != nodewire.IdentityFingerprint(public) ||
		hub.HubID != "" && hub.HubID != state.HubID {
		return nil, errors.New("managed Node execution binding does not match the locally approved Hub context")
	}
	hub.HubID = state.HubID
	return withMachineHubContext(ctx, hub), nil
}

func persistMachineNodeClaimResourceFence(client *machineNodeControlClient,
	job machineJob) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	ticket := client.state.ClaimTicket
	if ticket == nil || ticket.Phase != "READY" || ticket.WorkerID != job.WorkerID ||
		ticket.Attempt != job.Attempt || ticket.ExecutionID != job.executionID ||
		ticket.ResourceID != job.resourceID || ticket.FencingEpoch != job.fencingEpoch ||
		(ticket.ResourceID != "" && ticket.FencingEpoch <= 0) ||
		(ticket.ResourceID == "" && ticket.FencingEpoch != 0) {
		return errors.New("Node provider/resource fence differs from the durable claim ticket")
	}
	return nil
}

func confirmMachineNodeResourceStop(execution *nodelock.ResourceExecution,
	request nodelock.ResourceExecutionRequest) error {
	if execution == nil {
		return nodelock.ErrResourceExecutionUnknown
	}
	if request.ResourceID == "" || request.LeaseID == "" || request.FencingEpoch <= 0 || request.ExecutionID == "" {
		return nodelock.ErrResourceExecutionInvalid
	}
	// waitChildProcessTree only drains the original process group. It cannot
	// prove that a setsid descendant or an external provider process stopped, so
	// no STOP_CONFIRMED receipt is minted here. Keep the physical fence held for
	// an explicit trusted runtime/operator verifier instead.
	if err := execution.QuarantineStopUnverified(); err != nil {
		return err
	}
	return nodelock.ErrResourceStopUnverified
}

func runMachineNodeResourceCommand(ctx context.Context, job machineJob, command *exec.Cmd) (error, error, bool) {
	hub, managed := machineHubFrom(ctx)
	if !managed {
		configureChildProcess(command)
		runErr := command.Run()
		return runErr, waitChildProcessTree(command), command.Process != nil
	}
	if job.executionID == "" || job.providerID == "" || job.leaseID == "" {
		return errors.New("managed Worker lacks its durable provider execution identity"), nil, false
	}
	if job.resourceID == "" && job.fencingEpoch == 0 {
		// Ordinary Workers do not acquire the Node's whole-host physical resource
		// merely by being managed. Their exact execution/provider identity and
		// NativeWriter remain fenced; only an explicit Hub claim for a physical
		// resource enters the resource ledger below.
		configureChildProcess(command)
		runErr := command.Run()
		return runErr, waitChildProcessTree(command), command.Process != nil
	}
	if hub.ResourceExecutions == nil || job.resourceID == "" || job.leaseID == "" || job.fencingEpoch <= 0 {
		return errors.New("managed Worker physical-resource lease lacks its trusted execution fence"), nil, false
	}
	request := nodelock.ResourceExecutionRequest{ResourceID: job.resourceID, LeaseID: job.leaseID,
		FencingEpoch: job.fencingEpoch, ExecutionID: job.executionID}
	configureChildProcess(command)
	execution, startErr := hub.ResourceExecutions.StartCommand(request, command)
	if startErr != nil && command.Process == nil {
		return startErr, nil, false
	}
	started := command.Process != nil
	var runErr error
	if started {
		if execution != nil {
			runErr = execution.Wait()
		} else {
			runErr = command.Wait()
		}
	}
	stopErr := waitChildProcessTree(command)
	if stopErr != nil {
		if execution != nil {
			_ = execution.Quarantine()
		}
		return errors.Join(startErr, runErr), errors.Join(nodelock.ErrResourceStopUnverified, stopErr), started
	}
	if confirmErr := confirmMachineNodeResourceStop(execution, request); confirmErr != nil {
		if execution != nil && !errors.Is(confirmErr, nodelock.ErrResourceStopUnverified) {
			_ = execution.Quarantine()
		}
		return errors.Join(startErr, runErr), confirmErr, started
	}
	return errors.Join(startErr, runErr), nil, started
}
