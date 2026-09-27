package control

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	// ClientStatusSnapshotContractVersion versions the JSON shape independently
	// of the HTTP route or the Client↔Control encryption protocol.
	ClientStatusSnapshotContractVersion  = 1
	ClientStatusSnapshotScopeSingleOwner = "single_owner_control_database"
	ClientStatusSnapshotScopeAttributed  = "owner_attributed_v2"
)

type ClientStatusCode interface {
	~string
}

// ClientStatusObservation associates a state with the backend fact that
// supports it. Unknown is represented explicitly with Known=false; callers
// must not fill in a state from a related object.
type ClientStatusObservation[T ClientStatusCode] struct {
	State      T      `json:"state"`
	Known      bool   `json:"known"`
	ObservedAt string `json:"observed_at,omitempty"`
	Source     string `json:"source"`
	Stale      bool   `json:"stale"`
}

type ClientNodeConnectivity string

const (
	ClientNodeConnected ClientNodeConnectivity = "connected"
	ClientNodeStale     ClientNodeConnectivity = "stale"
	ClientNodeOffline   ClientNodeConnectivity = "offline"
	ClientNodeUnknown   ClientNodeConnectivity = "unknown"
)

type ClientEndpointPresence string

const (
	ClientEndpointOnline  ClientEndpointPresence = "online"
	ClientEndpointIdle    ClientEndpointPresence = "idle"
	ClientEndpointBusy    ClientEndpointPresence = "busy"
	ClientEndpointOffline ClientEndpointPresence = "offline"
	ClientEndpointLeft    ClientEndpointPresence = "left"
	ClientEndpointUnknown ClientEndpointPresence = "unknown"
)

type ClientNativeSessionState string

const (
	ClientNativeSessionKnown       ClientNativeSessionState = "known"
	ClientNativeSessionJoined      ClientNativeSessionState = "joined"
	ClientNativeSessionBindingLost ClientNativeSessionState = "binding_lost"
	ClientNativeSessionUnknown     ClientNativeSessionState = "unknown"
)

type ClientWorkerExecutionState string

const (
	ClientWorkerQueued           ClientWorkerExecutionState = "queued"
	ClientWorkerRunning          ClientWorkerExecutionState = "running"
	ClientWorkerRecovering       ClientWorkerExecutionState = "recovering"
	ClientWorkerVerifying        ClientWorkerExecutionState = "verifying"
	ClientWorkerCompleted        ClientWorkerExecutionState = "completed"
	ClientWorkerFailed           ClientWorkerExecutionState = "failed"
	ClientWorkerCancelled        ClientWorkerExecutionState = "cancelled"
	ClientWorkerOutcomeUncertain ClientWorkerExecutionState = "outcome_uncertain"
	ClientWorkerUnknown          ClientWorkerExecutionState = "unknown"
)

type ClientGoalLifecycleState string

const (
	ClientGoalQueued    ClientGoalLifecycleState = "queued"
	ClientGoalRunning   ClientGoalLifecycleState = "running"
	ClientGoalBlocked   ClientGoalLifecycleState = "blocked"
	ClientGoalPaused    ClientGoalLifecycleState = "paused"
	ClientGoalCompleted ClientGoalLifecycleState = "completed"
	ClientGoalFailed    ClientGoalLifecycleState = "failed"
	ClientGoalCancelled ClientGoalLifecycleState = "cancelled"
	ClientGoalUnknown   ClientGoalLifecycleState = "unknown"
)

type ClientGroupLifecycleState string

const (
	ClientGroupDraft     ClientGroupLifecycleState = "DRAFT"
	ClientGroupActive    ClientGroupLifecycleState = "ACTIVE"
	ClientGroupPaused    ClientGroupLifecycleState = "PAUSED"
	ClientGroupQuiescing ClientGroupLifecycleState = "QUIESCING"
	ClientGroupArchived  ClientGroupLifecycleState = "ARCHIVED"
	ClientGroupUnknown   ClientGroupLifecycleState = "unknown"
)

type ClientTaskState string

const (
	ClientTaskDraft           ClientTaskState = "DRAFT"
	ClientTaskReady           ClientTaskState = "READY"
	ClientTaskClaimed         ClientTaskState = "CLAIMED"
	ClientTaskRunning         ClientTaskState = "RUNNING"
	ClientTaskResultSubmitted ClientTaskState = "RESULT_SUBMITTED"
	ClientTaskCompleted       ClientTaskState = "COMPLETED"
	ClientTaskBlocked         ClientTaskState = "BLOCKED"
	ClientTaskNeedsRevision   ClientTaskState = "NEEDS_REVISION"
	ClientTaskCancelled       ClientTaskState = "CANCELLED"
	ClientTaskUnknown         ClientTaskState = "unknown"
)

type ClientStatusSnapshot struct {
	ContractVersion  int                    `json:"contract_version"`
	ScopeMode        string                 `json:"scope_mode"`
	OwnerPrincipalID string                 `json:"owner_principal_id"`
	CapturedAt       string                 `json:"captured_at"`
	ReadConsistency  string                 `json:"read_consistency"`
	Source           string                 `json:"source"`
	Nodes            []ClientNodeStatus     `json:"nodes"`
	Endpoints        []ClientEndpointStatus `json:"endpoints"`
	Workers          []ClientWorkerStatus   `json:"workers"`
	Goals            []ClientGoalStatus     `json:"goals"`
	Groups           []ClientGroupStatus    `json:"groups"`
	Tasks            []ClientTaskStatus     `json:"tasks"`
}

type ClientNodeStatus struct {
	NodeID       string                                          `json:"node_id"`
	Name         string                                          `json:"name,omitempty"`
	Verified     bool                                            `json:"verified"`
	Connectivity ClientStatusObservation[ClientNodeConnectivity] `json:"node_connectivity"`
}

type ClientEndpointStatus struct {
	EndpointID      string                                            `json:"endpoint_id"`
	Name            string                                            `json:"name,omitempty"`
	PrincipalID     string                                            `json:"principal_id,omitempty"`
	GroupIDs        []string                                          `json:"group_ids"`
	NodeID          string                                            `json:"node_id,omitempty"`
	Harness         string                                            `json:"harness,omitempty"`
	NativeSessionID string                                            `json:"native_session_id,omitempty"`
	Presence        ClientStatusObservation[ClientEndpointPresence]   `json:"presence"`
	NativeSession   ClientStatusObservation[ClientNativeSessionState] `json:"native_session"`
}

type ClientWorkerStatus struct {
	WorkerID  string                                              `json:"worker_id"`
	GoalID    string                                              `json:"goal_id,omitempty"`
	NodeID    string                                              `json:"node_id,omitempty"`
	Harness   string                                              `json:"harness,omitempty"`
	Attempt   int                                                 `json:"attempt"`
	Execution ClientStatusObservation[ClientWorkerExecutionState] `json:"worker_execution"`
}

type ClientGoalStatus struct {
	GoalID    string                                            `json:"goal_id"`
	Version   int64                                             `json:"lifecycle_version"`
	ParentID  string                                            `json:"parent_goal_id,omitempty"`
	NodeID    string                                            `json:"node_id,omitempty"`
	WorkerIDs []string                                          `json:"worker_ids"`
	Lifecycle ClientStatusObservation[ClientGoalLifecycleState] `json:"goal_lifecycle"`
}

type ClientGroupStatus struct {
	GroupID       string                                             `json:"group_id"`
	ParentGroupID string                                             `json:"parent_group_id,omitempty"`
	Name          string                                             `json:"name,omitempty"`
	Version       int64                                              `json:"version"`
	Lifecycle     ClientStatusObservation[ClientGroupLifecycleState] `json:"lifecycle"`
}

type ClientTaskStatus struct {
	TaskID           string                                   `json:"task_id"`
	GroupID          string                                   `json:"group_id"`
	GoalID           string                                   `json:"goal_id,omitempty"`
	OwnerPrincipalID string                                   `json:"owner_principal_id,omitempty"`
	OwnerEndpointID  string                                   `json:"owner_endpoint_id,omitempty"`
	Revision         int64                                    `json:"revision"`
	OwnerEpoch       int64                                    `json:"owner_epoch"`
	Lifecycle        ClientStatusObservation[ClientTaskState] `json:"task_lifecycle"`
}

// BuildClientStatusSnapshot constructs a read-only projection from the current
// Control store. The caller must authenticate the client and pass its verified
// owner Principal ID. The resident manager retains its legacy dedicated-store
// view. External owners receive only owner-attributed Nodes/Goals and their
// own Groups/Endpoints; ownerless legacy rows never enter that view. Workers
// are scoped through their owner-attributed Goal because they lack an owner
// column. It must not be exposed through the legacy
// bearer API. The result contains metadata and statuses only; it never reads
// peer message bodies, worker prompts/logs, credentials, or E2EE key material.
func (c *Control) BuildClientStatusSnapshot(authenticatedOwnerPrincipalID string) (*ClientStatusSnapshot, error) {
	if err := c.ValidateClientSessionOwner(authenticatedOwnerPrincipalID); err != nil {
		return nil, err
	}
	ownerID := strings.TrimSpace(authenticatedOwnerPrincipalID)
	residentOwner := ownerID == c.Identity().ID
	scopeMode := ClientStatusSnapshotScopeAttributed
	if residentOwner {
		scopeMode = ClientStatusSnapshotScopeSingleOwner
	}

	capturedAt := time.Now().UTC()
	snapshot := &ClientStatusSnapshot{
		ContractVersion:  ClientStatusSnapshotContractVersion,
		ScopeMode:        scopeMode,
		OwnerPrincipalID: ownerID,
		CapturedAt:       capturedAt.Format(time.RFC3339Nano),
		ReadConsistency:  "best_effort",
		Source:           "control.sqlite.read_projection",
		Nodes:            make([]ClientNodeStatus, 0),
		Endpoints:        make([]ClientEndpointStatus, 0),
		Workers:          make([]ClientWorkerStatus, 0),
		Goals:            make([]ClientGoalStatus, 0),
		Groups:           make([]ClientGroupStatus, 0),
		Tasks:            make([]ClientTaskStatus, 0),
	}

	groups, err := c.store.ListGroups(store.GroupFilter{Owner: ownerID, Limit: 1000})
	if err != nil {
		return nil, err
	}
	ownedGroups := make(map[string]store.Group, len(groups))
	for _, group := range groups {
		// Recheck ownership in the service layer in case a Store implementation
		// later broadens its filtering behavior.
		if group.OwnerPrincipalID != ownerID {
			continue
		}
		ownedGroups[group.ID] = group
		snapshot.Groups = append(snapshot.Groups, ClientGroupStatus{
			GroupID: group.ID, ParentGroupID: group.ParentGroupID, Name: group.Name,
			Version:   group.Version,
			Lifecycle: clientGroupLifecycle(group.State, group.UpdatedAt),
		})
	}

	endpointsByID := make(map[string]*ClientEndpointStatus)
	for _, group := range snapshot.Groups {
		// The Store query applies Endpoint-group and Principal-membership checks
		// before returning any Endpoint. It only returns currently active Group
		// membership, so archived or paused Groups remain visible as Groups but
		// do not expose their Endpoint roster through this projection.
		endpoints, err := c.store.ListEndpointsV2(store.EndpointV2Filter{GroupID: group.GroupID, Limit: 1000})
		if err != nil {
			return nil, err
		}
		for _, endpoint := range endpoints {
			if _, ok := ownedGroups[group.GroupID]; !ok {
				continue
			}
			if !residentOwner {
				principal, principalErr := c.store.GetPrincipal(endpoint.PrincipalID)
				if principalErr != nil || principal.OwnerID != ownerID || endpoint.Owner != ownerID {
					continue
				}
			}
			entry := endpointsByID[endpoint.ID]
			if entry == nil {
				presence := clientEndpointPresence(endpoint.Status, endpoint.LastSeen, capturedAt, c.clientStatusStaleAfter())
				native := clientNativeSession(endpoint)
				entry = &ClientEndpointStatus{
					EndpointID: endpoint.ID, Name: endpoint.Name, PrincipalID: endpoint.PrincipalID,
					GroupIDs: []string{}, NodeID: endpoint.MachineID, Harness: endpoint.Harness,
					NativeSessionID: endpoint.NativeSessionID,
					Presence:        presence, NativeSession: native,
				}
				endpointsByID[endpoint.ID] = entry
			}
			entry.GroupIDs = append(entry.GroupIDs, group.GroupID)
		}
	}

	machines, err := c.store.ListMachines()
	if err != nil {
		return nil, err
	}
	bindings, err := c.store.ListNodeDeviceBindings(ownerID)
	if err != nil {
		return nil, err
	}
	verifiedNodes := make(map[string]store.NodeDeviceBinding, len(bindings))
	boundNodeHistory := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		boundNodeHistory[binding.NodeID] = true
		if binding.Authorized {
			verifiedNodes[binding.NodeID] = binding
		}
	}
	nodeStates := make(map[string]ClientStatusObservation[ClientNodeConnectivity], len(machines))
	for _, machine := range machines {
		if !residentOwner && (machine.OwnerID != ownerID || !boundNodeHistory[machine.ID]) {
			continue
		}
		state := clientNodeConnectivity(machine, capturedAt, c.clientStatusStaleAfter())
		if boundNodeHistory[machine.ID] && !verifiedNodes[machine.ID].Authorized {
			state = ClientStatusObservation[ClientNodeConnectivity]{
				State: ClientNodeUnknown, Known: false, Stale: true,
				Source: "store.node_owner_bindings_v2",
			}
		}
		nodeStates[machine.ID] = state
		snapshot.Nodes = append(snapshot.Nodes, ClientNodeStatus{
			NodeID: machine.ID, Name: machine.Name, Verified: verifiedNodes[machine.ID].Authorized, Connectivity: state,
		})
	}
	for nodeID, binding := range verifiedNodes {
		if _, exists := nodeStates[nodeID]; exists {
			continue
		}
		state := ClientStatusObservation[ClientNodeConnectivity]{
			State: ClientNodeUnknown, Known: false, Stale: true,
			Source: "store.node_owner_bindings_v2",
		}
		nodeStates[nodeID] = state
		snapshot.Nodes = append(snapshot.Nodes, ClientNodeStatus{
			NodeID: nodeID, Name: binding.NodeName, Verified: true, Connectivity: state,
		})
	}
	for _, endpoint := range endpointsByID {
		if !residentOwner && !verifiedNodes[endpoint.NodeID].Authorized {
			endpoint.Presence = ClientStatusObservation[ClientEndpointPresence]{
				State: ClientEndpointUnknown, Known: false, Stale: true,
				Source: "store.node_owner_bindings_v2",
			}
			endpoint.NativeSession = ClientStatusObservation[ClientNativeSessionState]{
				State: ClientNativeSessionUnknown, Known: false, Stale: true,
				Source: "store.node_owner_bindings_v2",
			}
		}
		sort.Strings(endpoint.GroupIDs)
		snapshot.Endpoints = append(snapshot.Endpoints, *endpoint)
	}

	goals, err := c.store.ListGoals()
	if err != nil {
		return nil, err
	}
	if !residentOwner {
		ownedGoals := goals[:0]
		for _, goal := range goals {
			if goal.OwnerID == ownerID {
				ownedGoals = append(ownedGoals, goal)
			}
		}
		goals = ownedGoals
	}
	workers, err := c.store.ListWorkers()
	if err != nil {
		return nil, err
	}
	if !residentOwner {
		goalIDs := make(map[string]bool, len(goals))
		for _, goal := range goals {
			goalIDs[goal.ID] = true
		}
		ownedWorkers := workers[:0]
		for _, worker := range workers {
			if goalIDs[worker.GoalID] {
				ownedWorkers = append(ownedWorkers, worker)
			}
		}
		workers = ownedWorkers
	}
	workersByGoal := make(map[string][]store.Worker)
	for _, worker := range workers {
		workersByGoal[worker.GoalID] = append(workersByGoal[worker.GoalID], worker)
	}
	workerStates := make(map[string]ClientStatusObservation[ClientWorkerExecutionState], len(workers))
	for _, worker := range workers {
		state := clientWorkerExecution(worker.Status, worker.UpdatedAt)
		if isInFlightWorkerState(state.State) {
			node, found := nodeStates[worker.MachineID]
			if !found || node.State == ClientNodeOffline || node.State == ClientNodeStale || node.State == ClientNodeUnknown {
				state.Stale = true
			}
		}
		workerStates[worker.ID] = state
		snapshot.Workers = append(snapshot.Workers, ClientWorkerStatus{
			WorkerID: worker.ID, GoalID: worker.GoalID, NodeID: worker.MachineID,
			Harness: worker.Harness, Attempt: worker.Attempt, Execution: state,
		})
	}
	for _, goal := range goals {
		workerIDs := make([]string, 0, len(workersByGoal[goal.ID]))
		staleInFlight := false
		for _, worker := range workersByGoal[goal.ID] {
			workerIDs = append(workerIDs, worker.ID)
			if state, ok := workerStates[worker.ID]; ok && isInFlightWorkerState(state.State) && state.Stale {
				staleInFlight = true
			}
		}
		sort.Strings(workerIDs)
		lifecycle := clientGoalLifecycle(goal.Status, goal.UpdatedAt)
		if lifecycle.State == ClientGoalRunning && staleInFlight {
			lifecycle.Stale = true
		}
		snapshot.Goals = append(snapshot.Goals, ClientGoalStatus{
			GoalID: goal.ID, Version: goal.LifecycleVersion, ParentID: goal.ParentGoalID, NodeID: goal.MachineID,
			WorkerIDs: workerIDs, Lifecycle: lifecycle,
		})
	}

	groupIDs := make([]string, 0, len(ownedGroups))
	for groupID := range ownedGroups {
		groupIDs = append(groupIDs, groupID)
	}
	sort.Strings(groupIDs)
	for _, groupID := range groupIDs {
		tasks, err := c.store.ListSharedTasks(groupID, 500)
		if err != nil {
			return nil, err
		}
		for _, task := range tasks {
			// Again enforce the Group owner scope at the projection boundary.
			if task.GroupID != groupID {
				continue
			}
			snapshot.Tasks = append(snapshot.Tasks, ClientTaskStatus{
				TaskID: task.ID, GroupID: task.GroupID, GoalID: task.GoalID,
				OwnerPrincipalID: task.OwnerPrincipalID, OwnerEndpointID: task.OwnerEndpointID,
				Revision: task.Revision, OwnerEpoch: task.OwnerEpoch,
				Lifecycle: clientTaskLifecycle(task, capturedAt),
			})
		}
	}

	// Keep references to missing Machine records visible as unknown rather than
	// silently dropping the relationship or inferring connectivity.
	for _, worker := range workers {
		addUnknownClientNode(snapshot, nodeStates, worker.MachineID)
	}
	for _, goal := range goals {
		addUnknownClientNode(snapshot, nodeStates, goal.MachineID)
	}
	for _, endpoint := range snapshot.Endpoints {
		addUnknownClientNode(snapshot, nodeStates, endpoint.NodeID)
	}

	sort.Slice(snapshot.Nodes, func(i, j int) bool { return snapshot.Nodes[i].NodeID < snapshot.Nodes[j].NodeID })
	sort.Slice(snapshot.Endpoints, func(i, j int) bool { return snapshot.Endpoints[i].EndpointID < snapshot.Endpoints[j].EndpointID })
	sort.Slice(snapshot.Workers, func(i, j int) bool { return snapshot.Workers[i].WorkerID < snapshot.Workers[j].WorkerID })
	sort.Slice(snapshot.Goals, func(i, j int) bool { return snapshot.Goals[i].GoalID < snapshot.Goals[j].GoalID })
	sort.Slice(snapshot.Groups, func(i, j int) bool { return snapshot.Groups[i].GroupID < snapshot.Groups[j].GroupID })
	sort.Slice(snapshot.Tasks, func(i, j int) bool { return snapshot.Tasks[i].TaskID < snapshot.Tasks[j].TaskID })
	// Recheck revocation after the multi-table projection. Store APIs expose
	// independently locked reads, so this is a best-effort snapshot rather
	// than one transaction; it still fails closed if the owner was revoked
	// during construction.
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func addUnknownClientNode(snapshot *ClientStatusSnapshot, nodeStates map[string]ClientStatusObservation[ClientNodeConnectivity], nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	if _, exists := nodeStates[nodeID]; exists {
		return
	}
	state := ClientStatusObservation[ClientNodeConnectivity]{
		State: ClientNodeUnknown, Known: false,
		Source: "store.machines.status+last_seen", Stale: true,
	}
	nodeStates[nodeID] = state
	snapshot.Nodes = append(snapshot.Nodes, ClientNodeStatus{NodeID: nodeID, Connectivity: state})
}

// ValidateClientOwnerScope verifies that the already-authenticated Client
// owner is the one human Principal managed by this Control instance. Callers
// must authenticate the connection first; this method is a scope check, not
// an authentication mechanism. The current Store schema supports this guard
// only for a dedicated single-owner Control database.
func (c *Control) ValidateClientOwnerScope(ownerPrincipalID string) error {
	if c == nil || c.store == nil || c.identity == nil {
		return errors.New("client owner scope requires an initialized Control")
	}
	ownerID := strings.TrimSpace(ownerPrincipalID)
	identityID := strings.TrimSpace(c.Identity().ID)
	if ownerID == "" || identityID == "" || ownerID != identityID {
		return fmt.Errorf("%w: authenticated owner does not match this Control", ErrPermissionDenied)
	}
	owner, err := c.store.GetPrincipal(ownerID)
	if err != nil {
		if errors.Is(err, store.ErrPrincipalNotFound) {
			return fmt.Errorf("%w: owner Principal is not registered", ErrPermissionDenied)
		}
		return err
	}
	if owner.ID != identityID || owner.OwnerID != owner.ID || owner.Kind != store.PrincipalKindHuman || owner.Status != store.PrincipalStatusActive {
		return fmt.Errorf("%w: owner Principal is not an active self-owned human", ErrPermissionDenied)
	}
	return nil
}

func (c *Control) clientStatusStaleAfter() time.Duration {
	if c.config.MachineStaleAfter > 0 {
		return c.config.MachineStaleAfter
	}
	return 2 * time.Minute
}

func clientNodeConnectivity(machine store.Machine, now time.Time, staleAfter time.Duration) ClientStatusObservation[ClientNodeConnectivity] {
	observation := ClientStatusObservation[ClientNodeConnectivity]{
		State: ClientNodeUnknown, Source: "store.machines.status+last_seen",
	}
	if machine.ID == "control-local" || machine.ID == "worker-local" {
		// These are logical local executors, not remote heartbeats. Control is
		// observing its own process at capture time.
		observation.State = ClientNodeConnected
		observation.Known = true
		observation.Source = "control.local_machine_registry"
		observation.ObservedAt = now.UTC().Format(time.RFC3339Nano)
		return observation
	}
	lastSeen, parsed := parseClientStatusTime(machine.LastSeen)
	observation.ObservedAt = strings.TrimSpace(machine.LastSeen)
	if parsed {
		observation.Stale = now.Sub(lastSeen) > staleAfter || lastSeen.After(now.Add(30*time.Second))
	} else {
		observation.Stale = true
	}
	switch strings.ToLower(strings.TrimSpace(machine.Status)) {
	case "offline":
		observation.State, observation.Known = ClientNodeOffline, true
	case "available", "idle", "busy", "draining":
		if !parsed {
			observation.State = ClientNodeUnknown
			observation.Stale = true
			return observation
		}
		observation.Known = true
		if observation.Stale {
			observation.State = ClientNodeStale
		} else {
			observation.State = ClientNodeConnected
		}
	default:
		observation.State = ClientNodeUnknown
		observation.Stale = true
	}
	return observation
}

func clientEndpointPresence(status, lastSeen string, now time.Time, staleAfter time.Duration) ClientStatusObservation[ClientEndpointPresence] {
	observation := ClientStatusObservation[ClientEndpointPresence]{
		State: ClientEndpointUnknown, Source: "store.fabric_endpoints.status+last_seen",
	}
	observedAt, parsed := parseClientStatusTime(lastSeen)
	observation.ObservedAt = strings.TrimSpace(lastSeen)
	if parsed {
		observation.Stale = now.Sub(observedAt) > staleAfter || observedAt.After(now.Add(30*time.Second))
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "online":
		observation.State = ClientEndpointOnline
	case "idle":
		observation.State = ClientEndpointIdle
	case "busy":
		observation.State = ClientEndpointBusy
	case "offline":
		observation.State = ClientEndpointOffline
	case "left":
		observation.State = ClientEndpointLeft
	default:
		observation.Stale = true
		return observation
	}
	observation.Known = true
	if !parsed {
		observation.Stale = true
	}
	return observation
}

func clientNativeSession(endpoint store.Endpoint) ClientStatusObservation[ClientNativeSessionState] {
	observation := ClientStatusObservation[ClientNativeSessionState]{
		State: ClientNativeSessionUnknown, Source: "store.fabric_endpoints+endpoint_group_memberships",
	}
	if strings.TrimSpace(endpoint.NativeSessionID) == "" {
		observation.Stale = true
		return observation
	}
	observation.State = ClientNativeSessionKnown
	observation.Known = true
	observation.ObservedAt = strings.TrimSpace(endpoint.UpdatedAt)
	if endpoint.MigrationState != store.EndpointMigrationReady {
		observation.Stale = true
		return observation
	}
	if strings.TrimSpace(endpoint.BindingID) == "" || strings.EqualFold(strings.TrimSpace(endpoint.Status), "left") {
		observation.State = ClientNativeSessionBindingLost
		observation.Stale = true
		return observation
	}
	// Binding credentials are deliberately not loaded for a status projection.
	// The Endpoint and Group membership prove that the session identity is
	// known and enrolled. The binding's status/lease cannot be asserted without
	// loading credential-bearing SessionBinding rows, so report known+stale.
	observation.Stale = true
	return observation
}

func clientWorkerExecution(status, updatedAt string) ClientStatusObservation[ClientWorkerExecutionState] {
	state := ClientWorkerExecutionState(strings.ToLower(strings.TrimSpace(status)))
	switch state {
	case ClientWorkerQueued, ClientWorkerRunning, ClientWorkerRecovering, ClientWorkerVerifying,
		ClientWorkerCompleted, ClientWorkerFailed, ClientWorkerCancelled, ClientWorkerOutcomeUncertain:
		return ClientStatusObservation[ClientWorkerExecutionState]{
			State: state, Known: true, ObservedAt: strings.TrimSpace(updatedAt),
			Source: "store.workers.status+updated_at",
		}
	default:
		return ClientStatusObservation[ClientWorkerExecutionState]{
			State: ClientWorkerUnknown, ObservedAt: strings.TrimSpace(updatedAt),
			Source: "store.workers.status+updated_at", Stale: true,
		}
	}
}

func clientGoalLifecycle(status, updatedAt string) ClientStatusObservation[ClientGoalLifecycleState] {
	state := ClientGoalLifecycleState(strings.ToLower(strings.TrimSpace(status)))
	switch state {
	case ClientGoalQueued, ClientGoalRunning, ClientGoalBlocked, ClientGoalPaused, ClientGoalCompleted,
		ClientGoalFailed, ClientGoalCancelled:
		return ClientStatusObservation[ClientGoalLifecycleState]{
			State: state, Known: true, ObservedAt: strings.TrimSpace(updatedAt),
			Source: "store.goals.status+updated_at",
		}
	default:
		return ClientStatusObservation[ClientGoalLifecycleState]{
			State: ClientGoalUnknown, ObservedAt: strings.TrimSpace(updatedAt),
			Source: "store.goals.status+updated_at", Stale: true,
		}
	}
}

func clientGroupLifecycle(state, updatedAt string) ClientStatusObservation[ClientGroupLifecycleState] {
	value := ClientGroupLifecycleState(strings.ToUpper(strings.TrimSpace(state)))
	switch value {
	case ClientGroupDraft, ClientGroupActive, ClientGroupPaused, ClientGroupQuiescing, ClientGroupArchived:
		return ClientStatusObservation[ClientGroupLifecycleState]{
			State: value, Known: true, ObservedAt: strings.TrimSpace(updatedAt),
			Source: "store.groups.state+updated_at",
		}
	default:
		return ClientStatusObservation[ClientGroupLifecycleState]{
			State: ClientGroupUnknown, ObservedAt: strings.TrimSpace(updatedAt),
			Source: "store.groups.state+updated_at", Stale: true,
		}
	}
}

func clientTaskLifecycle(task store.SharedTask, now time.Time) ClientStatusObservation[ClientTaskState] {
	state := ClientTaskState(strings.ToUpper(strings.TrimSpace(task.Status)))
	observation := ClientStatusObservation[ClientTaskState]{
		State: state, ObservedAt: strings.TrimSpace(task.UpdatedAt),
		Source: "store.shared_tasks_v2.status+updated_at",
	}
	switch state {
	case ClientTaskDraft, ClientTaskReady, ClientTaskClaimed, ClientTaskRunning,
		ClientTaskResultSubmitted, ClientTaskCompleted, ClientTaskBlocked,
		ClientTaskNeedsRevision, ClientTaskCancelled:
		observation.Known = true
	default:
		observation.State = ClientTaskUnknown
		observation.Stale = true
		return observation
	}
	if state == ClientTaskClaimed || state == ClientTaskRunning {
		if expiry, ok := parseClientStatusTime(task.LeaseExpiresAt); !ok || !expiry.After(now) {
			observation.Stale = true
		}
	}
	return observation
}

func isInFlightWorkerState(state ClientWorkerExecutionState) bool {
	switch state {
	case ClientWorkerRunning, ClientWorkerRecovering, ClientWorkerVerifying:
		return true
	default:
		return false
	}
}

func parseClientStatusTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}
