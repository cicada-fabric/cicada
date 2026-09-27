package control

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	ClientStatusChangesContractVersion = 1
	ClientStatusChangesCompleteness    = "partial"
	ClientStatusChangesCoverage        = "node_endpoint_worker_goal_group_task_snapshot_deltas"
	clientStatusChangesDefaultLimit    = 100
	clientStatusChangesMaxLimit        = 500
)

var ErrInvalidClientStatusCursor = errors.New("invalid or mismatched Client status cursor")

type clientStatusCursor struct {
	Version          int    `json:"v"`
	OwnerPrincipalID string `json:"owner_principal_id"`
	Sequence         int64  `json:"sequence"`
}

// ClientStatusChangesPage is a durable, owner-bound delta read. The feed is
// deliberately partial: it reconciles the safe status snapshot entities and
// does not cover approvals, Control intents, topology memberships/links, or
// transient transitions that happen between reads.
type ClientStatusChangesPage struct {
	ContractVersion       int                             `json:"contract_version"`
	Completeness          string                          `json:"completeness"`
	Coverage              string                          `json:"coverage"`
	ScopeMode             string                          `json:"scope_mode"`
	OwnerPrincipalID      string                          `json:"owner_principal_id"`
	Events                []store.ClientStatusChangeEvent `json:"events"`
	Cursor                string                          `json:"cursor"`
	HasMore               bool                            `json:"has_more"`
	Limit                 int                             `json:"limit"`
	ExcludedChangeSources []string                        `json:"excluded_change_sources"`
}

// ReadClientStatusChanges compares the current typed, secret-free status
// projection against durable owner state and returns changes after cursor.
// The cursor is only a position marker; authenticatedOwnerID remains the
// authority and is checked on every call.
func (c *Control) ReadClientStatusChanges(authenticatedOwnerID, cursor string, limit int) (*ClientStatusChangesPage, error) {
	if err := c.ValidateClientOwnerScope(authenticatedOwnerID); err != nil {
		return nil, err
	}
	ownerID := strings.TrimSpace(authenticatedOwnerID)
	after, err := decodeClientStatusCursor(cursor, ownerID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = clientStatusChangesDefaultLimit
	} else if limit > clientStatusChangesMaxLimit {
		limit = clientStatusChangesMaxLimit
	}
	snapshot, err := c.BuildClientStatusSnapshot(ownerID)
	if err != nil {
		return nil, err
	}
	observations, err := clientStatusSnapshotObservations(snapshot)
	if err != nil {
		return nil, err
	}
	covered := []string{"node", "endpoint", "worker", "goal", "group", "task"}
	if err := c.store.RecordClientStatusObservations(ownerID, snapshot.CapturedAt, covered, observations); err != nil {
		return nil, err
	}
	latest, err := c.store.LatestClientStatusChangeID(ownerID)
	if err != nil {
		return nil, err
	}
	if after > latest {
		return nil, store.ErrClientStatusCursorRange
	}
	rows, err := c.store.ListClientStatusChanges(ownerID, after, limit)
	if err != nil {
		return nil, err
	}
	next := after
	if len(rows) > 0 {
		next = rows[len(rows)-1].ID
	}
	page := &ClientStatusChangesPage{
		ContractVersion:  ClientStatusChangesContractVersion,
		Completeness:     ClientStatusChangesCompleteness,
		Coverage:         ClientStatusChangesCoverage,
		ScopeMode:        ClientStatusSnapshotScopeSingleOwner,
		OwnerPrincipalID: ownerID,
		Events:           rows,
		Cursor:           encodeClientStatusCursor(ownerID, next),
		HasMore:          latest > next,
		Limit:            limit,
		ExcludedChangeSources: []string{
			"approvals", "control_intents", "topology_memberships_and_links",
			"transitions_between_snapshot_reads", "legacy_event_payload_history",
		},
	}
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return page, nil
}

func encodeClientStatusCursor(ownerID string, sequence int64) string {
	encoded, _ := json.Marshal(clientStatusCursor{Version: 1, OwnerPrincipalID: ownerID, Sequence: sequence})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeClientStatusCursor(value, authenticatedOwnerID string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if len(value) > 2048 {
		return 0, ErrInvalidClientStatusCursor
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, ErrInvalidClientStatusCursor
	}
	var cursor clientStatusCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Version != 1 || cursor.Sequence < 0 {
		return 0, ErrInvalidClientStatusCursor
	}
	if cursor.OwnerPrincipalID != authenticatedOwnerID {
		return 0, fmt.Errorf("%w: cursor belongs to another owner", ErrPermissionDenied)
	}
	return cursor.Sequence, nil
}

type clientStatusStateObservation struct {
	State string `json:"state"`
	Known bool   `json:"known"`
	Stale bool   `json:"stale"`
}

func clientStatusSnapshotObservations(snapshot *ClientStatusSnapshot) ([]store.ClientStatusObservation, error) {
	observations := make([]store.ClientStatusObservation, 0,
		len(snapshot.Nodes)+len(snapshot.Endpoints)+len(snapshot.Workers)+len(snapshot.Goals)+len(snapshot.Groups)+len(snapshot.Tasks))
	appendState := func(entityType, entityID string, state any) error {
		encoded, err := json.Marshal(state)
		if err != nil {
			return err
		}
		observations = append(observations, store.ClientStatusObservation{
			EntityType: entityType, EntityID: entityID, StateJSON: encoded,
		})
		return nil
	}
	for _, node := range snapshot.Nodes {
		if err := appendState("node", node.NodeID, struct {
			Name         string                       `json:"name,omitempty"`
			Verified     bool                         `json:"verified"`
			Connectivity clientStatusStateObservation `json:"connectivity"`
		}{node.Name, node.Verified, clientStatusStateObservation{string(node.Connectivity.State), node.Connectivity.Known, node.Connectivity.Stale}}); err != nil {
			return nil, err
		}
	}
	for _, endpoint := range snapshot.Endpoints {
		state := struct {
			Name            string                       `json:"name,omitempty"`
			PrincipalID     string                       `json:"principal_id,omitempty"`
			GroupIDs        []string                     `json:"group_ids"`
			NodeID          string                       `json:"node_id,omitempty"`
			Harness         string                       `json:"harness,omitempty"`
			NativeSessionID string                       `json:"native_session_id,omitempty"`
			Presence        clientStatusStateObservation `json:"presence"`
			NativeSession   clientStatusStateObservation `json:"native_session"`
		}{
			Name: endpoint.Name, PrincipalID: endpoint.PrincipalID,
			GroupIDs: append([]string(nil), endpoint.GroupIDs...), NodeID: endpoint.NodeID,
			Harness: endpoint.Harness, NativeSessionID: endpoint.NativeSessionID,
			Presence:      clientStatusStateObservation{string(endpoint.Presence.State), endpoint.Presence.Known, endpoint.Presence.Stale},
			NativeSession: clientStatusStateObservation{string(endpoint.NativeSession.State), endpoint.NativeSession.Known, endpoint.NativeSession.Stale},
		}
		if err := appendState("endpoint", endpoint.EndpointID, state); err != nil {
			return nil, err
		}
	}
	for _, worker := range snapshot.Workers {
		state := struct {
			GoalID    string                       `json:"goal_id,omitempty"`
			NodeID    string                       `json:"node_id,omitempty"`
			Harness   string                       `json:"harness,omitempty"`
			Attempt   int                          `json:"attempt"`
			Execution clientStatusStateObservation `json:"execution"`
		}{worker.GoalID, worker.NodeID, worker.Harness, worker.Attempt,
			clientStatusStateObservation{string(worker.Execution.State), worker.Execution.Known, worker.Execution.Stale}}
		if err := appendState("worker", worker.WorkerID, state); err != nil {
			return nil, err
		}
	}
	for _, goal := range snapshot.Goals {
		state := struct {
			ParentID  string                       `json:"parent_id,omitempty"`
			NodeID    string                       `json:"node_id,omitempty"`
			WorkerIDs []string                     `json:"worker_ids"`
			Lifecycle clientStatusStateObservation `json:"lifecycle"`
		}{goal.ParentID, goal.NodeID, append([]string(nil), goal.WorkerIDs...),
			clientStatusStateObservation{string(goal.Lifecycle.State), goal.Lifecycle.Known, goal.Lifecycle.Stale}}
		if err := appendState("goal", goal.GoalID, state); err != nil {
			return nil, err
		}
	}
	for _, group := range snapshot.Groups {
		state := struct {
			ParentGroupID string                       `json:"parent_group_id,omitempty"`
			Name          string                       `json:"name,omitempty"`
			Version       int64                        `json:"version"`
			Lifecycle     clientStatusStateObservation `json:"lifecycle"`
		}{group.ParentGroupID, group.Name, group.Version,
			clientStatusStateObservation{string(group.Lifecycle.State), group.Lifecycle.Known, group.Lifecycle.Stale}}
		if err := appendState("group", group.GroupID, state); err != nil {
			return nil, err
		}
	}
	for _, task := range snapshot.Tasks {
		state := struct {
			GroupID          string                       `json:"group_id"`
			GoalID           string                       `json:"goal_id,omitempty"`
			OwnerPrincipalID string                       `json:"owner_principal_id,omitempty"`
			OwnerEndpointID  string                       `json:"owner_endpoint_id,omitempty"`
			Revision         int64                        `json:"revision"`
			OwnerEpoch       int64                        `json:"owner_epoch"`
			Lifecycle        clientStatusStateObservation `json:"lifecycle"`
		}{task.GroupID, task.GoalID, task.OwnerPrincipalID, task.OwnerEndpointID, task.Revision, task.OwnerEpoch,
			clientStatusStateObservation{string(task.Lifecycle.State), task.Lifecycle.Known, task.Lifecycle.Stale}}
		if err := appendState("task", task.TaskID, state); err != nil {
			return nil, err
		}
	}
	return observations, nil
}
