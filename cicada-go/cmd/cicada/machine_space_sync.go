package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

// Subscriptions are local, private reconciliation state. The session token is
// required for a fresh Hub Guard on every page; it is never sent in an SSE hint.
type machineSpaceSubscription struct {
	GroupID      string `json:"group_id"`
	EndpointID   string `json:"endpoint_id"`
	SessionToken string `json:"session_token"`
	BindingEpoch uint64 `json:"binding_epoch"`
	HubID        string `json:"hub_id,omitempty"`
	NetworkID    string `json:"network_id,omitempty"`
	Watermark    string `json:"watermark_version,omitempty"`
	FetchedSeq   int64  `json:"fetched_seq"`
}

type machineSpaceSubscriptions struct {
	Version int                        `json:"version"`
	Items   []machineSpaceSubscription `json:"items"`
}

const machineSpaceSubscriptionLimit = 64

func (b *machineAgentJoinBridge) spaceSubscriptionsPath() string {
	return filepath.Join(machineNodeStateDir(b.stateDir, b.nodeID), "space-sync.json")
}

func (b *machineAgentJoinBridge) loadSpaceSubscriptions() (machineSpaceSubscriptions, error) {
	value := machineSpaceSubscriptions{Version: 2, Items: []machineSpaceSubscription{}}
	path := b.spaceSubscriptionsPath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 256*1024 {
		return value, errors.New("private Group Space sync state is unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &value) != nil || len(value.Items) > machineSpaceSubscriptionLimit {
		return value, errors.New("invalid private Group Space sync state")
	}
	if value.Version == 1 {
		// The old cursor was a reserved record sequence, not the durable
		// commit order. Reconcile from zero under current Guard.
		for index := range value.Items {
			value.Items[index].FetchedSeq = 0
		}
		value.Version = 2
	} else if value.Version != 2 {
		return value, errors.New("unsupported Group Space sync cursor version")
	}
	return value, nil
}

func (b *machineAgentJoinBridge) persistSpaceSubscriptions(value machineSpaceSubscriptions) error {
	if len(value.Items) > machineSpaceSubscriptionLimit {
		return errors.New("Group Space sync subscription limit reached")
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 256*1024 {
		return errors.New("invalid Group Space sync state")
	}
	return persistNodeSecretFile(b.spaceSubscriptionsPath(), append(data, '\n'), ".space-sync-*")
}

func (b *machineAgentJoinBridge) rememberGroupSpaceSubscription(request groupSpaceLocalRequest,
	actor store.GroupSpaceEndpointEvidence, syncResult *store.GroupSpaceSyncResult) error {
	b.spaceSyncMu.Lock()
	defer b.spaceSyncMu.Unlock()
	value, err := b.loadSpaceSubscriptions()
	if err != nil {
		return err
	}
	item := machineSpaceSubscription{GroupID: request.GroupID, EndpointID: actor.EndpointID,
		SessionToken: request.SessionToken, BindingEpoch: request.BindingEpoch}
	if syncResult != nil {
		if syncResult.WatermarkVersion != "commit_v1" || syncResult.BindingEpoch != request.BindingEpoch ||
			syncResult.HubID == "" || syncResult.HubID != machinePinnedHubID(b.ctx) ||
			syncResult.NetworkID == "" || syncResult.GroupID != request.GroupID {
			return errors.New("Hub returned unpinned Group Space sync watermark")
		}
		item.HubID, item.NetworkID, item.Watermark = syncResult.HubID, syncResult.NetworkID, syncResult.WatermarkVersion
		item.FetchedSeq = syncResult.NextSeq
	}
	for index := range value.Items {
		if value.Items[index].GroupID == item.GroupID && value.Items[index].EndpointID == item.EndpointID {
			previous := value.Items[index]
			if previous.BindingEpoch == item.BindingEpoch && previous.Watermark == item.Watermark &&
				(previous.HubID == "" || item.HubID == "" || previous.HubID == item.HubID) &&
				(previous.NetworkID == "" || item.NetworkID == "" || previous.NetworkID == item.NetworkID) {
				if previous.FetchedSeq > item.FetchedSeq {
					item.FetchedSeq = previous.FetchedSeq
				}
				if item.HubID == "" {
					item.HubID, item.NetworkID, item.Watermark = previous.HubID, previous.NetworkID, previous.Watermark
				}
			}
			value.Items[index] = item
			return b.persistSpaceSubscriptions(value)
		}
	}
	value.Items = append(value.Items, item)
	return b.persistSpaceSubscriptions(value)
}

// One cycle performs at most sixteen guarded page requests within ten seconds.
// The cursor rotates across watches so one busy or failing Group cannot starve
// another. Network I/O never holds the watch mutex used by native Join/MCP.
func (b *machineAgentJoinBridge) reconcileGroupSpaces() error {
	b.spaceSyncMu.Lock()
	value, err := b.loadSpaceSubscriptions()
	if err != nil {
		b.spaceSyncMu.Unlock()
		return err
	}
	if len(value.Items) == 0 {
		b.spaceSyncMu.Unlock()
		return nil
	}
	start := b.spaceSyncNext % len(value.Items)
	count := len(value.Items)
	if count > 16 {
		count = 16
	}
	b.spaceSyncNext = (start + count) % len(value.Items)
	items := make([]machineSpaceSubscription, 0, count)
	for offset := 0; offset < count; offset++ {
		items = append(items, value.Items[(start+offset)%len(value.Items)])
	}
	b.spaceSyncMu.Unlock()
	cycle, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	var firstErr error
	for _, item := range items {
		if cycle.Err() != nil {
			break
		}
		if strings.TrimSpace(item.SessionToken) == "" || item.GroupID == "" || item.EndpointID == "" {
			continue
		}
		var result store.GroupSpaceSyncResult
		err := b.groupSpaceHTTPWithContext(cycle, item.SessionToken, "sync", store.GroupSpaceSyncInput{
			GroupID: item.GroupID, AfterSeq: item.FetchedSeq, Limit: 16}, &result)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("reconcile Group Space: %w", err)
			}
			continue
		}
		if result.GroupID != item.GroupID || result.NextSeq < item.FetchedSeq ||
			result.LatestSeq < result.NextSeq || len(result.Hints) > 16 ||
			result.HubID == "" || result.HubID != machinePinnedHubID(b.ctx) ||
			result.NetworkID == "" || result.WatermarkVersion != "commit_v1" ||
			result.BindingEpoch != item.BindingEpoch ||
			(item.HubID != "" && item.HubID != result.HubID) ||
			(item.NetworkID != "" && item.NetworkID != result.NetworkID) ||
			(item.Watermark != "" && item.Watermark != result.WatermarkVersion) {
			if firstErr == nil {
				firstErr = errors.New("Hub returned invalid Group Space sync cursor")
			}
			continue
		}
		b.spaceSyncMu.Lock()
		current, err := b.loadSpaceSubscriptions()
		if err == nil {
			for index := range current.Items {
				candidate := &current.Items[index]
				if candidate.EndpointID != item.EndpointID || candidate.GroupID != item.GroupID ||
					candidate.BindingEpoch != item.BindingEpoch || candidate.SessionToken != item.SessionToken ||
					candidate.FetchedSeq != item.FetchedSeq {
					continue
				}
				candidate.FetchedSeq = result.NextSeq
				candidate.HubID, candidate.NetworkID, candidate.Watermark = result.HubID, result.NetworkID, result.WatermarkVersion
				err = b.persistSpaceSubscriptions(current)
				break
			}
		}
		b.spaceSyncMu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func runMachineSpaceSyncWorker(ctx context.Context, bridge *machineAgentJoinBridge,
	hints <-chan struct{}, interval time.Duration) {
	if bridge == nil {
		return
	}
	if interval < time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := bridge.reconcileGroupSpaces(); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "Group Space sync:", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-hints:
		case <-ticker.C:
		}
	}
}
