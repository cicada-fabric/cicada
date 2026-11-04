package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

// Private trusted process dependencies. They are not registry or IPC fields.
type nodeHubOperationHooks struct {
	Pair          func(context.Context, string, nodeHubRegistryEntry) (nodeHubRegistryEntry, error)
	ServiceRunner nodeServiceRunner
	Binary        string
	Output        io.Writer
}
type nodeHubOperationHooksKey struct{}
type nodeHubPairRetryKey struct{}

func nodeHubHooks(ctx context.Context) nodeHubOperationHooks {
	h, _ := ctx.Value(nodeHubOperationHooksKey{}).(nodeHubOperationHooks)
	if h.Pair == nil {
		h.Pair = pairNodeHubEntry
	}
	if h.ServiceRunner == nil {
		h.ServiceRunner = runNodeServiceCommand
	}
	if h.Output == nil {
		h.Output = os.Stderr
	}
	return h
}

func ListLocalNodeHubConnections(ctx context.Context, userRoot string) (LocalNodeHubList, error) {
	root, path, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return LocalNodeHubList{}, err
	}
	defer root.Close()
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		return LocalNodeHubList{}, err
	}
	if live, e := nodeHubManagerIPC(ctx, path, "STATUS", r.Revision); e == nil {
		return live, nil
	} else if !errors.Is(e, errNodeHubUnavailable) {
		return LocalNodeHubList{}, e
	}
	out := LocalNodeHubList{Format: LocalNodeHubsFormat, Revision: r.Revision, ManagerState: "STOPPED", Connections: []LocalNodeHubView{}}
	held, ge := inspectNodeHubDaemonGate(root)
	if ge != nil {
		return LocalNodeHubList{}, ge
	}
	if held {
		out.ManagerState = "UNKNOWN"
	}
	for _, e := range r.Connections {
		v := nodeHubEntryView(e)
		v.RuntimeState = "STOPPED"
		v.PairingState = "PENDING"
		if nodeHubRetainedReady(e) == nil {
			v.PairingState = "READY"
		}
		if busy, err := nodeServiceAgentBusy(nodeServiceSelection{id: e.NodeID, state: e.StateDir}); err != nil || busy {
			v.RuntimeState = "UNKNOWN"
			out.ManagerState = "UNKNOWN"
		}
		out.Connections = append(out.Connections, v)
	}
	return out, nil
}

func AddLocalNodeHubConnection(ctx context.Context, in LocalNodeHubAddInput) (LocalNodeHubView, error) {
	if in.FromService {
		return adoptNodeHubFromService(ctx, in)
	}
	root, path, err := nodeHubRoot(ctx, in.UserRoot, false)
	if err != nil {
		return LocalNodeHubView{}, err
	}
	r, _, err := readNodeHubRegistry(root)
	root.Close()
	if err != nil {
		return LocalNodeHubView{}, err
	}
	if _, err = nodeHubManagerIPC(ctx, path, "STATUS", r.Revision); err != nil {
		return LocalNodeHubView{}, err
	}
	var entry nodeHubRegistryEntry
	if in.ConnectionID != "" || in.HubAddress == "" {
		i, e := selectNodeHubEntry(r, LocalNodeHubSelection{ConnectionID: in.ConnectionID, Alias: in.Alias})
		if e != nil {
			return LocalNodeHubView{}, e
		}
		entry = r.Connections[i]
		if entry.DesiredState != "ENABLED" {
			return LocalNodeHubView{}, errNodeHubConflict
		}
		if in.NodeID != "" && in.NodeID != entry.NodeID || in.NodeName != "" && in.NodeName != entry.NodeName || in.HubAddress != "" && in.HubAddress != entry.HubAddress {
			return LocalNodeHubView{}, errNodeHubConflict
		}
	} else {
		if pqtls.ValidateIPDialAddress(in.HubAddress) != nil || !localNodeHubText(in.Alias, 128) {
			return LocalNodeHubView{}, ErrLocalNodeHubConfig
		}
		id, err := nodeHubID()
		if err != nil {
			return LocalNodeHubView{}, err
		}
		// Re-enable the original state under the same admission gate used by
		// removal. Acquire before the registry lock to keep lock ordering fixed.
		retiredRoot, _, err := nodeHubRoot(ctx, path, false)
		if err != nil {
			return LocalNodeHubView{}, err
		}
		retained, retiredErr := readNodeHubRetired(retiredRoot, LocalNodeHubSelection{Alias: in.Alias})
		retiredRoot.Close()
		release := func() {}
		if retiredErr == nil {
			release, err = acquireNodeHubAdmission(ctx, retained.Entry.StateDir, retained.Entry.NodeID, true)
			if err != nil {
				return LocalNodeHubView{}, err
			}
		} else if !errors.Is(retiredErr, errNodeHubNotFound) {
			return LocalNodeHubView{}, retiredErr
		}
		_, err = mutateNodeHubRegistry(ctx, path, func(root *os.Root, current *nodeHubRegistry) error {
			for _, e := range current.Connections {
				if strings.EqualFold(e.Alias, in.Alias) || e.HubAddress == in.HubAddress {
					return errNodeHubConflict
				}
			}
			if len(current.Connections) >= MaxLocalNodeHubConnections {
				return errNodeHubLimit
			}
			// An explicit old alias resumes only its retained original identity.
			retired, retiredErr := readNodeHubRetired(root, LocalNodeHubSelection{Alias: in.Alias})
			if retiredErr == nil {
				if retired.Entry.HubAddress != in.HubAddress || retired.Removal.State != "LOCAL_STOPPED" {
					return errNodeHubConflict
				}
				entry = retired.Entry
				if entry.LocalFence >= 1<<63-1 {
					return ErrLocalNodeHubConfig
				}
				entry.LocalFence++
				entry.DesiredState = "ENABLED"
			} else if !errors.Is(retiredErr, errNodeHubNotFound) {
				return retiredErr
			} else {
				if _, e := readNodeHubRetired(root, LocalNodeHubSelection{HubAddress: in.HubAddress}); e == nil {
					return errNodeHubConflict
				} else if !errors.Is(e, errNodeHubNotFound) {
					return e
				}
				entry = nodeHubDefaultEntry(*current, path, id, in.Alias, in.HubAddress)
				if in.NodeName != "" {
					entry.NodeName = in.NodeName
				}
				if in.NodeID != "" {
					entry.NodeID = in.NodeID
				}
			}
			current.Connections = append(current.Connections, entry)
			return nil
		})
		release()
		if err != nil {
			return LocalNodeHubView{}, err
		}
	}
	if err = writeNodeHubStateReference(ctx, path, entry); err != nil {
		return nodeHubEntryView(entry), err
	}
	if nodeHubRetainedReady(entry) != nil || in.RetryPairing {
		pairCtx := context.WithValue(ctx, nodeHubPairRetryKey{}, in.RetryPairing)
		updated, e := nodeHubHooks(ctx).Pair(pairCtx, path, entry)
		if e != nil {
			return nodeHubEntryView(entry), e
		}
		_, err = mutateNodeHubRegistry(ctx, path, func(_ *os.Root, current *nodeHubRegistry) error {
			i, e := selectNodeHubEntry(*current, LocalNodeHubSelection{ConnectionID: entry.ConnectionID})
			if e != nil {
				return e
			}
			candidate := entry
			candidate.HubID, candidate.Origin = updated.HubID, updated.Origin
			if current.Connections[i] != entry && current.Connections[i] != candidate {
				return errNodeHubConflict
			}
			if updated != candidate {
				return errNodeHubConflict
			}
			for j, v := range current.Connections {
				if j != i && updated.HubID != "" && v.HubID == updated.HubID {
					return errNodeHubConflict
				}
			}
			current.Connections[i] = updated
			return nil
		})
		if err != nil {
			return nodeHubEntryView(entry), err
		}
		entry = updated
	}
	if err = nodeHubRetainedReady(entry); err != nil {
		return nodeHubEntryView(entry), err
	}
	return waitNodeHubReady(ctx, path, entry)
}

func waitNodeHubReady(ctx context.Context, path string, entry nodeHubRegistryEntry) (LocalNodeHubView, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		root, _, err := nodeHubRoot(ctx, path, false)
		if err != nil {
			return nodeHubEntryView(entry), err
		}
		r, _, err := readNodeHubRegistry(root)
		root.Close()
		if err != nil {
			return nodeHubEntryView(entry), err
		}
		live, err := nodeHubManagerIPC(ctx, path, "RECONCILE", r.Revision)
		if err != nil {
			return nodeHubEntryView(entry), err
		}
		for _, v := range live.Connections {
			if v.ConnectionID == entry.ConnectionID {
				if v.LocalFence != entry.LocalFence || v.DesiredState != "ENABLED" {
					return v, errNodeHubConflict
				}
				if v.RuntimeState == "RUNNING" && v.PairingState == "READY" {
					return v, nil
				}
				if v.RuntimeState == "FAILED" {
					return v, errNodeHubUnavailable
				}
			}
		}
		if !time.Now().Before(deadline) {
			return nodeHubEntryView(entry), errNodeHubPending
		}
		select {
		case <-ctx.Done():
			return nodeHubEntryView(entry), errNodeHubPending
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func pairNodeHubEntry(ctx context.Context, userRoot string, e nodeHubRegistryEntry) (nodeHubRegistryEntry, error) {
	shared, err := nodelock.AcquireWriterRoot(e.WriterRoot)
	if err != nil {
		return e, err
	}
	defer shared.Close()
	if err = rejectMachineRecoveryMutation(e.StateDir, e.WriterRoot, e.NodeID); err != nil {
		return e, err
	}
	if err = rejectMachineNodePendingRecovery(e.StateDir, e.NodeID); err != nil {
		return e, err
	}
	profile, text, err := selectMachineNodePairProfile(ctx, e.StateDir, e.NodeID, e.HubAddress, "", false, "scoped")
	if err != nil || profile != "scoped" {
		return e, errNodeHubUnavailable
	}
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil {
		return e, errNodeHubUnavailable
	}
	root, _, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return e, err
	}
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		root.Close()
		return e, err
	}
	if previous, re := readNodeHubRetired(root, LocalNodeHubSelection{HubID: d.Claims.Hub.HubID}); re == nil && previous.Entry.ConnectionID != e.ConnectionID {
		root.Close()
		return e, errNodeHubConflict
	} else if re != nil && !errors.Is(re, errNodeHubNotFound) {
		root.Close()
		return e, re
	}
	root.Close()
	for _, other := range r.Connections {
		if other.ConnectionID != e.ConnectionID && other.HubID == d.Claims.Hub.HubID {
			return e, errNodeHubConflict
		}
	}
	// Once a Hub has been pinned, another origin/public descriptor cannot use
	// add as a replacement or a newly generated identity escape hatch.
	if e.HubID != "" && (e.HubID != d.Claims.Hub.HubID || e.Origin != d.Claims.Origin) {
		return e, errNodeHubConflict
	}
	// Reserve the discovered Hub before generating any Node proof/identity.
	// Two locators to one Hub cannot each create a fresh pending identity.
	e, err = reserveNodeHubCandidate(ctx, userRoot, e, d.Claims.Hub.HubID, d.Claims.Origin)
	if err != nil {
		return e, err
	}
	completed := false
	retry, _ := ctx.Value(nodeHubPairRetryKey{}).(bool)
	if err = prepareMachineNodePairTrust(ctx, e.StateDir, e.NodeID, e.NodeName, e.HubAddress, d.Claims.Origin, true, false, retry, nodeHubHooks(ctx).Output, &completed, "scoped"); err != nil {
		return e, err
	}
	client, _, err := loadMachineRecoveryClient(e.StateDir, e.NodeID)
	if err != nil || !client.bindingReady() || client.state.HubID != d.Claims.Hub.HubID || client.state.HubOrigin != d.Claims.Origin {
		return e, errNodeHubNotReady
	}
	e.HubID, e.Origin = client.state.HubID, client.state.HubOrigin
	return e, nodeHubRetainedReady(e)
}

func reserveNodeHubCandidate(ctx context.Context, userRoot string, e nodeHubRegistryEntry, hubID, origin string) (nodeHubRegistryEntry, error) {
	_, err := mutateNodeHubRegistry(ctx, userRoot, func(root *os.Root, r *nodeHubRegistry) error {
		i, se := selectNodeHubEntry(*r, LocalNodeHubSelection{ConnectionID: e.ConnectionID})
		if se != nil {
			return se
		}
		if r.Connections[i] != e {
			return errNodeHubConflict
		}
		for j, other := range r.Connections {
			if j != i && other.HubID == hubID {
				return errNodeHubConflict
			}
		}
		if retired, re := readNodeHubRetired(root, LocalNodeHubSelection{HubID: hubID}); re == nil && retired.Entry.ConnectionID != e.ConnectionID {
			return errNodeHubConflict
		} else if re != nil && !errors.Is(re, errNodeHubNotFound) {
			return re
		}
		e.HubID, e.Origin = hubID, origin
		r.Connections[i] = e
		return nil
	})
	if err != nil {
		return e, err
	}
	return e, nil
}

func RemoveLocalNodeHubConnection(ctx context.Context, s LocalNodeHubSelection) (LocalNodeHubRemoval, error) {
	root, path, err := nodeHubRoot(ctx, s.UserRoot, false)
	if err != nil {
		return LocalNodeHubRemoval{}, err
	}
	r, _, err := readNodeHubRegistry(root)
	if err != nil {
		root.Close()
		return LocalNodeHubRemoval{}, err
	}
	i, err := selectNodeHubEntry(r, s)
	if err != nil {
		retired, re := readNodeHubRetired(root, s)
		root.Close()
		if re == nil {
			return retired.Removal, nil
		}
		if !errors.Is(re, errNodeHubNotFound) {
			return LocalNodeHubRemoval{}, re
		}
		return LocalNodeHubRemoval{}, err
	}
	entry := r.Connections[i]
	root.Close()
	if entry.DesiredState != "REMOVING" {
		gateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		release, e := acquireNodeHubAdmission(gateCtx, entry.StateDir, entry.NodeID, true)
		cancel()
		if e != nil {
			return LocalNodeHubRemoval{}, e
		}
		_, err = mutateNodeHubRegistry(ctx, path, func(_ *os.Root, current *nodeHubRegistry) error {
			i, e := selectNodeHubEntry(*current, LocalNodeHubSelection{ConnectionID: entry.ConnectionID})
			if e != nil {
				return e
			}
			if current.Connections[i] != entry || entry.LocalFence >= 1<<63-1 {
				return errNodeHubConflict
			}
			entry.DesiredState = "REMOVING"
			entry.LocalFence++
			current.Connections[i] = entry
			return nil
		})
		release()
		if err != nil {
			return LocalNodeHubRemoval{}, err
		}
	}
	result := LocalNodeHubRemoval{Format: LocalNodeHubRemovalFormat, ConnectionID: entry.ConnectionID, HubID: entry.HubID, NodeID: entry.NodeID, LocalFence: entry.LocalFence, State: "STOP_PENDING", RemoteRevocation: "NOT_REQUESTED"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		live, ipcErr := nodeHubManagerIPC(ctx, path, "RECONCILE", 0)
		workerStopped := errors.Is(ipcErr, errNodeHubUnavailable)
		if workerStopped {
			// Missing IPC is not retirement proof while the daemon gate is
			// held, including a child which has not acquired its Agent lock yet.
			if saved, _, oe := nodeHubRoot(ctx, path, false); oe == nil {
				held, ge := inspectNodeHubDaemonGate(saved)
				saved.Close()
				workerStopped = ge == nil && !held
			} else {
				workerStopped = false
			}
		}
		if ipcErr == nil {
			workerStopped = true
			for _, v := range live.Connections {
				if v.ConnectionID == entry.ConnectionID && v.RuntimeState != "STOPPED" && v.RuntimeState != "FAILED" {
					workerStopped = false
				}
			}
		}
		busy, busyErr := nodeServiceAgentBusy(nodeServiceSelection{id: entry.NodeID, state: entry.StateDir})
		if busyErr == nil && !busy && workerStopped {
			uncertain, e := nodeHubUncertainLocalWork(ctx, entry)
			if e == nil && !uncertain {
				result.State = "LOCAL_STOPPED"
				break
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return result, nil
		case <-time.After(50 * time.Millisecond):
		}
	}
	if result.State != "LOCAL_STOPPED" {
		return result, nil
	}
	_, err = mutateNodeHubRegistry(context.WithoutCancel(ctx), path, func(root *os.Root, current *nodeHubRegistry) error {
		i, e := selectNodeHubEntry(*current, LocalNodeHubSelection{ConnectionID: entry.ConnectionID})
		if e != nil {
			return e
		}
		if current.Connections[i] != entry {
			return errNodeHubConflict
		}
		retired := nodeHubRetired{"cicada.node-hub-retired.v1", entry, result}
		if e = saveNodeHubRetired(root, retired); e != nil {
			return e
		}
		current.Connections = append(current.Connections[:i], current.Connections[i+1:]...)
		return nil
	})
	return result, err
}

func nodeHubUncertainLocalWork(ctx context.Context, e nodeHubRegistryEntry) (bool, error) {
	for _, path := range []string{machineNodeInboxPath(e.StateDir, e.NodeID), machineLocalGroupInboxPath(e.StateDir, e.NodeID), machineMonitorBroadcastInboxPath(e.StateDir, e.NodeID)} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !localNodePrivate(info, false) {
			return true, ErrLocalNodeHubConfig
		}
		uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
		db, err := sql.Open("sqlite", uri)
		if err != nil {
			return true, err
		}
		db.SetMaxOpenConns(1)
		rows, re := db.QueryContext(ctx, `SELECT message_id,digest,endpoint_id,session_id,binding_epoch FROM node_inbox_deliveries WHERE state IN ('INJECTING','INJECTION_UNCERTAIN')`)
		if re != nil {
			db.Close()
			return true, ErrLocalNodeHubConfig
		}
		type pending struct {
			message, digest, endpoint, session string
			epoch                              uint64
		}
		var records []pending
		for rows.Next() {
			var v pending
			if re = rows.Scan(&v.message, &v.digest, &v.endpoint, &v.session, &v.epoch); re != nil {
				break
			}
			records = append(records, v)
			if len(records) > 4096 {
				re = errNodeHubLimit
				break
			}
		}
		rowErr := rows.Err()
		rows.Close()
		db.Close()
		if re != nil || rowErr != nil {
			return true, ErrLocalNodeHubConfig
		}
		for _, v := range records {
			outcome, oe := nodelock.InspectNativeMessageOutcome(e.WriterRoot, machineNativeWriterScope(), "codex", v.session, nodelock.NativeOperation{HubID: e.HubID, NodeID: e.NodeID, EndpointID: v.endpoint, MessageID: v.message, Digest: v.digest, BindingEpoch: v.epoch})
			if oe != nil {
				return true, oe
			}
			if outcome != nodelock.NativeQueueAccepted {
				return true, nil
			}
		}
	}
	return nodeHubPendingProvider(ctx, e)
}

func nodeHubEntryAddressSelection(root, selector string) LocalNodeHubSelection {
	s := LocalNodeHubSelection{UserRoot: root}
	if pqtls.ValidateIPDialAddress(selector) == nil {
		s.HubAddress = selector
	} else {
		s.Alias = selector
	}
	return s
}

func nodeHubOriginalSocket(e nodeHubRegistryEntry) (string, error) {
	return machineAgentJoinSocketPathChecked(e.StateDir, e.NodeID)
}
func nodeHubAbsoluteExecutable() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	return p
}

func nodeHubPendingProvider(ctx context.Context, e nodeHubRegistryEntry) (bool, error) {
	_, statePath := machineNodeControlPaths(e.StateDir, e.NodeID)
	if _, err := os.Lstat(statePath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	data, err := recoveryReadPrivateFile(statePath, maxMachineNodeControlStateBytes)
	var state machineNodeControlState
	if err != nil || decodeMachineNodeControlJSON(data, &state) != nil || state.NodeID != e.NodeID {
		return true, ErrLocalNodeHubConfig
	}
	ticket := state.ClaimTicket
	if ticket == nil {
		return false, nil
	}
	if state.HubID != e.HubID || ticket.ExecutionID == "" || ticket.ProviderID == "" {
		return true, ErrLocalNodeHubConfig
	}
	ledger := filepath.Join(e.WriterRoot, "node-provider-admission.sqlite3")
	info, err := os.Lstat(ledger)
	if errors.Is(err, os.ErrNotExist) {
		return ticket.Phase != "READY" || ticket.ProviderAttempt > 0, nil
	}
	if err != nil || !localNodePrivate(info, false) {
		return true, ErrLocalNodeHubConfig
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: ledger, RawQuery: "mode=ro"}).String())
	if err != nil {
		return true, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var stage string
	var attempt int
	err = db.QueryRowContext(ctx, `SELECT state,attempts FROM node_provider_admission_v1 WHERE execution_id=? AND provider_id=?`, ticket.ExecutionID, ticket.ProviderID).Scan(&stage, &attempt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return true, ErrLocalNodeHubConfig
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ticket.Phase != "READY" || ticket.ProviderAttempt > 0, nil
	}
	if err == nil && (stage == "IN_PROGRESS" || stage == "INJECTION_UNCERTAIN" || ticket.ProviderAttempt > 0 && attempt != ticket.ProviderAttempt) {
		return true, nil
	}
	if ticket.ResourceID != "" {
		record, re := nodelock.InspectResourceExecutionExisting(e.WriterRoot, ticket.ResourceID)
		if re != nil {
			return true, re
		}
		if record == nil {
			return ticket.Phase != "READY", nil
		}
		if record.ExecutionID == ticket.ExecutionID && record.LeaseID == ticket.LeaseID && record.FencingEpoch == ticket.FencingEpoch && record.State != nodelock.ResourceExecutionStopConfirmed && record.State != nodelock.ResourceExecutionStartFailed {
			return true, nil
		}
	}
	return ticket.Phase == "START_UNVERIFIED" || ticket.Phase == "STOP_UNVERIFIED" || ticket.Phase == "RESOURCE_STOP_UNVERIFIED", nil
}
