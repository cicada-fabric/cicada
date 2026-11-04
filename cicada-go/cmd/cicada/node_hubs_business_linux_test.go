package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

// These tests exercise the local manager with synthetic entries and a trusted
// worker backend. They do not claim real Agent/NPT/Hub carrier coverage.
func nodeHubTestRegistry(t *testing.T, count int) (string, []nodeHubRegistryEntry) {
	t.Helper()
	ctx := context.Background()
	root := privateLocalNodeRoot(t)
	if err := initializeNodeHubRegistry(ctx, root); err != nil {
		t.Fatal(err)
	}
	var entries []nodeHubRegistryEntry
	if count > 0 {
		_, err := mutateNodeHubRegistry(ctx, root, func(_ *os.Root, r *nodeHubRegistry) error {
			for i := 0; i < count; i++ {
				e := nodeHubDefaultEntry(*r, root, fmt.Sprintf("%032x", i+1), fmt.Sprintf("synthetic-%d", i), fmt.Sprintf("127.0.0.1:%d", 20000+i))
				e.HubID, e.Origin = fmt.Sprintf("synthetic-hub-%d", i), fmt.Sprintf("https://synthetic-%d.invalid", i)
				r.Connections = append(r.Connections, e)
				entries = append(entries, e)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range entries {
		if err := writeNodeHubStateReference(ctx, root, e); err != nil {
			t.Fatal(err)
		}
	}
	return root, entries
}

func nodeHubTestWait(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("local test barrier timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func nodeHubTestStart(t *testing.T, root string, driver nodeHubRuntimeDriver) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveNodeHubManager(ctx, root, driver) }()
	nodeHubTestWait(t, func() bool { _, err := nodeHubManagerIPC(context.Background(), root, "STATUS", 0); return err == nil })
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("manager did not retire")
		}
	})
	return cancel, done
}

func nodeHubTestDriver() nodeHubRuntimeDriver {
	return nodeHubRuntimeDriver{RetainedReady: func(nodeHubRegistryEntry) error { return nil }, Ready: func(context.Context, nodeHubRegistryEntry) error { return nil }, Run: func(ctx context.Context, e nodeHubRegistryEntry) error {
		lock, err := nodelock.AcquireAgent(e.StateDir, e.NodeID)
		if err != nil {
			return err
		}
		defer lock.Close()
		<-ctx.Done()
		return nil
	}}
}

func TestNodeHubBusinessRegistryCapacityCASAndPrivateRecovery(t *testing.T) {
	for _, count := range []int{0, 1, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			root, _ := nodeHubTestRegistry(t, count)
			r, _, err := nodeHubRoot(context.Background(), root, false)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			before, raw, err := readNodeHubRegistry(r)
			if err != nil || len(before.Connections) != count {
				t.Fatal("cold registry differs", err)
			}
			changed := before
			changed.NodeName = "synthetic changed"
			changed.Revision++
			if err = saveNodeHubRegistry(r, changed, []byte("stale expected bytes")); !errors.Is(err, errNodeHubConflict) {
				t.Fatal("stale CAS accepted", err)
			}
			after, again, err := readNodeHubRegistry(r)
			if err != nil || after.NodeName != before.NodeName || string(raw) != string(again) {
				t.Fatal("failed CAS mutated registry")
			}
			if count == 8 {
				extra := nodeHubDefaultEntry(before, root, strings.Repeat("f", 32), "overflow", "127.0.0.1:30000")
				changed.Connections = append(changed.Connections, extra)
				if saveNodeHubRegistry(r, changed, raw) == nil {
					t.Fatal("ninth entry accepted")
				}
			}
			if err = os.Chmod(filepath.Join(root, nodeHubRegistryName), 0644); err != nil {
				t.Fatal(err)
			}
			if _, _, err = readNodeHubRegistry(r); err == nil {
				t.Fatal("unsafe registry repaired or accepted")
			}
		})
	}
}

func TestNodeHubBusinessConcurrentPendingHubReservation(t *testing.T) {
	root, entries := nodeHubTestRegistry(t, 2)
	_, err := mutateNodeHubRegistry(context.Background(), root, func(_ *os.Root, r *nodeHubRegistry) error {
		for i := range r.Connections {
			r.Connections[i].HubID = ""
			r.Connections[i].Origin = ""
			entries[i] = r.Connections[i]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, e := range entries {
		go func(e nodeHubRegistryEntry) {
			<-start
			_, err := reserveNodeHubCandidate(context.Background(), root, e, "synthetic-same-hub", "https://synthetic.invalid")
			results <- err
		}(e)
	}
	close(start)
	success, conflict := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, errNodeHubConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("pending scopes not exclusive")
	}
	r, _, err := nodeHubRoot(context.Background(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reg, _, err := readNodeHubRegistry(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range reg.Connections {
		if e.HubID == "synthetic-same-hub" {
			if _, err := reserveNodeHubCandidate(context.Background(), root, e, e.HubID, e.Origin); err != nil {
				t.Fatal("original pending scope could not resume", err)
			}
		}
		identity, _ := machineNodeControlPaths(e.StateDir, e.NodeID)
		if _, err = os.Stat(identity); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("reservation generated identity")
		}
	}
}

func TestNodeHubBusinessRuntimeIPCAndIndependentRemoval(t *testing.T) {
	root, entries := nodeHubTestRegistry(t, 2)
	driver := nodeHubTestDriver()
	var mu sync.Mutex
	starts := map[string]int{}
	run := driver.Run
	driver.Run = func(ctx context.Context, e nodeHubRegistryEntry) error {
		mu.Lock()
		starts[e.ConnectionID]++
		mu.Unlock()
		return run(ctx, e)
	}
	nodeHubTestStart(t, root, driver)
	nodeHubTestWait(t, func() bool {
		v, err := nodeHubManagerIPC(context.Background(), root, "STATUS", 0)
		return err == nil && len(v.Connections) == 2 && v.Connections[0].RuntimeState == "RUNNING" && v.Connections[1].RuntimeState == "RUNNING"
	})
	if _, err := nodeHubManagerIPCForPID(context.Background(), root, "STATUS", 0, os.Getpid()+1); err == nil {
		t.Fatal("wrong kernel-bound service PID accepted")
	}
	v, err := RemoveLocalNodeHubConnection(context.Background(), LocalNodeHubSelection{UserRoot: root, Alias: entries[0].Alias})
	if err != nil || v.State != "LOCAL_STOPPED" || v.RemoteRevocation != "NOT_REQUESTED" {
		t.Fatal("local removal did not quiesce", v.State, err)
	}
	live, err := nodeHubManagerIPC(context.Background(), root, "RECONCILE", 0)
	if err != nil || len(live.Connections) != 1 || live.Connections[0].ConnectionID != entries[1].ConnectionID || live.Connections[0].RuntimeState != "RUNNING" {
		t.Fatal("healthy peer disturbed", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if starts[entries[1].ConnectionID] != 1 {
		t.Fatal("healthy peer restarted")
	}
}

func TestNodeHubBusinessIdleIPCLossAndShutdownTimeoutRetainGate(t *testing.T) {
	t.Run("idle IPC loss", func(t *testing.T) {
		root, _ := nodeHubTestRegistry(t, 0)
		nodeHubTestStart(t, root, nodeHubTestDriver())
		if err := os.Remove(filepath.Join(root, nodeHubManagerLocatorName)); err != nil {
			t.Fatal(err)
		}
		list, err := ListLocalNodeHubConnections(context.Background(), root)
		if err != nil || list.ManagerState != "UNKNOWN" {
			t.Fatal("idle live daemon reported stopped", err)
		}
		busy, err := nodeHubAnyAgentBusy(context.Background(), root)
		if err != nil || !busy {
			t.Fatal("lifecycle lost idle daemon proof", err)
		}
		if err = serveNodeHubManager(context.Background(), root, nodeHubTestDriver()); !errors.Is(err, errNodeHubConflict) {
			t.Fatal("second daemon admitted", err)
		}
	})
	t.Run("uncooperative worker", func(t *testing.T) {
		root, _ := nodeHubTestRegistry(t, 1)
		driver := nodeHubTestDriver()
		release := make(chan struct{})
		started := make(chan struct{})
		driver.ShutdownTimeout = 25 * time.Millisecond
		driver.Run = func(ctx context.Context, e nodeHubRegistryEntry) error {
			lock, err := nodelock.AcquireAgent(e.StateDir, e.NodeID)
			if err != nil {
				return err
			}
			defer lock.Close()
			close(started)
			<-release
			return nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- serveNodeHubManager(ctx, root, driver) }()
		defer func() {
			cancel()
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		<-started
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, errNodeHubPending) {
				t.Fatal("timeout declared clean stop", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("bounded shutdown stuck")
		}
		busy, err := nodeHubAnyAgentBusy(context.Background(), root)
		if err != nil || !busy {
			t.Fatal("timed out daemon gate released", err)
		}
		if err = serveNodeHubManager(context.Background(), root, nodeHubTestDriver()); !errors.Is(err, errNodeHubConflict) {
			t.Fatal("replacement admitted before retirement", err)
		}
		close(release)
		nodeHubTestWait(t, func() bool { busy, err := nodeHubAnyAgentBusy(context.Background(), root); return err == nil && !busy })
		if _, err = os.Stat(filepath.Join(root, nodeHubManagerLocatorName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retired instance locator retained")
		}
	})
}

func TestNodeHubBusinessAtomicNativeAdmissionAndLegacyFence(t *testing.T) {
	for _, removeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(removeFirst), func(t *testing.T) {
			root, entries := nodeHubTestRegistry(t, 1)
			e := entries[0]
			h := machineHubContext{HubID: e.HubID, Origin: e.Origin, NodeID: e.NodeID, StateDir: e.StateDir, WriterRoot: e.WriterRoot, WriterScope: machineNativeWriterScope(), ManagedUserRoot: root, ManagedConnectionID: e.ConnectionID, ManagedConnectionEpoch: e.LocalFence}
			ctx := withMachineHubContext(context.Background(), h)
			legacy := h
			legacy.ManagedUserRoot = ""
			legacy.ManagedConnectionID = ""
			legacy.ManagedConnectionEpoch = 0
			if release, err := beginManagedNativeAdmission(withMachineHubContext(context.Background(), legacy)); err == nil {
				release()
				t.Fatal("legacy context bypassed adopted state reference")
			}
			if removeFirst {
				if _, err := RemoveLocalNodeHubConnection(ctx, LocalNodeHubSelection{UserRoot: root, Alias: e.Alias}); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(root, "synthetic-command-started")
			writer, err := nodelock.AcquireNativeWriter(ctx, e.WriterRoot, machineNativeWriterScope(), "codex", "synthetic-session")
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			op := nodelock.NativeOperation{HubID: e.HubID, NodeID: e.NodeID, EndpointID: "synthetic-endpoint", BindingID: "synthetic-binding", BindingEpoch: 1, MessageID: "synthetic-message", Digest: "synthetic-digest", AttemptID: "synthetic-attempt"}
			checked := false
			deps := machineNativeDeliveryLifecycle{command: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
				return exec.CommandContext(ctx, "/usr/bin/touch", marker)
			}, observe: func(phase string) {
				if phase != "managed_before_command_start" {
					return
				}
				checked = true
				blocked, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
				defer cancel()
				if _, err := RemoveLocalNodeHubConnection(blocked, LocalNodeHubSelection{UserRoot: root, Alias: e.Alias}); !errors.Is(err, errNodeHubPending) {
					t.Fatal("remove crossed final-check/Start gate", err)
				}
				if _, err := currentNodeHubFence(ctx, root, e.ConnectionID, 1); err != nil {
					t.Fatal("fence committed while admission shared lock held", err)
				}
			}}
			err = executeMachineNativeCodexHeld(ctx, writer, "synthetic-session", "synthetic body", op, nil, nil, deps)
			if removeFirst {
				if err == nil || checked {
					t.Fatal("removed epoch reached native Start")
				}
				if _, err = os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("removed epoch started process")
				}
			} else {
				if err != nil || !checked {
					t.Fatal("admitted command did not complete", err)
				}
				if _, err = os.Stat(marker); err != nil {
					t.Fatal("real Start marker missing")
				}
				if _, err = RemoveLocalNodeHubConnection(ctx, LocalNodeHubSelection{UserRoot: root, Alias: e.Alias}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestNodeHubBusinessRemoveReleasesAdmissionBeforeWaiting(t *testing.T) {
	root, entries := nodeHubTestRegistry(t, 1)
	e := entries[0]
	lock, err := nodelock.AcquireAgent(e.StateDir, e.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	v, err := RemoveLocalNodeHubConnection(ctx, LocalNodeHubSelection{UserRoot: root, Alias: e.Alias})
	if err != nil || v.State != "STOP_PENDING" {
		t.Fatal("busy worker falsely retired", err)
	}
	probe, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	release, err := acquireNodeHubAdmission(probe, e.StateDir, e.NodeID, false)
	if err != nil {
		t.Fatal("EX gate held during stop wait", err)
	}
	release()
}

func TestNodeHubBusinessRetiredSelectorsAndImmutableTuple(t *testing.T) {
	root, entries := nodeHubTestRegistry(t, 1)
	e := entries[0]
	v, err := RemoveLocalNodeHubConnection(context.Background(), LocalNodeHubSelection{UserRoot: root, Alias: e.Alias})
	if err != nil || v.State != "LOCAL_STOPPED" {
		t.Fatal(err)
	}
	for _, s := range []LocalNodeHubSelection{{ConnectionID: e.ConnectionID}, {HubAddress: e.HubAddress}, {HubID: e.HubID}, {Alias: strings.ToUpper(e.Alias)}} {
		s.UserRoot = root
		got, err := RemoveLocalNodeHubConnection(context.Background(), s)
		if err != nil || got != v {
			t.Fatal("lost removal response not exactly repeatable", err)
		}
	}
	if _, err = RemoveLocalNodeHubConnection(context.Background(), LocalNodeHubSelection{UserRoot: root, ConnectionID: e.ConnectionID, HubID: "synthetic-other"}); err == nil {
		t.Fatal("mismatched retired tuple accepted")
	}
	r, _, err := nodeHubRoot(context.Background(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	retired, err := readNodeHubRetired(r, LocalNodeHubSelection{ConnectionID: e.ConnectionID})
	if err != nil {
		t.Fatal(err)
	}
	retired.Removal.NodeID = "synthetic-other"
	b, _ := json.Marshal(retired)
	if err = os.WriteFile(filepath.Join(root, nodeHubRetiredIndex("id", e.ConnectionID)), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readNodeHubRetired(r, LocalNodeHubSelection{ConnectionID: e.ConnectionID}); err == nil {
		t.Fatal("forged retired tuple accepted")
	}
}

func TestNodeHubBusinessAcceptedQueueAndProviderUncertainty(t *testing.T) {
	root, entries := nodeHubTestRegistry(t, 1)
	e := entries[0]
	ctx := context.Background()
	path := machineNodeInboxPath(e.StateDir, e.NodeID)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE node_inbox_deliveries(message_id TEXT,digest TEXT,endpoint_id TEXT,session_id TEXT,binding_epoch INTEGER,state TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_inbox_deliveries VALUES('synthetic-message','synthetic-digest','synthetic-endpoint','synthetic-session',1,'CONSUMPTION_UNCONFIRMED')`); err != nil {
		t.Fatal(err)
	}
	if pending, err := nodeHubUncertainLocalWork(ctx, e); err != nil || pending {
		t.Fatal("known accepted queue blocked local removal", err)
	}
	if _, err = db.Exec(`UPDATE node_inbox_deliveries SET state='INJECTION_UNCERTAIN'`); err != nil {
		t.Fatal(err)
	}
	if pending, err := nodeHubUncertainLocalWork(ctx, e); err != nil || !pending {
		t.Fatal("true uncertainty declared stopped", err)
	}
	op := nodelock.NativeOperation{HubID: e.HubID, NodeID: e.NodeID, EndpointID: "synthetic-endpoint", MessageID: "synthetic-message", Digest: "synthetic-digest", BindingID: "synthetic-binding", AttemptID: "synthetic-attempt", BindingEpoch: 1}
	w, err := nodelock.AcquireNativeWriter(ctx, e.WriterRoot, machineNativeWriterScope(), "codex", "synthetic-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.BeginNativeOperation(op); err != nil {
		t.Fatal(err)
	}
	if err = w.FinishNativeOperation(op, nodelock.NativeQueueAccepted); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if pending, err := nodeHubUncertainLocalWork(ctx, e); err != nil || pending {
		t.Fatal("durable exact acceptance ignored", err)
	}
	_, control := machineNodeControlPaths(e.StateDir, e.NodeID)
	s := machineNodeControlState{NodeID: e.NodeID, HubID: e.HubID, ClaimTicket: &machineNodeControlClaimTicket{ExecutionID: "synthetic-A", ProviderID: "synthetic-provider", ProviderAttempt: 1, Phase: "EXECUTING"}}
	b, _ := json.Marshal(s)
	if err = os.WriteFile(control, b, 0600); err != nil {
		t.Fatal(err)
	}
	ledger, err := sql.Open("sqlite", filepath.Join(e.WriterRoot, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if _, err = ledger.Exec(`CREATE TABLE node_provider_admission_v1(execution_id TEXT,provider_id TEXT,state TEXT,attempts INTEGER); INSERT INTO node_provider_admission_v1 VALUES('synthetic-A','synthetic-provider','IN_PROGRESS',1),('synthetic-B','synthetic-provider','IN_PROGRESS',1)`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(e.WriterRoot, "node-provider-admission.sqlite3"), 0600); err != nil {
		t.Fatal(err)
	}
	if pending, err := nodeHubUncertainLocalWork(ctx, e); err != nil || !pending {
		t.Fatal("provider in progress declared stopped", err)
	}
	if _, err = ledger.Exec(`UPDATE node_provider_admission_v1 SET state='COMPLETED' WHERE execution_id='synthetic-A'`); err != nil {
		t.Fatal(err)
	}
	if pending, err := nodeHubUncertainLocalWork(ctx, e); err != nil || pending {
		t.Fatal("another Hub provider row blocked local stop", err)
	}
	_ = root
}

func TestNodeHubBusinessCodexInstallationCompatibility(t *testing.T) {
	root := privateLocalNodeRoot(t)
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0775); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "synthetic-codex")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "codex")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := validateNodeHubCodexExecutable(link); err != nil {
		t.Fatal("existing same-user wrapper rejected", err)
	}
	if validateNodeHubExecutable(link) == nil {
		t.Fatal("Cicada binary trust relaxed to external wrapper policy")
	}
	if err := os.Chmod(target, 0775); err != nil {
		t.Fatal(err)
	}
	if validateNodeHubCodexExecutable(link) == nil {
		t.Fatal("unsafe resolved target accepted")
	}
	if err := os.Chmod(target, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if nodeHubExternalExecutableTargetSafe(nodeHubForeignFileInfo{info}) {
		t.Fatal("foreign target owner accepted")
	}
}

type nodeHubForeignFileInfo struct{ os.FileInfo }

func (nodeHubForeignFileInfo) Sys() any { return &syscall.Stat_t{Uid: uint32(os.Geteuid() + 1)} }
