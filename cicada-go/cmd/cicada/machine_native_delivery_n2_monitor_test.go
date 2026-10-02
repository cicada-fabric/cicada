package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/store"
)

type n2MonitorReceiptAttempt struct {
	State  string `json:"state"`
	Status int    `json:"http_status"`
}

type n2MonitorFixture struct {
	base                *monitorBroadcastIntegrationFixture
	ctx                 context.Context
	bridge              *machineAgentJoinBridge
	inbox               *nodeinbox.Inbox
	process             nativeDeliveryProcessFixture
	notice              store.UserMonitorBroadcastV2Notification
	receiptMu           sync.Mutex
	receipts            []n2MonitorReceiptAttempt
	guardCalls          atomic.Int32
	guardUnavailable    atomic.Bool
	receiptUnavailable  atomic.Bool
	checkReceiptWriter  atomic.Bool
	receiptWriterChecks atomic.Int32
	controlCalls        atomic.Int32
}

func newN2MonitorFixture(t *testing.T) *n2MonitorFixture {
	t.Helper()
	f := &n2MonitorFixture{base: newMonitorBroadcastIntegrationFixture(t)}
	local := f.base.local
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			f.controlCalls.Add(1)
			http.Error(w, "Control business is absent", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/"+f.base.preview.PreviewID) {
			f.guardCalls.Add(1)
			if f.guardUnavailable.Load() {
				http.Error(w, "synthetic temporary Guard outage", http.StatusServiceUnavailable)
				return
			}
		}
		state := ""
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/receipt") {
			data, err := io.ReadAll(io.LimitReader(r.Body, 8193))
			if err != nil || len(data) > 8192 {
				t.Errorf("bounded synthetic receipt read: %v", err)
				return
			}
			var input struct {
				State string `json:"state"`
			}
			if err := json.Unmarshal(data, &input); err != nil {
				t.Error(err)
				return
			}
			state = input.State
			r.Body = io.NopCloser(bytes.NewReader(data))
			if state == store.UserMonitorBroadcastV2NoticeQueueAccepted && f.checkReceiptWriter.Load() {
				lockCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				writer, err := nodelock.AcquireNativeWriter(lockCtx, local.stateDir, f.process.WriterScope, "codex", local.nativeA)
				cancel()
				if err != nil {
					t.Errorf("success receipt arrived before physical writer release: %v", err)
				} else {
					if err := writer.Close(); err != nil {
						t.Error(err)
					}
					f.receiptWriterChecks.Add(1)
				}
			}
		}
		recorded := httptest.NewRecorder()
		if state == store.UserMonitorBroadcastV2NoticeQueueAccepted && f.receiptUnavailable.Load() {
			http.Error(recorded, "synthetic lost success receipt", http.StatusServiceUnavailable)
		} else {
			// Success authorization and receipts always come from the real Store
			// and Fabric-only handler, never fabricated permission JSON.
			f.base.hub.Config.Handler.ServeHTTP(recorded, r)
		}
		if state != "" {
			f.receiptMu.Lock()
			f.receipts = append(f.receipts, n2MonitorReceiptAttempt{State: state, Status: recorded.Code})
			f.receiptMu.Unlock()
		}
		relayRecordedMonitorResponse(w, recorded, recorded.Body.Bytes())
	}))
	t.Cleanup(proxy.Close)
	f.ctx = local.machineContextForNodeAt(local.nodeID, local.nodeToken, proxy.URL)
	f.bridge = &machineAgentJoinBridge{ctx: f.ctx, baseURL: proxy.URL, stateDir: local.stateDir,
		nodeID: local.nodeID, nodeToken: local.nodeToken}
	dir := t.TempDir()
	hub, _ := machineHubFrom(f.ctx)
	f.process = nativeDeliveryProcessFixture{Root: local.stateDir, HubID: local.hubID, NodeID: local.nodeID,
		Origin: proxy.URL, Token: local.nodeToken, WriterScope: hub.WriterScope, NativeID: local.nativeA,
		ConfigPath: filepath.Join(dir, "fixture.json"), CounterPath: filepath.Join(dir, "queue-count"),
		ArgsPath: filepath.Join(dir, "queue-argv.json"), WitnessPath: filepath.Join(dir, "witness")}
	nativeDeliverySaveConfig(t, f.process)
	f.ctx = context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath)})
	notice, err := f.bridge.monitorBroadcastNotification(f.base.preview.PreviewID)
	if err != nil {
		t.Fatal(err)
	}
	f.notice = *notice
	f.inbox, err = nodeinbox.Open(machineMonitorBroadcastInboxPath(local.stateDir, local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.inbox != nil {
			_ = f.inbox.Close()
		}
	})
	payload, digest, err := monitorNotificationBytes(f.notice)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.inbox.Save(f.ctx, nodeinbox.Message{MessageID: f.notice.PreviewID, Digest: digest,
		EndpointID: f.notice.MonitorEndpointID, SessionID: f.notice.NativeSessionID, BindingEpoch: f.notice.BindingEpoch,
		GroupID: f.notice.GroupID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if err := f.bridge.reportMonitorNotification(f.notice, nodeinbox.NODE_RECEIVED); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *n2MonitorFixture) claim(t *testing.T) nodeinbox.Claim {
	t.Helper()
	claim, err := f.inbox.Claim(f.ctx, "n2-monitor-notice-test")
	if err != nil {
		t.Fatal(err)
	}
	return *claim
}

func (f *n2MonitorFixture) delivery(t *testing.T) *nodeinbox.Delivery {
	t.Helper()
	delivery, err := f.inbox.Get(f.ctx, f.notice.PreviewID)
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func (f *n2MonitorFixture) processOnce(ctx context.Context) error {
	return processMachineMonitorBroadcastNotifications(ctx, f.bridge, &f.inbox,
		machineMonitorBroadcastInboxPath(f.base.local.stateDir, f.base.local.nodeID))
}

func (f *n2MonitorFixture) attempts() []n2MonitorReceiptAttempt {
	f.receiptMu.Lock()
	defer f.receiptMu.Unlock()
	return append([]n2MonitorReceiptAttempt(nil), f.receipts...)
}

func (f *n2MonitorFixture) assertNoBusiness(t *testing.T) {
	t.Helper()
	if f.controlCalls.Load() != 0 {
		t.Fatal("Monitor notice called Control business")
	}
	f.base.hubMu.Lock()
	sawBody := f.base.hubSawBody
	f.base.hubMu.Unlock()
	if sawBody {
		t.Fatal("Hub observed readable approved broadcast body")
	}
	if args, err := os.ReadFile(f.process.ArgsPath); err == nil && bytes.Contains(args, []byte(f.base.body)) {
		t.Fatal("management notice queued readable approved broadcast body")
	}
	f.base.assertNoLocalChildren(t)
}

// This new dispatcher runs only the owned test executable. The receiver invokes
// normal production Monitor process/recovery without a fixture PreviewID.
func TestNativeDeliveryN2MonitorProcessHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	if len(os.Args) < index+3 || os.Args[index+1] != "n2-monitor-adapter" {
		t.Fatal("invalid Monitor helper invocation")
	}
	data, err := os.ReadFile(os.Args[index+2])
	if err != nil {
		t.Fatal(err)
	}
	var f nativeDeliveryProcessFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	ctx := nativeDeliveryChildContext(t, f)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{
		command: nativeDeliveryQueueCommand(f.ConfigPath), observe: func(phase string) {
			if err := nativeDeliveryWriteWitness(f.WitnessPath, phase); err != nil {
				panic(err)
			}
			if phase == f.StopPhase {
				fmt.Println("READY " + phase)
				if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
					panic(err)
				}
			}
		}})
	bridge := &machineAgentJoinBridge{ctx: ctx, baseURL: f.Origin, stateDir: f.Root, nodeID: f.NodeID, nodeToken: f.Token}
	var inbox *nodeinbox.Inbox
	err = processMachineMonitorBroadcastNotifications(ctx, bridge, &inbox, machineMonitorBroadcastInboxPath(f.Root, f.NodeID))
	if inbox != nil {
		err = errors.Join(err, inbox.Close())
	}
	if err != nil {
		t.Fatal(err)
	}
}

func startN2MonitorProcess(t *testing.T, f nativeDeliveryProcessFixture) *nativeDeliveryProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeDeliveryN2MonitorProcessHelper$", "--", "n2-monitor-adapter", f.ConfigPath)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &nativeDeliveryProcess{command: cmd, stdin: stdin, lines: make(chan string, 32), done: make(chan error, 1)}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			p.lines <- scanner.Text()
		}
		close(p.lines)
		p.done <- cmd.Wait()
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = stdin.Close() })
	return p
}

func TestNativeDeliveryN2MonitorBusyPreservesPreIntent(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "writer-deadline"
		if cancelled {
			name = "already-cancelled"
		}
		t.Run(name, func(t *testing.T) {
			f := newN2MonitorFixture(t)
			held := nativeDeliveryStartProcess(t, "n1-hold", f.process)
			held.ready(t, "writer_held")
			claim := f.claim(t)
			ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
			if cancelled {
				cancel()
			}
			err := drainMachineMonitorBroadcastNotification(ctx, f.bridge, f.inbox, claim)
			cancel()
			if err == nil {
				t.Fatal("busy/cancelled writer was accepted")
			}
			stored := f.delivery(t)
			if stored.State != nodeinbox.NODE_RECEIVED || stored.AttemptID != "" || !bytes.Equal(stored.Payload, claim.Payload) || stored.Digest != claim.Digest ||
				nativeDeliveryCount(t, f.process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
				t.Fatalf("unstarted notice lost exact retry: %#v %v", stored, err)
			}
			if _, err := fmt.Fprintln(held.stdin, "release"); err != nil {
				t.Fatal(err)
			}
			held.wait(t, false)
			if err := drainMachineMonitorBroadcastNotification(f.ctx, f.bridge, f.inbox, f.claim(t)); err != nil {
				t.Fatal(err)
			}
			if f.delivery(t).State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
				t.Fatal("exact retry did not accept once")
			}
			f.assertNoBusiness(t)
		})
	}
}

func TestNativeDeliveryN2MonitorCurrentGuardAfterWriterWait(t *testing.T) {
	for _, change := range []string{"Client-revoked", "membership-revoked", "binding-epoch", "temporary-Guard"} {
		t.Run(change, func(t *testing.T) {
			f := newN2MonitorFixture(t)
			held := nativeDeliveryStartProcess(t, "n1-hold", f.process)
			held.ready(t, "writer_held")
			claim := f.claim(t)
			waiting := make(chan struct{})
			ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{
				command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
					if phase == "writer_wait" {
						close(waiting)
					}
				}})
			done := make(chan error, 1)
			go func() { done <- drainMachineMonitorBroadcastNotification(ctx, f.bridge, f.inbox, claim) }()
			select {
			case <-waiting:
			case <-time.After(5 * time.Second):
				t.Fatal("writer wait not reached")
			}
			if f.guardCalls.Load() != 1 {
				t.Fatal("fresh detail Guard ran before physical writer")
			}
			var err error
			switch change {
			case "Client-revoked":
				_, err = f.base.local.store.RevokeClientDevice(f.base.preview.OwnerID, f.base.deviceID, f.base.clientVersion)
			case "membership-revoked":
				_, err = f.base.local.store.RevokeMembershipForPrincipalGroup(f.base.request.PrincipalID, f.notice.GroupID, "synthetic revoke during writer wait")
			case "binding-epoch":
				_, err = f.base.local.store.FenceSessionBinding(f.notice.BindingID, f.notice.BindingEpoch, store.SessionBindingStatusSuperseded)
			case "temporary-Guard":
				f.guardUnavailable.Store(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintln(held.stdin, "release"); err != nil {
				t.Fatal(err)
			}
			held.wait(t, false)
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("held Guard did not finish")
			}
			stored := f.delivery(t)
			if nativeDeliveryCount(t, f.process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 || f.guardCalls.Load() != 2 {
				t.Fatal("stale authority reached native intent")
			}
			if change == "temporary-Guard" {
				if stored.State != nodeinbox.NODE_RECEIVED || stored.AttemptID != "" {
					t.Fatalf("temporary failure lost retry: %#v", stored)
				}
				f.guardUnavailable.Store(false)
				if err := drainMachineMonitorBroadcastNotification(f.ctx, f.bridge, f.inbox, f.claim(t)); err != nil {
					t.Fatal(err)
				}
				if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
					t.Fatal("Guard recovery did not accept once")
				}
			} else if stored.State != nodeinbox.FAILED {
				t.Fatalf("current denial not rejected: %#v", stored)
			}
			f.assertNoBusiness(t)
		})
	}
}

func TestNativeDeliveryN2MonitorPreflightAndTerminalAdmission(t *testing.T) {
	for _, failure := range []string{"missing-executable", "registry-unavailable", "terminal-notice"} {
		t.Run(failure, func(t *testing.T) {
			f := newN2MonitorFixture(t)
			ctx := f.ctx
			switch failure {
			case "missing-executable":
				ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
					return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "absent-synthetic-queue"))
				}})
			case "registry-unavailable":
				hub, _ := machineHubFrom(ctx)
				hub.NativeContexts = nil
				ctx = withMachineHubContext(ctx, hub)
			case "terminal-notice":
				if err := f.bridge.reportMonitorNotification(f.notice, nodeinbox.INJECTION_UNCERTAIN); err != nil {
					t.Fatal(err)
				}
			}
			err := drainMachineMonitorBroadcastNotification(ctx, f.bridge, f.inbox, f.claim(t))
			if err == nil {
				t.Fatal("negative preflight was accepted")
			}
			stored := f.delivery(t)
			want := nodeinbox.NODE_RECEIVED
			if failure == "terminal-notice" {
				want = nodeinbox.FAILED
			}
			if stored.State != want || (want == nodeinbox.NODE_RECEIVED && stored.AttemptID != "") || nativeDeliveryCount(t, f.process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
				t.Fatalf("preflight persisted intent: %#v %v", stored, err)
			}
			f.assertNoBusiness(t)
		})
	}
}

func TestNativeDeliveryN2MonitorReleasedWriterAllowsReceipt(t *testing.T) {
	f := newN2MonitorFixture(t)
	f.checkReceiptWriter.Store(true)
	f.receiptUnavailable.Store(true)
	if err := drainMachineMonitorBroadcastNotification(f.ctx, f.bridge, f.inbox, f.claim(t)); err == nil {
		t.Fatal("lost receipt was hidden")
	}
	if f.receiptWriterChecks.Load() != 1 || f.delivery(t).State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatal("writer was not released before durable local receipt/report")
	}
	if _, err := f.base.local.store.RevokeClientDevice(f.base.preview.OwnerID, f.base.deviceID, f.base.clientVersion); err != nil {
		t.Fatal(err)
	}
	f.receiptUnavailable.Store(false)
	if err := f.processOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.receiptWriterChecks.Load() != 2 || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("list-empty accepted report retried the queue or retained writer")
	}
	f.assertNoBusiness(t)
}

func TestNativeDeliveryN2MonitorIdentityConflictIsPermanent(t *testing.T) {
	f := newN2MonitorFixture(t)
	claim := f.claim(t)
	wrong := claim
	wrong.Digest = strings.Repeat("c", 64)
	operation, err := machineNativeOperation(f.ctx, wrong, f.notice.BindingID)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := machineNativeContextScopeFromMetadata(f.ctx, "codex", f.notice.NativeSessionID,
		f.notice.MonitorEndpointID, f.notice.BindingID, f.notice.BindingEpoch, *f.notice.NativeContextScope)
	if err != nil {
		t.Fatal(err)
	}
	// A genuine successful synthetic queue creates the conflicting immutable
	// native record; no hand-written QUEUE_ACCEPTED row backs this negative.
	if err := executeMachineNativeCodex(f.ctx, f.notice.NativeSessionID, "SYNTHETIC_N2_PRIOR_CONFLICT_NOTICE", operation, scope); err != nil {
		t.Fatal(err)
	}
	if err := drainMachineMonitorBroadcastNotification(f.ctx, f.bridge, f.inbox, claim); err != nil {
		t.Fatal(err)
	}
	if f.delivery(t).State != nodeinbox.FAILED || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("stable native identity conflict was requeued")
	}
	if _, err := f.inbox.Claim(f.ctx, "forbidden-conflict-retry"); !errors.Is(err, nodeinbox.ErrNoDelivery) {
		t.Fatal("conflict remains endlessly claimable")
	}
	f.assertNoBusiness(t)
}

func TestNativeDeliveryN2MonitorRecoveryErrorDoesNotStarvePending(t *testing.T) {
	f := newN2MonitorFixture(t)
	pending := f.claim(t)
	// Deliberately mismatched ORIGINAL metadata is a negative local canary,
	// not a fake Hub authorization or a fixture-created success observation.
	badID := "umbprev_mismatched_n2_history"
	if _, _, err := f.inbox.Save(f.ctx, nodeinbox.Message{MessageID: badID, Digest: pending.Digest,
		EndpointID: pending.EndpointID, SessionID: pending.SessionID, BindingEpoch: pending.BindingEpoch,
		GroupID: f.notice.GroupID, Payload: pending.Payload}); err != nil {
		t.Fatal(err)
	}
	bad, err := f.inbox.Claim(f.ctx, "bad-original-history")
	if err != nil || bad.MessageID != badID {
		t.Fatalf("bad original row claim: %#v %v", bad, err)
	}
	if _, err := f.inbox.BeginInjection(f.ctx, bad.AttemptID); err != nil {
		t.Fatal(err)
	}
	receipt := localGroupReceipt(*bad)
	receipt.State = nodeinbox.INJECTION_UNCERTAIN
	if _, err := f.inbox.Acknowledge(f.ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := f.inbox.AbandonClaim(f.ctx, pending.AttemptID); err != nil {
		t.Fatal(err)
	}
	if err := f.processOnce(f.ctx); err == nil {
		t.Fatal("bad original history error was hidden")
	}
	stored, err := f.inbox.Get(f.ctx, badID)
	if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN || stored.AttemptID != bad.AttemptID {
		t.Fatal("failed recovery row was erased")
	}
	if f.delivery(t).State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("recovery error starved real authorized pending notice")
	}
	f.assertNoBusiness(t)
}

func killN2MonitorAt(t *testing.T, f *n2MonitorFixture, phase string) (*nativeDeliveryProcess, []nativeDeliveryAuditRecord) {
	t.Helper()
	f.process.StopPhase = phase
	nativeDeliverySaveConfig(t, f.process)
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	f.inbox = nil
	child := startN2MonitorProcess(t, f.process)
	child.ready(t, phase)
	if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("helper did not durably accept exactly once")
	}
	witness, err := os.ReadFile(f.process.WitnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(witness), "helper_accepted\nqueue_wait_succeeded\n") {
		t.Fatal("barrier did not follow actual successful exec.Wait")
	}
	expected := nodelock.NativeInjecting
	if phase == "accepted_writer_closed" {
		expected = nodelock.NativeQueueAccepted
		if !strings.HasSuffix(string(witness), "accepted_durable\naccepted_writer_closed\n") {
			t.Fatal("D did not follow real durable Finish and writer Close")
		}
	}
	if !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.process.Root), []nodelock.NativeOutcomeState{expected}) {
		t.Fatal("raw native barrier state mismatch")
	}
	for _, receipt := range f.attempts() {
		if receipt.State != store.UserMonitorBroadcastV2NoticeNodeAccepted {
			t.Fatal("native receipt escaped crash window")
		}
	}
	before := nativeDeliveryAuditRecords(t, f.process.Root)
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.wait(t, true)
	f.process.StopPhase = ""
	nativeDeliverySaveConfig(t, f.process)
	return child, before
}

func TestNativeDeliveryN2MonitorCrashAfterSuccessfulWaitBeforeOutcome(t *testing.T) {
	f := newN2MonitorFixture(t)
	child, before := killN2MonitorAt(t, f, "queue_wait_succeeded")
	recovery := startN2MonitorProcess(t, f.process)
	recovery.wait(t, false)
	var err error
	f.inbox, err = nodeinbox.Open(machineMonitorBroadcastInboxPath(f.base.local.stateDir, f.base.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if f.delivery(t).State != nodeinbox.INJECTION_UNCERTAIN || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("C was promoted or reinjected")
	}
	if _, err := f.inbox.Claim(f.ctx, "forbidden-C-retry"); !errors.Is(err, nodeinbox.ErrNoDelivery) {
		t.Fatalf("uncertain notice became claimable: %v", err)
	}
	for _, receipt := range f.attempts() {
		if receipt.State == store.UserMonitorBroadcastV2NoticeQueueAccepted {
			t.Fatal("C reported unsupported success")
		}
	}
	exportN2MonitorAudit(t, f, child, "queue_wait_succeeded", before)
	f.assertNoBusiness(t)
}

func TestNativeDeliveryN2MonitorCrashAfterDurableOutcomeBeforeReceipt(t *testing.T) {
	for _, change := range []string{"listed", "Client-revoked-list-empty", "binding-fenced"} {
		t.Run(change, func(t *testing.T) {
			f := newN2MonitorFixture(t)
			child, before := killN2MonitorAt(t, f, "accepted_writer_closed")
			if change == "Client-revoked-list-empty" {
				if _, err := f.base.local.store.RevokeClientDevice(f.base.preview.OwnerID, f.base.deviceID, f.base.clientVersion); err != nil {
					t.Fatal(err)
				}
				var listing monitorBroadcastNotificationsResponse
				if err := f.bridge.monitorBroadcastHub(http.MethodGet, "", "", nil, &listing); err != nil || len(listing.Notifications) != 0 {
					t.Fatalf("real revoked Client did not hide list: %#v %v", listing, err)
				}
				if _, err := f.bridge.monitorBroadcastNotification(f.notice.PreviewID); err == nil {
					t.Fatal("real revoked Client retained fresh Guard")
				}
			}
			if change == "binding-fenced" {
				if _, err := f.base.local.store.FenceSessionBinding(f.notice.BindingID, f.notice.BindingEpoch, store.SessionBindingStatusSuperseded); err != nil {
					t.Fatal(err)
				}
				if err := f.processOnce(f.ctx); err == nil {
					t.Fatal("new binding permitted historical old-owner receipt")
				}
			} else {
				recovery := startN2MonitorProcess(t, f.process)
				recovery.wait(t, false)
			}
			if f.inbox == nil {
				var err error
				f.inbox, err = nodeinbox.Open(machineMonitorBroadcastInboxPath(f.base.local.stateDir, f.base.local.nodeID))
				if err != nil {
					t.Fatal(err)
				}
			}
			if f.delivery(t).State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 || !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.process.Root), []nodelock.NativeOutcomeState{nodelock.NativeQueueAccepted}) {
				t.Fatal("D lost exact accepted witness or reinjected")
			}
			accepted := false
			for _, receipt := range f.attempts() {
				if receipt.State == store.UserMonitorBroadcastV2NoticeInjectionUncertain {
					t.Fatal("D prematurely terminalized uncertainty")
				}
				if receipt.State == store.UserMonitorBroadcastV2NoticeQueueAccepted && receipt.Status == http.StatusOK {
					accepted = true
				}
			}
			if accepted != (change != "binding-fenced") {
				t.Fatalf("historical current binding fencing ignored: %v", f.attempts())
			}
			exportN2MonitorAudit(t, f, child, "accepted_writer_closed", before)
			f.assertNoBusiness(t)
		})
	}
}

func TestNativeDeliveryN2MonitorOutcomeReadBusyPreservesRecovery(t *testing.T) {
	f := newN2MonitorFixture(t)
	_, _ = killN2MonitorAt(t, f, "accepted_writer_closed")
	held := nativeDeliveryStartProcess(t, "n1-hold", f.process)
	held.ready(t, "writer_held")
	ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
	err := f.processOnce(ctx)
	cancel()
	if err == nil || f.delivery(t).State != nodeinbox.INJECTION_UNCERTAIN {
		t.Fatal("outcome reader busy lost original uncertainty")
	}
	for _, receipt := range f.attempts() {
		if receipt.State != store.UserMonitorBroadcastV2NoticeNodeAccepted {
			t.Fatal("unread accepted outcome became terminal uncertainty")
		}
	}
	if _, err := fmt.Fprintln(held.stdin, "release"); err != nil {
		t.Fatal(err)
	}
	held.wait(t, false)
	if err := f.processOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.delivery(t).State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("outcome reader recovery queued twice")
	}
	f.assertNoBusiness(t)
}

func TestNativeDeliveryN2MonitorStartedCancellationRemainsUnknown(t *testing.T) {
	f := newN2MonitorFixture(t)
	f.process.QueueBlock = true
	nativeDeliverySaveConfig(t, f.process)
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	blockRead, blockWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer blockRead.Close()
	defer blockWrite.Close()
	command := nativeDeliveryQueueCommand(f.process.ConfigPath)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: func(ctx context.Context, binary string, args ...string) *exec.Cmd {
		cmd := command(ctx, binary, args...)
		cmd.ExtraFiles = []*os.File{readyWrite, blockRead}
		return cmd
	}})
	claim := f.claim(t)
	done := make(chan error, 1)
	go func() { done <- drainMachineMonitorBroadcastNotification(ctx, f.bridge, f.inbox, claim) }()
	ready := make(chan error, 1)
	go func() { _, err := bufio.NewReader(readyRead).ReadString('\n'); ready <- err }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual queue did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled queue reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled queue did not stop")
	}
	if f.delivery(t).State != nodeinbox.INJECTING || !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.process.Root), []nodelock.NativeOutcomeState{nodelock.NativeUncertain}) || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("cancelled parent erased unknown or accepted work")
	}
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	f.inbox = nil
	if err := f.processOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.delivery(t).State != nodeinbox.INJECTION_UNCERTAIN || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("production reopen blindly retried cancellation")
	}
	f.assertNoBusiness(t)
}

func TestNativeDeliveryN2MonitorStartedFailureRetainsUnknown(t *testing.T) {
	for _, failure := range []string{"nonzero-Wait", "native-outcome-IO"} {
		t.Run(failure, func(t *testing.T) {
			f := newN2MonitorFixture(t)
			ctx := f.ctx
			var restore func()
			if failure == "nonzero-Wait" {
				f.process.QueueExit = 7
				nativeDeliverySaveConfig(t, f.process)
			} else {
				ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
					if phase != "queue_wait_succeeded" {
						return
					}
					paths, err := filepath.Glob(filepath.Join(f.process.Root, ".native-writers", "*.operations", "*.json"))
					if err != nil || len(paths) != 1 {
						panic("original native intent missing")
					}
					data, err := os.ReadFile(paths[0])
					if err != nil {
						panic(err)
					}
					if err := os.Remove(paths[0]); err != nil {
						panic(err)
					}
					if err := os.Mkdir(paths[0], 0o700); err != nil {
						panic(err)
					}
					restore = func() {
						if err := os.Remove(paths[0]); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(paths[0], data, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}})
			}
			err := drainMachineMonitorBroadcastNotification(ctx, f.bridge, f.inbox, f.claim(t))
			if failure == "native-outcome-IO" {
				if err == nil || f.delivery(t).State != nodeinbox.INJECTING {
					t.Fatal("unread native outcome became terminal")
				}
				for _, receipt := range f.attempts() {
					if receipt.State != store.UserMonitorBroadcastV2NoticeNodeAccepted {
						t.Fatal("I/O failure emitted terminal receipt")
					}
				}
				restore()
			}
			if err := f.inbox.Close(); err != nil {
				t.Fatal(err)
			}
			f.inbox = nil
			if err := f.processOnce(f.ctx); err != nil {
				t.Fatal(err)
			}
			if f.delivery(t).State != nodeinbox.INJECTION_UNCERTAIN || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
				t.Fatal("post-start failure was retried or falsely accepted")
			}
			f.assertNoBusiness(t)
		})
	}
}

func TestNativeDeliveryN2MonitorTransport(t *testing.T) {
	f := newN2MonitorFixture(t)
	f.checkReceiptWriter.Store(true)
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	f.inbox = nil
	child := startN2MonitorProcess(t, f.process)
	child.wait(t, false)
	if err := f.processOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.delivery(t).State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 || f.receiptWriterChecks.Load() < 1 {
		t.Fatal("actual TCP notice receiver did not queue/report once")
	}
	f.assertNoBusiness(t)
	t.Log("SYNTHETIC single-container TCP: parent real Client/Store/Fabric-only Hub and joined Unix bridge fixture; receiver subprocess production Monitor polling/recovery, current HTTP Guard, exact queue helper and original HTTP receipt; no provider/native Runtime or multicast execution")
}

func exportN2MonitorAudit(t *testing.T, f *n2MonitorFixture, child *nativeDeliveryProcess, phase string, before []nativeDeliveryAuditRecord) {
	t.Helper()
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 65536 {
			t.Fatalf("bounded synthetic audit read: %v", err)
		}
		return data
	}
	witness, counter, args := read(f.process.WitnessPath), read(f.process.CounterPath), read(f.process.ArgsPath)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	err = errors.Join(err, binary.Close())
	if err != nil {
		t.Fatal(err)
	}
	digest := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	audit := map[string]any{"test": t.Name(), "fixture": "SYNTHETIC OFFLINE MONITOR NOTICE QUEUE; NO CODEX OR PROVIDER", "barrier": phase,
		"adapter_exit_code": child.exitCode, "adapter_signal": child.signal, "native_before_kill": before,
		"native_after_recovery": nativeDeliveryAuditRecords(t, f.process.Root), "recovered_inbox_state": f.delivery(t).State,
		"witness": string(witness), "witness_sha256": digest(witness), "counter": string(counter), "counter_sha256": digest(counter),
		"synthetic_argv": json.RawMessage(args), "argv_raw_json_text": string(args), "argv_sha256": digest(args), "queue_count": nativeDeliveryCount(t, f.process.CounterPath),
		"production_http_receipt_attempts": f.attempts(), "test_helper_binary_sha256": hex.EncodeToString(hash.Sum(nil)), "product_binary": "NOT_BUILT_BY_THIS_TEST", "actual_native_runtime": "NOT_RUN"}
	encoded, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("N2_MONITOR_PROCESS_AUDIT %s", encoded)
	if directory := os.Getenv("CICADA_N2_TEST_EVIDENCE_DIR"); directory != "" {
		if !filepath.IsAbs(directory) {
			t.Fatal("test evidence directory must be absolute")
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		name := strings.ReplaceAll(t.Name(), "/", "_") + ".json"
		if err := os.WriteFile(filepath.Join(directory, name), append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
