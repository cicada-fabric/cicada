package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// The helper is this test executable, never installed Codex or a provider. Its
// public synthetic fixture configuration is private to the test's temp root.
type nativeDeliveryProcessFixture struct {
	QueueBlock                                                bool
	Root, HubID, NodeID, Origin, Token, WriterScope, NativeID string
	ConfigPath, CounterPath, ArgsPath, WitnessPath, StopPhase string
	QueueExit                                                 int
}

func nativeDeliveryWriteWitness(path, phase string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, phase)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func nativeDeliveryChildContext(t *testing.T, f nativeDeliveryProcessFixture) context.Context {
	t.Helper()
	history, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(f.Root, "native-context-history.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = history.Close() })
	return withMachineHubContext(context.Background(), machineHubContext{HubID: f.HubID, NodeID: f.NodeID,
		Origin: f.Origin, Token: f.Token, StateDir: f.Root, WriterRoot: f.Root, WriterScope: f.WriterScope,
		RequireNativeContext: true, NativeContexts: history})
}

func nativeDeliveryQueueCommand(configPath string) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		executable, err := os.Executable()
		if err != nil {
			panic(err)
		}
		argv := append([]string{"-test.run=^TestMachineNativeDeliveryProcessHelper$", "--", "n1-queue", configPath}, args...)
		return exec.CommandContext(ctx, executable, argv...)
	}
}

func TestMachineNativeDeliveryProcessHelper(t *testing.T) {
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
	if len(os.Args) < index+4 {
		t.Fatal("incomplete synthetic helper args")
	}
	mode, configPath := os.Args[index+1], os.Args[index+2]
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var f nativeDeliveryProcessFixture
	if json.Unmarshal(data, &f) != nil {
		t.Fatal("invalid helper config")
	}
	switch mode {
	case "n1-queue":
		args := os.Args[index+3:]
		if len(args) != 5 || args[0] != "queue" || args[1] != "--thread" || args[2] != f.NativeID || args[3] != "--message" {
			t.Fatal("queue received different literal argv")
		}
		encoded, _ := json.Marshal(args)
		if err := os.WriteFile(f.ArgsPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := nativeDeliveryWriteWitness(f.CounterPath, "accepted"); err != nil {
			t.Fatal(err)
		}
		if err := nativeDeliveryWriteWitness(f.WitnessPath, "helper_accepted"); err != nil {
			t.Fatal(err)
		}
		if f.QueueBlock {
			ready := os.NewFile(3, "synthetic-started-barrier")
			if _, err := ready.Write([]byte("accepted\n")); err != nil {
				t.Fatal(err)
			}
			_ = ready.Close()
			block := os.NewFile(4, "synthetic-queue-block")
			if _, err := bufio.NewReader(block).ReadString('\n'); err != nil {
				t.Fatal(err)
			}
		}
		os.Exit(f.QueueExit)
	case "n1-hold":
		lock, err := nodelock.AcquireNativeWriter(context.Background(), f.Root, f.WriterScope, "codex", f.NativeID)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("READY writer_held")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	case "n1-adapter", "n1-recover":
		ctx := nativeDeliveryChildContext(t, f)
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		lifecycle := machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(configPath), observe: func(phase string) {
			if err := nativeDeliveryWriteWitness(f.WitnessPath, phase); err != nil {
				panic(err)
			}
			if phase == f.StopPhase {
				fmt.Println("READY " + phase)
				// A real Wait()==nil has occurred before the C barrier. The D barrier
				// follows durable Finish and writer.Close; neither barrier touches state.
				if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
					panic(err)
				}
			}
		}}
		ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, lifecycle)
		inbox, err := nodeinbox.Open(machineNodeInboxPath(f.Root, f.NodeID))
		if err != nil {
			t.Fatal(err)
		}
		defer inbox.Close()
		journal, err := openMachineRelayJournal(f.Root, f.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "n1-recover" {
			if err := reconcileMachineRelayJournal(ctx, f.Origin, f.NodeID, f.Root, inbox, journal); err != nil {
				t.Fatal(err)
			}
		}
		if err := drainMachineRelayInbox(ctx, f.Origin, f.NodeID, f.Root, inbox, journal); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown synthetic helper mode")
	}
}

type nativeDeliveryProcess struct {
	exitCode int
	signal   int
	command  *exec.Cmd
	stdin    io.WriteCloser
	lines    chan string
	done     chan error
}

func nativeDeliveryStartProcess(t *testing.T, mode string, f nativeDeliveryProcessFixture) *nativeDeliveryProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestMachineNativeDeliveryProcessHelper$", "--", mode, f.ConfigPath, "fixture")
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

func (p *nativeDeliveryProcess) ready(t *testing.T, phase string) {
	t.Helper()
	timer := time.NewTimer(22 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				t.Fatalf("child ended before %s", phase)
			}
			if line == "READY "+phase {
				return
			}
		case <-timer.C:
			t.Fatalf("child barrier %s timed out", phase)
		}
	}
}

func (p *nativeDeliveryProcess) wait(t *testing.T, killed bool) {
	t.Helper()
	select {
	case err := <-p.done:
		if killed {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("expected SIGKILL child exit: %v", err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected child exit: %v", err)
			}
			p.exitCode = exit.ExitCode()
			p.signal = int(status.Signal())
			t.Logf("adapter child signal=%s exit_code=%d; parent gate independently checks recovery", status.Signal(), exit.ExitCode())
		} else if err != nil {
			t.Fatalf("child failed: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("child did not exit")
	}
}

func nativeDeliverySaveConfig(t *testing.T, f nativeDeliveryProcessFixture) {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.ConfigPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type nativeDeliveryRelayFixture struct {
	local            *localGroupFailureFixture
	process          nativeDeliveryProcessFixture
	ctx              context.Context
	messageID        string
	nativeScope      nodeinbox.NativeContextScopeInput
	journal          *machineRelayJournal
	inbox            *nodeinbox.Inbox
	receiptsMu       sync.Mutex
	receipts         []string
	guardUnavailable atomic.Bool
	guardCalls       atomic.Int32
}

func newNativeDeliveryRelayFixture(t *testing.T) *nativeDeliveryRelayFixture {
	t.Helper()
	local := newLocalGroupFailureFixture(t)
	authorizeSameNodeRelayFixture(t, local, local.sourceMCP, local.targetMCP)
	service, err := fabric.NewService(local.store, local.ownerID, local.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := serverpkg.NewFabricHandler(service, "") // no Control business service
	f := &nativeDeliveryRelayFixture{local: local, ctx: local.bridge.ctx}
	local.hub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/authorization") {
			f.guardCalls.Add(1)
			if f.guardUnavailable.Load() {
				http.Error(w, "synthetic temporary authority outage", http.StatusServiceUnavailable)
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/receipts") {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			var input fabric.NodeReceiptInput
			if err := json.Unmarshal(data, &input); err != nil {
				t.Error(err)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(data)))
			f.receiptsMu.Lock()
			f.receipts = append(f.receipts, input.Layer)
			f.receiptsMu.Unlock()
		}
		handler.ServeHTTP(w, r)
	})
	t.Setenv("CODEX_THREAD_ID", local.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+local.nativeA)
	const body = "SYNTHETIC_N1_PEER_BODY /resume 'quoted' `not-a-command`\nsecond line"
	result, err := local.sourceMCP.callTool("cicada_send", map[string]any{"target": local.targetMCP.endpointID, "body": body, "idempotency_key": "synthetic-n1-send"})
	if err != nil {
		t.Fatal(err)
	}
	public := result.(map[string]any)
	if public["delivery"] != "RELAY_PERSISTED" {
		t.Fatalf("not sealed Relay: %#v", public)
	}
	f.messageID = public["message_id"].(string)
	deliveries, err := service.ClaimNodeSameGroupSealedV1Deliveries(local.nodeToken, local.nodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(local.nodeID), Limit: 1})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("real current Hub claim: %v %#v", err, deliveries)
	}
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(local.stateDir, local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.inbox.Close() })
	f.journal, err = openMachineRelayJournal(local.stateDir, local.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptMachineCrossNodeGroupDelivery(f.ctx, local.hub.URL, local.nodeID, local.stateDir, f.inbox, f.journal, deliveries[0]); err != nil {
		t.Fatal(err)
	}
	authorization, err := fetchCrossNodeGroupDeliveryAuthorization(f.ctx, local.hub.URL, local.nodeID, deliveries[0].MessageID, deliveries[0].AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	f.nativeScope, err = machineNativeContextScopeFromMetadata(f.ctx, "codex", local.nativeB, authorization.EndpointID, authorization.BindingID, authorization.BindingEpoch, authorization.NativeContextScope)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hub, _ := machineHubFrom(f.ctx)
	f.process = nativeDeliveryProcessFixture{Root: local.stateDir, HubID: local.hubID, NodeID: local.nodeID, Origin: local.hub.URL, Token: local.nodeToken,
		WriterScope: hub.WriterScope, NativeID: local.nativeB, ConfigPath: filepath.Join(dir, "fixture.json"), CounterPath: filepath.Join(dir, "queue-count"), ArgsPath: filepath.Join(dir, "queue-argv.json"), WitnessPath: filepath.Join(dir, "witness")}
	nativeDeliverySaveConfig(t, f.process)
	f.ctx = context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath)})
	return f
}

func (f *nativeDeliveryRelayFixture) claim(t *testing.T) (nodeinbox.Claim, machineRelayJournalEntry) {
	t.Helper()
	claim, err := f.inbox.Claim(f.ctx, machineRelayConsumerID(f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	entry := f.journal.entry(claim.MessageID)
	if entry == nil {
		t.Fatal("missing original journal")
	}
	return *claim, *entry
}
func (f *nativeDeliveryRelayFixture) drain(ctx context.Context, claim nodeinbox.Claim, entry machineRelayJournalEntry) error {
	return drainMachineCrossNodeGroupRelayClaim(ctx, f.local.hub.URL, f.local.nodeID, f.local.stateDir, f.inbox, f.journal, claim, entry)
}
func (f *nativeDeliveryRelayFixture) layers() []string {
	f.receiptsMu.Lock()
	defer f.receiptsMu.Unlock()
	return append([]string(nil), f.receipts...)
}
func nativeDeliveryCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "accepted\n")
}
func nativeDeliveryRawOutcomes(t *testing.T, root string) []nodelock.NativeOutcomeState {
	t.Helper()
	var outcomes []nodelock.NativeOutcomeState
	paths, err := filepath.Glob(filepath.Join(root, ".native-writers", "*.operations", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var outcome struct {
			State nodelock.NativeOutcomeState `json:"state"`
		}
		if json.Unmarshal(data, &outcome) != nil {
			t.Fatal("bad outcome")
		}
		outcomes = append(outcomes, outcome.State)
	}
	return outcomes
}

func TestMachineNativeDeliveryBusyPreservesClaimAndJournal(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	held := nativeDeliveryStartProcess(t, "n1-hold", f.process)
	held.ready(t, "writer_held")
	claim, entry := f.claim(t)
	ctx, cancel := context.WithTimeout(f.ctx, 200*time.Millisecond)
	err := f.drain(ctx, claim, entry)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("writer wait error: %v", err)
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.NODE_RECEIVED || stored.AttemptID != "" {
		t.Fatalf("busy claim not released: %#v %v", stored, err)
	}
	if f.journal.entry(f.messageID) == nil || nativeDeliveryCount(t, f.process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
		t.Fatal("busy writer lost journal or began injection")
	}
	if !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived}) {
		t.Fatalf("busy receipts: %v", f.layers())
	}
	if _, err := fmt.Fprintln(held.stdin, "release"); err != nil {
		t.Fatal(err)
	}
	held.wait(t, false)
	next, nextEntry := f.claim(t)
	if err := f.drain(f.ctx, next, nextEntry); err != nil {
		t.Fatal(err)
	}
	stored, err = f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatalf("retry did not accept exact queue: %#v %v", stored, err)
	}
	data, err := os.ReadFile(f.process.ArgsPath)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if json.Unmarshal(data, &args) != nil || len(args) != 5 || args[2] != f.local.nativeB || !strings.Contains(args[4], "/resume 'quoted' `not-a-command`") || !strings.Contains(args[4], "second line") {
		t.Fatalf("literal peer argv changed: %q", args)
	}
	t.Log("synthetic queue accepted once; exact literal message argv; consumption remains unconfirmed")
}

func TestMachineNativeDeliveryAuthorityChangesDuringWriterWait(t *testing.T) {
	for _, change := range []string{"membership", "binding-epoch", "lease-expiry", "node-credential", "temporary-Guard"} {
		t.Run(change, func(t *testing.T) {
			f := newNativeDeliveryRelayFixture(t)
			binding, err := f.local.store.GetActiveSessionBinding(f.local.targetMCP.endpointID)
			if err != nil {
				t.Fatal(err)
			}
			var expiry time.Time
			if change == "lease-expiry" {
				expiry = time.Now().UTC().Add(2 * time.Second)
				if _, err := f.local.store.RenewSessionBindingLease(binding.ID, binding.LeaseOwner, binding.Epoch, expiry.Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			held := nativeDeliveryStartProcess(t, "n1-hold", f.process)
			held.ready(t, "writer_held")
			claim, entry := f.claim(t)
			waiting := make(chan struct{})
			lifecycle := machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
				if phase == "writer_wait" {
					close(waiting)
				}
			}}
			ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, lifecycle)
			done := make(chan error, 1)
			go func() { done <- f.drain(ctx, claim, entry) }()
			select {
			case <-waiting:
			case <-time.After(5 * time.Second):
				t.Fatal("did not reach writer wait")
			}
			switch change {
			case "membership":
				_, err = f.local.store.RevokeMembershipForPrincipalGroup(f.local.targetMCP.sessionPublic.NetworkCard.PrincipalID, f.local.groupID, "synthetic revoke while writer busy")
			case "binding-epoch":
				_, err = f.local.store.FenceSessionBinding(binding.ID, binding.Epoch, store.SessionBindingStatusSuperseded)
			case "lease-expiry":
				timer := time.NewTimer(time.Until(expiry))
				<-timer.C
			case "node-credential":
				_, ownerBinding, getErr := f.local.store.GetOwnerBoundNodeCredentialByHash(fabric.HashSessionCredential(f.local.nodeToken))
				if getErr != nil {
					t.Fatal(getErr)
				}
				_, err = f.local.store.RevokeNodeDeviceBinding(f.local.ownerID, ownerBinding.ID, ownerBinding.Version)
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
				t.Fatal("held Guard did not return")
			}
			if nativeDeliveryCount(t, f.process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
				t.Fatal("old authority caused native injection")
			}
			stored, err := f.inbox.Get(f.ctx, f.messageID)
			if err != nil {
				t.Fatal(err)
			}
			if change == "temporary-Guard" {
				if stored.State != nodeinbox.NODE_RECEIVED || stored.AttemptID != "" || f.journal.entry(f.messageID) == nil {
					t.Fatalf("temporary authority outage lost retry: %#v", stored)
				}
				f.guardUnavailable.Store(false)
				next, nextEntry := f.claim(t)
				if err := f.drain(f.ctx, next, nextEntry); err != nil {
					t.Fatal(err)
				}
				if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
					t.Fatal("authority recovery did not queue once")
				}
			} else if stored.State != nodeinbox.FAILED {
				t.Fatalf("current denial not fenced before intent: %#v", stored)
			}
			if f.guardCalls.Load() < 3 {
				t.Fatal("no actual held-writer Hub Guard request")
			}
		})
	}
}

func TestMachineNativeDeliveryCrashAfterSuccessfulWaitBeforeOutcome(t *testing.T) {
	testMachineNativeDeliveryCrash(t, "queue_wait_succeeded", false)
}
func TestMachineNativeDeliveryCrashAfterDurableOutcomeBeforeReceipt(t *testing.T) {
	testMachineNativeDeliveryCrash(t, "accepted_writer_closed", true)
}
func testMachineNativeDeliveryCrash(t *testing.T, phase string, accepted bool) {
	f := newNativeDeliveryRelayFixture(t)
	f.process.StopPhase = phase
	nativeDeliverySaveConfig(t, f.process)
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	child := nativeDeliveryStartProcess(t, "n1-adapter", f.process)
	child.ready(t, phase)
	if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("helper did not durably accept once")
	}
	witness, err := os.ReadFile(f.process.WitnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(witness), "helper_accepted\nqueue_wait_succeeded\n") {
		t.Fatalf("missing real successful Wait ordering: %s", witness)
	}
	expected := nodelock.NativeInjecting
	if accepted {
		expected = nodelock.NativeQueueAccepted
		if !strings.HasSuffix(string(witness), "accepted_durable\naccepted_writer_closed\n") {
			t.Fatalf("D writer not durably accepted and released: %s", witness)
		}
	}
	if outcomes := nativeDeliveryRawOutcomes(t, f.process.Root); !reflect.DeepEqual(outcomes, []nodelock.NativeOutcomeState{expected}) {
		t.Fatalf("barrier native state: %v", outcomes)
	}
	barrierRecords := nativeDeliveryAuditRecords(t, f.process.Root)
	if !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived}) {
		t.Fatalf("receipt escaped crash window: %v", f.layers())
	}
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.wait(t, true)
	f.process.StopPhase = ""
	nativeDeliverySaveConfig(t, f.process)
	recovery := nativeDeliveryStartProcess(t, "n1-recover", f.process)
	recovery.wait(t, false)
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	f.journal, err = openMachineRelayJournal(f.local.stateDir, f.local.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil {
		t.Fatal(err)
	}
	entry := machineRelayJournalEntry{MessageID: f.messageID, Digest: stored.Digest, EndpointID: stored.EndpointID,
		BindingEpoch: stored.BindingEpoch, BindingID: f.local.targetMCP.sessionPublic.NetworkCard.BindingID,
		SessionID: stored.SessionID, AttemptID: "synthetic-new-remote-attempt", Harness: "codex"}
	if !accepted {
		if stored.State != nodeinbox.INJECTION_UNCERTAIN || f.journal.entry(f.messageID) == nil {
			t.Fatalf("C unknown not retained: %#v", stored)
		}
		entry = *f.journal.entry(f.messageID)
		for _, attempt := range []string{entry.AttemptID, "synthetic-new-remote-attempt"} {
			entry.AttemptID = attempt
			op, err := machineRelayNativeOperation(f.ctx, nodeinbox.Claim{Delivery: *stored}, entry)
			if err != nil {
				t.Fatal(err)
			}
			var uncertain *nativeInjectionUncertainError
			if err := executeMachineNativeCodex(f.ctx, stored.SessionID, "synthetic retry forbidden", op, f.nativeScope); !errors.As(err, &uncertain) {
				t.Fatalf("C same/new attempt replay: %v", err)
			}
		}
		if !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived, fabric.ReceiptInjectionUncertain}) {
			t.Fatalf("C promoted success: %v", f.layers())
		}
	} else {
		if stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || f.journal.entry(f.messageID) != nil {
			t.Fatalf("D durable witness not recovered: %#v", stored)
		}
		if !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived, fabric.ReceiptCodexQueueAccepted, fabric.ReceiptConsumptionUncertain}) {
			t.Fatalf("D fabricated injection/consumption: %v", f.layers())
		}
	}
	if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("crash recovery reinjected")
	}
	nativeDeliveryExportAudit(t, f, child, phase, stored.State, barrierRecords)
	t.Logf("synthetic witnesses: helper accepted -> real Wait nil -> %s before SIGKILL; original state reopened through production recovery", phase)
}

func TestMachineNativeDeliveryPreflightNeverPersistsIntent(t *testing.T) {
	root := t.TempDir()
	ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "hub_synthetic_n1", NodeID: "node_synthetic_n1", WriterRoot: root, WriterScope: "synthetic-account"})
	op := nodelock.NativeOperation{HubID: "hub_synthetic_n1", NodeID: "node_synthetic_n1", EndpointID: "ep_synthetic_n1", BindingID: "bind_synthetic_n1", BindingEpoch: 1, MessageID: "msg_synthetic_n1", Digest: "digest_synthetic_n1", AttemptID: "attempt_synthetic_n1"}
	for _, kind := range []string{"scope-mismatch", "cancelled", "missing-helper"} {
		t.Run(kind, func(t *testing.T) {
			child, cancel := context.WithCancel(ctx)
			defer cancel()
			t.Setenv("CICADA_CODEX_BIN", "/synthetic/nonexistent/n1-helper")
			admitted := false
			err := runMachineNativeDelivery(child, "native_synthetic_n1", op, func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
				if kind == "cancelled" {
					cancel()
				}
				if kind == "scope-mismatch" {
					return "synthetic prompt", []nodeinbox.NativeContextScopeInput{{NativeSessionID: "wrong-native"}}, nil
				}
				return "synthetic prompt", nil, nil
			}, func(context.Context) error { admitted = true; return nil })
			if err == nil || admitted || len(nativeDeliveryRawOutcomes(t, root)) != 0 {
				t.Fatalf("fallible preflight entered intent: admitted=%t err=%v", admitted, err)
			}
		})
	}
}

func TestMachineNativeDeliveryCleanupCannotReleaseInjecting(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(filepath.Join(root, "inbox.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := inbox.Save(ctx, nodeinbox.Message{MessageID: "msg_synthetic_cleanup", Digest: "digest_synthetic_cleanup", EndpointID: "ep_synthetic_cleanup", SessionID: "native_synthetic_cleanup", BindingEpoch: 1, Payload: []byte("synthetic")}); err != nil {
		t.Fatal(err)
	}
	claim, err := inbox.Claim(ctx, "synthetic-consumer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := abandonMachineNativeClaim(ctx, inbox, *claim); err == nil {
		t.Fatal("cleanup released injecting")
	}
	stored, err := inbox.Get(context.Background(), claim.MessageID)
	if err != nil || stored.State != nodeinbox.INJECTING {
		t.Fatalf("cleanup changed unknown: %#v %v", stored, err)
	}
}

func TestMachineNativeDeliveryStartedFailureAndCommitFailureStayUncertain(t *testing.T) {
	for _, fault := range []string{"nonzero-after-accept", "outcome-commit-failure"} {
		t.Run(fault, func(t *testing.T) {
			f := newNativeDeliveryRelayFixture(t)
			ctx := f.ctx
			var original, backup string
			if fault == "nonzero-after-accept" {
				f.process.QueueExit = 2
				nativeDeliverySaveConfig(t, f.process)
			} else {
				lifecycle := machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
					if phase != "queue_wait_succeeded" {
						return
					}
					dirs, err := filepath.Glob(filepath.Join(f.process.Root, ".native-writers", "*.operations"))
					if err != nil || len(dirs) != 1 {
						panic("missing authentic native intent")
					}
					original = dirs[0]
					backup = original + ".synthetic-backup"
					if err := os.Rename(original, backup); err != nil {
						panic(err)
					}
					if err := os.WriteFile(original, []byte("synthetic commit fault"), 0o600); err != nil {
						panic(err)
					}
				}}
				ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, lifecycle)
			}
			claim, entry := f.claim(t)
			err := f.drain(ctx, claim, entry)
			if fault == "outcome-commit-failure" {
				if err == nil {
					t.Fatal("commit failure was swallowed")
				}
				if err := os.Remove(original); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(backup, original); err != nil {
					t.Fatal(err)
				}
				if err := reconcileMachineRelayJournal(f.ctx, f.local.hub.URL, f.local.nodeID, f.local.stateDir, f.inbox, f.journal); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			stored, err := f.inbox.Get(f.ctx, f.messageID)
			if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN || f.journal.entry(f.messageID) == nil {
				t.Fatalf("started failure not uncertain: %#v %v", stored, err)
			}
			if _, err := f.inbox.Claim(f.ctx, "synthetic-new-consumer"); !errors.Is(err, nodeinbox.ErrNoDelivery) {
				t.Fatalf("uncertain was claimable: %v", err)
			}
			op, err := machineRelayNativeOperation(f.ctx, nodeinbox.Claim{Delivery: *stored}, entry)
			if err != nil {
				t.Fatal(err)
			}
			op.AttemptID = "synthetic-new-remote-attempt"
			var uncertain *nativeInjectionUncertainError
			if err := executeMachineNativeCodex(f.ctx, stored.SessionID, "synthetic retry forbidden", op, f.nativeScope); !errors.As(err, &uncertain) {
				t.Fatalf("failed operation requeued: %v", err)
			}
			if nativeDeliveryCount(t, f.process.CounterPath) != 1 || !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived, fabric.ReceiptInjectionUncertain}) {
				t.Fatal("failure fabricated success or duplicated queue")
			}
		})
	}
}

func TestMachineNativeDeliveryAcceptedReplayUsesExactDurableIdentity(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	claim, entry := f.claim(t)
	if err := f.drain(f.ctx, claim, entry); err != nil {
		t.Fatal(err)
	}
	op, err := machineRelayNativeOperation(f.ctx, claim, entry)
	if err != nil {
		t.Fatal(err)
	}
	op.AttemptID = "synthetic-new-remote-attempt"
	t.Setenv("CICADA_CODEX_BIN", "/synthetic/missing/codex")
	// No dependency override: a durable result needs no CLI preparation.
	ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{})
	if err := executeMachineNativeCodex(ctx, claim.SessionID, "synthetic replay", op, f.nativeScope); err != nil {
		t.Fatal(err)
	}
	if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("accepted receipt replay called queue")
	}
	for _, change := range []string{"Hub", "binding", "epoch", "digest"} {
		different := op
		switch change {
		case "Hub":
			different.HubID = "hub_other_synthetic"
		case "binding":
			different.BindingID = "bind_other_synthetic"
		case "epoch":
			different.BindingEpoch++
		case "digest":
			different.Digest = "other_synthetic_digest"
		}
		if err := requireMachineNativeQueueOutcome(f.ctx, claim.SessionID, different); err == nil {
			t.Fatalf("accepted outcome transplanted %s", change)
		}
	}
}

func TestMachineNativeDeliveryDurableReceiptDeniedRetainsRecovery(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	f.process.StopPhase = "accepted_writer_closed"
	nativeDeliverySaveConfig(t, f.process)
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	child := nativeDeliveryStartProcess(t, "n1-adapter", f.process)
	child.ready(t, "accepted_writer_closed")
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.wait(t, true)
	binding, err := f.local.store.GetActiveSessionBinding(f.local.targetMCP.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.store.FenceSessionBinding(binding.ID, binding.Epoch, store.SessionBindingStatusSuperseded); err != nil {
		t.Fatal(err)
	}
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	f.journal, err = openMachineRelayJournal(f.local.stateDir, f.local.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	if err := reconcileMachineRelayJournal(ctx, f.local.hub.URL, f.local.nodeID, f.local.stateDir, f.inbox, f.journal); err == nil {
		t.Fatal("rebound receiver posted new queue success")
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatalf("durable local witness lost: %#v %v", stored, err)
	}
	entry := f.journal.entry(f.messageID)
	if entry == nil || !entry.QueueAccepted || entry.QueueAcceptedSent {
		t.Fatalf("denied receipt lost exact journal: %#v", entry)
	}
	if outcomes := nativeDeliveryRawOutcomes(t, f.process.Root); !reflect.DeepEqual(outcomes, []nodelock.NativeOutcomeState{nodelock.NativeQueueAccepted}) {
		t.Fatalf("denied receipt rewrote native outcome: %v", outcomes)
	}
	if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("receipt denial reinjected")
	}
	t.Log("production current-binding receipt Guard denies stale success; local durable acceptance/journal retained without a second queue")
}

// This separately selectable transport gate runs production MCP + owner Unix
// socket, a Fabric-only HTTP/TCP Hub, authenticated sealed ingress, and a Node
// receiver subprocess. The queue witness is synthetic; it is one loopback
// topology, not two physical Nodes, public HTTPS, or actual Codex wake.
func TestMachineNativeDeliveryTransport(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	response, err := http.Get(f.local.hub.URL + "/v1/groups")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil Control management status=%d", response.StatusCode)
	}
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	child := nativeDeliveryStartProcess(t, "n1-adapter", f.process)
	child.wait(t, false)
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatalf("receiver did not persist exact queue acceptance: %#v %v", stored, err)
	}
	if !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived, fabric.ReceiptCodexQueueAccepted, fabric.ReceiptConsumptionUncertain}) {
		t.Fatalf("transport layers=%v", f.layers())
	}
	t.Log("production MCP/socket/TCP Fabric-only sealed transport + receiver subprocess PASS; synthetic queue witness; native consumption NOT_RUN")
}

func TestMachineNativeDeliveryConflictingDurableIdentityIsFenced(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	claim, entry := f.claim(t)
	op, err := machineRelayNativeOperation(f.ctx, claim, entry)
	if err != nil {
		t.Fatal(err)
	}
	// An actual successful queue persists a different immutable digest under the
	// same operation key. This is not a hand-written native intent/success row.
	op.Digest = "synthetic-prior-different-digest"
	if err := executeMachineNativeCodex(f.ctx, claim.SessionID, "synthetic earlier queue", op, f.nativeScope); err != nil {
		t.Fatal(err)
	}
	if err := f.drain(f.ctx, claim, entry); err != nil {
		t.Fatal(err)
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.FAILED || f.journal.entry(f.messageID) != nil {
		t.Fatalf("stable identity conflict remained retryable: %#v %v", stored, err)
	}
	if _, err := f.inbox.Claim(f.ctx, "synthetic-conflict-retry"); !errors.Is(err, nodeinbox.ErrNoDelivery) {
		t.Fatalf("stable conflict can be reclaimed: %v", err)
	}
	if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatal("identity conflict started another queue")
	}
}

type nativeDeliveryAuditRecord struct {
	File    string          `json:"file"`
	SHA256  string          `json:"sha256"`
	Bytes   json.RawMessage `json:"synthetic_native_outcome"`
	RawJSON string          `json:"raw_json_text"`
}

func nativeDeliveryAuditRecords(t *testing.T, root string) []nativeDeliveryAuditRecord {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, ".native-writers", "*.operations", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	records := make([]nativeDeliveryAuditRecord, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 8192 {
			t.Fatalf("bounded native audit read: %v", err)
		}
		digest := sha256.Sum256(data)
		records = append(records, nativeDeliveryAuditRecord{File: filepath.Base(path), SHA256: hex.EncodeToString(digest[:]), Bytes: data, RawJSON: string(data)})
	}
	return records
}
func nativeDeliveryExportAudit(t *testing.T, f *nativeDeliveryRelayFixture, child *nativeDeliveryProcess, phase string, recovered nodeinbox.State, before []nativeDeliveryAuditRecord) {
	t.Helper()
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 65536 {
			t.Fatalf("bounded synthetic witness read: %v", err)
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
	audit := map[string]any{"test": t.Name(), "fixture": "SYNTHETIC OFFLINE QUEUE; NO CODEX OR PROVIDER", "barrier": phase,
		"adapter_exit_code": child.exitCode, "adapter_signal": child.signal, "native_before_kill": before,
		"native_after_recovery": nativeDeliveryAuditRecords(t, f.process.Root), "recovered_inbox_state": recovered,
		"witness": string(witness), "witness_sha256": digest(witness), "counter": string(counter), "counter_sha256": digest(counter),
		"synthetic_argv": json.RawMessage(args), "argv_raw_json_text": string(args), "argv_sha256": digest(args), "queue_count": nativeDeliveryCount(t, f.process.CounterPath),
		"production_http_receipt_layers": f.layers(), "test_helper_binary_sha256": hex.EncodeToString(hash.Sum(nil)),
		"product_binary": "NOT_BUILT_BY_THIS_TEST", "actual_native_runtime": "NOT_RUN"}
	encoded, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("N1_PROCESS_AUDIT %s", encoded)
	// Test-only evidence export; production never reads this environment variable.
	if directory := os.Getenv("CICADA_N1_TEST_EVIDENCE_DIR"); directory != "" {
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

func TestMachineNativeDeliveryAmbiguousInboxAdmissionStaysUnknown(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	claim, entry := f.claim(t)
	op, err := machineRelayNativeOperation(f.ctx, claim, entry)
	if err != nil {
		t.Fatal(err)
	}
	err = runMachineNativeDelivery(f.ctx, claim.SessionID, op, func(context.Context) (string, []nodeinbox.NativeContextScopeInput, error) {
		return "synthetic partial admission", []nodeinbox.NativeContextScopeInput{f.nativeScope}, nil
	}, func(ctx context.Context) error {
		if _, err := f.inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
			return err
		}
		return errors.New("synthetic lost local BeginInjection acknowledgement")
	})
	if err == nil {
		t.Fatal("ambiguous local admission ignored")
	}
	if err := abandonMachineNativeClaim(f.ctx, f.inbox, claim); err == nil {
		t.Fatal("ambiguous admission released injecting")
	}
	if nativeDeliveryCount(t, f.process.CounterPath) != 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
		t.Fatal("partial admission started native operation")
	}
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN || f.journal.entry(f.messageID) == nil {
		t.Fatalf("partial admission falsely reset: %#v %v", stored, err)
	}
	if err := reconcileMachineRelayJournal(f.ctx, f.local.hub.URL, f.local.nodeID, f.local.stateDir, f.inbox, f.journal); err != nil {
		t.Fatal(err)
	}
	if nativeDeliveryCount(t, f.process.CounterPath) != 0 || !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived, fabric.ReceiptInjectionUncertain}) {
		t.Fatal("partial admission promoted success or queue retry")
	}
}

func TestMachineNativeDeliveryStartedCancellationRecoversUnknown(t *testing.T) {
	f := newNativeDeliveryRelayFixture(t)
	f.process.QueueBlock = true
	nativeDeliverySaveConfig(t, f.process)
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	blockReader, blockWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = readyReader.Close()
		_ = readyWriter.Close()
		_ = blockReader.Close()
		_ = blockWriter.Close()
	})
	command := nativeDeliveryQueueCommand(f.process.ConfigPath)
	lifecycle := machineNativeDeliveryLifecycle{command: func(ctx context.Context, binary string, args ...string) *exec.Cmd {
		child := command(ctx, binary, args...)
		child.ExtraFiles = []*os.File{readyWriter, blockReader}
		return child
	}}
	ctx, cancel := context.WithCancel(context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, lifecycle))
	defer cancel()
	claim, entry := f.claim(t)
	done := make(chan error, 1)
	go func() { done <- f.drain(ctx, claim, entry) }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(readyReader).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "accepted\n" {
			t.Fatalf("queue start witness=%q", line)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("queue never durably accepted before cancellation")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled started queue returned success")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("started queue cancellation stuck")
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.INJECTING {
		t.Fatalf("cancelled parent unexpectedly committed inbox receipt: %#v %v", stored, err)
	}
	if outcomes := nativeDeliveryRawOutcomes(t, f.process.Root); !reflect.DeepEqual(outcomes, []nodelock.NativeOutcomeState{nodelock.NativeUncertain}) {
		t.Fatalf("started cancellation native outcome=%v", outcomes)
	}
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.local.stateDir, f.local.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileMachineRelayJournal(f.ctx, f.local.hub.URL, f.local.nodeID, f.local.stateDir, f.inbox, f.journal); err != nil {
		t.Fatal(err)
	}
	stored, err = f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN || f.journal.entry(f.messageID) == nil || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatalf("started cancellation recovery: %#v %v", stored, err)
	}
	t.Log("started parent cancellation retains local INJECTING until production reopen; native UNCERTAIN fences reinjection; no detached-context unknown cleanup")
}
