package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// g4CrashProcessConfig contains only synthetic fixture values. The helper is
// this test executable running selected production Go components in a distinct
// OS process; it never starts Codex, a native Runtime, or an external provider.
type g4CrashProcessConfig struct {
	DatabasePath string         `json:"database_path,omitempty"`
	OwnerID      string         `json:"owner_id,omitempty"`
	GatePath     string         `json:"gate_path,omitempty"`
	GateMode     string         `json:"gate_mode,omitempty"`
	OutboxPath   string         `json:"outbox_path,omitempty"`
	OutboxScope  mcpOutboxScope `json:"outbox_scope,omitempty"`
	OutboxKind   string         `json:"outbox_kind,omitempty"`
	OutboxKey    string         `json:"outbox_key,omitempty"`
	OutboxInput  mcpOutboxInput `json:"outbox_input,omitempty"`
	OperationID  string         `json:"operation_id,omitempty"`
	NodeID       string         `json:"node_id,omitempty"`
	NodeToken    string         `json:"node_token,omitempty"`
	StateDir     string         `json:"state_dir,omitempty"`
	MessageID    string         `json:"message_id,omitempty"`
	DeliveryPath string         `json:"delivery_path,omitempty"`
}

func g4ReadConfig(path string) (g4CrashProcessConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return g4CrashProcessConfig{}, err
	}
	var config g4CrashProcessConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return config, err
	}
	return config, nil
}

func g4WaitForLine() error {
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return err
}

// TestG4CrashWindowProcessHelper is invoked only by TestG4CrashWindowsAtDurableBoundaries.
// It deliberately exposes three deterministic barriers around real persisted
// boundaries, without adding a production hook or invoking Runtime injection.
func TestG4CrashWindowProcessHelper(t *testing.T) {
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || len(os.Args) <= separator+2 {
		return
	}
	mode, configPath := os.Args[separator+1], os.Args[separator+2]
	cfg, err := g4ReadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "outbox-before-http":
		outbox := newMCPOutbox(cfg.OutboxPath)
		op, created, err := outbox.prepare(cfg.OutboxScope, cfg.OutboxKind, cfg.OutboxKey, cfg.OutboxInput)
		if err != nil || !created {
			t.Fatalf("prepare synthetic outbox: created=%t err=%v", created, err)
		}
		op, err = outbox.markAttempt(cfg.OutboxScope, op.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if op.Status != mcpOutboxStatusUnknown || op.AttemptCount != 1 {
			t.Fatalf("unexpected pre-HTTP durable state: status=%s attempts=%d", op.Status, op.AttemptCount)
		}
		fmt.Printf("READY outbox %s %s\n", op.OperationID, op.InputDigest)
		if err := g4WaitForLine(); err != nil {
			t.Fatal(err)
		}
	case "hub-serve":
		state, err := store.New(cfg.DatabasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer state.Close()
		service, err := fabric.NewService(state, cfg.OwnerID, cfg.OwnerID)
		if err != nil {
			t.Fatal(err)
		}
		inner := serverpkg.NewFabricHandler(service, "")
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.GatePath == "" || r.URL.Path != cfg.GatePath {
				inner.ServeHTTP(w, r)
				return
			}
			if cfg.GateMode == "before" {
				fmt.Printf("READY gate %s\n", r.URL.Path)
				if err := g4WaitForLine(); err != nil {
					return
				}
				inner.ServeHTTP(w, r)
				return
			}
			recorded := httptest.NewRecorder()
			inner.ServeHTTP(recorded, r)
			fmt.Printf("READY gate %s\n", r.URL.Path)
			if err := g4WaitForLine(); err != nil {
				return
			}
			for key, values := range recorded.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			status := recorded.Code
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			_, _ = w.Write(recorded.Body.Bytes())
		})
		server := &http.Server{Handler: gate, ReadHeaderTimeout: 2 * time.Second}
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve(listener) }()
		fmt.Printf("READY listen http://%s\n", listener.Addr().String())
		if err := g4WaitForLine(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		if err := <-serveDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	case "node-accept", "node-reaccept":
		var delivery fabric.NodeSealedDelivery
		if mode == "node-accept" {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var response struct {
				Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
			}
			endpoint := strings.TrimRight(os.Getenv("G4_HUB_ORIGIN"), "/") +
				"/v2/relay/nodes/" + urlPath(cfg.NodeID) + "/sealed/claim"
			if err := machineAPIJSON(ctx, endpoint, http.MethodPost,
				fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(cfg.NodeID), Limit: 10}, &response); err != nil {
				t.Fatalf("claim through production Node HTTP route: %v", err)
			}
			if len(response.Deliveries) != 1 || response.Deliveries[0].MessageID != cfg.MessageID {
				t.Fatalf("claim exact synthetic delivery: count=%d", len(response.Deliveries))
			}
			delivery = response.Deliveries[0]
			data, err := json.Marshal(delivery)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.DeliveryPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
		} else {
			data, err := os.ReadFile(cfg.DeliveryPath)
			if err != nil || json.Unmarshal(data, &delivery) != nil {
				t.Fatal("read claimed synthetic delivery")
			}
		}
		inbox, err := nodeinbox.Open(machineNodeInboxPath(cfg.StateDir, cfg.NodeID))
		if err != nil {
			t.Fatal(err)
		}
		defer inbox.Close()
		journal, err := openMachineRelayJournal(cfg.StateDir, cfg.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := acceptMachineSealedRelayDelivery(ctx, os.Getenv("G4_HUB_ORIGIN"), cfg.NodeID,
			cfg.StateDir, inbox, journal, delivery); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("READY node-accepted %s\n", delivery.MessageID)
		if err := g4WaitForLine(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown G4 helper mode %q", mode)
	}
}

type g4CrashChild struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	done   chan error
	stderr bytes.Buffer
}

func g4StartCrashChild(t *testing.T, mode, configPath string, env map[string]string) *g4CrashChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestG4CrashWindowProcessHelper$", "--", mode, configPath)
	baseEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	for key, value := range env {
		baseEnv = append(baseEnv, key+"="+value)
	}
	cmd.Env = baseEnv
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child := &g4CrashChild{cmd: cmd, stdin: stdin, lines: make(chan string, 32), done: make(chan error, 1)}
	cmd.Stderr = &child.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			child.lines <- scanner.Text()
		}
		close(child.lines)
		child.done <- cmd.Wait()
	}()
	t.Cleanup(func() { child.killAndWait(t) })
	return child
}

func (p *g4CrashChild) ready(t *testing.T, prefix string) string {
	t.Helper()
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				t.Fatalf("helper exited before %q: %s", prefix, p.stderr.String())
			}
			if strings.HasPrefix(line, prefix) {
				return line
			}
		case <-timer.C:
			t.Fatalf("helper did not reach %q: %s", prefix, p.stderr.String())
		}
	}
}

func (p *g4CrashChild) killAndWait(t *testing.T) {
	t.Helper()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case err := <-p.done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Errorf("expected killed helper process, exit=%v", err)
		} else if status, ok := exit.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Errorf("helper did not receive SIGKILL: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("owned G4 helper did not exit after kill")
	}
	_ = p.stdin.Close()
	p.cmd.Process = nil
}

func (p *g4CrashChild) stop(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(p.stdin, "stop\n"); err != nil {
		t.Fatalf("stop helper: %v", err)
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("helper shutdown: %v stderr=%s", err, p.stderr.String())
		}
		p.cmd.Process = nil
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not stop")
	}
}

func g4SaveConfig(t *testing.T, config g4CrashProcessConfig) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "g4-process.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestG4CrashWindowsAtDurableBoundaries(t *testing.T) {
	t.Setenv("G4_CRASH_WINDOW_FIXTURE", "PUBLIC_SYNTHETIC_ONLY")
	t.Run("sender_outbox_durable_before_http", func(t *testing.T) {
		outboxPath := filepath.Join(t.TempDir(), "mcp-outbox.sqlite3")
		var requests atomic.Int32
		counter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer counter.Close()
		scope := mcpOutboxScope{APIOrigin: counter.URL, Scope: "g4-synthetic-scope",
			Harness: "codex", NativeSessionID: "thread-g4-synthetic", NodeID: "node-g4-synthetic",
			Workspace: "/PUBLIC_SYNTHETIC/g4", EndpointID: "ep-g4-synthetic", GroupID: "group-g4-synthetic"}
		input := mcpOutboxInput{LinkID: "link-g4-synthetic", DataScope: "thread.message", Body: "PUBLIC_SYNTHETIC_G4_ASK"}
		cfg := g4CrashProcessConfig{OutboxPath: outboxPath, OutboxScope: scope, OutboxKind: "sealed_ask",
			OutboxKey: "PUBLIC_SYNTHETIC_IDEMPOTENCY", OutboxInput: input}
		child := g4StartCrashChild(t, "outbox-before-http", g4SaveConfig(t, cfg), nil)
		line := child.ready(t, "READY outbox ")
		parts := strings.Fields(line)
		if len(parts) != 4 {
			t.Fatalf("bad helper witness: %q", line)
		}
		child.killAndWait(t)
		outbox := newMCPOutbox(outboxPath)
		op, err := outbox.load(scope, parts[2])
		if err != nil {
			t.Fatalf("reload durable outbox operation: %v", err)
		}
		if op.Status != mcpOutboxStatusUnknown || op.AttemptCount != 1 || op.InputDigest != parts[3] {
			t.Fatalf("outbox recovery changed immutable attempt: status=%s attempts=%d digest_match=%t err=%v",
				op.Status, op.AttemptCount, op.InputDigest == parts[3], err)
		}
		retry, created, err := outbox.prepare(scope, cfg.OutboxKind, cfg.OutboxKey, input)
		if err != nil || created || retry.OperationID != op.OperationID || retry.InputDigest != op.InputDigest {
			t.Fatalf("outbox retry changed operation identity: created=%t err=%v", created, err)
		}
		if got := requests.Load(); got != 0 {
			t.Fatalf("pre-HTTP crash unexpectedly contacted the synthetic Hub: requests=%d", got)
		}
	})

	t.Run("hub_commit_before_http_ack_and_node_persist_before_receipt", func(t *testing.T) {
		fixture := newMachineSealedReceiveFixtureWithActions(t, false, "ask", []string{"ask", "reply"})
		ask := fabric.NodeSealedLinkAskInput{LinkID: fixture.link.ID, MessageID: fixture.messageID,
			RequestID: fixture.requestID, IdempotencyKey: "PUBLIC_SYNTHETIC_G4_ASK_KEY",
			DataScope: fixture.dataScope, ExpiresAt: fixture.link.ExpiresAt, Ciphertext: fixture.ciphertext}
		askJSON, err := json.Marshal(ask)
		if err != nil {
			t.Fatal(err)
		}
		askPath := "/v2/relay/nodes/" + fixture.sourceNodeID + "/sealed/ask"
		hubConfig := g4CrashProcessConfig{DatabasePath: fixture.databasePath,
			OwnerID: fixture.link.SourceOwnerID, GatePath: askPath, GateMode: "after"}
		hub := g4StartCrashChild(t, "hub-serve", g4SaveConfig(t, hubConfig), nil)
		listen := strings.Fields(hub.ready(t, "READY listen "))
		if len(listen) != 3 {
			t.Fatalf("bad Hub listener witness: %v", listen)
		}
		origin := listen[2]
		requestDone := make(chan error, 1)
		go func() {
			_, requestErr := g4PostJSON(origin+askPath, fixture.sourceToken, askJSON)
			requestDone <- requestErr
		}()
		hub.ready(t, "READY gate "+askPath)
		hub.killAndWait(t) // service handler returned from the committed ASK before its HTTP response is written.
		if err := <-requestDone; err == nil {
			t.Fatal("client unexpectedly received the ACK that the child was killed before writing")
		}
		persisted, err := fixture.store.GetRelaySealedV1(fixture.messageID)
		if err != nil || persisted.Route.RequestID != fixture.requestID || persisted.Route.ReplyTo != "" ||
			persisted.Route.Kind != "ask" || persisted.PayloadMode != store.RelayPayloadModeSealedV1 {
			t.Fatalf("committed ASK route changed across Hub process death: %#v err=%v", persisted, err)
		}
		status, err := fixture.service.NodeSealedLinkRequestStatus(fixture.sourceToken, fixture.requestID)
		if err != nil || status.MessageID != fixture.messageID || status.RequestID != fixture.requestID ||
			status.State != store.FabricRequestOpen {
			t.Fatalf("committed ASK state/request changed: %#v err=%v", status, err)
		}

		hubConfig.GatePath = ""
		hub = g4StartCrashChild(t, "hub-serve", g4SaveConfig(t, hubConfig), nil)
		listen = strings.Fields(hub.ready(t, "READY listen "))
		origin = listen[2]
		response, err := g4PostJSON(origin+askPath, fixture.sourceToken, askJSON)
		if err != nil || response.StatusCode != http.StatusAccepted {
			t.Fatalf("idempotent post-restart ASK retry: status=%d err=%v", response.StatusCode, err)
		}
		var accepted struct {
			MessageID string `json:"message_id"`
			RequestID string `json:"request_id"`
			State     string `json:"state"`
		}
		if json.Unmarshal(response.Body, &accepted) != nil || accepted.MessageID != fixture.messageID ||
			accepted.RequestID != fixture.requestID || accepted.State != string(store.FabricRequestOpen) {
			t.Fatalf("retry did not preserve durable ASK identifiers/state: %#v", accepted)
		}
		hub.stop(t)

		deliveryPath := filepath.Join(t.TempDir(), "claimed-delivery.json")
		nodeConfig := g4CrashProcessConfig{DatabasePath: fixture.databasePath, OwnerID: fixture.link.SourceOwnerID,
			NodeID: fixture.targetNodeID, NodeToken: fixture.targetToken, StateDir: fixture.stateDir,
			MessageID: fixture.messageID, DeliveryPath: deliveryPath}
		gatePath := "/v2/relay/nodes/" + fixture.targetNodeID + "/receipts"
		hubConfig = g4CrashProcessConfig{DatabasePath: fixture.databasePath, OwnerID: fixture.link.SourceOwnerID,
			GatePath: gatePath, GateMode: "before"}
		hub = g4StartCrashChild(t, "hub-serve", g4SaveConfig(t, hubConfig), nil)
		listen = strings.Fields(hub.ready(t, "READY listen "))
		origin = listen[2]
		node := g4StartCrashChild(t, "node-accept", g4SaveConfig(t, nodeConfig), map[string]string{
			"G4_HUB_ORIGIN": origin, "CICADA_NODE_TOKEN": fixture.targetToken,
		})
		hub.ready(t, "READY gate "+gatePath)
		deliveryJSON, err := os.ReadFile(deliveryPath)
		if err != nil {
			t.Fatalf("read claimed delivery before receipt boundary: %v", err)
		}
		var delivery fabric.NodeSealedDelivery
		if err := json.Unmarshal(deliveryJSON, &delivery); err != nil || delivery.MessageID != fixture.messageID ||
			delivery.RequestID != fixture.requestID || delivery.BindingEpoch != fixture.manifest.Target.BindingEpoch {
			t.Fatalf("claim did not retain current ASK route/epoch: %#v err=%v", delivery, err)
		}
		wrongAck := fabric.NodeReceiptInput{AttemptID: delivery.AttemptID, MessageID: delivery.MessageID,
			Digest: delivery.Digest, EndpointID: delivery.RecipientEndpointID, BindingID: delivery.BindingID,
			BindingEpoch: delivery.BindingEpoch + 1, Layer: fabric.ReceiptNodeReceived}
		if _, err := fixture.service.RecordNodeReceipt(fixture.targetNodeID, wrongAck); err == nil {
			t.Fatal("wrong-epoch Node receipt was accepted")
		}
		wrongDigest := wrongAck
		wrongDigest.BindingEpoch = delivery.BindingEpoch
		wrongDigest.Digest = "PUBLIC_SYNTHETIC_WRONG_DIGEST"
		if _, err := fixture.service.RecordNodeReceipt(fixture.targetNodeID, wrongDigest); err == nil {
			t.Fatal("wrong-digest Node receipt was accepted")
		}
		node.killAndWait(t) // acceptMachineSealedRelayDelivery saves journal+inbox before POSTing NODE_RECEIVED.
		hub.killAndWait(t)
		inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := inbox.Get(context.Background(), fixture.messageID)
		_ = inbox.Close()
		if err != nil || stored == nil || stored.State != nodeinbox.NODE_RECEIVED {
			t.Fatalf("Node process died before a durable correlated inbox entry: %#v err=%v", stored, err)
		}
		journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
		if err != nil {
			t.Fatal(err)
		}
		entry := journal.entry(fixture.messageID)
		if entry == nil || entry.NodeReceived || entry.RequestID != fixture.requestID || entry.BindingEpoch != delivery.BindingEpoch {
			t.Fatalf("pre-receipt journal did not preserve exact route/epoch: %#v", entry)
		}

		hubConfig.GatePath = ""
		hub = g4StartCrashChild(t, "hub-serve", g4SaveConfig(t, hubConfig), nil)
		listen = strings.Fields(hub.ready(t, "READY listen "))
		origin = listen[2]
		node = g4StartCrashChild(t, "node-reaccept", g4SaveConfig(t, nodeConfig), map[string]string{
			"G4_HUB_ORIGIN": origin, "CICADA_NODE_TOKEN": fixture.targetToken,
		})
		node.ready(t, "READY node-accepted "+fixture.messageID)
		node.stop(t)
		hub.stop(t)
		inbox, err = nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
		if err != nil {
			t.Fatal(err)
		}
		stored, err = inbox.Get(context.Background(), fixture.messageID)
		_ = inbox.Close()
		journal, err = openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
		if err != nil {
			t.Fatalf("reopen durable Node journal after restart: %v", err)
		}
		entry = journal.entry(fixture.messageID)
		if stored == nil || stored.MessageID != fixture.messageID || stored.State != nodeinbox.NODE_RECEIVED ||
			entry == nil || !entry.NodeReceived || entry.RequestID != fixture.requestID ||
			entry.AttemptID != delivery.AttemptID {
			t.Fatalf("Node restart did not deduplicate and finish receipt: inbox=%#v entry=%#v err=%v", stored, entry, err)
		}
		requestState, err := fixture.service.NodeSealedLinkRequestStatus(fixture.targetToken, fixture.requestID)
		if err != nil || requestState.MessageID != fixture.messageID || requestState.State != store.FabricRequestOpen {
			t.Fatalf("Node receipt changed ASK correlation/lifecycle: %#v err=%v", requestState, err)
		}
		const replyMessageID = "msg_g4_synthetic_reply"
		_ = enqueueMachineSealedReply(t, fixture, replyMessageID, "PUBLIC_SYNTHETIC_G4_REPLY")
		reply, err := fixture.store.GetRelaySealedV1(replyMessageID)
		if err != nil || reply.Route.RequestID != fixture.requestID || reply.Route.ReplyTo != fixture.messageID ||
			reply.Route.Kind != "reply" {
			t.Fatalf("synthetic reply lost immutable ASK correlation: %#v err=%v", reply, err)
		}
	})
}

type g4HTTPResult struct {
	StatusCode int
	Body       []byte
}

func g4PostJSON(endpoint, token string, payload []byte) (g4HTTPResult, error) {
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return g4HTTPResult{}, err
	}
	request.Header.Set("Authorization", "CicadaNode "+token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Do(request)
	if err != nil {
		return g4HTTPResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	return g4HTTPResult{StatusCode: response.StatusCode, Body: body}, err
}
