package main

// Opt-in protocol acceptance only. This file never creates a native Thread,
// starts a Runtime, mounts credentials, resumes, or starts a model turn.
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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodelock"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/coder/websocket"
)

type realQueueFixture struct {
	Schema                 string `json:"schema"`
	Root                   string `json:"root"`
	CLI                    string `json:"cli"`
	CLISHA256              string `json:"cli_sha256"`
	RuntimeImage           string `json:"runtime_image"`
	Socket                 string `json:"socket"`
	CodexHome              string `json:"codex_home"`
	SID                    string `json:"sid"`
	Synthetic              bool   `json:"synthetic"`
	CredentialsAbsent      bool   `json:"credentials_absent"`
	ProviderEgressDisabled bool   `json:"provider_egress_disabled"`
	MaxProviderPOSTs       int    `json:"max_provider_posts"`
	ProfileScope           string `json:"profile_scope"`
	BaselineTurnCount      *int   `json:"baseline_turn_count"`
	BaselineHistorySHA256  string `json:"baseline_history_sha256"`
}

var realQueueSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var realQueueSID = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
var realQueueUserAgentVersion = regexp.MustCompile(`(?:^|[/ ])` + regexp.QuoteMeta(realQueueCLIVersion) + `(?:[ /)]|$)`)

const realQueueMaxCLIBytes int64 = 512 << 20
const realQueueProfileScope = "independent-copy-historical-synthetic-b"
const realQueueCLIVersion = "0.162.0"

func realQueueHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func realQueueVersionMatches(output string) bool {
	return strings.TrimSpace(output) == "codex-cli "+realQueueCLIVersion
}

func realQueueUserAgentMatches(value string) bool {
	return realQueueUserAgentVersion.MatchString(value)
}

func realQueueDecodeFixture(data []byte, expectedSHA string) (realQueueFixture, error) {
	var f realQueueFixture
	if len(data) == 0 || len(data) > 8192 || !realQueueSHA.MatchString(expectedSHA) || realQueueHash(data) != expectedSHA {
		return f, errors.New("fixture receipt size or digest mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF {
		return f, errors.New("fixture receipt is not one typed object")
	}
	if f.Schema != "cicada.synthetic-native-queue-crash.v1" || !f.Synthetic || !f.CredentialsAbsent || !f.ProviderEgressDisabled || f.MaxProviderPOSTs != 0 || !realQueueSID.MatchString(f.SID) || !realQueueSHA.MatchString(f.CLISHA256) || !strings.HasPrefix(f.RuntimeImage, "sha256:") || !realQueueSHA.MatchString(strings.TrimPrefix(f.RuntimeImage, "sha256:")) {
		return f, errors.New("fixture identity or zero-provider policy mismatch")
	}
	if f.ProfileScope != realQueueProfileScope || f.BaselineTurnCount == nil || *f.BaselineTurnCount < 0 || *f.BaselineTurnCount > 4 || !realQueueSHA.MatchString(f.BaselineHistorySHA256) {
		return f, errors.New("independent synthetic B profile or explicit frozen history baseline mismatch")
	}
	for _, p := range []string{f.Root, f.CLI, f.Socket, f.CodexHome} {
		if len(p) > 512 || !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return f, errors.New("fixture path is not bounded and absolute")
		}
	}
	if !strings.HasPrefix(filepath.Base(f.Root), "cicada-native-queue-crash-") || len(f.Socket) > 100 {
		return f, errors.New("disposable root or Unix socket path mismatch")
	}
	for _, p := range []string{f.Socket, f.CodexHome} {
		rel, err := filepath.Rel(f.Root, p)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return f, errors.New("fixture state escapes disposable root")
		}
	}
	return f, nil
}

func realQueueCheckFiles(f realQueueFixture) error {
	for _, p := range []string{f.Root, f.CLI, f.Socket, f.CodexHome} {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil || resolved != p {
			return errors.New("fixture file is unavailable or traverses a symlink")
		}
	}
	root, err := os.Stat(f.Root)
	if err != nil || !root.IsDir() || root.Mode().Perm()&0077 != 0 {
		return errors.New("fixture root must be a private directory")
	}
	socket, err := os.Stat(f.Socket)
	if err != nil || socket.Mode()&os.ModeSocket == 0 {
		return errors.New("owned Unix socket is unavailable")
	}
	file, err := os.Open(f.CLI)
	if err != nil {
		return errors.New("pinned official CLI unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("pinned CLI file invalid")
	}
	if info.Size() > realQueueMaxCLIBytes {
		return errors.New("pinned CLI exceeds 512 MiB limit")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || hex.EncodeToString(hash.Sum(nil)) != f.CLISHA256 {
		return errors.New("official CLI digest mismatch")
	}
	return nil
}

// No inherited provider credentials/config environment enters the child. The
// owner must additionally isolate the already-running Runtime's network/config.
func realQueueEnvironment(f realQueueFixture) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=" + f.Root, "CODEX_HOME=" + f.CodexHome, "TMPDIR=" + f.Root}
}

type realQueueRPC struct {
	conn    *websocket.Conn
	mu      sync.Mutex
	next    int
	pending map[int]chan json.RawMessage
	turns   int
	err     error
	done    chan struct{}
}

func realQueueConnect(ctx context.Context, socket string) (*realQueueRPC, error) {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	conn, _, err := websocket.Dial(ctx, "ws://127.0.0.1/", &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errors.New("owned app-server WebSocket unavailable")
	}
	conn.SetReadLimit(2 << 20)
	r := &realQueueRPC{conn: conn, pending: make(map[int]chan json.RawMessage), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		defer transport.CloseIdleConnections()
		for {
			kind, data, err := conn.Read(ctx)
			if err != nil {
				r.mu.Lock()
				r.err = errors.New("native observation ended")
				r.mu.Unlock()
				return
			}
			var m struct {
				ID     *int            `json:"id"`
				Method string          `json:"method"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if kind != websocket.MessageText || json.Unmarshal(data, &m) != nil {
				r.mu.Lock()
				r.err = errors.New("invalid native frame")
				r.mu.Unlock()
				return
			}
			r.mu.Lock()
			if m.Method == "turn/started" {
				r.turns++
				r.err = errors.New("new-turn policy violated")
			}
			if m.Method == "error" || (m.Method != "" && m.ID != nil) {
				r.err = errors.New("unexpected native error or server request")
			}
			if m.Method == "" && m.ID != nil {
				ch := r.pending[*m.ID]
				if ch == nil || len(m.Error) != 0 || len(m.Result) == 0 {
					r.err = errors.New("invalid native RPC response")
				} else {
					ch <- m.Result
					delete(r.pending, *m.ID)
				}
			}
			failed := r.err != nil
			r.mu.Unlock()
			if failed {
				_ = conn.CloseNow()
				return
			}
		}
	}()
	return r, nil
}

func (r *realQueueRPC) request(ctx context.Context, method string, params any, result any) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.mu.Lock()
	r.next++
	id := r.next
	ch := make(chan json.RawMessage, 1)
	r.pending[id] = ch
	prior := r.err
	r.mu.Unlock()
	if prior != nil {
		return prior
	}
	data, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err := r.conn.Write(ctx, websocket.MessageText, data); err != nil {
		return errors.New("native RPC write failed")
	}
	select {
	case raw := <-ch:
		if json.Unmarshal(raw, result) != nil {
			return errors.New("native RPC result invalid")
		}
		return r.check()
	case <-r.done:
		return errors.New("native RPC observation ended")
	case <-ctx.Done():
		return errors.New("native RPC deadline exceeded")
	}
}
func (r *realQueueRPC) check() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.turns != 0 {
		return errors.New("new-turn policy violated")
	}
	return nil
}

// The 0.160 generated ThreadTurnsListResponse requires data; nextCursor is
// optional/null at the terminal page. Turn requires id/items/status, with
// itemsView defaulting to full. Hash every data field/item, never print history.
func realQueueHistoryWitness(response json.RawMessage, baselineCount int, baselineSHA string) error {
	if baselineCount < 0 || baselineCount > 4 || !realQueueSHA.MatchString(baselineSHA) || len(response) > 2<<20 {
		return errors.New("frozen history baseline invalid")
	}
	var history struct {
		Data json.RawMessage `json:"data"`
		Next json.RawMessage `json:"nextCursor"`
	}
	if json.Unmarshal(response, &history) != nil || len(history.Data) == 0 || (len(history.Next) != 0 && string(bytes.TrimSpace(history.Next)) != "null") {
		return errors.New("history witness absent or paginated")
	}
	var turns []json.RawMessage
	if json.Unmarshal(history.Data, &turns) != nil || turns == nil || len(turns) != baselineCount {
		return errors.New("historical turn count changed")
	}
	seen := make(map[string]bool)
	for _, raw := range turns {
		var turn struct {
			ID        string            `json:"id"`
			Status    string            `json:"status"`
			Items     []json.RawMessage `json:"items"`
			ItemsView json.RawMessage   `json:"itemsView"`
			Error     json.RawMessage   `json:"error"`
		}
		if json.Unmarshal(raw, &turn) != nil || turn.ID == "" || len(turn.ID) > 256 || seen[turn.ID] || turn.Status != "completed" || turn.Items == nil || (len(turn.ItemsView) != 0 && string(bytes.TrimSpace(turn.ItemsView)) != `"full"`) || (len(turn.Error) != 0 && string(bytes.TrimSpace(turn.Error)) != "null") {
			return errors.New("history is not unique completed full turns")
		}
		seen[turn.ID] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(history.Data))
	decoder.UseNumber()
	var fullHistory any
	if decoder.Decode(&fullHistory) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("full history JSON invalid")
	}
	canonical, err := json.Marshal(fullHistory)
	if err != nil || realQueueHash(canonical) != baselineSHA {
		return errors.New("canonical full-history hash changed")
	}
	return nil
}

func (r *realQueueRPC) snapshot(ctx context.Context, fixture realQueueFixture) ([]json.RawMessage, error) {
	sid := fixture.SID
	var read struct {
		Thread struct {
			ID     string `json:"id"`
			Status struct {
				Type string `json:"type"`
			} `json:"status"`
		} `json:"thread"`
	}
	if err := r.request(ctx, "thread/read", map[string]any{"threadId": sid, "includeTurns": false}, &read); err != nil {
		return nil, err
	}
	if read.Thread.ID != sid || read.Thread.Status.Type != "notLoaded" {
		return nil, errors.New("exact cold Thread identity changed")
	}
	var history json.RawMessage
	if err := r.request(ctx, "thread/turns/list", map[string]any{"threadId": sid, "limit": 8, "sortDirection": "asc", "itemsView": "full"}, &history); err != nil {
		return nil, err
	}
	if fixture.BaselineTurnCount == nil {
		return nil, errors.New("explicit historical turn baseline absent")
	}
	if err := realQueueHistoryWitness(history, *fixture.BaselineTurnCount, fixture.BaselineHistorySHA256); err != nil {
		return nil, err
	}
	var queue struct {
		Data []json.RawMessage `json:"data"`
		Next json.RawMessage   `json:"nextCursor"`
	}
	if err := r.request(ctx, "thread/queue/list", map[string]any{"threadId": sid, "limit": 8}, &queue); err != nil {
		return nil, err
	}
	if queue.Data == nil || string(queue.Next) != "null" {
		return nil, errors.New("queue witness absent or paginated")
	}
	return queue.Data, r.check()
}

type realQueueDispatch struct {
	SID        string `json:"sid"`
	MessageSHA string `json:"message_sha256"`
}

func realQueueWitness(rows []json.RawMessage, expected realQueueDispatch) (string, error) {
	if len(rows) != 1 || !realQueueSID.MatchString(expected.SID) || !realQueueSHA.MatchString(expected.MessageSHA) {
		return "", errors.New("queue witness is not exactly one")
	}
	var entry struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId"`
		Input    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"input"`
	}
	if json.Unmarshal(rows[0], &entry) != nil || entry.ID == "" || len(entry.ID) > 256 || (entry.ThreadID != "" && entry.ThreadID != expected.SID) || len(entry.Input) != 1 || entry.Input[0].Type != "text" || realQueueHash([]byte(entry.Input[0].Text)) != expected.MessageSHA {
		return "", errors.New("exact queue identity or literal input hash mismatch")
	}
	return realQueueHash([]byte(entry.ID)), nil
}

type realQueueChildConfig struct {
	Native  nativeDeliveryProcessFixture
	Runtime realQueueFixture
}

func realQueueCommand(t *testing.T, cfg realQueueChildConfig) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		if len(args) != 5 || args[0] != "queue" || args[1] != "--thread" || args[2] != cfg.Runtime.SID || args[3] != "--message" || len(args[4]) == 0 || len(args[4]) > 32768 || strings.ContainsRune(args[4], 0) {
			t.Fatal("production queue argv differs from exact literal fixture")
		}
		if err := realQueueCheckFiles(cfg.Runtime); err != nil {
			t.Fatal(err)
		}
		dispatch, _ := json.Marshal(realQueueDispatch{SID: args[2], MessageSHA: realQueueHash([]byte(args[4]))})
		if err := nativeDeliveryWriteWitness(cfg.Native.CounterPath, string(dispatch)); err != nil {
			t.Fatal(err)
		}
		return exec.CommandContext(ctx, cfg.Runtime.CLI, "queue", "--remote", "unix://"+cfg.Runtime.Socket, args[1], args[2], args[3], args[4])
	}
}

func TestMachineNativeRealQueueCrashProcessHelper(t *testing.T) {
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
	if len(os.Args) != index+3 {
		t.Fatal("invalid real queue child argv")
	}
	data, err := os.ReadFile(os.Args[index+2])
	if err != nil {
		t.Fatal("child configuration unavailable")
	}
	var cfg realQueueChildConfig
	if len(data) > 16384 || json.Unmarshal(data, &cfg) != nil {
		t.Fatal("invalid child configuration")
	}
	mode := os.Args[index+1]
	if mode != "adapter" && mode != "recover" {
		t.Fatal("invalid real queue helper mode")
	}
	if err := realQueueCheckFiles(cfg.Runtime); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(nativeDeliveryChildContext(t, cfg.Native), 20*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: realQueueCommand(t, cfg), observe: func(phase string) {
		if err := nativeDeliveryWriteWitness(cfg.Native.WitnessPath, phase); err != nil {
			t.Fatal(err)
		}
		if mode == "adapter" && phase == "queue_wait_succeeded" {
			fmt.Println("READY queue_wait_succeeded")
			if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
				t.Fatal("barrier closed before owned kill")
			}
		}
	}})
	inbox, err := nodeinbox.Open(machineNodeInboxPath(cfg.Native.Root, cfg.Native.NodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	journal, err := openMachineRelayJournal(cfg.Native.Root, cfg.Native.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "recover" {
		if err := reconcileMachineRelayJournal(ctx, cfg.Native.Origin, cfg.Native.NodeID, cfg.Native.Root, inbox, journal); err != nil {
			t.Fatal(err)
		}
	}
	if err := drainMachineRelayInbox(ctx, cfg.Native.Origin, cfg.Native.NodeID, cfg.Native.Root, inbox, journal); err != nil {
		t.Fatal(err)
	}
}

func realQueueStartChild(t *testing.T, mode string, cfg realQueueChildConfig) *nativeDeliveryProcess {
	t.Helper()
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfg.Native.ConfigPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestMachineNativeRealQueueCrashProcessHelper$", "--", mode, cfg.Native.ConfigPath)
	cmd.Env = realQueueEnvironment(cfg.Runtime)
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

func realQueueRelayFixture(t *testing.T, runtime realQueueFixture) *nativeDeliveryRelayFixture {
	t.Helper()
	local := newLocalGroupFailureFixture(t)
	syntheticHome := os.Getenv("CODEX_HOME")
	t.Setenv("CODEX_HOME", runtime.CodexHome)
	local.nativeB = runtime.SID
	local.targetMCP = local.joinSession(t, runtime.SID)
	authorizeSameNodeRelayFixture(t, local, local.sourceMCP, local.targetMCP)
	service, err := fabric.NewService(local.store, local.ownerID, local.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	f := &nativeDeliveryRelayFixture{local: local, ctx: local.bridge.ctx}
	handler := serverpkg.NewFabricHandler(service, "")
	local.hub.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/authorization") {
			f.guardCalls.Add(1)
		}
		if strings.HasSuffix(r.URL.Path, "/receipts") {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			var receipt fabric.NodeReceiptInput
			if json.Unmarshal(data, &receipt) != nil {
				t.Error("invalid receipt")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			f.receiptsMu.Lock()
			f.receipts = append(f.receipts, receipt.Layer)
			f.receiptsMu.Unlock()
		}
		handler.ServeHTTP(w, r)
	})
	t.Setenv("CODEX_HOME", syntheticHome)
	t.Setenv("CODEX_THREAD_ID", local.nativeA)
	t.Setenv("CODEX_SESSION_ID", "session-"+local.nativeA)
	result, err := local.sourceMCP.callTool("cicada_send", map[string]any{"target": local.targetMCP.endpointID, "body": "SYNTHETIC_NATIVE_QUEUE_CRASH_LITERAL_ONLY", "idempotency_key": "synthetic-real-native-crash"})
	if err != nil {
		t.Fatal(err)
	}
	public := result.(map[string]any)
	if public["delivery"] != "RELAY_PERSISTED" {
		t.Fatal("not sealed Relay")
	}
	f.messageID = public["message_id"].(string)
	deliveries, err := service.ClaimNodeSameGroupSealedV1Deliveries(local.nodeToken, local.nodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(local.nodeID), Limit: 1})
	if err != nil || len(deliveries) != 1 {
		t.Fatal("current Hub claim failed")
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
	f.nativeScope, err = machineNativeContextScopeFromMetadata(f.ctx, "codex", runtime.SID, authorization.EndpointID, authorization.BindingID, authorization.BindingEpoch, authorization.NativeContextScope)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hub, _ := machineHubFrom(f.ctx)
	f.process = nativeDeliveryProcessFixture{Root: local.stateDir, HubID: local.hubID, NodeID: local.nodeID, Origin: local.hub.URL, Token: local.nodeToken, WriterScope: hub.WriterScope, NativeID: runtime.SID, ConfigPath: filepath.Join(dir, "child.json"), CounterPath: filepath.Join(dir, "dispatch.jsonl"), WitnessPath: filepath.Join(dir, "phases")}
	t.Setenv("CODEX_HOME", runtime.CodexHome)
	return f
}

func TestMachineNativeRealQueueCrashAcceptance(t *testing.T) {
	if os.Getenv("CICADA_NATIVE_QUEUE_CRASH_ACCEPTANCE") != "1" {
		t.Skip("real native queue crash acceptance NOT_RUN: explicit opt-in absent")
	}
	path, pin := os.Getenv("CICADA_NATIVE_QUEUE_CRASH_FIXTURE"), os.Getenv("CICADA_NATIVE_QUEUE_CRASH_FIXTURE_SHA256")
	if path == "" || pin == "" {
		t.Fatal("opt-in requires pinned disposable fixture receipt")
	}
	if !filepath.IsAbs(path) || len(path) > 512 {
		t.Fatal("fixture receipt path invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("fixture receipt unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	_ = file.Close()
	if err != nil {
		t.Fatal("fixture receipt unreadable")
	}
	runtime, err := realQueueDecodeFixture(data, pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := realQueueCheckFiles(runtime); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	version := exec.CommandContext(ctx, runtime.CLI, "--version")
	version.Env = realQueueEnvironment(runtime)
	version.Stderr = io.Discard
	output, err := version.Output()
	if err != nil || !realQueueVersionMatches(string(output)) {
		t.Fatal("official CLI version mismatch")
	}
	rpc, err := realQueueConnect(ctx, runtime.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rpc.conn.CloseNow(); <-rpc.done }()
	var initialized struct {
		UserAgent string `json:"userAgent"`
	}
	if err := rpc.request(ctx, "initialize", map[string]any{"clientInfo": map[string]any{"name": "cicada_real_queue_crash", "version": "0.1"}, "capabilities": map[string]any{"experimentalApi": true}}, &initialized); err != nil {
		t.Fatal(err)
	}
	if !realQueueUserAgentMatches(initialized.UserAgent) {
		t.Fatal("app-server version mismatch")
	}
	notification, _ := json.Marshal(map[string]any{"method": "initialized", "params": map[string]any{}})
	if err := rpc.conn.Write(ctx, websocket.MessageText, notification); err != nil {
		t.Fatal("initialize notification failed")
	}
	rows, err := rpc.snapshot(ctx, runtime)
	if err != nil || len(rows) != 0 {
		t.Fatal("exact cold fixture must start with empty queue and unchanged frozen history")
	}
	f := realQueueRelayFixture(t, runtime)
	cfg := realQueueChildConfig{Native: f.process, Runtime: runtime}
	if err := f.inbox.Close(); err != nil {
		t.Fatal(err)
	}
	child := realQueueStartChild(t, "adapter", cfg)
	child.ready(t, "queue_wait_succeeded")
	dispatchData, err := os.ReadFile(f.process.CounterPath)
	if err != nil || bytes.Count(dispatchData, []byte("\n")) != 1 {
		t.Fatal("official queue dispatch count differs from one")
	}
	var dispatch realQueueDispatch
	if json.Unmarshal(bytes.TrimSpace(dispatchData), &dispatch) != nil || dispatch.SID != runtime.SID {
		t.Fatal("dispatch SID changed")
	}
	rows, err = rpc.snapshot(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	submissionHash, err := realQueueWitness(rows, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.process.Root), []nodelock.NativeOutcomeState{nodelock.NativeInjecting}) || !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived}) || f.guardCalls.Load() == 0 {
		t.Fatal("pre-ledger writer/Guard/receipt ordering failed")
	}
	pre, err := nodeinbox.OpenReadOnly(machineNodeInboxPath(f.process.Root, f.process.NodeID))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := pre.Get(ctx, f.messageID)
	_ = pre.Close()
	if err != nil || stored.State != nodeinbox.INJECTING {
		t.Fatal("pre-kill inbox is not injecting")
	}
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	child.wait(t, true)
	recovery := realQueueStartChild(t, "recover", cfg)
	recovery.wait(t, false)
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.process.Root, f.process.NodeID))
	if err != nil {
		t.Fatal(err)
	}
	f.journal, err = openMachineRelayJournal(f.process.Root, f.process.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err = f.inbox.Get(ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN || f.journal.entry(f.messageID) == nil {
		t.Fatal("production recovery lost uncertainty/journal")
	}
	if !reflect.DeepEqual(nativeDeliveryRawOutcomes(t, f.process.Root), []nodelock.NativeOutcomeState{nodelock.NativeUncertain}) || !reflect.DeepEqual(f.layers(), []string{fabric.ReceiptNodeReceived, fabric.ReceiptInjectionUncertain}) {
		t.Fatal("recovery promoted success or lost durable uncertainty")
	}
	entry := *f.journal.entry(f.messageID)
	for _, attempt := range []string{entry.AttemptID, "synthetic-new-remote-attempt"} {
		entry.AttemptID = attempt
		op, err := machineRelayNativeOperation(f.ctx, nodeinbox.Claim{Delivery: *stored}, entry)
		if err != nil {
			t.Fatal(err)
		}
		replay := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: realQueueCommand(t, cfg)})
		var uncertain *nativeInjectionUncertainError
		if err := executeMachineNativeCodex(replay, runtime.SID, "SYNTHETIC_RETRY_FORBIDDEN", op, f.nativeScope); !errors.As(err, &uncertain) {
			t.Fatal("original/new attempt was not refused")
		}
	}
	after, err := os.ReadFile(f.process.CounterPath)
	if err != nil || !bytes.Equal(after, dispatchData) {
		t.Fatal("recovery/replay made another official queue dispatch")
	}
	rows, err = rpc.snapshot(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	afterHash, err := realQueueWitness(rows, dispatch)
	if err != nil || afterHash != submissionHash {
		t.Fatal("exact native queue witness changed after recovery/replay")
	}
	if err := rpc.check(); err != nil {
		t.Fatal(err)
	}
	t.Logf("real_queue_crash_gate=PASS queue_witness=EXACT_ONE_SUBMISSION adapter_recovery=INJECTION_UNCERTAIN reinjection=REFUSED_ORIGINAL_AND_NEW_ATTEMPT actual_turn_started=0 historical_turn_baseline=%d baseline_history=UNCHANGED provider_POSTs=OWNER_ATTESTED_ZERO_EGRESS busy_delivery=NOT_RUN foreground_input_protection=NOT_RUN original_A_context_continuity=NOT_RUN runtime_image_identity=OWNER_ATTESTED profile_scope=OWNER_ATTESTED_INDEPENDENT_SYNTHETIC_B", *runtime.BaselineTurnCount)
}

func TestMachineNativeRealQueueRequiresExactCLI0162(t *testing.T) {
	for _, tc := range []struct {
		name        string
		version     string
		userAgent   string
		wantVersion bool
		wantAgent   bool
	}{
		{name: "current", version: "codex-cli 0.162.0\n", userAgent: "codex/0.162.0", wantVersion: true, wantAgent: true},
		{name: "previous release", version: "codex-cli 0.161.0\n", userAgent: "codex/0.161.0"},
		{name: "version suffix", version: "codex-cli 0.162.0-beta", userAgent: "codex/0.162.0-beta"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := realQueueVersionMatches(tc.version); got != tc.wantVersion {
				t.Fatalf("CLI version accepted = %t, want %t", got, tc.wantVersion)
			}
			if got := realQueueUserAgentMatches(tc.userAgent); got != tc.wantAgent {
				t.Fatalf("app-server UserAgent accepted = %t, want %t", got, tc.wantAgent)
			}
		})
	}
}

func TestMachineNativeRealQueueCrashFixtureValidation(t *testing.T) {
	baselineCount := 2
	f := realQueueFixture{Schema: "cicada.synthetic-native-queue-crash.v1", Root: "/tmp/cicada-native-queue-crash-test", CLI: "/usr/bin/codex", CLISHA256: strings.Repeat("a", 64), RuntimeImage: "sha256:" + strings.Repeat("b", 64), Socket: "/tmp/cicada-native-queue-crash-test/server.sock", CodexHome: "/tmp/cicada-native-queue-crash-test/home", SID: "01234567-89ab-cdef-0123-456789abcdef", Synthetic: true, CredentialsAbsent: true, ProviderEgressDisabled: true, ProfileScope: realQueueProfileScope, BaselineTurnCount: &baselineCount, BaselineHistorySHA256: strings.Repeat("c", 64)}
	data, _ := json.Marshal(f)
	if _, err := realQueueDecodeFixture(data, realQueueHash(data)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*realQueueFixture){func(f *realQueueFixture) { f.SID = "wrong" }, func(f *realQueueFixture) { f.Socket = "/tmp/other.sock" }, func(f *realQueueFixture) { f.CredentialsAbsent = false }, func(f *realQueueFixture) { f.MaxProviderPOSTs = 1 }, func(f *realQueueFixture) { f.RuntimeImage = "sha256:bad" }, func(f *realQueueFixture) { f.CLI = "/usr/bin/codex\n" }, func(f *realQueueFixture) { f.BaselineTurnCount = nil }, func(f *realQueueFixture) { count := 5; f.BaselineTurnCount = &count }, func(f *realQueueFixture) { f.BaselineHistorySHA256 = "bad" }, func(f *realQueueFixture) { f.ProfileScope = "original-a" }} {
		bad := f
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := realQueueDecodeFixture(raw, realQueueHash(raw)); err == nil {
			t.Fatal("invalid fixture accepted")
		}
	}
	if _, err := realQueueDecodeFixture(data, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong receipt hash accepted")
	}
	var omitted map[string]json.RawMessage
	if err := json.Unmarshal(data, &omitted); err != nil {
		t.Fatal(err)
	}
	delete(omitted, "baseline_turn_count")
	missingCount, _ := json.Marshal(omitted)
	if _, err := realQueueDecodeFixture(missingCount, realQueueHash(missingCount)); err == nil {
		t.Fatal("omitted baseline count accepted")
	}
	if _, err := realQueueDecodeFixture(append(data, []byte(" {}")...), realQueueHash(append(data, []byte(" {}")...))); err == nil {
		t.Fatal("trailing receipt accepted")
	}
	rows := []json.RawMessage{json.RawMessage(`{"id":"submission","threadId":"01234567-89ab-cdef-0123-456789abcdef","input":[{"type":"text","text":"SYNTHETIC"}]}`)}
	expected := realQueueDispatch{SID: f.SID, MessageSHA: realQueueHash([]byte("SYNTHETIC"))}
	if _, err := realQueueWitness(rows, expected); err != nil {
		t.Fatal(err)
	}
	expected.MessageSHA = realQueueHash([]byte("wrong"))
	if _, err := realQueueWitness(rows, expected); err == nil {
		t.Fatal("wrong payload hash accepted")
	}
	if _, err := realQueueWitness(append(rows, rows[0]), expected); err == nil {
		t.Fatal("duplicate queue witness accepted")
	}
	if _, err := realQueueWitness([]json.RawMessage{json.RawMessage(`{"id":"submission","threadId":"wrong","input":[{"type":"text","text":"SYNTHETIC"}]}`)}, realQueueDispatch{SID: f.SID, MessageSHA: realQueueHash([]byte("SYNTHETIC"))}); err == nil {
		t.Fatal("wrong native SID accepted")
	}
	if strings.Contains(strings.Join(realQueueEnvironment(f), "\n"), "API_KEY") {
		t.Fatal("provider credentials entered child environment")
	}
}

// This is a protocol/schema guard fixture, not historical/native evidence.
func TestMachineNativeRealQueueCrashFrozenHistory(t *testing.T) {
	const turn = `{"id":"synthetic-historical-turn","status":"completed","items":[{"type":"agentMessage","id":"synthetic-item","text":"SYNTHETIC_PRIOR_HISTORY <&>"}],"error":null,"itemsView":"full","startedAt":1700000000,"completedAt":1700000001,"durationMs":1000}`
	const canonical = `[{"completedAt":1700000001,"durationMs":1000,"error":null,"id":"synthetic-historical-turn","items":[{"id":"synthetic-item","text":"SYNTHETIC_PRIOR_HISTORY \u003c\u0026\u003e","type":"agentMessage"}],"itemsView":"full","startedAt":1700000000,"status":"completed"}]`
	baseline := realQueueHash([]byte(canonical))
	response := `{"data":[` + turn + `],"nextCursor":null,"backwardsCursor":"synthetic-anchor"}`
	if err := realQueueHistoryWitness(json.RawMessage(response), 1, baseline); err != nil {
		t.Fatal(err)
	}
	// Cursors are transport pagination metadata; full data contents are pinned.
	if err := realQueueHistoryWitness(json.RawMessage(strings.ReplaceAll(response, `,"nextCursor":null`, "")), 1, baseline); err != nil {
		t.Fatal("schema-optional terminal cursor rejected")
	}
	var reordered bytes.Buffer
	if err := json.Indent(&reordered, []byte(response), "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := realQueueHistoryWitness(reordered.Bytes(), 1, baseline); err != nil {
		t.Fatal("JSON whitespace changed canonical history")
	}
	for _, change := range []struct {
		response string
		count    int
		sha      string
		failure  string
	}{
		{response, 2, baseline, "count"},
		{response, 1, realQueueHash([]byte("changed")), "hash"},
		{strings.ReplaceAll(response, `"nextCursor":null`, `"nextCursor":"more"`), 1, baseline, "paginated"},
		{strings.ReplaceAll(response, `"status":"completed"`, `"status":"inProgress"`), 1, baseline, "completed"},
		{strings.ReplaceAll(response, `"itemsView":"full"`, `"itemsView":"summary"`), 1, baseline, "full"},
		{strings.ReplaceAll(response, `"itemsView":"full"`, `"itemsView":null`), 1, baseline, "full"},
		{strings.ReplaceAll(response, `"error":null`, `"error":{"message":"SYNTHETIC_ERROR"}`), 1, baseline, "completed"},
		{strings.ReplaceAll(response, "SYNTHETIC_PRIOR_HISTORY", "SYNTHETIC_CHANGED_HISTORY"), 1, baseline, "hash"},
		{strings.ReplaceAll(response, `"durationMs":1000`, `"durationMs":1000,"unknownHistoryField":"SYNTHETIC_NEW"`), 1, baseline, "hash"},
		{`{"data":[` + turn + `,` + turn + `],"nextCursor":null}`, 2, baseline, "unique"},
		{`{"data":[{"id":"synthetic-historical-turn","status":"completed"}],"nextCursor":null}`, 1, baseline, "full"},
		{`{"data":null,"nextCursor":null}`, 0, realQueueHash([]byte(`[]`)), "count"},
		{response, 5, baseline, "baseline"},
	} {
		if err := realQueueHistoryWitness(json.RawMessage(change.response), change.count, change.sha); err == nil || !strings.Contains(err.Error(), change.failure) {
			t.Fatal("history mutation did not fail at expected protocol guard")
		}
	}
	// 0.160 Turn.itemsView defaults to full when omitted; pin that exact shape.
	defaultView := `{"data":[{"id":"synthetic-empty-completed-turn","items":[],"status":"completed"}]}`
	defaultSHA := realQueueHash([]byte(`[{"id":"synthetic-empty-completed-turn","items":[],"status":"completed"}]`))
	if err := realQueueHistoryWitness(json.RawMessage(defaultView), 1, defaultSHA); err != nil {
		t.Fatal("schema default full view rejected")
	}
}

func TestMachineNativeRealQueueCrashOptInRefusesIncompleteFixture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestMachineNativeRealQueueCrashAcceptance$", "-test.v")
	cmd.Env = []string{"CICADA_NATIVE_QUEUE_CRASH_ACCEPTANCE=1"}
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !bytes.Contains(output, []byte("opt-in requires pinned disposable fixture receipt")) {
		t.Fatal("incomplete explicit opt-in did not fail before fixture/native access")
	}
}

// Sparse bytes and an inert Unix listener test only the pre-hash size fence.
// They are never executed and are not a native Runtime or queue witness.
func TestMachineNativeRealQueueCrashOversizedCLI(t *testing.T) {
	root := shortLocalJoinStateDir(t)
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "inert.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cli := filepath.Join(root, "synthetic-oversized-cli")
	file, err := os.OpenFile(cli, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate(realQueueMaxCLIBytes + 1)
	if closeErr := file.Close(); err != nil || closeErr != nil {
		t.Fatal("could not prepare sparse size-fence fixture")
	}
	f := realQueueFixture{Root: root, CLI: cli, Socket: socket, CodexHome: home, CLISHA256: realQueueHash(nil)}
	if err := realQueueCheckFiles(f); err == nil || err.Error() != "pinned CLI exceeds 512 MiB limit" {
		t.Fatal("oversized executable did not fail at size fence before hashing")
	}
	if realQueueMaxCLIBytes != 512<<20 || 289101384 > realQueueMaxCLIBytes {
		t.Fatal("bounded cap does not admit the independently measured official 0.160 CLI size")
	}
}

// This is synthetic fixture-plumbing validation, never native Runtime proof.
func TestMachineNativeRealQueueCrashRelayFixtureScope(t *testing.T) {
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	const sid = "01234567-89ab-cdef-0123-456789abcdef"
	writeCodexSessionRecord(t, home, sid, workspace)
	f := realQueueRelayFixture(t, realQueueFixture{CodexHome: home, SID: sid})
	claim, entry := f.claim(t)
	if claim.SessionID != sid || f.nativeScope.NativeSessionID != sid || entry.SessionID != sid {
		t.Fatal("new protocol fixture substituted its synthetic placeholder SID")
	}
	ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{
		command: func(context.Context, string, ...string) *exec.Cmd {
			t.Fatal("preflight validation must not reach native execution")
			return nil
		},
	})
	op, err := machineRelayNativeOperation(ctx, claim, entry)
	if err != nil {
		t.Fatal(err)
	}
	wrongScope := f.nativeScope
	wrongScope.NativeSessionID = "wrong-native-session"
	if err := executeMachineNativeCodex(ctx, sid, "SYNTHETIC_PREFLIGHT_ONLY", op, wrongScope); err == nil {
		t.Fatal("mismatched actual operation/context SID admitted")
	}
	if f.guardCalls.Load() == 0 || len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
		t.Fatal("fixture omitted production Guard or persisted an intent during failed preflight")
	}
}
