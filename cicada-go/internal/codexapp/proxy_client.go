package codexapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// daemonInfo is the read-only status returned by `codex app-server daemon
// version`. The proxy must attach to this already-running daemon; a private
// app-server would not share the native Thread's loaded state.
type daemonInfo struct {
	Status           string `json:"status"`
	SocketPath       string `json:"socketPath"`
	AppServerVersion string `json:"appServerVersion"`
}

// ProxyClient speaks JSON-RPC text messages over the official app-server
// WebSocket proxy. It exposes read-only Thread/queue operations; queue/add,
// thread/resume, and queue/start intentionally remain unavailable here.
type ProxyClient struct {
	process   *exec.Cmd
	conn      *websocket.Conn
	transport *http.Transport
	onEvent   EventHandler
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	nextID    int64
}

type ThreadStatus struct {
	Type        string
	ActiveFlags []string
}

type ThreadSnapshot struct {
	ID     string
	Status ThreadStatus
}

// QueuedSubmission is a read-only view of one exact queue/list entry. Input is
// retained as JSON for callers to compare; it must not be logged or formatted.
type QueuedSubmission struct {
	ID                  string
	ClientUserMessageID string
	Input               json.RawMessage
}

const (
	proxyReadLimitBytes = 2 * 1024 * 1024
	queuePageLimit      = 64
	queueMaxPages       = 4
)

// StartRunningProxy attaches to the existing Codex daemon through its official
// WebSocket proxy. It never starts a private app-server or creates a Thread.
func StartRunningProxy(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler) (*ProxyClient, error) {
	if strings.TrimSpace(binary) == "" {
		binary = "codex"
	}
	versionCommand := exec.CommandContext(ctx, binary, "app-server", "daemon", "version")
	versionCommand.Dir = cwd
	versionCommand.Env = env
	versionCommand.Stderr = io.Discard
	output, err := versionCommand.Output()
	if err != nil {
		return nil, errors.New("Codex app-server daemon status is unavailable")
	}
	var daemon daemonInfo
	if err := json.Unmarshal(output, &daemon); err != nil || daemon.Status != "running" ||
		strings.TrimSpace(daemon.SocketPath) == "" || !versionAtLeast(daemon.AppServerVersion, minimumQueueWakeVersion) {
		return nil, errors.New("a compatible running Codex app-server daemon is required")
	}

	process := exec.CommandContext(ctx, binary, "app-server", "proxy", "--sock", daemon.SocketPath)
	process.Dir = cwd
	process.Env = env
	process.Stderr = io.Discard
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, errors.New("Codex app-server proxy stdout is unavailable")
	}
	stdin, err := process.StdinPipe()
	if err != nil {
		return nil, errors.New("Codex app-server proxy stdin is unavailable")
	}
	if err := process.Start(); err != nil {
		return nil, errors.New("Codex app-server proxy could not start")
	}
	conn, transport, err := dialProxyWebSocket(ctx, stdout, stdin)
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		if process.Process != nil {
			_ = process.Process.Kill()
		}
		_ = process.Wait()
		return nil, errors.New("Codex app-server proxy WebSocket handshake failed")
	}
	conn.SetReadLimit(proxyReadLimitBytes)
	return &ProxyClient{process: process, conn: conn, transport: transport,
		onEvent: onEvent, nextID: 1}, nil
}

// dialProxyWebSocket hands the proxy's stdin/stdout byte stream to net/http
// for the WebSocket upgrade. WebSocket framing is delegated to coder/websocket.
func dialProxyWebSocket(ctx context.Context, stdout io.ReadCloser, stdin io.WriteCloser) (*websocket.Conn, *http.Transport, error) {
	stream := &proxyPipeConn{reader: stdout, writer: stdin}
	var dialMu sync.Mutex
	dialed := false
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			if dialed {
				return nil, errors.New("Codex proxy stream was already used")
			}
			dialed = true
			return stream, nil
		},
	}
	client := &http.Client{Transport: transport}
	conn, _, err := websocket.Dial(ctx, "ws://127.0.0.1/", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		transport.CloseIdleConnections()
		_ = stream.Close()
		return nil, nil, err
	}
	return conn, transport, nil
}

type proxyPipeConn struct {
	reader io.ReadCloser
	writer io.WriteCloser
	close  sync.Once
}

func (c *proxyPipeConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *proxyPipeConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *proxyPipeConn) Close() error {
	var closeErr error
	c.close.Do(func() {
		closeErr = errors.Join(c.reader.Close(), c.writer.Close())
	})
	return closeErr
}
func (c *proxyPipeConn) LocalAddr() net.Addr                { return proxyPipeAddr("local") }
func (c *proxyPipeConn) RemoteAddr() net.Addr               { return proxyPipeAddr("proxy") }
func (c *proxyPipeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *proxyPipeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *proxyPipeConn) SetWriteDeadline(_ time.Time) error { return nil }

type proxyPipeAddr string

func (a proxyPipeAddr) Network() string { return "codex-proxy" }
func (a proxyPipeAddr) String() string  { return string(a) }

func (c *ProxyClient) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		if c.conn != nil {
			_ = c.conn.CloseNow()
		}
		if c.transport != nil {
			c.transport.CloseIdleConnections()
		}
		if c.process != nil {
			if c.process.Process != nil {
				_ = c.process.Process.Kill()
			}
			_ = c.process.Wait()
		}
	})
}

func (c *ProxyClient) InitializeExperimental(ctx context.Context, clientName, title, clientVersion string) error {
	result, err := c.request(ctx, "initialize", map[string]any{
		"clientInfo":   map[string]any{"name": clientName, "title": title, "version": clientVersion},
		"capabilities": map[string]any{"experimentalApi": true},
	})
	if err != nil {
		return err
	}
	userAgent, _ := result["userAgent"].(string)
	if !versionAtLeast(userAgent, minimumQueueWakeVersion) {
		return errors.New("Codex app-server did not negotiate the required experimental protocol")
	}
	return c.notify(ctx, "initialized", map[string]any{})
}

func (c *ProxyClient) ReadThread(ctx context.Context, threadID string) (ThreadSnapshot, error) {
	threadID = strings.TrimSpace(threadID)
	if threadID == "" {
		return ThreadSnapshot{}, errors.New("native Thread ID is required")
	}
	result, err := c.request(ctx, "thread/read", map[string]any{
		"threadId": threadID, "includeTurns": false,
	})
	if err != nil {
		return ThreadSnapshot{}, err
	}
	thread, ok := result["thread"].(map[string]any)
	if !ok {
		return ThreadSnapshot{}, errors.New("Codex thread/read returned no Thread")
	}
	id, _ := thread["id"].(string)
	if id != threadID {
		return ThreadSnapshot{}, errors.New("Codex thread/read returned a different native Thread")
	}
	statusMap, ok := thread["status"].(map[string]any)
	if !ok {
		return ThreadSnapshot{}, errors.New("Codex thread/read returned no Thread status")
	}
	statusType, _ := statusMap["type"].(string)
	switch statusType {
	case "notLoaded", "idle", "systemError":
	case "active":
	default:
		return ThreadSnapshot{}, errors.New("Codex thread/read returned an unknown Thread status")
	}
	var flags []string
	if rawFlags, present := statusMap["activeFlags"]; present {
		items, ok := rawFlags.([]any)
		if !ok {
			return ThreadSnapshot{}, errors.New("Codex thread/read returned invalid active flags")
		}
		for _, raw := range items {
			flag, ok := raw.(string)
			if !ok || (flag != "waitingOnApproval" && flag != "waitingOnUserInput") {
				return ThreadSnapshot{}, errors.New("Codex thread/read returned an unknown active flag")
			}
			flags = append(flags, flag)
		}
	}
	return ThreadSnapshot{ID: id, Status: ThreadStatus{Type: statusType, ActiveFlags: flags}}, nil
}

func (c *ProxyClient) ListQueue(ctx context.Context, threadID string) ([]QueuedSubmission, error) {
	threadID = strings.TrimSpace(threadID)
	if threadID == "" {
		return nil, errors.New("native Thread ID is required")
	}
	queued := make([]QueuedSubmission, 0)
	cursor := ""
	seenCursors := make(map[string]struct{})
	for page := 0; page < queueMaxPages; page++ {
		params := map[string]any{"threadId": threadID, "limit": queuePageLimit}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, err := c.request(ctx, "thread/queue/list", params)
		if err != nil {
			return nil, err
		}
		data, ok := result["data"].([]any)
		if !ok {
			return nil, errors.New("Codex thread/queue/list returned no queue data")
		}
		if len(data) > queuePageLimit {
			return nil, errors.New("Codex thread/queue/list exceeded the requested page size")
		}
		for _, raw := range data {
			item, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("Codex thread/queue/list returned an invalid queue entry")
			}
			id, _ := item["id"].(string)
			clientID, _ := item["clientUserMessageId"].(string)
			input, present := item["input"]
			if strings.TrimSpace(id) == "" || !present || input == nil {
				return nil, errors.New("Codex thread/queue/list returned an incomplete queue entry")
			}
			encodedInput, err := json.Marshal(input)
			if err != nil {
				return nil, errors.New("Codex thread/queue/list returned invalid input")
			}
			queued = append(queued, QueuedSubmission{ID: id, ClientUserMessageID: clientID, Input: encodedInput})
		}
		nextCursor, present := result["nextCursor"]
		if !present {
			return nil, errors.New("Codex thread/queue/list returned no pagination state")
		}
		if nextCursor == nil {
			return queued, nil
		}
		cursor, ok = nextCursor.(string)
		if !ok || strings.TrimSpace(cursor) == "" {
			return nil, errors.New("Codex thread/queue/list returned an invalid pagination cursor")
		}
		if _, exists := seenCursors[cursor]; exists {
			return nil, errors.New("Codex thread/queue/list repeated a pagination cursor")
		}
		seenCursors[cursor] = struct{}{}
	}
	return nil, errors.New("Codex thread/queue/list exceeded the bounded page limit")
}

func (c *ProxyClient) request(ctx context.Context, method string, params any) (map[string]any, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	id := c.nextID
	c.nextID++
	if err := c.write(ctx, map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		messageType, data, err := c.conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				c.Close()
				return nil, ctx.Err()
			}
			c.Close()
			return nil, fmt.Errorf("Codex app-server %s read failed", method)
		}
		if messageType != websocket.MessageText {
			c.Close()
			return nil, errors.New("Codex app-server returned a non-text JSON-RPC message")
		}
		message := decodeProxyMessage(data)
		if message == nil {
			c.Close()
			return nil, errors.New("Codex app-server returned invalid JSON-RPC data")
		}
		if responseID, ok := numberAsInt64(message["id"]); ok && responseID == id {
			if _, exists := message["error"]; exists {
				return nil, fmt.Errorf("Codex app-server %s request failed", method)
			}
			result, ok := message["result"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Codex app-server %s returned no result", method)
			}
			return result, nil
		}
		c.handleMessage(ctx, message)
	}
}

func (c *ProxyClient) notify(ctx context.Context, method string, params any) error {
	return c.write(ctx, map[string]any{"method": method, "params": params})
}

func (c *ProxyClient) write(ctx context.Context, message map[string]any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.Write(ctx, websocket.MessageText, data); err != nil {
		if ctx.Err() != nil {
			c.Close()
			return ctx.Err()
		}
		c.Close()
		return errors.New("Codex app-server proxy write failed")
	}
	return nil
}

func (c *ProxyClient) handleMessage(ctx context.Context, message map[string]any) {
	method, _ := message["method"].(string)
	if method == "" {
		return
	}
	params, _ := message["params"].(map[string]any)
	if message["id"] != nil {
		_ = c.write(ctx, map[string]any{"id": message["id"], "error": map[string]any{
			"code": -32601, "message": "client method is not supported",
		}})
		return
	}
	if c.onEvent != nil {
		c.onEvent(method, params)
	}
}

func decodeProxyMessage(data []byte) map[string]any {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var message map[string]any
	if decoder.Decode(&message) != nil {
		return nil
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil
	}
	return message
}
