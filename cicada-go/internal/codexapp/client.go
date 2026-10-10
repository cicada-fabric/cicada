// Package codexapp provides the small stdio app-server transport shared by
// Control's local Workers and the Node Agent's remote Workers. It owns no
// approval policy or Hub authorization decisions.
package codexapp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

type EventHandler func(method string, params map[string]any)
type RequestHandler func(id any, method string, params map[string]any) any
type ProcessStarter func(*exec.Cmd) error
type ProcessWaiter func(*exec.Cmd) error

// StartError preserves a partial process start separately from its stop proof.
// No process means admission failed before the runtime could begin.
type StartError struct {
	Err     error
	StopErr error
	Started bool
}

func (e *StartError) Error() string { return errors.Join(e.Err, e.StopErr).Error() }
func (e *StartError) Unwrap() error { return errors.Join(e.Err, e.StopErr) }

type Client struct {
	process       *exec.Cmd
	processWaiter ProcessWaiter
	stdin         io.WriteCloser
	scanner       *bufio.Scanner
	writeMu       sync.Mutex
	readMu        sync.Mutex
	closeMu       sync.Mutex
	closeErr      error
	closed        bool
	nextID        int64
	onEvent       EventHandler
	onRequest     RequestHandler
	asyncRequests bool
	// Only successful native responses confirm these IDs; readMu protects them.
	threadID string
	turnID   string
}

const minimumQueueWakeVersion = "0.156.1"

var semanticVersion = regexp.MustCompile(`(?:^|[^0-9])v?([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?(?:$|[^0-9])`)

// versionAtLeast deliberately parses the runtime's reported version rather
// than relying on a compiled-in exact CLI release. Unknown versions fail
// closed because the experimental queue API is part of the pinned protocol.
func versionAtLeast(version, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		match := semanticVersion.FindStringSubmatch(strings.TrimSpace(value))
		if len(match) != 6 || match[4] != "" {
			return [3]int{}, false
		}
		var parsed [3]int
		for index := range parsed {
			if _, err := fmt.Sscanf(match[index+1], "%d", &parsed[index]); err != nil {
				return [3]int{}, false
			}
		}
		return parsed, true
	}
	actual, ok := parse(version)
	if !ok {
		return false
	}
	wanted, ok := parse(minimum)
	if !ok {
		return false
	}
	for index := range actual {
		if actual[index] != wanted[index] {
			return actual[index] > wanted[index]
		}
	}
	return true
}

// InitializeExperimental negotiates the experimental queue methods and
// verifies that the server handshake reports a version supported by this
// client. Call it before any thread mutation.
func (c *Client) InitializeExperimental(ctx context.Context, clientName, title, clientVersion string) error {
	result, err := c.Request(ctx, "initialize", map[string]any{
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
	return c.Notify("initialized", map[string]any{})
}

// StartAsync keeps the stdout reader active while an approval request waits
// for its human decision. Replies still use the original server request ID.
func StartAsync(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler, onRequest RequestHandler) (*Client, error) {
	return StartAsyncWithLifecycle(ctx, binary, cwd, env, onEvent, onRequest, nil, nil)
}

// StartAsyncWithLifecycle is the narrow Node execution hook. The caller may
// reserve a durable physical resource before process start and own the root
// Cmd.Wait observation. Control's ordinary local execution uses StartAsync.
func StartAsyncWithLifecycle(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler, onRequest RequestHandler, starter ProcessStarter,
	waiter ProcessWaiter) (*Client, error) {
	client, err := StartWithLifecycle(ctx, binary, cwd, env, onEvent, onRequest, starter, waiter)
	if err == nil {
		client.asyncRequests = true
	}
	return client, err
}

// Start launches the actual Codex app-server, not a replacement Thread. The
// caller supplies an environment with its own CODEX_HOME and no Hub secrets.
func Start(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler, onRequest RequestHandler) (*Client, error) {
	return StartWithLifecycle(ctx, binary, cwd, env, onEvent, onRequest, nil, nil)
}

// StartWithLifecycle configures one app-server process while allowing the
// caller to own its start/wait boundary without importing Node policy here.
func StartWithLifecycle(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler, onRequest RequestHandler, starter ProcessStarter,
	waiter ProcessWaiter) (*Client, error) {
	if strings.TrimSpace(binary) == "" {
		binary = "codex"
	}
	// Plugins are outside the Worker execution boundary. Disabling them also
	// avoids a plugin update delaying approval handling on startup.
	process := exec.CommandContext(ctx, binary, "app-server", "--stdio", "--disable", "plugins")
	configureAppServerProcess(process)
	process.Dir = cwd
	process.Env = env
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := process.StdinPipe()
	if err != nil {
		return nil, err
	}
	process.Stderr = os.Stderr
	start := starter
	if start == nil {
		start = func(command *exec.Cmd) error { return command.Start() }
	}
	if err := start(process); err != nil {
		var cleanupErr error
		if process.Process != nil {
			if process.Cancel != nil {
				cancelErr := process.Cancel()
				if cancelErr != nil && !errors.Is(cancelErr, os.ErrProcessDone) {
					cleanupErr = errors.Join(cleanupErr, cancelErr)
				}
			}
			var waitErr error
			if waiter != nil {
				waitErr = waiter(process)
			} else {
				waitErr = process.Wait()
				if process.ProcessState != nil && (waitErr == context.Canceled || waitErr == context.DeadlineExceeded) {
					waitErr = nil
				}
				if _, exitOnly := waitErr.(*exec.ExitError); exitOnly {
					waitErr = nil
				}
			}
			cleanupErr = errors.Join(cleanupErr, waitErr, waitAppServerProcessTree(process))
		}
		return nil, &StartError{Err: err, StopErr: cleanupErr, Started: process.Process != nil}
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	return &Client{process: process, processWaiter: waiter, stdin: stdin, scanner: scanner,
		nextID: 1, onEvent: onEvent, onRequest: onRequest}, nil
}

func (c *Client) PID() int {
	if c == nil || c.process == nil || c.process.Process == nil {
		return 0
	}
	return c.process.Process.Pid
}

func (c *Client) Close() {
	_ = c.CloseAndWait()
}

// CloseAndWait asks the app-server process group to stop, waits for the direct
// child, and confirms the group is gone before its caller releases any native
// writer lease. The runtime's parent process exit alone is not sufficient.
func (c *Client) CloseAndWait() error {
	if c == nil {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	c.writeMu.Lock()
	var closeErr error
	if c.stdin != nil {
		closeErr = c.stdin.Close()
	}
	c.writeMu.Unlock()
	var waitErr error
	if c.process != nil && c.process.Process != nil {
		if c.process.ProcessState == nil && c.process.Cancel != nil {
			cancelErr := c.process.Cancel()
			if cancelErr != nil && !errors.Is(cancelErr, os.ErrProcessDone) {
				closeErr = errors.Join(closeErr, cancelErr)
			}
		}
		if c.processWaiter != nil {
			waitErr = c.processWaiter(c.process)
		} else {
			waitErr = c.process.Wait()
			// CommandContext can return its cancellation after a successful
			// child exit. A recorded ProcessState still proves Cmd.Wait observed
			// that exit; the process-group check below remains mandatory.
			if c.process.ProcessState != nil && (waitErr == context.Canceled || waitErr == context.DeadlineExceeded) {
				waitErr = nil
			}
			if _, exitOnly := waitErr.(*exec.ExitError); exitOnly {
				waitErr = nil // Default Cmd.Wait observed the signalled/nonzero exit.
			}
		}
		closeErr = errors.Join(closeErr, waitErr, waitAppServerProcessTree(c.process))
	}
	c.closeErr = closeErr
	return c.closeErr
}

func (c *Client) write(message map[string]any) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = fmt.Fprintln(c.stdin, string(data))
	return err
}

func (c *Client) Notify(method string, params any) error {
	return c.write(map[string]any{"method": method, "params": params})
}

func (c *Client) Request(ctx context.Context, method string, params any) (map[string]any, error) {
	// Request and WaitTurn share one scanner. Serialize all reads and use the
	// same operation context for Start and requests so cancellation terminates
	// the app-server process and unblocks a pending Scan.
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if method == "thread/start" || method == "thread/resume" {
		c.threadID, c.turnID = "", ""
	} else if method == "turn/start" {
		c.turnID = ""
	}
	id := c.nextID
	c.nextID++
	if err := c.write(map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for c.scanner.Scan() {
		message := decodeMessage(c.scanner.Text())
		if message == nil {
			continue
		}
		if responseID, ok := numberAsInt64(message["id"]); ok && responseID == id && message["method"] == nil {
			if _, exists := message["error"]; exists {
				return nil, fmt.Errorf("codex %s returned an error", method)
			}
			if result, ok := message["result"].(map[string]any); ok {
				if err := c.confirmNativeResponse(method, params, result); err != nil {
					return nil, err
				}
				return result, nil
			}
			return map[string]any{}, nil
		}
		c.handleMessage(message)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := c.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("codex app-server closed stdout")
}

// Called with readMu held after the matching successful JSON-RPC response.
// Request parameters identify the requested Thread, never confirm a native ID.
func (c *Client) confirmNativeResponse(method string, params any, result map[string]any) error {
	switch method {
	case "thread/start", "thread/resume":
		thread, _ := result["thread"].(map[string]any)
		id, _ := thread["id"].(string)
		if !validNativeID(id) {
			return errors.New("Codex did not confirm a native Thread ID")
		}
		if method == "thread/resume" {
			requested, _ := params.(map[string]any)
			if requested["threadId"] != id {
				return errors.New("Codex did not confirm the requested native Thread")
			}
		}
		c.threadID = id
	case "turn/start":
		requested, _ := params.(map[string]any)
		turn, _ := result["turn"].(map[string]any)
		id, _ := turn["id"].(string)
		if c.threadID == "" || requested["threadId"] != c.threadID || !validNativeID(id) {
			return errors.New("Codex did not confirm a Turn on the original native Thread")
		}
		c.turnID = id
	}
	return nil
}

func validNativeID(id string) bool {
	return id != "" && id == strings.TrimSpace(id) && !strings.ContainsAny(id, "\x00\r\n")
}

func (c *Client) handleMessage(message map[string]any) {
	method, _ := message["method"].(string)
	if method == "" {
		return
	}
	params, _ := message["params"].(map[string]any)
	if message["id"] != nil {
		respond := func() {
			result := any(map[string]any{})
			if c.onRequest != nil {
				result = c.onRequest(message["id"], method, params)
			}
			_ = c.write(map[string]any{"id": message["id"], "result": result})
		}
		if c.asyncRequests {
			go respond()
		} else {
			respond()
		}
		return
	}
	if c.onEvent != nil {
		c.onEvent(method, params)
	}
}

func (c *Client) WaitTurn(ctx context.Context) (string, string, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.threadID == "" || c.turnID == "" {
		return "", "failed", errors.New("Codex turn completion lacks a confirmed original Thread and Turn")
	}
	var summary string
	for c.scanner.Scan() {
		message := decodeMessage(c.scanner.Text())
		if message == nil {
			continue
		}
		method, _ := message["method"].(string)
		params, _ := message["params"].(map[string]any)
		if message["id"] == nil && params["threadId"] == c.threadID {
			if params["turnId"] == c.turnID {
				summary = agentMessageSummary(params["item"], summary)
			}
			if method == "turn/completed" {
				turn, _ := params["turn"].(map[string]any)
				status, _ := turn["status"].(string)
				items, itemsPresent := turn["items"].([]any)
				if turn["id"] == c.turnID && itemsPresent &&
					(status == "completed" || status == "failed" || status == "interrupted") {
					for _, item := range items {
						summary = agentMessageSummary(item, summary)
					}
					c.handleMessage(message)
					return summary, status, nil
				}
			}
		}
		// Foreign or malformed notifications cannot finish the confirmed turn.
		// Keep processing requests/events so its actual completion can still arrive.
		c.handleMessage(message)
		if err := ctx.Err(); err != nil {
			return summary, "interrupted", err
		}
	}
	if err := c.scanner.Err(); err != nil {
		return summary, "failed", err
	}
	return summary, "failed", errors.New("codex app-server closed before exact turn completion")
}

func agentMessageSummary(value any, previous string) string {
	item, _ := value.(map[string]any)
	if item["type"] == "agentMessage" {
		if text, ok := item["text"].(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return previous
}

func decodeMessage(line string) map[string]any {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(line)))
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

func numberAsInt64(value any) (int64, bool) {
	if number, ok := value.(json.Number); ok {
		parsed, err := number.Int64()
		return parsed, err == nil
	}
	if number, ok := value.(float64); ok {
		return int64(number), true
	}
	if number, ok := value.(int64); ok {
		return number, true
	}
	return 0, false
}
