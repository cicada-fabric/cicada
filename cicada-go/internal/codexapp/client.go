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
	"strings"
	"sync"
)

type EventHandler func(method string, params map[string]any)
type RequestHandler func(id any, method string, params map[string]any) any

type Client struct {
	process       *exec.Cmd
	stdin         io.WriteCloser
	scanner       *bufio.Scanner
	writeMu       sync.Mutex
	nextID        int64
	onEvent       EventHandler
	onRequest     RequestHandler
	asyncRequests bool
}

// StartAsync keeps the stdout reader active while an approval request waits
// for its human decision. Replies still use the original server request ID.
func StartAsync(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler, onRequest RequestHandler) (*Client, error) {
	client, err := Start(ctx, binary, cwd, env, onEvent, onRequest)
	if err == nil {
		client.asyncRequests = true
	}
	return client, err
}

// Start launches the actual Codex app-server, not a replacement Thread. The
// caller supplies an environment with its own CODEX_HOME and no Hub secrets.
func Start(ctx context.Context, binary, cwd string, env []string,
	onEvent EventHandler, onRequest RequestHandler) (*Client, error) {
	if strings.TrimSpace(binary) == "" {
		binary = "codex"
	}
	// Plugins are outside the Worker execution boundary. Disabling them also
	// avoids a plugin update delaying approval handling on startup.
	process := exec.CommandContext(ctx, binary, "app-server", "--stdio", "--disable", "plugins")
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
	if err := process.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	return &Client{process: process, stdin: stdin, scanner: scanner,
		nextID: 1, onEvent: onEvent, onRequest: onRequest}, nil
}

func (c *Client) PID() int {
	if c == nil || c.process == nil || c.process.Process == nil {
		return 0
	}
	return c.process.Process.Pid
}

func (c *Client) Close() {
	if c == nil {
		return
	}
	c.writeMu.Lock()
	_ = c.stdin.Close()
	c.writeMu.Unlock()
	if c.process.Process != nil {
		_ = c.process.Process.Kill()
	}
	_ = c.process.Wait()
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
		if responseID, ok := numberAsInt64(message["id"]); ok && responseID == id {
			if _, exists := message["error"]; exists {
				return nil, fmt.Errorf("codex %s returned an error", method)
			}
			if result, ok := message["result"].(map[string]any); ok {
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
	var summary string
	for c.scanner.Scan() {
		message := decodeMessage(c.scanner.Text())
		if message == nil {
			continue
		}
		if method, _ := message["method"].(string); method != "" {
			params, _ := message["params"].(map[string]any)
			if item, ok := params["item"].(map[string]any); ok && item["type"] == "agentMessage" {
				if body, ok := item["text"].(string); ok && strings.TrimSpace(body) != "" {
					summary = strings.TrimSpace(body)
				}
			}
			if method == "turn/completed" {
				status := turnStatus(params)
				c.handleMessage(message)
				return summary, status, nil
			}
			if method == "thread/status/changed" && !c.asyncRequests {
				if status, ok := params["status"].(map[string]any); ok && status["type"] == "idle" {
					c.handleMessage(message)
					return summary, "completed", nil
				}
			}
		}
		c.handleMessage(message)
		if err := ctx.Err(); err != nil {
			return summary, "interrupted", err
		}
	}
	if err := c.scanner.Err(); err != nil {
		return summary, "failed", err
	}
	return summary, "failed", errors.New("codex app-server closed before turn completion")
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

func turnStatus(params map[string]any) string {
	if turn, ok := params["turn"].(map[string]any); ok {
		if value, ok := turn["status"].(string); ok {
			return value
		}
	}
	if value, ok := params["status"].(string); ok {
		return value
	}
	return "completed"
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
