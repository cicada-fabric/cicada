package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

const (
	mcpStdioMaxFrame      = 2 << 20
	mcpStdioQueueSize     = 16
	mcpStdioResponseGrace = 2 * time.Second
)

var (
	errMCPStdioClosed   = errors.New("MCP_TRANSPORT_CLOSED: the original MCP connection is closed")
	errMCPStdioOverflow = errors.New("MCP_TRANSPORT_OVERLOADED: too many queued requests; reconnect before retrying")
)

type mcpStdioCall struct {
	request mcpRequest
	key     string
	ctx     context.Context
	cancel  context.CancelFunc
	form    bool
}

type mcpStdioWrite struct {
	value any
	done  chan error
}

// The reader never runs business handlers or waits for queue space. One worker
// retains the existing serial trusted-Actor lifecycle while responses and
// cancellation continue to reach a waiting server-initiated request.
type mcpStdioTransport struct {
	input         io.Reader
	output        io.Writer
	writerOnce    sync.Once
	writes        chan mcpStdioWrite
	writerDone    chan struct{}
	streamCleanup func()
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	err           error
	started       bool
	negotiated    bool
	formSupported bool
	calls         map[string]*mcpStdioCall
	active        *mcpStdioCall
	pending       map[string]chan mcpElicitationReply
	formTimeout   time.Duration
}

// The transport owns these connection streams. Closable streams are closed on
// shutdown to interrupt blocked reads/writes; production passes only its MCP
// stdin/stdout. Nonclosable arbitrary writers cannot promise writer recovery.
func newMCPStdioTransport(input io.Reader, output io.Writer) *mcpStdioTransport {
	ctx, cancel := context.WithCancel(context.Background())
	t := &mcpStdioTransport{input: input, output: output, ctx: ctx, cancel: cancel,
		calls: make(map[string]*mcpStdioCall), pending: make(map[string]chan mcpElicitationReply),
		writes:      make(chan mcpStdioWrite, 1),
		writerDone:  make(chan struct{}),
		formTimeout: 2 * time.Minute}
	preparedInput, preparedOutput, cleanup, err := prepareMCPStdioStreams(input, output)
	if err != nil {
		t.shutdown(fmt.Errorf("prepare interruptible MCP streams: %w", err))
		return t
	}
	t.input, t.output, t.streamCleanup = preparedInput, preparedOutput, cleanup
	return t
}

func (t *mcpStdioTransport) serve(handle func(mcpRequest) (mcpResponse, bool)) error {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return errors.New("MCP transport has already started")
	}
	t.started = true
	t.mu.Unlock()
	defer t.shutdown(nil)
	queue := make(chan *mcpStdioCall, mcpStdioQueueSize)
	go t.read(queue)
	for {
		select {
		case <-t.ctx.Done():
			t.mu.Lock()
			err := t.err
			t.mu.Unlock()
			return err
		case call := <-queue:
			if call.ctx.Err() == nil {
				t.mu.Lock()
				t.active = call
				t.mu.Unlock()
				response, send := handle(call.request)
				if send && len(call.request.ID) != 0 && call.ctx.Err() == nil {
					// Keep integer/string request IDs exact, including large integers.
					response.ID = json.RawMessage(call.request.ID)
					writeCtx, cancelWrite := context.WithTimeout(call.ctx, t.formTimeout)
					if call.form {
						cancelWrite()
						// This is only a bounded output grace, never new time to
						// choose a peer, renew a proof or perform business work.
						writeCtx, cancelWrite = context.WithTimeout(call.ctx, mcpStdioResponseGrace)
					}
					if err := t.writeContext(writeCtx, response); err != nil {
						t.shutdown(err)
					}
					cancelWrite()
				}
			}
			t.mu.Lock()
			if t.active == call {
				t.active = nil
			}
			delete(t.calls, call.key)
			t.mu.Unlock()
			call.cancel()
		}
	}
}

func (t *mcpStdioTransport) shutdown(err error) {
	t.mu.Lock()
	if t.ctx.Err() != nil {
		t.mu.Unlock()
		return
	}
	t.err = err
	t.cancel()
	for _, call := range t.calls {
		call.cancel()
	}
	// Waiters retain their channel, but no late response can find it again.
	clear(t.pending)
	t.mu.Unlock()
	if input, ok := t.input.(io.Closer); ok {
		_ = input.Close()
	}
	if output, ok := t.output.(io.Closer); ok {
		_ = output.Close()
	}
	if t.streamCleanup != nil {
		t.streamCleanup()
	}
}

func (t *mcpStdioTransport) write(value any) error {
	return t.writeContext(t.ctx, value)
}

func (t *mcpStdioTransport) writeContext(ctx context.Context, value any) error {
	t.writerOnce.Do(func() { go t.writeLoop() })
	job := mcpStdioWrite{value: value, done: make(chan error, 1)}
	if ctx.Err() != nil || t.ctx.Err() != nil {
		t.shutdown(errMCPStdioClosed)
		return errMCPStdioClosed
	}
	select {
	case <-ctx.Done():
		t.shutdown(errMCPStdioClosed)
		return errMCPStdioClosed
	case <-t.ctx.Done():
		return errMCPStdioClosed
	case t.writes <- job:
	}
	select {
	case <-ctx.Done():
		// Output may have been partially written. Close the connection rather
		// than enqueueing a second frame or letting business continue.
		t.shutdown(errMCPStdioClosed)
		return errMCPStdioClosed
	case <-t.ctx.Done():
		return errMCPStdioClosed
	case err := <-job.done:
		return err
	}
}

// Exactly one writer may block on a Host that stops reading. Cancellation
// releases the caller without spawning replacement writers. The owner closes
// its streams (the production stdio process exits) after serve returns.
func (t *mcpStdioTransport) writeLoop() {
	defer close(t.writerDone)
	encoder := json.NewEncoder(t.output)
	for {
		select {
		case <-t.ctx.Done():
			return
		case job := <-t.writes:
			if t.ctx.Err() != nil {
				job.done <- errMCPStdioClosed
				return
			}
			err := encoder.Encode(job.value)
			if err != nil {
				err = fmt.Errorf("encode MCP message: %w", err)
				t.shutdown(err)
			}
			job.done <- err
		}
	}
}

func (t *mcpStdioTransport) read(queue chan<- *mcpStdioCall) {
	// MCP stdio frames are individual newline-delimited JSON messages. Bound
	// each frame and the request queue independently of an open human form.
	scanner := bufio.NewScanner(t.input)
	scanner.Buffer(make([]byte, 4096), mcpStdioMaxFrame)
	for scanner.Scan() {
		if t.ctx.Err() != nil {
			return
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &fields); err != nil || fields == nil || string(fields["jsonrpc"]) != `"2.0"` || !mcpJSONUniqueKeys(scanner.Bytes()) {
			t.shutdown(errors.New("invalid MCP JSON-RPC frame"))
			return
		}
		if _, request := fields["method"]; !request {
			t.receiveReply(fields)
			continue
		}
		var request mcpRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil || request.Method == "" || fields["result"] != nil || fields["error"] != nil {
			t.shutdown(errors.New("invalid MCP request"))
			return
		}
		if request.Method == "notifications/cancelled" && len(request.ID) == 0 {
			t.receiveCancellation(request.Params)
			continue
		}
		// Notifications must not invoke a request-only business tool.
		if len(request.ID) == 0 && request.Method != "notifications/initialized" {
			continue
		}
		key := ""
		if len(request.ID) != 0 {
			var ok bool
			key, ok = mcpStdioIDKey(request.ID)
			if !ok {
				t.shutdown(errors.New("invalid MCP request ID"))
				return
			}
		}
		ctx, cancel := context.WithCancel(t.ctx)
		call := &mcpStdioCall{request: request, key: key, ctx: ctx, cancel: cancel}
		t.mu.Lock()
		_, duplicate := t.calls[key]
		if key != "" && !duplicate {
			t.calls[key] = call
		}
		t.mu.Unlock()
		if key != "" && duplicate {
			cancel()
			t.shutdown(errors.New("duplicate in-flight MCP request ID"))
			return
		}
		select {
		case queue <- call:
		default:
			cancel()
			// Closing rather than blocking leaves no hidden queued business
			// operation after the Host has overloaded the connection.
			t.shutdown(errMCPStdioOverflow)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		t.shutdown(fmt.Errorf("read MCP frame: %w", err))
	} else {
		t.shutdown(nil)
	}
}

func mcpStdioIDKey(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", false
	}
	var text string
	if raw[0] == '"' && json.Unmarshal(raw, &text) == nil {
		return "s:" + text, true
	}
	var number json.Number
	if json.Unmarshal(raw, &number) != nil || string(raw) == "null" {
		return "", false
	}
	value, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return "", false
	}
	return "n:" + strconv.FormatInt(value, 10), true
}

func (t *mcpStdioTransport) receiveCancellation(raw json.RawMessage) {
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(raw, &params) != nil {
		return
	}
	key, ok := mcpStdioIDKey(params.RequestID)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if call := t.calls[key]; call != nil {
		call.cancel()
	}
}

// Reject ambiguous duplicate fields in both envelopes and nested form content.
// This uses only the bounded input frame; it never interprets a model payload.
func mcpJSONUniqueKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delim {
		case '{':
			keys := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return false
				}
				keys[name] = true
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		end, err := decoder.Token()
		return err == nil && ((delim == '{' && end == json.Delim('}')) || (delim == '[' && end == json.Delim(']')))
	}
	if !value(0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}
