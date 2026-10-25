package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These fixtures exercise the real stdio transport, not Cicada authorization.
// No Node, actor proof, peer messages, Host config or provider is involved.
type mcpStdioFixture struct {
	t         *testing.T
	transport *mcpStdioTransport
	input     *io.PipeWriter
	output    *io.PipeReader
	frames    chan map[string]json.RawMessage
	done      chan error
}

func newMCPStdioFixture(t *testing.T, handler func(*mcpStdioTransport, mcpRequest) (mcpResponse, bool)) *mcpStdioFixture {
	t.Helper()
	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	f := &mcpStdioFixture{t: t, transport: newMCPStdioTransport(inReader, outWriter), input: inWriter, output: outReader,
		frames: make(chan map[string]json.RawMessage, 64), done: make(chan error, 1)}
	go func() {
		decoder := json.NewDecoder(outReader)
		for {
			var frame map[string]json.RawMessage
			if decoder.Decode(&frame) != nil {
				return
			}
			f.frames <- frame
		}
	}()
	go func() {
		f.done <- f.transport.serve(func(request mcpRequest) (mcpResponse, bool) { return handler(f.transport, request) })
	}()
	t.Cleanup(func() {
		_ = inWriter.Close()
		_ = inReader.Close()
		_ = outReader.Close()
		_ = outWriter.Close()
		f.transport.shutdown(nil)
	})
	return f
}

func (f *mcpStdioFixture) send(value any) {
	f.t.Helper()
	if err := json.NewEncoder(f.input).Encode(value); err != nil {
		f.t.Fatal(err)
	}
}

func (f *mcpStdioFixture) request(id any, method string) {
	f.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method})
}

func (f *mcpStdioFixture) next() map[string]json.RawMessage {
	f.t.Helper()
	select {
	case frame := <-f.frames:
		return frame
	case <-time.After(3 * time.Second):
		f.t.Fatal("timed out waiting for MCP frame")
		return nil
	}
}

func (f *mcpStdioFixture) stopped() error {
	f.t.Helper()
	select {
	case err := <-f.done:
		return err
	case <-time.After(3 * time.Second):
		f.t.Fatal("transport did not stop")
		return nil
	}
}

func mcpTestOptions() []mcpPeerFormOption {
	return []mcpPeerFormOption{{ID: "synthetic-a-binding-v1", Label: "Alpha | /synthetic/a | lease snapshot"},
		{ID: "synthetic-b-binding-v2", Label: "Beta | /synthetic/b | unknown presence"}}
}

func mcpTestFormHandler(errorsSeen chan<- error) func(*mcpStdioTransport, mcpRequest) (mcpResponse, bool) {
	return func(transport *mcpStdioTransport, request mcpRequest) (mcpResponse, bool) {
		if request.Method == "initialize" {
			transport.negotiate(request.Params)
			return mcpResponse{JSONRPC: "2.0", Result: map[string]any{}}, true
		}
		if request.Method == "tools/call" {
			selected, err := transport.elicitPeer("Choose an authorized peer; selection grants no rights.", mcpTestOptions())
			if errorsSeen != nil {
				errorsSeen <- err
			}
			return mcpResponse{JSONRPC: "2.0", Result: map[string]any{"selected": selected, "failed": err != nil}}, true
		}
		return mcpResponse{JSONRPC: "2.0", Result: map[string]any{}}, len(request.ID) != 0
	}
}

func (f *mcpStdioFixture) initialize(capabilities any) {
	f.send(map[string]any{"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": map[string]any{"capabilities": capabilities}})
	f.next()
}

func (f *mcpStdioFixture) answer(form map[string]json.RawMessage, result any) {
	f.send(map[string]any{"jsonrpc": "2.0", "id": form["id"], "result": result})
}

func mcpTestAccept(value string) any {
	return map[string]any{"action": "accept", "content": map[string]any{"peer": value}}
}

func TestMCPStdioExactFormsRemainBoundToOriginalRequest(t *testing.T) {
	errorsSeen := make(chan error, 2)
	f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
	f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
	f.request(json.Number("9007199254740993"), "tools/call")
	first := f.next()
	if string(first["method"]) != `"elicitation/create"` {
		t.Fatal("expected server form request")
	}
	var params struct {
		Mode   string `json:"mode"`
		Schema struct {
			Properties map[string]struct {
				OneOf []struct{ Const, Title string } `json:"oneOf"`
			} `json:"properties"`
			Required   []string `json:"required"`
			Additional bool     `json:"additionalProperties"`
		} `json:"requestedSchema"`
	}
	if json.Unmarshal(first["params"], &params) != nil || params.Mode != "form" || len(params.Schema.Properties["peer"].OneOf) != 2 || len(params.Schema.Required) != 1 || params.Schema.Additional {
		t.Fatal("form is not a bounded required opaque peer enum")
	}
	f.request("caller-b", "tools/call")
	// A response for another ID cannot supply the first caller's choice.
	f.send(map[string]any{"jsonrpc": "2.0", "id": "not-the-form", "result": mcpTestAccept("synthetic-a-binding-v1")})
	f.answer(first, mcpTestAccept("synthetic-b-binding-v2"))
	result := f.next()
	if string(result["id"]) != "9007199254740993" || !bytes.Contains(result["result"], []byte("synthetic-b-binding-v2")) {
		t.Fatal("original request ID or exact choice was lost")
	}
	second := f.next()
	if bytes.Equal(first["id"], second["id"]) {
		t.Fatal("form IDs were reused across callers")
	}
	// Late/duplicate responses never complete the second caller's form.
	f.answer(first, mcpTestAccept("synthetic-b-binding-v2"))
	f.answer(second, mcpTestAccept("synthetic-a-binding-v1"))
	result = f.next()
	if string(result["id"]) != `"caller-b"` || !bytes.Contains(result["result"], []byte("synthetic-a-binding-v1")) {
		t.Fatal("cross-call response mixup")
	}
	for range 2 {
		if err := <-errorsSeen; err != nil {
			t.Fatal(err)
		}
	}
}

func TestMCPStdioFormCapabilityMustBeExplicit(t *testing.T) {
	for _, capabilities := range []string{`{}`, `{"elicitation":{}}`, `{"elicitation":{"url":{}}}`, `{"elicitation":{"form":null}}`, `{"elicitation":{"form":true}}`} {
		t.Run(capabilities, func(t *testing.T) {
			errorsSeen := make(chan error, 1)
			f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
			f.initialize(json.RawMessage(capabilities))
			// A later initialization cannot silently upgrade this connection.
			f.transport.negotiate(json.RawMessage(`{"capabilities":{"elicitation":{"form":{}}}}`))
			f.request("a", "tools/call")
			if string(f.next()["id"]) != `"a"` || !errors.Is(<-errorsSeen, errMCPFormUnsupported) {
				t.Fatal("incompatible Host received a form")
			}
		})
	}
	if _, err := (*mcpStdioTransport)(nil).elicitPeer("Select", mcpTestOptions()); !errors.Is(err, errMCPFormUnsupported) {
		t.Fatal(err)
	}
}

func TestMCPStdioDeclineCancelAndInvalidChoiceReturnNoSelection(t *testing.T) {
	cases := []struct {
		name   string
		result any
		want   error
	}{
		{"decline", map[string]any{"action": "decline"}, errMCPFormDeclined},
		{"cancel", map[string]any{"action": "cancel"}, errMCPFormCancelled},
		{"unknown", map[string]any{"action": "continue"}, errMCPFormInvalid},
		{"foreign-choice", mcpTestAccept("other-binding"), errMCPFormInvalid},
		{"label-is-not-id", mcpTestAccept(mcpTestOptions()[0].Label), errMCPFormInvalid},
		{"extra-field", map[string]any{"action": "accept", "content": map[string]any{"peer": "synthetic-a-binding-v1", "thread_id": "forged"}}, errMCPFormInvalid},
		{"extra-result", map[string]any{"action": "accept", "content": map[string]any{"peer": "synthetic-a-binding-v1"}, "grant": true}, errMCPFormInvalid},
		{"no-content", map[string]any{"action": "accept"}, errMCPFormInvalid},
		{"non-string", map[string]any{"action": "accept", "content": map[string]any{"peer": 1}}, errMCPFormInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errorsSeen := make(chan error, 1)
			f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
			f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
			f.request("a", "tools/call")
			f.answer(f.next(), tc.result)
			result := f.next()
			if !errors.Is(<-errorsSeen, tc.want) || !bytes.Contains(result["result"], []byte(`"selected":""`)) {
				t.Fatal("refusal returned a peer selection")
			}
		})
	}
}

func TestMCPStdioCancellationAlsoCancelsQueuedCaller(t *testing.T) {
	errorsSeen := make(chan error, 1)
	f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
	f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
	f.request("a", "tools/call")
	form := f.next()
	f.request("b", "tools/call")
	for _, id := range []string{"b", "a"} {
		f.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id}})
	}
	f.answer(form, mcpTestAccept("synthetic-a-binding-v1"))
	f.request("barrier", "ping")
	if string(f.next()["id"]) != `"barrier"` || !errors.Is(<-errorsSeen, errMCPFormCancelled) {
		t.Fatal("cancelled call was revived")
	}
	f.transport.mu.Lock()
	pending := len(f.transport.pending)
	f.transport.mu.Unlock()
	if pending != 0 {
		t.Fatal("cancelled form retained pending state")
	}
}

func TestMCPStdioEOFAndTimeoutCleanPendingForms(t *testing.T) {
	for _, eof := range []bool{true, false} {
		t.Run(fmt.Sprint("eof=", eof), func(t *testing.T) {
			errorsSeen := make(chan error, 1)
			f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
			f.transport.formTimeout = 100 * time.Millisecond
			f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
			f.request("a", "tools/call")
			form := f.next()
			if eof {
				_ = f.input.Close()
				if err := f.stopped(); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(<-errorsSeen, errMCPFormCancelled) {
					t.Fatal("EOF did not cancel original form")
				}
			} else {
				if string(f.next()["id"]) != `"a"` {
					t.Fatal("form timeout did not return the original tool error")
				}
				if !errors.Is(<-errorsSeen, errMCPFormTimeout) {
					t.Fatal("form did not expire")
				}
				f.answer(form, mcpTestAccept("synthetic-a-binding-v1"))
				f.request("barrier", "ping")
				if string(f.next()["id"]) != `"barrier"` {
					t.Fatal("timeout broke the healthy connection")
				}
				f.request("next", "tools/call")
				f.answer(f.next(), mcpTestAccept("synthetic-b-binding-v2"))
				if string(f.next()["id"]) != `"next"` || <-errorsSeen != nil {
					t.Fatal("next selection failed after timeout")
				}
			}
			f.transport.mu.Lock()
			pending := len(f.transport.pending)
			f.transport.mu.Unlock()
			if pending != 0 {
				t.Fatal("closed form retained pending response route")
			}
		})
	}
}

func TestMCPStdioOverloadClosesInsteadOfBlockingResponseReader(t *testing.T) {
	var invoked atomic.Int64
	errorsSeen := make(chan error, 1)
	base := mcpTestFormHandler(errorsSeen)
	f := newMCPStdioFixture(t, func(transport *mcpStdioTransport, request mcpRequest) (mcpResponse, bool) {
		if request.Method == "tools/call" {
			invoked.Add(1)
		}
		return base(transport, request)
	})
	f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
	f.request("waiting", "tools/call")
	f.next()
	for i := range mcpStdioQueueSize + 1 {
		f.request(i, "tools/call")
	}
	if err := f.stopped(); !errors.Is(err, errMCPStdioOverflow) {
		t.Fatal(err)
	}
	if invoked.Load() != 1 || !errors.Is(<-errorsSeen, errMCPFormCancelled) {
		t.Fatal("queued business ran after overload")
	}
}

func TestMCPStdioMalformedResponseCannotBeRepairedByDuplicate(t *testing.T) {
	errorsSeen := make(chan error, 1)
	f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
	f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
	f.request("a", "tools/call")
	form := f.next()
	f.send(map[string]any{"jsonrpc": "2.0", "id": form["id"], "error": map[string]any{"code": -32601, "message": "Synthetic Host rejection"}})
	f.answer(form, mcpTestAccept("synthetic-a-binding-v1"))
	if !bytes.Contains(f.next()["result"], []byte(`"selected":""`)) || !errors.Is(<-errorsSeen, errMCPFormInvalid) {
		t.Fatal("duplicate repaired a rejected form")
	}
}

func TestMCPStdioFrameLimitsAndAmbiguousJSONFailClosed(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1.1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":"x","result":{"action":"cancel","action":"accept"}}`,
		strings.Repeat(" ", mcpStdioMaxFrame),
	} {
		t.Run(fmt.Sprint(len(raw), "-", strings.Count(raw, "method")), func(t *testing.T) {
			f := newMCPStdioFixture(t, mcpTestFormHandler(nil))
			// An oversized scanner frame can leave its final byte unread. The
			// fixture owns/ closes both pipe ends after observing shutdown.
			go func() { _, _ = io.WriteString(f.input, raw+"\n") }()
			if f.stopped() == nil {
				t.Fatal("ambiguous or oversized frame was accepted")
			}
		})
	}
}

func TestMCPStdioWritesAreWholeJSONFrames(t *testing.T) {
	var output bytes.Buffer
	transport := newMCPStdioTransport(strings.NewReader(""), &output)
	t.Cleanup(func() { transport.shutdown(nil) })
	var writers sync.WaitGroup
	for i := range 20 {
		writers.Go(func() {
			if err := transport.write(map[string]any{"jsonrpc": "2.0", "id": i, "result": strings.Repeat("synthetic", 512)}); err != nil {
				t.Error(err)
			}
		})
	}
	writers.Wait()
	decoder := json.NewDecoder(&output)
	seen := map[int]bool{}
	for range 20 {
		var frame struct{ ID int }
		if decoder.Decode(&frame) != nil || seen[frame.ID] {
			t.Fatal("stdout frames interleaved")
		}
		seen[frame.ID] = true
	}
}

type mcpBlockedOutput struct {
	writer   io.WriteCloser
	entered  chan struct{}
	finished chan struct{}
	once     sync.Once
	written  atomic.Int64
}

func (output *mcpBlockedOutput) Write(raw []byte) (int, error) {
	output.once.Do(func() { close(output.entered) })
	n, err := output.writer.Write(raw)
	output.written.Add(int64(n))
	close(output.finished)
	return n, err
}

func (output *mcpBlockedOutput) Close() error { return output.writer.Close() }

func TestMCPStdioBlockedOutputCancellationTimeoutEOFReclaimsWriter(t *testing.T) {
	for _, kind := range []string{"io-pipe", "os-pipe"} {
		for _, stop := range []string{"cancel", "timeout", "eof"} {
			t.Run(kind+"/"+stop, func(t *testing.T) {
				input, hostInput := io.Pipe()
				var output io.WriteCloser
				var hostOutput io.ReadCloser
				if kind == "os-pipe" {
					reader, writer, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					hostOutput, output = reader, writer
				} else {
					reader, writer := io.Pipe()
					hostOutput, output = reader, writer
				}
				blocked := &mcpBlockedOutput{writer: output, entered: make(chan struct{}), finished: make(chan struct{})}
				transport := newMCPStdioTransport(input, blocked)
				if stop == "timeout" {
					transport.formTimeout = 100 * time.Millisecond
				}
				transport.negotiate(json.RawMessage(`{"capabilities":{"elicitation":{"form":{}}}}`))
				t.Cleanup(func() { _ = hostInput.Close(); _ = hostOutput.Close(); transport.shutdown(nil) })
				choices := make([]mcpPeerFormOption, 64)
				for i := range choices {
					choices[i] = mcpPeerFormOption{ID: fmt.Sprintf("synthetic-%02d", i), Label: strings.Repeat("x", 2048)}
				}
				errorsSeen := make(chan error, 1)
				done := make(chan error, 1)
				go func() {
					done <- transport.serve(func(request mcpRequest) (mcpResponse, bool) {
						selected, err := transport.elicitPeer("Select", choices)
						if selected != "" {
							t.Error("blocked output returned a peer")
						}
						errorsSeen <- err
						return mcpResponse{JSONRPC: "2.0", Result: map[string]any{}}, true
					})
				}()
				encoder := json.NewEncoder(hostInput)
				if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": "original", "method": "tools/call"}); err != nil {
					t.Fatal(err)
				}
				select {
				case <-blocked.entered:
				case <-time.After(3 * time.Second):
					t.Fatal("writer did not start")
				}
				switch stop {
				case "cancel":
					if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "original"}}); err != nil {
						t.Fatal(err)
					}
				case "eof":
					_ = hostInput.Close()
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("blocked output trapped the serial worker")
				}
				select {
				case <-transport.writerDone:
				case <-time.After(3 * time.Second):
					t.Fatal("blocked writer was not reclaimed")
				}
				want := errMCPFormCancelled
				if stop == "timeout" {
					want = errMCPFormTimeout
				}
				if err := <-errorsSeen; !errors.Is(err, want) {
					t.Fatal(err)
				}
				if blocked.written.Load() >= 128*1024 {
					t.Fatal("fixture did not block before the complete form frame")
				}
			})
		}
	}
}

func TestMCPStdioFormsRequireActiveCallAndBoundedOptions(t *testing.T) {
	transport := newMCPStdioTransport(strings.NewReader(""), io.Discard)
	transport.negotiate(json.RawMessage(`{"capabilities":{"elicitation":{"form":{}}}}`))
	if _, err := transport.elicitPeer("Select", mcpTestOptions()); !errors.Is(err, errMCPFormUnavailable) {
		t.Fatal(err)
	}
	options := mcpTestOptions()
	options[1].ID = options[0].ID
	if _, err := transport.elicitPeer("Select", options); !errors.Is(err, errMCPFormInvalid) {
		t.Fatal("duplicate options accepted")
	}
	if _, err := transport.elicitPeer("Select", make([]mcpPeerFormOption, 65)); !errors.Is(err, errMCPFormInvalid) {
		t.Fatal("unbounded options accepted")
	}
}

type mcpGatedResponse struct {
	io.WriteCloser
	writes    atomic.Int64
	entered   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (output *mcpGatedResponse) Write(raw []byte) (int, error) {
	if output.writes.Add(1) == 3 {
		close(output.entered)
		select {
		case <-output.release:
		case <-output.closed:
			return 0, io.ErrClosedPipe
		}
	}
	return output.WriteCloser.Write(raw)
}

func (output *mcpGatedResponse) Close() error {
	output.closeOnce.Do(func() { close(output.closed) })
	return output.WriteCloser.Close()
}

func TestMCPStdioFinalResponseHasOnlyShortOutputGrace(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint("blocked=", blocked), func(t *testing.T) {
			errorsSeen := make(chan error, 1)
			f := newMCPStdioFixture(t, mcpTestFormHandler(errorsSeen))
			f.transport.formTimeout = 200 * time.Millisecond
			gate := &mcpGatedResponse{WriteCloser: f.transport.output.(io.WriteCloser), entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
			f.transport.output = gate
			f.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
			f.request("a", "tools/call")
			f.answer(f.next(), mcpTestAccept("synthetic-a-binding-v1"))
			select {
			case <-gate.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("tool result did not reach writer")
			}
			if blocked {
				if f.stopped() == nil {
					t.Fatal("unread final response did not close transport")
				}
				select {
				case <-f.transport.writerDone:
				case <-time.After(time.Second):
					t.Fatal("final response writer leaked")
				}
			} else {
				// The selection is already accepted. Output can finish shortly after
				// its old form deadline without extending any business permission.
				time.Sleep(250 * time.Millisecond)
				close(gate.release)
				if string(f.next()["id"]) != `"a"` {
					t.Fatal("accepted selection result was lost at the old form deadline")
				}
				f.request("barrier", "ping")
				if string(f.next()["id"]) != `"barrier"` {
					t.Fatal("response grace broke the connection")
				}
			}
			if err := <-errorsSeen; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPStdioInheritedPipeChild(t *testing.T) {
	stop := os.Getenv("CICADA_SYNTHETIC_STDIO_CHILD")
	if stop == "" {
		return
	}
	transport := newMCPStdioTransport(os.Stdin, os.Stdout)
	transport.output = &mcpInheritedOutput{transport.output.(io.WriteCloser)}
	if stop == "timeout" {
		transport.formTimeout = 100 * time.Millisecond
	}
	transport.negotiate(json.RawMessage(`{"capabilities":{"elicitation":{"form":{}}}}`))
	choices := make([]mcpPeerFormOption, 64)
	for i := range choices {
		choices[i] = mcpPeerFormOption{ID: fmt.Sprintf("synthetic-%02d", i), Label: strings.Repeat("x", 2048)}
	}
	var selected string
	var formErr error
	_ = transport.serve(func(request mcpRequest) (mcpResponse, bool) {
		selected, formErr = transport.elicitPeer("Select", choices)
		return mcpResponse{JSONRPC: "2.0", Result: map[string]any{}}, true
	})
	want := errMCPFormCancelled
	if stop == "timeout" {
		want = errMCPFormTimeout
	}
	if selected != "" || !errors.Is(formErr, want) {
		t.Fatalf("unexpected synthetic form outcome: %v", formErr)
	}
	select {
	case <-transport.writerDone:
	case <-time.After(time.Second):
		t.Fatal("inherited stdout writer did not exit")
	}
}

type mcpInheritedOutput struct{ io.WriteCloser }

func (output *mcpInheritedOutput) Write(raw []byte) (int, error) {
	// stderr is only a test barrier, never an MCP frame or identity source.
	fmt.Fprintln(os.Stderr, "synthetic-form-start")
	return output.WriteCloser.Write(raw)
}

func TestMCPStdioInheritedBlockingStdoutReclaimsWriter(t *testing.T) {
	for _, stop := range []string{"cancel", "timeout", "eof"} {
		t.Run(stop, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			input, hostInput, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			hostOutput, output, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestMCPStdioInheritedPipeChild$", "-test.timeout=5s")
			command.Env = append(os.Environ(), "CICADA_SYNTHETIC_STDIO_CHILD="+stop)
			command.Stdin, command.Stdout = input, output
			stderr, err := command.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			_ = input.Close()
			_ = output.Close()
			t.Cleanup(func() {
				_ = hostInput.Close()
				_ = hostOutput.Close()
				if command.ProcessState == nil {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			})
			encoder := json.NewEncoder(hostInput)
			if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": "original", "method": "tools/call"}); err != nil {
				t.Fatal(err)
			}
			barrier := make(chan string, 1)
			go func() { reader := bufio.NewReader(stderr); line, _ := reader.ReadString('\n'); barrier <- line }()
			select {
			case line := <-barrier:
				if line != "synthetic-form-start\n" {
					t.Fatalf("unexpected child barrier %q", line)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("child did not enter form")
			}
			if stop == "cancel" {
				if err = encoder.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "original"}}); err != nil {
					t.Fatal(err)
				}
			}
			if stop == "eof" {
				_ = hostInput.Close()
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			select {
			case err = <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Fatal("inherited blocking stdout prevented shutdown")
			}
		})
	}
}
