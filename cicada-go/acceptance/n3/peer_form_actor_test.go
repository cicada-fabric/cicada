package n3_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// This is a bounded adversarial MCP Host for the actual CLI, not a Node,
// native-context issuer, Hub authority or native-UI acceptance substitute.
// Production server requests are kept private; public evidence uses only
// counts, associations and hashes. The caller supplies the original isolated
// command/environment through the existing process fixture.
type peerFormHost struct {
	process *process
	input   io.WriteCloser
	writes  sync.Mutex
	frames  chan peerFormFrame
	stop    chan struct{}
	close   sync.Once
	saved   []peerFormFrame
}

type peerFormFrame struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
	valid  bool
}

func (f *peerFormFrame) clear() {
	clear(f.ID)
	clear(f.Params)
	clear(f.Result)
	clear(f.Error)
}

func startPeerFormHost(t *testing.T, command *exec.Cmd) *peerFormHost {
	t.Helper()
	input, output := must(command.StdinPipe()), must(command.StdoutPipe())
	h := &peerFormHost{input: input, frames: make(chan peerFormFrame, 64), stop: make(chan struct{})}
	h.process = startProcess(t, command)
	t.Cleanup(func() {
		h.close.Do(func() { close(h.stop) })
		h.input.Close()
		for i := range h.saved {
			h.saved[i].clear()
		}
	})
	go func() {
		defer close(h.frames)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), harnessPacketLimit)
		for scanner.Scan() {
			var frame peerFormFrame
			var wire struct {
				Version string `json:"jsonrpc"`
				peerFormFrame
			}
			raw := scanner.Bytes()
			// Unmarshal rejects trailing text. No stdout diagnostic is silently
			// discarded as if it were a protocol result.
			if json.Unmarshal(raw, &wire) == nil && wire.Version == "2.0" {
				frame = wire.peerFormFrame
				frame.valid = true
			}
			select {
			case h.frames <- frame:
			case <-h.stop:
				frame.clear()
				return
			}
			if !frame.valid {
				return
			}
		}
	}()
	return h
}

func (h *peerFormHost) write(t *testing.T, value any) {
	t.Helper()
	raw := must(json.Marshal(value))
	defer clear(raw)
	if len(raw) == 0 || len(raw) >= harnessPacketLimit {
		t.Fatal("owned MCP Host frame exceeds its bound")
	}
	h.writes.Lock()
	defer h.writes.Unlock()
	if _, err := h.input.Write(append(raw, '\n')); err != nil {
		t.Fatal("actual MCP Host stdin closed before its expected request/response")
	}
}

func (h *peerFormHost) call(t *testing.T, id int, method string, params any) {
	t.Helper()
	if id <= 0 || method == "" {
		t.Fatal("invalid owned MCP Host call selector")
	}
	h.write(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

func (h *peerFormHost) await(t *testing.T, matches func(peerFormFrame) bool) peerFormFrame {
	t.Helper()
	return h.awaitFor(t, 12*time.Second, matches)
}

func (h *peerFormHost) awaitFor(t *testing.T, timeout time.Duration, matches func(peerFormFrame) bool) peerFormFrame {
	t.Helper()
	// Normal operations stay short; the actual frozen 120-second expiry case
	// may request a bounded longer observation without altering product time.
	if timeout <= 0 || timeout > 135*time.Second {
		t.Fatal("unreviewed peer-form Host observation deadline")
	}
	for i := range h.saved {
		if matches(h.saved[i]) {
			result := h.saved[i]
			h.saved = append(h.saved[:i], h.saved[i+1:]...)
			return result
		}
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case frame, ok := <-h.frames:
			if !ok || !frame.valid {
				t.Fatal("actual MCP stdout ended or contained a nonprotocol frame")
			}
			if matches(frame) {
				return frame
			}
			if len(h.saved) >= 64 {
				frame.clear()
				t.Fatal("actual MCP exceeded the bounded outstanding Host observations")
			}
			h.saved = append(h.saved, frame)
		case <-deadline.C:
			t.Fatal("actual MCP did not produce the expected bounded Host event")
		}
	}
}

func (h *peerFormHost) reply(t *testing.T, id int) peerFormFrame {
	t.Helper()
	expected := must(json.Marshal(id))
	return h.await(t, func(frame peerFormFrame) bool {
		return frame.Method == "" && bytes.Equal(frame.ID, expected)
	})
}

func (h *peerFormHost) serverRequest(t *testing.T) peerFormFrame {
	t.Helper()
	return h.await(t, func(frame peerFormFrame) bool {
		return frame.Method == "elicitation/create" && len(frame.ID) != 0 && !bytes.Equal(frame.ID, []byte("null"))
	})
}

func (h *peerFormHost) respond(t *testing.T, request peerFormFrame, action string, content any) {
	t.Helper()
	if request.Method != "elicitation/create" || len(request.ID) == 0 {
		t.Fatal("owned Host response does not target an actual elicitation request")
	}
	result := map[string]any{"action": action}
	if content != nil {
		result["content"] = content
	}
	// RawMessage preserves the production server's exact correlation ID;
	// it is not an actor, ticket, Endpoint or authorization capability.
	h.write(t, map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
}

func initializePeerFormHost(t *testing.T, h *peerFormHost, capabilities map[string]any, clientName string) {
	t.Helper()
	h.call(t, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": capabilities,
		"clientInfo": map[string]any{"name": clientName, "version": "synthetic-acceptance"}})
	frame := h.reply(t, 1)
	defer frame.clear()
	if len(frame.Error) != 0 || len(frame.Result) == 0 {
		t.Fatal("actual MCP refused its explicit owned initialization")
	}
	h.write(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

func startProductPeerFormHost(t *testing.T, v *codexProductFixture, capabilities map[string]any) *peerFormHost {
	t.Helper()
	command := exec.Command(os.Getenv("CICADA_N3_CICADA_BINARY"), "mcp", "--codex-context")
	command.Env, command.Dir = v.environment, v.workspace
	log := must(os.OpenFile(filepath.Join(v.root, "private-peer-form-mcp.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	command.Stderr = log
	h := startPeerFormHost(t, command)
	initializePeerFormHost(t, h, capabilities, "synthetic-peer-form-security-Host")
	return h
}

// Require the new product entry to be present. An old CLI's unknown-tool
// refusal is never accepted as the new feature's context/capability denial.
func peerFormAdvertisedNonce(t *testing.T, h *peerFormHost, name string) string {
	t.Helper()
	h.call(t, 2, "tools/list", map[string]any{})
	frame := h.reply(t, 2)
	defer frame.clear()
	var listed struct {
		Tools []struct {
			Name   string `json:"name"`
			Schema struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if len(frame.Error) != 0 || json.Unmarshal(frame.Result, &listed) != nil {
		t.Fatal("actual peer-selection MCP did not return its tool schema")
	}
	for _, tool := range listed.Tools {
		if tool.Name != name {
			continue
		}
		var context struct {
			Properties struct {
				Nonce struct {
					Const string `json:"const"`
				} `json:"connection_nonce"`
			} `json:"properties"`
			Additional *bool `json:"additionalProperties"`
		}
		if !containsText(tool.Schema.Required, "_cicada_context") ||
			json.Unmarshal(tool.Schema.Properties["_cicada_context"], &context) != nil ||
			context.Additional == nil || *context.Additional || len(context.Properties.Nonce.Const) != 64 {
			t.Fatal("peer selection lacks its closed original native-context schema")
		}
		return context.Properties.Nonce.Const
	}
	t.Fatal("formal peer-selection product tool is absent; new acceptance cannot run")
	return ""
}

type peerFormChoices struct {
	Field   string
	Choices map[string]string
}

// Decode the schema actually produced by the executable; do not maintain a
// second business directory or invent its choice/Endpoint mapping in QA.
func decodePeerFormChoices(t *testing.T, request peerFormFrame) peerFormChoices {
	t.Helper()
	var params struct {
		Mode    string `json:"mode"`
		Message string `json:"message"`
		Schema  struct {
			Type       string `json:"type"`
			Properties map[string]struct {
				Type  string `json:"type"`
				OneOf []struct {
					ID    string `json:"const"`
					Label string `json:"title"`
				} `json:"oneOf"`
			} `json:"properties"`
			Required   []string `json:"required"`
			Additional *bool    `json:"additionalProperties"`
		} `json:"requestedSchema"`
	}
	if request.Method != "elicitation/create" || json.Unmarshal(request.Params, &params) != nil || params.Mode != "form" ||
		params.Message == "" || params.Schema.Type != "object" || params.Schema.Additional == nil || *params.Schema.Additional ||
		len(params.Schema.Properties) != 1 || len(params.Schema.Required) != 1 || params.Schema.Required[0] != "peer" {
		t.Fatal("actual peer form differs from the frozen closed standard form schema")
	}
	field, found := params.Schema.Properties["peer"]
	if !found || field.Type != "string" || len(field.OneOf) == 0 || len(field.OneOf) > 64 {
		t.Fatal("actual peer form options are absent or exceed their frozen bound")
	}
	result := peerFormChoices{Field: "peer", Choices: make(map[string]string, len(field.OneOf))}
	for _, choice := range field.OneOf {
		if choice.ID == "" || choice.Label == "" {
			t.Fatal("actual peer choice lacks its opaque value or projected label")
		}
		if _, duplicate := result.Choices[choice.ID]; duplicate {
			t.Fatal("actual form reused one opaque choice for different directory rows")
		}
		result.Choices[choice.ID] = choice.Label
	}
	return result
}
