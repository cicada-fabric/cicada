package codexapp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestStdioRequestHandlesServerRequestWithSameID(t *testing.T) {
	input := strings.NewReader("{\"id\":1,\"method\":\"synthetic/approval\",\"params\":{}}\n" +
		"{\"id\":1,\"result\":{\"accepted\":true}}\n")
	output := &testWriteCloser{}
	requests := 0
	client := &Client{stdin: output, scanner: bufio.NewScanner(input), nextID: 1,
		onRequest: func(id any, method string, params map[string]any) any {
			requests++
			if method != "synthetic/approval" {
				t.Errorf("unexpected server request %q", method)
			}
			return map[string]any{"decision": "deny"}
		}}
	result, err := client.Request(context.Background(), "synthetic/client", map[string]any{})
	if err != nil || result["accepted"] != true || requests != 1 {
		t.Fatalf("server request collision: result=%v requests=%d err=%v", result, requests, err)
	}
	if !strings.Contains(output.String(), "\"decision\":\"deny\"") {
		t.Fatal("server-initiated request received no JSON-RPC response")
	}
}

func TestProxyRequestRejectsServerRequestWithSameID(t *testing.T) {
	responseObserved := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_, request, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var call map[string]any
		if json.Unmarshal(request, &call) != nil {
			return
		}
		_ = conn.Write(r.Context(), websocket.MessageText,
			[]byte(`{"id":1,"method":"synthetic/approval","params":{}}`))
		_, response, err := conn.Read(r.Context())
		responseObserved <- err == nil && strings.Contains(string(response), "\"code\":-32601")
		_ = conn.Write(r.Context(), websocket.MessageText,
			[]byte(`{"id":1,"result":{"accepted":true}}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &ProxyClient{conn: conn, nextID: 1}
	defer client.Close()
	result, err := client.request(ctx, "synthetic/client", map[string]any{})
	if err != nil || result["accepted"] != true {
		t.Fatalf("server request collision: result=%v err=%v", result, err)
	}
	if !<-responseObserved {
		t.Fatal("proxy did not reject unsupported server request")
	}
}

type testWriteCloser struct{ strings.Builder }

func (*testWriteCloser) Close() error { return nil }
