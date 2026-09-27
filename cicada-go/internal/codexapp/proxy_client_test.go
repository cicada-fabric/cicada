package codexapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestDialProxyWebSocketUpgradesAndUsesTextFrames(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	listener := &singleConnListener{conn: serverSide, done: make(chan struct{})}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept WebSocket upgrade: %v", err)
			return
		}
		defer conn.CloseNow()
		messageType, data, err := conn.Read(r.Context())
		if err != nil {
			t.Errorf("read WebSocket request: %v", err)
			return
		}
		if messageType != websocket.MessageText || string(data) != `{"id":1,"method":"initialize","params":{}}` {
			t.Errorf("unexpected WebSocket request type=%v data=%s", messageType, data)
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageText,
			[]byte(`{"id":1,"result":{"userAgent":"codex-cli/0.157.0"}}`)); err != nil {
			t.Errorf("write WebSocket response: %v", err)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = clientSide.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, transport, err := dialProxyWebSocket(ctx, clientSide, clientSide)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	defer transport.CloseIdleConnections()
	if err := conn.Write(ctx, websocket.MessageText,
		[]byte(`{"id":1,"method":"initialize","params":{}}`)); err != nil {
		t.Fatal(err)
	}
	typ, response, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageText || !strings.Contains(string(response), `"userAgent":"codex-cli/0.157.0"`) {
		t.Fatalf("unexpected WebSocket response type=%v data=%s", typ, response)
	}
}

func TestProxyClientReadsExactThreadStates(t *testing.T) {
	tests := []struct {
		name   string
		status map[string]any
		want   ThreadStatus
	}{
		{name: "cold", status: map[string]any{"type": "notLoaded"}, want: ThreadStatus{Type: "notLoaded"}},
		{name: "idle", status: map[string]any{"type": "idle"}, want: ThreadStatus{Type: "idle"}},
		{name: "system error", status: map[string]any{"type": "systemError"}, want: ThreadStatus{Type: "systemError"}},
		{name: "busy", status: map[string]any{"type": "active", "activeFlags": []any{}}, want: ThreadStatus{Type: "active"}},
		{name: "approval waiting", status: map[string]any{"type": "active", "activeFlags": []any{"waitingOnApproval"}}, want: ThreadStatus{Type: "active", ActiveFlags: []string{"waitingOnApproval"}}},
		{name: "user input waiting", status: map[string]any{"type": "active", "activeFlags": []any{"waitingOnUserInput"}}, want: ThreadStatus{Type: "active", ActiveFlags: []string{"waitingOnUserInput"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testProxyClient(t, func(method string, params map[string]any) map[string]any {
				switch method {
				case "initialize":
					return map[string]any{"userAgent": "codex-cli/0.157.0"}
				case "thread/read":
					if params["threadId"] != "native-thread-exact" || params["includeTurns"] != false {
						t.Errorf("thread/read params = %#v", params)
					}
					return map[string]any{"thread": map[string]any{"id": "native-thread-exact", "status": test.status}}
				default:
					t.Errorf("unexpected method %q", method)
					return map[string]any{}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.InitializeExperimental(ctx, "test", "protocol test", "0"); err != nil {
				t.Fatal(err)
			}
			got, err := client.ReadThread(ctx, "native-thread-exact")
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != "native-thread-exact" || got.Status.Type != test.want.Type ||
				strings.Join(got.Status.ActiveFlags, ",") != strings.Join(test.want.ActiveFlags, ",") {
				t.Fatalf("ReadThread() = %#v, want status %#v", got, test.want)
			}
		})
	}
}

func TestProxyClientRejectsAmbiguousThreadAndUnknownState(t *testing.T) {
	tests := []struct {
		name   string
		thread map[string]any
	}{
		{name: "wrong ID", thread: map[string]any{"id": "another-thread", "status": map[string]any{"type": "notLoaded"}}},
		{name: "unknown status", thread: map[string]any{"id": "native-thread-exact", "status": map[string]any{"type": "futureState"}}},
		{name: "unknown active flag", thread: map[string]any{"id": "native-thread-exact", "status": map[string]any{"type": "active", "activeFlags": []any{"futureWait"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testProxyClient(t, func(method string, _ map[string]any) map[string]any {
				if method == "initialize" {
					return map[string]any{"userAgent": "codex-cli/0.157.0"}
				}
				return map[string]any{"thread": test.thread}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.InitializeExperimental(ctx, "test", "protocol test", "0"); err != nil {
				t.Fatal(err)
			}
			if _, err := client.ReadThread(ctx, "native-thread-exact"); err == nil {
				t.Fatal("ReadThread accepted an ambiguous or unknown state")
			}
		})
	}
}

func TestProxyClientListsQueueWithoutDeduplicatingWitnesses(t *testing.T) {
	client := testProxyClient(t, func(method string, params map[string]any) map[string]any {
		switch method {
		case "initialize":
			return map[string]any{"userAgent": "codex-cli/0.157.0"}
		case "thread/queue/list":
			if params["threadId"] != "native-thread-exact" {
				t.Errorf("queue/list threadId = %#v", params["threadId"])
			}
			return map[string]any{"nextCursor": nil, "data": []any{
				map[string]any{"id": "queued-a", "clientUserMessageId": "submission-1", "input": []any{map[string]any{"type": "text", "text": "synthetic body"}}},
				map[string]any{"id": "queued-b", "clientUserMessageId": "submission-1", "input": []any{map[string]any{"type": "text", "text": "synthetic body"}}},
			}}
		default:
			t.Errorf("unexpected method %q", method)
			return map[string]any{}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.InitializeExperimental(ctx, "test", "protocol test", "0"); err != nil {
		t.Fatal(err)
	}
	queued, err := client.ListQueue(ctx, "native-thread-exact")
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 2 || queued[0].ClientUserMessageID != queued[1].ClientUserMessageID ||
		queued[0].ID == queued[1].ID || !strings.Contains(string(queued[0].Input), "synthetic body") {
		t.Fatalf("queue/list entries were altered: count=%d ids=%q,%q", len(queued), queued[0].ID, queued[1].ID)
	}
}

func TestProxyClientListQueuePaginatesAndFailsOnCursorLoop(t *testing.T) {
	t.Run("all pages", func(t *testing.T) {
		page := 0
		client := testProxyClient(t, func(method string, params map[string]any) map[string]any {
			switch method {
			case "initialize":
				return map[string]any{"userAgent": "codex-cli/0.157.0"}
			case "thread/queue/list":
				page++
				limit, ok := numberAsInt64(params["limit"])
				if !ok || limit != queuePageLimit {
					t.Errorf("queue/list limit = %#v", params["limit"])
				}
				if page == 1 {
					if _, exists := params["cursor"]; exists {
						t.Errorf("first page included cursor: %#v", params)
					}
					return map[string]any{"nextCursor": "next", "data": []any{syntheticQueueEntry("queued-a")}}
				}
				if params["cursor"] != "next" {
					t.Errorf("second page cursor = %#v", params["cursor"])
				}
				return map[string]any{"nextCursor": nil, "data": []any{syntheticQueueEntry("queued-b")}}
			default:
				t.Errorf("unexpected method %q", method)
				return map[string]any{}
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := client.InitializeExperimental(ctx, "test", "protocol test", "0"); err != nil {
			t.Fatal(err)
		}
		queued, err := client.ListQueue(ctx, "native-thread-exact")
		if err != nil {
			t.Fatal(err)
		}
		if page != 2 || len(queued) != 2 {
			t.Fatalf("ListQueue pages=%d items=%d, want 2 pages and 2 items", page, len(queued))
		}
	})

	t.Run("repeated cursor", func(t *testing.T) {
		page := 0
		client := testProxyClient(t, func(method string, _ map[string]any) map[string]any {
			switch method {
			case "initialize":
				return map[string]any{"userAgent": "codex-cli/0.157.0"}
			case "thread/queue/list":
				page++
				return map[string]any{"nextCursor": "stuck", "data": []any{}}
			default:
				t.Errorf("unexpected method %q", method)
				return map[string]any{}
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := client.InitializeExperimental(ctx, "test", "protocol test", "0"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ListQueue(ctx, "native-thread-exact"); err == nil || page != 2 {
			t.Fatalf("ListQueue repeated cursor accepted: err=%v pages=%d", err, page)
		}
	})
}

func TestProxyClientRejectsUnsupportedInitializationVersion(t *testing.T) {
	client := testProxyClient(t, func(string, map[string]any) map[string]any {
		return map[string]any{"userAgent": "codex-cli/0.156.1-beta"}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.InitializeExperimental(ctx, "test", "protocol test", "0"); err == nil {
		t.Fatal("experimental protocol accepted a prerelease version")
	}
}

func TestProxyClientRequestContextUnblocksPendingRead(t *testing.T) {
	requestReceived := make(chan struct{})
	releaseServer := make(chan struct{})
	var releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
		close(requestReceived)
		<-releaseServer
	}))
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseServer) })
		server.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &ProxyClient{conn: conn, nextID: 1}
	t.Cleanup(client.Close)

	readCtx, cancelRead := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelRead()
	_, err = client.ReadThread(readCtx, "native-thread-exact")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadThread error = %v, want deadline exceeded", err)
	}
	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the bounded read request")
	}
}

func TestProxyClientRealDaemonReadSmoke(t *testing.T) {
	if os.Getenv("CICADA_CODEX_PROXY_SMOKE") != "1" {
		t.Skip("set CICADA_CODEX_PROXY_SMOKE=1 with an isolated daemon and pre-seeded cold Thread")
	}
	codeHome := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if codeHome == "" || samePath(codeHome, filepath.Join(os.Getenv("HOME"), ".codex")) {
		t.Fatal("real Codex proxy smoke requires an isolated CODEX_HOME")
	}
	threadID := strings.TrimSpace(os.Getenv("CICADA_CODEX_SMOKE_THREAD_ID"))
	clientMessageID := strings.TrimSpace(os.Getenv("CICADA_CODEX_SMOKE_CLIENT_MESSAGE_ID"))
	if threadID == "" || clientMessageID == "" {
		t.Fatal("real Codex proxy smoke requires exact pre-seeded Thread and queue identities")
	}
	binary := strings.TrimSpace(os.Getenv("CICADA_CODEX_BIN"))
	if binary == "" {
		binary = "codex"
	}
	env := []string{"CODEX_HOME=" + codeHome}
	if value := os.Getenv("HOME"); value != "" {
		env = append(env, "HOME="+value)
	}
	if value := os.Getenv("PATH"); value != "" {
		env = append(env, "PATH="+value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := StartRunningProxy(ctx, binary, ".", env, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err := client.InitializeExperimental(ctx, "cicada-protocol-smoke", "CICADA protocol smoke", "0"); err != nil {
		t.Fatal(err)
	}
	thread, err := client.ReadThread(ctx, threadID)
	if err != nil {
		t.Fatal(err)
	}
	if thread.ID != threadID || thread.Status.Type != "notLoaded" {
		t.Fatalf("real Codex Thread state was not the exact cold target: exact_id=%t status=%s", thread.ID == threadID, thread.Status.Type)
	}
	queued, err := client.ListQueue(ctx, threadID)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].ClientUserMessageID != clientMessageID {
		t.Fatalf("real Codex queue witness was not unique: item_count=%d unique_client_id=%t", len(queued), len(queued) == 1 && queued[0].ClientUserMessageID == clientMessageID)
	}
	t.Logf("initialize=true exact_thread_id=true thread_status=%s queue_items=%d unique_submission=true read_only=true",
		thread.Status.Type, len(queued))
}

func samePath(left, right string) bool {
	left, leftErr := filepath.Abs(left)
	right, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	if resolved, err := filepath.EvalSymlinks(left); err == nil {
		left = resolved
	}
	if resolved, err := filepath.EvalSymlinks(right); err == nil {
		right = resolved
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func testProxyClient(t *testing.T, response func(method string, params map[string]any) map[string]any) *ProxyClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			typ, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			message := decodeProxyMessage(data)
			if message == nil {
				return
			}
			method, _ := message["method"].(string)
			if message["id"] == nil {
				continue
			}
			params, _ := message["params"].(map[string]any)
			payload, marshalErr := json.Marshal(map[string]any{
				"id": message["id"], "result": response(method, params),
			})
			if marshalErr != nil || conn.Write(r.Context(), websocket.MessageText, payload) != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &ProxyClient{conn: conn, nextID: 1}
	t.Cleanup(client.Close)
	return client
}

func syntheticQueueEntry(id string) map[string]any {
	return map[string]any{
		"id": id, "clientUserMessageId": "submission-1",
		"input": []any{map[string]any{"type": "text", "text": "synthetic body"}},
	}
}

type singleConnListener struct {
	conn      net.Conn
	used      sync.Once
	done      chan struct{}
	closeOnce sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	first := false
	l.used.Do(func() { first = true })
	if first {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return testAddr("pipe-test") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }
