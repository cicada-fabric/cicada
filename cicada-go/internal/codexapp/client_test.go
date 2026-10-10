package codexapp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCloseAndWaitPreservesProcessWaiterStopError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires /bin/sh and process groups")
	}

	root := t.TempDir()
	script := filepath.Join(root, "app-server")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("joined stop error survives exit", func(t *testing.T) {
		stopUnverified := errors.New("STOP_UNVERIFIED")
		waiter := func(command *exec.Cmd) error {
			waitErr := command.Wait()
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				return errors.Join(waitErr, errors.New("expected shell process to be terminated"))
			}
			return errors.Join(waitErr, stopUnverified)
		}
		client, err := StartWithLifecycle(context.Background(), "/bin/sh", root, nil,
			nil, nil, nil, waiter)
		if err != nil {
			t.Fatal(err)
		}

		firstErr := client.CloseAndWait()
		if !errors.Is(firstErr, stopUnverified) {
			t.Fatalf("CloseAndWait() error = %v, want STOP_UNVERIFIED", firstErr)
		}
		if secondErr := client.CloseAndWait(); !errors.Is(secondErr, stopUnverified) {
			t.Fatalf("repeated CloseAndWait() error = %v, want STOP_UNVERIFIED", secondErr)
		}
	})

	t.Run("default nonzero exit is still a completed wait", func(t *testing.T) {
		client, err := StartWithLifecycle(context.Background(), "/bin/sh", root, nil,
			nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CloseAndWait(); err != nil {
			t.Fatalf("CloseAndWait() treated a pure signalled exit as an unverified wait: %v", err)
		}
		if err := client.CloseAndWait(); err != nil {
			t.Fatalf("repeated CloseAndWait() = %v, want nil", err)
		}
	})
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "0.156.0", want: false},
		{version: "codex-cli 0.156.1", want: true},
		{version: "codex-cli 0.156.1-beta", want: false},
		{version: "0.157.0", want: true},
		{version: "unknown", want: false},
		{version: "0.156", want: false},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			if got := versionAtLeast(test.version, minimumQueueWakeVersion); got != test.want {
				t.Fatalf("versionAtLeast(%q) = %v, want %v", test.version, got, test.want)
			}
		})
	}
}

func TestStartRunningProxyFailsClosedWithoutCompatibleDaemon(t *testing.T) {
	tests := []struct {
		name string
		info string
	}{
		{name: "stopped", info: `{"status":"stopped","socketPath":"/tmp/stale.sock","appServerVersion":"0.157.0"}`},
		{name: "old protocol", info: `{"status":"running","socketPath":"/tmp/old.sock","appServerVersion":"0.156.0"}`},
		{name: "prerelease protocol", info: `{"status":"running","socketPath":"/tmp/beta.sock","appServerVersion":"0.156.1-beta"}`},
		{name: "unknown version", info: `{"status":"running","socketPath":"/tmp/unknown.sock","appServerVersion":"development"}`},
		{name: "missing socket", info: `{"status":"running","appServerVersion":"0.157.0"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			binary := filepath.Join(root, "codex-fake")
			proxyMarker := filepath.Join(root, "proxy-started")
			script := `#!/bin/sh
if [ "$2" = "daemon" ]; then
  printf '%s\n' "$FAKE_DAEMON_INFO"
  exit 0
fi
if [ "$2" = "proxy" ]; then
  : > "$FAKE_PROXY_MARKER"
fi
exit 9
`
			if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			env := append(os.Environ(), "FAKE_DAEMON_INFO="+test.info, "FAKE_PROXY_MARKER="+proxyMarker)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, err := StartRunningProxy(ctx, binary, root, env, nil)
			if client != nil {
				client.Close()
			}
			if err == nil {
				t.Fatal("StartRunningProxy succeeded without a supported running daemon")
			}
			if _, err := os.Stat(proxyMarker); !os.IsNotExist(err) {
				t.Fatalf("proxy started despite incompatible daemon: stat error=%v", err)
			}
		})
	}
}

func TestInitializeExperimentalRejectsUnsupportedServerVersion(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "codex-fake")
	script := `#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"id":1,"result":{"userAgent":"codex-cli/0.155.9"}}' ;;
  esac
done
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Start(ctx, binary, root, os.Environ(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.InitializeExperimental(ctx, "cicada-test", "CICADA test", "test"); err == nil {
		t.Fatal("InitializeExperimental accepted an unsupported server version")
	}
}

// These synthetic stdio transcripts exercise the official response/notification
// tuple without a model, network, or native-runtime acceptance claim.
func TestWaitTurnRequiresConfirmedOriginalTuple(t *testing.T) {
	terminal := `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","items":[{"type":"agentMessage","text":"ORIGINAL_DONE"}],"status":"completed"}}}`
	for _, tc := range []struct {
		name, event string
		status      string
		wantErr     bool
	}{
		{"foreign-thread", `{"method":"turn/completed","params":{"threadId":"thread-b","turn":{"id":"turn-a","items":[],"status":"completed"}}}`, "completed", false},
		{"foreign-turn", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-b","items":[],"status":"failed"}}}`, "completed", false},
		{"missing-thread", `{"method":"turn/completed","params":{"turn":{"id":"turn-a","items":[],"status":"completed"}}}`, "completed", false},
		{"missing-turn", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"items":[],"status":"completed"}}}`, "completed", false},
		{"missing-status", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","items":[]}}}`, "completed", false},
		{"missing-items", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","status":"completed"}}}`, "completed", false},
		{"nonterminal-status", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","items":[],"status":"inProgress"}}}`, "completed", false},
		{"idle-is-not-completion", `{"method":"thread/status/changed","params":{"threadId":"thread-a","status":{"type":"idle"}}}`, "completed", false},
		{"failed-original", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","items":[],"status":"failed","error":{"message":"synthetic failure"}}}}`, "failed", false},
		{"malformed-only-eof", `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","items":[]}}}`, "failed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := `{"id":1,"result":{"thread":{"id":"thread-a"}}}` + "\n" + `{"id":2,"result":{"turn":{"id":"turn-a","items":[],"status":"inProgress"}}}` + "\n" + tc.event + "\n"
			if tc.name != "malformed-only-eof" {
				wire += terminal + "\n"
			}
			c := &Client{stdin: discardWriteCloser{}, scanner: bufio.NewScanner(strings.NewReader(wire)), nextID: 1}
			ctx := context.Background()
			if _, err := c.Request(ctx, "thread/start", map[string]any{}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Request(ctx, "turn/start", map[string]any{"threadId": "thread-a"}); err != nil {
				t.Fatal(err)
			}
			summary, status, err := c.WaitTurn(ctx)
			if (err != nil) != tc.wantErr || status != tc.status {
				t.Fatalf("status=%q err=%v", status, err)
			}
			if status == "completed" && summary != "ORIGINAL_DONE" {
				t.Fatalf("wrong-turn/malformed event completed original turn: summary=%q", summary)
			}
		})
	}
}

type discardWriteCloser struct{}

func (discardWriteCloser) Write(p []byte) (int, error) { return io.Discard.Write(p) }
func (discardWriteCloser) Close() error                { return nil }

func TestWaitTurnRejectsUnconfirmedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		thread         string
	}{
		{"missing-turn-id", `{"id":2,"result":{"turn":{"items":[],"status":"inProgress"}}}`, "thread-a"},
		{"different-thread-parameter", `{"id":2,"result":{"turn":{"id":"turn-a","items":[],"status":"inProgress"}}}`, "thread-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{stdin: discardWriteCloser{}, scanner: bufio.NewScanner(strings.NewReader(`{"id":1,"result":{"thread":{"id":"thread-a"}}}` + "\n" + tc.response + "\n" + `{"method":"turn/completed","params":{"threadId":"thread-a","turn":{"id":"turn-a","items":[],"status":"completed"}}}` + "\n")), nextID: 1}
			_, err := c.Request(context.Background(), "thread/start", map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Request(context.Background(), "turn/start", map[string]any{"threadId": tc.thread})
			if err == nil {
				_, _, err = c.WaitTurn(context.Background())
			}
			if err == nil {
				t.Fatal("unconfirmed tuple allowed completion")
			}
		})
	}
}

func TestStartFailurePreservesPartialProcessStopEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires /bin/sh and process groups")
	}
	for _, tc := range []struct {
		name                 string
		started, stopFailure bool
	}{
		{"before-process", false, false}, {"partial-start-confirmed-stop", true, false}, {"partial-start-unconfirmed-stop", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "app-server")
			if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0600); err != nil {
				t.Fatal(err)
			}
			startFailure := errors.New("synthetic START_FAILED")
			stopFailure := errors.New("synthetic STOP_UNVERIFIED")
			var pid, waits int
			var startedCommand *exec.Cmd
			starter := func(cmd *exec.Cmd) error {
				if tc.started {
					if err := cmd.Start(); err != nil {
						return err
					}
					pid = cmd.Process.Pid
					startedCommand = cmd
				}
				return startFailure
			}
			var waiter ProcessWaiter = func(cmd *exec.Cmd) error {
				waits++
				err := cmd.Wait()
				if tc.stopFailure {
					return errors.Join(err, stopFailure)
				}
				return err
			}
			if !tc.stopFailure {
				waiter = nil
			}
			client, err := StartWithLifecycle(context.Background(), "/bin/sh", root, nil, nil, nil, starter, waiter)
			var evidence *StartError
			if client != nil || !errors.As(err, &evidence) || !errors.Is(err, startFailure) || evidence.Started != tc.started {
				t.Fatalf("partial-start evidence missing: client=%v err=%v", client, err)
			}
			if errors.Is(evidence.StopErr, stopFailure) != tc.stopFailure {
				t.Fatalf("stop proof=%v", evidence.StopErr)
			}
			if tc.started && (pid <= 0 || startedCommand.ProcessState == nil) {
				t.Fatal("actual process start/wait evidence missing")
			}
			if tc.stopFailure && waits != 1 {
				t.Fatal("custom stop waiter was not called exactly once")
			}
			if !tc.stopFailure && waits != 0 {
				t.Fatal("confirmed stop must use default Cmd.Wait")
			}
			if !tc.started && waits != 0 {
				t.Fatal("waiter called before process start")
			}
			if !tc.stopFailure && evidence.StopErr != nil {
				t.Fatalf("confirmed stop misclassified: %v", evidence.StopErr)
			}
		})
	}
}

func TestCloseAndWaitAcceptsObservedCanceledProcessExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires /bin/sh and process groups")
	}
	root := t.TempDir()
	script := filepath.Join(root, "app-server")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceled := make(chan struct{})
	var once sync.Once
	starter := func(cmd *exec.Cmd) error {
		cmd.Cancel = func() error { once.Do(func() { close(canceled) }); return nil }
		return cmd.Start()
	}
	client, err := StartWithLifecycle(ctx, "/bin/sh", root, nil, nil, nil, starter, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("CommandContext cancellation was not observed")
	}
	if err := client.CloseAndWait(); err != nil {
		t.Fatalf("actual zero-exit Wait/group stop misclassified: %v", err)
	}
	if client.process.ProcessState == nil || !client.process.ProcessState.Success() {
		t.Fatal("actual successful process exit was not observed")
	}
}

func TestCustomWaiterExitErrorPreservesStopFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires /bin/sh and process groups")
	}
	for _, partial := range []bool{false, true} {
		name := "CloseAndWait"
		if partial {
			name = "partial-start"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "app-server")
			if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var observed *exec.ExitError
			waiter := func(cmd *exec.Cmd) error {
				err := cmd.Wait()
				if !errors.As(err, &observed) {
					return errors.Join(err, errors.New("expected actual custom ExitError"))
				}
				return err
			}
			var starter ProcessStarter
			startFailure := errors.New("synthetic partial START_FAILED")
			if partial {
				starter = func(cmd *exec.Cmd) error {
					if err := cmd.Start(); err != nil {
						return err
					}
					return startFailure
				}
			}
			client, err := StartWithLifecycle(context.Background(), "/bin/sh", root, nil, nil, nil, starter, waiter)
			if partial {
				var evidence *StartError
				if client != nil || !errors.As(err, &evidence) || !evidence.Started || !errors.Is(err, startFailure) {
					t.Fatalf("start evidence=%v", err)
				}
				if observed == nil || !errors.Is(evidence.StopErr, observed) {
					t.Fatalf("custom ExitError was erased from StartError.StopErr: %v", evidence.StopErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				err = client.CloseAndWait()
				if observed == nil || !errors.Is(err, observed) {
					t.Fatalf("custom ExitError was erased from CloseAndWait: %v", err)
				}
				if !errors.Is(client.CloseAndWait(), observed) {
					t.Fatal("idempotent stop lost custom error")
				}
			}
		})
	}
}
