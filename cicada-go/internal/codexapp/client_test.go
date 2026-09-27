package codexapp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
