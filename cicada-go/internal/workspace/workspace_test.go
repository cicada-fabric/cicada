package workspace

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWorkspaceSourceValidation(t *testing.T) {
	valid, err := SourceFromResources(map[string]any{"workspace_source": map[string]any{
		"kind": "git", "url": "https://github.com/cicada-fabric/cicada.git", "revision": "main",
	}})
	if err != nil || valid.Revision != "main" {
		t.Fatalf("valid source=%#v err=%v", valid, err)
	}
	invalid := []map[string]any{
		{"workspace_source": "url"},
		{"workspace_source": map[string]any{"url": "http://github.com/org/repo"}},
		{"workspace_source": map[string]any{"url": "https://user:secret@github.com/org/repo"}},
		{"workspace_source": map[string]any{"url": "https://github.com/org/repo?token=secret"}},
		{"workspace_source": map[string]any{"url": "https://github.com/org/repo", "revision": "--upload-pack=bad"}},
	}
	for _, resources := range invalid {
		if _, err := SourceFromResources(resources); err == nil {
			t.Fatalf("unsafe workspace source was accepted: %#v", resources)
		}
	}
}

func TestPrepareClonesOnceAndResumesPinnedWorkspace(t *testing.T) {
	restore := stubPublicDNS(t)
	defer restore()
	git, logPath := fakeGit(t)
	t.Setenv("CICADA_GIT_BIN", git)
	t.Setenv("API_KEY", "must-not-reach-git")
	path := filepath.Join(t.TempDir(), "workspace")
	resources := map[string]any{"workspace_source": map[string]any{
		"url": "https://github.com/cicada-fabric/cicada.git", "revision": "main",
	}}
	first, err := Prepare(context.Background(), path, resources, os.Environ())
	if err != nil || !first.Created || first.Revision != "0123456789abcdef" {
		t.Fatalf("first prepare=%#v err=%v", first, err)
	}
	second, err := Prepare(context.Background(), path, resources, os.Environ())
	if err != nil || second.Created || second.Revision != first.Revision {
		t.Fatalf("resume prepare=%#v err=%v", second, err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(logData), " init ") != 1 {
		t.Fatalf("workspace was cloned more than once:\n%s", logData)
	}
	if _, err := os.Stat(filepath.Join(path, markerName)); err != nil {
		t.Fatalf("provenance marker missing: %v", err)
	}
}

func TestPrepareRejectsPrivateResolutionAndNonEmptyWorkspace(t *testing.T) {
	original := lookupIP
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	defer func() { lookupIP = original }()
	resources := map[string]any{"workspace_source": map[string]any{"url": "https://example.com/org/repo"}}
	if _, err := Prepare(context.Background(), filepath.Join(t.TempDir(), "workspace"), resources, os.Environ()); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("private Git resolution was accepted: %v", err)
	}
	restore := stubPublicDNS(t)
	defer restore()
	path := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "existing"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), path, resources, os.Environ()); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("non-empty workspace was overwritten: %v", err)
	}
}

func TestResolveWithinRejectsLexicalAndSymlinkEscapes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveWithin(root, outside); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("lexical workspace escape was accepted: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveWithin(root, link); err == nil || !strings.Contains(err.Error(), "resolves outside") {
		t.Fatalf("symlink workspace escape was accepted: %v", err)
	}
}

func stubPublicDNS(t *testing.T) func() {
	t.Helper()
	original := lookupIP
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	return func() { lookupIP = original }
}

func fakeGit(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	path, logPath := filepath.Join(root, "git"), filepath.Join(root, "git.log")
	script := `#!/bin/sh
set -eu
test -z "${API_KEY:-}"
printf ' %s \n' "$*" >> "$CICADA_TEST_GIT_LOG"
repository=''
previous=''
for argument in "$@"; do
  if [ "$previous" = '-C' ]; then repository="$argument"; fi
  previous="$argument"
done
case " $* " in
  *' init --quiet '*)
    for argument in "$@"; do target="$argument"; done
    mkdir -p "$target/.git"
    ;;
  *' checkout --quiet '*) printf 'ready\n' > "$repository/README.md" ;;
  *' rev-parse HEAD '*) printf '0123456789abcdef\n' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_TEST_GIT_LOG", logPath)
	return path, logPath
}

func TestGitTimeoutKillsHelperProcessGroup(t *testing.T) {
	root := t.TempDir()
	git, pidFile := filepath.Join(root, "git"), filepath.Join(root, "child.pid")
	script := `#!/bin/sh
sleep 30 &
printf '%s' "$!" > "$CICADA_TEST_CHILD_PID"
wait
`
	if err := os.WriteFile(git, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_GIT_BIN", git)
	t.Setenv("CICADA_TEST_CHILD_PID", pidFile)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := gitOutput(ctx, os.Environ(), "fetch"); err == nil {
		t.Fatal("timed-out Git command succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("Git process group ignored cancellation for %s", time.Since(started))
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if processZombie(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Git helper process %d survived cancellation", pid)
}

func processZombie(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	return len(fields) > 2 && fields[2] == "Z"
}
