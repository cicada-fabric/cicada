package componentinstall

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func shellTestHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home ' $() `literal`")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	return home
}
func shellTestCommand(t *testing.T, f fixture, home string, args []string, out io.Writer) error {
	t.Helper()
	return commandWithHome(args, out, f.target, func() (string, error) { return home, nil })
}
func shellTestRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestShellIntegrationInstallRepeatRemoveAndPreserve(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	home := shellTestHome(t)
	rc := filepath.Join(home, ".bashrc")
	original := []byte("# SYNTHETIC user bytes without final newline")
	if err := os.WriteFile(rc, original, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rc, 0640); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	for range 2 {
		output.Reset()
		if err := shellTestCommand(t, f, home, f.installArgs("hub,node"), &output); err != nil {
			t.Fatal(err)
		}
	}
	var installed result
	if json.Unmarshal(output.Bytes(), &installed) != nil || installed.ShellIntegration == nil || installed.ShellIntegration.State != "installed" || installed.ServicesChanged {
		t.Fatal("incorrect shell install result")
	}
	entry := filepath.Join(home, ".cicada", "bin", "cicada")
	receipt := filepath.Join(home, ".cicada", shellReceiptName)
	before := shellTestRead(t, rc)
	if bytes.Count(before, []byte(shellBegin)) != 1 || !bytes.HasPrefix(before, original) {
		t.Fatal("managed block duplicated or user bytes lost")
	}
	if info, err := os.Stat(rc); err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("bashrc permissions changed", err)
	}
	if !bytes.Equal(shellTestRead(t, entry), shellLauncher(f.prefix)) {
		t.Fatal("stable launcher differs")
	}
	for _, mode := range []string{"unset", "empty", "existing"} {
		t.Run(mode, func(t *testing.T) {
			init := "unset PATH\n"
			if mode == "empty" {
				init = "PATH=\n"
			}
			if mode == "existing" {
				init = "PATH='/SYNTHETIC_EXTERNAL:/usr/bin:/bin'\n"
			}
			cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "set -u\n"+init+". \"$1\"\n. \"$1\"\nprintf '%s' \"$PATH\"", "synthetic-source", rc)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil || stderr.Len() != 0 {
				t.Fatal("Bash block emitted output or failed", err, stderr.String())
			}
			expected := filepath.Dir(entry)
			if mode == "existing" {
				expected = "/SYNTHETIC_EXTERNAL:/usr/bin:/bin:" + expected
			}
			if stdout.String() != expected {
				t.Fatal("PATH changed precedence, duplicated, or introduced current directory")
			}
		})
	}
	// Source itself, including a repeated source, produces no output at all.
	quiet := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", ". \"$1\"; . \"$1\"", "synthetic-source", rc)
	if out, err := quiet.CombinedOutput(); err != nil || len(out) != 0 {
		t.Fatal("shell startup was not quiet", err)
	}
	canary := filepath.Join(f.prefix, "state", "synthetic-original")
	mustWrite(t, canary, "SYNTHETIC_ORIGINAL_KEY_AND_PENDING_BYTES")
	if err := shellTestCommand(t, f, home, []string{"remove", "--prefix", f.prefix, "--components", "node"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shellTestRead(t, rc), before) || !bytes.Equal(shellTestRead(t, entry), shellLauncher(f.prefix)) {
		t.Fatal("removing one component removed the shared entry")
	}
	if err := shellTestCommand(t, f, home, []string{"remove", "--prefix", f.prefix, "--components", "hub"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shellTestRead(t, rc), original) {
		t.Fatal("last removal did not restore exact user bashrc bytes")
	}
	for _, path := range []string{entry, receipt} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("owned entry survived last removal")
		}
	}
	requireBytes(t, canary, "SYNTHETIC_ORIGINAL_KEY_AND_PENDING_BYTES")
	// The ordinary remove/install update path recreates the same stable command.
	if err := shellTestCommand(t, f, home, f.installArgs("node"), io.Discard); err != nil {
		t.Fatal("reinstall after removal failed", err)
	}
	if !bytes.Equal(shellTestRead(t, entry), shellLauncher(f.prefix)) {
		t.Fatal("update changed stable entry coordinates")
	}
}

func TestShellIntegrationPreflightConflictsLeaveComponentsUntouched(t *testing.T) {
	for _, kind := range []string{"bashrc symlink", "bashrc writable", "bashrc hardlink", "unknown block", "external entry", "bin symlink", "home colon"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, platform{"linux", "amd64"}, "node")
			home := shellTestHome(t)
			rc := filepath.Join(home, ".bashrc")
			outside := filepath.Join(t.TempDir(), "original")
			if err := os.WriteFile(outside, []byte("USER_ORIGINAL"), 0644); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "bashrc symlink":
				if err := os.Symlink(outside, rc); err != nil {
					t.Fatal(err)
				}
			case "bashrc writable":
				if err := os.WriteFile(rc, []byte("USER_ORIGINAL"), 0664); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(rc, 0664); err != nil {
					t.Fatal(err)
				}
			case "bashrc hardlink":
				if err := os.Link(outside, rc); err != nil {
					t.Fatal(err)
				}
			case "unknown block":
				if err := os.WriteFile(rc, []byte(shellBegin+"\nUSER_ORIGINAL\n"+shellEnd+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "external entry":
				mustWrite(t, filepath.Join(home, ".cicada", "bin", "cicada"), "USER_EXTERNAL_COMMAND")
			case "bin symlink":
				if err := os.Mkdir(filepath.Join(home, ".cicada"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), filepath.Join(home, ".cicada", "bin")); err != nil {
					t.Fatal(err)
				}
			case "home colon":
				next := home + ":colon"
				if err := os.Rename(home, next); err != nil {
					t.Fatal(err)
				}
				home = next
			}
			err := shellTestCommand(t, f, home, f.installArgs("node"), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "components unchanged") {
				t.Fatal("shell conflict not refused before component writes", err)
			}
			if _, err := os.Lstat(filepath.Join(f.prefix, "components")); !os.IsNotExist(err) {
				t.Fatal("preflight conflict installed component files")
			}
			requireBytes(t, outside, "USER_ORIGINAL")
		})
	}
}

func TestShellIntegrationOffListAndOtherPrefix(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	home := shellTestHome(t)
	if err := shellTestCommand(t, f, home, f.installArgs("node"), io.Discard); err != nil {
		t.Fatal(err)
	}
	before := shellTestRead(t, filepath.Join(home, ".bashrc"))
	entry := shellTestRead(t, filepath.Join(home, ".cicada", "bin", "cicada"))
	other := f
	other.prefix = filepath.Join(t.TempDir(), "other prefix : ' $() `literal`")
	if err := shellTestCommand(t, other, home, other.installArgs("node"), io.Discard); err == nil {
		t.Fatal("second prefix redirected stable entry")
	}
	if _, err := os.Stat(filepath.Join(other.prefix, "components")); !os.IsNotExist(err) {
		t.Fatal("prefix conflict installed files")
	}
	neverHome := func() (string, error) { t.Fatal("file-only/list consulted shell home"); return "", nil }
	args := append(other.installArgs("node"), "--shell-integration=off")
	if err := commandWithHome(args, io.Discard, other.target, neverHome); err != nil {
		t.Fatal(err)
	}
	if err := commandWithHome([]string{"list", "--prefix", f.prefix}, io.Discard, f.target, neverHome); err != nil {
		t.Fatal(err)
	}
	if err := shellTestCommand(t, other, home, []string{"remove", "--prefix", other.prefix, "--components", "node"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, shellTestRead(t, filepath.Join(home, ".bashrc"))) || !bytes.Equal(entry, shellTestRead(t, filepath.Join(home, ".cicada", "bin", "cicada"))) {
		t.Fatal("other prefix changed active entry")
	}
}

func TestShellIntegrationPartialPublicationRecoversWithoutClobber(t *testing.T) {
	home := shellTestHome(t)
	prefix := filepath.Join(t.TempDir(), "prefix")
	rc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(rc, []byte("# user\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := prepareShellIntegration(home, prefix, "install")
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("# user\n# concurrent user edit\n")
	if err := os.WriteFile(rc, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.apply(true); err == nil {
		t.Fatal("concurrent bashrc edit clobbered")
	}
	p.close()
	if !bytes.Equal(shellTestRead(t, rc), changed) {
		t.Fatal("CAS refusal lost user edit")
	}
	retry, err := prepareShellIntegration(home, prefix, "install")
	if err != nil {
		t.Fatal("original partial receipt could not recover", err)
	}
	if err = retry.apply(true); err != nil {
		retry.close()
		t.Fatal(err)
	}
	retry.close()
	if bytes.Count(shellTestRead(t, rc), []byte(shellBegin)) != 1 {
		t.Fatal("recovery duplicated block")
	}
	cleanup, err := prepareShellIntegration(home, prefix, "remove")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup.close()
	if err = cleanup.apply(false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shellTestRead(t, rc), changed) {
		t.Fatal("cleanup changed independent user edit")
	}
}

func TestShellLauncherRoutesLiteralArgumentsAndNoShellInjection(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "prefix : ' $() `touch SHOULD_NOT_EXIST`")
	for _, role := range []string{"hub", "node"} {
		dir := filepath.Join(prefix, "components", role)
		mustWrite(t, filepath.Join(dir, manifestName), "SYNTHETIC_ROUTING_ONLY")
		mustWrite(t, filepath.Join(dir, "bin", "cicada"), "#!/bin/sh\nprintf '%s\\n' "+codexShellQuote(role)+" \"$@\"\n")
		if err := os.Chmod(filepath.Join(dir, "bin", "cicada"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	launcher := filepath.Join(t.TempDir(), "cicada")
	if err := os.WriteFile(launcher, shellLauncher(prefix), 0755); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	args := []string{"on", "argument with spaces", "' $() `touch SHOULD_NOT_EXIST`"}
	for _, role := range []string{"node", "hub"} {
		cmd := exec.Command(launcher, args...)
		cmd.Dir = workspace
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != role+"\n"+strings.Join(args, "\n")+"\n" {
			t.Fatal("launcher changed routing or argv", err, string(out))
		}
		if role == "node" {
			if err = os.Remove(filepath.Join(prefix, "components", "node", manifestName)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(workspace, "SHOULD_NOT_EXIST")); !os.IsNotExist(err) {
		t.Fatal("quoted shell data executed a command")
	}
}
