//go:build linux

package componentinstall

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the public command's common production implementation against an
// explicit disposable shell home. Never redirect HOME or touch the operator's
// bashrc. The product artifact remains synthetic and is never executed.
func TestAcceptanceShellLifecycleAndQuotedPaths(t *testing.T) {
	for _, special := range []bool{false, true} {
		name := "plain"
		if special {
			name = "spaces-quotes-dollar-backtick-backslash"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, platform{"linux", "amd64"}, "node")
			root := filepath.Dir(f.binary)
			homeName, prefixName := "shell home", "selected prefix"
			if special {
				homeName += " ' \" $QA_LITERAL $(touch QA_INJECTION) `touch QA_BACKTICK` \\"
				prefixName += ":literal ' \" $QA_LITERAL $(touch QA_INJECTION) `touch QA_BACKTICK` \\"
			}
			home := filepath.Join(root, homeName)
			f.prefix = filepath.Join(root, prefixName)
			for _, path := range []string{home, filepath.Join(f.prefix, "state"), filepath.Join(home, ".codex"), filepath.Join(home, ".agents", "plugins", "external")} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			bashrc := filepath.Join(home, ".bashrc")
			original := "# SYNTHETIC external shell configuration\nexport QA_SHELL_ACCEPTANCE=preserved" // no final newline
			if err := os.WriteFile(bashrc, []byte(original), 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(bashrc, 0640); err != nil {
				t.Fatal(err)
			}
			preserved := map[string]string{
				filepath.Join(home, ".codex", "config.toml"):                      "# SYNTHETIC external configuration\n",
				filepath.Join(home, ".agents", "plugins", "external", "keep.txt"): "SYNTHETIC external plugin\n",
				filepath.Join(f.prefix, "state", "keep.txt"):                      "SYNTHETIC user state\n",
			}
			for path, data := range preserved {
				mustWrite(t, path, data)
			}
			provider := func() (string, error) { return home, nil }
			call := func(args []string) {
				t.Helper()
				if err := commandWithHome(args, io.Discard, f.target, provider); err != nil {
					t.Fatal(err)
				}
			}
			call(f.installArgs("hub,node"))
			launcher := filepath.Join(home, ".cicada", "bin", "cicada")
			installedRC, err := os.ReadFile(bashrc)
			if err != nil {
				t.Fatal(err)
			}
			installedLauncher, err := os.ReadFile(launcher)
			if err != nil {
				t.Fatal(err)
			}
			call(f.installArgs("hub,node"))
			requireBytes(t, bashrc, string(installedRC))
			requireBytes(t, launcher, string(installedLauncher))
			acceptanceShellNoStartup(t, root, bashrc, launcher, filepath.Join(f.prefix, "components", "node", "bin", "cicada"), filepath.Join(f.prefix, "components", "hub", "bin", "cicada"))
			acceptanceShellRoute(t, root, launcher, filepath.Join(f.prefix, "components", "node", "bin", "cicada"), "NODE")

			other := f
			other.prefix = filepath.Join(root, "other prefix")
			if err := commandWithHome(other.installArgs("node"), io.Discard, f.target, provider); err == nil {
				t.Fatal("another prefix silently took the active shell route")
			}
			if _, err := os.Stat(filepath.Join(other.prefix, "components", "node")); !os.IsNotExist(err) {
				t.Fatal("shell conflict was discovered after installing another component")
			}
			requireBytes(t, bashrc, string(installedRC))
			requireBytes(t, launcher, string(installedLauncher))

			call([]string{"remove", "--prefix", f.prefix, "--components", "node"})
			acceptanceShellSource(t, root, bashrc, launcher)
			acceptanceShellRoute(t, root, launcher, filepath.Join(f.prefix, "components", "hub", "bin", "cicada"), "HUB")
			call([]string{"remove", "--prefix", f.prefix, "--components", "hub"})
			requireBytes(t, bashrc, original)
			info, err := os.Stat(bashrc)
			if err != nil || info.Mode().Perm() != 0640 {
				t.Fatal("last removal changed external bashrc mode", err)
			}
			for _, path := range []string{launcher, filepath.Join(home, ".cicada", ".shell-command.json")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("last component left its managed shell entry", path, err)
				}
			}
			for path, data := range preserved {
				requireBytes(t, path, data)
			}
			for _, name := range []string{"QA_INJECTION", "QA_BACKTICK"} {
				if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("a literal path executed shell syntax", name, err)
				}
			}
			// A complete remove/reinstall/remove cycle must restore the same
			// external file bytes rather than accumulating managed blocks.
			call(f.installArgs("node"))
			acceptanceShellSource(t, root, bashrc, launcher)
			call([]string{"remove", "--prefix", f.prefix, "--components", "node"})
			requireBytes(t, bashrc, original)
		})
	}
}

func TestAcceptanceShellOffAndListNeverResolveHome(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	forbidden := func() (string, error) {
		t.Error("file-only command attempted to resolve the real shell home")
		return "", os.ErrPermission
	}
	args := append(f.installArgs("hub,node"), "--shell-integration=off")
	for _, args := range [][]string{args, {"list", "--prefix", f.prefix}, {"remove", "--prefix", f.prefix, "--components", "hub,node", "--shell-integration=off"}} {
		if err := commandWithHome(args, io.Discard, f.target, forbidden); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAcceptanceShellHomeWithColonRefusesBeforeInstall(t *testing.T) {
	f := newFixture(t, platform{"linux", "amd64"}, "node")
	home := filepath.Join(filepath.Dir(f.binary), "SYNTHETIC:invalid-PATH-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	bashrc := filepath.Join(home, ".bashrc")
	mustWrite(t, bashrc, "# SYNTHETIC external configuration\n")
	if err := commandWithHome(f.installArgs("node"), io.Discard, f.target, func() (string, error) { return home, nil }); err == nil {
		t.Fatal("a home containing ':' cannot represent one literal PATH entry")
	}
	requireBytes(t, bashrc, "# SYNTHETIC external configuration\n")
	if _, err := os.Stat(filepath.Join(f.prefix, "components", "node")); !os.IsNotExist(err) {
		t.Fatal("invalid shell home was discovered after installing a component", err)
	}
}

func acceptanceShellSource(t *testing.T, dir, bashrc, launcher string) {
	t.Helper()
	// An explicit rcfile and positional source avoid expansion of the fixture
	// path. PATH is scoped to this subprocess; HOME is inherited unchanged.
	for _, args := range [][]string{
		{"--noprofile", "--norc", "-c", `source "$1"; source "$1"`, "--", bashrc},
		{"--noprofile", "--rcfile", bashrc, "-ic", "command -v cicada"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "bash", args...)
		command.Dir = dir
		command.Env = acceptanceBashEnvironment()
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			t.Fatal("isolated shell startup failed", err, stderr.String())
		}
		if args[1] == "--norc" {
			if stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatal("noninteractive shell initialization emitted output")
			}
		} else if stdout.String() != launcher+"\n" {
			t.Fatal("a fresh interactive shell did not resolve the owned command", stdout.String())
		}
	}
	// Literal PATH states cover both a clean shell and strict-mode users.
	// Empty/unset PATH must not inject cwd; a populated PATH keeps its order;
	// sourcing the managed block repeatedly must not duplicate the owned bin.
	for _, initial := range []string{"unset", "", "/usr/bin:/bin", filepath.Dir(launcher) + ":/usr/bin:/bin"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		script := `if [[ "$2" = unset ]]; then unset PATH; else PATH="$2"; fi; set -u; source "$1"; first=$PATH; source "$1"; [[ "$PATH" = "$first" ]] || exit 51; printf '%s' "$PATH"`
		command := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", script, "--", bashrc, initial)
		command.Dir, command.Env = dir, acceptanceBashEnvironment()
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil || stderr.Len() != 0 {
			t.Fatal("strict-mode PATH initialization failed", initial, err, stderr.String())
		}
		want := filepath.Dir(launcher)
		if initial == "/usr/bin:/bin" {
			want = initial + ":" + want
		} else if strings.HasPrefix(initial, filepath.Dir(launcher)+":") {
			want = initial
		}
		if stdout.String() != want {
			t.Fatal("shell changed PATH precedence, added cwd or duplicated its entry", initial, stdout.String())
		}
	}
}

func acceptanceBashEnvironment() []string {
	var result []string
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch key {
		case "PATH", "BASH_ENV", "ENV", "PROMPT_COMMAND", "HISTFILE", "HISTSIZE":
			continue
		}
		if strings.HasPrefix(key, "BASH_FUNC_") {
			continue
		}
		result = append(result, value)
	}
	return append(result, "PATH=/usr/bin:/bin", "HISTFILE=/dev/null", "HISTSIZE=0")
}

func acceptanceShellNoStartup(t *testing.T, dir, bashrc, launcher string, targets ...string) {
	t.Helper()
	marker := filepath.Join(dir, "QA_UNEXPECTED_STARTUP")
	for _, target := range targets {
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
				t.Error(err)
			}
		}()
		probe := "#!/bin/sh\nprintf SYNTHETIC_UNEXPECTED_STARTUP > " + codexShellQuote(marker) + "\nexit 97\n"
		if err := os.WriteFile(target, []byte(probe), info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	acceptanceShellSource(t, dir, bashrc, launcher)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("shell initialization executed a component instead of only registering PATH", err)
	}
}

func acceptanceShellRoute(t *testing.T, dir, launcher, target, route string) {
	t.Helper()
	// Replace only this disposable, verified synthetic artifact with an inert
	// argv probe, then restore its exact bytes and mode before product removal.
	// This proves the launcher's actual exec route without running any daemon.
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(target, original, info.Mode().Perm()); err != nil {
			t.Error(err)
		}
	}()
	probe := "#!/bin/sh\nprintf '%s\\n' SYNTHETIC_QA_ROUTE_" + route + " \"$@\"\n"
	if err := os.WriteFile(target, []byte(probe), info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	argument := "SYNTHETIC argument ' \" $QA_LITERAL `literal` \\"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, launcher, "--synthetic-qa-probe", argument)
	command.Dir, command.Env = dir, acceptanceBashEnvironment()
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "SYNTHETIC_QA_ROUTE_"+route+"\n--synthetic-qa-probe\n"+argument+"\n" {
		t.Fatal("launcher lost its route or exact argv", err, string(output))
	}
}
