package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const cicadaCodexHookMainChild = "CICADA_TEST_CODEX_HOOK_MAIN_CHILD"

// The child executes the real dispatcher and stdio. Outside its child role
// this is only a subprocess harness, not a separate product test.
func TestCicadaCodexHookMainChild(t *testing.T) {
	if os.Getenv(cicadaCodexHookMainChild) != "1" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("CICADA_TEST_CODEX_HOOK_MAIN_ARGS")), &args) != nil {
		os.Exit(3)
	}
	os.Args = append([]string{"cicada"}, args...)
	main()
	os.Exit(0) // Keep the Go test footer out of the actual hook JSON stream.
}

func TestCicadaCodexHookMainEntry(t *testing.T) {
	for _, test := range []struct {
		name           string
		args           []string
		input          string
		exit           int
		stdout, stderr string
	}{
		{name: "ignored_event", args: []string{"codex-hook"}, input: `{"hook_event_name":"SyntheticIgnoredEvent"}`, stdout: "{}"},
		{name: "invalid_stdin", args: []string{"codex-hook"}, input: `{`, exit: 1, stderr: "CODEX_HOOK_INPUT_INVALID"},
		{name: "extra_argument", args: []string{"codex-hook", "--synthetic-argument"}, input: `{}`, exit: 1, stderr: "usage: cicada codex-hook"},
		{name: "command_usage", args: []string{"synthetic-unknown-command"}, exit: 2, stderr: "mcp|codex-hook|migration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCicadaCodexHookMainChild$")
			args, _ := json.Marshal(test.args)
			// These cases never discover identity or call a Node. Do not inherit
			// any resident Hub/Node/Codex state configuration into the child.
			command.Env = []string{cicadaCodexHookMainChild + "=1", "CICADA_TEST_CODEX_HOOK_MAIN_ARGS=" + string(args)}
			command.Dir = t.TempDir()
			command.Stdin = strings.NewReader(test.input)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			exit := 0
			if err != nil {
				var failure *exec.ExitError
				if !errors.As(err, &failure) {
					t.Fatal("isolated dispatcher did not finish")
				}
				exit = failure.ExitCode()
			}
			if exit != test.exit || strings.TrimSpace(stdout.String()) != test.stdout {
				t.Fatalf("dispatcher exit/stdout mismatch: exit=%d", exit)
			}
			if test.stderr == "" {
				if stderr.Len() != 0 {
					t.Fatal("successful hook produced unexpected stderr")
				}
			} else if !strings.Contains(stderr.String(), test.stderr) {
				t.Fatal("dispatcher did not return the expected error/help")
			}
		})
	}
}
