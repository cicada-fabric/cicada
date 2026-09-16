package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const machineDiscoveryOutputLimit = 1 << 20

// runMachinePair enrolls a host through the operator's existing SSH trust.
// The remote command is fixed, and all user input is passed as an argv value;
// no shell or remote command interpolation is involved.
func runMachinePair(args []string) error {
	flags := newFlagSet("machine pair")
	host := flags.String("host", "", "SSH host or configured SSH alias")
	user := flags.String("user", "", "SSH user")
	port := flags.Int("port", 22, "SSH port")
	identity := flags.String("identity-file", "", "optional SSH private key path")
	id := flags.String("id", "", "stable Cicada machine ID")
	name := flags.String("name", "", "machine display name (defaults to ID)")
	controlURL := flags.String("control-url", envOr("CICADA_API_URL", "http://127.0.0.1:8787"), "Control base URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validatePairInput(*host, *user, *port, *id); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		*name = *id
	}
	base, err := normalizeControlURL(*controlURL)
	if err != nil {
		return err
	}
	sshArgs := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	if *port != 22 {
		sshArgs = append(sshArgs, "-p", fmt.Sprint(*port))
	}
	if strings.TrimSpace(*identity) != "" {
		identityPath, absErr := filepath.Abs(*identity)
		if absErr != nil {
			return fmt.Errorf("resolve identity file: %w", absErr)
		}
		sshArgs = append(sshArgs, "-i", identityPath)
	}
	target := *host
	if strings.TrimSpace(*user) != "" {
		target = *user + "@" + *host
	}
	sshArgs = append(sshArgs, target, "cicada", "machine", "discover")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", sshArgs...)
	var stdout boundedOutput
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("SSH discovery timed out: %w", ctx.Err())
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("SSH discovery failed: %s", message)
	}
	var capabilities map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &capabilities); err != nil {
		return fmt.Errorf("decode remote capability profile: %w", err)
	}
	if capabilities == nil {
		return errors.New("remote capability profile must be a JSON object")
	}
	capabilities["enrollment"] = "ssh"
	return requestJSON(base+"/v1/machines", http.MethodPost, map[string]any{
		"id": *id, "name": *name, "status": "available", "capabilities": capabilities,
	})
}

func validatePairInput(host, user string, port int, id string) error {
	if strings.TrimSpace(host) == "" || strings.HasPrefix(host, "-") || strings.IndexFunc(host, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }) >= 0 {
		return errors.New("machine pair requires a safe --host without whitespace or a leading '-'")
	}
	if strings.TrimSpace(user) != "" && (strings.HasPrefix(user, "-") || strings.ContainsAny(user, " \t\r\n@")) {
		return errors.New("machine pair --user contains unsupported characters")
	}
	if port < 1 || port > 65535 {
		return errors.New("machine pair --port must be between 1 and 65535")
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("machine pair requires --id")
	}
	return nil
}

type boundedOutput struct {
	bytes.Buffer
	limited bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	remaining := machineDiscoveryOutputLimit - b.Len()
	if remaining <= 0 {
		b.limited = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.Buffer.Write(data[:remaining])
		b.limited = true
		return len(data), nil
	}
	return b.Buffer.Write(data)
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}
