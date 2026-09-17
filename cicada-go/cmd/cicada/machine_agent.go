package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
)

func runMachineAgent(args []string) error {
	flags := flag.NewFlagSet("machine agent", flag.ContinueOnError)
	id := flags.String("id", envOr("CICADA_MACHINE_ID", ""), "stable machine ID")
	name := flags.String("name", envOr("CICADA_MACHINE_NAME", ""), "machine display name")
	controlURL := flags.String("control-url", envOr("CICADA_CONTROL_URL", "http://127.0.0.1:8787"), "Control base URL")
	interval := flags.Duration("interval", machineAgentInterval(), "heartbeat interval")
	once := flags.Bool("once", false, "register, heartbeat, and process the current job queue once")
	lanDiscovery := flags.Bool("lan-discovery", false, "answer unauthenticated LAN capability discovery requests")
	lanPort := flags.Int("lan-port", lanDiscoveryPort, "UDP LAN discovery port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("machine agent requires --id or CICADA_MACHINE_ID")
	}
	if strings.TrimSpace(*name) == "" {
		*name = *id
	}
	base, err := normalizeControlURL(*controlURL)
	if err != nil {
		return err
	}
	if *interval < time.Second {
		return errors.New("machine agent interval must be at least 1s")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *lanDiscovery {
		if *lanPort < 1 || *lanPort > 65535 {
			return errors.New("LAN discovery port must be between 1 and 65535")
		}
		go func() {
			if err := serveLANDiscovery(ctx, *id, *name, *lanPort); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "LAN discovery:", err)
			}
		}()
	}
	send := func() error {
		capabilities := control.DiscoverMachineCapabilities()
		capabilities["role"] = "worker"
		capabilities["harnesses"] = discoveredMachineHarnesses()
		if err := machineAPI(ctx, base+"/v1/machines", http.MethodPost, map[string]any{
			"id": *id, "name": *name, "status": "available", "capabilities": capabilities,
		}); err != nil {
			return fmt.Errorf("register machine: %w", err)
		}
		return machineAPI(ctx, base+"/v1/machines/"+url.PathEscape(*id)+"/heartbeat", http.MethodPost, map[string]any{
			"status": "available", "capabilities": capabilities,
		})
	}
	process := func() error {
		if err := processMachineFabricDeliveries(ctx, base, *id); err != nil {
			return err
		}
		jobs, err := pollMachineJobs(ctx, base, *id)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			claimed, claimErr := claimMachineJob(ctx, base, job)
			if claimErr != nil {
				// A second agent may have claimed the job between polling and
				// claiming. Continue polling instead of treating that as a
				// machine failure.
				if machineAPIHasStatus(claimErr, http.StatusConflict) {
					continue
				}
				return claimErr
			}
			result := executeMachineJobWithHeartbeats(ctx, base, *id, *interval, claimed)
			if err := reportMachineJobReliably(ctx, base, claimed, result, *interval); err != nil {
				return err
			}
		}
		return nil
	}
	if err := send(); err != nil {
		if *once {
			return err
		}
		fmt.Fprintln(os.Stderr, err)
	}
	if err := process(); err != nil {
		if *once {
			return fmt.Errorf("process machine jobs: %w", err)
		}
		fmt.Fprintln(os.Stderr, err)
	}
	if *once {
		return nil
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := send(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			if err := process(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
}

func executeMachineJobWithHeartbeats(ctx context.Context, base, machineID string, interval time.Duration, job machineJob) machineJobResult {
	workspace, _, pathErr := machineJobPaths(job)
	if pathErr != nil {
		return machineJobResult{Status: "failed", Error: pathErr.Error()}
	}
	if job.WorkspaceSnapshotDigest != "" {
		if err := downloadMachineSnapshot(ctx, base, job, workspace); err != nil {
			return machineJobResult{Status: "failed", Error: "restore workspace snapshot: " + err.Error()}
		}
	}
	done := make(chan machineJobResult, 1)
	go func() { done <- executeMachineJob(ctx, job) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case result := <-done:
			if job.WorkspaceID != "" {
				digest, err := uploadMachineSnapshot(ctx, base, job, workspace)
				if err != nil {
					result.Status = "failed"
					result.Error = "store workspace snapshot: " + err.Error()
				} else {
					result.WorkspaceSnapshotDigest = digest
				}
			}
			return result
		case <-ticker.C:
			if err := machineAPI(ctx, base+"/v1/machines/"+url.PathEscape(machineID)+"/heartbeat", http.MethodPost, map[string]any{"status": "busy"}); err != nil {
				fmt.Fprintln(os.Stderr, "machine heartbeat:", err)
			}
		case <-ctx.Done():
			return machineJobResult{Status: "failed", Error: ctx.Err().Error()}
		}
	}
}

func machineAgentInterval() time.Duration {
	seconds := envInt("CICADA_MACHINE_HEARTBEAT_SECONDS", 30)
	if seconds < 1 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

func normalizeControlURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("control URL must be an absolute http or https URL without credentials")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func machineAPI(ctx context.Context, endpoint, method string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	setMachineAuth(request)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Control returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
