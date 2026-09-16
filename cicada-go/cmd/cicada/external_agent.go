package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func runExternalAgent(args []string) error {
	flags := flag.NewFlagSet("external agent", flag.ContinueOnError)
	controlURL := flags.String("control-url", envOr("CICADA_CONTROL_URL", "http://127.0.0.1:8787"), "Control base URL")
	interval := flags.Duration("interval", externalAgentInterval(), "poll interval")
	runner := flags.String("browser-bin", envOr("CICADA_BROWSER_EXECUTOR_BIN", ""), "absolute browser runner path")
	once := flags.Bool("once", false, "process queued browser actions once")
	if err := flags.Parse(args); err != nil {
		return err
	}
	base, err := normalizeControlURL(*controlURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*runner) == "" {
		return errors.New("external agent requires --browser-bin or CICADA_BROWSER_EXECUTOR_BIN")
	}
	if *interval < time.Second {
		return errors.New("external agent interval must be at least 1s")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	process := func() error {
		actions, err := pollExternalActions(ctx, base)
		if err != nil {
			return err
		}
		for index := range actions {
			action := &actions[index]
			if !isBrowserAction(action.Kind) {
				continue
			}
			claimed, err := claimExternalAction(ctx, base, action.ID)
			if err != nil {
				if machineAPIHasStatus(err, http.StatusConflict) {
					continue
				}
				return err
			}
			if claimed == nil || claimed.Status != "running" {
				continue
			}
			result, executeErr := executeBrowserAction(ctx, claimed, *runner)
			payload := map[string]any{"result": json.RawMessage(`{}`)}
			if executeErr != nil {
				payload["error"] = executeErr.Error()
			} else {
				payload["result"] = json.RawMessage(result)
			}
			if err := machineAPIJSON(ctx, base+"/v1/actions/"+urlPath(action.ID)+"/complete", http.MethodPost, payload, nil); err != nil {
				return err
			}
		}
		return nil
	}
	if *once {
		return process()
	}
	for {
		if err := process(); err != nil {
			fmt.Fprintln(os.Stderr, "external agent:", err)
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func pollExternalActions(ctx context.Context, base string) ([]store.ExternalAction, error) {
	var payload struct {
		Actions []store.ExternalAction `json:"actions"`
	}
	err := machineAPIJSON(ctx, base+"/v1/actions?status=queued", http.MethodGet, nil, &payload)
	return payload.Actions, err
}

func claimExternalAction(ctx context.Context, base, id string) (*store.ExternalAction, error) {
	var action store.ExternalAction
	err := machineAPIJSON(ctx, base+"/v1/actions/"+urlPath(id)+"/claim", http.MethodPost, map[string]any{}, &action)
	return &action, err
}

func isBrowserAction(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "browser", "authenticated_browser", "form_fill":
		return true
	default:
		return false
	}
}

func externalAgentInterval() time.Duration {
	seconds := envInt("CICADA_EXTERNAL_AGENT_INTERVAL_SECONDS", 10)
	if seconds < 1 {
		seconds = 10
	}
	return time.Duration(seconds) * time.Second
}
