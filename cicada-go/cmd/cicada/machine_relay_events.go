package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"
)

// runMachineRelayEventStream keeps one outbound connection to Relay. A wake
// hint only schedules the durable claim path; no message is consumed here.
func runMachineRelayEventStream(ctx context.Context, base, machineID string, wake chan<- struct{}, revoked chan<- error) {
	backoff := time.Second
	for ctx.Err() == nil {
		openedAt := time.Now()
		connected, err := streamMachineRelayEvents(ctx, base, machineID, wake)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "machine Relay event stream:", err)
			if machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden) {
				select {
				case revoked <- err:
				default:
				}
				return
			}
		}
		// A successful HTTP handshake followed by an immediate close is not a
		// healthy stream. Back off repeated short-lived connections as well as
		// failed handshakes; reset only after the stream was actually stable.
		if connected && time.Since(openedAt) >= 30*time.Second {
			backoff = time.Second
		}
		timer := time.NewTimer(relayEventReconnectDelay(backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

// Equal jitter keeps independently reconnecting Nodes from retrying in lockstep
// without making a healthy stream's first reconnect slower than one second.
func relayEventReconnectDelay(backoff time.Duration) time.Duration {
	half := backoff / 2
	return half + time.Duration(rand.Int64N(int64(backoff-half)+1))
}

func streamMachineRelayEvents(ctx context.Context, base, machineID string, wake chan<- struct{}) (bool, error) {
	token := machineNodeToken()
	if token == "" {
		return false, errors.New("Node credential is not available")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/v2/relay/nodes/"+urlPath(machineID)+"/events", nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Authorization", "CicadaNode "+token)
	// The Node bearer is scoped to this Hub. Never forward it through a redirect.
	client := http.Client{CheckRedirect: rejectNodeRedirect}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return false, &machineAPIError{StatusCode: response.StatusCode, Status: response.Status, Body: strings.TrimSpace(string(body))}
	}
	if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		return false, errors.New("Relay did not return an event stream")
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 1024), 8*1024)
	event := ""
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if event == "ready" || event == "wake" {
				select {
				case wake <- struct{}{}:
				default:
				}
			}
			event = ""
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			event = strings.TrimPrefix(line, "event: ")
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return true, err
	}
	return true, nil
}
