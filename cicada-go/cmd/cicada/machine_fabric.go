package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
)

func processMachineFabricDeliveries(ctx context.Context, base, machineID string) error {
	var payload struct {
		Deliveries []control.MachineFabricDelivery `json:"deliveries"`
	}
	if err := machineAPIJSON(ctx, base+"/v1/machines/"+urlPath(machineID)+"/fabric-deliveries", http.MethodGet, nil, &payload); err != nil {
		return fmt.Errorf("poll Fabric deliveries: %w", err)
	}
	for _, delivery := range payload.Deliveries {
		deliveryError := executeMachineFabricDelivery(ctx, delivery)
		if err := reportMachineFabricDeliveryReliably(ctx, base, machineID, delivery.MessageID, deliveryError); err != nil {
			return fmt.Errorf("report Fabric delivery %s: %w", delivery.MessageID, err)
		}
	}
	return nil
}

func reportMachineFabricDeliveryReliably(ctx context.Context, base, machineID, messageID, deliveryError string) error {
	endpoint := base + "/v1/machines/" + urlPath(machineID) + "/fabric-deliveries/" + urlPath(messageID)
	for {
		err := machineAPIJSON(ctx, endpoint, http.MethodPost, map[string]string{"error": deliveryError}, nil)
		if err == nil || machineAPIHasStatus(err, http.StatusNotFound, http.StatusConflict) {
			return nil
		}
		var apiErr *machineAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func executeMachineFabricDelivery(parent context.Context, delivery control.MachineFabricDelivery) string {
	if delivery.Harness != "codex" {
		return limitText("exact native-session wake is not available for harness "+delivery.Harness, 512)
	}
	if strings.TrimSpace(delivery.NativeSessionID) == "" || strings.TrimSpace(delivery.Prompt) == "" {
		return "Fabric delivery is missing its native session or prompt"
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	binary := strings.TrimSpace(os.Getenv("CICADA_CODEX_BIN"))
	if binary == "" {
		binary = "codex"
	}
	command := exec.CommandContext(ctx, binary, "queue", "--thread", delivery.NativeSessionID, "--message", delivery.Prompt)
	command.Env = os.Environ()
	output, err := command.CombinedOutput()
	if err == nil {
		return ""
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		detail = err.Error()
	}
	return limitText(detail, 512)
}
