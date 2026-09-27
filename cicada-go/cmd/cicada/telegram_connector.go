package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/connectors/telegram"
)

func runTelegramConnector(args []string) error {
	flags := flag.NewFlagSet("connector telegram", flag.ContinueOnError)
	controlURL := flags.String("control-url", envOr("CICADA_CONTROL_URL", "http://127.0.0.1:8787"), "Control base URL")
	apiURL := flags.String("api-url", envOr("CICADA_TELEGRAM_API_URL", "https://api.telegram.org"), "Telegram Bot API base URL")
	interval := flags.Duration("interval", telegramConnectorInterval(), "poll retry interval")
	offsetPath := flags.String("offset-file", envOr("CICADA_TELEGRAM_OFFSET_FILE", filepath.Join(envOr("CICADA_STATE_DIR", "/state"), "telegram-offset")), "durable Telegram update offset")
	goalID := flags.String("goal-id", envOr("CICADA_TELEGRAM_GOAL_ID", ""), "optional Goal to receive normalized events")
	once := flags.Bool("once", false, "poll Telegram once")
	if err := flags.Parse(args); err != nil {
		return err
	}
	base, err := normalizeControlURL(*controlURL)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(os.Getenv("CICADA_TELEGRAM_BOT_TOKEN"))
	if token == "" {
		return errors.New("telegram connector requires CICADA_TELEGRAM_BOT_TOKEN")
	}
	secret := strings.TrimSpace(os.Getenv("CICADA_CONNECTOR_SECRET_TELEGRAM"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("CICADA_WEBHOOK_SECRET"))
	}
	if secret == "" {
		return errors.New("telegram connector requires CICADA_CONNECTOR_SECRET_TELEGRAM or CICADA_WEBHOOK_SECRET")
	}
	if *interval < time.Second {
		return errors.New("telegram connector interval must be at least 1s")
	}
	client, err := telegram.NewClient(*apiURL, token, nil)
	if err != nil {
		return err
	}
	client.PollWait = telegramPollWait()
	offset, err := readTelegramOffset(*offsetPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	poll := func() error {
		updates, err := client.GetUpdates(ctx, offset)
		if err != nil {
			return err
		}
		for _, raw := range updates {
			updateID, idErr := telegram.UpdateID(raw)
			if idErr != nil {
				continue
			}
			if updateID < offset {
				continue
			}
			externalID, eventType, payload, normalizeErr := telegram.Normalize(raw)
			if normalizeErr == nil {
				if err := postTelegramEvent(ctx, base, *goalID, externalID, eventType, payload, secret); err != nil {
					return err
				}
			}
			offset = updateID + 1
			if err := writeTelegramOffset(*offsetPath, offset); err != nil {
				return err
			}
		}
		return nil
	}
	if *once {
		return poll()
	}
	for {
		if err := poll(); err != nil {
			fmt.Fprintln(os.Stderr, "telegram connector:", err)
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

func postTelegramEvent(ctx context.Context, base, goalID, externalID, eventType string, payload []byte, secret string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/connectors/events", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Cicada-Connector", "telegram")
	request.Header.Set("X-Cicada-Event-ID", externalID)
	request.Header.Set("X-Cicada-Event-Type", eventType)
	request.Header.Set("X-Cicada-Signature", telegram.Signature(secret, payload))
	if goalID = strings.TrimSpace(goalID); goalID != "" {
		request.Header.Set("X-Cicada-Goal-ID", goalID)
	}
	if token := clientAPIToken(); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Control returned %s", response.Status)
	}
	return nil
}

func readTelegramOffset(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New("telegram offset file is invalid")
	}
	return value, nil
}

func writeTelegramOffset(path string, offset int64) error {
	if offset < 0 {
		return errors.New("telegram offset must be non-negative")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".telegram-offset-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(strconv.FormatInt(offset, 10) + "\n"); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func telegramConnectorInterval() time.Duration {
	seconds := envInt("CICADA_TELEGRAM_RETRY_SECONDS", 10)
	if seconds < 1 {
		seconds = 10
	}
	return time.Duration(seconds) * time.Second
}

func telegramPollWait() time.Duration {
	seconds := envInt("CICADA_TELEGRAM_POLL_SECONDS", 25)
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 50 {
		seconds = 50
	}
	return time.Duration(seconds) * time.Second
}
