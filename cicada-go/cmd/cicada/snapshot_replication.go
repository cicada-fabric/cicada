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
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func runSnapshotReplication(args []string) error {
	flags := flag.NewFlagSet("snapshot replicate", flag.ContinueOnError)
	source := flags.String("source-url", envOr("CICADA_SNAPSHOT_SOURCE_URL", ""), "source Control URL")
	destination := flags.String("destination-url", envOr("CICADA_SNAPSHOT_DESTINATION_URL", envOr("CICADA_API_URL", "http://127.0.0.1:8787")), "destination Control URL")
	digest := flags.String("digest", "", "snapshot SHA-256 digest")
	workspacePath := flags.String("workspace-path", "", "optional destination workspace path to attach")
	sourceToken := flags.String("source-token", envOr("CICADA_SNAPSHOT_SOURCE_TOKEN", envOr("CICADA_API_TOKEN", "")), "source Control bearer token")
	destinationToken := flags.String("destination-token", envOr("CICADA_SNAPSHOT_DESTINATION_TOKEN", envOr("CICADA_API_TOKEN", "")), "destination Control bearer token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	sourceBase, err := normalizeSnapshotURL(*source)
	if err != nil {
		return fmt.Errorf("source URL: %w", err)
	}
	destinationBase, err := normalizeSnapshotURL(*destination)
	if err != nil {
		return fmt.Errorf("destination URL: %w", err)
	}
	digestValue := strings.TrimSpace(*digest)
	if len(digestValue) != 64 || !isSnapshotHex(digestValue) {
		return errors.New("snapshot digest must be a SHA-256 hex value")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	archive, metadata, err := fetchSnapshotArchive(ctx, sourceBase, digestValue, strings.TrimSpace(*sourceToken))
	if err != nil {
		return err
	}
	defer os.Remove(archive)
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	endpoint := destinationBase + "/v1/snapshots"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, file)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-cicada-workspace-tar")
	request.Header.Set("X-Cicada-Snapshot-Digest", metadata.Digest)
	if path := strings.TrimSpace(*workspacePath); path != "" {
		request.Header.Set("X-Cicada-Workspace-Path", path)
	}
	if token := strings.TrimSpace(*destinationToken); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 10 * time.Minute}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("destination Control returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var result any
	if err := json.Unmarshal(body, &result); err == nil {
		encoded, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Print(string(body))
	}
	return nil
}

func fetchSnapshotArchive(ctx context.Context, base, digest, token string) (string, snapshot.Snapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/snapshots/"+url.PathEscape(digest), nil)
	if err != nil {
		return "", snapshot.Snapshot{}, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := (&http.Client{Timeout: 10 * time.Minute}).Do(request)
	if err != nil {
		return "", snapshot.Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", snapshot.Snapshot{}, fmt.Errorf("source Control returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	temporary, err := os.CreateTemp("", ".cicada-replication-*")
	if err != nil {
		return "", snapshot.Snapshot{}, err
	}
	path := temporary.Name()
	_ = temporary.Chmod(0o600)
	defer func() {
		_ = temporary.Close()
	}()
	if _, err := io.Copy(temporary, io.LimitReader(response.Body, snapshot.MaxArchiveBytes+1)); err != nil {
		_ = os.Remove(path)
		return "", snapshot.Snapshot{}, err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(path)
		return "", snapshot.Snapshot{}, err
	}
	metadata, err := snapshot.Inspect(path)
	if err != nil {
		_ = os.Remove(path)
		return "", snapshot.Snapshot{}, err
	}
	if metadata.Digest != digest {
		_ = os.Remove(path)
		return "", snapshot.Snapshot{}, errors.New("source Control returned a different snapshot digest")
	}
	return path, metadata, nil
}

func normalizeSnapshotURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(value), "/"))
	if err != nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("must be an absolute http or https URL without credentials, query, or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isSnapshotHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}
