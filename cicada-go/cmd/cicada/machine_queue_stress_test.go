//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
)

// Runs concurrent unique queue operations for one actual local native writer
// lock and verifies every durable operation result. The executable is a
// synthetic shell queue; it does not invoke Codex, a model, or a provider.
func TestStressMachineNativeQueueSerializesSameEndpoint(t *testing.T) {
	const operations = 32
	root := t.TempDir()
	activePath := filepath.Join(root, "active")
	seenPath := filepath.Join(root, "seen-operations")
	overlapPath := filepath.Join(root, "overlap")
	queue := filepath.Join(root, "synthetic-codex-queue")
	script := fmt.Sprintf(`#!/bin/sh
if ! mkdir %s 2>/dev/null; then
  printf 'overlap\n' >> %s
fi
printf '%%s\n' "$5" >> %s
sleep 0.005
rmdir %s || exit 88
exit 0
`, shellQuote(activePath), shellQuote(overlapPath), shellQuote(seenPath), shellQuote(activePath))
	if err := os.WriteFile(queue, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(queue)
	if err != nil {
		t.Fatalf("stat synthetic queue executable: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("synthetic queue executable mode=%#o, want 0700", info.Mode().Perm())
	}
	t.Setenv("CICADA_CODEX_BIN", queue)
	ctx := withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub_stress_synthetic", NodeID: "node_stress_synthetic",
		WriterRoot: root, WriterScope: "uid:1000",
	})
	type operationCase struct {
		op     nodelock.NativeOperation
		prompt string
	}
	cases := make([]operationCase, operations)
	for i := range cases {
		messageID := fmt.Sprintf("msg_stress_queue_%03d", i)
		digest := sha256.Sum256([]byte("PUBLIC_SYNTHETIC:" + messageID))
		cases[i] = operationCase{op: nodelock.NativeOperation{
			HubID: "hub_stress_synthetic", NodeID: "node_stress_synthetic",
			EndpointID: "ep_stress_same_worker", BindingID: "binding_stress_same_worker",
			BindingEpoch: 7, MessageID: messageID, Digest: hex.EncodeToString(digest[:]),
			AttemptID: "attempt_" + messageID,
		}, prompt: "synthetic-queue-" + messageID}
	}
	started := time.Now()
	start := make(chan struct{})
	results := make(chan queueStressResult, len(cases))
	var wait sync.WaitGroup
	for _, item := range cases {
		wait.Add(1)
		go func(item operationCase) {
			defer wait.Done()
			<-start
			callStarted := time.Now()
			err := executeMachineNativeCodex(ctx, "native_stress_same_sid", item.prompt, item.op)
			results <- queueStressResult{messageID: item.op.MessageID, elapsed: time.Since(callStarted), err: err}
		}(item)
	}
	close(start)
	wait.Wait()
	close(results)
	totalElapsed := time.Since(started)
	latencies := make([]time.Duration, 0, len(cases))
	for result := range results {
		latencies = append(latencies, result.elapsed)
		if result.err != nil {
			t.Fatalf("synthetic queue operation %s failed: %v", result.messageID, result.err)
		}
	}
	if len(latencies) != operations {
		t.Fatalf("completed operation count=%d, want=%d", len(latencies), operations)
	}
	if _, err := os.Stat(overlapPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("two queue processes overlapped on the same native writer: stat=%v", err)
	}

	seen := make(map[string]int, operations)
	file, err := os.Open(seenPath)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		seen[scanner.Text()]++
	}
	if err := scanner.Err(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != operations {
		t.Fatalf("unique queue messages=%d, want=%d", len(seen), operations)
	}
	for _, item := range cases {
		if seen[item.prompt] != 1 {
			t.Fatalf("queue message %s appeared %d times", item.op.MessageID, seen[item.prompt])
		}
		if err := requireMachineNativeQueueOutcome(ctx, "native_stress_same_sid", item.op); err != nil {
			t.Fatalf("durable accepted outcome for %s: %v", item.op.MessageID, err)
		}
	}
	metric := map[string]any{
		"schema": "cicada.v01.stress.metric.v1", "stage": "same_sid_native_writer_queue",
		"unique_operations": operations, "parallel_callers": operations,
		"all_queue_messages_once": true, "overlap_detected": false,
		"durable_queue_accepted": operations, "elapsed_ms": totalElapsed.Milliseconds(),
		"throughput_ops_s": float64(operations) / totalElapsed.Seconds(),
		"latency_p50_ms":   queueLatencyPercentileMs(latencies, 0.50),
		"latency_p95_ms":   queueLatencyPercentileMs(latencies, 0.95),
	}
	emitCommandStressMetric(t, metric)
}

type queueStressResult struct {
	messageID string
	elapsed   time.Duration
	err       error
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func queueLatencyPercentileMs(samples []time.Duration, percentile float64) float64 {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return float64(ordered[index].Microseconds()) / 1000
}
