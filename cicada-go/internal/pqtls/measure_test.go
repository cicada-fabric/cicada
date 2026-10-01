//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func processMemory(field string) (int64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		v := strings.Fields(line)
		if len(v) == 3 && v[0] == field+":" {
			n, e := strconv.ParseInt(v[1], 10, 64)
			return n * 1024, e
		}
	}
	return 0, ErrUnavailable
}

// Run this test alone for an attributable process measurement. Results include
// Go/runtime/kernel overhead and are not a capacity or production latency claim.
func TestTransportResourceMeasurements(t *testing.T) {
	const pairs = 8
	cfg := clone(hubConfig)
	cfg.MaxPendingHandshakes = pairs
	l, e := Listen("tcp", "127.0.0.1:0", cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	client, e := NewClient(nodeConfig)
	if e != nil {
		t.Fatal(e)
	}
	idle, e := processMemory("VmRSS")
	if e != nil {
		t.Fatal(e)
	}
	var peak atomic.Int64
	peak.Store(idle)
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				r, e := processMemory("VmRSS")
				if e == nil && r > peak.Load() {
					peak.Store(r)
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	servers := make(chan net.Conn, pairs)
	failures := make(chan error, 2*pairs)
	go func() {
		for i := 0; i < pairs; i++ {
			c, e := l.Accept()
			if e != nil {
				failures <- e
				return
			}
			servers <- c
		}
	}()
	clients := make(chan net.Conn, pairs)
	durations := make(chan time.Duration, pairs)
	var wg sync.WaitGroup
	for i := 0; i < pairs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			c, e := client.DialContext(ctx, "tcp", l.Addr().String())
			if e != nil {
				failures <- e
				return
			}
			durations <- time.Since(start)
			clients <- c
		}()
	}
	wg.Wait()
	var all []net.Conn
	defer func() {
		for _, c := range all {
			c.Close()
		}
	}()
	for i := 0; i < 2*pairs; i++ {
		select {
		case c := <-clients:
			all = append(all, c)
		case c := <-servers:
			all = append(all, c)
		case e := <-failures:
			close(stop)
			<-sampled
			t.Fatal(e)
		case <-ctx.Done():
			close(stop)
			<-sampled
			t.Fatal("concurrent connection measurements timed out")
		}
	}
	open, e := processMemory("VmRSS")
	if e != nil {
		t.Fatal(e)
	}
	if open > peak.Load() {
		peak.Store(open)
	}
	close(stop)
	<-sampled
	high, e := processMemory("VmHWM")
	if e != nil {
		t.Fatal(e)
	}
	latencies := make([]float64, 0, pairs)
	for i := 0; i < pairs; i++ {
		latencies = append(latencies, float64(<-durations)/float64(time.Millisecond))
	}
	sort.Float64s(latencies)
	data, e := json.Marshal(map[string]any{
		"architecture": "linux/amd64", "pairs": pairs, "tls_connections": 2 * pairs, "idle_rss_bytes": idle,
		"open_connections_rss_bytes": open, "sampled_peak_rss_bytes": peak.Load(), "process_peak_rss_bytes": high,
		"sampled_peak_delta_bytes": peak.Load() - idle, "delta_per_tls_connection_bytes": (peak.Load() - idle) / (2 * pairs),
		"sampling_interval_ms": 1, "concurrent_dial_ms_sorted": latencies, "median_dial_ms": (latencies[3] + latencies[4]) / 2, "max_dial_ms": latencies[7],
		"scope": "isolated synthetic loopback; includes Go/provider/socket overhead; no production capacity claim",
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Log("PQTLS_RESOURCE_MEASUREMENT " + string(data))
}
