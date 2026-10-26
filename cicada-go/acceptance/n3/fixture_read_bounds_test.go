package n3_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Synthetic file-size/privacy checks, never a product identity or Runtime case.
func TestN3NodeProtectedStateReadBounds(t *testing.T) {
	t.Run("restart_observes_three_MiB_state", func(t *testing.T) {
		p := &nodeProcess{id: "SYNTHETIC_BOUND_NODE", state: t.TempDir()}
		f := &hubFixture{}
		f.cfg.Origin, f.cfg.Hub.HubID = "http://127.0.0.1:1", "SYNTHETIC_BOUND_HUB"
		if os.MkdirAll(filepath.Dir(p.statePath()), 0700) != nil {
			t.Fatal("synthetic protected-state directory unavailable")
		}
		writeJSON(t, p.statePath(), map[string]any{"node_id": p.id, "hub_id": f.cfg.Hub.HubID, "hub_origin": f.cfg.Origin,
			"binding_id": "SYNTHETIC_BOUND_BINDING", "binding_version": 1, "node_key_epoch": 1,
			"synthetic_history": strings.Repeat("SYNTHETIC", (3<<20)/9)})
		state := p.awaitState(t, f, true)
		if state.BindingID != "SYNTHETIC_BOUND_BINDING" {
			t.Fatal("protected-state observation lost its original binding")
		}
	})
	t.Run("exact_eight_MiB_read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node-control-state.json")
		if os.WriteFile(path, bytes.Repeat([]byte("S"), 8<<20), 0600) != nil {
			t.Fatal("synthetic boundary file unavailable")
		}
		raw := readNodeControlState(t, path)
		defer clear(raw)
		if len(raw) != 8<<20 {
			t.Fatal("protected-state reader truncated its exact product bound")
		}
	})
	for _, mode := range []string{"generic_oversize", "node_oversize", "large_log_tail"} {
		t.Run(mode, func(t *testing.T) {
			command := exec.Command(must(os.Executable()), "-test.run=^TestN3FixtureFileBoundSubprocess$", "-test.v", "-test.timeout=15s")
			command.Env = append(os.Environ(), "CICADA_N3_FILE_BOUND_CHILD="+mode)
			raw, err := command.CombinedOutput()
			defer clear(raw)
			if mode == "large_log_tail" {
				if err != nil || !bytes.Contains(raw, []byte("observed_tail_bytes=2097152 truncated=true")) || bytes.Contains(raw, []byte("SYNTHETIC_PRIVATE_LOG_CONTENT")) {
					t.Fatal("bounded log observation failed or exported private content")
				}
				return
			}
			class, limit := "synthetic-private.json", harnessPacketLimit
			if mode == "node_oversize" {
				class, limit = "node-control-state.json", 8<<20
			}
			if err == nil || !bytes.Contains(raw, []byte("class="+class)) ||
				!bytes.Contains(raw, []byte("bytes="+strconv.Itoa(limit+1))) || !bytes.Contains(raw, []byte("limit_bytes="+strconv.Itoa(limit))) {
				t.Fatal("oversized fixture file lost its exact class/size refusal")
			}
		})
	}
}

func TestN3FixtureFileBoundSubprocess(t *testing.T) {
	mode := os.Getenv("CICADA_N3_FILE_BOUND_CHILD")
	if mode == "" {
		t.Skip("synthetic bound-check subprocess only")
	}
	if mode == "large_log_tail" {
		p := &nodeProcess{state: t.TempDir()}
		path := filepath.Join(p.state, "private-process.log")
		if os.WriteFile(path, append(bytes.Repeat([]byte("S"), 3<<20), []byte("SYNTHETIC_PRIVATE_LOG_CONTENT")...), 0600) != nil {
			t.Fatal("synthetic growing log unavailable")
		}
		p.reportFailure(t)
		return
	}
	name, size := "synthetic-private.json", harnessPacketLimit+1
	if mode == "node_oversize" {
		name, size = "node-control-state.json", (8<<20)+1
	}
	path := filepath.Join(t.TempDir(), name)
	file := must(os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600))
	if file.Truncate(int64(size)) != nil || file.Close() != nil {
		t.Fatal("synthetic refusal file unavailable")
	}
	if mode == "node_oversize" {
		readNodeControlState(t, path)
	} else {
		readPrivate(t, path)
	}
	t.Fatal("oversized fixture file unexpectedly accepted")
}
