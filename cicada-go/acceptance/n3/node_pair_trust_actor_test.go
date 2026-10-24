package n3_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Read only the actual local CLI's TTY output. Do not reconstruct a code from
// SQLite, a private Node record, a fake terminal flag or a manually supplied pin.
// argv is supplied by the frozen CLI consumer adapter, never a shell command.
func nodePairPrivateTTYCode(t *testing.T, root string, argv, environment []string) string {
	t.Helper()
	dir := must(os.MkdirTemp(root, "private-node-code-"))
	capture := filepath.Join(dir, "terminal.private")
	config := filepath.Join(dir, "capture-config.json")
	writeJSON(t, config, map[string]any{"argv": argv, "capture_path": capture, "timeout_seconds": 15})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "/qa/scripts/fixtures/native-pair/node_pair_private_tty.py", config)
	cmd.Env = environment
	var metadata directIPBoundedError
	cmd.Stdout, cmd.Stderr = &metadata, &metadata
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		t.Fatal("actual local pairing-code CLI failed its bounded private TTY capture")
	}
	var result struct {
		Scope    string `json:"scope"`
		Exit     int    `json:"child_exit_code"`
		Timeout  bool   `json:"timeout"`
		Overflow bool   `json:"overflow"`
		Bytes    int    `json:"captured_bytes"`
		SHA256   string `json:"capture_sha256"`
	}
	if json.Unmarshal(metadata.raw, &result) != nil || result.Scope != "OWNED_REAL_PTY_PRIVATE_CAPTURE_NOT_PHYSICAL_KEYBOARD" ||
		result.Exit != 0 || result.Timeout || result.Overflow || result.Bytes <= 0 || result.Bytes > 65536 {
		t.Fatal("actual local pairing-code CLI did not return qualified private TTY metadata")
	}
	info := must(os.Lstat(capture))
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("actual terminal capture is not a new private regular fixture file")
	}
	raw := readPrivate(t, capture)
	defer clear(raw)
	if len(raw) != result.Bytes || hash(raw) != result.SHA256 {
		t.Fatal("actual terminal capture changed before private decoding")
	}
	var code string
	for _, field := range bytes.Fields(raw) {
		if !bytes.HasPrefix(field, []byte(wire.NodePairTrustCodePrefix)) {
			continue
		}
		if code != "" || len(field) > wire.MaxNodePairTrustCodeBytes {
			t.Fatal("actual terminal returned ambiguous or oversized secret pairing material")
		}
		code = string(field)
	}
	decoded, err := wire.DecodeNodePairTrustCode(code, time.Now().UTC())
	clear(decoded.OOBSecret)
	if err != nil || code == "" {
		t.Fatal("actual terminal did not contain one complete canonical current pairing code")
	}
	return code // Only the private actual-App command mailbox receives this text.
}

type nodePairBoundedCapture struct {
	raw      []byte
	overflow bool
}

func (b *nodePairBoundedCapture) Write(raw []byte) (int, error) {
	count := len(raw)
	remaining := 65536 - len(b.raw)
	if count > remaining {
		b.overflow = true
	}
	b.raw = append(b.raw, raw[:min(remaining, count)]...)
	return count, nil
}

// The real companion CLI must refuse redirected output. Keep both streams
// private and assert no complete code or S representation escapes on failure.
func nodePairRedirectRefusesCode(t *testing.T, argv, environment []string, code string) {
	t.Helper()
	if len(argv) == 0 || code == "" {
		t.Fatal("redirect refusal fixture lacks its actual CLI or original private code")
	}
	decoded, decodeErr := wire.DecodeNodePairTrustCode(code, time.Now().UTC())
	defer clear(decoded.OOBSecret)
	if decodeErr != nil {
		t.Fatal("redirect refusal fixture lacks a current original private code")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = environment
	var out nodePairBoundedCapture
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	defer clear(out.raw)
	leaked := bytes.Contains(out.raw, []byte(wire.NodePairTrustCodePrefix)) || bytes.Contains(out.raw, []byte(code))
	for _, secret := range [][]byte{decoded.OOBSecret, []byte(base64.RawURLEncoding.EncodeToString(decoded.OOBSecret)),
		[]byte(base64.StdEncoding.EncodeToString(decoded.OOBSecret)), []byte(hex.EncodeToString(decoded.OOBSecret))} {
		leaked = leaked || bytes.Contains(out.raw, secret)
	}
	if err == nil || ctx.Err() != nil || out.overflow || leaked {
		t.Fatal("actual local pairing-code CLI did not refuse redirected secret output")
	}
}
