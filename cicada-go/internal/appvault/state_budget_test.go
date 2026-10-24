package appvault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStateBudgetChecksAllLimitsWithoutWritingOrChangingCAS(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "app.vault")
	v, err := Create(path, testScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := v.CompareAndSwapState("saved.pending", 0, []byte("synthetic-original")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	large := bytes.Repeat([]byte{0x42}, maxStateBytes)
	defer clear(large)
	if err := v.CheckStateUpdates(map[string][]byte{"saved.pending": large}); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckStateUpdates(map[string][]byte{"saved.pending": make([]byte, maxStateBytes+1)}); err == nil {
		t.Fatal("record overflow accepted")
	}
	if err := v.CheckStateUpdates(map[string][]byte{"one": large, "two": large, "three": large}); err == nil {
		t.Fatal("total base64 payload overflow accepted")
	}
	updates := map[string][]byte{}
	for i := 0; i < maxStateRecords; i++ {
		updates["record."+string(rune('a'+i))] = []byte{1}
	}
	if err := v.CheckStateUpdates(updates); err == nil {
		t.Fatal("record count overflow accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("budget preflight wrote vault")
	}
	data, version, found, err := v.LoadState("saved.pending")
	defer clear(data)
	if err != nil || !found || version != 1 || string(data) != "synthetic-original" {
		t.Fatal("budget preflight changed original/CAS")
	}
}
