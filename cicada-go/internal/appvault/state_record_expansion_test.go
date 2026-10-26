package appvault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTwentyOneStateRecordsPreserveOriginalCASAndTombstones(t *testing.T) {
	if maxStateRecords != 21 || maxStateBytes != 1<<20 || maxVaultPlainBytes != 4<<20 || maxVaultFileBytes != 8<<20 || maxVaultEntries != 2 {
		t.Fatal("record-count expansion changed another vault budget")
	}
	path := filepath.Join(privateTestDir(t), "synthetic-budget.vault")
	v, err := Create(path, testScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	for i := 0; i < 16; i++ {
		if _, err := v.CompareAndSwapState(fmt.Sprintf("synthetic.legacy.%02d", i), 0, []byte("synthetic retained legacy state")); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"appcore.endpoint-groups-original.v1", "appcore.endpoint-groups-response.v1", "appcore.endpoint-groups-recovery.v1", "appcore.endpoint-groups-recovery-response.v1", "appcore.endpoint-groups-state.v1"}
	for _, name := range names {
		if _, err := v.CompareAndSwapState(name, 0, []byte("synthetic opaque original packet")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.CompareAndSwapState(names[1], 1, nil); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	if err := v.CheckStateUpdates(map[string][]byte{"synthetic.overflow": {1}}); err == nil {
		t.Fatal("twenty-second namespace passed the no-write preflight")
	}
	if _, err := v.CompareAndSwapState("synthetic.overflow", 0, []byte{1}); err == nil {
		t.Fatal("twenty-second namespace was written")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("record-count rejection changed the original vault", err)
	}
	clear(after)
	if _, err := v.CompareAndSwapState("synthetic.legacy.00", 1, []byte("synthetic known namespace update")); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	v, err = Open(path, testScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		data, version, found, err := v.LoadState(name)
		wantVersion, want := uint64(1), []byte("synthetic opaque original packet")
		if i == 1 {
			wantVersion, want = 2, nil
		}
		if err != nil || !found || version != wantVersion || !bytes.Equal(data, want) {
			t.Fatal("opaque Group packet/CAS/tombstone changed", name, err)
		}
		clear(data)
	}
}
