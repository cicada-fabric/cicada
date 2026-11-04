package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestCodexRouteCacheColdSelectionRetainsRemovedHubWithoutBorrowingRoster(t *testing.T) {
	root := privateLocalNodeRoot(t)
	a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-network-a", "SYNTHETIC-group-a")
	b := syntheticMCPGroupRoute("hub-b", "SYNTHETIC-network-b", "SYNTHETIC-group-b")
	live := codexRouteCache{Format: codexRouteCacheFormat, ParentNonce: strings.Repeat("1", 64), Native: codexRouteThread(a.Native), Selected: &b, Routes: []mcpGroupRoute{a, b}, Complete: true}
	if err := saveCodexRouteSelection(root, live); err != nil {
		t.Fatal(err)
	}
	warm, err := loadCodexRouteCache(root, live.ParentNonce, a.Native)
	if err != nil || warm.Selected == nil || *warm.Selected != b || len(warm.Routes) != 2 {
		t.Fatal("live parent lost exact hint", err)
	}
	cold, err := loadCodexRouteCache(root, strings.Repeat("2", 64), a.Native)
	if err != nil || cold.Selected == nil || *cold.Selected != b || len(cold.Routes) != 0 || len(cold.Senders) != 0 || cold.Complete {
		t.Fatal("cold parent borrowed roster or lost selected Hub", err)
	}
	if _, err := codexRoutedHookConnections("cicada_whoami", map[string]any{}, []LocalNodeConnection{{Pin: a.Pin}}, root, cold.ParentNonce, a.Native); err == nil {
		t.Fatal("removed selected Hub fell back to remaining Hub")
	}
	other := a.Native
	other.NativeSessionID = "SYNTHETIC-other-thread"
	foreign, err := loadCodexRouteCache(root, live.ParentNonce, other)
	if err != nil || foreign.Selected != nil || len(foreign.Routes) != 0 {
		t.Fatal("another actual Thread borrowed routing hint", err)
	}
}

func TestCodexRouteCacheRejectsTamperingAliasesAndQuotaWithoutReplacingOriginal(t *testing.T) {
	for _, kind := range []string{"unknown", "duplicate", "wrong_native", "permission", "symlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-network", "SYNTHETIC-group")
			value := codexRouteCache{Format: codexRouteCacheFormat, ParentNonce: strings.Repeat("1", 64), Native: codexRouteThread(a.Native), Selected: &a, Routes: []mcpGroupRoute{a}}
			if err := writeCodexRouteCache(root, value); err != nil {
				t.Fatal(err)
			}
			path, _ := codexRouteCachePath(root, value.ParentNonce, a.Native)
			raw, _ := os.ReadFile(path)
			invalid := append([]byte(nil), raw...)
			switch kind {
			case "unknown":
				invalid = bytes.Replace(invalid, []byte(`{"format"`), []byte(`{"session_token":"SYNTHETIC_FORBIDDEN","format"`), 1)
			case "duplicate":
				invalid = bytes.Replace(invalid, []byte(`{"format"`), []byte(`{"format":"SYNTHETIC_WRONG","format"`), 1)
			case "wrong_native":
				invalid = bytes.ReplaceAll(invalid, []byte(a.Native.NativeSessionID), []byte("SYNTHETIC-other-thread"))
			case "permission":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				invalid = append(invalid, bytes.Repeat([]byte(" "), maxCodexRouteCache)...)
			}
			if kind != "permission" && kind != "symlink" {
				if err := os.WriteFile(path, invalid, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readCodexRouteCache(root, value.ParentNonce, a.Native); err == nil {
				t.Fatal("unverified hint accepted")
			}
		})
	}
	root := privateLocalNodeRoot(t)
	a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-network", "SYNTHETIC-group")
	value := codexRouteCache{Format: codexRouteCacheFormat, ParentNonce: strings.Repeat("1", 64), Native: codexRouteThread(a.Native), Selected: &a}
	if err := writeCodexRouteCache(root, value); err != nil {
		t.Fatal(err)
	}
	path, _ := codexRouteCachePath(root, value.ParentNonce, a.Native)
	before, _ := os.ReadFile(path)
	value.Routes = make([]mcpGroupRoute, maxCodexRouteRows+1)
	if err := writeCodexRouteCache(root, value); err == nil {
		t.Fatal("oversized roster accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed write replaced original selected route")
	}
}

func TestCodexRoutedHookRefusesAmbiguousPartialOrClonedHubHints(t *testing.T) {
	root := privateLocalNodeRoot(t)
	a := syntheticMCPGroupRoute("hub-a", "SYNTHETIC-network-a", "SYNTHETIC-shared-group")
	b := syntheticMCPGroupRoute("hub-b", "SYNTHETIC-network-b", a.GroupID)
	cache := codexRouteCache{Format: codexRouteCacheFormat, ParentNonce: strings.Repeat("1", 64), Native: codexRouteThread(a.Native), Selected: &a, Routes: []mcpGroupRoute{a, b}, Complete: true}
	if err := saveCodexRouteSelection(root, cache); err != nil {
		t.Fatal(err)
	}
	connections := []LocalNodeConnection{{Pin: a.Pin}, {Pin: b.Pin}}
	if _, err := codexRoutedHookConnections("cicada_use_group", map[string]any{"group_id": a.GroupID}, connections, root, cache.ParentNonce, a.Native); err == nil {
		t.Fatal("ambiguous Group guessed Hub")
	}
	chosen, err := codexRoutedHookConnections("cicada_use_group", map[string]any{"hub_id": b.Pin.HubID, "network_id": b.NetworkID, "group_id": b.GroupID}, connections, root, cache.ParentNonce, a.Native)
	if err != nil || len(chosen) != 1 || chosen[0].Pin != b.Pin {
		t.Fatal("qualified Group chose another Hub", err)
	}
	clone := a.Pin
	clone.Binding.HubFingerprint = strings.Repeat("c", 64)
	if _, err := codexRoutedHookConnections("cicada_whoami", map[string]any{}, []LocalNodeConnection{{Pin: clone}}, root, cache.ParentNonce, a.Native); err == nil {
		t.Fatal("cloned same-ID Hub borrowed original selection")
	}
	cache.Complete = false
	cache.Routes = []mcpGroupRoute{a}
	if err := writeCodexRouteCache(root, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := codexRoutedHookConnections("cicada_use_group", map[string]any{"group_id": a.GroupID}, connections, root, cache.ParentNonce, a.Native); err == nil {
		t.Fatal("partial roster established global uniqueness")
	}
}
