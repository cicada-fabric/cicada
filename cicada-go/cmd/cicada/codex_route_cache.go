package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/apppaths"
)

const (
	codexRouteCacheFormat = "cicada.codex-route-hint.v1"
	maxCodexRouteRows     = MaxLocalNodeHubConnections * 64
	maxCodexRouteCache    = 4 << 20
)

var errCodexRouteCache = errors.New("GROUP_ROUTE_CACHE_UNAVAILABLE: retain the original selection and refresh this Thread's Groups")

// This protected file is only a routing hint. It holds no token, one-use
// ticket, packet, private key or grant. Every use needs a fresh original Node
// context and current child Guard. NodeID varies between a Thread's Hubs.
// The Node verifies the actual transcript at issue time; this file neither
// discovers a SID nor asserts an additional cloud-account identity.
type codexRouteCache struct {
	Format      string            `json:"format"`
	ParentNonce string            `json:"parent_nonce,omitempty"`
	Native      mcpTrustedContext `json:"native"`
	Selected    *mcpGroupRoute    `json:"selected,omitempty"`
	Routes      []mcpGroupRoute   `json:"routes,omitempty"`
	Senders     []mcpGroupRoute   `json:"senders,omitempty"`
	Complete    bool              `json:"complete"`
}

func codexRouteThread(native mcpTrustedContext) mcpTrustedContext {
	native.NodeID = ""
	return native
}

func codexRouteCachePath(userRoot, parentNonce string, native mcpTrustedContext) (string, error) {
	if _, err := apppaths.ResolveUserRoot(userRoot); err != nil || !sameMCPRouteThread(native, native) ||
		parentNonce != "" && !localContextHex(parentNonce, 64) {
		return "", errCodexRouteCache
	}
	raw, _ := json.Marshal(codexRouteThread(native))
	sum := sha256.Sum256(append([]byte("cicada/codex/route-thread/v1\x00"), raw...))
	name := "selection.json"
	if parentNonce != "" {
		name = parentNonce + ".json"
	}
	return filepath.Join(userRoot, "mcp", "routing", hex.EncodeToString(sum[:]), name), nil
}

func validateCodexRouteCache(value codexRouteCache, parentNonce string, native mcpTrustedContext) error {
	if value.Format != codexRouteCacheFormat || value.ParentNonce != parentNonce || value.Native != codexRouteThread(native) ||
		len(value.Routes) > maxCodexRouteRows || len(value.Senders) > MaxLocalNodeHubConnections ||
		parentNonce == "" && (len(value.Routes) != 0 || len(value.Senders) != 0) {
		return errCodexRouteCache
	}
	if value.Selected != nil && (!validMCPGroupRoute(*value.Selected) || !sameMCPRouteThread(value.Selected.Native, native)) {
		return errCodexRouteCache
	}
	for _, route := range value.Routes {
		if !validMCPGroupRoute(route) || !sameMCPRouteThread(route.Native, native) {
			return errCodexRouteCache
		}
	}
	for _, sender := range value.Senders {
		if !validMCPSenderRoute(sender) || sender.GroupID != "" || !sameMCPRouteThread(sender.Native, native) {
			return errCodexRouteCache
		}
	}
	return nil
}

func readCodexRouteCache(userRoot, parentNonce string, native mcpTrustedContext) (*codexRouteCache, error) {
	path, err := codexRouteCachePath(userRoot, parentNonce, native)
	if err != nil {
		return nil, err
	}
	if _, err := apppaths.ResolveUserRoot(filepath.Dir(path)); err != nil {
		return nil, errCodexRouteCache
	}
	before, err := codexOperatorPrivateFile(path, true)
	if err != nil || before == nil {
		if err != nil {
			return nil, errCodexRouteCache
		}
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errCodexRouteCache
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errCodexRouteCache
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCodexRouteCache+1))
	var value codexRouteCache
	if err != nil || len(raw) == 0 || len(raw) > maxCodexRouteCache || decodeLocalNodeJSON(raw, &value) != nil ||
		validateCodexRouteCache(value, parentNonce, native) != nil {
		return nil, errCodexRouteCache
	}
	return &value, nil
}

func writeCodexRouteCache(userRoot string, value codexRouteCache) error {
	if validateCodexRouteCache(value, value.ParentNonce, value.Native) != nil {
		return errCodexRouteCache
	}
	path, err := codexRouteCachePath(userRoot, value.ParentNonce, value.Native)
	if err != nil {
		return err
	}
	if _, err := apppaths.ResolveUserRoot(filepath.Dir(path)); err != nil {
		return errCodexRouteCache
	}
	// Never chmod or repair an existing installation. ResolveUserRoot checks
	// all existing ancestors before creation; the new cache uses private modes.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errCodexRouteCache
	}
	if _, err := apppaths.ResolveUserRoot(filepath.Dir(path)); err != nil {
		return errCodexRouteCache
	}
	if _, err := codexOperatorPrivateFile(path, true); err != nil {
		return errCodexRouteCache
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > maxCodexRouteCache {
		return errCodexRouteCache
	}
	if err := persistNodeSecretFile(path, append(raw, '\n'), ".route-hint-*"); err != nil {
		return errCodexRouteCache
	}
	return nil
}

// A new MCP parent restores only the selected original route. It cannot reuse
// another parent's roster, nonce or ticket. Missing/unusable selection remains
// explicit; callers never choose the sole remaining connection as a fallback.
func loadCodexRouteCache(userRoot, parentNonce string, native mcpTrustedContext) (*codexRouteCache, error) {
	value, err := readCodexRouteCache(userRoot, parentNonce, native)
	if err != nil || value != nil {
		return value, err
	}
	cold, err := readCodexRouteCache(userRoot, "", native)
	if err != nil {
		return nil, err
	}
	value = &codexRouteCache{Format: codexRouteCacheFormat, ParentNonce: parentNonce, Native: codexRouteThread(native)}
	if cold != nil {
		value.Selected = cold.Selected
	}
	return value, nil
}

func saveCodexRouteSelection(userRoot string, live codexRouteCache) error {
	if live.Selected == nil || live.ParentNonce == "" {
		return errCodexRouteCache
	}
	// Persist cold selection first. A lost acknowledgement cannot make the
	// subsequent parent silently restore the previous Hub instead.
	cold := codexRouteCache{Format: codexRouteCacheFormat, Native: live.Native, Selected: live.Selected}
	if err := writeCodexRouteCache(userRoot, cold); err != nil {
		return err
	}
	return writeCodexRouteCache(userRoot, live)
}
