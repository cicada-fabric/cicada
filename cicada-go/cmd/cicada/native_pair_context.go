package main

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/harness"
)

type nativePairJoinSelection struct{ PairID, Slot string }

// The model chooses only a previously Owner-created Pair and reserved slot.
// Identity, generation, proof, Workspace and transport never come from args.
func parseNativePairJoinSelection(args map[string]any) (nativePairJoinSelection, bool, error) {
	var s nativePairJoinSelection
	_, pairPresent := args["pair_id"]
	_, slotPresent := args["slot"]
	if !pairPresent && !slotPresent {
		return s, false, nil
	}
	for k := range args {
		if k != "pair_id" && k != "slot" {
			return s, true, errors.New("reserved Pair Join accepts only pair_id and slot")
		}
	}
	var ok bool
	s.PairID, ok = args["pair_id"].(string)
	if !ok {
		return s, true, errors.New("Pair ID is required")
	}
	s.Slot, ok = args["slot"].(string)
	if !ok {
		return s, true, errors.New("reserved slot A or B is required")
	}
	id, err := hex.DecodeString(s.PairID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != s.PairID || (s.Slot != "A" && s.Slot != "B") {
		return s, true, errors.New("invalid exact Pair ID or reserved slot")
	}
	return s, true, nil
}

// Local-only IPC, deliberately distinct from the Hub wire DTO. The Node agent
// derives generation/bootstrap digest from its authenticated description and
// independently checks this original native record before dedicated Join.
type localNativePairJoinRequest struct {
	Version         int    `json:"version"`
	Operation       string `json:"operation"`
	PairID          string `json:"pair_id"`
	Slot            string `json:"slot"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Workspace       string `json:"workspace"`
	APIOrigin       string `json:"api_origin"`
}

func nativePairLocalJoinRequest(s nativePairJoinSelection, current harness.SessionContext) (localNativePairJoinRequest, error) {
	var empty localNativePairJoinRequest
	if _, _, err := parseNativePairJoinSelection(map[string]any{"pair_id": s.PairID, "slot": s.Slot}); err != nil {
		return empty, err
	}
	if harness.Canonical(current.Harness) != "codex" || current.NativeSessionID == "" || len(current.NativeSessionID) > 128 || strings.TrimSpace(current.NativeSessionID) != current.NativeSessionID || strings.ContainsAny(current.NativeSessionID, "/\\\r\n\x00") {
		return empty, errors.New("reserved Pair Join requires the actual Codex Thread identity")
	}
	if !filepath.IsAbs(current.Workspace) || !utf8.ValidString(current.Workspace) || current.Workspace == "" || len(current.Workspace) > 1024 || strings.ContainsRune(current.Workspace, 0) || filepath.Clean(current.Workspace) != current.Workspace {
		return empty, errors.New("reserved Pair Join requires the original verified workspace within 1024 UTF-8 bytes")
	}
	return localNativePairJoinRequest{Version: localJoinProtocolVersion, Operation: "native_pair_join", PairID: s.PairID, Slot: s.Slot, Harness: "codex", NativeSessionID: current.NativeSessionID, Workspace: current.Workspace}, nil
}
