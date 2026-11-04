package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

func nodeHubRetiredIndex(kind, value string) string {
	if kind == "alias" {
		value = strings.ToLower(value)
	}
	h := sha256.Sum256([]byte(value))
	return "node-hub-retired-" + kind + "-" + hex.EncodeToString(h[:]) + ".json"
}

func nodeHubRetiredMatches(r nodeHubRetired, s LocalNodeHubSelection) bool {
	e, v := r.Entry, r.Removal
	if r.Format != "cicada.node-hub-retired.v1" || e.DesiredState != "REMOVING" || v.ConnectionID != e.ConnectionID || v.HubID != e.HubID || v.NodeID != e.NodeID || v.LocalFence != e.LocalFence {
		return false
	}
	if ValidateLocalNodeHubView(nodeHubEntryView(e)) != nil {
		return false
	}
	b, _ := json.Marshal(v)
	if _, err := DecodeLocalNodeHubRemoval(b); err != nil {
		return false
	}
	return (s.ConnectionID == "" || s.ConnectionID == e.ConnectionID) && (s.Alias == "" || strings.EqualFold(s.Alias, e.Alias)) && (s.HubAddress == "" || s.HubAddress == e.HubAddress) && (s.HubID == "" || s.HubID == e.HubID) && (s.NodeID == "" || s.NodeID == e.NodeID)
}

func readNodeHubRetired(root *os.Root, s LocalNodeHubSelection) (nodeHubRetired, error) {
	var names []string
	if s.Alias != "" {
		names = append(names, nodeHubRetiredName(s.Alias), nodeHubRetiredIndex("alias", s.Alias))
	}
	for _, pair := range [][2]string{{"id", s.ConnectionID}, {"address", s.HubAddress}, {"hub", s.HubID}} {
		if pair[1] != "" {
			names = append(names, nodeHubRetiredIndex(pair[0], pair[1]))
		}
	}
	if len(names) == 0 {
		return nodeHubRetired{}, errNodeHubNotFound
	}
	var found *nodeHubRetired
	for _, name := range names {
		b, _, err := readLocalNodeFile(root, name, MaxLocalNodeHubRegistryBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var r nodeHubRetired
		if err != nil || decodeLocalNodeJSON(b, &r) != nil || !nodeHubRetiredMatches(r, s) {
			return nodeHubRetired{}, errNodeHubConflict
		}
		if found != nil && *found != r {
			return nodeHubRetired{}, errNodeHubConflict
		}
		copy := r
		found = &copy
	}
	if found == nil {
		return nodeHubRetired{}, errNodeHubNotFound
	}
	return *found, nil
}

func saveNodeHubRetired(root *os.Root, r nodeHubRetired) error {
	if !nodeHubRetiredMatches(r, LocalNodeHubSelection{ConnectionID: r.Entry.ConnectionID}) {
		return ErrLocalNodeHubConfig
	}
	b, _ := json.Marshal(r)
	names := []string{nodeHubRetiredName(r.Entry.Alias), nodeHubRetiredIndex("alias", r.Entry.Alias), nodeHubRetiredIndex("id", r.Entry.ConnectionID), nodeHubRetiredIndex("address", r.Entry.HubAddress)}
	if r.Entry.HubID != "" {
		names = append(names, nodeHubRetiredIndex("hub", r.Entry.HubID))
	}
	for _, name := range names {
		old, _, err := readLocalNodeFile(root, name, MaxLocalNodeHubRegistryBytes)
		if err == nil {
			var previous nodeHubRetired
			if decodeLocalNodeJSON(old, &previous) != nil || previous.Entry.ConnectionID != r.Entry.ConnectionID || previous.Entry.HubID != r.Entry.HubID || previous.Entry.NodeID != r.Entry.NodeID || previous.Entry.StateDir != r.Entry.StateDir || previous.Entry.WriterRoot != r.Entry.WriterRoot || previous.Entry.HubAddress != r.Entry.HubAddress || previous.Entry.LocalFence > r.Entry.LocalFence {
				return errNodeHubConflict
			}
		} else if errors.Is(err, os.ErrNotExist) {
			old = nil
		} else {
			return ErrLocalNodeHubConfig
		}
		if err = writeNodeHubAtomic(root, name, append(b, '\n'), old); err != nil {
			return err
		}
	}
	return nil
}
