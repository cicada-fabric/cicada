package main

import (
	"errors"
	"sort"
	"strings"
)

// Network permission presets are intentionally small and explicit. They do
// not imply Group membership, Task authority, broadcast rights, or a native
// Owner approval; the Owner still signs the exact resulting grant set.
var networkPermissionPresets = map[string][]string{
	"directory_guest":       {"directory.discover"},
	"network_collaborator":  {"direct.receive", "direct.send", "directory.discover", "directory.publish"},
	"network_admin_inviter": {"network.admin.invite"},
	"network_task_worker":   {"task.offer.claim", "task.offer.list", "task.offer.result"},
	"network_task_publisher": {"directory.discover", "directory.publish",
		"task.offer.accept", "task.offer.list", "task.offer.publish"},
	"network_broadcast_publisher": {"broadcast.publish"},
	"network_broadcast_receiver":  {"broadcast.receive"},
}

// The operator workflow exposes only grants enforced by the current Network
// Guard. Selecting a preset is an explicit invitation choice; it does not
// infer authority from a member role or update existing grants.
var networkM1PermissionGrants = map[string]bool{
	"directory.discover":   true,
	"directory.publish":    true,
	"direct.receive":       true,
	"direct.send":          true,
	"network.admin.invite": true,
	"task.offer.publish":   true,
	"task.offer.list":      true,
	"task.offer.claim":     true,
	"task.offer.result":    true,
	"task.offer.accept":    true,
	"broadcast.publish":    true,
	"broadcast.receive":    true,
}

func selectNetworkPermissionGrants(grantsArg, preset string, ownerMayGrantAdmin bool) ([]string, error) {
	grantsArg, preset = strings.TrimSpace(grantsArg), strings.TrimSpace(preset)
	if grantsArg != "" && preset != "" {
		return nil, errors.New("choose either --grants or --preset")
	}
	var grants []string
	if preset != "" {
		selected, ok := networkPermissionPresets[preset]
		if !ok {
			return nil, errors.New("unknown Network permission preset")
		}
		grants = append([]string(nil), selected...)
	} else if grantsArg != "" {
		for _, value := range strings.Split(grantsArg, ",") {
			grant := strings.TrimSpace(value)
			if grant == "" {
				return nil, errors.New("grant set contains an empty value")
			}
			grants = append(grants, grant)
		}
	}
	sort.Strings(grants)
	for index := 1; index < len(grants); index++ {
		if grants[index] == grants[index-1] {
			return nil, errors.New("grant set contains a duplicate value")
		}
	}
	if !ownerMayGrantAdmin {
		for _, grant := range grants {
			if strings.HasPrefix(grant, "network.admin.") || strings.HasPrefix(grant, "broadcast.") {
				return nil, errors.New("NetworkAdmin cannot regrant admin or broadcast permissions")
			}
		}
	}
	for _, grant := range grants {
		if !networkM1PermissionGrants[grant] {
			return nil, errors.New("unsupported Network M1 permission grant")
		}
	}
	return grants, nil
}
