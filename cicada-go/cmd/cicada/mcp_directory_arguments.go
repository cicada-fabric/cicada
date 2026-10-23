package main

import "fmt"

// Directory fields select a target within the current authenticated Group.
// They never supply the caller's Node, native Thread, workspace or credentials.
// Keep these exact per-tool properties aligned with the advertised closed schemas.
func validateMCPDirectoryArguments(name string, arguments map[string]any) (bool, error) {
	var stringsAllowed []string
	list := false
	switch name {
	case "cicada_members":
		stringsAllowed, list = []string{"status", "node_id", "harness"}, true
	case "cicada_list":
		stringsAllowed, list = []string{"status", "node_id", "machine_id", "harness"}, true
	case "cicada_find", "cicada_resolve", "cicada_inspect":
		stringsAllowed = []string{"query", "node_id", "workspace"}
	default:
		return false, nil
	}
	for key, value := range arguments {
		if list && key == "limit" {
			if _, ok := strictMCPInteger(value); !ok {
				return true, fmt.Errorf("MCP argument %q must be an integer", key)
			}
			continue
		}
		allowed := false
		for _, declared := range stringsAllowed {
			if key == declared {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, fmt.Errorf("MCP argument %q is not accepted by %s", key, name)
		}
		if _, ok := value.(string); !ok {
			return true, fmt.Errorf("MCP argument %q must be a string", key)
		}
	}
	return true, nil
}
