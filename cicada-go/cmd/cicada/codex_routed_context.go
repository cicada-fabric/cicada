package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	codexRoutingVersion    = 1
	maxCodexRoutedChildren = MaxLocalNodeHubConnections
	maxCodexRoutedContext  = 8 << 10
)

// The parent carries no native identity or reusable authority. Each child
// ticket is issued and consumed by its original Node for the unchanged full
// business arguments, tool and child nonce. Only read-only aggregation may
// require more than one child; ordinary calls require exactly their one route.
type codexRoutedContext struct {
	ConnectionNonce string                   `json:"connection_nonce"`
	RoutingVersion  int                      `json:"routing_version"`
	Children        []codexRoutedChildTicket `json:"children"`
}

type codexRoutedChildTicket struct {
	RouteID         string `json:"route_id"`
	ConnectionNonce string `json:"connection_nonce"`
	Ticket          string `json:"ticket"`
}

// This identifier is not a discovery mechanism or a pin verifier. Callers
// obtain the pin from verified local discovery first. Numeric reachability is
// excluded only when tied to the same authenticated transport descriptor.
func codexChildRouteID(pin LocalNodeConnectionPin) (string, error) {
	origin, err := normalizeMCPAPIOrigin(pin.APIOrigin)
	if err != nil || origin != pin.APIOrigin || !localContextText(pin.HubID, 256) || !localContextText(pin.NodeID, 256) {
		return "", errCodexMCPContext
	}
	if pin.HubTransportDescriptor != "" {
		pin.HubDialAddress = ""
	}
	raw, err := json.Marshal(pin)
	if err != nil || len(raw) > localNodeMaxPinBytes {
		return "", errCodexMCPContext
	}
	sum := sha256.Sum256(append([]byte("cicada/codex/child-route/v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func codexChildConnectionNonce(parentNonce, routeID string) (string, error) {
	if !localContextHex(parentNonce, 64) || !localContextHex(routeID, 64) {
		return "", errCodexMCPContext
	}
	sum := sha256.Sum256([]byte("cicada/codex/child-nonce/v1\x00" + parentNonce + "\x00" + routeID))
	return hex.EncodeToString(sum[:]), nil
}

// expected is constructed locally for this exact call after route selection.
// Model-supplied child IDs, nonces and tickets never expand that set. The raw
// codec rejects unknown and duplicate keys before decoding typed fields.
func decodeCodexRoutedContext(raw []byte, parentNonce string, expected map[string]string) (codexRoutedContext, error) {
	var zero, value codexRoutedContext
	if len(raw) > maxCodexRoutedContext || !localContextHex(parentNonce, 64) || len(expected) == 0 || len(expected) > maxCodexRoutedChildren ||
		decodeLocalNodeJSON(raw, &value) != nil || value.ConnectionNonce != parentNonce || value.RoutingVersion != codexRoutingVersion ||
		len(value.Children) != len(expected) {
		return zero, errCodexMCPContext
	}
	seen := make(map[string]bool, len(expected))
	seenNonces := make(map[string]bool, len(expected))
	for _, child := range value.Children {
		nonce, err := codexChildConnectionNonce(parentNonce, child.RouteID)
		if err != nil || expected[child.RouteID] != nonce || child.ConnectionNonce != nonce || nonce == parentNonce ||
			seen[child.RouteID] || seenNonces[nonce] || child.Ticket == "" || len(child.Ticket) > 256 {
			return zero, errCodexMCPContext
		}
		seen[child.RouteID], seenNonces[nonce] = true, true
	}
	return value, nil
}

// Preserve business keys and nested values exactly. Changing the reserved
// envelope cannot change the digest that the original child issuer signed.
func codexRoutedChildArguments(arguments map[string]any, child codexRoutedChildTicket) (map[string]any, error) {
	if !localContextHex(child.RouteID, 64) || !localContextHex(child.ConnectionNonce, 64) || child.Ticket == "" || len(child.Ticket) > 256 {
		return nil, errCodexMCPContext
	}
	business, err := codexBusinessArguments(arguments)
	if err != nil {
		return nil, err
	}
	business[codexMCPContextArgument] = map[string]any{"connection_nonce": child.ConnectionNonce, "ticket": child.Ticket}
	return business, nil
}

// One facade advertises the existing tool set exactly once. The trusted Hook
// supplies children; the model only echoes the parent connection coordinates.
func codexRoutedMCPTools(parentNonce string) ([]map[string]any, error) {
	if !localContextHex(parentNonce, 64) {
		return nil, errCodexMCPContext
	}
	tools := cicadaMCPTools()
	for _, tool := range tools {
		schema := tool["inputSchema"].(map[string]any)
		properties := schema["properties"].(map[string]any)
		properties[codexMCPContextArgument] = map[string]any{
			"type": "object", "description": "Runtime context. Echo this connection nonce and routing version. The trusted local Hook supplies fresh child tickets; never provide a Thread ID.",
			"properties": map[string]any{
				"connection_nonce": map[string]any{"type": "string", "const": parentNonce},
				"routing_version":  map[string]any{"type": "integer", "const": codexRoutingVersion},
				"children": map[string]any{"type": "array", "minItems": 1, "maxItems": maxCodexRoutedChildren, "items": map[string]any{
					"type": "object", "properties": map[string]any{
						"route_id":         map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						"connection_nonce": map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"},
						"ticket":           map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
					}, "required": []string{"route_id", "connection_nonce", "ticket"}, "additionalProperties": false}},
			}, "required": []string{"connection_nonce", "routing_version"}, "additionalProperties": false,
		}
		required, _ := schema["required"].([]string)
		schema["required"] = append(required, codexMCPContextArgument)
	}
	return tools, nil
}
