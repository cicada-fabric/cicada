package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func syntheticRoutedContext(t *testing.T, count int) (codexRoutedContext, map[string]string) {
	t.Helper()
	value := codexRoutedContext{ConnectionNonce: strings.Repeat("1", 64), RoutingVersion: codexRoutingVersion}
	expected := make(map[string]string, count)
	for i := 0; i < count; i++ {
		route := syntheticMCPGroupRoute(fmt.Sprintf("synthetic-hub-%d", i), "SYNTHETIC-network", "SYNTHETIC-group")
		id, err := codexChildRouteID(route.Pin)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := codexChildConnectionNonce(value.ConnectionNonce, id)
		if err != nil {
			t.Fatal(err)
		}
		value.Children = append(value.Children, codexRoutedChildTicket{RouteID: id, ConnectionNonce: nonce, Ticket: strings.Repeat("S", 256)})
		expected[id] = nonce
	}
	return value, expected
}

func TestCodexRoutedContextClosedBoundsAndExactChildSet(t *testing.T) {
	for _, count := range []int{1, maxCodexRoutedChildren} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			value, expected := syntheticRoutedContext(t, count)
			raw, _ := json.Marshal(value)
			got, err := decodeCodexRoutedContext(raw, value.ConnectionNonce, expected)
			if err != nil || !reflect.DeepEqual(got, value) || len(raw) > maxCodexRoutedContext {
				t.Fatal("bounded exact child set failed", err)
			}
		})
	}
	value, expected := syntheticRoutedContext(t, 2)
	raw, _ := json.Marshal(value)
	first, _ := json.Marshal(value.Children[0])
	for name, invalid := range map[string][]byte{
		"unknown_parent":        bytes.Replace(raw, []byte(`{"connection_nonce"`), []byte(`{"sid":"SYNTHETIC-forged","connection_nonce"`), 1),
		"duplicate_parent":      bytes.Replace(raw, []byte(`{"connection_nonce"`), []byte(`{"routing_version":1,"connection_nonce"`), 1),
		"unknown_child":         bytes.Replace(raw, []byte(`{"route_id"`), []byte(`{"hub":"SYNTHETIC-forged","route_id"`), 1),
		"duplicate_child_field": bytes.Replace(raw, []byte(`{"route_id"`), []byte(`{"ticket":"SYNTHETIC-forged","route_id"`), 1),
		"duplicate_route":       []byte(fmt.Sprintf(`{"connection_nonce":%q,"routing_version":1,"children":[%s,%s]}`, value.ConnectionNonce, first, first)),
		"trailing":              append(append([]byte(nil), raw...), []byte(`{}`)...),
		"oversize":              append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), maxCodexRoutedContext)...),
		"null":                  []byte(`null`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCodexRoutedContext(invalid, value.ConnectionNonce, expected); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*codexRoutedContext){
		"parent_nonce":   func(v *codexRoutedContext) { v.ConnectionNonce = strings.Repeat("2", 64) },
		"version":        func(v *codexRoutedContext) { v.RoutingVersion++ },
		"child_nonce":    func(v *codexRoutedContext) { v.Children[0].ConnectionNonce = v.Children[1].ConnectionNonce },
		"unknown_route":  func(v *codexRoutedContext) { v.Children[0].RouteID = strings.Repeat("a", 64) },
		"missing_ticket": func(v *codexRoutedContext) { v.Children[0].Ticket = "" },
		"large_ticket":   func(v *codexRoutedContext) { v.Children[0].Ticket = strings.Repeat("x", 257) },
		"missing_child":  func(v *codexRoutedContext) { v.Children = v.Children[:1] },
		"extra_child":    func(v *codexRoutedContext) { v.Children = append(v.Children, v.Children[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := value
			changed.Children = append([]codexRoutedChildTicket(nil), value.Children...)
			mutate(&changed)
			invalid, _ := json.Marshal(changed)
			if _, err := decodeCodexRoutedContext(invalid, value.ConnectionNonce, expected); err == nil {
				t.Fatal("mismatched envelope accepted")
			}
		})
	}
	if _, err := decodeCodexRoutedContext(raw, value.ConnectionNonce, nil); err == nil {
		t.Fatal("empty locally selected route set accepted")
	}
	tooMany, tooManyExpected := syntheticRoutedContext(t, maxCodexRoutedChildren+1)
	tooManyRaw, _ := json.Marshal(tooMany)
	if _, err := decodeCodexRoutedContext(tooManyRaw, tooMany.ConnectionNonce, tooManyExpected); err == nil {
		t.Fatal("child count overflow accepted")
	}
}

func TestCodexChildNonceSeparatesHubBindingAndParentConnection(t *testing.T) {
	a := syntheticMCPGroupRoute("synthetic-a", "SYNTHETIC-network", "SYNTHETIC-group").Pin
	b := syntheticMCPGroupRoute("synthetic-b", "SYNTHETIC-network", "SYNTHETIC-group").Pin
	parent := strings.Repeat("1", 64)
	aID, _ := codexChildRouteID(a)
	bID, _ := codexChildRouteID(b)
	aNonce, _ := codexChildConnectionNonce(parent, aID)
	bNonce, _ := codexChildConnectionNonce(parent, bID)
	newNonce, _ := codexChildConnectionNonce(strings.Repeat("2", 64), aID)
	if aID == bID || aNonce == bNonce || aNonce == parent || aNonce == newNonce {
		t.Fatal("separate child or parent connection reused nonce")
	}
	changed := a
	changed.Binding.BindingVersion++
	changedID, _ := codexChildRouteID(changed)
	if aID == changedID {
		t.Fatal("changed binding reused route identity")
	}
	a.HubTransportDescriptor = "SYNTHETIC-already-verified-descriptor"
	a.HubDialAddress = "192.0.2.1:8787"
	changed = a
	changed.HubDialAddress = "192.0.2.2:8787"
	aID, _ = codexChildRouteID(a)
	changedID, _ = codexChildRouteID(changed)
	if aID != changedID {
		t.Fatal("numeric reachability changed immutable route identity")
	}
}

func TestCodexRoutedChildArgumentsPreserveOriginalBusinessDigest(t *testing.T) {
	value, _ := syntheticRoutedContext(t, 2)
	arguments := map[string]any{"operation_id": "SYNTHETIC-original-operation", "group_id": "SYNTHETIC-original-group",
		"content":               map[string]any{"body": "SYNTHETIC-original-content", "array": []any{json.Number("123"), true}},
		codexMCPContextArgument: map[string]any{"connection_nonce": value.ConnectionNonce, "children": value.Children}}
	before, _ := json.Marshal(arguments)
	business, _ := codexBusinessArguments(arguments)
	originalDigest, _ := codexArgumentsDigest(business)
	for _, child := range value.Children {
		got, err := codexRoutedChildArguments(arguments, child)
		if err != nil {
			t.Fatal(err)
		}
		childBusiness, _ := codexBusinessArguments(got)
		digest, _ := codexArgumentsDigest(childBusiness)
		context := got[codexMCPContextArgument].(map[string]any)
		if digest != originalDigest || !reflect.DeepEqual(childBusiness, business) || len(context) != 2 || context["connection_nonce"] != child.ConnectionNonce || context["ticket"] != child.Ticket {
			t.Fatal("child envelope changed original business or borrowed another nonce")
		}
	}
	after, _ := json.Marshal(arguments)
	if !bytes.Equal(before, after) {
		t.Fatal("routing mutated caller arguments")
	}
}

func TestCodexRoutedMCPToolsRetainOneOriginalSchema(t *testing.T) {
	original := cicadaMCPTools()
	routed, err := codexRoutedMCPTools(strings.Repeat("1", 64))
	if err != nil || len(routed) != len(original) {
		t.Fatal("facade changed tool count", len(original), len(routed), err)
	}
	for i, tool := range routed {
		if tool["name"] != original[i]["name"] {
			t.Fatal("facade duplicated or renamed a tool")
		}
		schema := tool["inputSchema"].(map[string]any)
		properties := schema["properties"].(map[string]any)
		context := properties[codexMCPContextArgument].(map[string]any)
		contextProperties := context["properties"].(map[string]any)
		if len(contextProperties) != 3 || contextProperties["connection_nonce"].(map[string]any)["const"] != strings.Repeat("1", 64) || context["additionalProperties"] != false {
			t.Fatal("context accepts an unclosed caller identity")
		}
		delete(properties, codexMCPContextArgument)
		required := schema["required"].([]string)
		if required[len(required)-1] != codexMCPContextArgument {
			t.Fatal("facade context was not required")
		}
		if len(required) == 1 {
			// object() omits the empty required list in the original schema.
			if _, ok := original[i]["inputSchema"].(map[string]any)["required"]; !ok {
				delete(schema, "required")
			} else {
				schema["required"] = required[:0]
			}
		} else {
			schema["required"] = required[:len(required)-1]
		}
		if !reflect.DeepEqual(tool, original[i]) {
			t.Fatal("facade changed original business schema", tool["name"])
		}
	}
}
