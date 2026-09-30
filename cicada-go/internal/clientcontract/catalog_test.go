package clientcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCatalogIsVersionedCompleteAndPointsIntoWireContract(t *testing.T) {
	definition := CatalogDefinition()
	if definition.CatalogSchemaVersion != 1 || definition.ContractRevision != ContractRevision ||
		definition.WireVersion != 1 || definition.RPCRoute != "/v2/client/rpc" {
		t.Fatalf("unexpected catalog header: %#v", definition)
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate catalog test source")
	}
	wirePath := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../docs/client-hub-wire-v1.md"))
	wire, err := os.ReadFile(wirePath)
	if err != nil {
		t.Fatalf("read wire contract: %v", err)
	}
	openAPIPath := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../docs/client-hub-v1.openapi.yaml"))
	openAPI, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("read OpenAPI contract: %v", err)
	}
	openAPIText := string(openAPI)
	if !strings.Contains(openAPIText, "x-contract-revision: "+ContractRevision) {
		t.Fatalf("OpenAPI contract revision does not match catalog revision %s", ContractRevision)
	}

	seen := make(map[string]bool, len(definition.Operations))
	for _, operation := range definition.Operations {
		if operation.ID == "" || seen[operation.ID] {
			t.Fatalf("empty or duplicate operation ID %q", operation.ID)
		}
		seen[operation.ID] = true
		if operation.Method != "POST" || operation.Boundary == "" {
			t.Fatalf("operation %s has incomplete method/boundary metadata: %#v", operation.ID, operation)
		}
		if len(operation.Roles) == 0 {
			t.Fatalf("operation %s has invalid role set: %#v", operation.ID, operation.Roles)
		}
		roleSet := make(map[Role]bool, len(operation.Roles))
		for _, role := range operation.Roles {
			if role != RoleManager && role != RoleExternal || roleSet[role] {
				t.Fatalf("operation %s has invalid role set: %#v", operation.ID, operation.Roles)
			}
			roleSet[role] = true
		}
		for _, ref := range []string{operation.RequestRef, operation.ResultRef} {
			if !strings.HasPrefix(ref, "docs/client-hub-wire-v1.md#") ||
				!strings.Contains(string(wire), "id=\""+strings.TrimPrefix(ref, "docs/client-hub-wire-v1.md#")+"\"") {
				t.Errorf("operation %s has unresolved wire reference %q", operation.ID, ref)
			}
		}
		if operation.RequestSchema != "" || operation.ResultSchema != "" {
			if operation.RequestSchema == "" || operation.ResultSchema == "" {
				t.Errorf("operation %s has an incomplete request/result schema pair", operation.ID)
			}
			for _, schema := range []string{operation.RequestSchema, operation.ResultSchema} {
				if !strings.Contains(openAPIText, "    "+schema+":\n") {
					t.Errorf("operation %s refers to missing OpenAPI schema %q", operation.ID, schema)
				}
			}
			mapping := "        " + operation.ID + ":\n          request: '#/components/schemas/" + operation.RequestSchema + "'\n          result: '#/components/schemas/" + operation.ResultSchema + "'"
			if !strings.Contains(openAPIText, mapping) {
				t.Errorf("operation %s catalog schemas do not match OpenAPI operation mapping", operation.ID)
			}
		}
	}
	if got := len(OperationsForRole(RoleManager)); got != 46 {
		t.Errorf("manager operation count = %d, want 46", got)
	}
	if got := len(OperationsForRole(RoleExternal)); got != 38 {
		t.Errorf("external operation count = %d, want 38", got)
	}
	if Allows(RoleExternal, "intent.submit") || Allows(RoleExternal, "goal.result") || Allows(RoleExternal, "approvals.decide") ||
		!Allows(RoleExternal, "group.key_manifest") || !Allows(RoleExternal, "network.key_manifest") ||
		!Allows(RoleExternal, "monitor.broadcast_prepare") ||
		!Allows(RoleManager, "monitor.broadcast_confirm") || !Allows(RoleManager, "intent.submit") ||
		Allows(Role("unknown"), "session.capabilities") {
		t.Fatal("catalog role authorization does not preserve the current owner boundary")
	}
	monitorOperations := []string{"monitor.broadcast_prepare", "monitor.broadcast_confirm", "monitor.broadcast_status", "monitor.broadcast_recover"}
	for _, operationID := range monitorOperations {
		if !Allows(RoleManager, operationID) || !Allows(RoleExternal, operationID) {
			t.Errorf("owner-scoped Monitor operation %s must be catalogued for both owner roles", operationID)
		}
	}
	for _, operationID := range []string{"topology.regroup_proposal", "topology.delegation_issue", "topology.delegation_revoke",
		"space.foreign_member_admit", "space.foreign_member_revoke", "space.foreign_endpoint_join", "space.key_manifest_v2", "space.key_consent_v2",
		"space.key_admission_v2", "space.key_status_v2"} {
		if !Allows(RoleManager, operationID) || !Allows(RoleExternal, operationID) {
			t.Errorf("v1.5 owner operation %s is missing for a role", operationID)
		}
	}
	if !strings.Contains(openAPIText, "membership.set_broadcast_permission: '#/components/schemas/TopologySetBroadcastPermissionAction'") ||
		!strings.Contains(openAPIText, "broadcast_permission_enabled:") {
		t.Fatal("OpenAPI does not describe the explicit broadcast permission action and topology snapshot field")
	}
	for _, marker := range []string{
		"group.create: '#/components/schemas/TopologyCreateGroupAction'",
		"x-topology-snapshot-schema: '#/components/schemas/ClientTopologySnapshot'",
		"x-topology-network-projection-schema: '#/components/schemas/ClientTopologyNetwork'",
		"network_endpoints_truncated:", "can_create_group:", "network_ids:",
	} {
		if !strings.Contains(openAPIText, marker) {
			t.Fatalf("OpenAPI omits ACTIVE Network topology %q", marker)
		}
	}
	assertOpenAPIOperationsMatchCatalog(t, definition)
}

func TestCatalogDigestNamesExactEmbeddedBytes(t *testing.T) {
	digest := sha256.Sum256(CatalogBytes())
	if got, want := CatalogSHA256(), hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("catalog digest = %s, want %s", got, want)
	}
	copyOfCatalog := CatalogBytes()
	copyOfCatalog[0] ^= 0xff
	if string(copyOfCatalog) == string(CatalogBytes()) {
		t.Fatal("CatalogBytes exposed mutable embedded storage")
	}
}

func assertOpenAPIOperationsMatchCatalog(t *testing.T, definition Definition) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate catalog test source")
	}
	openAPIPath := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../../../docs/client-hub-v1.openapi.yaml"))
	data, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("read OpenAPI contract: %v", err)
	}
	text := string(data)
	start := strings.Index(text, "    ClientRpcOperation:\n")
	if start < 0 {
		t.Fatal("OpenAPI ClientRpcOperation schema was not found")
	}
	endOffset := strings.Index(text[start:], "\n    SessionCapabilities:")
	if endOffset < 0 {
		t.Fatal("OpenAPI SessionCapabilities boundary was not found")
	}
	block := text[start : start+endOffset]
	enumOffset := strings.Index(block, "      enum:\n")
	if enumOffset < 0 {
		t.Fatal("OpenAPI ClientRpcOperation enum was not found")
	}
	actual := make(map[string]bool)
	for _, line := range strings.Split(block[enumOffset+len("      enum:\n"):], "\n") {
		if !strings.HasPrefix(line, "        - ") {
			if len(actual) > 0 {
				break
			}
			continue
		}
		operationID := strings.TrimSpace(strings.TrimPrefix(line, "        - "))
		if operationID == "" || actual[operationID] {
			t.Errorf("OpenAPI contains empty or duplicate operation ID %q", operationID)
		}
		actual[operationID] = true
	}
	expected := make(map[string]bool, len(definition.Operations))
	for _, operation := range definition.Operations {
		expected[operation.ID] = true
	}
	for operationID := range expected {
		if !actual[operationID] {
			t.Errorf("catalog operation %q is missing from OpenAPI enum", operationID)
		}
	}
	for operationID := range actual {
		if !expected[operationID] {
			t.Errorf("OpenAPI operation %q is missing from catalog", operationID)
		}
	}
}
