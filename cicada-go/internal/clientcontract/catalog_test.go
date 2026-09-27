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
	}
	if got := len(OperationsForRole(RoleManager)); got != 29 {
		t.Errorf("manager operation count = %d, want 29", got)
	}
	if got := len(OperationsForRole(RoleExternal)); got != 21 {
		t.Errorf("external operation count = %d, want 21", got)
	}
	if Allows(RoleExternal, "intent.submit") || Allows(RoleExternal, "goal.result") || Allows(RoleExternal, "approvals.decide") ||
		!Allows(RoleExternal, "group.key_manifest") || !Allows(RoleManager, "intent.submit") ||
		Allows(Role("unknown"), "session.capabilities") {
		t.Fatal("catalog role authorization does not preserve the current owner boundary")
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
