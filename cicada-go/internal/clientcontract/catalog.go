// Package clientcontract owns the Hub's versioned Android Client RPC catalog.
package clientcontract

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// ContractRevision identifies the cross-repository Client/Hub contract
// revision. The encrypted Client-Control wire framing remains version 1.
const ContractRevision = "client-hub-v1.6.4"

type Role string

const (
	RoleManager  Role = "manager"
	RoleExternal Role = "external"
)

// Operation describes one encrypted RPC method and its authorization and
// documentation references. Optional RequestSchema/ResultSchema name
// OpenAPI component schemas when the contract publishes a complete pair.
type Operation struct {
	ID            string `json:"id"`
	Method        string `json:"method"`
	Roles         []Role `json:"roles"`
	RequestRef    string `json:"request_ref"`
	ResultRef     string `json:"result_ref"`
	Boundary      string `json:"boundary"`
	RequestSchema string `json:"request_schema,omitempty"`
	ResultSchema  string `json:"result_schema,omitempty"`
}

// Definition is the machine-readable operation catalog embedded into the Hub.
type Definition struct {
	CatalogSchemaVersion int         `json:"catalog_schema_version"`
	ContractRevision     string      `json:"contract_revision"`
	WireVersion          int         `json:"wire_version"`
	RPCRoute             string      `json:"rpc_route"`
	Operations           []Operation `json:"operations"`
}

//go:embed catalog.json
var catalogFS embed.FS

var (
	catalogOnce        sync.Once
	catalogData        []byte
	catalogDef         Definition
	operationsByRole   map[Role][]string
	operationIDsByRole map[Role]map[string]struct{}
)

func loadCatalog() {
	catalogOnce.Do(func() {
		var err error
		catalogData, err = catalogFS.ReadFile("catalog.json")
		if err != nil {
			panic("read embedded Client RPC catalog: " + err.Error())
		}
		if err := json.Unmarshal(catalogData, &catalogDef); err != nil {
			panic("decode embedded Client RPC catalog: " + err.Error())
		}
		operationsByRole = map[Role][]string{
			RoleManager:  make([]string, 0, len(catalogDef.Operations)),
			RoleExternal: make([]string, 0, len(catalogDef.Operations)),
		}
		operationIDsByRole = map[Role]map[string]struct{}{
			RoleManager:  make(map[string]struct{}, len(catalogDef.Operations)),
			RoleExternal: make(map[string]struct{}, len(catalogDef.Operations)),
		}
		for _, operation := range catalogDef.Operations {
			for _, role := range operation.Roles {
				operationsByRole[role] = append(operationsByRole[role], operation.ID)
				operationIDsByRole[role][operation.ID] = struct{}{}
			}
		}
	})
}

// CatalogBytes returns a copy of the exact embedded JSON bytes. The catalog
// digest is computed over these bytes, including any trailing newline.
func CatalogBytes() []byte {
	loadCatalog()
	return append([]byte(nil), catalogData...)
}

// CatalogSHA256 is the lowercase SHA-256 hex digest of CatalogBytes. It names
// only the catalog file, not the complete Client/Hub contract bundle.
func CatalogSHA256() string {
	loadCatalog()
	digest := sha256.Sum256(catalogData)
	return hex.EncodeToString(digest[:])
}

// CatalogDefinition returns a deep-enough copy for read-only inspection.
func CatalogDefinition() Definition {
	loadCatalog()
	out := catalogDef
	out.Operations = make([]Operation, len(catalogDef.Operations))
	for i, operation := range catalogDef.Operations {
		out.Operations[i] = operation
		out.Operations[i].Roles = append([]Role(nil), operation.Roles...)
	}
	return out
}

// OperationsForRole returns operation IDs in catalog order for a capability
// response. Unknown roles receive an empty list.
func OperationsForRole(role Role) []string {
	loadCatalog()
	return append([]string(nil), operationsByRole[role]...)
}

// Allows reports whether role is listed for operation in the catalog.
func Allows(role Role, operationID string) bool {
	if role != RoleManager && role != RoleExternal {
		return false
	}
	loadCatalog()
	_, allowed := operationIDsByRole[role][operationID]
	return allowed
}
