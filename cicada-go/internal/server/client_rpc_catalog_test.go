package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientcontract"
)

func TestClientRPCDispatchCasesMatchCatalog(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source")
	}
	dispatchPath := filepath.Join(filepath.Dir(sourceFile), "client_rpc_v2.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, dispatchPath, nil, 0)
	if err != nil {
		t.Fatalf("parse RPC dispatcher: %v", err)
	}

	var dispatch *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "dispatchClientRPC" {
			dispatch = function
			break
		}
	}
	if dispatch == nil {
		t.Fatal("dispatchClientRPC was not found")
	}

	var operationSwitch *ast.SwitchStmt
	ast.Inspect(dispatch.Body, func(node ast.Node) bool {
		switchStatement, ok := node.(*ast.SwitchStmt)
		if ok {
			if tag, ok := switchStatement.Tag.(*ast.Ident); ok && tag.Name == "operation" {
				operationSwitch = switchStatement
				return false
			}
		}
		return true
	})
	if operationSwitch == nil {
		t.Fatal("operation dispatch switch was not found")
	}

	actual := make(map[string]bool)
	for _, statement := range operationSwitch.Body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expression := range clause.List {
			literal, ok := expression.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatalf("unexpected non-string operation case at %s", fset.Position(expression.Pos()))
			}
			operationID := unquoteTestString(t, literal.Value)
			if actual[operationID] {
				t.Errorf("duplicate dispatch case %q", operationID)
			}
			actual[operationID] = true
		}
	}

	expected := make(map[string]bool)
	for _, operation := range clientcontract.CatalogDefinition().Operations {
		expected[operation.ID] = true
	}
	for operationID := range expected {
		if !actual[operationID] {
			t.Errorf("catalog operation %q has no dispatch case", operationID)
		}
	}
	for operationID := range actual {
		if !expected[operationID] {
			t.Errorf("dispatch operation %q is missing from catalog", operationID)
		}
	}
}

func unquoteTestString(t *testing.T, literal string) string {
	t.Helper()
	value, err := strconv.Unquote(literal)
	if err != nil {
		t.Fatalf("unquote AST string literal %q: %v", literal, err)
	}
	return value
}
