package fabric

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryOwnerPrivacyAndExactContextResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-directory.sqlite")
	s, _, group := newFabricTestServiceAtPath(t, path)
	join := func(name, sid, node, workspace string) *JoinResult {
		t.Helper()
		v, err := s.Join(JoinInput{GroupID: group.ID, PrincipalName: sid, EndpointName: name, Harness: "codex", NativeSessionID: sid, NodeID: node, Workspace: workspace})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	self := join("self", "synthetic-self", "node-self", "/synthetic/self")
	foreign := join("private-project-name", "synthetic-foreign", "private-hostname", "/private/foreign/project")
	// Synthetic foreign membership in an Owner Group: directory permission
	// must not turn Group administration into ownership of the foreign Thread.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`UPDATE principals SET owner_id='foreign-owner' WHERE id=?`, foreign.Endpoint.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE fabric_endpoints SET owner='foreign-owner',tags_json='["private-tag"]',capabilities_json='{"private-path":"/private/foreign/project"}' WHERE id=?`, foreign.Endpoint.ID); err != nil {
		t.Fatal(err)
	}
	actor, err := s.Authenticate(self.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	cards, err := s.List(actor, "", "", "", 100)
	if err != nil || len(cards) != 2 {
		t.Fatal("scoped directory", err)
	}
	encoded, _ := json.Marshal(cards)
	for _, private := range []string{"private-project-name", "private-hostname", "/private/foreign/project", "private-tag", "synthetic-foreign"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("foreign private metadata leaked", private)
		}
	}
	card, err := s.Resolve(actor, ResolveInput{Query: foreign.Endpoint.ID})
	if err != nil || card.Name != foreign.Endpoint.ID || card.NodeID != "" || card.Workspace != "" || card.BindingID != "" {
		t.Fatal("foreign ID projection", err)
	}
	if _, err = s.Resolve(actor, ResolveInput{Query: card.Address}); err != nil {
		t.Fatal("published opaque address was not resolvable", err)
	}
	for _, input := range []ResolveInput{
		{Query: foreign.Endpoint.Name}, {Query: foreign.Endpoint.Name + "@" + foreign.Endpoint.MachineID},
		{Query: foreign.Endpoint.ID, NodeID: foreign.Endpoint.MachineID}, {Query: foreign.Endpoint.ID, Workspace: foreign.Endpoint.Workspace},
		{Query: self.Endpoint.ID, NodeID: "wrong-node"}, {Query: self.Endpoint.ID, Workspace: "/wrong/workspace"},
	} {
		if _, err = s.Resolve(actor, input); !errors.Is(err, ErrNotFoundOrNotAuthorized) {
			t.Fatal("private/incorrect context resolved", err)
		}
	}
	if own, err := s.Resolve(actor, ResolveInput{Query: self.Endpoint.ID, NodeID: self.Endpoint.MachineID, Workspace: self.Endpoint.Workspace}); err != nil || own.Workspace != self.Endpoint.Workspace {
		t.Fatal("same Owner context lost", err)
	}
	join("重复名字", "synthetic-duplicate-a", "node-a", "/synthetic/a")
	join("重复名字", "synthetic-duplicate-b", "node-b", "/synthetic/b")
	_, err = s.Resolve(actor, ResolveInput{Query: "重复名字"})
	var ambiguous *AmbiguityError
	if !errors.As(err, &ambiguous) || len(ambiguous.Candidates) != 2 {
		t.Fatal("duplicate names were guessed", err)
	}
	if strings.Contains(err.Error(), foreign.Endpoint.Name) || strings.Contains(err.Error(), foreign.Endpoint.Workspace) {
		t.Fatal("ambiguity leaked foreign metadata")
	}
}
