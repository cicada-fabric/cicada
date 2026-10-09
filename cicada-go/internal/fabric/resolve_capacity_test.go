package fabric

import (
	"errors"
	"strings"
	"testing"
)

// This regression keeps 1001 eligible same-name Endpoints in one Group. The
// old Directory page returned exactly one of the duplicate aliases, so
// Resolve falsely selected it as unique. Candidate resolution must prove
// ambiguity and still use a qualified machine spelling without requiring the
// optional NodeID filter.
func TestResolveDoesNotLoseEligibleAliasesBeyondDirectoryPage(t *testing.T) {
	f := newDirectoryListQueryFixture(t)
	seedDirectoryListQueryPeers(t, f, 1001)
	for i := 0; i < 1001; i++ {
		name := "tail-filler"
		if i == 0 || i == 1000 {
			name = "tail-duplicate"
		}
		if _, err := f.db.Exec(`UPDATE fabric_endpoints SET name=?, status='online', updated_at='2040-01-01T00:00:00Z' WHERE id=?`,
			name, directoryListPeerID(i)); err != nil {
			t.Fatal(err)
		}
	}
	targetID := directoryListPeerID(1000)
	targetNode := "PUBLIC_SYNTHETIC_late_target_node"
	if _, err := f.db.Exec(`UPDATE fabric_endpoints SET machine_id=? WHERE id=?`, targetNode, targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE session_bindings SET node_id=? WHERE endpoint_id=?`, targetNode, targetID); err != nil {
		t.Fatal(err)
	}

	firstPage, err := f.service.List(f.actor, "", "", "", 1000)
	if err != nil || len(firstPage) != 1000 {
		t.Fatalf("first page returned %d endpoints, err=%v; want 1000", len(firstPage), err)
	}
	visibleDuplicateAliases := 0
	for _, card := range firstPage {
		if card.Name == "tail-duplicate" {
			visibleDuplicateAliases++
		}
	}
	if visibleDuplicateAliases != 1 {
		t.Fatalf("fixture must put exactly one eligible duplicate in the old first page; got %d", visibleDuplicateAliases)
	}

	if _, err := f.service.Resolve(f.actor, ResolveInput{Query: "tail-duplicate"}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("1001 eligible same-name rows must prove ambiguity, got err=%v", err)
	} else {
		var ambiguous *AmbiguityError
		if !errors.As(err, &ambiguous) || len(ambiguous.Candidates) != 2 {
			t.Fatalf("ambiguity should return a two-candidate proof sample, got %#v", err)
		}
	}

	target, err := f.store.GetEndpointV2(targetID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetActiveSessionBinding(targetID)
	if err != nil {
		t.Fatal(err)
	}
	targetCard := f.service.networkCard(*target, binding, f.groupID)
	for _, query := range []string{
		targetCard.Name + "@" + targetCard.NodeID,
		targetCard.Address,
	} {
		card, err := f.service.Resolve(f.actor, ResolveInput{Query: query})
		if err != nil || card.EndpointID != targetID {
			t.Fatalf("qualified target %q should resolve without NodeID: card=%#v err=%v", query, card, err)
		}
	}
	card, err := f.service.Resolve(f.actor, ResolveInput{Query: "tail-duplicate", NodeID: targetNode})
	if err != nil || card.EndpointID != targetID {
		t.Fatalf("explicit NodeID narrowing changed: card=%#v err=%v", card, err)
	}
	card, err = f.service.Resolve(f.actor, ResolveInput{Query: targetID})
	if err != nil || card.EndpointID != targetID {
		t.Fatalf("EndpointID fast path changed: card=%#v err=%v", card, err)
	}
}

func TestResolveQualifiedTargetAmongMoreThanThousandSameNameRows(t *testing.T) {
	f := newDirectoryListQueryFixture(t)
	seedDirectoryListQueryPeers(t, f, 1001)
	for i := 0; i < 1001; i++ {
		if _, err := f.db.Exec(`UPDATE fabric_endpoints SET name='capacity-shared', status='online', updated_at='2040-01-01T00:00:00Z' WHERE id=?`,
			directoryListPeerID(i)); err != nil {
			t.Fatal(err)
		}
	}
	targetID := directoryListPeerID(1000)
	targetNode := "PUBLIC_SYNTHETIC_capacity_target"
	if _, err := f.db.Exec(`UPDATE fabric_endpoints SET machine_id=? WHERE id=?`, targetNode, targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE session_bindings SET node_id=? WHERE endpoint_id=?`, targetNode, targetID); err != nil {
		t.Fatal(err)
	}

	if _, err := f.service.Resolve(f.actor, ResolveInput{Query: "capacity-shared"}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("more than 1000 same-name active rows must prove ambiguity, got %v", err)
	}
	target, err := f.store.GetEndpointV2(targetID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.store.GetActiveSessionBinding(targetID)
	if err != nil {
		t.Fatal(err)
	}
	targetCard := f.service.networkCard(*target, binding, f.groupID)
	for _, query := range []string{
		targetCard.Name + "@" + targetCard.NodeID,
		targetCard.Address,
	} {
		card, err := f.service.Resolve(f.actor, ResolveInput{Query: query})
		if err != nil || card.EndpointID != targetID {
			t.Fatalf("qualified target %q among 1001 same-name rows: card=%#v err=%v", query, card, err)
		}
	}

	// The SQL matcher deliberately forms a Unicode EqualFold superset; the Go
	// alias predicate is ToLower equality. These 1000 long-s names therefore
	// occupy several SQL pages but are not aliases for "shared". The last row
	// must still be found after paging past them.
	if !strings.EqualFold("ſhared", "shared") || strings.ToLower("ſhared") == strings.ToLower("shared") {
		t.Fatal("fixture requires a Unicode EqualFold-only candidate pair")
	}
	for i := 0; i < 1000; i++ {
		if _, err := f.db.Exec(`UPDATE fabric_endpoints SET name='ſhared' WHERE id=?`, directoryListPeerID(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Exec(`UPDATE fabric_endpoints SET name='shared' WHERE id=?`, targetID); err != nil {
		t.Fatal(err)
	}
	card, err := f.service.Resolve(f.actor, ResolveInput{Query: "shared"})
	if err != nil || card.EndpointID != targetID {
		t.Fatalf("unique ToLower alias beyond Unicode candidate pages: card=%#v err=%v", card, err)
	}

	unicodeMachine, err := f.service.Join(JoinInput{
		GroupID: f.groupID, PrincipalName: "PUBLIC_SYNTHETIC unicode machine",
		EndpointName: "unicode-machine-target", Harness: "codex",
		NativeSessionID: "PUBLIC_SYNTHETIC_unicode_machine_target", NodeID: "A Σ",
	})
	if err != nil {
		t.Fatal(err)
	}
	unicodeCard, err := f.service.Resolve(f.actor, ResolveInput{Query: "unicode-machine-target"})
	if err != nil || unicodeCard.EndpointID != unicodeMachine.Endpoint.ID {
		t.Fatalf("Unicode machine fixture resolution: card=%#v err=%v", unicodeCard, err)
	}
	unicodeFoldAddress := strings.Replace(unicodeCard.Address, "a-σ", "a-ς", 1)
	if unicodeFoldAddress == unicodeCard.Address || !strings.EqualFold(unicodeFoldAddress, unicodeCard.Address) {
		t.Fatalf("fixture does not exercise normalized Unicode machine folding: %q vs %q", unicodeFoldAddress, unicodeCard.Address)
	}
	card, err = f.service.Resolve(f.actor, ResolveInput{Query: unicodeFoldAddress})
	if err != nil || card.EndpointID != unicodeMachine.Endpoint.ID {
		t.Fatalf("Unicode-folded address should resolve without NodeID: card=%#v err=%v", card, err)
	}
}
