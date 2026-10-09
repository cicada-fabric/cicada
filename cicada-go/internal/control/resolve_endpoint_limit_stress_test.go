package control

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// This management-Control-path regression probe makes one authorized resolver
// list span its existing 1000-row cap. The duplicate alias is intentionally
// placed on both sides of that boundary using real JoinEndpoint calls.
func TestStressResolveEndpointAliasBeyondListLimitFailsClosed(t *testing.T) {
	root := t.TempDir()
	c, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown stress Control: %v", err)
		}
	}()

	join := func(id, name string) {
		t.Helper()
		if _, err := c.JoinEndpoint(EndpointJoinInput{
			EndpointID: id, Name: name, Harness: "codex", NativeSessionID: "thread_" + id,
			MachineID: "node_stress_resolver", Workspace: "/stress/" + id,
			Status: "online", Visibility: "fabric",
		}); err != nil {
			t.Fatalf("legal synthetic JoinEndpoint %s: %v", id, err)
		}
	}
	join("ep_stress_alias_old", "stress-duplicate-alias")
	// Store timestamps have second precision. Cross a full timestamp boundary
	// so this older duplicate is unambiguously below the subsequent 1000 rows.
	boundary := time.Now().UTC().Truncate(time.Second).Add(time.Second + 20*time.Millisecond)
	time.Sleep(time.Until(boundary))
	for i := 0; i < 999; i++ {
		join(fmt.Sprintf("ep_stress_resolver_filler_%04d", i), fmt.Sprintf("stress-filler-%04d", i))
	}
	join("ep_stress_alias_new", "stress-duplicate-alias")

	bounded, err := c.ListEndpoints(EndpointListInput{Limit: 1000})
	if err != nil || len(bounded) != 1000 {
		t.Fatalf("fixture boundary query returned %d endpoints, err=%v, want exactly 1000", len(bounded), err)
	}
	oldVisible, newVisible := false, false
	for _, endpoint := range bounded {
		oldVisible = oldVisible || endpoint.ID == "ep_stress_alias_old"
		newVisible = newVisible || endpoint.ID == "ep_stress_alias_new"
	}
	if oldVisible || !newVisible {
		t.Fatalf("fixture did not place duplicate aliases across the active 1000-row boundary: old_visible=%t new_visible=%t",
			oldVisible, newVisible)
	}

	resolved, err := c.ResolveEndpoint(EndpointResolveInput{Query: "stress-duplicate-alias"})
	if !errors.Is(err, ErrEndpointAmbiguous) {
		resolvedID := ""
		if resolved != nil {
			resolvedID = resolved.ID
		}
		t.Fatalf("1001-row duplicate alias should fail closed as ambiguous; resolver returned endpoint=%q err=%v", resolvedID, err)
	}
}
