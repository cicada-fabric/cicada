package fabric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func artifactTestDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func grantArtifactRole(t *testing.T, persistence *store.Store, actor Actor, grants ...string) Actor {
	t.Helper()
	membership, err := persistence.GetMembership(actor.MembershipID)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]string(nil), membership.Grants...)
	all = append(all, grants...)
	updated, err := persistence.UpdateMembershipAuthorization(membership.ID, membership.Roles, all, membership.Authorization, membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	actor.MembershipRevision = updated.Revision
	actor.MembershipID = updated.ID
	return actor
}

func TestArtifactV2ExactScopeRevocationAndDigestGuard(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	root := t.TempDir()
	content := []byte("scoped artifact")
	if err := os.WriteFile(filepath.Join(root, "result.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := persistence.CreateWorkspace("workspace-v2", "", root, "test", "r1")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := persistence.CreateArtifact(store.Artifact{
		ID: "legacy-artifact-1", WorkspaceID: workspace.ID, Name: "result.txt", Path: "result.txt",
		Kind: "evidence", Digest: artifactTestDigest(content), Status: "available",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "worker", EndpointName: "worker", Harness: "codex", NativeSessionID: "artifact-session", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	actor = grantArtifactRole(t, persistence, actor, "artifact.read", "artifact.publish", "artifact.share")
	// The legacy row has no Worker/Goal provenance. A trusted migration first
	// scopes it to this exact Actor; later native publications can version it.
	if _, err := persistence.CreateArtifactRefV2(store.ArtifactRefV2Input{ArtifactID: legacy.ID,
		GroupID: actor.GroupID, ProducerPrincipalID: actor.PrincipalID,
		ProducerEndpointID: actor.EndpointID, Scopes: []string{store.ArtifactRefV2ScopeMetadata}}); err != nil {
		t.Fatal(err)
	}
	ref, err := service.CreateArtifactRefV2(actor, store.ArtifactRefV2Input{
		ArtifactID: legacy.ID, WorkspaceID: workspace.ID, Digest: artifactTestDigest(content), Size: int64(len(content)),
		RelativePath: "result.txt", Scopes: []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeSummary, store.ArtifactRefV2ScopeDigest, store.ArtifactRefV2ScopeContent},
	})
	if err != nil {
		t.Fatal(err)
	}
	read, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{ArtifactRefID: ref.ID, Scopes: []string{store.ArtifactRefV2ScopeContent}})
	if err != nil || string(read.Content) != string(content) {
		t.Fatalf("authorized content read=%q err=%v", read.Content, err)
	}
	if _, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{ArtifactRefID: ref.ID, Scopes: []string{"workspace"}}); !errors.Is(err, store.ErrArtifactRefV2ScopeDenied) {
		t.Fatalf("unknown scope accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "result.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{ArtifactRefID: ref.ID, Scopes: []string{store.ArtifactRefV2ScopeContent}}); !errors.Is(err, store.ErrArtifactRefV2DigestMismatch) {
		t.Fatalf("changed bytes were accepted: %v", err)
	}
	if _, err := persistence.RevokeMembership(actor.MembershipID, "test revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{ArtifactRefID: ref.ID, Scopes: []string{store.ArtifactRefV2ScopeSummary}}); !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrStaleBinding) && !errors.Is(err, store.ErrArtifactRefV2Denied) {
		t.Fatalf("revoked membership retained read access: %v", err)
	}
}

func TestArtifactV2ListDoesNotBypassReferenceScopes(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	root := t.TempDir()
	content := []byte("content-only fixture")
	if err := os.WriteFile(filepath.Join(root, "content.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := persistence.CreateWorkspace("workspace-content-only", "", root, "test", "r1")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := persistence.CreateArtifact(store.Artifact{
		ID: "legacy-content-only", WorkspaceID: workspace.ID, Name: "sensitive-name.txt",
		Path: "content.txt", Kind: "sensitive-kind", Digest: artifactTestDigest(content),
		Evidence: "sensitive summary",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := service.Join(JoinInput{
		GroupID: group.ID, PrincipalName: "content-only-reader", EndpointName: "content-only-reader",
		Harness: "codex", NativeSessionID: "artifact-content-only-session", NodeID: "node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	actor = grantArtifactRole(t, persistence, actor, "artifact.read")
	ref, err := persistence.CreateArtifactRefV2(store.ArtifactRefV2Input{
		ArtifactID: legacy.ID, GroupID: actor.GroupID, ProducerPrincipalID: actor.PrincipalID,
		ProducerEndpointID: actor.EndpointID, WorkspaceID: workspace.ID,
		Digest: artifactTestDigest(content), Scopes: []string{store.ArtifactRefV2ScopeContent},
	})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := service.ListArtifactRefsV2(actor, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list content-only ref: %#v err=%v", listed, err)
	}
	if listed[0].ID != ref.ID || listed[0].Name != "" || listed[0].Kind != "" ||
		listed[0].WorkspaceID != "" || listed[0].ProducerEndpointID != "" ||
		listed[0].Summary != "" || listed[0].Digest != "" {
		t.Fatalf("list exposed fields outside the ref's scopes: %#v", listed[0])
	}
	if _, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{
		ArtifactRefID: ref.ID, Scopes: []string{store.ArtifactRefV2ScopeSummary},
	}); !errors.Is(err, store.ErrArtifactRefV2ScopeDenied) {
		t.Fatalf("summary read unexpectedly bypassed its scope: %v", err)
	}
	read, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{
		ArtifactRefID: ref.ID, Scopes: []string{store.ArtifactRefV2ScopeContent},
	})
	if err != nil || string(read.Content) != string(content) {
		t.Fatalf("authorized content read=%q err=%v", read.Content, err)
	}
}

func TestArtifactV2RejectsTraversalAndSymlinkEscape(t *testing.T) {
	service, persistence, group := newFabricTestService(t)
	root := t.TempDir()
	outside := t.TempDir()
	content := []byte("outside")
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	workspace, err := persistence.CreateWorkspace("workspace-v2-path", "", root, "test", "r1")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := persistence.CreateArtifact(store.Artifact{ID: "legacy-path", WorkspaceID: workspace.ID, Name: "link.txt", Path: "link.txt", Kind: "file", Digest: artifactTestDigest(content)})
	if err != nil {
		t.Fatal(err)
	}
	joined, err := service.Join(JoinInput{GroupID: group.ID, PrincipalName: "path-worker", EndpointName: "path-worker", Harness: "codex", NativeSessionID: "path-session", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	actor = grantArtifactRole(t, persistence, actor, "artifact.read", "artifact.publish")
	if _, err := persistence.CreateArtifactRefV2(store.ArtifactRefV2Input{ArtifactID: legacy.ID,
		GroupID: actor.GroupID, ProducerPrincipalID: actor.PrincipalID,
		ProducerEndpointID: actor.EndpointID, Scopes: []string{store.ArtifactRefV2ScopeMetadata}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateArtifactRefV2(actor, store.ArtifactRefV2Input{ArtifactID: legacy.ID, WorkspaceID: workspace.ID, Digest: artifactTestDigest(content), RelativePath: "../secret.txt", Scopes: []string{store.ArtifactRefV2ScopeContent}}); !errors.Is(err, store.ErrArtifactRefV2UnsafePath) && !errors.Is(err, ErrArtifactV2PathTraversal) {
		t.Fatalf("traversal path accepted: %v", err)
	}
	ref, err := service.CreateArtifactRefV2(actor, store.ArtifactRefV2Input{ArtifactID: legacy.ID, WorkspaceID: workspace.ID, Digest: artifactTestDigest(content), RelativePath: "link.txt", Scopes: []string{store.ArtifactRefV2ScopeContent}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadArtifactRefV2(actor, ArtifactRefReadInput{ArtifactRefID: ref.ID, Scopes: []string{store.ArtifactRefV2ScopeContent}}); !errors.Is(err, ErrArtifactV2SymlinkEscape) {
		t.Fatalf("symlink escape was read: %v", err)
	}
}
