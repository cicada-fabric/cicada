package control

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestGroupManagementCreatesExplicitMembershipWithoutExecutionRole(t *testing.T) {
	root := t.TempDir()
	manager, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())

	group, err := manager.CreateGroup(GroupCreateInput{Name: "kernel", Purpose: "bounded collaboration"})
	if err != nil {
		t.Fatal(err)
	}
	if group.State != store.GroupStateActive || group.ExternalMode != "monitor_mediated" {
		t.Fatalf("unexpected group: %#v", group)
	}
	ownerMembership, err := manager.store.GetMembershipByPrincipalGroup(manager.Identity().ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ownerMembership.Role != "owner" {
		t.Fatalf("owner role = %q", ownerMembership.Role)
	}

	membership, err := manager.AddGroupMember(group.ID, GroupMemberInput{Name: "optimizer"})
	if err != nil {
		t.Fatal(err)
	}
	if membership.Role != "member" {
		t.Fatalf("join granted execution role %q", membership.Role)
	}
	if _, err := manager.AddGroupMember(group.ID, GroupMemberInput{Name: "not-a-role-binding", Role: "monitor"}); err == nil {
		t.Fatal("plain membership accepted a monitor role")
	}

	revoked, err := manager.RevokeGroupMember(group.ID, membership.ID, "test revoke")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != store.MembershipStatusRevoked {
		t.Fatalf("membership status = %q", revoked.Status)
	}
}

func TestMembershipRoleBindingIsExplicitVersionedAndPreservesMessageGrants(t *testing.T) {
	root := t.TempDir()
	manager, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())

	group, err := manager.CreateGroup(GroupCreateInput{Name: "role-binding"})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := manager.AddGroupMember(group.ID, GroupMemberInput{Name: "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	version := membership.Version
	bound, err := manager.BindMembershipRole(group.ID, membership.ID, "monitor", version)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Role != "monitor" || !containsGrant(bound.Grants, "federation.represent") {
		t.Fatalf("monitor binding missing role grant: %#v", bound)
	}
	for _, grant := range []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"} {
		if !containsGrant(bound.Grants, grant) {
			t.Fatalf("monitor binding dropped message grant %q: %#v", grant, bound.Grants)
		}
	}
	if _, err := manager.BindMembershipRole(group.ID, membership.ID, "worker", version); err != store.ErrVersionConflict {
		t.Fatalf("stale role binding error=%v, want version conflict", err)
	}
	worker, err := manager.BindMembershipRole(group.ID, membership.ID, "worker", bound.Version)
	if err != nil {
		t.Fatal(err)
	}
	if worker.Role != "worker" || !containsGrant(worker.Grants, "federation.request") || !containsGrant(worker.Grants, "federation.produce") || containsGrant(worker.Grants, "federation.represent") {
		t.Fatalf("worker binding grants are wrong: %#v", worker)
	}
}

func containsGrant(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
