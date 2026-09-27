package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFabricV2IdentityBindingAndFencing(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state", "cicada.sqlite3")
	persistence, err := New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	endpoint, err := persistence.UpsertEndpoint(Endpoint{
		ID: "ep_legacy", Name: "optimizer", Role: "thread", Harness: "codex",
		NativeSessionID: "native-optimizer", MachineID: "node-a", Workspace: "/ws/a",
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := persistence.GetEndpointV2(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ID != "ep_legacy" || legacy.NativeSessionID != "native-optimizer" || legacy.MigrationState != EndpointMigrationPendingGroup {
		t.Fatalf("legacy endpoint was not preserved as pending migration: %#v", legacy)
	}

	principal, err := persistence.CreatePrincipal(Principal{
		ID: "pr_optimizer", Kind: PrincipalKindAgent, Name: "optimizer",
		CredentialHash: HashCredential([]byte("enrollment-secret")),
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(Group{
		ID: "grp_kernel", OwnerPrincipalID: principal.ID, Name: "kernel",
		State: GroupStateActive, Purpose: "kernel optimization",
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := persistence.CreateMembership(Membership{
		PrincipalID: principal.ID, GroupID: group.ID, Role: "worker",
		Roles: []string{"worker"}, Grants: []string{"message.send", "message.receive"},
		Authorization: map[string]any{"scope": "group"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if membership.Status != MembershipStatusActive || membership.Role != "worker" || len(membership.Grants) != 2 {
		t.Fatalf("unexpected membership: %#v", membership)
	}

	binding, err := persistence.CreateSessionBinding(SessionBinding{
		ID: "bind_optimizer", EndpointID: endpoint.ID, PrincipalID: principal.ID,
		GroupID: group.ID, NativeSessionID: endpoint.NativeSessionID, NodeID: "node-a",
		WorkspaceID: "workspace-a", CredentialHash: HashCredential([]byte("binding-secret")),
		ContextContinuity: "native_resume",
	})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Epoch != 1 || binding.Version != 1 || binding.CredentialHash == "binding-secret" || binding.CredentialHash == "" {
		t.Fatalf("binding fields/credential policy are wrong: %#v", binding)
	}
	if got, err := persistence.GetSessionBindingByCredentialHash(binding.CredentialHash); err != nil || got.ID != binding.ID {
		t.Fatalf("credential hash lookup failed: %#v err=%v", got, err)
	}
	associated, err := persistence.GetEndpointV2(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if associated.PrincipalID != principal.ID || associated.GroupID != group.ID || associated.BindingID != binding.ID || associated.MigrationState != EndpointMigrationReady {
		t.Fatalf("endpoint association was not persisted: %#v", associated)
	}

	rejoined, err := persistence.CreateSessionBinding(SessionBinding{
		EndpointID: endpoint.ID, PrincipalID: principal.ID, GroupID: group.ID,
		NativeSessionID: endpoint.NativeSessionID, NodeID: "node-a",
		CredentialHash: binding.CredentialHash,
	})
	if err != nil || rejoined.ID != binding.ID {
		t.Fatalf("same verified session was not idempotent: %#v err=%v", rejoined, err)
	}

	leaseExpiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	leased, err := persistence.AcquireSessionBindingLease(binding.ID, "adapter-a", binding.Epoch, leaseExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if leased.Status != SessionBindingStatusLeased || leased.LeaseOwner != "adapter-a" || leased.Epoch != binding.Epoch+1 {
		t.Fatalf("unexpected acquired lease: %#v", leased)
	}
	if _, err := persistence.AcquireSessionBindingLease(binding.ID, "adapter-b", binding.Epoch, leaseExpiry); !errors.Is(err, ErrSessionBindingStaleEpoch) {
		t.Fatalf("stale owner epoch was accepted: %v", err)
	}
	if _, err := persistence.AcquireSessionBindingLease(binding.ID, "adapter-b", leased.Epoch, leaseExpiry); !errors.Is(err, ErrSessionBindingLeaseHeld) {
		t.Fatalf("active lease was stolen: %v", err)
	}
	renewed, err := persistence.RenewSessionBindingLease(binding.ID, "adapter-a", leased.Epoch, leaseExpiry)
	if err != nil || renewed.Epoch != leased.Epoch || renewed.Version <= leased.Version {
		t.Fatalf("lease renewal did not fence/version correctly: %#v err=%v", renewed, err)
	}
	released, err := persistence.ReleaseSessionBindingLease(binding.ID, "adapter-a", renewed.Epoch)
	if err != nil || released.Status != SessionBindingStatusActive || released.LeaseOwner != "" || released.Epoch != renewed.Epoch+1 {
		t.Fatalf("lease release did not fence old owner: %#v err=%v", released, err)
	}
	if err := persistence.ValidateSessionBindingLease(binding.ID, "adapter-a", renewed.Epoch); !errors.Is(err, ErrSessionBindingStaleEpoch) {
		t.Fatalf("released epoch remained valid: %v", err)
	}
	oldHash := binding.CredentialHash
	newHash := HashCredential([]byte("rotated-binding-secret"))
	rotated, err := persistence.RotateSessionBindingCredential(binding.ID, released.Epoch, newHash, "adapter-b", leaseExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.EndpointID != binding.EndpointID || rotated.NativeSessionID != binding.NativeSessionID || rotated.CredentialHash != newHash || rotated.CredentialHashVersion != binding.CredentialHashVersion+1 || rotated.Epoch != released.Epoch+1 || rotated.Version <= released.Version {
		t.Fatalf("credential rotation did not preserve/fence binding: %#v", rotated)
	}
	if _, err := persistence.GetSessionBindingByCredentialHash(oldHash); !errors.Is(err, ErrSessionBindingNotFound) {
		t.Fatalf("old credential hash remained usable: %v", err)
	}
	if err := persistence.ValidateSessionBindingLease(binding.ID, "adapter-b", released.Epoch); !errors.Is(err, ErrSessionBindingStaleEpoch) {
		t.Fatalf("pre-rotation epoch remained valid: %v", err)
	}
	if current, err := persistence.GetSessionBindingByCredentialHash(newHash); err != nil || current.ID != binding.ID {
		t.Fatalf("new credential hash was not indexed: %#v err=%v", current, err)
	}

	revoked, err := persistence.RevokeMembership(membership.ID, "operator revoked")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != MembershipStatusRevoked {
		t.Fatalf("membership was not revoked: %#v", revoked)
	}
	fenced, err := persistence.GetSessionBinding(binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fenced.Status != SessionBindingStatusRevoked || fenced.Epoch != rotated.Epoch+1 {
		t.Fatalf("membership revocation did not fence binding: %#v", fenced)
	}
	if _, err := persistence.AcquireSessionBindingLease(binding.ID, "adapter-a", fenced.Epoch, leaseExpiry); !errors.Is(err, ErrSessionBindingInactive) {
		t.Fatalf("revoked binding accepted lease: %v", err)
	}
}

func TestFabricV2LegacyEndpointMigrationIsAdditiveAndRepeatable(t *testing.T) {
	stateDir := t.TempDir()
	statePath := filepath.Join(stateDir, "legacy.sqlite3")
	db, err := sql.Open("sqlite", statePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE fabric_endpoints (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'thread',
  harness TEXT NOT NULL DEFAULT 'codex',
  native_session_id TEXT NOT NULL DEFAULT '',
  machine_id TEXT NOT NULL DEFAULT '',
  workspace TEXT NOT NULL DEFAULT '',
  goal_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'online',
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  tags_json TEXT NOT NULL DEFAULT '[]',
  owner TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'private',
  joined_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO fabric_endpoints
(id, name, role, harness, native_session_id, machine_id, workspace, goal_id,
 status, capabilities_json, tags_json, owner, visibility, joined_at, last_seen,
 created_at, updated_at)
VALUES ('ep_old', 'old', 'thread', 'codex', 'native-old', 'node-old', '/old',
 '', 'online', '{}', '[]', 'owner-old', 'private', '2026-01-01T00:00:00Z',
 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	persistence, err := New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	old, err := persistence.GetEndpointV2("ep_old")
	if err != nil {
		t.Fatal(err)
	}
	if old.ID != "ep_old" || old.NativeSessionID != "native-old" || old.Owner != "owner-old" || old.MigrationState != EndpointMigrationPendingGroup {
		t.Fatalf("legacy endpoint data or marker changed: %#v", old)
	}
	var groups int
	if err := persistence.db.QueryRow(`SELECT COUNT(*) FROM groups`).Scan(&groups); err != nil {
		t.Fatal(err)
	}
	if groups != 0 {
		t.Fatalf("legacy endpoint migration invented a Group: %d", groups)
	}
	if pending, err := persistence.ListPendingEndpointMigrations(10); err != nil || len(pending) != 1 || pending[0].ID != "ep_old" {
		t.Fatalf("pending endpoint inventory incorrect: %#v err=%v", pending, err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}

	// A second open must be a no-op migration and preserve the same old row.
	persistence, err = New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	again, err := persistence.GetEndpointV2("ep_old")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != old.ID || again.NativeSessionID != old.NativeSessionID || again.MigrationState != EndpointMigrationPendingGroup {
		t.Fatalf("repeatable migration changed legacy endpoint: %#v", again)
	}
}
