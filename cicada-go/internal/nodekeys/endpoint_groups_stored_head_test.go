package nodekeys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func storedEndpointGroupHeadFixture(t *testing.T) *endpointGroupsKeyFixture {
	t.Helper()
	f := syntheticEndpointGroupsKeys(t, true, false)
	if err := f.x.f.state.RememberEndpointGroupGrant(context.Background(), f.x.f.hub, f.anchors[0], f.grants[0], f.heads[0], f.x.f.now); err != nil {
		t.Fatal("synthetic signed stored head", err)
	}
	return f
}
func storedEndpointGroupHeadReader(t *testing.T, f *endpointGroupsKeyFixture) *CryptoState {
	t.Helper()
	reader, err := OpenExistingCryptoState(context.Background(), f.x.f.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	return reader
}
func TestReadEndpointGroupStoredOwnerHeadNormalExistingReadIsUnchanged(t *testing.T) {
	f := storedEndpointGroupHeadFixture(t)
	reader := storedEndpointGroupHeadReader(t, f)
	before := runtimeTrustTree(t, f.x.f.root)
	got, err := reader.ReadEndpointGroupStoredOwnerHead(context.Background(), f.x.f.hub, f.anchors[0], f.grants[0].Relation.GroupID)
	if err != nil || got != f.heads[0] {
		t.Fatal("stored original head unavailable", err)
	}
	if after := runtimeTrustTree(t, f.x.f.root); after != before {
		t.Fatal("stored head read changed existing private files")
	}
	// query_only on this dedicated handle independently rejects any write path.
	if _, err = reader.db.Exec(`UPDATE node_crypto_schema SET version=version`); err == nil {
		t.Fatal("existing-only reader became writable")
	}
	if got, err = f.x.f.state.ReadEndpointGroupStoredOwnerHead(context.Background(), f.x.f.hub, f.anchors[0], f.grants[0].Relation.GroupID); !errors.Is(err, ErrEndpointGroupsPolicy) || got != (e2ee.EndpointGroupOwnerControl{}) {
		t.Fatal("writer handle accepted by existing-only API", err)
	}
}
func TestReadEndpointGroupStoredOwnerHeadTerminalRetainsOldIdentity(t *testing.T) {
	for _, deny := range []string{"REMOVED", "EXPIRED"} {
		t.Run(deny, func(t *testing.T) {
			f := storedEndpointGroupHeadFixture(t)
			a := f.anchors[0]
			group := f.grants[0].Relation.GroupID
			terminal := f.heads[0]
			terminal.Revision++
			terminal.DenyReason = deny
			if err := f.x.f.state.ObserveEndpointGroupOwnerControl(context.Background(), a, group, terminal, f.x.f.now); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			if err := f.x.f.state.db.QueryRow(`SELECT identity_json FROM node_endpoint_group_heads_v1 WHERE endpoint_id=? AND group_id=?`, a.Registration.EndpointID, group).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var old wire.EndpointGroupRelation
			if json.Unmarshal(raw, &old) != nil || old.DecisionRevision == terminal.Revision {
				t.Fatal("fixture did not retain previous ACTIVE identity")
			}
			reader := storedEndpointGroupHeadReader(t, f)
			before := runtimeTrustTree(t, f.x.f.root)
			got, err := reader.ReadEndpointGroupStoredOwnerHead(context.Background(), f.x.f.hub, a, group)
			if err != nil || got != terminal {
				t.Fatal("valid terminal head required old identity to be rewritten", err)
			}
			if after := runtimeTrustTree(t, f.x.f.root); after != before {
				t.Fatal("terminal read advanced state")
			}
		})
	}
}
func TestReadEndpointGroupStoredOwnerHeadRequiresExistingRegistrationHeadAndTrust(t *testing.T) {
	for _, kind := range []string{"registration_missing", "head_missing", "trust_missing", "trust_revoked"} {
		t.Run(kind, func(t *testing.T) {
			f := storedEndpointGroupHeadFixture(t)
			a := f.anchors[0]
			group := f.grants[0].Relation.GroupID
			writer := f.x.f.state
			switch kind {
			case "registration_missing":
				a.Registration.EndpointID = "synthetic-unregistered-endpoint"
				var err error
				a.RegistrationDigest, err = e2ee.EndpointGroupRegistrationDigest(a.Registration)
				if err != nil {
					t.Fatal(err)
				}
			case "head_missing":
				group = "synthetic-group-with-no-head"
			case "trust_missing":
				if _, err := writer.db.Exec(`DELETE FROM node_crypto_owner_key_trust WHERE owner_id=?`, a.Registration.OwnerID); err != nil {
					t.Fatal(err)
				}
			case "trust_revoked":
				if _, err := writer.RevokeNodeOwnerKeyTrustLocal(a.Registration.OwnerID, f.x.f.owner.Public().ID, 1); err != nil {
					t.Fatal(err)
				}
			}
			reader := storedEndpointGroupHeadReader(t, f)
			before := runtimeTrustTree(t, f.x.f.root)
			got, err := reader.ReadEndpointGroupStoredOwnerHead(context.Background(), f.x.f.hub, a, group)
			if err == nil || got != (e2ee.EndpointGroupOwnerControl{}) {
				t.Fatal("missing or revoked prerequisite manufactured a stored head")
			}
			if (kind == "registration_missing" || kind == "head_missing") && !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("missing original row was not reported", err)
			}
			if after := runtimeTrustTree(t, f.x.f.root); after != before {
				t.Fatal("failed read initialized or repaired private state")
			}
		})
	}
}
func TestReadEndpointGroupStoredOwnerHeadRejectsScopeHeadAndDigestCorruption(t *testing.T) {
	for _, kind := range []string{"identity_scope", "identity_candidate", "identity_group", "identity_json", "head_json", "head_shape", "head_digest", "terminal_digest_from_old_identity", "anchor_binding"} {
		t.Run(kind, func(t *testing.T) {
			f := storedEndpointGroupHeadFixture(t)
			a := f.anchors[0]
			group := f.grants[0].Relation.GroupID
			writer := f.x.f.state
			var raw []byte
			var field string
			identity := f.grants[0].Relation
			switch kind {
			case "identity_scope":
				identity.NodeID = "synthetic-other-node"
				raw, _ = json.Marshal(identity)
				field = "identity_json"
			case "identity_candidate":
				identity.CandidateProofDigest = strings.Repeat("0", 64)
				raw, _ = json.Marshal(identity)
				field = "identity_json"
			case "identity_group":
				identity.GroupID = "synthetic-other-group"
				raw, _ = json.Marshal(identity)
				field = "identity_json"
			case "identity_json":
				raw = []byte(`{"broken":`)
				field = "identity_json"
			case "head_json":
				raw = []byte(`{"broken":`)
				field = "head_json"
			case "head_shape":
				bad := f.heads[0]
				bad.Mode = "DEFAULT"
				raw, _ = json.Marshal(bad)
				field = "head_json"
			case "head_digest":
				raw = []byte(strings.Repeat("0", 64))
				field = "head_digest"
			case "terminal_digest_from_old_identity":
				terminal := f.heads[0]
				terminal.Revision++
				terminal.DenyReason = "REMOVED"
				if err := writer.ObserveEndpointGroupOwnerControl(context.Background(), a, group, terminal, f.x.f.now); err != nil {
					t.Fatal(err)
				}
				raw = []byte(f.grants[0].Relation.OwnerControlDigest)
				field = "head_digest"
			case "anchor_binding":
				a.BindingEpoch++
			}
			if field != "" {
				if _, err := writer.db.Exec(`UPDATE node_endpoint_group_heads_v1 SET `+field+`=? WHERE endpoint_id=? AND group_id=?`, raw, a.Registration.EndpointID, group); err != nil {
					t.Fatal(err)
				}
			}
			reader := storedEndpointGroupHeadReader(t, f)
			before := runtimeTrustTree(t, f.x.f.root)
			got, err := reader.ReadEndpointGroupStoredOwnerHead(context.Background(), f.x.f.hub, a, group)
			if err == nil || got != (e2ee.EndpointGroupOwnerControl{}) {
				t.Fatal("corrupt stored scope/control evidence returned a head")
			}
			if after := runtimeTrustTree(t, f.x.f.root); after != before {
				t.Fatal("corruption was silently repaired")
			}
		})
	}
}
func TestReadEndpointGroupStoredOwnerHeadNeverCreatesOrMigrates(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "synthetic-absent-state")
	if _, err := OpenExistingCryptoState(ctx, root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing private directory created")
	}
	f := storedEndpointGroupHeadFixture(t)
	if err := f.x.f.state.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(f.x.f.root, cryptoStateDBName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE node_crypto_schema SET version=7`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before := runtimeTrustTree(t, f.x.f.root)
	if reader, err := OpenExistingCryptoState(ctx, f.x.f.root); err == nil {
		reader.Close()
		t.Fatal("existing-only reader migrated an old schema")
	}
	if after := runtimeTrustTree(t, f.x.f.root); after != before {
		t.Fatal("opening unsupported existing state changed files")
	}
}
