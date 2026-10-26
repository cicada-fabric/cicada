package nodekeys

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestEndpointGroupsHeadAndContributionHighwater(t *testing.T) {
	initial := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	active := e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "NONE", PolicyID: strings.Repeat("1", 32), PolicyEpoch: 1}
	removed := active
	removed.Revision = 2
	removed.DenyReason = "REMOVED"
	for _, pair := range [][2]e2ee.EndpointGroupOwnerControl{{initial, active}, {active, removed}, {removed, removed}} {
		if err := compareEndpointGroupHead(pair[0], pair[1]); err != nil {
			t.Fatal("monotonic head rejected", err)
		}
	}
	for _, pair := range [][2]e2ee.EndpointGroupOwnerControl{{active, initial}, {removed, active}, {removed, {Mode: "OWNER", Revision: 2, DenyReason: "NONE", PolicyID: active.PolicyID, PolicyEpoch: 1}}, {removed, {Mode: "OWNER", Revision: 2, DenyReason: "REMOVED", PolicyID: strings.Repeat("2", 32), PolicyEpoch: 2}}} {
		if compareEndpointGroupHead(pair[0], pair[1]) == nil {
			t.Fatal("head rollback or same revision substitution accepted")
		}
	}
	old := wire.EndpointGroupRelation{HubID: "synthetic-hub", OwnerID: "synthetic-owner", NodeID: "synthetic-node", LocalUserScope: "uid:1000", NetworkID: "synthetic-network", GroupID: "synthetic-G1", EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-agent", RegistrationDigest: strings.Repeat("a", 64), RegistrationRevision: 1, Source: "DEFAULT_POLICY", AuthorityID: strings.Repeat("b", 32), AuthorityEpoch: 1, ContributionRevision: 4, State: "ACTIVE", BindingID: "synthetic-original-binding", BindingEpoch: 1, CandidateVersion: 1, CandidateKeyID: "synthetic-original-key", CandidateFingerprint: "sha256:" + strings.Repeat("c", 64), CandidateProofDigest: strings.Repeat("d", 64)}
	if err := compareEndpointGroupRelation(old, old, initial, initial); err != nil {
		t.Fatal(err)
	}
	for i, change := range []func(*wire.EndpointGroupRelation){func(r *wire.EndpointGroupRelation) { r.ContributionRevision-- }, func(r *wire.EndpointGroupRelation) { r.AuthorityID = strings.Repeat("c", 32) }, func(r *wire.EndpointGroupRelation) { r.CandidateKeyID = "synthetic-replacement-key" }, func(r *wire.EndpointGroupRelation) { r.BindingID = "synthetic-replacement-binding" }, func(r *wire.EndpointGroupRelation) { r.BindingEpoch++ }, func(r *wire.EndpointGroupRelation) { r.NetworkID = "synthetic-other-network" }, func(r *wire.EndpointGroupRelation) { r.RegistrationDigest = strings.Repeat("0", 64) }} {
		next := old
		change(&next)
		if compareEndpointGroupRelation(old, next, initial, initial) == nil {
			t.Fatalf("relation substitution %d accepted", i)
		}
	}
	// An unrelated source's aggregate revision is absent from this evidence.
	// Switching to a newly Owner-authorized source does not compare its counter
	// to the independent default contribution counter.
	next := old
	next.Source = "OWNER_EXPLICIT"
	next.AuthorityID = active.PolicyID
	next.AuthorityEpoch = active.PolicyEpoch
	next.ContributionRevision = 1
	if err := compareEndpointGroupRelation(old, next, initial, active); err != nil {
		t.Fatal("independent source counters were blended", err)
	}
}

func TestEndpointGroupsPrivateSchemaPreservesLegacyAndPermanentMarkers(t *testing.T) {
	s, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	r := wire.EndpointGroupRelation{HubID: "synthetic-hub", NetworkID: "synthetic-network", GroupID: "synthetic-G1", EndpointID: "synthetic-endpoint"}
	if err := s.writeTx(ctx, func(conn *sql.Conn) error { return rememberEndpointGroupsRequired(ctx, conn, r) }); err != nil {
		t.Fatal(err)
	}
	if yes, err := s.EndpointGroupsRequired(ctx, r.EndpointID, r.GroupID); err != nil || !yes {
		t.Fatal("marker not persisted", err)
	}
	if yes, err := s.EndpointGroupsRequired(ctx, "synthetic-other-endpoint", r.GroupID); err != nil || yes {
		t.Fatal("marker expanded to whole Group", err)
	}
	if _, err := s.db.Exec(`DELETE FROM node_endpoint_group_required_v1`); err == nil {
		t.Fatal("permanent marker erased")
	}
	if err := endpointGroupsLegacyAllowed(ctx, s.db, r.GroupID, r.EndpointID); !errors.Is(err, ErrEndpointGroupsPolicy) {
		t.Fatal("legacy entry bypassed Owner marker", err)
	}
	if err := endpointGroupsLegacyAllowed(ctx, s.db, r.GroupID, "synthetic-other-endpoint"); err != nil {
		t.Fatal("unrelated Endpoint blocked", err)
	}
	var version int
	if s.db.QueryRow(`SELECT version FROM node_crypto_schema`).Scan(&version) != nil || version != 8 {
		t.Fatal("private schema migration not completed")
	}
	var tables int
	if s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('node_crypto_replay','node_crypto_peer_pins','node_crypto_owner_key_trust','node_local_domain_local_keys_v1','node_native_pair_local_keys')`).Scan(&tables) != nil || tables != 5 {
		t.Fatal("legacy state missing after migration")
	}
	var rows int
	if s.db.QueryRow(`SELECT count(*) FROM node_crypto_owner_key_trust`).Scan(&rows) != nil || rows != 0 {
		t.Fatal("migration manufactured Owner trust")
	}
}
