package n3_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

type nodePairExistingBasis struct {
	ownerBinding, keyBinding, credential string
	clientRequest, clientResponse        uint64
	grants, provenance                   int
}

func (v *nodePairFixture) existingBasis(t *testing.T) nodePairExistingBasis {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	defer db.Close()
	var basis nodePairExistingBasis
	// Full immutable rows, not a projection invented by the acceptance driver.
	for _, q := range []struct {
		query string
		out   *string
	}{
		{`SELECT json_object('id',id,'owner_id',owner_id,'hub_id',hub_id,'node_id',node_id,'node_name',node_name,'client_device_id',client_device_id,'owner_key_id',owner_key_id,'credential_digest',node_credential_digest,'credential_version',node_credential_version,'state',state,'version',version,'created_at',created_at,'revoked_at',revoked_at) FROM node_owner_bindings_v2 WHERE node_id=?`, &basis.ownerBinding},
		{`SELECT json_object('binding_id',owner_binding_id,'owner_id',owner_id,'hub_id',hub_id,'node_id',node_id,'credential_digest',node_credential_digest,'credential_version',node_credential_version,'node_key_id',node_key_id,'node_key_version',node_key_version,'node_key_epoch',node_key_epoch,'node_public',node_public_identity_json,'hub_public',hub_public_identity_json,'hub_key_version',hub_key_version,'approved_request_id',approved_request_id,'approved_request_version',approved_request_version,'approved_candidate_digest',approved_candidate_digest,'state',state,'version',version,'approved_at',approved_at,'revoked_at',revoked_at) FROM node_control_key_bindings_v1 WHERE node_id=?`, &basis.keyBinding},
		{`SELECT json_object('hash',credential_hash,'version',version,'status',status) FROM fabric_node_credentials WHERE node_id=?`, &basis.credential},
	} {
		if db.QueryRow(q.query, v.node.id).Scan(q.out) != nil {
			t.Fatal("original retained binding/credential immutable row is unavailable")
		}
	}
	if db.QueryRow(`SELECT last_request_sequence,next_response_sequence FROM client_devices_v2 WHERE owner_id=? AND device_id=?`, v.original.Account.OwnerID, v.original.Account.DeviceID).Scan(&basis.clientRequest, &basis.clientResponse) != nil ||
		db.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1 WHERE owner_id=?`, v.original.Account.OwnerID).Scan(&basis.grants) != nil ||
		db.QueryRow(`SELECT count(*) FROM hub_app_node_provenance_v1 WHERE owner_id=?`, v.original.Account.OwnerID).Scan(&basis.provenance) != nil {
		t.Fatal("retained original App counters/grants/provenance are unavailable")
	}
	return basis
}

func nodePairExistingBindingTrustOnly(t *testing.T) {
	// The advanced explicitly pinned legacy path is used only to create the
	// genuine old 14-field local subset with no independent Owner pin. It is
	// historical migration input, never the default new onboarding procedure.
	old := newDirectIPNodeFixture(t, "127.0.0.1")
	old.node.kill(t)
	v := &nodePairFixture{hub: old.hub, app: old.app, original: old.original, node: old.node,
		binary: filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(old.hub.binary))), "node", "bin", "cicada"),
		home:   old.home, state: old.state, userRoot: filepath.Join(old.home, ".cicada"), mode: wire.NodePairTrustExisting}
	v.environment = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + v.home, "LANG=C.UTF-8", "TMPDIR=" + filepath.Join(old.root, "tmp")}
	localPath := v.node.statePath()
	var originalState struct {
		NodeID       string                     `json:"node_id"`
		BindingID    string                     `json:"binding_id"`
		OwnerBinding map[string]json.RawMessage `json:"binding"`
		Transport    string                     `json:"hub_transport_descriptor"`
		PairAttempt  string                     `json:"node_pair_trust_attempt_id"`
	}
	raw := readPrivate(t, localPath)
	if json.Unmarshal(raw, &originalState) != nil || originalState.NodeID != v.node.id || originalState.BindingID != old.bound.BindingID ||
		originalState.Transport == "" || originalState.PairAttempt != "" {
		clear(raw)
		t.Fatal("trust-only test did not retain a genuine known-transport old Node binding")
	}
	clear(raw)
	keyPath := filepath.Join(filepath.Dir(localPath), "node-control-identity.bin")
	keyBefore := hash(readPrivate(t, keyPath))
	basis := v.existingBasis(t)
	crypto := must(nodekeys.OpenCryptoState(filepath.Dir(localPath)))
	if _, err := crypto.GetNodeOwnerKeyTrustLocal(v.original.Account.OwnerID, v.original.Account.LocalOwnerKeyID); err != nodekeys.ErrNodeOwnerKeyTrustNotFound {
		crypto.Close()
		t.Fatal("legacy migration fixture already has the independent Owner pin it is meant to establish")
	}
	other := must(e2ee.NewIdentity())
	tombstone := must(crypto.TrustOwnerApprovalKeyLocal("synthetic-unrelated-old-owner", other.Public().ID, other.Public(), must(nodekeys.PeerKeyFingerprint(other.Public()))))
	tombstone = must(crypto.RevokeNodeOwnerKeyTrustLocal(tombstone.OwnerID, tombstone.KeyID, tombstone.Version))
	crypto.Close()
	if _, err := os.Stat(filepath.Join(filepath.Dir(localPath), "node-pair-trust.sealed.json")); !os.IsNotExist(err) {
		t.Fatal("old-subset migration fixture unexpectedly has a new pairing attempt")
	}
	v.start(t)
	v.awaitCommittedCandidate(t)
	v.readCode(t)
	c, _ := v.side(t)
	if c.Mode != wire.NodePairTrustExisting || c.Candidate != nil || c.Binding == nil || c.Binding.OwnerBindingID != old.bound.BindingID ||
		c.Binding.NodePublic.ID != old.bound.NodeKeyID || c.Binding.NodeKeyEpoch != old.bound.NodeKeyEpoch {
		t.Fatal("old local subset was reconstructed into a different binding or an INITIAL candidate")
	}
	review := v.action(t, appcore.Action{Kind: appcore.ActionReviewNodePairing, DevicePairingCode: v.code})
	if review.Node.Pairing == nil || review.Node.Pairing.State != "REVIEW" || review.Node.Pairing.ReviewID == "" {
		t.Fatal("actual App did not review its retained same-Owner existing binding")
	}
	approved := v.action(t, appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: review.Node.Pairing.ReviewID, ConfirmNodePairing: true})
	if approved.Node.Pairing == nil || approved.Node.Pairing.State != wire.NodePairTrustOwnerApproved {
		t.Fatal("actual App did not keep trust-only Owner approval separate from Node ACK")
	}
	s := v.awaitACK(t)
	if s.Node.Binding.ID != old.bound.BindingID || s.Node.Binding.Version != old.bound.BindingVersion || v.existingBasis(t) != basis ||
		hash(readPrivate(t, keyPath)) != keyBefore {
		t.Fatal("trust-only onboarding replaced the original binding/credential/key/epochs/counters or minted another grant")
	}
	v.assertAutomaticOwnerPin(t, s)
	v.node.kill(t)
	crypto = must(nodekeys.OpenCryptoState(filepath.Dir(localPath)))
	defer crypto.Close()
	retained := must(crypto.GetNodeOwnerKeyTrustLocal(tombstone.OwnerID, tombstone.KeyID))
	if !reflect.DeepEqual(retained, tombstone) {
		t.Fatal("trust-only onboarding reset an unrelated original revocation tombstone")
	}
	nodePairFacts(t, "NPT11_ExistingBindingTrustOnly", map[string]bool{"exact_original_binding_and_pin": true,
		"no_new_bearer_or_binding": true, "no_epoch_or_tombstone_reset": true, "no_business_grant": true})
}
