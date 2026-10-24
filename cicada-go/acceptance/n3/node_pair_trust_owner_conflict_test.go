package n3_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func nodePairOwnerPinConflict(t *testing.T) {
	for _, tombstone := range []bool{false, true} {
		v := newNodePairFixture(t, "127.0.0.1")
		v.node.kill(t)
		dir := filepath.Join(v.state, "nodes", "node-"+url.PathEscape(v.node.id))
		state := must(nodekeys.OpenCryptoState(dir))
		fake := must(e2ee.NewIdentity())
		if fake.Public().ID == v.original.Account.LocalOwnerKeyID {
			t.Fatal("negative Owner-conflict fixture did not choose another key ID")
		}
		trust := must(state.TrustOwnerApprovalKeyLocal(v.original.Account.OwnerID, fake.Public().ID,
			fake.Public(), must(nodekeys.PeerKeyFingerprint(fake.Public()))))
		if tombstone {
			trust = must(state.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version))
		}
		if state.Close() != nil {
			t.Fatal("owned conflicting public trust fixture did not close before actual Node restart")
		}
		// This manual public pin is an adversarial pre-existing conflict. It is
		// never a positive onboarding prerequisite or a replacement Owner key.
		v.approve(t)
		before := v.admission(t)
		v.start(t)
		db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
		deadline := time.Now().Add(15 * time.Second)
		delivered := false
		for time.Now().Before(deadline) {
			var count int
			if db.QueryRow(`SELECT count(*) FROM hub_node_pair_trust_receipts_v1 WHERE attempt_id=? AND operation=? AND state=?`,
				v.local.AttemptID, wire.OperationNodePairTrustPoll, wire.NodePairTrustOwnerApproved).Scan(&count) != nil {
				t.Fatal("actual Node conflict test could not observe original approval delivery")
			}
			if count > 0 {
				delivered = true
				break
			}
			if !v.node.running() {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		db.Close()
		if !delivered {
			t.Fatal("actual Node did not receive the original valid Owner approval in the conflict fixture")
		}
		time.Sleep(time.Second)
		if v.node.running() {
			v.node.kill(t)
		}
		after := v.admission(t)
		if after != before || after.state != wire.NodePairTrustOwnerApproved || after.ownerBindings != 0 || after.keyBindings != 0 {
			t.Fatal("actual Node ACKed or bound despite a pre-existing same-Owner different-key conflict")
		}
		local := nodePairReadOnlyDB(t, filepath.Join(dir, "node-crypto-state.sqlite"))
		rows := must(local.Query(`SELECT key_id,public_identity_json,fingerprint,state,version FROM node_crypto_owner_key_trust WHERE owner_id=?`, trust.OwnerID))
		count := 0
		for rows.Next() {
			var keyID, publicJSON, fp, status string
			var version int64
			if rows.Scan(&keyID, &publicJSON, &fp, &status, &version) != nil {
				t.Fatal("owned pre-existing Owner trust became unreadable")
			}
			var public e2ee.PublicIdentity
			if json.Unmarshal([]byte(publicJSON), &public) != nil || keyID != trust.KeyID || fp != trust.ExpectedFingerprint ||
				status != trust.State || version != trust.Version || public.ID != fake.Public().ID {
				t.Fatal("actual Node replaced/revived a conflicting ACTIVE or REVOKED Owner pin")
			}
			count++
		}
		if rows.Err() != nil || count != 1 {
			t.Fatal("actual Node added another same-Owner key while a conflicting public record existed")
		}
		rows.Close()
		local.Close()
	}
	nodePairConditionalOwnerWriter(t)
	nodePairFacts(t, "NPT10_OwnerPinConflict", map[string]bool{"same_Owner_different_key_ID_refused": true,
		"ACTIVE_and_REVOKED_pin_refused": true, "conditional_writer_rechecks_pin": true, "zero_new_pin_ACK_or_binding": true})
}

func nodePairConditionalOwnerWriter(t *testing.T) {
	dir := t.TempDir()
	a, b := must(nodekeys.OpenCryptoState(dir)), must(nodekeys.OpenCryptoState(dir))
	defer a.Close()
	defer b.Close()
	keys := []*e2ee.Identity{must(e2ee.NewIdentity()), must(e2ee.NewIdentity())}
	states := []*nodekeys.CryptoState{a, b}
	type conditionalWriter interface {
		TrustOwnerApprovalKeyForPairLocal(string, string, e2ee.PublicIdentity, string) (*nodekeys.OwnerKeyTrust, error)
	}
	writers := make([]conditionalWriter, len(states))
	for i, state := range states {
		var ok bool
		writers[i], ok = any(state).(conditionalWriter)
		if !ok {
			t.Fatal("formally delivered Node pair conditional Owner writer unavailable; full product acceptance NOT_RUN")
		}
	}
	type result struct {
		index int
		trust *nodekeys.OwnerKeyTrust
		err   error
	}
	start, done := make(chan struct{}), make(chan result, 2)
	for i := range keys {
		// Compute the independent expectation before either conditional writer.
		fp := must(nodekeys.PeerKeyFingerprint(keys[i].Public()))
		go func(i int, fp string) {
			<-start
			trust, err := writers[i].TrustOwnerApprovalKeyForPairLocal("synthetic-owner-concurrent-pin", keys[i].Public().ID, keys[i].Public(), fp)
			done <- result{i, trust, err}
		}(i, fp)
	}
	close(start)
	first, second := <-done, <-done
	if first.err != nil {
		first, second = second, first
	}
	if first.err != nil || first.trust == nil || second.trust != nil || !errors.Is(second.err, nodekeys.ErrNodeOwnerKeyTrustConflict) {
		t.Fatal("two independent conditional Owner writers did not serialize to one same-Owner key winner")
	}
	winner := must(states[first.index].GetNodeOwnerKeyTrustLocal(first.trust.OwnerID, first.trust.KeyID))
	if winner.State != nodekeys.NodeOwnerKeyTrustActive || winner.Version != 1 {
		t.Fatal("conditional Owner pin winner lost its original public state")
	}
	must(states[first.index].RevokeNodeOwnerKeyTrustLocal(winner.OwnerID, winner.KeyID, winner.Version))
	loser := keys[second.index].Public()
	if trust, err := writers[second.index].TrustOwnerApprovalKeyForPairLocal(winner.OwnerID, loser.ID, loser,
		must(nodekeys.PeerKeyFingerprint(loser))); trust != nil || !errors.Is(err, nodekeys.ErrNodeOwnerKeyTrustConflict) {
		t.Fatal("a revoked old key allowed the different-key conditional writer to reopen the same Owner")
	}
}
