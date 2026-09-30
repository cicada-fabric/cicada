package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// These identities and enrollments are synthetic and never leave the test DB.
type groupSpaceTestFixture struct {
	sealed    *sameGroupSealedV1Fixture
	networkID string
}

func newGroupSpaceTestFixture(t *testing.T) *groupSpaceTestFixture {
	t.Helper()
	f, networkID := mappedSealedFixture(t)
	for _, endpoint := range []sameGroupSealedV1EndpointFixture{f.source, f.target, f.sameNode} {
		membership, err := f.store.GetMembershipByPrincipalGroup(endpoint.principal, f.groupID)
		if err != nil {
			t.Fatal(err)
		}
		grants := []string{"space.read"}
		if endpoint.id == f.source.id {
			grants = append(grants, "space.write", "space.moderate")
		}
		if _, err := f.store.UpdateMembershipAuthorization(membership.ID, membership.Roles,
			grants, membership.Authorization, membership.Version); err != nil {
			t.Fatal(err)
		}
		f.grant(t, endpoint.id)
	}
	return &groupSpaceTestFixture{sealed: f, networkID: networkID}
}

func (f *groupSpaceTestFixture) actor(t *testing.T, endpoint sameGroupSealedV1EndpointFixture) GroupSpaceActor {
	t.Helper()
	m, err := f.sealed.store.GetMembershipByPrincipalGroup(endpoint.principal, f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	nodeCredential := f.sealed.sourceNode.nodeCredential
	if endpoint.nodeID == f.sealed.target.nodeID {
		nodeCredential = f.sealed.targetNode.nodeCredential
	}
	return GroupSpaceActor{Scope: NativeActorScope{
		PrincipalID: endpoint.principal, EndpointID: endpoint.id, GroupID: f.sealed.groupID,
		NetworkID: f.networkID, MembershipID: m.ID, MembershipRevision: m.Revision,
		BindingID: endpoint.binding.ID, BindingEpoch: endpoint.binding.Epoch,
		LeaseOwner: endpoint.binding.LeaseOwner}, NodeCredentialDigest: nodeCredential}
}

func (f *groupSpaceTestFixture) prepare(t *testing.T, operationID, kind string) *GroupSpaceSnapshot {
	t.Helper()
	snapshot, err := f.sealed.store.PrepareGroupSpaceWrite(f.actor(t, f.sealed.source),
		GroupSpacePrepareInput{GroupID: f.sealed.groupID, OperationID: operationID, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *groupSpaceTestFixture) sealedInput(t *testing.T, snapshot *GroupSpaceSnapshot, body []byte) GroupSpaceCommitInput {
	t.Helper()
	if len(snapshot.Readers) != 3 {
		t.Fatalf("want exact three readers, got %d", len(snapshot.Readers))
	}
	base := GroupSpaceReaderContext(*snapshot, snapshot.Readers[0])
	inner, err := e2ee.SignGroupSpaceBody(f.sealed.source.identity, base, body)
	if err != nil {
		t.Fatal(err)
	}
	input := GroupSpaceCommitInput{ReservationID: snapshot.ReservationID}
	for i, reader := range snapshot.Readers {
		wire, err := e2ee.SealGroupSpaceReader(f.sealed.source.identity, reader.PublicIdentity,
			GroupSpaceReaderContext(*snapshot, reader), inner, uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		input.ReaderCiphertexts = append(input.ReaderCiphertexts, GroupSpaceReaderCiphertext{
			EndpointID: reader.EndpointID, KeyID: reader.KeyID, Wire: wire})
	}
	return input
}

func (f *groupSpaceTestFixture) commit(t *testing.T, snapshot *GroupSpaceSnapshot, body []byte) (*GroupSpaceRecord, GroupSpaceCommitInput) {
	t.Helper()
	input := f.sealedInput(t, snapshot, body)
	record, err := f.sealed.store.CommitGroupSpaceWrite(f.actor(t, f.sealed.source), input)
	if err != nil {
		t.Fatal(err)
	}
	return record, input
}

func TestGroupSpaceOfflineReaderAndTopicIdempotency(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	// Only the producer needs a live native lease. An enrolled reader can be
	// offline while the durable board item is encrypted for its Owner key.
	if _, err := f.sealed.store.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), f.sealed.target.binding.ID); err != nil {
		t.Fatal(err)
	}
	snapshot := f.prepare(t, "synthetic_topic_retry", GroupSpaceKindTopic)
	retry := f.prepare(t, "synthetic_topic_retry", GroupSpaceKindTopic)
	if retry.RecordID != snapshot.RecordID || retry.ReservationID != snapshot.ReservationID || retry.TopicID != snapshot.RecordID {
		t.Fatalf("topic retry changed reservation: first=%#v retry=%#v", snapshot, retry)
	}
	record, input := f.commit(t, snapshot, []byte("synthetic offline reader topic"))
	repeated, err := f.sealed.store.CommitGroupSpaceWrite(f.actor(t, f.sealed.source), input)
	if err != nil || repeated.Snapshot.RecordID != record.Snapshot.RecordID ||
		!bytes.Equal(repeated.ReaderCiphertext.Wire, record.ReaderCiphertext.Wire) {
		t.Fatalf("lost Commit response retry failed: record=%#v err=%v", repeated, err)
	}
	if _, err := f.sealed.store.GetGroupSpace(f.actor(t, f.sealed.target), GroupSpaceGetInput{
		GroupID: f.sealed.groupID, RecordID: record.Snapshot.RecordID}); !errors.Is(err, ErrGroupSpaceDenied) {
		t.Fatalf("expired reader native lease allowed read: %v", err)
	}
	if _, err := f.sealed.store.db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), f.sealed.target.binding.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.sealed.store.GetGroupSpace(f.actor(t, f.sealed.target), GroupSpaceGetInput{
		GroupID: f.sealed.groupID, RecordID: record.Snapshot.RecordID})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot.Readers) != 1 || got.Snapshot.Readers[0].EndpointID != f.sealed.target.id {
		t.Fatalf("read projection leaked other reader proof: %#v", got.Snapshot.Readers)
	}
	plaintext, _, err := e2ee.OpenGroupSpaceReader(f.sealed.target.identity,
		got.Snapshot.Producer.PublicIdentity, got.Snapshot.Producer.PublicIdentity,
		GroupSpaceReaderContext(got.Snapshot, got.Snapshot.Readers[0]), got.ReaderCiphertext.Wire)
	if err != nil || string(plaintext) != "synthetic offline reader topic" {
		t.Fatalf("offline catchup: %q %v", plaintext, err)
	}
}

func TestGroupSpaceNetworkRejoinDoesNotRestoreOldHistory(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	old, _ := f.commit(t, f.prepare(t, "synthetic_before_network_leave", GroupSpaceKindJournal), []byte("old private entry"))
	revokeSealedFixtureNetwork(t, f.sealed, f.networkID)
	if _, err := f.sealed.store.GetGroupSpace(f.actor(t, f.sealed.target), GroupSpaceGetInput{
		GroupID: f.sealed.groupID, RecordID: old.Snapshot.RecordID}); !errors.Is(err, ErrGroupSpaceDenied) {
		t.Fatalf("revoked Network reader retained history: %v", err)
	}
	rejoinSealedFixtureNetwork(t, f.sealed, f.networkID)
	// A fresh Network enrollment requires renewed Owner key consent, while
	// its new audience window still excludes the old sequence.
	f.sealed.grant(t, f.sealed.target.id)
	if _, err := f.sealed.store.GetGroupSpace(f.actor(t, f.sealed.target), GroupSpaceGetInput{
		GroupID: f.sealed.groupID, RecordID: old.Snapshot.RecordID}); !errors.Is(err, ErrGroupSpaceDenied) {
		t.Fatalf("Network rejoin revived pre-rejoin envelope: %v", err)
	}
	_, err := f.sealed.store.PrepareGroupSpaceWrite(f.actor(t, f.sealed.source), GroupSpacePrepareInput{
		GroupID: f.sealed.groupID, OperationID: "synthetic_after_network_rejoin", Kind: GroupSpaceKindJournal})
	if err != nil {
		t.Fatalf("Network rejoin blocked future board writes: %v", err)
	}
}

func TestGroupSpacePrepareRejectsWrongScopeAndInactiveAuthorization(t *testing.T) {
	for _, name := range []string{"other Group", "wrong Node", "stale binding", "expired grant", "future grant"} {
		t.Run(name, func(t *testing.T) {
			f := newGroupSpaceTestFixture(t)
			actor := f.actor(t, f.sealed.source)
			input := GroupSpacePrepareInput{GroupID: f.sealed.groupID, OperationID: "synthetic_denied", Kind: GroupSpaceKindJournal}
			switch name {
			case "other Group":
				input.GroupID = "grp_other"
			case "wrong Node":
				actor.NodeCredentialDigest = f.sealed.targetNode.nodeCredential
			case "stale binding":
				actor.Scope.BindingEpoch++
			case "expired grant":
				if _, err := f.sealed.store.db.Exec(`UPDATE memberships SET expires_at=? WHERE id=?`,
					time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), actor.Scope.MembershipID); err != nil {
					t.Fatal(err)
				}
			case "future grant":
				if _, err := f.sealed.store.db.Exec(`UPDATE memberships SET effective_at=? WHERE id=?`,
					time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), actor.Scope.MembershipID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.sealed.store.PrepareGroupSpaceWrite(actor, input); err == nil {
				t.Fatalf("%s prepared a record", name)
			}
		})
	}
}

func TestGroupSpaceCommitRechecksReaderAndTopicVersion(t *testing.T) {
	t.Run("reader revoked", func(t *testing.T) {
		f := newGroupSpaceTestFixture(t)
		snapshot := f.prepare(t, "synthetic_reader_revoke", GroupSpaceKindJournal)
		input := f.sealedInput(t, snapshot, []byte("must not publish"))
		m, err := f.sealed.store.GetMembershipByPrincipalGroup(f.sealed.target.principal, f.sealed.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.UpdateMembershipAuthorization(m.ID, m.Roles, []string{}, m.Authorization, m.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.CommitGroupSpaceWrite(f.actor(t, f.sealed.source), input); err == nil {
			t.Fatal("reader revoked after Prepare still received a committed envelope")
		}
		var state string
		if err := f.sealed.store.db.QueryRow(`SELECT state FROM group_space_records_v2 WHERE record_id=?`, snapshot.RecordID).Scan(&state); err != nil || state != "PREPARED" {
			t.Fatalf("revoked commit published record: state=%q err=%v", state, err)
		}
	})
	t.Run("topic compare and swap", func(t *testing.T) {
		f := newGroupSpaceTestFixture(t)
		topic, _ := f.commit(t, f.prepare(t, "synthetic_cas_topic", GroupSpaceKindTopic), []byte("topic"))
		prepareState := func(op string) *GroupSpaceSnapshot {
			s, err := f.sealed.store.PrepareGroupSpaceWrite(f.actor(t, f.sealed.source), GroupSpacePrepareInput{
				GroupID: f.sealed.groupID, OperationID: op, Kind: GroupSpaceKindTopicStatus,
				TopicID: topic.Snapshot.RecordID, ExpectedTopicVersion: 1, Status: "RESOLVED"})
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		first := prepareState("synthetic_cas_first")
		second := prepareState("synthetic_cas_second")
		f.commit(t, first, []byte("resolved"))
		if _, err := f.sealed.store.CommitGroupSpaceWrite(f.actor(t, f.sealed.source),
			f.sealedInput(t, second, []byte("stale status"))); !errors.Is(err, ErrGroupSpaceConflict) {
			t.Fatalf("stale status CAS: %v", err)
		}
		fresh, err := f.sealed.store.GetGroupSpace(f.actor(t, f.sealed.source), GroupSpaceGetInput{
			GroupID: f.sealed.groupID, RecordID: topic.Snapshot.RecordID})
		if err != nil || fresh.CurrentTopicVersion != 2 || fresh.CurrentTopicStatus != "RESOLVED" {
			t.Fatalf("topic current state: %#v err=%v", fresh, err)
		}
	})
}

func TestGroupSpaceCommittedQuotaRecheckedAfterReservations(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	first := f.prepare(t, "synthetic_quota_first", GroupSpaceKindJournal)
	second := f.prepare(t, "synthetic_quota_second", GroupSpaceKindJournal)
	// Populate a synthetic retained ledger directly to reach the boundary
	// without spending time or keys on 511 redundant encryptions.
	for i := 0; i < groupSpaceCommittedQuota-1; i++ {
		id := NewID("synthetic_quota")
		_, err := f.sealed.store.db.Exec(`INSERT INTO group_space_records_v2
(record_id,reservation_id,operation_id,group_id,network_id,hub_id,seq,kind,topic_id,corrects_id,
expected_topic_version,topic_status,retention_class,producer_endpoint_id,producer_principal_id,
snapshot_json,snapshot_digest,state,reserved_at,reservation_expires_at,committed_at,expires_at,ciphertext_digest,topic_version)
SELECT ?,?,?,?,?,?,?,'JOURNAL','','',0,'','standard',producer_endpoint_id,producer_principal_id,
'{}',snapshot_digest,'COMMITTED',reserved_at,reservation_expires_at,committed_at,expires_at,'synthetic',0
FROM group_space_records_v2 WHERE record_id=?`, id, NewID("synthetic_res"), NewID("synthetic_op"),
			f.sealed.groupID, f.networkID, first.HubID, 1000+i, first.RecordID)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.commit(t, first, []byte("fills row quota"))
	if _, err := f.sealed.store.CommitGroupSpaceWrite(f.actor(t, f.sealed.source),
		f.sealedInput(t, second, []byte("over quota"))); !errors.Is(err, ErrGroupSpaceLimit) {
		t.Fatalf("parallel reservation bypassed committed quota: %v", err)
	}
}

func TestGroupSpaceRetainedBytesQuotaRejectsNewReservation(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	record, _ := f.commit(t, f.prepare(t, "synthetic_bytes_seed", GroupSpaceKindJournal), []byte("seed"))
	if _, err := f.sealed.store.db.Exec(`UPDATE group_space_records_v2 SET snapshot_json=zeroblob(?) WHERE record_id=?`,
		groupSpaceCiphertextQuota, record.Snapshot.RecordID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.PrepareGroupSpaceWrite(f.actor(t, f.sealed.source), GroupSpacePrepareInput{
		GroupID: f.sealed.groupID, OperationID: "synthetic_bytes_over", Kind: GroupSpaceKindJournal}); !errors.Is(err, ErrGroupSpaceLimit) {
		t.Fatalf("retained snapshot bytes bypassed quota: %v", err)
	}
}

func TestGroupSpaceThirtyTwoReaderSnapshotFitsLimit(t *testing.T) {
	f := newGroupSpaceTestFixture(t)
	for i := 0; i < GroupSpaceMaxReaders-3; i++ {
		endpoint := createSameGroupBroadcastV2Endpoint(t, f.sealed,
			fmt.Sprintf("ep_synthetic_space_reader_%02d", i), f.sealed.source.nodeID, f.sealed.groupID, true)
		enrollSealedFixtureNetwork(t, f.sealed, f.networkID, endpoint)
		m, err := f.sealed.store.GetMembershipByPrincipalGroup(endpoint.principal, f.sealed.groupID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sealed.store.UpdateMembershipAuthorization(m.ID, m.Roles,
			[]string{"space.read"}, m.Authorization, m.Version); err != nil {
			t.Fatal(err)
		}
		f.sealed.grant(t, endpoint.id)
	}
	snapshot := f.prepare(t, "synthetic_full_audience", GroupSpaceKindJournal)
	if len(snapshot.Readers) != GroupSpaceMaxReaders {
		t.Fatalf("readers=%d", len(snapshot.Readers))
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic %d-reader snapshot bytes=%d, limit=%d", len(snapshot.Readers), len(encoded), groupSpaceSnapshotLimit)
	if len(encoded) > groupSpaceSnapshotLimit {
		t.Fatalf("full snapshot exceeds bound: %d", len(encoded))
	}
	body := bytes.Repeat([]byte("s"), e2ee.GroupSpaceMaxBody)
	inner, err := e2ee.SignGroupSpaceBody(f.sealed.source.identity,
		GroupSpaceReaderContext(*snapshot, snapshot.Readers[0]), body)
	if err != nil {
		t.Fatal(err)
	}
	input := GroupSpaceCommitInput{ReservationID: snapshot.ReservationID}
	for i, reader := range snapshot.Readers {
		wire, err := e2ee.SealGroupSpaceReader(f.sealed.source.identity, reader.PublicIdentity,
			GroupSpaceReaderContext(*snapshot, reader), inner, uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		input.ReaderCiphertexts = append(input.ReaderCiphertexts, GroupSpaceReaderCiphertext{
			EndpointID: reader.EndpointID, KeyID: reader.KeyID, Wire: wire})
	}
	commitJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic 32-reader 16-KiB-body commit JSON bytes=%d", len(commitJSON))
	if _, err := f.sealed.store.CommitGroupSpaceWrite(f.actor(t, f.sealed.source), input); err != nil {
		t.Fatal(err)
	}
	got, err := f.sealed.store.GetGroupSpace(f.actor(t, f.sealed.source), GroupSpaceGetInput{
		GroupID: f.sealed.groupID, RecordID: snapshot.RecordID})
	if err != nil {
		t.Fatal(err)
	}
	getJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	page := GroupSpacePage{Records: make([]GroupSpaceRecord, GroupSpaceMaxPage)}
	for i := range page.Records {
		page.Records[i] = *got
	}
	pageJSON, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic one-reader Get JSON bytes=%d; 16-projection page JSON bytes=%d", len(getJSON), len(pageJSON))
}
