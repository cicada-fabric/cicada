package e2ee

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestGroupSpaceReaderEnvelopeAndHistoricalRewrap(t *testing.T) {
	producer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	late, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	base := GroupSpaceContext{HubID: "synthetic_hub", NetworkID: "synthetic_network",
		GroupID: "synthetic_group", RecordID: "synthetic_record", Sequence: 7,
		Kind: "JOURNAL", SnapshotDigest: "synthetic_snapshot_digest",
		ProducerEndpointID: "synthetic_author", ProducerKeyID: producer.Public().ID,
		ReservedAt: "2026-09-30T00:00:00Z", ExpiresAt: "2026-10-01T00:00:00Z"}
	self := base
	self.ReaderEndpointID, self.ReaderKeyID = "synthetic_author", producer.Public().ID
	inner, err := SignGroupSpaceBody(producer, self, []byte("synthetic checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	selfWire, err := SealGroupSpaceReader(producer, producer.Public(), self, inner, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, savedInner, err := OpenGroupSpaceReader(producer, producer.Public(),
		producer.Public(), self, selfWire)
	if err != nil || string(got) != "synthetic checkpoint" || !bytes.Equal(inner, savedInner) {
		t.Fatalf("self reader open failed: %v", err)
	}
	peer := base
	peer.ReaderEndpointID, peer.ReaderKeyID = "synthetic_peer", other.Public().ID
	peerWire, err := SealGroupSpaceReader(producer, other.Public(), peer, inner, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenGroupSpaceReader(other, producer.Public(), producer.Public(), peer, peerWire); err != nil {
		t.Fatal(err)
	}
	wrongHub := peer
	wrongHub.HubID = "other_hub"
	if _, _, err := OpenGroupSpaceReader(other, producer.Public(), producer.Public(), wrongHub, peerWire); err == nil {
		t.Fatal("wrong Hub accepted")
	}
	var tampered GroupSpaceReaderEnvelope
	if err := json.Unmarshal(peerWire, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Sealed[10] ^= 1
	bad, _ := json.Marshal(tampered)
	if VerifyGroupSpaceReader(producer.Public(), peer, bad) == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := SignGroupSpaceBody(producer, self, bytes.Repeat([]byte("x"), GroupSpaceMaxBody+1)); err == nil {
		t.Fatal("oversize Group Space body accepted")
	}
	history := base
	history.ReaderEndpointID, history.ReaderKeyID = "synthetic_late", late.Public().ID
	history.HistoryGrantID = "synthetic_owner_grant"
	historyWire, err := SealGroupSpaceReader(other, late.Public(), history, inner, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, historyInner, err := OpenGroupSpaceReader(late, other.Public(),
		producer.Public(), history, historyWire)
	if err != nil || string(got) != "synthetic checkpoint" || !bytes.Equal(historyInner, inner) {
		t.Fatalf("history rewrap lost original producer proof: %v", err)
	}
	if _, _, err := OpenGroupSpaceReader(late, other.Public(), other.Public(), history, historyWire); err == nil {
		t.Fatal("rewrapper passed as original producer")
	}
}
