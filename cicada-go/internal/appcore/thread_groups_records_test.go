package appcore

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestThreadGroupRecoveryFrameFitsWithoutBase64Expansion(t *testing.T) {
	packet := bytes.Repeat([]byte("synthetic"), (896<<10)/9)
	record := &threadGroupRecord{Format: "synthetic-storage-frame", NodeID: "synthetic-node", NetworkID: "synthetic-network", Packet: packet}
	raw, err := encodeThreadGroupRecord(record)
	if err != nil || len(raw) > threadGroupRecordLimit {
		t.Fatal("bounded recovery packet did not fit an unchanged one-MiB record", err)
	}
	defer clear(raw)
	got, err := decodeThreadGroupRecord(raw)
	if err != nil || got.NodeID != record.NodeID || got.NetworkID != record.NetworkID || !bytes.Equal(got.Packet, packet) {
		t.Fatal("original packet bytes or fixed target changed on storage round trip", err)
	}
	got.Packet[0] ^= 1
	if !bytes.Equal(record.Packet, packet) || bytes.Equal(got.Packet, packet) {
		t.Fatal("decoded packet shares mutable storage with another frame")
	}
	clear(got.Packet)
	oversized := *record
	oversized.Packet = make([]byte, threadGroupRecordLimit)
	if _, err := encodeThreadGroupRecord(&oversized); err == nil {
		t.Fatal("record budget ignored its metadata")
	}
	corrupt := append([]byte(nil), raw...)
	defer clear(corrupt)
	binary.BigEndian.PutUint32(corrupt[4:8], uint32(len(corrupt)))
	if _, err := decodeThreadGroupRecord(corrupt); err == nil {
		t.Fatal("corrupt header boundary was accepted")
	}
}
