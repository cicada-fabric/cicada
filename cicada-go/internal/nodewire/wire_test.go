package nodewire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/workspace/snapshot"
)

func testBinding(t *testing.T) (*e2ee.Identity, *e2ee.Identity, Binding, Route) {
	t.Helper()
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{HubID: "hub-synthetic", NodeID: "node-synthetic", BindingID: "binding-synthetic",
		BindingVersion: 2, NodeKeyEpoch: 3, HubKeyVersion: 1, NodeKeyVersion: 1,
		NodeKey: node.Public(), HubKey: hub.Public()}
	route := Route{Version: Version, Direction: DirectionRequest, HubID: binding.HubID,
		NodeID: binding.NodeID, BindingID: binding.BindingID, BindingVersion: binding.BindingVersion,
		NodeKeyEpoch: binding.NodeKeyEpoch, Sequence: 7, OperationID: "op-synthetic",
		Operation: "node.jobs.list", SenderKeyID: node.Public().ID, SenderKeyVersion: 1,
		ReceiverKeyID: hub.Public().ID, ReceiverKeyVersion: 1}
	return node, hub, binding, route
}

func TestNodeControlPacketRoundTripAndDirectionBinding(t *testing.T) {
	node, hub, binding, route := testBinding(t)
	plain := []byte(`{"safe":"synthetic fixture"}`)
	request, err := SealRequest(node, hub.Public(), binding, route, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRequest(hub, node.Public(), binding, request)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened.Plaintext) != string(plain) || opened.Route != route {
		t.Fatalf("unexpected opened request: %#v", opened)
	}
	if _, err := OpenResponse(hub, node.Public(), binding, request); err == nil {
		t.Fatal("request packet was accepted as a response")
	}
	responseRoute := route
	responseRoute.Direction = DirectionResponse
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	responsePacket, err := SealResponse(hub, node.Public(), binding, responseRoute, []byte(`{"cached":true}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := OpenResponse(node, hub.Public(), binding, responsePacket)
	if err != nil || string(response.Plaintext) != `{"cached":true}` {
		t.Fatalf("open response: %v, plaintext=%q", err, response.Plaintext)
	}
	if string(aadDomain) == "cicada/client-control/packet/v1\x00" {
		t.Fatal("Node and Client packet domains must remain separate")
	}
}

func TestNodeControlUsesRequestAndResponseBodyCeilings(t *testing.T) {
	node, hub, binding, route := testBinding(t)
	payload := make([]byte, MaxRequestPlaintextBytes)
	for index := range payload {
		payload[index] = 'x'
	}
	packet, err := SealRequest(node, hub.Public(), binding, route, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) > MaxPacketBytes {
		t.Fatalf("wire packet %d exceeds configured %d byte ceiling", len(packet), MaxPacketBytes)
	}
	opened, err := OpenRequest(hub, node.Public(), binding, packet)
	if err != nil || len(opened.Plaintext) != MaxRequestPlaintextBytes {
		t.Fatalf("maximum request failed to roundtrip: %v (%d bytes)", err, len(opened.Plaintext))
	}
	if _, err := SealRequest(node, hub.Public(), binding, route, make([]byte, MaxRequestPlaintextBytes+1)); err == nil {
		t.Fatal("request above management-body ceiling was accepted")
	}
	responseRoute := route
	responseRoute.Direction = DirectionResponse
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	responsePayload := make([]byte, MaxPlaintextBytes)
	for index := range responsePayload {
		responsePayload[index] = 'r'
	}
	responsePacket, err := SealResponse(hub, node.Public(), binding, responseRoute, responsePayload)
	if err != nil {
		t.Fatal(err)
	}
	response, err := OpenResponse(node, hub.Public(), binding, responsePacket)
	if err != nil || len(response.Plaintext) != MaxPlaintextBytes {
		t.Fatalf("maximum response failed to roundtrip: %v (%d bytes)", err, len(response.Plaintext))
	}
}

func TestNodeControlPacketRejectsWrongEpochAndStrictJSON(t *testing.T) {
	node, hub, binding, route := testBinding(t)
	packet, err := SealRequest(node, hub.Public(), binding, route, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongEpoch := binding
	wrongEpoch.NodeKeyEpoch++
	if _, err := OpenRequest(hub, node.Public(), wrongEpoch, packet); err == nil {
		t.Fatal("packet was accepted under another Node key epoch")
	}
	zeroVersions := binding
	zeroVersions.HubKeyVersion = 0
	if _, err := OpenRequest(hub, node.Public(), zeroVersions, packet); err == nil {
		t.Fatal("zero Hub key version was accepted")
	}
	var decoded Packet
	if err := json.Unmarshal(packet, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Route.BindingVersion++
	tampered, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRequest(hub, node.Public(), binding, tampered); err == nil {
		t.Fatal("route tampering was not authenticated")
	}
	if _, err := OpenRequest(hub, node.Public(), binding, append(packet, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
	unknown := append(append([]byte(nil), packet[:len(packet)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := OpenRequest(hub, node.Public(), binding, unknown); err == nil {
		t.Fatal("unknown packet field was accepted")
	}
}

func TestSnapshotChunksHaveIndependentAADAndBoundedFraming(t *testing.T) {
	node, hub, _, route := testBinding(t)
	plaintext := []byte("synthetic snapshot bytes")
	digest := sha256.Sum256(plaintext)
	manifest := SnapshotManifest{Version: Version, Direction: SnapshotDirectionUpload,
		WorkerID: "worker-synthetic", Attempt: 2, WorkspaceID: "workspace-synthetic",
		Digest: hex.EncodeToString(digest[:]), Size: int64(len(plaintext)), FileCount: 1,
		ChunkSize: SnapshotChunkBytes, ChunkCount: 1}
	route.Operation = SnapshotUploadOperation
	envelope, err := SealSnapshotChunk(node, hub.Public(), route, manifest, 0, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenSnapshotChunk(hub, node.Public(), route, manifest, 0, envelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("snapshot chunk failed to roundtrip: %v", err)
	}
	wrongManifest := manifest
	wrongManifest.WorkspaceID = "workspace-other"
	if _, err := OpenSnapshotChunk(hub, node.Public(), route, wrongManifest, 0, envelope); err == nil {
		t.Fatal("chunk was not bound to the exact snapshot manifest")
	}
	wrongRoute := route
	wrongRoute.Sequence++
	if _, err := OpenSnapshotChunk(hub, node.Public(), wrongRoute, manifest, 0, envelope); err == nil {
		t.Fatal("chunk was not bound to the Node-Control request route")
	}
	if _, err := OpenSnapshotChunk(hub, node.Public(), route, manifest, 1, envelope); err == nil {
		t.Fatal("chunk was accepted at the wrong index")
	}
	var framed bytes.Buffer
	if err := WriteFrame(&framed, envelope); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(&framed, len(envelope))
	if err != nil || !bytes.Equal(frame, envelope) {
		t.Fatalf("snapshot frame failed to roundtrip: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 8, 1}), 7); err == nil {
		t.Fatal("truncated frame was accepted")
	}
	manifest.Size = snapshot.MaxArchiveBytes + 1
	if err := manifest.Validate(false); err == nil {
		t.Fatal("snapshot above the durable archive quota was accepted")
	}
}
