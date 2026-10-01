package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func startStoreNodeControlRequest(t *testing.T, s *Store, nodeID, digest, mode, target string,
	nodeKey, hubKey *e2ee.Identity, codeSuffix string) *NodeControlKeyCandidate {
	t.Helper()
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	codeHash := nodeBindingTestCodeDigest("node-control-" + codeSuffix)
	candidate, err := s.StartNodeControlKeyRequest(NodeControlKeyRequestInput{
		Mode: mode, NodeID: nodeID, NodeName: "synthetic worker", CredentialDigest: digest,
		CodeDigest: codeHash, NodePublicIdentity: nodeKey.Public(),
		NodeFingerprint: nodeControlFingerprint(nodeKey.Public()), ProofPacket: []byte("synthetic sealed proof"),
		HubPublicIdentity: hubKey.Public(), HubKeyVersion: 1,
		HubFingerprint: nodeControlFingerprint(hubKey.Public()), TargetBindingID: target,
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.HubID != hubID {
		t.Fatalf("candidate Hub ID=%q want %q", candidate.HubID, hubID)
	}
	return candidate
}

func confirmStoreNodeControlRequest(t *testing.T, s *Store, device *ClientDevice,
	candidate *NodeControlKeyCandidate, codeSuffix string) *NodeControlKeyBinding {
	t.Helper()
	codeHash := nodeBindingTestCodeDigest("node-control-" + codeSuffix)
	preview, err := s.PreviewNodeControlKeyRequest("owner_a", device.DeviceID, codeHash)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Version != candidate.Version || preview.CandidateDigest != candidate.CandidateDigest ||
		preview.NodeKeyFingerprint != candidate.NodeKeyFingerprint ||
		preview.HubNodeControlFingerprint != candidate.HubNodeControlFingerprint {
		t.Fatalf("Owner preview did not identify exact Node/Hub key candidate: %#v", preview)
	}
	binding, err := s.ConfirmNodeControlKeyRequest("owner_a", device.DeviceID, codeHash,
		candidate.Version, candidate.CandidateDigest, candidate.HubNodeControlKeyID,
		candidate.HubNodeControlFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestNodeControlOwnerConfirmationAndCredentialDigestRemainExact(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	var digest string
	for index := 0; index < 64; index++ {
		digest = nodeBindingTestCredentialDigest(fmt.Sprintf("node-control-digest-%d", index))
		if strings.ToLower(digest) != digest {
			break
		}
	}
	if strings.ToLower(digest) == digest {
		t.Fatal("test fixture did not produce a mixed-case base64url digest")
	}
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate := startStoreNodeControlRequest(t, s, "node-control-confirm", digest,
		NodeControlPairingInitial, "", nodeKey, hubKey, "confirm")
	binding := confirmStoreNodeControlRequest(t, s, device, candidate, "confirm")
	if binding.CredentialDigest != digest || binding.NodeKeyEpoch != 1 || binding.BindingVersion != 1 ||
		binding.NodeKeyFingerprint != nodeControlFingerprint(nodeKey.Public()) ||
		binding.HubKeyFingerprint != nodeControlFingerprint(hubKey.Public()) {
		t.Fatalf("Owner confirmation did not persist exact candidate evidence: %#v", binding)
	}
	resolved, err := s.NodeControlKeyForCredential(digest, candidate.NodeID)
	if err != nil || resolved.NodeKeyID != nodeKey.Public().ID {
		t.Fatalf("exact case-sensitive bearer digest did not resolve: binding=%#v err=%v", resolved, err)
	}
	if _, err := s.NodeControlKeyForCredential(strings.ToLower(digest), candidate.NodeID); !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatalf("case-folded base64url digest resolved a different credential: %v", err)
	}
}

func TestNodeControlMaxResponsePacketSurvivesStoreAndNodeDecode(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	digest := nodeBindingTestCredentialDigest("node-control-max-response")
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate := startStoreNodeControlRequest(t, s, "node-control-max-response", digest,
		NodeControlPairingInitial, "", nodeKey, hubKey, "max-response")
	approved := confirmStoreNodeControlRequest(t, s, device, candidate, "max-response")
	binding := nodewire.Binding{HubID: approved.HubID, NodeID: approved.NodeID,
		BindingID: approved.OwnerBindingID, BindingVersion: approved.BindingVersion,
		NodeKeyEpoch: approved.NodeKeyEpoch, NodeKeyVersion: approved.NodeKeyVersion,
		HubKeyVersion: approved.HubKeyVersion, NodeKey: nodeKey.Public(), HubKey: hubKey.Public()}
	input := NodeControlRPCInput{CredentialDigest: digest, NodeID: approved.NodeID,
		BindingID: approved.OwnerBindingID, BindingVersion: approved.BindingVersion,
		NodeKeyID: approved.NodeKeyID, NodeKeyEpoch: approved.NodeKeyEpoch,
		Sequence: 1, OperationID: "ceiling-response-op", Operation: "node.binding.status"}
	requestDigest := sha256.Sum256([]byte("synthetic request packet digest"))
	input.RequestDigest = hex.EncodeToString(requestDigest[:])
	if _, retry, err := s.BeginNodeControlRPC(input); err != nil || retry {
		t.Fatalf("begin response-ceiling operation: retry=%t err=%v", retry, err)
	}
	responseRoute := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionResponse,
		HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID,
		BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch,
		Sequence: input.Sequence, OperationID: input.OperationID, Operation: input.Operation,
		SenderKeyID: binding.HubKey.ID, SenderKeyVersion: binding.HubKeyVersion,
		ReceiverKeyID: binding.NodeKey.ID, ReceiverKeyVersion: binding.NodeKeyVersion}
	const prefix = `{"ok":true,"operation_id":"ceiling-response-op","sequence":1,"result":{"padding":"`
	const suffix = `"}}`
	padding := strings.Repeat("x", nodewire.MaxPlaintextBytes-len(prefix)-len(suffix))
	plaintext := []byte(prefix + padding + suffix)
	if len(plaintext) != nodewire.MaxPlaintextBytes {
		t.Fatalf("test plaintext size=%d want=%d", len(plaintext), nodewire.MaxPlaintextBytes)
	}
	packet, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding, responseRoute, plaintext)
	if err != nil {
		t.Fatalf("seal maximum legal response: %v", err)
	}
	if len(packet) <= 3<<20 || len(packet) > nodewire.MaxPacketBytes {
		t.Fatalf("response packet size=%d did not exercise the Store/wire cap mismatch", len(packet))
	}
	if err := s.CompleteNodeControlRPC(NodeControlRPCCompletion{NodeControlRPCInput: input,
		ResponsePacket: packet}); err != nil {
		t.Fatalf("persist maximum legal Node-Control response packet: %v", err)
	}
	record, retry, err := s.BeginNodeControlRPC(input)
	if err != nil || !retry || record.State != NodeControlRPCComplete || string(record.ResponsePacket) != string(packet) {
		t.Fatalf("retry did not return exact response packet: record=%#v retry=%t err=%v", record, retry, err)
	}
	opened, err := nodewire.OpenResponse(nodeKey, binding.HubKey, binding, record.ResponsePacket)
	if err != nil || len(opened.Plaintext) != nodewire.MaxPlaintextBytes || string(opened.Plaintext) != string(plaintext) {
		t.Fatalf("Node could not decode exact maximum response: size=%d err=%v", len(opened.Plaintext), err)
	}
}

func TestNodeControlSnapshotProjectionFailsClosedOnMissingCorruptOrMismatchedRow(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	digest := nodeBindingTestCredentialDigest("node-control-snapshot-projection")
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate := startStoreNodeControlRequest(t, s, "node-control-snapshot-projection", digest,
		NodeControlPairingInitial, "", nodeKey, hubKey, "snapshot-projection")
	approved := confirmStoreNodeControlRequest(t, s, device, candidate, "snapshot-projection")
	binding := nodewire.Binding{HubID: approved.HubID, NodeID: approved.NodeID,
		BindingID: approved.OwnerBindingID, BindingVersion: approved.BindingVersion,
		NodeKeyEpoch: approved.NodeKeyEpoch, NodeKeyVersion: approved.NodeKeyVersion,
		HubKeyVersion: approved.HubKeyVersion, NodeKey: nodeKey.Public(), HubKey: hubKey.Public()}
	manifestDigest := sha256.Sum256([]byte("synthetic snapshot archive"))
	requestManifest := nodewire.SnapshotManifest{Version: nodewire.Version,
		Direction: nodewire.SnapshotDirectionDownload, WorkerID: "worker-projection", Attempt: 1,
		WorkspaceID: "workspace-projection", Digest: hex.EncodeToString(manifestDigest[:])}
	encodedRequest, err := json.Marshal(requestManifest)
	if err != nil {
		t.Fatal(err)
	}
	requestRoute := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest,
		HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID,
		BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch,
		Sequence: 1, OperationID: "snapshot-projection-success", Operation: nodewire.SnapshotDownloadOperation,
		SenderKeyID: binding.NodeKey.ID, SenderKeyVersion: binding.NodeKeyVersion,
		ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	requestPacket, err := nodewire.SealRequest(nodeKey, binding.HubKey, binding, requestRoute, encodedRequest)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(requestPacket)
	input := NodeControlRPCInput{CredentialDigest: digest, NodeID: approved.NodeID,
		BindingID: approved.OwnerBindingID, BindingVersion: approved.BindingVersion,
		NodeKeyID: approved.NodeKeyID, NodeKeyEpoch: approved.NodeKeyEpoch,
		Sequence: requestRoute.Sequence, OperationID: requestRoute.OperationID,
		Operation: requestRoute.Operation, RequestDigest: hex.EncodeToString(requestDigest[:])}
	if _, retry, err := s.BeginNodeControlRPC(input); err != nil || retry {
		t.Fatalf("begin snapshot projection request: retry=%t err=%v", retry, err)
	}
	responseRoute := requestRoute
	responseRoute.Direction = nodewire.DirectionResponse
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	responsePacket, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding, responseRoute, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	completedManifest := requestManifest
	completedManifest.Size, completedManifest.FileCount = int64(len("synthetic snapshot archive")), 1
	completedManifest.ChunkSize, completedManifest.ChunkCount = nodewire.SnapshotChunkBytes, 1
	if err := s.CompleteNodeControlRPC(NodeControlRPCCompletion{NodeControlRPCInput: input,
		ResponsePacket: responsePacket, SnapshotRequestRoute: &requestRoute,
		SnapshotManifest: &completedManifest}); err != nil {
		t.Fatalf("complete snapshot with durable projection: %v", err)
	}
	projection, err := s.NodeControlSnapshotRPCResponseProjection(input, requestRoute)
	if err != nil || projection.Manifest == nil || *projection.Manifest != completedManifest {
		t.Fatalf("exact projection lookup: projection=%#v err=%v", projection, err)
	}
	wrongDigestInput := input
	wrongRequestDigest := sha256.Sum256([]byte("different request"))
	wrongDigestInput.RequestDigest = hex.EncodeToString(wrongRequestDigest[:])
	if _, err := s.NodeControlSnapshotRPCResponseProjection(wrongDigestInput, requestRoute); err == nil {
		t.Fatal("projection accepted a different request digest")
	}
	wrongRoute := requestRoute
	wrongRoute.OperationID = "different-operation"
	if _, err := s.NodeControlSnapshotRPCResponseProjection(input, wrongRoute); err == nil {
		t.Fatal("projection accepted a different request route")
	}
	if _, err := s.db.Exec(`UPDATE node_control_snapshot_rpc_responses_v1 SET manifest_json='{}'
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`,
		input.BindingID, input.NodeKeyEpoch, input.Sequence, input.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeControlSnapshotRPCResponseProjection(input, requestRoute); err == nil {
		t.Fatal("projection accepted corrupted manifest metadata")
	}

	legacyRoute := requestRoute
	legacyRoute.Sequence, legacyRoute.OperationID = 2, "snapshot-projection-v54-cache"
	legacyPacket, err := nodewire.SealRequest(nodeKey, binding.HubKey, binding, legacyRoute, encodedRequest)
	if err != nil {
		t.Fatal(err)
	}
	legacyRequestDigest := sha256.Sum256(legacyPacket)
	legacyInput := input
	legacyInput.Sequence, legacyInput.OperationID = legacyRoute.Sequence, legacyRoute.OperationID
	legacyInput.RequestDigest = hex.EncodeToString(legacyRequestDigest[:])
	if _, retry, err := s.BeginNodeControlRPC(legacyInput); err != nil || retry {
		t.Fatalf("begin simulated pre-v55 request: retry=%t err=%v", retry, err)
	}
	legacyResponseRoute := legacyRoute
	legacyResponseRoute.Direction = nodewire.DirectionResponse
	legacyResponseRoute.SenderKeyID, legacyResponseRoute.ReceiverKeyID = legacyResponseRoute.ReceiverKeyID, legacyResponseRoute.SenderKeyID
	legacyResponseRoute.SenderKeyVersion, legacyResponseRoute.ReceiverKeyVersion = legacyResponseRoute.ReceiverKeyVersion, legacyResponseRoute.SenderKeyVersion
	legacyResponsePacket, err := nodewire.SealResponse(hubKey, binding.NodeKey, binding, legacyResponseRoute, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_control_rpc_inbox_v1 SET state='COMPLETE',response_packet=?
WHERE owner_binding_id=? AND node_key_epoch=? AND sequence=? AND operation_id=?`,
		legacyResponsePacket, legacyInput.BindingID, legacyInput.NodeKeyEpoch,
		legacyInput.Sequence, legacyInput.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeControlSnapshotRPCResponseProjection(legacyInput, legacyRoute); err == nil {
		t.Fatal("projection lookup accepted historical COMPLETE row without v55 metadata")
	}
}

func TestNodeControlOwnerKeyUpgradeFencesRequestAdmittedBeforeEpochChange(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	digest := nodeBindingTestCredentialDigest("node-control-upgrade-token")
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate := startStoreNodeControlRequest(t, s, "node-control-upgrade", digest,
		NodeControlPairingInitial, "", nodeKey, hubKey, "upgrade-initial")
	initial := confirmStoreNodeControlRequest(t, s, device, candidate, "upgrade-initial")
	ownerNode := boundNodeFixture{ownerID: "owner_a", device: device,
		nodeID: initial.NodeID, digest: digest}
	worker := createOwnerWorker(t, s, ownerNode, "upgrade-fence")
	requestHash := sha256.Sum256([]byte("synthetic exact encrypted packet"))
	oldInput := NodeControlRPCInput{CredentialDigest: digest, NodeID: initial.NodeID,
		BindingID: initial.OwnerBindingID, BindingVersion: initial.BindingVersion,
		NodeKeyID: initial.NodeKeyID, NodeKeyEpoch: initial.NodeKeyEpoch,
		Sequence: 1, OperationID: "op-upgrade-fence", Operation: "node.jobs.claim",
		RequestDigest: hex.EncodeToString(requestHash[:])}
	if record, retry, err := s.BeginNodeControlRPC(oldInput); err != nil || retry || record.State != NodeControlRPCProcessing {
		t.Fatalf("begin old request: record=%#v retry=%t err=%v", record, retry, err)
	}
	// Honor the existing five-second unauthenticated device-code cooldown while
	// keeping this deterministic; created_at is not candidate evidence.
	if _, err := s.db.Exec(`UPDATE node_control_key_requests_v1 SET created_at=? WHERE id=?`,
		time.Now().UTC().Add(-2*nodeDeviceBindingReissueCooldown).Format(time.RFC3339Nano), initial.ApprovedRequestID); err != nil {
		t.Fatal(err)
	}
	nextNodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	upgrade := startStoreNodeControlRequest(t, s, initial.NodeID, digest,
		NodeControlPairingUpgrade, initial.OwnerBindingID, nextNodeKey, hubKey, "upgrade-next")
	if upgrade.NodeKeyEpoch != initial.NodeKeyEpoch+1 {
		t.Fatalf("upgrade did not advance Node key epoch: %d -> %d", initial.NodeKeyEpoch, upgrade.NodeKeyEpoch)
	}
	confirmStoreNodeControlRequest(t, s, device, upgrade, "upgrade-next")
	if _, _, err := s.ClaimBoundNodeWorkerControlRPC(oldInput, worker.ID); !errors.Is(err, ErrNodeControlKeyUnauthorized) {
		t.Fatalf("pre-upgrade request passed mutation-time fence: %v", err)
	}
	stored, err := s.GetWorker(worker.ID)
	if err != nil || stored.Status != "queued" || stored.Attempt != 0 {
		t.Fatalf("stale key epoch changed Worker state: %#v err=%v", stored, err)
	}
	active, err := s.NodeControlKeyForCredential(digest, initial.NodeID)
	if err != nil || active.NodeKeyEpoch != initial.NodeKeyEpoch+1 || active.BindingVersion != initial.BindingVersion+1 {
		t.Fatalf("Owner-approved key upgrade did not fence old binding: %#v err=%v", active, err)
	}
}

func TestNodeControlReinitializationUsesHistoricalNodeKeyEpoch(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	firstDigest := nodeBindingTestCredentialDigest("node-control-initial-1")
	firstNodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	firstCandidate := startStoreNodeControlRequest(t, s, "node-control-reinitialize", firstDigest,
		NodeControlPairingInitial, "", firstNodeKey, hubKey, "reinit-first")
	first := confirmStoreNodeControlRequest(t, s, device, firstCandidate, "reinit-first")
	if _, err := s.RevokeNodeDeviceBinding("owner_a", first.OwnerBindingID, int64(first.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_control_key_requests_v1 SET created_at=? WHERE id=?`,
		time.Now().UTC().Add(-2*nodeDeviceBindingReissueCooldown).Format(time.RFC3339Nano), first.ApprovedRequestID); err != nil {
		t.Fatal(err)
	}
	secondDigest := nodeBindingTestCredentialDigest("node-control-initial-2")
	secondNodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secondCandidate := startStoreNodeControlRequest(t, s, first.NodeID, secondDigest,
		NodeControlPairingInitial, "", secondNodeKey, hubKey, "reinit-second")
	if secondCandidate.NodeKeyEpoch != first.NodeKeyEpoch+1 {
		t.Fatalf("reinitialized Node reused a historical key epoch: %d -> %d", first.NodeKeyEpoch, secondCandidate.NodeKeyEpoch)
	}
	second := confirmStoreNodeControlRequest(t, s, device, secondCandidate, "reinit-second")
	if second.NodeKeyEpoch != 2 || second.BindingVersion != 1 {
		t.Fatalf("reinitialized binding has wrong epoch/version: %#v", second)
	}
}
