package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestNodeControlV1HTTPProtocolFlow exercises the production Handler over a
// disposable loopback TCP listener. Client and Node packets use their public
// encrypted wire formats; only the documented initial Owner trust-key
// bootstrap is local. This does not launch the Node agent or a native runtime.
func TestNodeControlV1HTTPProtocolFlow(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "hub-state")
	controlPlane, err := control.New(control.Config{
		StateDir: stateDir, WorkspaceRoot: filepath.Join(root, "workspace"),
		APIToken: "synthetic-node-control-flow-management-token",
	})
	if err != nil {
		t.Fatal("create disposable Control", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := controlPlane.Shutdown(ctx); err != nil {
			t.Errorf("shutdown disposable Control: %v", err)
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for disposable Hub", err)
	}
	hubServer := &http.Server{Handler: NewHandler(controlPlane)}
	serveDone := make(chan error, 1)
	go func() { serveDone <- hubServer.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := hubServer.Shutdown(ctx); err != nil {
			t.Errorf("shutdown disposable HTTP Hub: %v", err)
		}
		if err := <-serveDone; err != nil && err != http.ErrServerClosed {
			t.Errorf("disposable HTTP Hub stopped unexpectedly: %v", err)
		}
	})
	baseURL := "http://" + listener.Addr().String()
	httpClient := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil}}

	clientIdentityResponse := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodGet,
		"/v2/client/identity", nil, "", http.StatusOK)
	var clientHub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(clientIdentityResponse, &clientHub); err != nil || clientHub.HubID == "" {
		t.Fatalf("decode Client Hub identity: err=%v", err)
	}
	nodeIdentityResponse := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodGet,
		"/v2/node/identity", nil, "", http.StatusOK)
	var hubNodeIdentity control.NodeControlHubIdentity
	if err := json.Unmarshal(nodeIdentityResponse, &hubNodeIdentity); err != nil ||
		hubNodeIdentity.HubID != clientHub.HubID || hubNodeIdentity.KeyVersion == 0 {
		t.Fatalf("decode Node-Control Hub identity: err=%v", err)
	}

	// The initial independent Owner trust key is installed through the same
	// documented local bootstrap operation used by a new Hub. All device and
	// Node approvals below use public HTTP enrollment and encrypted Client RPC.
	// A single-owner Control requires the Client owner principal to match its
	// identity. Use the disposable Control's generated ID rather than a second
	// independent synthetic name; all keys remain fixture-only.
	ownerID := controlPlane.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("generate synthetic Owner approval key", err)
	}
	clientKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("generate synthetic Client device key", err)
	}
	bootstrapStore, err := store.New(filepath.Join(stateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal("open disposable Owner bootstrap store", err)
	}
	if err := bootstrapStore.EnsureLocalOwnerPrincipal(ownerID); err != nil {
		_ = bootstrapStore.Close()
		t.Fatal("create synthetic Owner principal", err)
	}
	if _, err := bootstrapStore.RegisterOwnerApprovalKeyLocal(ownerID, ownerKey.Public()); err != nil {
		_ = bootstrapStore.Close()
		t.Fatal("register synthetic Owner trust key", err)
	}
	if err := bootstrapStore.Close(); err != nil {
		t.Fatal("close disposable Owner bootstrap store", err)
	}
	const clientDeviceID = "client-node-control-flow"
	ownerGrant, err := ownerKey.SignOwnerDeviceGrant(ownerID, clientDeviceID, clientKey.Public(),
		clientHub.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal("sign synthetic Client enrollment", err)
	}
	enrollment, err := json.Marshal(map[string]any{
		"owner_id": ownerID, "owner_key_id": ownerKey.Public().ID, "device_id": clientDeviceID,
		"device_public_identity": clientKey.Public(), "owner_device_grant": ownerGrant,
	})
	if err != nil {
		t.Fatal("encode synthetic Client enrollment", err)
	}
	var enrolled struct {
		SessionEpoch     uint64 `json:"session_epoch"`
		DeviceKeyVersion uint64 `json:"device_key_version"`
		State            string `json:"state"`
	}
	enrollmentResponse := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
		"/v2/client/devices/enroll", enrollment, "", http.StatusCreated)
	if err := json.Unmarshal(enrollmentResponse, &enrolled); err != nil || enrolled.State != "ACTIVE" ||
		enrolled.SessionEpoch == 0 || enrolled.DeviceKeyVersion == 0 {
		t.Fatalf("decode Client enrollment response: err=%v", err)
	}
	clientBinding := clientwire.Binding{HubID: clientHub.HubID, OwnerID: ownerID, DeviceID: clientDeviceID,
		SessionEpoch: enrolled.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: enrolled.DeviceKeyVersion}
	var clientSequence uint64
	callOwnerRPC := func(operation string, body []byte) json.RawMessage {
		t.Helper()
		clientSequence++
		route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
			HubID: clientBinding.HubID, OwnerID: ownerID, DeviceID: clientDeviceID,
			SessionEpoch: clientBinding.SessionEpoch, Sequence: clientSequence,
			OperationID: fmt.Sprintf("node-control-flow-client-%d", clientSequence), Operation: operation,
			SenderKeyID: clientKey.Public().ID, SenderKeyVersion: clientBinding.DeviceKeyVersion,
			ReceiverKeyID: clientHub.ControlPublicIdentity.ID, ReceiverKeyVersion: clientBinding.HubKeyVersion}
		packet, err := clientwire.SealRequest(clientKey, clientHub.ControlPublicIdentity, clientBinding, route, body)
		if err != nil {
			t.Fatalf("seal Owner Client RPC %s: %v", operation, err)
		}
		response := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
			"/v2/client/rpc", packet, "", http.StatusOK)
		opened, err := clientwire.OpenResponse(clientKey, clientHub.ControlPublicIdentity, clientBinding, response)
		if err != nil {
			t.Fatalf("open Owner Client RPC %s response: %v", operation, err)
		}
		var envelope struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(opened.Plaintext, &envelope); err != nil || !envelope.OK {
			t.Fatalf("Owner Client RPC %s failed: decode=%v", operation, err)
		}
		return envelope.Result
	}

	const nodeID = "node-control-flow-synthetic"
	nodeKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("generate synthetic Node-Control identity", err)
	}
	nodeToken, credentialDigest, err := fabricpkg.NewNodeCredential()
	if err != nil {
		t.Fatal("generate synthetic Node bearer", err)
	}
	requestNonce := make([]byte, 32)
	if _, err := rand.Read(requestNonce); err != nil {
		t.Fatal("generate Node pairing nonce", err)
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{
		HubID: hubNodeIdentity.HubID, NodeID: nodeID, RequestNonce: requestNonce,
		CredentialDigest: credentialDigest, NodePublicIdentity: nodeKey.Public(),
		HubPublicIdentity: hubNodeIdentity.PublicIdentity, HubKeyVersion: hubNodeIdentity.KeyVersion,
	})
	if err != nil {
		t.Fatal("build Node pairing proof transcript", err)
	}
	proofPacket, err := e2ee.Seal(nodeKey, hubNodeIdentity.PublicIdentity,
		transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal("seal Node pairing proof", err)
	}
	deviceCodeRequest, err := json.Marshal(map[string]any{
		"node_id": nodeID, "node_name": "Synthetic Node-Control protocol fixture",
		"credential_digest": credentialDigest, "request_nonce": requestNonce,
		"node_public_identity": nodeKey.Public(), "node_fingerprint": nodewire.IdentityFingerprint(nodeKey.Public()),
		"proof_packet": proofPacket, "hub_id": hubNodeIdentity.HubID,
		"hub_public_identity": hubNodeIdentity.PublicIdentity, "hub_key_version": hubNodeIdentity.KeyVersion,
		"hub_fingerprint": hubNodeIdentity.Fingerprint,
	})
	if err != nil {
		t.Fatal("encode Node device-code request", err)
	}
	deviceCodeResponse := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
		"/v2/nodes/device-code", deviceCodeRequest, "", http.StatusCreated)
	if bytes.Contains(deviceCodeResponse, []byte(nodeToken)) || bytes.Contains(deviceCodeResponse, []byte(credentialDigest)) {
		t.Fatal("public pairing response exposed Node credential material")
	}
	var deviceCode control.NodeControlDeviceCode
	if err := json.Unmarshal(deviceCodeResponse, &deviceCode); err != nil || deviceCode.UserCode == "" ||
		deviceCode.Candidate == nil || deviceCode.Candidate.RequestID == "" {
		t.Fatalf("decode Node pairing response: err=%v", err)
	}
	previewBody, _ := json.Marshal(map[string]string{"user_code": deviceCode.UserCode})
	var preview store.NodeControlKeyCandidate
	if err := json.Unmarshal(callOwnerRPC("nodes.preview", previewBody), &preview); err != nil ||
		preview.RequestID != deviceCode.Candidate.RequestID || preview.CandidateDigest == "" || preview.State != store.NodeControlPairingPending {
		t.Fatalf("Owner Client preview did not show exact pending Node candidate: err=%v", err)
	}
	confirmBody, _ := json.Marshal(map[string]any{"user_code": deviceCode.UserCode,
		"candidate_digest": preview.CandidateDigest, "candidate_version": preview.Version})
	var confirmed store.NodeControlKeyBinding
	if err := json.Unmarshal(callOwnerRPC("nodes.confirm", confirmBody), &confirmed); err != nil ||
		confirmed.State != store.NodeControlKeyActive || confirmed.NodeID != nodeID ||
		confirmed.NodeKeyID != nodeKey.Public().ID || confirmed.HubKeyID != hubNodeIdentity.KeyID {
		t.Fatalf("Owner Client confirmation did not bind exact Node-Control keys: err=%v", err)
	}

	statusPath := "/v2/node/device-code/" + url.PathEscape(preview.RequestID) + "/status?node_id=" + url.QueryEscape(nodeID)
	statusResponse := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodGet,
		statusPath, nil, "CicadaNode "+nodeToken, http.StatusOK)
	var paired store.NodeControlKeyCandidate
	if err := json.Unmarshal(statusResponse, &paired); err != nil || paired.State != store.NodeControlPairingConfirmed ||
		paired.BindingID != confirmed.OwnerBindingID || paired.BindingVersion != confirmed.BindingVersion {
		t.Fatalf("Node pairing status did not expose the current confirmed binding: err=%v", err)
	}
	nodeBinding := nodewire.Binding{HubID: hubNodeIdentity.HubID, NodeID: nodeID,
		BindingID: confirmed.OwnerBindingID, BindingVersion: confirmed.BindingVersion,
		NodeKeyEpoch: confirmed.NodeKeyEpoch, HubKeyVersion: confirmed.HubKeyVersion,
		NodeKeyVersion: confirmed.NodeKeyVersion, NodeKey: nodeKey.Public(), HubKey: hubNodeIdentity.PublicIdentity}
	var nodeSequence uint64
	callNodeRPC := func(operation string, body []byte) json.RawMessage {
		t.Helper()
		nodeSequence++
		route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest,
			HubID: nodeBinding.HubID, NodeID: nodeID, BindingID: nodeBinding.BindingID,
			BindingVersion: nodeBinding.BindingVersion, NodeKeyEpoch: nodeBinding.NodeKeyEpoch,
			Sequence: nodeSequence, OperationID: fmt.Sprintf("node-control-flow-node-%d", nodeSequence), Operation: operation,
			SenderKeyID: nodeBinding.NodeKey.ID, SenderKeyVersion: nodeBinding.NodeKeyVersion,
			ReceiverKeyID: nodeBinding.HubKey.ID, ReceiverKeyVersion: nodeBinding.HubKeyVersion}
		packet, err := nodewire.SealRequest(nodeKey, nodeBinding.HubKey, nodeBinding, route, body)
		if err != nil {
			t.Fatalf("seal Node-Control RPC %s: %v", operation, err)
		}
		response := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
			"/v2/node/control/rpc", packet, "CicadaNode "+nodeToken, http.StatusOK)
		opened, err := nodewire.OpenResponse(nodeKey, nodeBinding.HubKey, nodeBinding, response)
		if err != nil || opened.Route.OperationID != route.OperationID || opened.Route.Sequence != route.Sequence {
			t.Fatalf("open Node-Control RPC %s response: err=%v", operation, err)
		}
		var envelope struct {
			OK        bool            `json:"ok"`
			Result    json.RawMessage `json:"result"`
			ErrorCode string          `json:"error_code"`
		}
		if err := json.Unmarshal(opened.Plaintext, &envelope); err != nil || !envelope.OK {
			t.Fatalf("Node-Control RPC %s refused: decode=%v code=%s", operation, err, envelope.ErrorCode)
		}
		return envelope.Result
	}
	var bindingStatus struct {
		NodeID         string `json:"node_id"`
		BindingID      string `json:"binding_id"`
		BindingVersion uint64 `json:"binding_version"`
		NodeKeyEpoch   uint64 `json:"node_key_epoch"`
	}
	if err := json.Unmarshal(callNodeRPC("node.binding.status", []byte(`{}`)), &bindingStatus); err != nil ||
		bindingStatus.NodeID != nodeID || bindingStatus.BindingID != nodeBinding.BindingID ||
		bindingStatus.BindingVersion != nodeBinding.BindingVersion || bindingStatus.NodeKeyEpoch != nodeBinding.NodeKeyEpoch {
		t.Fatalf("sealed Node binding status mismatch: err=%v", err)
	}
	callNodeRPC("node.heartbeat", []byte(`{"status":"available","capabilities":{"harnesses":["codex"]}}`))

	goal, err := controlPlane.CreateGoalForOwner(ownerID, control.GoalInput{
		Objective:       "Synthetic Node-Control HTTP protocol fixture",
		SuccessCriteria: "The disposable Node receives a sealed workspace snapshot",
		Constraints:     "No native runtime or external provider is started",
		MachineID:       nodeID, Harness: "codex",
	})
	if err != nil || goal == nil || goal.Worker == nil || goal.Worker.MachineID != nodeID {
		t.Fatalf("create disposable remote Worker: worker=%#v err=%v", func() any {
			if goal == nil {
				return nil
			}
			return goal.Worker
		}(), err)
	}
	workspaces, err := controlPlane.Workspaces(goal.ID)
	if err != nil {
		t.Fatal("list disposable Worker workspaces", err)
	}
	var workerWorkspace *store.Workspace
	for index := range workspaces {
		if workspaces[index].Path == goal.Worker.Workspace {
			workerWorkspace = &workspaces[index]
			break
		}
	}
	if workerWorkspace == nil {
		t.Fatal("remote Worker Workspace was not registered")
	}
	expectedSnapshot, err := controlPlane.SnapshotWorkspace(workerWorkspace.ID)
	if err != nil || expectedSnapshot.Digest == "" {
		t.Fatalf("stage disposable Worker snapshot: err=%v", err)
	}
	var jobList struct {
		Jobs []control.MachineJob `json:"jobs"`
	}
	if err := json.Unmarshal(callNodeRPC("node.jobs.list", []byte(`{}`)), &jobList); err != nil || len(jobList.Jobs) != 1 ||
		jobList.Jobs[0].WorkerID != goal.Worker.ID || jobList.Jobs[0].WorkspaceSnapshotDigest != expectedSnapshot.Digest {
		t.Fatalf("sealed Node job list did not contain the staged Worker: err=%v jobs=%d", err, len(jobList.Jobs))
	}
	claimBody, _ := json.Marshal(map[string]string{"worker_id": goal.Worker.ID})
	var claimed control.MachineJob
	if err := json.Unmarshal(callNodeRPC("node.jobs.claim", claimBody), &claimed); err != nil ||
		claimed.WorkerID != goal.Worker.ID || claimed.Attempt <= 0 || claimed.WorkspaceID != workerWorkspace.ID {
		t.Fatalf("sealed Node job claim failed: err=%v", err)
	}

	manifest := nodewire.SnapshotManifest{Version: nodewire.Version, Direction: nodewire.SnapshotDirectionDownload,
		WorkerID: claimed.WorkerID, Attempt: claimed.Attempt, WorkspaceID: claimed.WorkspaceID,
		Digest: expectedSnapshot.Digest}
	nodeSequence++
	snapshotRoute := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest,
		HubID: nodeBinding.HubID, NodeID: nodeID, BindingID: nodeBinding.BindingID,
		BindingVersion: nodeBinding.BindingVersion, NodeKeyEpoch: nodeBinding.NodeKeyEpoch,
		Sequence: nodeSequence, OperationID: fmt.Sprintf("node-control-flow-node-%d", nodeSequence),
		Operation: nodewire.SnapshotDownloadOperation, SenderKeyID: nodeBinding.NodeKey.ID,
		SenderKeyVersion: nodeBinding.NodeKeyVersion, ReceiverKeyID: nodeBinding.HubKey.ID,
		ReceiverKeyVersion: nodeBinding.HubKeyVersion}
	snapshotRequest, err := nodewire.SealRequest(nodeKey, nodeBinding.HubKey, nodeBinding, snapshotRoute,
		mustJSONNodeControlFlow(t, manifest))
	if err != nil {
		t.Fatal("seal Node workspace snapshot download request", err)
	}
	var framedRequest bytes.Buffer
	if err := nodewire.WriteFrame(&framedRequest, snapshotRequest); err != nil {
		t.Fatal("frame Node workspace snapshot request", err)
	}
	snapshotPath := "/v2/relay/nodes/" + nodeID + "/jobs/" + claimed.WorkerID + "/snapshot/download"
	snapshotAuthorization := "CicadaNode " + nodeToken
	// Drop the first successful HTTP response after headers. The Hub must have
	// atomically cached the exact response packet plus the manifest projection
	// before streaming, so a retry with the byte-identical Node packet can
	// reconstruct the response without decrypting its own Hub->Node packet.
	dropped, err := http.NewRequest(http.MethodPost, baseURL+snapshotPath, bytes.NewReader(framedRequest.Bytes()))
	if err != nil {
		t.Fatal("build first disposable snapshot download", err)
	}
	dropped.Header.Set("Content-Type", "application/x-cicada-node-snapshot-v1")
	dropped.Header.Set("Authorization", snapshotAuthorization)
	droppedResponse, err := httpClient.Do(dropped)
	if err != nil {
		t.Fatal("send first disposable snapshot download", err)
	}
	if droppedResponse.StatusCode != http.StatusOK {
		_ = droppedResponse.Body.Close()
		t.Fatalf("first snapshot download returned status %d, wanted %d", droppedResponse.StatusCode, http.StatusOK)
	}
	if err := droppedResponse.Body.Close(); err != nil {
		t.Fatalf("drop first snapshot response: %v", err)
	}
	snapshotResponse := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
		snapshotPath, framedRequest.Bytes(), snapshotAuthorization, http.StatusOK,
		"application/x-cicada-node-snapshot-v1")
	responseReader := bytes.NewReader(snapshotResponse)
	responsePacket, err := nodewire.ReadFrame(responseReader, nodewire.MaxPacketBytes)
	if err != nil {
		t.Fatal("read sealed Node snapshot manifest response", err)
	}
	openedManifest, err := nodewire.OpenResponse(nodeKey, nodeBinding.HubKey, nodeBinding, responsePacket)
	if err != nil || openedManifest.Route.OperationID != snapshotRoute.OperationID {
		t.Fatalf("open sealed Node snapshot manifest: err=%v", err)
	}
	var snapshotReply struct {
		OK          bool                      `json:"ok"`
		Result      nodewire.SnapshotManifest `json:"result"`
		OperationID string                    `json:"operation_id"`
		Sequence    uint64                    `json:"sequence"`
	}
	if err := json.Unmarshal(openedManifest.Plaintext, &snapshotReply); err != nil || !snapshotReply.OK ||
		snapshotReply.OperationID != snapshotRoute.OperationID || snapshotReply.Sequence != snapshotRoute.Sequence ||
		snapshotReply.Result.Digest != expectedSnapshot.Digest || snapshotReply.Result.Validate(false) != nil {
		t.Fatalf("sealed Node snapshot manifest is invalid: err=%v", err)
	}
	archiveHasher := sha256.New()
	var archiveBytes int64
	for index := 0; index < snapshotReply.Result.ChunkCount; index++ {
		frame, err := nodewire.ReadFrame(responseReader, nodewire.SnapshotMaxChunkFrame)
		if err != nil {
			t.Fatalf("read encrypted Node snapshot chunk %d: %v (remaining_bytes=%d chunk_count=%d)",
				index, err, responseReader.Len(), snapshotReply.Result.ChunkCount)
		}
		chunk, err := nodewire.OpenSnapshotChunk(nodeKey, nodeBinding.HubKey,
			openedManifest.Route, snapshotReply.Result, index, frame)
		if err != nil {
			t.Fatalf("open encrypted Node snapshot chunk %d: %v", index, err)
		}
		_, _ = archiveHasher.Write(chunk)
		archiveBytes += int64(len(chunk))
	}
	if responseReader.Len() != 0 || archiveBytes != snapshotReply.Result.Size ||
		hex.EncodeToString(archiveHasher.Sum(nil)) != snapshotReply.Result.Digest {
		t.Fatalf("decrypted Node snapshot archive failed its digest/size check: size=%d", archiveBytes)
	}

	// A syntactically authenticated but invalid manifest receives an encrypted
	// terminal refusal. Replaying the same request packet must return the exact
	// cached refusal frame and no snapshot chunks.
	nodeSequence++
	refusalRoute := snapshotRoute
	refusalRoute.Sequence = nodeSequence
	refusalRoute.OperationID = fmt.Sprintf("node-control-flow-refusal-%d", nodeSequence)
	refusalManifest := manifest
	refusalManifest.Digest = "not-a-canonical-sha256"
	refusalPacket, err := nodewire.SealRequest(nodeKey, nodeBinding.HubKey, nodeBinding, refusalRoute,
		mustJSONNodeControlFlow(t, refusalManifest))
	if err != nil {
		t.Fatal("seal invalid snapshot manifest request", err)
	}
	var framedRefusalRequest bytes.Buffer
	if err := nodewire.WriteFrame(&framedRefusalRequest, refusalPacket); err != nil {
		t.Fatal("frame invalid snapshot manifest request", err)
	}
	refusalFirst := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
		snapshotPath, framedRefusalRequest.Bytes(), snapshotAuthorization, http.StatusOK,
		"application/x-cicada-node-snapshot-v1")
	refusalRetry := nodeControlFlowRequest(t, httpClient, baseURL, http.MethodPost,
		snapshotPath, framedRefusalRequest.Bytes(), snapshotAuthorization, http.StatusOK,
		"application/x-cicada-node-snapshot-v1")
	if !bytes.Equal(refusalFirst, refusalRetry) {
		t.Fatal("exact invalid-manifest retry did not replay the cached refusal bytes")
	}
	var framedRefusal bytes.Reader
	framedRefusal.Reset(refusalRetry)
	refusalResponsePacket, err := nodewire.ReadFrame(&framedRefusal, nodewire.MaxPacketBytes)
	if err != nil || framedRefusal.Len() != 0 {
		t.Fatalf("cached signed refusal response framing is invalid: err=%v trailing=%d", err, framedRefusal.Len())
	}
	openedRefusal, err := nodewire.OpenResponse(nodeKey, nodeBinding.HubKey, nodeBinding, refusalResponsePacket)
	if err != nil || openedRefusal.Route.OperationID != refusalRoute.OperationID ||
		openedRefusal.Route.Sequence != refusalRoute.Sequence {
		t.Fatalf("cached snapshot refusal did not authenticate on the exact route: err=%v", err)
	}
	var refusalReply struct {
		OK          bool   `json:"ok"`
		ErrorCode   string `json:"error_code"`
		OperationID string `json:"operation_id"`
		Sequence    uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(openedRefusal.Plaintext, &refusalReply); err != nil || refusalReply.OK ||
		refusalReply.ErrorCode != "SNAPSHOT_INVALID" || refusalReply.OperationID != refusalRoute.OperationID ||
		refusalReply.Sequence != refusalRoute.Sequence {
		t.Fatalf("cached snapshot refusal was not a signed terminal failure: err=%v reply=%#v", err, refusalReply)
	}

	// Owner revocation must fence the old credential before the completed
	// response cache is considered. This uses the encrypted Client RPC rather
	// than mutating the Store directly.
	revokeBody, _ := json.Marshal(map[string]any{"binding_id": confirmed.OwnerBindingID,
		"expected_version": confirmed.BindingVersion})
	var revoked struct {
		State   string `json:"state"`
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal(callOwnerRPC("nodes.revoke", revokeBody), &revoked); err != nil ||
		revoked.State != "REVOKED" || revoked.Version <= confirmed.BindingVersion {
		t.Fatalf("Owner did not revoke the exact Node binding: err=%v result=%#v", err, revoked)
	}
	staleRetryRequest, err := http.NewRequest(http.MethodPost, baseURL+snapshotPath, bytes.NewReader(framedRequest.Bytes()))
	if err != nil {
		t.Fatal("build stale-epoch snapshot retry", err)
	}
	staleRetryRequest.Header.Set("Content-Type", "application/x-cicada-node-snapshot-v1")
	staleRetryRequest.Header.Set("Authorization", snapshotAuthorization)
	staleRetryResponse, err := httpClient.Do(staleRetryRequest)
	if err != nil {
		t.Fatal("send stale-epoch snapshot retry", err)
	}
	_ = staleRetryResponse.Body.Close()
	if staleRetryResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked Node credential reached cached snapshot replay: status=%d want=%d",
			staleRetryResponse.StatusCode, http.StatusUnauthorized)
	}
	t.Log("scope=HTTP_PROTOCOL status=PASS owner_client_rpc=encrypted node_pairing=owner_confirmed node_rpc=sealed snapshot=sealed native_agent=NOT_RUN")
}

func nodeControlFlowRequest(t *testing.T, client *http.Client, baseURL, method, path string,
	body []byte, authorization string, expectedStatus int, contentType ...string) []byte {
	t.Helper()
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal("build disposable HTTP request", err)
	}
	if len(contentType) > 0 {
		request.Header.Set("Content-Type", contentType[0])
	} else if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send disposable HTTP request %s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, int64(nodewire.SnapshotMaxWireBytes)+1))
	if err != nil || len(responseBody) > nodewire.SnapshotMaxWireBytes {
		t.Fatalf("read disposable HTTP response %s %s: err=%v", method, path, err)
	}
	if response.StatusCode != expectedStatus {
		// Error bodies are intentionally omitted because a future route may
		// include private fixture details; status and route identify the failure.
		t.Fatalf("disposable HTTP route %s %s returned status %d, wanted %d", method, path,
			response.StatusCode, expectedStatus)
	}
	return responseBody
}

func mustJSONNodeControlFlow(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode Node-Control fixture message", err)
	}
	return encoded
}
