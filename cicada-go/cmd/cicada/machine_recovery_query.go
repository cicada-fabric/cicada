package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const machineRecoveryQueryUsage = "usage: cicada machine recovery query --backup DIR --state-dir DIR --plan-sha256 SHA256 [--writer-root DIR] [--node-pqtls-config FILE]"

func recoveryPrivatePath(path string, directory bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return errors.New("recovery path must exist without symlinks")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("recovery path must be private and have its expected type")
	}
	return nil
}
func recoveryReadPrivateFile(path string, max int64) ([]byte, error) {
	if err := recoveryPrivatePath(path, false); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || len(data) == 0 || int64(len(data)) > max {
		return nil, errors.New("recovery file is empty or exceeds its bound")
	}
	return data, nil
}

// This loader does not call the ordinary key-creating, chmod/persisting cached loader.
func loadMachineRecoveryClient(stateDir, nodeID string) (*machineNodeControlClient, string, error) {
	identityPath, statePath := machineNodeControlPaths(stateDir, nodeID)
	if recoveryPrivatePath(stateDir, true) != nil || recoveryPrivatePath(filepath.Dir(statePath), true) != nil {
		return nil, "", errors.New("Node recovery directories must exist and be private")
	}
	data, err := recoveryReadPrivateFile(statePath, maxMachineNodeControlStateBytes)
	if err != nil {
		return nil, "", err
	}
	var state machineNodeControlState
	if decodeMachineNodeControlJSON(data, &state) != nil || state.Version != machineNodeControlStateVersion || state.NodeID != nodeID {
		return nil, "", errors.New("recovery state does not match Node")
	}
	key, err := recoveryReadPrivateFile(identityPath, 1<<20)
	if err != nil {
		return nil, "", err
	}
	identity, err := e2ee.UnmarshalIdentity(key)
	if err != nil {
		return nil, "", errors.New("existing Node recovery identity is invalid")
	}
	if state.BindingID == "" || state.BindingVersion == 0 || state.NodeKeyEpoch == 0 || state.NodeKeyVersion == 0 || state.HubKeyVersion == 0 || state.NodeKeyID != identity.Public().ID || state.NodeKeyFingerprint != nodewire.IdentityFingerprint(identity.Public()) || e2ee.ValidatePublicIdentity(state.HubPublicIdentity) != nil || state.HubKeyID != state.HubPublicIdentity.ID || state.HubFingerprint != nodewire.IdentityFingerprint(state.HubPublicIdentity) {
		return nil, "", errors.New("recovery state lost its exact approved key pins")
	}
	tokenData, err := recoveryReadPrivateFile(machineNodeCredentialPath(stateDir, nodeID), 4096)
	if err != nil {
		return nil, "", err
	}
	token := strings.TrimSpace(string(tokenData))
	if _, err = fabric.NodeCredentialFromAuthorization("CicadaNode " + token); err != nil {
		return nil, "", errors.New("existing recovery credential is invalid")
	}
	identityJSON, err := recoveryReadPrivateFile(filepath.Join(filepath.Dir(statePath), "identity.json"), 4096)
	if err != nil {
		return nil, "", err
	}
	var nodeIdentity machineNodeIdentity
	if decodeMachineNodeControlJSON(identityJSON, &nodeIdentity) != nil || nodeIdentity.Version != machineNodeIdentityVersion || nodeIdentity.NodeID != nodeID {
		return nil, "", errors.New("existing Node identity does not match recovery scope")
	}
	return &machineNodeControlClient{stateDir: stateDir, statePath: statePath, base: state.HubOrigin, nodeID: nodeID, identity: identity, state: state}, token, nil
}

// A byte/mode inventory before inspection and after acquiring both writer locks
// closes the inspection-to-query handoff without reopening writable databases.
func recoveryTreeDigest(root string) (string, error) {
	h := sha256.New()
	count := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 50000 {
			return errors.New("recovery tree exceeds inventory bound")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("recovery tree contains unsafe file type")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%q:%o:%d\n", rel, info.Mode(), info.Size())
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, readErr := io.Copy(h, file)
		closeErr := file.Close()
		return errors.Join(readErr, closeErr)
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func recoveryQueryStateDigest(nodeDir, stateDir, writerRoot, nodeID string) (string, error) {
	nodeDigest, err := recoveryTreeDigest(nodeDir)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintln(h, nodeDigest)
	// These holds lie outside the selected subtree. Do not inventory foreign
	// Nodes or unrelated WriterRoot state. Exact shared fence bytes are checked
	// against the verified archive after both exclusive locks are acquired.
	for _, path := range []string{
		filepath.Join(stateDir, "nodes", ".recovery-pending", "node-"+urlPath(nodeID)+".json"),
		filepath.Join(writerRoot, ".writer-root-recovery-pending.json"),
	} {
		data, err := recoveryReadPrivateFile(path, 16*1024)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%o:%d\n", info.Mode(), len(data))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func machineRecoveryQueryCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("machine recovery query", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backup := flags.String("backup", "", "verified backup")
	stateDir := flags.String("state-dir", "", "existing restored per-Hub root")
	root := flags.String("writer-root", "", "existing common WriterRoot")
	plan := flags.String("plan-sha256", "", "immutable recovery plan digest")
	pq := flags.String("node-pqtls-config", "", "explicit private per-Hub transport config")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *backup == "" || *stateDir == "" || !nodewire.ValidRecoveryDigest(*plan) {
		return errors.New(machineRecoveryQueryUsage)
	}
	if *root == "" {
		*root = *stateDir
	}
	for _, path := range []string{*backup, *stateDir, *root} {
		if err := recoveryPrivatePath(path, true); err != nil {
			return err
		}
	}
	manifest, err := nodebackup.Verify(*backup)
	if err != nil {
		return err
	}
	nodeDir := machineNodeStateDir(*stateDir, manifest.NodeID)
	// Restore has already established these advisory files. Reject incomplete
	// layouts before calling lock helpers, which otherwise prepare missing paths.
	for _, path := range []string{filepath.Join(*stateDir, "nodes"), filepath.Join(*stateDir, "nodes", ".locks")} {
		if err := recoveryPrivatePath(path, true); err != nil {
			return err
		}
		// nodelock canonicalizes .locks to 0700. Reject other private modes
		// before that helper can change the restored layout.
		info, err := os.Lstat(path)
		if err != nil || info.Mode() != os.ModeDir|0700 {
			return errors.New("existing recovery lock directories must have mode 0700")
		}
	}
	for _, path := range []string{filepath.Join(*stateDir, "nodes", ".locks", "node-"+urlPath(manifest.NodeID)+".maintenance.lock"), filepath.Join(*root, ".writer-root.maintenance.lock")} {
		if err := recoveryPrivatePath(path, false); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode() != 0600 {
			return errors.New("existing recovery lock files must have mode 0600")
		}
	}
	before, err := recoveryQueryStateDigest(nodeDir, *stateDir, *root, manifest.NodeID)
	if err != nil {
		return err
	}
	proof, err := nodebackup.InspectWithWriterRoot(*backup, *stateDir, *root)
	if err != nil {
		return err
	}
	if proof.QuarantineStatus != "pending" || proof.AgentMayStart || !nodewire.ValidRecoveryDigest(proof.BackupManifestSHA256) {
		return errors.New("verified pending restore proof is required")
	}
	// Restore/Agent use this same lock order. These locks never stop processes.
	maintenance, err := nodelock.AcquireMaintenanceExclusive(*stateDir, proof.NodeID)
	if err != nil {
		return err
	}
	defer maintenance.Close()
	writer, err := nodelock.AcquireWriterRootExclusive(*root)
	if err != nil {
		return err
	}
	defer writer.Close()
	after, err := recoveryQueryStateDigest(nodeDir, *stateDir, *root, manifest.NodeID)
	if err != nil || before != after {
		return errors.New("restored Node changed during recovery inspection")
	}
	if err := nodebackup.VerifyRecoveryLineage(*backup, *stateDir, *root); err != nil {
		return err
	}
	manifest, err = nodebackup.Verify(*backup)
	if err != nil {
		return err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil || nodewire.RecoveryDigest(manifestBytes) != proof.BackupManifestSHA256 {
		return errors.New("recovery archive changed during inspection")
	}
	client, token, err := loadMachineRecoveryClient(*stateDir, proof.NodeID)
	if err != nil {
		return err
	}
	q := nodewire.RecoveryRequest{Nonce: make([]byte, 32), Origin: client.state.HubOrigin, CredentialDigest: fabric.HashSessionCredential(token), RestoreDigest: proof.BackupManifestSHA256, PlanDigest: *plan, Operations: []nodewire.RecoveryOperationQuery{}}
	if _, err = rand.Read(q.Nonce); err != nil {
		return err
	}
	if len(client.state.PendingPacket) > 0 {
		packet, err := nodewire.DecodePacket(client.state.PendingPacket)
		if err != nil || packet.Route.Operation == nodewire.RecoveryOperation || packet.Route.HubID != client.state.HubID || packet.Route.NodeID != client.nodeID || packet.Route.BindingID != client.state.BindingID || packet.Route.BindingVersion != client.state.BindingVersion || packet.Route.NodeKeyEpoch != client.state.NodeKeyEpoch || packet.Route.OperationID != client.state.PendingOperationID || packet.Route.Sequence != client.state.PendingSequence || packet.Route.Operation != client.state.PendingOperation || packet.Route.Direction != nodewire.DirectionRequest || packet.Route.SenderKeyID != client.state.NodeKeyID || packet.Route.SenderKeyVersion != client.state.NodeKeyVersion || packet.Route.ReceiverKeyID != client.state.HubKeyID || packet.Route.ReceiverKeyVersion != client.state.HubKeyVersion || packet.Route.Sequence > client.state.Sequence {
			return errors.New("restored pending packet scope is inconsistent")
		}
		q.Operations = append(q.Operations, nodewire.RecoveryOperationQuery{OperationID: packet.Route.OperationID, Sequence: packet.Route.Sequence, RequestDigest: nodewire.RecoveryDigest(client.state.PendingPacket)})
	}
	binding := machineNodeControlBindingFromState(client)
	packet, err := nodewire.SealRecoveryRequest(client.identity, binding, q)
	if err != nil {
		return errors.New("recovery query has invalid pinned coordinates")
	}
	hub := machineHubContext{HubID: client.state.HubID, Origin: client.base, NodeID: client.nodeID, StateDir: *stateDir, Token: token, WriterRoot: *root}
	if err = configureMachinePQTransport(&hub, *pq); err != nil {
		return err
	}
	if closer, ok := hub.NodeTransport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	ctx, cancel := context.WithTimeout(withMachineHubContext(context.Background(), hub), 30*time.Second)
	defer cancel()
	status, err := queryMachineRecoveryStatus(ctx, client, token, q, packet)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		RestoreDigest string                  `json:"restore_digest"`
		PlanDigest    string                  `json:"plan_digest"`
		AgentMayStart bool                    `json:"agent_may_start"`
		Status        nodewire.RecoveryStatus `json:"status"`
	}{q.RestoreDigest, q.PlanDigest, false, status})
}
func queryMachineRecoveryStatus(ctx context.Context, client *machineNodeControlClient, token string, q nodewire.RecoveryRequest, packet []byte) (nodewire.RecoveryStatus, error) {
	endpoint := client.base + "/v2/node/control/rpc"
	if !machineHubOriginMatches(ctx, endpoint) {
		return nodewire.RecoveryStatus{}, errors.New("recovery request escaped pinned origin")
	}
	httpClient, err := machineNodeHTTPClient(ctx, 30*time.Second)
	if err != nil {
		return nodewire.RecoveryStatus{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packet))
		if err != nil {
			return nodewire.RecoveryStatus{}, err
		}
		request.Header.Set("Authorization", "CicadaNode "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := httpClient.Do(request)
		if err != nil {
			if attempt == 0 && ctx.Err() == nil {
				continue
			}
			return nodewire.RecoveryStatus{}, errors.New("recovery query transport failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, nodewire.MaxRecoveryPacketBytes+1))
		response.Body.Close()
		if readErr != nil {
			if attempt == 0 && ctx.Err() == nil {
				continue
			}
			return nodewire.RecoveryStatus{}, errors.New("recovery response read failed")
		}
		if response.StatusCode != http.StatusOK {
			return nodewire.RecoveryStatus{}, errors.New("Hub rejected recovery query")
		}
		return nodewire.OpenRecoveryResponse(client.identity, machineNodeControlBindingFromState(client), q, packet, data)
	}
	return nodewire.RecoveryStatus{}, errors.New("recovery query failed")
}
