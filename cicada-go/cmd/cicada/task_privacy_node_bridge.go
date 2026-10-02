package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Reading the existing Node inbox does not open its crypto state, recover an
// injection or change replay/counters. Hub Guard and the exact local receipt are
// checked separately before private content is presented as a formal Task body.
func (m *mcpServer) readLocalRegisteredTaskPacket(scope mcpOutboxScope, ref store.SharedTaskSealedRef) (*sealedTaskObjectPacket, error) {
	if ref.ReaderEndpointID != scope.EndpointID || ref.GroupID != scope.GroupID {
		return nil, store.ErrSharedTaskSealedReference
	}
	m.sessionMu.RLock()
	bindingEpoch := m.sessionPublic.BindingEpoch
	m.sessionMu.RUnlock()
	if bindingEpoch == 0 || scope.NodeID == "" || scope.NativeSessionID == "" || m.endpointKeyNodeStateBase() == "" {
		return nil, store.ErrSharedTaskSealedReference
	}
	nodeDir := machineNodeStateDir(m.endpointKeyNodeStateBase(), scope.NodeID)
	if _, err := nodekeys.LoadExisting(nodeDir, ref.ReaderEndpointID); err != nil {
		return nil, store.ErrSharedTaskSealedReference
	}
	inboxPath, inboxStable, inboxCleanup, err := privateTaskDBSnapshot(machineNodeInboxPath(m.endpointKeyNodeStateBase(), scope.NodeID))
	if err != nil {
		return nil, store.ErrSharedTaskSealedReference
	}
	defer inboxCleanup()
	inbox, err := nodeinbox.OpenReadOnly(inboxPath)
	if err != nil {
		return nil, errors.New("registered sealed Task body is unavailable in the local Node inbox")
	}
	defer inbox.Close()
	// The exact local receipt digest is compared to the current registered
	// ciphertext. Message ID alone cannot authorize a transplanted local body.
	delivery, err := inbox.Get(context.Background(), ref.MessageID)
	if err != nil || delivery.Digest != ref.MessageDigest || delivery.EndpointID != scope.EndpointID || delivery.SessionID != scope.NativeSessionID || delivery.BindingEpoch != bindingEpoch {
		return nil, store.ErrSharedTaskSealedReference
	}
	// Node readability is not a runtime injection/consumption receipt. Never
	// claim, recover, retry or advance the delivery merely to read its body.
	if delivery.State == nodeinbox.FAILED {
		return nil, store.ErrSharedTaskSealedReference
	}
	plaintext, err := readTaskPeerCryptoPlaintext(machineNodeStateDir(m.endpointKeyNodeStateBase(), scope.NodeID), ref, bindingEpoch)
	if err != nil || !bytes.Equal(plaintext, delivery.Payload) {
		return nil, store.ErrSharedTaskSealedReference
	}
	packet, err := decodeSealedTaskObjectPacket(string(plaintext))
	if err != nil || !matchSealedTaskObjectPacket(packet, ref) || !inboxStable() {
		return nil, store.ErrSharedTaskSealedReference
	}
	return packet, nil
}

// This reads existing crypto/replay and pin tables without OpenCryptoState:
// that writable constructor would migrate/protect state. Pure E2EE open below
// authenticates the cached ciphertext again, without counter/replay mutation.
func readTaskPeerCryptoPlaintext(nodeDir string, ref store.SharedTaskSealedRef, receiverBindingEpoch uint64) ([]byte, error) {
	local, err := nodekeys.LoadExisting(nodeDir, ref.ReaderEndpointID)
	if err != nil {
		return nil, store.ErrSharedTaskSealedReference
	}
	path := filepath.Join(nodeDir, "node-crypto-state.sqlite")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode() != 0600 {
		return nil, store.ErrSharedTaskSealedReference
	}
	snapshot, stable, cleanup, err := privateTaskDBSnapshot(path)
	if err != nil {
		return nil, store.ErrSharedTaskSealedReference
	}
	defer cleanup()
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: snapshot, RawQuery: "mode=ro"}).String())
	if err != nil {
		return nil, store.ErrSharedTaskSealedReference
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.Begin()
	if err != nil {
		return nil, store.ErrSharedTaskSealedReference
	}
	defer tx.Rollback()
	var publicJSON, keyID, revoked, sourceExpiry, targetExpiry string
	var senderEpoch uint64
	err = tx.QueryRow(`SELECT public_identity_json,peer_key_id,binding_epoch,revoked_at,source_grant_expires_at,target_grant_expires_at FROM node_crypto_peer_pins WHERE local_endpoint_id=? AND local_group_id=? AND peer_endpoint_id=? AND peer_group_id=? AND communication_link_id=''`, ref.ReaderEndpointID, ref.GroupID, ref.SenderEndpointID, ref.GroupID).Scan(&publicJSON, &keyID, &senderEpoch, &revoked, &sourceExpiry, &targetExpiry)
	if err != nil || revoked != "" || senderEpoch != ref.SealedRoute.SenderBindingEpoch {
		return nil, store.ErrSharedTaskSealedReference
	}
	// Unlinked Group pins intentionally do not persist grant expiry fields;
	// current signed Group grants/expiry are checked by the Hub ref Guard before
	// and after this read. Link pin expiries, when present, must remain current.
	for _, expiry := range []string{sourceExpiry, targetExpiry} {
		if expiry == "" {
			continue
		}
		deadline, err := time.Parse(time.RFC3339Nano, expiry)
		if err != nil || !deadline.After(time.Now().UTC()) {
			return nil, store.ErrSharedTaskSealedReference
		}
	}
	var sender e2ee.PublicIdentity
	if json.Unmarshal([]byte(publicJSON), &sender) != nil || sender.ID != keyID || keyID != ref.SealedRoute.SenderKeyID {
		return nil, store.ErrSharedTaskSealedReference
	}
	var digest, replayDigest, wire []byte
	var sequence, replaySequence int64
	err = tx.QueryRow(`SELECT digest,sequence,envelope FROM node_crypto_inbox WHERE receiver_endpoint_id=? AND sender_key_id=? AND message_id=? AND state='RECEIVED'`, ref.ReaderEndpointID, keyID, ref.MessageID).Scan(&digest, &sequence, &wire)
	if err != nil || sequence <= 0 || len(wire) == 0 || len(wire) > 256*1024 {
		return nil, store.ErrSharedTaskSealedReference
	}
	actual := sha256.Sum256(wire)
	if len(digest) != sha256.Size || !bytes.Equal(digest, actual[:]) || hex.EncodeToString(actual[:]) != ref.MessageDigest {
		return nil, store.ErrSharedTaskSealedReference
	}
	err = tx.QueryRow(`SELECT digest,sequence FROM node_crypto_replay WHERE receiver_endpoint_id=? AND sender_key_id=? AND message_id=?`, ref.ReaderEndpointID, keyID, ref.MessageID).Scan(&replayDigest, &replaySequence)
	if err != nil || sequence != replaySequence || !bytes.Equal(digest, replayDigest) {
		return nil, store.ErrSharedTaskSealedReference
	}
	route := ref.SealedRoute
	if route.Kind != "SEND" || route.MessageID != ref.MessageID || route.SenderEndpointID != ref.SenderEndpointID || route.ReceiverEndpointID != ref.ReaderEndpointID || route.SenderGroupID != ref.GroupID || route.ReceiverGroupID != ref.GroupID || route.ReceiverBindingEpoch != receiverBindingEpoch || route.ReceiverKeyID != local.Public().ID || route.RequestID != "" || route.ReplyTo != "" || route.ParentRequestID != "" || route.LinkID != "" {
		return nil, store.ErrSharedTaskSealedReference
	}
	plaintext, verifiedSequence, err := e2ee.OpenEndpointMessage(local, sender, route, wire)
	if err != nil || verifiedSequence != uint64(sequence) || !stable() {
		return nil, store.ErrSharedTaskSealedReference
	}
	return plaintext, nil
}

// SQLite can create WAL/SHM even for mode=ro when its enclosing directory is
// writable. Read only the existing bounded DB/WAL into one private disposable
// directory, open that copy, and reject source changes. No StateDir/key copy,
// schema initialization, counter reset or recovery runs on the source.
func privateTaskDBSnapshot(source string) (string, func() bool, func(), error) {
	const maxTaskSnapshotFile = 64 << 20
	type fingerprint struct {
		Exists bool
		Mode   os.FileMode
		Digest [32]byte
	}
	read := func(path string, required bool) ([]byte, fingerprint, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil, fingerprint{}, nil
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode() != 0600 || info.Size() > maxTaskSnapshotFile {
			return nil, fingerprint{}, store.ErrSharedTaskSealedReference
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, fingerprint{}, err
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() {
			return nil, fingerprint{}, store.ErrSharedTaskSealedReference
		}
		data, err := io.ReadAll(io.LimitReader(file, maxTaskSnapshotFile+1))
		if err != nil || len(data) > maxTaskSnapshotFile {
			return nil, fingerprint{}, store.ErrSharedTaskSealedReference
		}
		return data, fingerprint{true, info.Mode(), sha256.Sum256(data)}, nil
	}
	main, mainPrint, err := read(source, true)
	if err != nil {
		return "", nil, nil, err
	}
	wal, walPrint, err := read(source+"-wal", false)
	if err != nil {
		return "", nil, nil, err
	}
	directory, err := os.MkdirTemp("", "cicada-task-body-")
	if err != nil {
		return "", nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	target := filepath.Join(directory, "snapshot.sqlite")
	if err = os.WriteFile(target, main, 0600); err != nil {
		cleanup()
		return "", nil, nil, err
	}
	if walPrint.Exists {
		if err = os.WriteFile(target+"-wal", wal, 0600); err != nil {
			cleanup()
			return "", nil, nil, err
		}
	}
	stable := func() bool {
		_, currentMain, err := read(source, true)
		if err != nil || currentMain != mainPrint {
			return false
		}
		_, currentWal, err := read(source+"-wal", false)
		return err == nil && currentWal == walPrint
	}
	if !stable() {
		cleanup()
		return "", nil, nil, store.ErrSharedTaskSealedReference
	}
	return target, stable, cleanup, nil
}
