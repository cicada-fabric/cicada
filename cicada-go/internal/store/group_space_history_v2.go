package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type GroupSpaceHistoryManifestInput struct {
	GroupID             string `json:"group_id"`
	RecordID            string `json:"record_id"`
	RecipientEndpointID string `json:"recipient_endpoint_id"`
	OwnerKeyID          string `json:"owner_key_id"`
}

type GroupSpaceHistoryManifest struct {
	Grant     e2ee.GroupSpaceHistoryGrant `json:"grant"`
	Recipient GroupSpaceEndpointEvidence  `json:"recipient"`
	Resharer  GroupSpaceEndpointEvidence  `json:"resharer"`
	Original  GroupSpaceRecord            `json:"original"`
}

type GroupSpaceHistoryCommitInput struct {
	ManifestID       string                     `json:"manifest_id"`
	OwnerProof       []byte                     `json:"owner_proof"`
	ReaderCiphertext GroupSpaceReaderCiphertext `json:"reader_ciphertext"`
}

func groupSpaceEvidenceDigest(evidence GroupSpaceEndpointEvidence) string {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("cicada/group-space/recipient-evidence/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

func GroupSpaceHistoryReaderContext(snapshot GroupSpaceSnapshot,
	reader GroupSpaceEndpointEvidence, manifestID string) e2ee.GroupSpaceContext {
	c := groupSpaceContext(snapshot, reader)
	c.HistoryGrantID = manifestID
	return c
}

func (s *Store) GroupSpaceHistoryManifestGroupID(manifestID string) (string, error) {
	if !validSameGroupSealedV1Token(manifestID) {
		return "", ErrGroupSpaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var groupID string
	if s.db.QueryRow(`SELECT r.group_id FROM group_space_history_manifests_v2 h
JOIN group_space_records_v2 r ON r.record_id=h.record_id WHERE h.manifest_id=?`,
		manifestID).Scan(&groupID) != nil {
		return "", ErrGroupSpaceNotFound
	}
	return groupID, nil
}

// GetGroupSpaceHistoryManifest freezes one recipient key and the original
// ciphertext digest for independent Owner signing. The requester must be a
// currently authorized original reader able to supply the old signed body.
func (s *Store) GetGroupSpaceHistoryManifest(actor GroupSpaceActor,
	in GroupSpaceHistoryManifestInput) (*GroupSpaceHistoryManifest, error) {
	if !validSameGroupSealedV1Token(in.GroupID) || in.GroupID != actor.Scope.GroupID ||
		!validSameGroupSealedV1Token(in.RecordID) ||
		!validSameGroupSealedV1Token(in.RecipientEndpointID) ||
		!validSameGroupSealedV1Token(in.OwnerKeyID) ||
		in.RecipientEndpointID == actor.Scope.EndpointID {
		return nil, ErrGroupSpaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err := guardGroupSpaceActorTx(tx, actor, "space.read", at); err != nil {
		return nil, err
	}
	if _, err := purgeExpiredGroupSpacesTx(tx, at, GroupSpaceMaxPage); err != nil {
		return nil, err
	}
	original, err := groupSpaceProjectionTx(tx, actor.Scope, in.RecordID, at)
	if err != nil {
		return nil, err
	}
	var ownerID string
	if tx.QueryRow(`SELECT p.owner_id FROM groups g JOIN principals p ON p.id=g.owner_principal_id
WHERE g.id=? AND g.network_id=? AND g.state='ACTIVE'`, in.GroupID,
		actor.Scope.NetworkID).Scan(&ownerID) != nil || ownerID == "" {
		return nil, ErrGroupSpaceDenied
	}
	var ownerKey e2ee.PublicIdentity
	var keyState string
	var publicJSON string
	if tx.QueryRow(`SELECT public_identity_json,state FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, ownerID, in.OwnerKeyID).Scan(&publicJSON, &keyState) != nil ||
		keyState != OwnerApprovalKeyActive || json.Unmarshal([]byte(publicJSON), &ownerKey) != nil ||
		ownerKey.ID != in.OwnerKeyID {
		return nil, ErrGroupSpaceDenied
	}
	var recipientPrincipal string
	if tx.QueryRow(`SELECT principal_id FROM fabric_endpoints WHERE id=?`,
		in.RecipientEndpointID).Scan(&recipientPrincipal) != nil ||
		networkGuardGroupEndpointTx(tx, recipientPrincipal, in.RecipientEndpointID, in.GroupID, at) != nil {
		return nil, ErrGroupSpaceDenied
	}
	var hasRead int
	if tx.QueryRow(`SELECT 1 FROM memberships m WHERE m.principal_id=? AND m.group_id=?
AND m.status='active' AND cicada_network_expiry_allows(m.expires_at,?)=1
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))`,
		recipientPrincipal, in.GroupID, at.Format(time.RFC3339Nano)).Scan(&hasRead) != nil {
		return nil, ErrGroupSpaceDenied
	}
	var cutoff int64
	var active int
	if tx.QueryRow(`SELECT read_from_seq,active FROM group_space_audience_v2
WHERE group_id=? AND endpoint_id=? AND principal_id=?`, in.GroupID,
		in.RecipientEndpointID, recipientPrincipal).Scan(&cutoff, &active) != nil ||
		active != 1 || cutoff <= original.Snapshot.Sequence {
		return nil, ErrGroupSpaceInvalid
	}
	var totalRecipients int
	if tx.QueryRow(`SELECT COUNT(*) FROM (SELECT endpoint_id FROM group_space_readers_v2 WHERE record_id=?
UNION SELECT recipient_endpoint_id FROM group_space_history_grants_v2 WHERE record_id=?)`, in.RecordID,
		in.RecordID).Scan(&totalRecipients) != nil {
		return nil, ErrGroupSpaceLimit
	}
	var alreadyRecipient int
	if tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM group_space_readers_v2 WHERE record_id=? AND endpoint_id=?
UNION SELECT 1 FROM group_space_history_grants_v2 WHERE record_id=? AND recipient_endpoint_id=?)`,
		in.RecordID, in.RecipientEndpointID, in.RecordID,
		in.RecipientEndpointID).Scan(&alreadyRecipient) != nil ||
		(totalRecipients >= GroupSpaceMaxReaders && alreadyRecipient != 1) {
		return nil, ErrGroupSpaceLimit
	}
	recipient, err := groupSpaceEndpointEvidenceTx(tx, in.GroupID, in.RecipientEndpointID, at)
	if err != nil || recipient.OwnerID != ownerID {
		return nil, ErrGroupSpaceNotReady
	}
	resharer, err := groupSpaceEndpointEvidenceTx(tx, in.GroupID, actor.Scope.EndpointID, at)
	if err != nil || resharer.OwnerID != ownerID {
		return nil, ErrGroupSpaceNotReady
	}
	var networkRevision int64
	if tx.QueryRow(`SELECT revision FROM endpoint_network_memberships_v2
WHERE network_id=? AND endpoint_id=? AND status='active'`, actor.Scope.NetworkID,
		in.RecipientEndpointID).Scan(&networkRevision) != nil {
		return nil, ErrGroupSpaceDenied
	}
	var priorID string
	err = tx.QueryRow(`SELECT manifest_id FROM group_space_history_manifests_v2
WHERE record_id=? AND recipient_endpoint_id=? AND resharer_endpoint_id=?
ORDER BY reserved_at DESC, manifest_id DESC LIMIT 1`,
		in.RecordID, in.RecipientEndpointID, actor.Scope.EndpointID).Scan(&priorID)
	if err == nil {
		manifest, err := groupSpaceHistoryManifestTx(tx, priorID)
		if err == nil && manifest.Grant.RecipientKeyID == recipient.KeyID &&
			manifest.Grant.RecipientJoinRevision == recipient.JoinRevision &&
			manifest.Grant.RecipientNetworkRevision == networkRevision &&
			manifest.Grant.RecipientEvidenceDigest == groupSpaceEvidenceDigest(recipient) &&
			networkExpiryAllows(manifest.Grant.ExpiresAt, at) {
			manifest.Original = original
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return &manifest, nil
		}
		var grantCount int
		if tx.QueryRow(`SELECT COUNT(*) FROM group_space_history_grants_v2 WHERE manifest_id=?`,
			priorID).Scan(&grantCount) != nil {
			return nil, ErrGroupSpaceConflict
		}
		if grantCount == 0 {
			if _, err := tx.Exec(`DELETE FROM group_space_history_manifests_v2 WHERE manifest_id=?`, priorID); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var pendingGroup, pendingRecord int
	if tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN h.record_id=? THEN 1 ELSE 0 END),0)
FROM group_space_history_manifests_v2 h JOIN group_space_records_v2 r ON r.record_id=h.record_id
WHERE r.group_id=? AND cicada_network_expiry_allows(h.expires_at,?)=1
AND NOT EXISTS(SELECT 1 FROM group_space_history_grants_v2 gr WHERE gr.manifest_id=h.manifest_id)`,
		in.RecordID, in.GroupID, at.Format(time.RFC3339Nano)).Scan(&pendingGroup, &pendingRecord) != nil ||
		pendingGroup >= groupSpaceActiveQuota || pendingRecord >= groupSpaceHistoryQuota {
		return nil, ErrGroupSpaceLimit
	}
	deadline := at.Add(time.Hour)
	recordDeadline, err := time.Parse(time.RFC3339Nano, original.Snapshot.ExpiresAt)
	if err != nil {
		return nil, ErrGroupSpaceInvalid
	}
	if deadline.After(recordDeadline) {
		deadline = recordDeadline
	}
	grant := e2ee.GroupSpaceHistoryGrant{
		Version: 1, ManifestID: NewID("spaces_hist"), HubID: original.Snapshot.HubID,
		NetworkID: original.Snapshot.NetworkID, GroupID: original.Snapshot.GroupID,
		RecordID: in.RecordID, OriginalCiphertextDigest: original.CiphertextDigest,
		RecipientEndpointID: recipient.EndpointID, RecipientKeyID: recipient.KeyID,
		RecipientBindingID:          recipient.BindingID,
		RecipientBindingEpoch:       recipient.BindingEpoch,
		RecipientMembershipRevision: recipient.MembershipRevision,
		RecipientEvidenceDigest:     groupSpaceEvidenceDigest(recipient),
		RecipientJoinRevision:       recipient.JoinRevision,
		RecipientNetworkRevision:    networkRevision, OwnerID: ownerID,
		OwnerKeyID: in.OwnerKeyID, ExpiresAt: deadline.Format(time.RFC3339Nano),
	}
	grantJSON, _ := json.Marshal(grant)
	recipientJSON, _ := json.Marshal(recipient)
	resharerJSON, _ := json.Marshal(resharer)
	_, retainedBytes, err := groupSpaceUsageTx(tx, in.GroupID, at)
	if err != nil || retainedBytes+int64(len(grantJSON)+len(recipientJSON)+len(resharerJSON)) > groupSpaceCiphertextQuota {
		return nil, ErrGroupSpaceLimit
	}
	_, err = tx.Exec(`INSERT INTO group_space_history_manifests_v2
(manifest_id,record_id,recipient_endpoint_id,resharer_endpoint_id,grant_json,recipient_json,resharer_json,reserved_at,expires_at)
VALUES(?,?,?,?,?,?,?,?,?)`, grant.ManifestID, in.RecordID, recipient.EndpointID,
		resharer.EndpointID, string(grantJSON), string(recipientJSON),
		string(resharerJSON), at.Format(time.RFC3339Nano), grant.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &GroupSpaceHistoryManifest{Grant: grant, Recipient: recipient,
		Resharer: resharer, Original: original}, nil
}

func groupSpaceHistoryManifestTx(tx *sql.Tx, id string) (GroupSpaceHistoryManifest, error) {
	var grantJSON, recipientJSON, resharerJSON string
	err := tx.QueryRow(`SELECT grant_json,recipient_json,resharer_json
FROM group_space_history_manifests_v2 WHERE manifest_id=?`, id).Scan(
		&grantJSON, &recipientJSON, &resharerJSON)
	if err != nil {
		return GroupSpaceHistoryManifest{}, err
	}
	var manifest GroupSpaceHistoryManifest
	if json.Unmarshal([]byte(grantJSON), &manifest.Grant) != nil ||
		json.Unmarshal([]byte(recipientJSON), &manifest.Recipient) != nil ||
		json.Unmarshal([]byte(resharerJSON), &manifest.Resharer) != nil {
		return GroupSpaceHistoryManifest{}, ErrGroupSpaceInvalid
	}
	return manifest, nil
}

// GrantGroupSpaceHistorySealed is one-record, one-reader authorization. The
// Owner proof is independent of the current old-reader's ciphertext rewrap.
func (s *Store) GrantGroupSpaceHistorySealed(actor GroupSpaceActor,
	in GroupSpaceHistoryCommitInput) (*GroupSpaceRecord, error) {
	if !validSameGroupSealedV1Token(in.ManifestID) ||
		!validSameGroupSealedV1Token(in.ReaderCiphertext.EndpointID) ||
		len(in.OwnerProof) == 0 || len(in.OwnerProof) > 16*1024 ||
		len(in.ReaderCiphertext.Wire) == 0 || len(in.ReaderCiphertext.Wire) > 64*1024 {
		return nil, ErrGroupSpaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	manifest, err := groupSpaceHistoryManifestTx(tx, in.ManifestID)
	if err != nil || manifest.Grant.GroupID != actor.Scope.GroupID ||
		manifest.Grant.NetworkID != actor.Scope.NetworkID ||
		manifest.Resharer.EndpointID != actor.Scope.EndpointID {
		return nil, ErrGroupSpaceDenied
	}
	if err := guardGroupSpaceActorTx(tx, actor, "space.read", at); err != nil {
		return nil, err
	}
	if groupSpaceRecordReadableTx(tx, actor.Scope, manifest.Grant.RecordID, at) != nil {
		return nil, ErrGroupSpaceDenied
	}
	var storedDigest, recordExpiry string
	var recordSeq int64
	if tx.QueryRow(`SELECT ciphertext_digest,expires_at,seq FROM group_space_records_v2
WHERE record_id=? AND state='COMMITTED'`, manifest.Grant.RecordID).Scan(
		&storedDigest, &recordExpiry, &recordSeq) != nil ||
		storedDigest != manifest.Grant.OriginalCiphertextDigest ||
		!networkExpiryAllows(recordExpiry, at) ||
		!networkExpiryAllows(manifest.Grant.ExpiresAt, at) {
		return nil, ErrGroupSpaceConflict
	}
	if in.ReaderCiphertext.EndpointID != manifest.Recipient.EndpointID ||
		in.ReaderCiphertext.KeyID != manifest.Recipient.KeyID {
		return nil, ErrGroupSpaceConflict
	}
	// A retry must use the identical Owner proof and sealed bytes, even after
	// a response was lost. Current Guard above remains mandatory.
	var existingProof, existingWire []byte
	err = tx.QueryRow(`SELECT owner_proof,ciphertext FROM group_space_history_grants_v2
WHERE manifest_id=?`, in.ManifestID).Scan(&existingProof, &existingWire)
	if err == nil {
		if !bytes.Equal(existingProof, in.OwnerProof) ||
			!bytes.Equal(existingWire, in.ReaderCiphertext.Wire) {
			return nil, ErrGroupSpaceConflict
		}
		record, err := groupSpaceProjectionTx(tx, actor.Scope, manifest.Grant.RecordID, at)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &record, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var historyCount int
	if tx.QueryRow(`SELECT COUNT(*) FROM group_space_history_grants_v2 WHERE record_id=?`,
		manifest.Grant.RecordID).Scan(&historyCount) != nil || historyCount >= groupSpaceHistoryQuota {
		return nil, ErrGroupSpaceLimit
	}
	var readerFrom int64
	var readerActive, networkRevision int64
	if tx.QueryRow(`SELECT read_from_seq,active FROM group_space_audience_v2
WHERE group_id=? AND endpoint_id=?`, manifest.Grant.GroupID,
		manifest.Recipient.EndpointID).Scan(&readerFrom, &readerActive) != nil ||
		readerActive != 1 || readerFrom <= recordSeq ||
		tx.QueryRow(`SELECT revision FROM endpoint_network_memberships_v2
WHERE network_id=? AND endpoint_id=? AND status='active'`,
			manifest.Grant.NetworkID, manifest.Recipient.EndpointID).Scan(&networkRevision) != nil ||
		networkRevision != manifest.Grant.RecipientNetworkRevision {
		return nil, ErrGroupSpaceDenied
	}
	if networkGuardGroupEndpointTx(tx, manifest.Recipient.PrincipalID,
		manifest.Recipient.EndpointID, manifest.Grant.GroupID, at) != nil {
		return nil, ErrGroupSpaceDenied
	}
	var hasRead int
	if tx.QueryRow(`SELECT 1 FROM memberships m WHERE m.principal_id=? AND m.group_id=?
AND m.status='active' AND cicada_network_expiry_allows(m.expires_at,?)=1
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))`,
		manifest.Recipient.PrincipalID, manifest.Grant.GroupID,
		at.Format(time.RFC3339Nano)).Scan(&hasRead) != nil {
		return nil, ErrGroupSpaceDenied
	}
	recipient, err := groupSpaceEndpointEvidenceTx(tx, manifest.Grant.GroupID,
		manifest.Recipient.EndpointID, at)
	if err != nil || recipient.KeyID != manifest.Grant.RecipientKeyID ||
		recipient.JoinRevision != manifest.Grant.RecipientJoinRevision ||
		recipient.BindingID != manifest.Grant.RecipientBindingID ||
		recipient.BindingEpoch != manifest.Grant.RecipientBindingEpoch ||
		recipient.MembershipRevision != manifest.Grant.RecipientMembershipRevision ||
		groupSpaceEvidenceDigest(recipient) != manifest.Grant.RecipientEvidenceDigest ||
		recipient.Grant.Manifest.Digest != manifest.Recipient.Grant.Manifest.Digest {
		return nil, ErrGroupSpaceConflict
	}
	resharer, err := groupSpaceEndpointEvidenceTx(tx, manifest.Grant.GroupID,
		actor.Scope.EndpointID, at)
	if err != nil || resharer.KeyID != manifest.Resharer.KeyID ||
		resharer.Grant.Manifest.Digest != manifest.Resharer.Grant.Manifest.Digest {
		return nil, ErrGroupSpaceConflict
	}
	var ownerPublicJSON, ownerState string
	if tx.QueryRow(`SELECT public_identity_json,state FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, manifest.Grant.OwnerID,
		manifest.Grant.OwnerKeyID).Scan(&ownerPublicJSON, &ownerState) != nil ||
		ownerState != OwnerApprovalKeyActive {
		return nil, ErrGroupSpaceDenied
	}
	var ownerPublic e2ee.PublicIdentity
	if json.Unmarshal([]byte(ownerPublicJSON), &ownerPublic) != nil {
		return nil, ErrGroupSpaceDenied
	}
	verified, err := e2ee.VerifyGroupSpaceHistoryGrant(in.OwnerProof,
		ownerPublic, manifest.Grant, at)
	if err != nil {
		return nil, ErrGroupSpaceDenied
	}
	var snapshot GroupSpaceSnapshot
	var snapshotJSON string
	if tx.QueryRow(`SELECT snapshot_json FROM group_space_records_v2 WHERE record_id=?`,
		manifest.Grant.RecordID).Scan(&snapshotJSON) != nil ||
		json.Unmarshal([]byte(snapshotJSON), &snapshot) != nil {
		return nil, ErrGroupSpaceNotFound
	}
	context := GroupSpaceHistoryReaderContext(snapshot, recipient, in.ManifestID)
	if e2ee.VerifyGroupSpaceReader(resharer.PublicIdentity, context,
		in.ReaderCiphertext.Wire) != nil {
		return nil, ErrGroupSpaceInvalid
	}
	var totalRecipients int
	if tx.QueryRow(`SELECT COUNT(*) FROM (SELECT endpoint_id FROM group_space_readers_v2 WHERE record_id=?
UNION SELECT recipient_endpoint_id FROM group_space_history_grants_v2 WHERE record_id=?)`,
		manifest.Grant.RecordID, manifest.Grant.RecordID).Scan(&totalRecipients) != nil {
		return nil, ErrGroupSpaceLimit
	}
	var alreadyRecipient int
	if tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM group_space_readers_v2 WHERE record_id=? AND endpoint_id=?
UNION SELECT 1 FROM group_space_history_grants_v2 WHERE record_id=? AND recipient_endpoint_id=?)`,
		manifest.Grant.RecordID, recipient.EndpointID, manifest.Grant.RecordID,
		recipient.EndpointID).Scan(&alreadyRecipient) != nil ||
		(totalRecipients >= GroupSpaceMaxReaders && alreadyRecipient != 1) {
		return nil, ErrGroupSpaceLimit
	}
	wireDigest := sha256.Sum256(in.ReaderCiphertext.Wire)
	resharerJSON, _ := json.Marshal(resharer)
	_, retainedBytes, err := groupSpaceUsageTx(tx, manifest.Grant.GroupID, at)
	if err != nil || retainedBytes+int64(len(in.ReaderCiphertext.Wire)+len(in.OwnerProof)+len(resharerJSON)) > groupSpaceCiphertextQuota {
		return nil, ErrGroupSpaceLimit
	}
	_, err = tx.Exec(`INSERT INTO group_space_history_grants_v2
(manifest_id,record_id,recipient_endpoint_id,recipient_key_id,recipient_join_revision,
recipient_network_revision,resharer_endpoint_id,resharer_json,owner_proof,owner_nonce,
ciphertext,ciphertext_digest,expires_at,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, in.ManifestID, manifest.Grant.RecordID,
		recipient.EndpointID, recipient.KeyID, recipient.JoinRevision, networkRevision,
		resharer.EndpointID, string(resharerJSON), in.OwnerProof, verified.Nonce,
		in.ReaderCiphertext.Wire, hex.EncodeToString(wireDigest[:]),
		verified.ExpiresAt, at.Format(time.RFC3339Nano))
	if err != nil {
		return nil, ErrGroupSpaceConflict
	}
	record, err := groupSpaceProjectionTx(tx, actor.Scope, manifest.Grant.RecordID, at)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &record, nil
}
