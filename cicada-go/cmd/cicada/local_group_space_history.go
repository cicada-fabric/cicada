package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func (b *machineAgentJoinBridge) groupSpaceHistory(request groupSpaceLocalRequest,
	actor store.GroupSpaceEndpointEvidence, identity *e2ee.Identity,
	cryptoState *nodekeys.CryptoState) (*groupSpaceLocalResult, error) {
	var proof []byte
	var claimed e2ee.GroupSpaceHistoryGrant
	if request.Operation == "space_history_share" {
		var err error
		proof, err = base64.StdEncoding.Strict().DecodeString(request.OwnerProof)
		if err != nil || len(proof) == 0 || len(proof) > 16*1024 ||
			json.Unmarshal(proof, &claimed) != nil || claimed.ManifestID == "" ||
			claimed.GroupID != request.GroupID {
			return nil, errors.New("invalid Owner history proof")
		}
		request.RecordID = claimed.RecordID
		request.RecipientEndpointID = claimed.RecipientEndpointID
		request.OwnerKeyID = claimed.OwnerKeyID
	}
	if request.RecordID == "" || request.RecipientEndpointID == "" || request.OwnerKeyID == "" {
		return nil, errors.New("history manifest scope is incomplete")
	}
	var manifest store.GroupSpaceHistoryManifest
	if err := b.groupSpaceHTTP(request.SessionToken, "history/manifest",
		store.GroupSpaceHistoryManifestInput{GroupID: request.GroupID,
			RecordID: request.RecordID, RecipientEndpointID: request.RecipientEndpointID,
			OwnerKeyID: request.OwnerKeyID}, &manifest); err != nil {
		return nil, err
	}
	grant := manifest.Grant
	if grant.GroupID != request.GroupID || grant.RecordID != request.RecordID ||
		grant.RecipientEndpointID != request.RecipientEndpointID ||
		grant.OwnerKeyID != request.OwnerKeyID || grant.ManifestID == "" ||
		grant.OriginalCiphertextDigest != manifest.Original.CiphertextDigest ||
		grant.HubID != manifest.Original.Snapshot.HubID ||
		grant.NetworkID != manifest.Original.Snapshot.NetworkID ||
		manifest.Resharer.EndpointID != actor.EndpointID ||
		manifest.Resharer.KeyID != identity.Public().ID ||
		manifest.Recipient.EndpointID != grant.RecipientEndpointID ||
		manifest.Recipient.KeyID != grant.RecipientKeyID {
		return nil, errors.New("Hub returned a mismatched history manifest")
	}
	if request.Operation == "space_history_share" && claimed.ManifestID != grant.ManifestID {
		return nil, errors.New("Owner proof names a stale history manifest")
	}
	if verified, err := b.verifyGroupSpaceKey(cryptoState, manifest.Original.Snapshot,
		manifest.Resharer, time.Now().UTC()); err != nil ||
		!machineSamePublicIdentity(verified, identity.Public()) {
		return nil, errors.New("history resharer key is not currently Owner-trusted")
	}
	recipientKey, err := b.verifyGroupSpaceKey(cryptoState, manifest.Original.Snapshot,
		manifest.Recipient, time.Now().UTC())
	if err != nil || !machineSamePublicIdentity(recipientKey, manifest.Recipient.PublicIdentity) {
		return nil, errors.New("history recipient key is not currently Owner-trusted")
	}
	_, signedBody, err := b.openGroupSpaceRecordSigned(manifest.Original,
		request.GroupID, actor.EndpointID, identity, cryptoState)
	if err != nil {
		return nil, err
	}
	if request.Operation == "space_history_manifest" {
		return &groupSpaceLocalResult{HistoryGrant: &grant}, nil
	}
	ownerTrust, err := cryptoState.GetNodeOwnerKeyTrustLocal(grant.OwnerID, grant.OwnerKeyID)
	if err != nil || ownerTrust.State != nodekeys.NodeOwnerKeyTrustActive {
		return nil, errors.New("history Owner key is not locally trusted")
	}
	if _, err := e2ee.VerifyGroupSpaceHistoryGrant(proof, ownerTrust.PublicIdentity,
		grant, time.Now().UTC()); err != nil {
		return nil, errors.New("history Owner proof does not authorize this exact record and reader")
	}
	cachePath := groupSpaceCachePath(b.stateDir, b.nodeID, request.GroupID,
		"history:"+grant.ManifestID)
	proofSum := sha256.Sum256(proof)
	cache, err := loadGroupSpaceCache(cachePath)
	if err != nil {
		return nil, err
	}
	if cache == nil {
		context := store.GroupSpaceHistoryReaderContext(manifest.Original.Snapshot,
			manifest.Recipient, grant.ManifestID)
		sequence, err := cryptoState.ReserveOutboundSequence(b.ctx,
			actor.EndpointID, identity.Public().ID)
		if err != nil {
			return nil, errors.New("could not reserve history rewrap crypto sequence")
		}
		wire, err := e2ee.SealGroupSpaceReader(identity, recipientKey, context,
			signedBody, sequence)
		if err != nil {
			return nil, err
		}
		cache, err = persistGroupSpaceCache(cachePath, groupSpaceSealedCache{
			ReservationID: grant.ManifestID, RecordID: grant.RecordID,
			OperationID: grant.ManifestID, GroupID: request.GroupID,
			BodyDigest:     hex.EncodeToString(proofSum[:]),
			SnapshotDigest: grant.RecipientEvidenceDigest,
			ReaderCiphertexts: []store.GroupSpaceReaderCiphertext{{
				EndpointID: grant.RecipientEndpointID, KeyID: grant.RecipientKeyID,
				Wire: wire}},
		})
		if err != nil {
			return nil, err
		}
	}
	if cache.ReservationID != grant.ManifestID || cache.RecordID != grant.RecordID ||
		cache.OperationID != grant.ManifestID || cache.GroupID != request.GroupID ||
		cache.BodyDigest != hex.EncodeToString(proofSum[:]) ||
		cache.SnapshotDigest != grant.RecipientEvidenceDigest ||
		len(cache.ReaderCiphertexts) != 1 ||
		cache.ReaderCiphertexts[0].EndpointID != grant.RecipientEndpointID ||
		cache.ReaderCiphertexts[0].KeyID != grant.RecipientKeyID {
		return nil, errors.New("history grant retry conflicts with durable sealed material")
	}
	var record store.GroupSpaceRecord
	if err := b.groupSpaceHTTP(request.SessionToken, "history/grant",
		store.GroupSpaceHistoryCommitInput{ManifestID: grant.ManifestID,
			OwnerProof: proof, ReaderCiphertext: cache.ReaderCiphertexts[0]}, &record); err != nil {
		return nil, err
	}
	public, err := b.openGroupSpaceRecord(record, request.GroupID,
		actor.EndpointID, identity, cryptoState)
	if err != nil {
		return nil, err
	}
	return &groupSpaceLocalResult{Record: &public}, nil
}
