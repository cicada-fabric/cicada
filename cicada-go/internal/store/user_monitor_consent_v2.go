package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// UserMonitorBroadcastV2Preview is the bounded, Client-visible authorization
// evidence. It deliberately contains no native session, workspace or PQ roster.
type UserMonitorBroadcastV2Preview struct {
	MonitorGrantManifest    GroupEndpointKeyGrantManifest     `json:"monitor_grant_manifest"`
	MonitorGrantSignedProof []byte                            `json:"monitor_grant_signed_proof"`
	ConsentScope            e2ee.MonitorBroadcastConsentScope `json:"consent_scope"`
	ConsentSHA256           string                            `json:"consent_sha256"`
}

func userMonitorConsentEndpoint(endpoint SameGroupBroadcastV2Endpoint) (e2ee.MonitorBroadcastConsentEndpoint, error) {
	fingerprint, err := nodekeys.PeerKeyFingerprint(endpoint.PublicKey)
	if err != nil {
		return e2ee.MonitorBroadcastConsentEndpoint{}, err
	}
	return e2ee.MonitorBroadcastConsentEndpoint{
		EndpointID: endpoint.EndpointID, PrincipalID: endpoint.PrincipalID,
		OwnerID: endpoint.OwnerID, NodeID: endpoint.NodeID,
		MembershipRevision: endpoint.MembershipRevision, GroupJoinRevision: endpoint.GroupJoinRevision,
		BindingID: endpoint.BindingID, BindingEpoch: endpoint.BindingEpoch,
		KeyID: endpoint.KeyID, KeyVersion: endpoint.KeyVersion,
		KeyFingerprint: fingerprint, KeyProofDigest: endpoint.KeyProofDigest,
	}, nil
}

func userMonitorConsentScope(snapshot *SameGroupBroadcastV2Snapshot) (e2ee.MonitorBroadcastConsentScope, string, error) {
	if snapshot == nil || len(snapshot.Recipients) > SameGroupBroadcastV2MaxRecipients {
		return e2ee.MonitorBroadcastConsentScope{}, "", ErrUserMonitorBroadcastV2Denied
	}
	source, err := userMonitorConsentEndpoint(snapshot.Source)
	if err != nil {
		return e2ee.MonitorBroadcastConsentScope{}, "", err
	}
	scope := e2ee.MonitorBroadcastConsentScope{Version: e2ee.MonitorBroadcastConsentVersion,
		BroadcastID: snapshot.BroadcastID, GroupID: snapshot.GroupID,
		GroupRevision: snapshot.GroupRevision, Source: source,
		Recipients: make([]e2ee.MonitorBroadcastConsentEndpoint, 0, len(snapshot.Recipients))}
	for _, recipient := range snapshot.Recipients {
		card, err := userMonitorConsentEndpoint(recipient)
		if err != nil {
			return e2ee.MonitorBroadcastConsentScope{}, "", err
		}
		scope.Recipients = append(scope.Recipients, card)
	}
	digest, err := e2ee.MonitorBroadcastConsentDigest(scope)
	return scope, digest, err
}

// MonitorBroadcastConsentFromSnapshot lets the native Node independently
// recompute the scope before releasing the decrypted body to its session.
func MonitorBroadcastConsentFromSnapshot(snapshot *SameGroupBroadcastV2Snapshot) (e2ee.MonitorBroadcastConsentScope, string, error) {
	return userMonitorConsentScope(snapshot)
}

func userMonitorPreviewTx(tx *sql.Tx, snapshot *SameGroupBroadcastV2Snapshot, at time.Time) (*UserMonitorBroadcastV2Preview, error) {
	grant, err := readLatestGroupEndpointKeyGrant(tx, snapshot.Source.OwnerID, snapshot.GroupID, snapshot.Source.EndpointID)
	if err != nil || evaluateGroupEndpointKeyGrant(tx, grant, at) != GroupEndpointKeyGrantCurrent {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	manifest := grant.Manifest
	if manifest.CandidateKeyID != snapshot.Source.KeyID ||
		manifest.CandidateVersion != snapshot.Source.KeyVersion ||
		manifest.CandidateProofDigest != snapshot.Source.KeyProofDigest ||
		manifest.BindingID != snapshot.Source.BindingID || manifest.BindingEpoch != snapshot.Source.BindingEpoch ||
		manifest.CandidatePublicIdentity.ID != snapshot.Source.PublicKey.ID ||
		manifest.GroupRevision != snapshot.GroupRevision ||
		manifest.MembershipRevision != snapshot.Source.MembershipRevision ||
		manifest.EndpointJoinRevision != snapshot.Source.GroupJoinRevision {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	scope, digest, err := userMonitorConsentScope(snapshot)
	if err != nil || manifest.CandidateFingerprint != scope.Source.KeyFingerprint {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	return &UserMonitorBroadcastV2Preview{MonitorGrantManifest: manifest,
		MonitorGrantSignedProof: append([]byte(nil), grant.SignedProof...),
		ConsentScope:            scope, ConsentSHA256: digest}, nil
}

func encodedUserMonitorPreview(preview *UserMonitorBroadcastV2Preview) (string, error) {
	if preview == nil {
		return "", errors.New("missing Monitor preview")
	}
	data, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	if len(data) > 48*1024 {
		return "", ErrUserMonitorBroadcastV2Denied
	}
	return string(data), nil
}

func decodedUserMonitorPreview(raw string, snapshot *SameGroupBroadcastV2Snapshot, consentDigest string) (*UserMonitorBroadcastV2Preview, error) {
	if len(raw) == 0 || len(raw) > 48*1024 {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	var preview UserMonitorBroadcastV2Preview
	if err := json.Unmarshal([]byte(raw), &preview); err != nil {
		return nil, err
	}
	scope, digest, err := userMonitorConsentScope(snapshot)
	if err != nil || digest != consentDigest || preview.ConsentSHA256 != digest {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	actual, err := json.Marshal(scope)
	if err != nil {
		return nil, err
	}
	stored, err := json.Marshal(preview.ConsentScope)
	if err != nil || string(actual) != string(stored) {
		return nil, ErrUserMonitorBroadcastV2Denied
	}
	return &preview, nil
}

func verifyStoredUserMonitorPreviewTx(tx *sql.Tx, preview *UserMonitorBroadcastV2Preview,
	snapshot *SameGroupBroadcastV2Snapshot) error {
	if preview == nil || snapshot == nil {
		return ErrUserMonitorBroadcastV2Denied
	}
	manifest := preview.MonitorGrantManifest
	if groupEndpointKeyManifestDigest(manifest) != manifest.Digest ||
		manifest.OwnerID != snapshot.Source.OwnerID || manifest.GroupID != snapshot.GroupID ||
		manifest.GroupRevision != snapshot.GroupRevision || manifest.EndpointID != snapshot.Source.EndpointID ||
		manifest.PrincipalID != snapshot.Source.PrincipalID || manifest.NodeID != snapshot.Source.NodeID ||
		manifest.BindingID != snapshot.Source.BindingID || manifest.BindingEpoch != snapshot.Source.BindingEpoch ||
		manifest.MembershipRevision != snapshot.Source.MembershipRevision ||
		manifest.EndpointJoinRevision != snapshot.Source.GroupJoinRevision ||
		manifest.CandidateKeyID != snapshot.Source.KeyID || manifest.CandidateVersion != snapshot.Source.KeyVersion ||
		manifest.CandidateProofDigest != snapshot.Source.KeyProofDigest ||
		manifest.CandidateFingerprint != preview.ConsentScope.Source.KeyFingerprint ||
		!reflect.DeepEqual(manifest.CandidatePublicIdentity, snapshot.Source.PublicKey) {
		return ErrUserMonitorBroadcastV2Denied
	}
	attested, err := e2ee.VerifyEndpointKeyAttestation(manifest.CandidateAttestation,
		manifest.EndpointID, manifest.PrincipalID, manifest.NodeID, manifest.BindingID, manifest.BindingEpoch)
	proofDigest := sha256.Sum256(manifest.CandidateAttestation)
	if err != nil || hex.EncodeToString(proofDigest[:]) != manifest.CandidateProofDigest ||
		!reflect.DeepEqual(attested, snapshot.Source.PublicKey) {
		return ErrUserMonitorBroadcastV2Denied
	}
	ownerKey, err := scanOwnerApprovalKey(tx.QueryRow(`SELECT owner_id,key_id,public_identity_json,
state,version,created_at,updated_at,revoked_at FROM owner_approval_keys_v2 WHERE owner_id=? AND key_id=?`,
		manifest.OwnerID, manifest.OwnerKeyID))
	if err != nil || ownerKey.State != OwnerApprovalKeyActive {
		return ErrUserMonitorBroadcastV2Denied
	}
	var signed e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(preview.MonitorGrantSignedProof, &signed); err != nil {
		return ErrUserMonitorBroadcastV2Denied
	}
	at, err := time.Parse(time.RFC3339Nano, signed.IssuedAt)
	if err != nil {
		return ErrUserMonitorBroadcastV2Denied
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(preview.MonitorGrantSignedProof, ownerKey.Public,
		manifest.OwnerID, GroupEndpointKeyGrantOperation, manifest.Digest,
		manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, at); err != nil {
		return ErrUserMonitorBroadcastV2Denied
	}
	return nil
}
