package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	GroupSpaceKindJournal     = "JOURNAL"
	GroupSpaceKindTopic       = "TOPIC"
	GroupSpaceKindReply       = "REPLY"
	GroupSpaceKindTopicStatus = "TOPIC_STATUS"
	GroupSpaceMaxReaders      = 32
	GroupSpaceMaxPage         = 16
	GroupSpaceMaxRetention    = 30 * 24 * time.Hour
	GroupSpaceReservationTTL  = 5 * time.Minute
	groupSpaceActiveQuota     = 64
	groupSpaceCommittedQuota  = 512
	groupSpaceCiphertextQuota = 64 << 20
	groupSpaceSnapshotLimit   = 2 << 20
	groupSpaceHistoryQuota    = 32
	groupSpaceTombstoneQuota  = 4096
)

var (
	ErrGroupSpaceDenied   = errors.New("Group Space access denied")
	ErrGroupSpaceInvalid  = errors.New("invalid Group Space request")
	ErrGroupSpaceConflict = errors.New("Group Space idempotency or version conflict")
	ErrGroupSpaceNotFound = errors.New("Group Space record not found")
	ErrGroupSpaceNotReady = errors.New("Group Space reader key is not ready")
	ErrGroupSpaceLimit    = errors.New("Group Space limit exceeded")
	ErrGroupSpaceHistory  = errors.New("Group Space history requires separately sealed material")
)

type GroupSpaceEndpointEvidence struct {
	EndpointID         string                     `json:"endpoint_id"`
	PrincipalID        string                     `json:"principal_id"`
	OwnerID            string                     `json:"owner_id"`
	NodeID             string                     `json:"node_id"`
	BindingID          string                     `json:"binding_id"`
	BindingEpoch       uint64                     `json:"binding_epoch"`
	MembershipRevision int64                      `json:"membership_revision"`
	JoinRevision       int64                      `json:"join_revision"`
	KeyID              string                     `json:"key_id"`
	PublicIdentity     e2ee.PublicIdentity        `json:"public_identity"`
	Grant              OwnerGroupEndpointKeyGrant `json:"grant"`
	// Empty for the frozen same-Owner v1 snapshot: omitempty preserves its
	// existing signed context bytes and stored ciphertext protocol.
	EvidenceProtocol    string                    `json:"evidence_protocol,omitempty"`
	CrossOwnerKeyStatus *CrossOwnerGroupKeyStatus `json:"cross_owner_key_status,omitempty"`
	Candidate           EndpointKeyCandidate      `json:"candidate"`
}

type GroupSpacePrepareInput struct {
	GroupID              string `json:"group_id"`
	OperationID          string `json:"operation_id"`
	Kind                 string `json:"kind"`
	TopicID              string `json:"topic_id,omitempty"`
	CorrectsID           string `json:"corrects_id,omitempty"`
	ExpectedTopicVersion int64  `json:"expected_topic_version,omitempty"`
	Status               string `json:"status,omitempty"`
	RetentionClass       string `json:"retention_class,omitempty"`
}

type GroupSpaceSnapshot struct {
	ReservationID        string                       `json:"reservation_id"`
	RecordID             string                       `json:"record_id"`
	OperationID          string                       `json:"operation_id"`
	HubID                string                       `json:"hub_id"`
	NetworkID            string                       `json:"network_id"`
	GroupID              string                       `json:"group_id"`
	Sequence             int64                        `json:"sequence"`
	Kind                 string                       `json:"kind"`
	TopicID              string                       `json:"topic_id,omitempty"`
	CorrectsID           string                       `json:"corrects_id,omitempty"`
	ExpectedTopicVersion int64                        `json:"expected_topic_version,omitempty"`
	Status               string                       `json:"status,omitempty"`
	RetentionClass       string                       `json:"retention_class"`
	ReaderSnapshotDigest string                       `json:"reader_snapshot_digest"`
	Producer             GroupSpaceEndpointEvidence   `json:"producer"`
	Readers              []GroupSpaceEndpointEvidence `json:"readers"`
	ReservedAt           string                       `json:"reserved_at"`
	ExpiresAt            string                       `json:"expires_at"`
	ReservationExpiresAt string                       `json:"reservation_expires_at"`
	Committed            bool                         `json:"committed"`
}

type GroupSpaceReaderCiphertext struct {
	EndpointID string `json:"endpoint_id"`
	KeyID      string `json:"key_id"`
	Wire       []byte `json:"wire"`
}

type GroupSpaceCommitInput struct {
	ReservationID     string                       `json:"reservation_id"`
	ReaderCiphertexts []GroupSpaceReaderCiphertext `json:"reader_ciphertexts"`
}

type GroupSpaceListInput struct {
	GroupID string `json:"group_id"`
	Kind    string `json:"kind,omitempty"`
	TopicID string `json:"topic_id,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

type GroupSpaceGetInput struct {
	GroupID  string `json:"group_id"`
	RecordID string `json:"record_id"`
}

type GroupSpaceRecord struct {
	Snapshot            GroupSpaceSnapshot           `json:"snapshot"`
	TopicVersion        int64                        `json:"topic_version,omitempty"`
	CurrentTopicVersion int64                        `json:"current_topic_version,omitempty"`
	CurrentTopicStatus  string                       `json:"current_topic_status,omitempty"`
	CreatedAt           string                       `json:"created_at"`
	CiphertextDigest    string                       `json:"ciphertext_digest"`
	ReaderCiphertext    GroupSpaceReaderCiphertext   `json:"reader_ciphertext"`
	HistoryGrantID      string                       `json:"history_grant_id,omitempty"`
	EnvelopeSigner      GroupSpaceEndpointEvidence   `json:"envelope_signer"`
	HistoryGrant        *e2ee.GroupSpaceHistoryGrant `json:"history_grant,omitempty"`
	HistoryOwnerProof   []byte                       `json:"history_owner_proof,omitempty"`
	HistoryOwnerPublic  e2ee.PublicIdentity          `json:"history_owner_public,omitempty"`
	HistoryGrantedAt    string                       `json:"history_granted_at,omitempty"`
}

type GroupSpacePage struct {
	Records    []GroupSpaceRecord `json:"records"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type GroupSpaceActor struct {
	Scope                NativeActorScope
	NodeCredentialDigest string
}

type groupSpaceCursor struct {
	Version    int    `json:"v"`
	GroupID    string `json:"g"`
	EndpointID string `json:"e"`
	Kind       string `json:"k"`
	TopicID    string `json:"t"`
	After      int64  `json:"a"`
}

func encodeGroupSpaceCursor(after int64, scope NativeActorScope, kind, topicID string) string {
	encoded, err := json.Marshal(groupSpaceCursor{Version: 1, GroupID: scope.GroupID,
		EndpointID: scope.EndpointID, Kind: kind, TopicID: topicID, After: after})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeGroupSpaceCursor(value string, scope NativeActorScope, kind, topicID string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	if len(value) > 2048 {
		return 0, ErrGroupSpaceInvalid
	}
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(encoded) > 1024 {
		return 0, ErrGroupSpaceInvalid
	}
	var cursor groupSpaceCursor
	if json.Unmarshal(encoded, &cursor) != nil || cursor.Version != 1 ||
		cursor.GroupID != scope.GroupID || cursor.EndpointID != scope.EndpointID ||
		cursor.Kind != kind || cursor.TopicID != topicID || cursor.After < 0 {
		return 0, ErrGroupSpaceInvalid
	}
	return cursor.After, nil
}

func (s *Store) initializeGroupSpaceSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS group_space_sequences_v2 (
 group_id TEXT PRIMARY KEY, next_seq INTEGER NOT NULL DEFAULT 1 CHECK(next_seq > 0)
);
CREATE TABLE IF NOT EXISTS group_space_audience_v2 (
 group_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, principal_id TEXT NOT NULL,
 read_from_seq INTEGER NOT NULL CHECK(read_from_seq > 0), active INTEGER NOT NULL CHECK(active IN (0,1)),
 updated_at TEXT NOT NULL, PRIMARY KEY(group_id,endpoint_id)
);
CREATE TABLE IF NOT EXISTS group_space_records_v2 (
 record_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL UNIQUE,
 operation_id TEXT NOT NULL, group_id TEXT NOT NULL, network_id TEXT NOT NULL, hub_id TEXT NOT NULL,
 seq INTEGER NOT NULL CHECK(seq > 0), kind TEXT NOT NULL CHECK(kind IN ('JOURNAL','TOPIC','REPLY','TOPIC_STATUS')),
 topic_id TEXT NOT NULL DEFAULT '', corrects_id TEXT NOT NULL DEFAULT '',
 expected_topic_version INTEGER NOT NULL DEFAULT 0, topic_version INTEGER NOT NULL DEFAULT 0,
 topic_status TEXT NOT NULL DEFAULT '', retention_class TEXT NOT NULL,
 producer_endpoint_id TEXT NOT NULL, producer_principal_id TEXT NOT NULL,
 snapshot_json TEXT NOT NULL, snapshot_digest TEXT NOT NULL,
 ciphertext_digest TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL CHECK(state IN ('PREPARED','COMMITTED','EXPIRED')),
 reserved_at TEXT NOT NULL, reservation_expires_at TEXT NOT NULL,
 committed_at TEXT NOT NULL DEFAULT '', expires_at TEXT NOT NULL,
 UNIQUE(group_id,seq), UNIQUE(hub_id,network_id,group_id,producer_endpoint_id,kind,operation_id)
);
CREATE TABLE IF NOT EXISTS group_space_readers_v2 (
 record_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, key_id TEXT NOT NULL,
 ciphertext BLOB NOT NULL DEFAULT X'',
 PRIMARY KEY(record_id,endpoint_id), FOREIGN KEY(record_id) REFERENCES group_space_records_v2(record_id)
);
CREATE TABLE IF NOT EXISTS group_space_topics_v2 (
 topic_id TEXT PRIMARY KEY, group_id TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version > 0), status TEXT NOT NULL CHECK(status IN ('OPEN','RESOLVED')),
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_space_history_manifests_v2 (
 manifest_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, recipient_endpoint_id TEXT NOT NULL,
 resharer_endpoint_id TEXT NOT NULL, grant_json TEXT NOT NULL, recipient_json TEXT NOT NULL,
 resharer_json TEXT NOT NULL, reserved_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_space_history_grants_v2 (
 manifest_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, recipient_endpoint_id TEXT NOT NULL,
 recipient_key_id TEXT NOT NULL, recipient_join_revision INTEGER NOT NULL,
 recipient_network_revision INTEGER NOT NULL, resharer_endpoint_id TEXT NOT NULL,
 resharer_json TEXT NOT NULL, owner_proof BLOB NOT NULL, owner_nonce TEXT NOT NULL UNIQUE,
 ciphertext BLOB NOT NULL, ciphertext_digest TEXT NOT NULL, expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL,
 FOREIGN KEY(manifest_id) REFERENCES group_space_history_manifests_v2(manifest_id)
);
CREATE TABLE IF NOT EXISTS group_space_tombstones_v2 (
 record_id TEXT PRIMARY KEY, hub_id TEXT NOT NULL,network_id TEXT NOT NULL,
 group_id TEXT NOT NULL,producer_endpoint_id TEXT NOT NULL,kind TEXT NOT NULL,
 operation_id TEXT NOT NULL,seq INTEGER NOT NULL,
 expired_at TEXT NOT NULL, purged_at TEXT NOT NULL,
 UNIQUE(hub_id,network_id,group_id,producer_endpoint_id,kind,operation_id)
);
CREATE INDEX IF NOT EXISTS group_space_history_record_reader_v2
 ON group_space_history_grants_v2(record_id,recipient_endpoint_id);
CREATE INDEX IF NOT EXISTS group_space_records_page_v2
 ON group_space_records_v2(group_id,kind,seq);
CREATE INDEX IF NOT EXISTS group_space_records_topic_v2
 ON group_space_records_v2(group_id,topic_id,seq);
CREATE INDEX IF NOT EXISTS group_space_records_expiry_v2
 ON group_space_records_v2(expires_at,state);
INSERT OR IGNORE INTO group_space_sequences_v2(group_id,next_seq)
 SELECT id,1 FROM groups;
INSERT OR IGNORE INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT eg.group_id,eg.endpoint_id,e.principal_id,1,1,strftime('%Y-%m-%dT%H:%M:%fZ','now')
 FROM endpoint_group_memberships eg JOIN fabric_endpoints e ON e.id=eg.endpoint_id
 JOIN memberships m ON m.principal_id=e.principal_id AND m.group_id=eg.group_id
 WHERE eg.status='active' AND m.status='active'
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'));
`)
	if err != nil {
		return fmt.Errorf("initialize Group Spaces: %w", err)
	}
	return s.initializeGroupSpaceCutoffTriggers()
}

// These triggers run in the existing join/authorization transaction. A
// previously active reader keeps its cutoff across unrelated grant, key, or
// lease changes; actual loss and regain of space.read starts a new window.
func (s *Store) initializeGroupSpaceCutoffTriggers() error {
	_, err := s.db.Exec(`
CREATE TRIGGER IF NOT EXISTS group_space_join_insert_v2 AFTER INSERT ON endpoint_group_memberships
WHEN NEW.status='active' BEGIN
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT NEW.group_id,NEW.endpoint_id,e.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=NEW.group_id),1),1,NEW.updated_at
 FROM fabric_endpoints e JOIN memberships m ON m.principal_id=e.principal_id AND m.group_id=NEW.group_id
 WHERE e.id=NEW.endpoint_id AND m.status='active'
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS group_space_join_update_v2 AFTER UPDATE OF status ON endpoint_group_memberships
WHEN OLD.status!=NEW.status BEGIN
 UPDATE group_space_audience_v2 SET active=0,updated_at=NEW.updated_at
 WHERE group_id=NEW.group_id AND endpoint_id=NEW.endpoint_id AND NEW.status!='active';
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT NEW.group_id,NEW.endpoint_id,e.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=NEW.group_id),1),1,NEW.updated_at
 FROM fabric_endpoints e JOIN memberships m ON m.principal_id=e.principal_id AND m.group_id=NEW.group_id
 WHERE e.id=NEW.endpoint_id AND NEW.status='active' AND m.status='active'
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS group_space_member_insert_v2 AFTER INSERT ON memberships
WHEN NEW.status='active' AND EXISTS(SELECT 1 FROM json_each(NEW.grants_json) WHERE value IN ('*','space.read')) BEGIN
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT NEW.group_id,e.id,NEW.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=NEW.group_id),1),1,NEW.updated_at
 FROM fabric_endpoints e JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=NEW.group_id
 WHERE e.principal_id=NEW.principal_id AND eg.status='active'
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS group_space_member_update_v2 AFTER UPDATE OF status,grants_json,expires_at ON memberships BEGIN
 UPDATE group_space_audience_v2 SET active=0,updated_at=NEW.updated_at
 WHERE group_id=NEW.group_id AND principal_id=NEW.principal_id
 AND (NEW.status!='active' OR NOT EXISTS(SELECT 1 FROM json_each(NEW.grants_json) WHERE value IN ('*','space.read'))
 OR cicada_network_expiry_allows(NEW.expires_at,NEW.updated_at)=0);
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT NEW.group_id,e.id,NEW.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=NEW.group_id),1),1,NEW.updated_at
 FROM fabric_endpoints e JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=NEW.group_id
 WHERE e.principal_id=NEW.principal_id AND eg.status='active' AND NEW.status='active'
 AND EXISTS(SELECT 1 FROM json_each(NEW.grants_json) WHERE value IN ('*','space.read'))
 AND (OLD.status!='active' OR NOT EXISTS(SELECT 1 FROM json_each(OLD.grants_json) WHERE value IN ('*','space.read'))
 OR cicada_network_expiry_allows(OLD.expires_at,NEW.updated_at)=0)
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS group_space_network_member_update_v2
AFTER UPDATE OF status,expires_at ON network_memberships_v2
WHEN OLD.status!=NEW.status OR cicada_network_expiry_allows(OLD.expires_at,NEW.updated_at)=0 BEGIN
 UPDATE group_space_audience_v2 SET active=0,updated_at=NEW.updated_at
 WHERE principal_id=NEW.principal_id AND group_id IN
 (SELECT id FROM groups WHERE network_id=NEW.network_id);
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT g.id,e.id,NEW.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=g.id),1),1,NEW.updated_at
 FROM groups g JOIN memberships m ON m.group_id=g.id AND m.principal_id=NEW.principal_id
 JOIN fabric_endpoints e ON e.principal_id=NEW.principal_id
 JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=g.id
 JOIN endpoint_network_memberships_v2 en ON en.endpoint_id=e.id AND en.network_id=NEW.network_id
 WHERE g.network_id=NEW.network_id AND NEW.status='active'
 AND cicada_network_expiry_allows(NEW.expires_at,NEW.updated_at)=1
 AND m.status='active' AND eg.status='active' AND en.status='active'
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS group_space_network_endpoint_insert_v2
AFTER INSERT ON endpoint_network_memberships_v2 WHEN NEW.status='active' BEGIN
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT g.id,e.id,e.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=g.id),1),1,NEW.updated_at
 FROM fabric_endpoints e JOIN groups g ON g.network_id=NEW.network_id
 JOIN memberships m ON m.group_id=g.id AND m.principal_id=e.principal_id
 JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=g.id
 JOIN network_memberships_v2 nm ON nm.network_id=NEW.network_id AND nm.principal_id=e.principal_id
 WHERE e.id=NEW.endpoint_id AND m.status='active' AND eg.status='active' AND nm.status='active'
 AND cicada_network_expiry_allows(nm.expires_at,NEW.updated_at)=1
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS group_space_network_endpoint_update_v2
AFTER UPDATE OF status ON endpoint_network_memberships_v2 WHEN OLD.status!=NEW.status BEGIN
 UPDATE group_space_audience_v2 SET active=0,updated_at=NEW.updated_at
 WHERE endpoint_id=NEW.endpoint_id AND group_id IN
 (SELECT id FROM groups WHERE network_id=NEW.network_id) AND NEW.status!='active';
 INSERT INTO group_space_audience_v2(group_id,endpoint_id,principal_id,read_from_seq,active,updated_at)
 SELECT g.id,e.id,e.principal_id,
 COALESCE((SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=g.id),1),1,NEW.updated_at
 FROM fabric_endpoints e JOIN groups g ON g.network_id=NEW.network_id
 JOIN memberships m ON m.group_id=g.id AND m.principal_id=e.principal_id
 JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=g.id
 JOIN network_memberships_v2 nm ON nm.network_id=NEW.network_id AND nm.principal_id=e.principal_id
 WHERE e.id=NEW.endpoint_id AND NEW.status='active' AND m.status='active'
 AND eg.status='active' AND nm.status='active'
 AND cicada_network_expiry_allows(nm.expires_at,NEW.updated_at)=1
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))
 ON CONFLICT(group_id,endpoint_id) DO UPDATE SET read_from_seq=excluded.read_from_seq,
 active=1,updated_at=excluded.updated_at;
END;
`)
	return err
}

func groupSpaceContext(snapshot GroupSpaceSnapshot, reader GroupSpaceEndpointEvidence) e2ee.GroupSpaceContext {
	return e2ee.GroupSpaceContext{
		HubID: snapshot.HubID, NetworkID: snapshot.NetworkID, GroupID: snapshot.GroupID,
		RecordID: snapshot.RecordID, Sequence: snapshot.Sequence, Kind: snapshot.Kind,
		TopicID: snapshot.TopicID, CorrectsID: snapshot.CorrectsID, Status: snapshot.Status,
		SnapshotDigest:     snapshot.ReaderSnapshotDigest,
		ProducerEndpointID: snapshot.Producer.EndpointID, ProducerKeyID: snapshot.Producer.KeyID,
		ReaderEndpointID: reader.EndpointID, ReaderKeyID: reader.KeyID, ExpiresAt: snapshot.ExpiresAt,
		ReservedAt: snapshot.ReservedAt,
	}
}

// GroupSpaceReaderContext is the exact domain-separated context expected by
// the per-reader Endpoint cryptographic helper.
func GroupSpaceReaderContext(snapshot GroupSpaceSnapshot, reader GroupSpaceEndpointEvidence) e2ee.GroupSpaceContext {
	return groupSpaceContext(snapshot, reader)
}

func groupSpaceSnapshotDigest(snapshot GroupSpaceSnapshot) (string, error) {
	snapshot.ReaderSnapshotDigest = ""
	snapshot.Committed = false
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("cicada/group-space/snapshot/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:]), nil
}

func validGroupSpaceInput(in GroupSpacePrepareInput) bool {
	if !validSameGroupSealedV1Token(in.GroupID) || !validSameGroupSealedV1Token(in.OperationID) ||
		len(in.OperationID) > 128 || (in.TopicID != "" && !validSameGroupSealedV1Token(in.TopicID)) ||
		(in.CorrectsID != "" && !validSameGroupSealedV1Token(in.CorrectsID)) {
		return false
	}
	switch in.Kind {
	case GroupSpaceKindJournal:
		return in.TopicID == "" && in.Status == "" && in.ExpectedTopicVersion == 0
	case GroupSpaceKindTopic:
		return in.TopicID == "" && in.CorrectsID == "" && in.Status == "" && in.ExpectedTopicVersion == 0
	case GroupSpaceKindReply:
		return in.TopicID != "" && in.CorrectsID == "" && in.Status == "" && in.ExpectedTopicVersion == 0
	case GroupSpaceKindTopicStatus:
		return in.TopicID != "" && in.CorrectsID == "" && in.ExpectedTopicVersion > 0 &&
			(in.Status == "OPEN" || in.Status == "RESOLVED")
	default:
		return false
	}
}

func groupSpaceRetention(class string) (time.Duration, bool) {
	switch class {
	case "", "standard":
		return 30 * 24 * time.Hour, true
	case "short":
		return 24 * time.Hour, true
	case "week":
		return 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func groupSpaceCiphertextDigest(ciphertexts []GroupSpaceReaderCiphertext) (string, []byte, error) {
	if len(ciphertexts) == 0 || len(ciphertexts) > GroupSpaceMaxReaders {
		return "", nil, ErrGroupSpaceInvalid
	}
	copySet := append([]GroupSpaceReaderCiphertext(nil), ciphertexts...)
	sort.Slice(copySet, func(i, j int) bool { return copySet[i].EndpointID < copySet[j].EndpointID })
	for i, ciphertext := range copySet {
		if !validSameGroupSealedV1Token(ciphertext.EndpointID) || !validSameGroupSealedV1Token(ciphertext.KeyID) ||
			len(ciphertext.Wire) == 0 || len(ciphertext.Wire) > 64*1024 ||
			(i > 0 && copySet[i-1].EndpointID == ciphertext.EndpointID) {
			return "", nil, ErrGroupSpaceInvalid
		}
	}
	encoded, err := json.Marshal(copySet)
	if err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(append([]byte("cicada/group-space/ciphertexts/v1\x00"), encoded...))
	return hex.EncodeToString(digest[:]), encoded, nil
}

func guardGroupSpaceActorTx(tx *sql.Tx, actor GroupSpaceActor, action string, at time.Time) error {
	if !validNodeCredentialDigest(actor.NodeCredentialDigest) ||
		guardNativeActorTx(tx, actor.Scope, action, at) != nil {
		return ErrGroupSpaceDenied
	}
	var effectiveAt string
	if tx.QueryRow(`SELECT effective_at FROM memberships WHERE id=? AND principal_id=? AND group_id=?`,
		actor.Scope.MembershipID, actor.Scope.PrincipalID,
		actor.Scope.GroupID).Scan(&effectiveAt) != nil ||
		!networkEffectiveAllows(effectiveAt, at) {
		return ErrGroupSpaceDenied
	}
	nodeID, ownerID, _, _, err := readCurrentBoundNodeOwnerTx(tx, actor.NodeCredentialDigest)
	if err != nil {
		return ErrGroupSpaceDenied
	}
	var endpointNode, endpointOwner string
	if tx.QueryRow(`SELECT machine_id,owner FROM fabric_endpoints WHERE id=? AND principal_id=?`,
		actor.Scope.EndpointID, actor.Scope.PrincipalID).Scan(&endpointNode, &endpointOwner) != nil ||
		endpointNode != nodeID || endpointOwner != ownerID {
		return ErrGroupSpaceDenied
	}
	var groupOwnerID string
	if tx.QueryRow(`SELECT p.owner_id FROM groups g JOIN principals p ON p.id=g.owner_principal_id
WHERE g.id=?`, actor.Scope.GroupID).Scan(&groupOwnerID) != nil {
		return ErrGroupSpaceDenied
	}
	if endpointOwner != groupOwnerID {
		status, err := crossOwnerGroupKeyStatusTx(tx, actor.Scope.GroupID, actor.Scope.EndpointID, at)
		if err != nil || !status.Current {
			return ErrGroupSpaceDenied
		}
	}
	return nil
}

func groupSpaceReadWindowTx(tx *sql.Tx, scope NativeActorScope, sequence int64) error {
	var from int64
	var active int
	if tx.QueryRow(`SELECT read_from_seq,active FROM group_space_audience_v2
 WHERE group_id=? AND endpoint_id=? AND principal_id=?`,
		scope.GroupID, scope.EndpointID, scope.PrincipalID).Scan(&from, &active) != nil ||
		active != 1 || sequence < from {
		return ErrGroupSpaceHistory
	}
	return nil
}

func groupSpaceEndpointEvidenceTx(tx *sql.Tx, groupID, endpointID string, at time.Time) (GroupSpaceEndpointEvidence, error) {
	var principalID, ownerID, nodeID, bindingID, groupOwnerID string
	var bindingStatus, memberStatus, joinStatus, endpointStatus, migrationState string
	var memberExpiry, memberEffective, networkID, hubID string
	var bindingEpoch uint64
	var memberRevision, joinRevision, groupRevision int64
	err := tx.QueryRow(`SELECT e.principal_id,e.owner,e.machine_id,e.binding_id,e.status,e.migration_state,
 gp.owner_id,g.network_id,n.hub_id,g.revision,m.status,m.expires_at,m.effective_at,m.revision,
 eg.status,eg.revision,b.status,b.epoch
FROM fabric_endpoints e JOIN principals p ON p.id=e.principal_id AND p.status='active'
JOIN groups g ON g.id=? AND g.state='ACTIVE'
JOIN principals gp ON gp.id=g.owner_principal_id AND gp.status='active'
JOIN networks_v2 n ON n.id=g.network_id AND n.state='ACTIVE'
JOIN memberships m ON m.principal_id=e.principal_id AND m.group_id=g.id
JOIN endpoint_group_memberships eg ON eg.endpoint_id=e.id AND eg.group_id=g.id
JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id AND b.principal_id=e.principal_id
 AND b.node_id=e.machine_id AND b.native_session_id=e.native_session_id
WHERE e.id=?`, groupID, endpointID).Scan(&principalID, &ownerID, &nodeID,
		&bindingID, &endpointStatus, &migrationState, &groupOwnerID,
		&networkID, &hubID, &groupRevision, &memberStatus, &memberExpiry,
		&memberEffective, &memberRevision, &joinStatus, &joinRevision,
		&bindingStatus, &bindingEpoch)
	if err != nil || principalID == "" || ownerID == "" ||
		endpointStatus == "left" || migrationState != EndpointMigrationReady ||
		memberStatus != "active" || joinStatus != "active" ||
		!isActiveBindingStatus(bindingStatus) || bindingEpoch == 0 ||
		!networkExpiryAllows(memberExpiry, at) || !networkEffectiveAllows(memberEffective, at) ||
		networkID == "" || hubID == "" {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	if err := networkGuardGroupEndpointTx(tx, principalID, endpointID, groupID, at); err != nil {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceDenied
	}
	if ownerID != groupOwnerID {
		return crossOwnerGroupSpaceEndpointEvidenceTx(tx, groupID, endpointID, at)
	}
	grant, err := readLatestGroupEndpointKeyGrant(tx, ownerID, groupID, endpointID)
	if err != nil {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	m := grant.Manifest
	if m.HubID != hubID || m.GroupID != groupID || m.GroupRevision != groupRevision ||
		m.OwnerID != ownerID || m.PrincipalID != principalID || m.EndpointID != endpointID ||
		m.NodeID != nodeID || m.BindingID != bindingID || m.BindingEpoch != bindingEpoch ||
		m.MembershipRevision != memberRevision || m.EndpointJoinRevision != joinRevision ||
		m.Digest == "" || groupEndpointKeyManifestDigest(m) != m.Digest {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	expires, err := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if err != nil || !expires.After(at) {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	var ownerPublicJSON, keyState string
	if tx.QueryRow(`SELECT public_identity_json,state FROM owner_approval_keys_v2
 WHERE owner_id=? AND key_id=?`, ownerID, m.OwnerKeyID).Scan(
		&ownerPublicJSON, &keyState) != nil || keyState != OwnerApprovalKeyActive {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	var ownerPublic e2ee.PublicIdentity
	if json.Unmarshal([]byte(ownerPublicJSON), &ownerPublic) != nil ||
		ownerPublic.ID != m.OwnerKeyID {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	if _, err := e2ee.VerifyOwnerLinkKeyGrant(grant.SignedProof, ownerPublic,
		ownerID, GroupEndpointKeyGrantOperation, m.Digest,
		m.CandidateBindingDigest, uint64(m.CandidateVersion),
		e2ee.OwnerLinkGrantSideSource, at); err != nil {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	side, err := readCommunicationLinkKeySide(tx, endpointID, groupID,
		principalID, ownerID, nodeID, bindingID, bindingEpoch)
	if err != nil || side.KeyID != m.CandidateKeyID ||
		side.CandidateVersion != m.CandidateVersion ||
		side.KeyFingerprint != m.CandidateFingerprint ||
		side.ProofDigest != m.CandidateProofDigest ||
		side.PublicIdentity.ID != m.CandidatePublicIdentity.ID {
		return GroupSpaceEndpointEvidence{}, ErrGroupSpaceNotReady
	}
	grant.CurrentStatus = GroupEndpointKeyGrantCurrent
	candidate := EndpointKeyCandidate{EndpointID: side.EndpointID,
		PrincipalID: side.PrincipalID, OwnerID: side.OwnerID, NodeID: side.NodeID,
		Public: side.PublicIdentity, KeyID: side.KeyID, BindingID: side.BindingID,
		BindingEpoch: side.BindingEpoch, Proof: side.Attestation,
		ProofDigest: side.ProofDigest, State: EndpointKeyCandidateStateCandidate,
		Version: side.CandidateVersion}
	return GroupSpaceEndpointEvidence{EndpointID: endpointID, PrincipalID: principalID,
		OwnerID: ownerID, NodeID: nodeID, BindingID: bindingID,
		BindingEpoch: bindingEpoch, MembershipRevision: memberRevision,
		JoinRevision: joinRevision, KeyID: side.KeyID,
		PublicIdentity: side.PublicIdentity, Grant: *grant, Candidate: candidate}, nil
}

func groupSpaceReaderIDsTx(tx *sql.Tx, groupID, nowText string) ([]string, error) {
	rows, err := tx.Query(`SELECT eg.endpoint_id FROM endpoint_group_memberships eg
JOIN fabric_endpoints e ON e.id=eg.endpoint_id AND e.migration_state='READY' AND e.status!='left'
JOIN memberships m ON m.principal_id=e.principal_id AND m.group_id=eg.group_id
JOIN group_space_audience_v2 a ON a.group_id=eg.group_id AND a.endpoint_id=e.id
WHERE eg.group_id=? AND eg.status='active' AND m.status='active'
 AND cicada_network_expiry_allows(m.expires_at,?)=1
 AND cicada_network_effective_allows(m.effective_at,?)=1 AND a.active=1
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))
ORDER BY eg.endpoint_id LIMIT ?`, groupID, nowText, nowText, GroupSpaceMaxReaders+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func groupSpaceSnapshotTx(tx *sql.Tx, reservationID string) (GroupSpaceSnapshot, string, error) {
	var encoded, state string
	if err := tx.QueryRow(`SELECT snapshot_json,state FROM group_space_records_v2 WHERE reservation_id=?`,
		reservationID).Scan(&encoded, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GroupSpaceSnapshot{}, "", ErrGroupSpaceNotFound
		}
		return GroupSpaceSnapshot{}, "", err
	}
	var snapshot GroupSpaceSnapshot
	if err := json.Unmarshal([]byte(encoded), &snapshot); err != nil {
		return GroupSpaceSnapshot{}, "", err
	}
	snapshot.Committed = state == "COMMITTED"
	return snapshot, state, nil
}

// GroupSpaceReservationGroupID is an internal routing lookup. It grants no
// read or write; Commit repeats the full current actor Guard in its own tx.
func (s *Store) GroupSpaceReservationGroupID(reservationID string) (string, error) {
	if !validSameGroupSealedV1Token(reservationID) {
		return "", ErrGroupSpaceInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var groupID string
	if err := s.db.QueryRow(`SELECT group_id FROM group_space_records_v2 WHERE reservation_id=?`,
		reservationID).Scan(&groupID); err != nil {
		return "", ErrGroupSpaceNotFound
	}
	return groupID, nil
}

func groupSpaceRecordReadableTx(tx *sql.Tx, scope NativeActorScope, recordID string, at time.Time) error {
	var groupID, state, expiry, kind, topicID, reservedAt string
	var seq int64
	err := tx.QueryRow(`SELECT group_id,seq,state,expires_at,kind,topic_id,reserved_at
FROM group_space_records_v2 WHERE record_id=?`, recordID).Scan(
		&groupID, &seq, &state, &expiry, &kind, &topicID, &reservedAt)
	if err != nil || groupID != scope.GroupID || state != "COMMITTED" ||
		!networkExpiryAllows(expiry, at) {
		return ErrGroupSpaceNotFound
	}
	if kind == GroupSpaceKindReply || kind == GroupSpaceKindTopicStatus {
		if err := groupSpaceRecordReadableTx(tx, scope, topicID, at); err != nil {
			return ErrGroupSpaceDenied
		}
	}
	var membershipEffective string
	if tx.QueryRow(`SELECT effective_at FROM memberships WHERE id=? AND principal_id=? AND group_id=?`,
		scope.MembershipID, scope.PrincipalID,
		scope.GroupID).Scan(&membershipEffective) != nil {
		return ErrGroupSpaceDenied
	}
	reservedTime, err := time.Parse(time.RFC3339Nano, reservedAt)
	if err != nil {
		return ErrGroupSpaceDenied
	}
	if groupSpaceReadWindowTx(tx, scope, seq) == nil &&
		networkEffectiveAllows(membershipEffective, reservedTime) {
		var present int
		if tx.QueryRow(`SELECT 1 FROM group_space_readers_v2
WHERE record_id=? AND endpoint_id=? AND length(ciphertext)>0`,
			recordID, scope.EndpointID).Scan(&present) == nil {
			return nil
		}
		return ErrGroupSpaceDenied
	}
	// A separate, unexpired Owner grant plus an actual sealed envelope is
	// required before an old sequence can cross the join cutoff.
	var present int
	if tx.QueryRow(`SELECT 1 FROM group_space_history_grants_v2 h
JOIN group_space_audience_v2 a ON a.group_id=? AND a.endpoint_id=h.recipient_endpoint_id
 AND a.principal_id=? AND a.active=1
JOIN endpoint_group_memberships eg ON eg.endpoint_id=h.recipient_endpoint_id AND eg.group_id=?
JOIN endpoint_network_memberships_v2 en ON en.endpoint_id=h.recipient_endpoint_id
 AND en.network_id=? AND en.status='active'
JOIN endpoint_key_candidates_v2 key ON key.endpoint_id=h.recipient_endpoint_id
WHERE h.record_id=? AND h.recipient_endpoint_id=? AND h.recipient_join_revision=eg.revision
 AND h.recipient_network_revision=en.revision AND h.recipient_key_id=key.key_id
 AND cicada_network_expiry_allows(h.expires_at,?)=1 AND length(h.ciphertext)>0`,
		scope.GroupID, scope.PrincipalID, scope.GroupID, scope.NetworkID,
		recordID, scope.EndpointID, at.Format(time.RFC3339Nano)).Scan(&present) != nil {
		return ErrGroupSpaceDenied
	}
	return nil
}

func groupSpaceOriginalWindowTx(tx *sql.Tx, scope NativeActorScope, snapshot GroupSpaceSnapshot) bool {
	var effective string
	if tx.QueryRow(`SELECT effective_at FROM memberships WHERE id=? AND principal_id=? AND group_id=?`,
		scope.MembershipID, scope.PrincipalID, scope.GroupID).Scan(&effective) != nil {
		return false
	}
	reserved, err := time.Parse(time.RFC3339Nano, snapshot.ReservedAt)
	return err == nil && networkEffectiveAllows(effective, reserved) &&
		groupSpaceReadWindowTx(tx, scope, snapshot.Sequence) == nil
}

func groupSpaceUsageTx(tx *sql.Tx, groupID string, at time.Time) (int, int64, error) {
	var committed int
	var bytes int64
	now := at.Format(time.RFC3339Nano)
	err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(length(snapshot_json)),0)
FROM group_space_records_v2 WHERE group_id=? AND state='COMMITTED'
AND cicada_network_expiry_allows(expires_at,?)=1`, groupID, now).Scan(&committed, &bytes)
	if err != nil {
		return 0, 0, err
	}
	var extra int64
	err = tx.QueryRow(`SELECT
COALESCE((SELECT SUM(length(rd.ciphertext)) FROM group_space_readers_v2 rd
JOIN group_space_records_v2 r ON r.record_id=rd.record_id
WHERE r.group_id=? AND r.state='COMMITTED' AND cicada_network_expiry_allows(r.expires_at,?)=1),0)+
COALESCE((SELECT SUM(length(h.ciphertext)+length(h.owner_proof)+length(h.resharer_json))
FROM group_space_history_grants_v2 h JOIN group_space_records_v2 r ON r.record_id=h.record_id
WHERE r.group_id=? AND r.state='COMMITTED' AND cicada_network_expiry_allows(r.expires_at,?)=1),0)+
COALESCE((SELECT SUM(length(h.grant_json)+length(h.recipient_json)+length(h.resharer_json))
FROM group_space_history_manifests_v2 h JOIN group_space_records_v2 r ON r.record_id=h.record_id
WHERE r.group_id=? AND cicada_network_expiry_allows(h.expires_at,?)=1),0)`,
		groupID, now, groupID, now, groupID, now).Scan(&extra)
	return committed, bytes + extra, err
}

// PrepareGroupSpaceWrite reserves an immutable sequence and exact reader key
// snapshot. A retry of the same operation returns the same reservation; a
// changed semantic request conflicts. A reservation does not publish a body.
func (s *Store) PrepareGroupSpaceWrite(actor GroupSpaceActor, in GroupSpacePrepareInput) (*GroupSpaceSnapshot, error) {
	if !validGroupSpaceInput(in) || in.GroupID != actor.Scope.GroupID {
		return nil, ErrGroupSpaceInvalid
	}
	retention, ok := groupSpaceRetention(in.RetentionClass)
	if !ok || retention > GroupSpaceMaxRetention {
		return nil, ErrGroupSpaceInvalid
	}
	if in.RetentionClass == "" {
		in.RetentionClass = "standard"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	action := "space.write"
	if in.Kind == GroupSpaceKindTopicStatus {
		action = "space.moderate"
	}
	if err := guardGroupSpaceActorTx(tx, actor, action, at); err != nil {
		return nil, err
	}
	if err := guardGroupSpaceActorTx(tx, actor, "space.read", at); err != nil {
		return nil, err
	}
	if _, err := purgeExpiredGroupSpacesTx(tx, at, GroupSpaceMaxPage); err != nil {
		return nil, err
	}
	var hubID, ownerID string
	err = tx.QueryRow(`SELECT n.hub_id,p.owner_id FROM groups g JOIN networks_v2 n ON n.id=g.network_id
JOIN principals p ON p.id=g.owner_principal_id
WHERE g.id=? AND g.network_id=? AND g.state='ACTIVE' AND n.state='ACTIVE'`,
		in.GroupID, actor.Scope.NetworkID).Scan(&hubID, &ownerID)
	if err != nil || hubID == "" {
		return nil, ErrGroupSpaceDenied
	}
	var tombstone int
	if tx.QueryRow(`SELECT 1 FROM group_space_tombstones_v2 WHERE hub_id=? AND network_id=?
AND group_id=? AND producer_endpoint_id=? AND kind=? AND operation_id=?`,
		hubID, actor.Scope.NetworkID, in.GroupID, actor.Scope.EndpointID,
		in.Kind, in.OperationID).Scan(&tombstone) == nil {
		return nil, ErrGroupSpaceConflict
	}
	var existingID string
	err = tx.QueryRow(`SELECT reservation_id FROM group_space_records_v2
WHERE hub_id=? AND network_id=? AND group_id=? AND producer_endpoint_id=? AND kind=? AND operation_id=?`,
		hubID, actor.Scope.NetworkID, in.GroupID, actor.Scope.EndpointID, in.Kind, in.OperationID).Scan(&existingID)
	if err == nil {
		snapshot, state, err := groupSpaceSnapshotTx(tx, existingID)
		if err != nil {
			return nil, err
		}
		if (in.Kind != GroupSpaceKindTopic && snapshot.TopicID != in.TopicID) ||
			(in.Kind == GroupSpaceKindTopic && snapshot.TopicID != snapshot.RecordID) ||
			snapshot.CorrectsID != in.CorrectsID ||
			snapshot.ExpectedTopicVersion != in.ExpectedTopicVersion || snapshot.Status != in.Status ||
			snapshot.RetentionClass != in.RetentionClass || state == "EXPIRED" {
			return nil, ErrGroupSpaceConflict
		}
		if !snapshot.Committed && !networkExpiryAllows(snapshot.ReservationExpiresAt, at) {
			return nil, ErrGroupSpaceConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &snapshot, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if in.CorrectsID != "" {
		if in.Kind != GroupSpaceKindJournal || groupSpaceRecordReadableTx(tx, actor.Scope, in.CorrectsID, at) != nil {
			return nil, ErrGroupSpaceDenied
		}
		var kind string
		if tx.QueryRow(`SELECT kind FROM group_space_records_v2 WHERE record_id=?`, in.CorrectsID).Scan(&kind) != nil || kind != GroupSpaceKindJournal {
			return nil, ErrGroupSpaceDenied
		}
	}
	if in.TopicID != "" {
		if groupSpaceRecordReadableTx(tx, actor.Scope, in.TopicID, at) != nil {
			return nil, ErrGroupSpaceDenied
		}
		var kind string
		if tx.QueryRow(`SELECT kind FROM group_space_records_v2 WHERE record_id=?`, in.TopicID).Scan(&kind) != nil || kind != GroupSpaceKindTopic {
			return nil, ErrGroupSpaceDenied
		}
	}
	var activeReservations int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM group_space_records_v2
WHERE group_id=? AND state='PREPARED'
AND cicada_network_expiry_allows(reservation_expires_at,?)=1`,
		in.GroupID, at.Format(time.RFC3339Nano)).Scan(&activeReservations); err != nil {
		return nil, err
	}
	if activeReservations >= groupSpaceActiveQuota {
		return nil, ErrGroupSpaceLimit
	}
	committedCount, retainedBytes, err := groupSpaceUsageTx(tx, in.GroupID, at)
	if err != nil {
		return nil, err
	}
	if committedCount >= groupSpaceCommittedQuota || retainedBytes >= groupSpaceCiphertextQuota {
		return nil, ErrGroupSpaceLimit
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO group_space_sequences_v2(group_id,next_seq) VALUES(?,1)`, in.GroupID); err != nil {
		return nil, err
	}
	var seq int64
	if err := tx.QueryRow(`SELECT next_seq FROM group_space_sequences_v2 WHERE group_id=?`, in.GroupID).Scan(&seq); err != nil || seq <= 0 {
		return nil, ErrGroupSpaceConflict
	}
	if _, err := tx.Exec(`UPDATE group_space_sequences_v2 SET next_seq=next_seq+1 WHERE group_id=?`, in.GroupID); err != nil {
		return nil, err
	}
	ids, err := groupSpaceReaderIDsTx(tx, in.GroupID, at.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > GroupSpaceMaxReaders {
		return nil, ErrGroupSpaceLimit
	}
	readers := make([]GroupSpaceEndpointEvidence, 0, len(ids))
	var producer GroupSpaceEndpointEvidence
	for _, id := range ids {
		evidence, err := groupSpaceEndpointEvidenceTx(tx, in.GroupID, id, at)
		if err != nil {
			return nil, ErrGroupSpaceNotReady
		}
		readers = append(readers, evidence)
		if id == actor.Scope.EndpointID {
			producer = evidence
		}
	}
	if producer.EndpointID == "" {
		return nil, ErrGroupSpaceDenied
	}
	snapshot := GroupSpaceSnapshot{
		ReservationID: NewID("spaces_res"), RecordID: NewID("spaces_rec"),
		OperationID: in.OperationID, HubID: hubID, NetworkID: actor.Scope.NetworkID,
		GroupID: in.GroupID, Sequence: seq, Kind: in.Kind, TopicID: in.TopicID,
		CorrectsID: in.CorrectsID, ExpectedTopicVersion: in.ExpectedTopicVersion,
		Status: in.Status, RetentionClass: in.RetentionClass, Producer: producer,
		Readers: readers, ReservedAt: at.Format(time.RFC3339Nano),
		ExpiresAt:            at.Add(retention).Format(time.RFC3339Nano),
		ReservationExpiresAt: at.Add(GroupSpaceReservationTTL).Format(time.RFC3339Nano),
	}
	if in.Kind == GroupSpaceKindTopic {
		snapshot.TopicID = snapshot.RecordID
	}
	snapshot.ReaderSnapshotDigest, err = groupSpaceSnapshotDigest(snapshot)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if len(encoded) > groupSpaceSnapshotLimit || retainedBytes+int64(len(encoded)) > groupSpaceCiphertextQuota {
		return nil, ErrGroupSpaceLimit
	}
	_, err = tx.Exec(`INSERT INTO group_space_records_v2
(record_id,reservation_id,operation_id,group_id,network_id,hub_id,seq,kind,topic_id,corrects_id,
expected_topic_version,topic_status,retention_class,producer_endpoint_id,producer_principal_id,
snapshot_json,snapshot_digest,state,reserved_at,reservation_expires_at,expires_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PREPARED',?,?,?)`,
		snapshot.RecordID, snapshot.ReservationID, snapshot.OperationID, snapshot.GroupID,
		snapshot.NetworkID, snapshot.HubID, snapshot.Sequence, snapshot.Kind, snapshot.TopicID,
		snapshot.CorrectsID, snapshot.ExpectedTopicVersion, snapshot.Status,
		snapshot.RetentionClass, producer.EndpointID, producer.PrincipalID, string(encoded),
		snapshot.ReaderSnapshotDigest, at.Format(time.RFC3339Nano),
		snapshot.ReservationExpiresAt, snapshot.ExpiresAt)
	if err != nil {
		return nil, err
	}
	for _, reader := range readers {
		if _, err := tx.Exec(`INSERT INTO group_space_readers_v2(record_id,endpoint_id,key_id) VALUES(?,?,?)`,
			snapshot.RecordID, reader.EndpointID, reader.KeyID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// CommitGroupSpaceWrite accepts exactly the frozen reader set. Reader changes,
// key changes, binding changes, or writer revocation all fail this transaction.
// A lost response may be retried using the exact ciphertext bytes.
func (s *Store) CommitGroupSpaceWrite(actor GroupSpaceActor, in GroupSpaceCommitInput) (*GroupSpaceRecord, error) {
	digest, _, err := groupSpaceCiphertextDigest(in.ReaderCiphertexts)
	if err != nil || !validSameGroupSealedV1Token(in.ReservationID) {
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
	snapshot, state, err := groupSpaceSnapshotTx(tx, in.ReservationID)
	if err != nil {
		return nil, err
	}
	if snapshot.Producer.EndpointID != actor.Scope.EndpointID ||
		snapshot.Producer.PrincipalID != actor.Scope.PrincipalID ||
		snapshot.GroupID != actor.Scope.GroupID || snapshot.NetworkID != actor.Scope.NetworkID {
		return nil, ErrGroupSpaceDenied
	}
	action := "space.write"
	if snapshot.Kind == GroupSpaceKindTopicStatus {
		action = "space.moderate"
	}
	if err := guardGroupSpaceActorTx(tx, actor, action, at); err != nil {
		return nil, err
	}
	if err := guardGroupSpaceActorTx(tx, actor, "space.read", at); err != nil {
		return nil, err
	}
	if state == "COMMITTED" {
		var existing string
		if tx.QueryRow(`SELECT ciphertext_digest FROM group_space_records_v2 WHERE record_id=?`,
			snapshot.RecordID).Scan(&existing) != nil || existing != digest {
			return nil, ErrGroupSpaceConflict
		}
		record, err := groupSpaceProjectionTx(tx, actor.Scope, snapshot.RecordID, at)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &record, nil
	}
	if state != "PREPARED" || !networkExpiryAllows(snapshot.ReservationExpiresAt, at) ||
		!networkExpiryAllows(snapshot.ExpiresAt, at) {
		return nil, ErrGroupSpaceConflict
	}
	if got, err := groupSpaceSnapshotDigest(snapshot); err != nil || got != snapshot.ReaderSnapshotDigest {
		return nil, ErrGroupSpaceConflict
	}
	if len(snapshot.Readers) != len(in.ReaderCiphertexts) {
		return nil, ErrGroupSpaceConflict
	}
	if snapshot.CorrectsID != "" && groupSpaceRecordReadableTx(tx, actor.Scope, snapshot.CorrectsID, at) != nil {
		return nil, ErrGroupSpaceDenied
	}
	if snapshot.Kind == GroupSpaceKindReply || snapshot.Kind == GroupSpaceKindTopicStatus {
		if groupSpaceRecordReadableTx(tx, actor.Scope, snapshot.TopicID, at) != nil {
			return nil, ErrGroupSpaceDenied
		}
	}
	wires := make(map[string]GroupSpaceReaderCiphertext, len(in.ReaderCiphertexts))
	for _, ciphertext := range in.ReaderCiphertexts {
		wires[ciphertext.EndpointID] = ciphertext
	}
	for _, reader := range snapshot.Readers {
		wire, ok := wires[reader.EndpointID]
		if !ok || wire.KeyID != reader.KeyID ||
			e2ee.VerifyGroupSpaceReader(snapshot.Producer.PublicIdentity,
				groupSpaceContext(snapshot, reader), wire.Wire) != nil {
			return nil, ErrGroupSpaceConflict
		}
		if err := networkGuardGroupEndpointTx(tx, reader.PrincipalID, reader.EndpointID, snapshot.GroupID, at); err != nil {
			return nil, ErrGroupSpaceDenied
		}
		var hasRead int
		if tx.QueryRow(`SELECT 1 FROM memberships m WHERE m.principal_id=? AND m.group_id=?
 AND m.status='active' AND cicada_network_expiry_allows(m.expires_at,?)=1
 AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value IN ('*','space.read'))`,
			reader.PrincipalID, snapshot.GroupID, at.Format(time.RFC3339Nano)).Scan(&hasRead) != nil {
			return nil, ErrGroupSpaceDenied
		}
		current, err := groupSpaceEndpointEvidenceTx(tx, snapshot.GroupID, reader.EndpointID, at)
		if err != nil || current.KeyID != reader.KeyID ||
			current.BindingEpoch != reader.BindingEpoch ||
			current.MembershipRevision != reader.MembershipRevision ||
			current.JoinRevision != reader.JoinRevision ||
			current.Grant.Manifest.Digest != reader.Grant.Manifest.Digest ||
			crossOwnerEvidenceDigest(current) != crossOwnerEvidenceDigest(reader) {
			return nil, ErrGroupSpaceConflict
		}
		if _, err := tx.Exec(`UPDATE group_space_readers_v2 SET ciphertext=? WHERE record_id=? AND endpoint_id=? AND key_id=?`,
			wire.Wire, snapshot.RecordID, reader.EndpointID, reader.KeyID); err != nil {
			return nil, err
		}
	}
	committedCount, retainedBytes, err := groupSpaceUsageTx(tx, snapshot.GroupID, at)
	if err != nil {
		return nil, err
	}
	if committedCount >= groupSpaceCommittedQuota {
		return nil, ErrGroupSpaceLimit
	}
	var incomingBytes int64
	for _, wire := range in.ReaderCiphertexts {
		incomingBytes += int64(len(wire.Wire))
	}
	var snapshotBytes int64
	if tx.QueryRow(`SELECT length(snapshot_json) FROM group_space_records_v2 WHERE record_id=?`,
		snapshot.RecordID).Scan(&snapshotBytes) != nil ||
		retainedBytes+snapshotBytes+incomingBytes > groupSpaceCiphertextQuota {
		return nil, ErrGroupSpaceLimit
	}
	if snapshot.Kind == GroupSpaceKindTopic {
		if _, err := tx.Exec(`INSERT INTO group_space_topics_v2(topic_id,group_id,version,status,updated_at)
VALUES(?,?,1,'OPEN',?)`, snapshot.RecordID, snapshot.GroupID, at.Format(time.RFC3339Nano)); err != nil {
			return nil, ErrGroupSpaceConflict
		}
	} else if snapshot.Kind == GroupSpaceKindTopicStatus {
		result, err := tx.Exec(`UPDATE group_space_topics_v2 SET version=version+1,status=?,updated_at=?
WHERE topic_id=? AND group_id=? AND version=?`, snapshot.Status,
			at.Format(time.RFC3339Nano), snapshot.TopicID, snapshot.GroupID,
			snapshot.ExpectedTopicVersion)
		if err != nil {
			return nil, err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return nil, ErrGroupSpaceConflict
		}
	}
	topicVersion := int64(0)
	if snapshot.Kind == GroupSpaceKindTopic {
		topicVersion = 1
	} else if snapshot.Kind == GroupSpaceKindTopicStatus {
		topicVersion = snapshot.ExpectedTopicVersion + 1
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO group_space_change_sequences_v2(group_id,next_seq) VALUES(?,1)`,
		snapshot.GroupID); err != nil {
		return nil, err
	}
	var commitSeq int64
	if err := tx.QueryRow(`SELECT next_seq FROM group_space_change_sequences_v2 WHERE group_id=?`,
		snapshot.GroupID).Scan(&commitSeq); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE group_space_change_sequences_v2 SET next_seq=next_seq+1 WHERE group_id=?`,
		snapshot.GroupID); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`UPDATE group_space_records_v2 SET state='COMMITTED',ciphertext_digest=?,
topic_version=?,committed_at=?,commit_seq=? WHERE record_id=? AND state='PREPARED'`,
		digest, topicVersion, at.Format(time.RFC3339Nano), commitSeq, snapshot.RecordID)
	if err != nil {
		return nil, err
	}
	record, err := groupSpaceProjectionTx(tx, actor.Scope, snapshot.RecordID, at)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &record, nil
}

// groupSpaceProjectionTx returns only the authenticated reader's envelope and
// the historical producer proof. It never discloses the full audience roster.
func groupSpaceProjectionTx(tx *sql.Tx, scope NativeActorScope, recordID string, at time.Time) (GroupSpaceRecord, error) {
	if err := groupSpaceRecordReadableTx(tx, scope, recordID, at); err != nil {
		return GroupSpaceRecord{}, err
	}
	var reservationID, createdAt, digest string
	var topicVersion int64
	if err := tx.QueryRow(`SELECT reservation_id,committed_at,ciphertext_digest,topic_version
FROM group_space_records_v2 WHERE record_id=?`, recordID).Scan(
		&reservationID, &createdAt, &digest, &topicVersion); err != nil {
		return GroupSpaceRecord{}, err
	}
	snapshot, state, err := groupSpaceSnapshotTx(tx, reservationID)
	if err != nil || state != "COMMITTED" {
		return GroupSpaceRecord{}, ErrGroupSpaceNotFound
	}
	var keyID, historyID string
	var wire []byte
	var historySigner GroupSpaceEndpointEvidence
	var from int64
	if tx.QueryRow(`SELECT read_from_seq FROM group_space_audience_v2
WHERE group_id=? AND endpoint_id=?`, scope.GroupID, scope.EndpointID).Scan(&from) != nil {
		return GroupSpaceRecord{}, ErrGroupSpaceDenied
	}
	if snapshot.Sequence >= from && groupSpaceOriginalWindowTx(tx, scope, snapshot) {
		if err := tx.QueryRow(`SELECT key_id,ciphertext FROM group_space_readers_v2
WHERE record_id=? AND endpoint_id=?`, recordID, scope.EndpointID).Scan(&keyID, &wire); err != nil {
			return GroupSpaceRecord{}, ErrGroupSpaceDenied
		}
	} else {
		var signerJSON string
		if err := tx.QueryRow(`SELECT h.manifest_id,h.recipient_key_id,h.ciphertext,h.resharer_json
FROM group_space_history_grants_v2 h
JOIN endpoint_group_memberships eg ON eg.endpoint_id=h.recipient_endpoint_id AND eg.group_id=?
JOIN endpoint_network_memberships_v2 en ON en.endpoint_id=h.recipient_endpoint_id AND en.network_id=?
JOIN endpoint_key_candidates_v2 key ON key.endpoint_id=h.recipient_endpoint_id
WHERE h.record_id=? AND h.recipient_endpoint_id=? AND h.recipient_join_revision=eg.revision
AND h.recipient_network_revision=en.revision AND en.status='active'
AND h.recipient_key_id=key.key_id AND cicada_network_expiry_allows(h.expires_at,?)=1
ORDER BY h.created_at DESC LIMIT 1`,
			scope.GroupID, scope.NetworkID, recordID, scope.EndpointID, at.Format(time.RFC3339Nano)).Scan(
			&historyID, &keyID, &wire, &signerJSON); err != nil ||
			json.Unmarshal([]byte(signerJSON), &historySigner) != nil {
			return GroupSpaceRecord{}, ErrGroupSpaceDenied
		}
	}
	var reader GroupSpaceEndpointEvidence
	if historyID == "" {
		for _, candidate := range snapshot.Readers {
			if candidate.EndpointID == scope.EndpointID {
				reader = candidate
				break
			}
		}
	} else {
		manifest, err := groupSpaceHistoryManifestTx(tx, historyID)
		if err != nil {
			return GroupSpaceRecord{}, ErrGroupSpaceDenied
		}
		reader = manifest.Recipient
		current, err := groupSpaceEndpointEvidenceTx(tx, scope.GroupID, scope.EndpointID, at)
		if err != nil || current.KeyID != reader.KeyID ||
			current.JoinRevision != reader.JoinRevision ||
			current.BindingID != reader.BindingID ||
			current.BindingEpoch != reader.BindingEpoch ||
			current.MembershipRevision != reader.MembershipRevision ||
			groupSpaceEvidenceDigest(current) != manifest.Grant.RecipientEvidenceDigest {
			return GroupSpaceRecord{}, ErrGroupSpaceDenied
		}
	}
	if reader.EndpointID == "" || reader.KeyID != keyID {
		return GroupSpaceRecord{}, ErrGroupSpaceDenied
	}
	// Keep only producer and caller proof in the response. Public metadata for
	// unrelated readers is not a side effect of Group Space read permission.
	snapshot.Readers = []GroupSpaceEndpointEvidence{reader}
	// The original envelope signer is already the producer in Snapshot.
	// Emit a separate signer proof only for an independently sealed history
	// grant, where it identifies the authorized resharer.
	var signer GroupSpaceEndpointEvidence
	if historyID != "" {
		signer = historySigner
	}
	record := GroupSpaceRecord{Snapshot: snapshot, TopicVersion: topicVersion,
		CreatedAt: createdAt, CiphertextDigest: digest,
		ReaderCiphertext: GroupSpaceReaderCiphertext{EndpointID: scope.EndpointID, KeyID: keyID, Wire: wire},
		HistoryGrantID:   historyID, EnvelopeSigner: signer}
	if historyID != "" {
		manifest, err := groupSpaceHistoryManifestTx(tx, historyID)
		if err != nil {
			return GroupSpaceRecord{}, ErrGroupSpaceDenied
		}
		record.HistoryGrant = &manifest.Grant
		var ownerJSON string
		if tx.QueryRow(`SELECT h.owner_proof,h.created_at,k.public_identity_json
FROM group_space_history_grants_v2 h JOIN owner_approval_keys_v2 k
ON k.owner_id=? AND k.key_id=? WHERE h.manifest_id=?`,
			manifest.Grant.OwnerID, manifest.Grant.OwnerKeyID, historyID).Scan(
			&record.HistoryOwnerProof, &record.HistoryGrantedAt, &ownerJSON) != nil ||
			json.Unmarshal([]byte(ownerJSON), &record.HistoryOwnerPublic) != nil {
			return GroupSpaceRecord{}, ErrGroupSpaceDenied
		}
	}
	if snapshot.Kind == GroupSpaceKindTopic || snapshot.Kind == GroupSpaceKindReply ||
		snapshot.Kind == GroupSpaceKindTopicStatus {
		if err := tx.QueryRow(`SELECT version,status FROM group_space_topics_v2 WHERE topic_id=? AND group_id=?`,
			snapshot.TopicID, snapshot.GroupID).Scan(&record.CurrentTopicVersion, &record.CurrentTopicStatus); err != nil {
			return GroupSpaceRecord{}, ErrGroupSpaceNotFound
		}
	}
	return record, nil
}

func (s *Store) GetGroupSpace(actor GroupSpaceActor, in GroupSpaceGetInput) (*GroupSpaceRecord, error) {
	if !validSameGroupSealedV1Token(in.GroupID) || !validSameGroupSealedV1Token(in.RecordID) ||
		in.GroupID != actor.Scope.GroupID {
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
	record, err := groupSpaceProjectionTx(tx, actor.Scope, in.RecordID, at)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &record, nil
}

// ListGroupSpace pages by Group-local sequence. The cursor is an opaque
// scope-bound encoding, not an authorization token; every result is guarded.
func (s *Store) ListGroupSpace(actor GroupSpaceActor, in GroupSpaceListInput) (*GroupSpacePage, error) {
	if !validSameGroupSealedV1Token(in.GroupID) || in.GroupID != actor.Scope.GroupID ||
		(in.Kind != "" && in.Kind != GroupSpaceKindJournal && in.Kind != GroupSpaceKindTopic &&
			in.Kind != GroupSpaceKindReply && in.Kind != GroupSpaceKindTopicStatus) ||
		(in.TopicID != "" && !validSameGroupSealedV1Token(in.TopicID)) || in.Limit < 0 {
		return nil, ErrGroupSpaceInvalid
	}
	if in.Limit == 0 || in.Limit > GroupSpaceMaxPage {
		in.Limit = GroupSpaceMaxPage
	}
	after, err := decodeGroupSpaceCursor(in.Cursor, actor.Scope, in.Kind, in.TopicID)
	if err != nil {
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
	var from int64
	var active int
	if tx.QueryRow(`SELECT read_from_seq,active FROM group_space_audience_v2
WHERE group_id=? AND endpoint_id=? AND principal_id=?`, actor.Scope.GroupID,
		actor.Scope.EndpointID, actor.Scope.PrincipalID).Scan(&from, &active) != nil || active != 1 {
		return nil, ErrGroupSpaceDenied
	}
	var effectiveAt string
	if tx.QueryRow(`SELECT effective_at FROM memberships WHERE id=?`,
		actor.Scope.MembershipID).Scan(&effectiveAt) != nil {
		return nil, ErrGroupSpaceDenied
	}
	query := `SELECT r.record_id,r.seq FROM group_space_records_v2 r
WHERE r.group_id=? AND r.state='COMMITTED' AND r.seq>?
AND cicada_network_expiry_allows(r.expires_at,?)=1
AND ((r.seq>=? AND cicada_network_effective_allows(?,r.reserved_at)=1
 AND EXISTS(SELECT 1 FROM group_space_readers_v2 rd
 WHERE rd.record_id=r.record_id AND rd.endpoint_id=? AND length(rd.ciphertext)>0))
 OR EXISTS(SELECT 1 FROM group_space_history_grants_v2 hg
 JOIN endpoint_group_memberships eg ON eg.endpoint_id=hg.recipient_endpoint_id AND eg.group_id=r.group_id
 JOIN endpoint_network_memberships_v2 en ON en.endpoint_id=hg.recipient_endpoint_id AND en.network_id=r.network_id
 JOIN endpoint_key_candidates_v2 key ON key.endpoint_id=hg.recipient_endpoint_id
 WHERE hg.record_id=r.record_id AND hg.recipient_endpoint_id=?
 AND hg.recipient_join_revision=eg.revision AND hg.recipient_network_revision=en.revision
 AND hg.recipient_key_id=key.key_id AND en.status='active'
 AND cicada_network_expiry_allows(hg.expires_at,?)=1 AND length(hg.ciphertext)>0))`
	args := []any{actor.Scope.GroupID, after, at.Format(time.RFC3339Nano),
		from, effectiveAt, actor.Scope.EndpointID, actor.Scope.EndpointID,
		at.Format(time.RFC3339Nano)}
	if in.Kind != "" {
		query += ` AND r.kind=?`
		args = append(args, in.Kind)
	}
	if in.TopicID != "" {
		// Visibility of a topic is independent of a later readable reply.
		if groupSpaceRecordReadableTx(tx, actor.Scope, in.TopicID, at) != nil {
			return nil, ErrGroupSpaceDenied
		}
		query += ` AND r.topic_id=?`
		args = append(args, in.TopicID)
	}
	query += ` ORDER BY r.seq LIMIT ?`
	args = append(args, in.Limit+1)
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	var seqs []int64
	for rows.Next() {
		var id string
		var seq int64
		if err := rows.Scan(&id, &seq); err != nil {
			rows.Close()
			return nil, err
		}
		ids, seqs = append(ids, id), append(seqs, seq)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	page := &GroupSpacePage{Records: []GroupSpaceRecord{}}
	hasMore := len(ids) > in.Limit
	if hasMore {
		ids, seqs = ids[:in.Limit], seqs[:in.Limit]
	}
	for _, id := range ids {
		record, err := groupSpaceProjectionTx(tx, actor.Scope, id, at)
		if err != nil {
			return nil, err
		}
		page.Records = append(page.Records, record)
	}
	if hasMore && len(seqs) > 0 {
		page.NextCursor = encodeGroupSpaceCursor(seqs[len(seqs)-1], actor.Scope, in.Kind, in.TopicID)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
