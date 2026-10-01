package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	networkBroadcastMaxRecipients = 64
	networkBroadcastMaxCandidates = 256
	networkBroadcastMaxRetained   = 4096
	networkBroadcastMaxAge        = 24 * time.Hour
	networkBroadcastPrefix        = "nbroadcast_"
)

var (
	ErrNetworkBroadcastPending         = errors.New("Network Broadcast route metadata is not committed yet")
	ErrNetworkBroadcastUnavailable     = errors.New("Network Broadcast route is unavailable")
	ErrNetworkBroadcastExpired         = errors.New("Network Broadcast expired")
	ErrNetworkBroadcastRecipientLimit  = errors.New("Network Broadcast recipient limit exceeded")
	ErrNetworkBroadcastCandidateLimit  = errors.New("Network Broadcast candidate scan limit exceeded")
	ErrNetworkBroadcastSnapshotChanged = errors.New("Network Broadcast recipient snapshot changed")
	ErrNetworkBroadcastQuota           = errors.New("Network Broadcast retained-record limit reached")
)

// NetworkBroadcast contains metadata only. Recipient roster is included only
// in publisher views; recipients receive their own route authorization.
type NetworkBroadcast struct {
	ID                  string                           `json:"broadcast_id"`
	NetworkID           string                           `json:"network_id"`
	PublisherEndpointID string                           `json:"publisher_endpoint_id"`
	Status              string                           `json:"status"`
	Revision            int64                            `json:"revision"`
	RecipientCount      int                              `json:"recipient_count,omitempty"`
	DeliveryState       string                           `json:"delivery_state,omitempty"`
	Recipients          []NetworkBroadcastRecipientState `json:"recipients,omitempty"`
	ExpiresAt           string                           `json:"expires_at"`
	CreatedAt           string                           `json:"created_at"`
	UpdatedAt           string                           `json:"updated_at"`
}

type NetworkBroadcastSnapshotRecipient struct {
	EndpointID string `json:"endpoint_id"`
}

type NetworkBroadcastRecipientSnapshot struct {
	NetworkID           string                              `json:"network_id"`
	PublisherEndpointID string                              `json:"publisher_endpoint_id"`
	SnapshotDigest      string                              `json:"snapshot_digest"`
	Recipients          []NetworkBroadcastSnapshotRecipient `json:"recipients"`
}

type NetworkBroadcastPublishRecipient struct {
	EndpointID string `json:"endpoint_id"`
	MessageID  string `json:"message_id"`
}

type NetworkBroadcastPublishInput struct {
	BroadcastID    string                             `json:"broadcast_id"`
	SnapshotDigest string                             `json:"snapshot_digest"`
	ExpiresAt      string                             `json:"expires_at"`
	Recipients     []NetworkBroadcastPublishRecipient `json:"recipients"`
}

type NetworkBroadcastRecipientState struct {
	EndpointID string `json:"endpoint_id"`
	MessageID  string `json:"message_id"`
	State      string `json:"state"`
}

type NetworkBroadcastDeliveryAuthorization struct {
	NetworkID          string `json:"network_id"`
	BroadcastID        string `json:"broadcast_id"`
	MessageID          string `json:"message_id"`
	SenderEndpointID   string `json:"sender_endpoint_id"`
	ReceiverEndpointID string `json:"receiver_endpoint_id"`
	Revision           int64  `json:"revision"`
	ExpiresAt          string `json:"expires_at"`
	Status             string `json:"status"`
}

type networkBroadcastSnapshotMember struct {
	EndpointID         string `json:"endpoint_id"`
	PrincipalID        string `json:"principal_id"`
	MembershipRevision int64  `json:"membership_revision"`
	EnrollmentRevision int64  `json:"enrollment_revision"`
	BindingID          string `json:"binding_id"`
	BindingEpoch       uint64 `json:"binding_epoch"`
	KeyID              string `json:"key_id"`
	KeyGrantRevision   int64  `json:"key_grant_revision"`
	ManifestDigest     string `json:"manifest_digest"`
}

type networkBroadcastSnapshotClaims struct {
	Version   int                              `json:"version"`
	Purpose   string                           `json:"purpose"`
	NetworkID string                           `json:"network_id"`
	Publisher networkBroadcastSnapshotMember   `json:"publisher"`
	Readers   []networkBroadcastSnapshotMember `json:"readers"`
}

func (s *Store) initializeNetworkBroadcastSchema() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS network_broadcasts_v2 (
	id TEXT PRIMARY KEY, network_id TEXT NOT NULL, publisher_endpoint_id TEXT NOT NULL,
	publisher_principal_id TEXT NOT NULL, snapshot_digest TEXT NOT NULL,
	expires_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('PUBLISHED')),
	revision INTEGER NOT NULL CHECK(revision>0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
	FOREIGN KEY(network_id) REFERENCES networks_v2(id),
	FOREIGN KEY(publisher_endpoint_id) REFERENCES fabric_endpoints(id)
);
CREATE INDEX IF NOT EXISTS network_broadcasts_v2_network_created_idx
	ON network_broadcasts_v2(network_id,created_at,id);
CREATE TABLE IF NOT EXISTS network_broadcast_recipients_v2 (
	broadcast_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, message_id TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL, PRIMARY KEY(broadcast_id,endpoint_id),
	FOREIGN KEY(broadcast_id) REFERENCES network_broadcasts_v2(id),
	FOREIGN KEY(endpoint_id) REFERENCES fabric_endpoints(id),
	FOREIGN KEY(message_id) REFERENCES network_direct_message_routes_v2(message_id)
);
CREATE INDEX IF NOT EXISTS network_broadcast_recipients_v2_endpoint_idx
	ON network_broadcast_recipients_v2(endpoint_id,broadcast_id);`)
	return err
}

func networkBroadcastIDValid(id string) bool {
	if len(id) < 24 || len(id) > 96 || !strings.HasPrefix(id, networkBroadcastPrefix) {
		return false
	}
	for _, b := range []byte(id) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

func networkBroadcastDigestValid(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

// networkBroadcastIDFromMessageID recognizes only reader fanout sends. The
// endpoint roster and route IDs live in a separate committed metadata row.
func networkBroadcastIDFromMessageID(messageID string) (string, bool) {
	if !strings.HasPrefix(messageID, networkBroadcastPrefix) {
		return "", false
	}
	separator := strings.IndexByte(messageID, ':')
	if separator < 0 || separator+1 >= len(messageID) || len(messageID) > 256 {
		return "", true
	}
	id := messageID[:separator]
	suffix := messageID[separator+1:]
	if !networkBroadcastIDValid(id) || !strings.HasPrefix(suffix, "reader:") || len(suffix) <= len("reader:") {
		return "", true
	}
	for _, b := range []byte(strings.TrimPrefix(suffix, "reader:")) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') &&
			(b < '0' || b > '9') && b != '_' && b != '-' {
			return "", true
		}
	}
	return id, true
}

func networkBroadcastDeadline(value string, at time.Time) (time.Time, bool) {
	deadline, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || deadline.UTC().Format(time.RFC3339Nano) != value ||
		!deadline.After(at) || deadline.After(at.Add(networkBroadcastMaxAge)) {
		return time.Time{}, false
	}
	return deadline, true
}

func networkBroadcastSnapshotMemberFromEvidence(evidence NetworkDirectPeerKeyEvidence) networkBroadcastSnapshotMember {
	manifest := evidence.Manifest
	grantRevision := int64(0)
	if evidence.CollaborationGrant != nil {
		grantRevision = evidence.CollaborationGrant.Revision
	}
	return networkBroadcastSnapshotMember{EndpointID: manifest.EndpointID,
		PrincipalID: manifest.PrincipalID, MembershipRevision: manifest.MembershipRevision,
		EnrollmentRevision: manifest.EndpointEnrollmentRevision, BindingID: manifest.BindingID,
		BindingEpoch: manifest.BindingEpoch, KeyID: manifest.Candidate.Public.ID,
		KeyGrantRevision: grantRevision, ManifestDigest: evidence.CollaborationManifest.Digest}
}

func networkBroadcastSnapshotTx(tx *sql.Tx, scope NetworkAccessScope,
	at time.Time) (*NetworkBroadcastRecipientSnapshot, error) {
	if err := networkGuardAccessTx(tx, scope, "broadcast.publish", at); err != nil {
		return nil, err
	}
	publisher, err := readNetworkCollaborationPeerKeyEvidenceTx(tx, scope.NetworkID,
		scope.EndpointID, e2ee.NetworkCollaborationPurposeBroadcast, at)
	if err != nil || publisher.Manifest.PrincipalID != scope.PrincipalID ||
		publisher.Manifest.MembershipRevision != scope.MembershipRevision ||
		publisher.Manifest.EndpointEnrollmentRevision != scope.EndpointMembershipRevision {
		return nil, ErrNetworkPermission
	}
	readers := []networkBroadcastSnapshotMember{}
	lastEndpointID := ""
	scannedCandidates := 0
	for {
		pageLimit := networkBroadcastMaxRecipients
		remainingWithLookahead := networkBroadcastMaxCandidates - scannedCandidates + 1
		if pageLimit > remainingWithLookahead {
			pageLimit = remainingWithLookahead
		}
		rows, err := tx.Query(`SELECT endpoint.id,endpoint.principal_id
FROM endpoint_network_memberships_v2 enrollment
JOIN network_memberships_v2 membership ON membership.network_id=enrollment.network_id
	AND membership.principal_id=(SELECT principal_id FROM fabric_endpoints WHERE id=enrollment.endpoint_id)
JOIN fabric_endpoints endpoint ON endpoint.id=enrollment.endpoint_id
JOIN principals principal ON principal.id=endpoint.principal_id
WHERE enrollment.network_id=? AND enrollment.status='active'
	AND membership.status='active' AND endpoint.status!='left' AND principal.status='active'
AND endpoint.id>? AND EXISTS(SELECT 1 FROM json_each(membership.grants_json) grant
	WHERE grant.value='broadcast.receive')
ORDER BY endpoint.id LIMIT ?`, scope.NetworkID, lastEndpointID, pageLimit)
		if err != nil {
			return nil, err
		}
		type endpointIdentity struct{ endpointID, principalID string }
		candidates := make([]endpointIdentity, 0, pageLimit)
		nextEndpointID := ""
		for rows.Next() {
			var item endpointIdentity
			if err := rows.Scan(&item.endpointID, &item.principalID); err != nil {
				rows.Close()
				return nil, err
			}
			nextEndpointID = item.endpointID
			candidates = append(candidates, item)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(candidates) == 0 {
			break
		}
		if scannedCandidates+len(candidates) > networkBroadcastMaxCandidates {
			return nil, ErrNetworkBroadcastCandidateLimit
		}
		scannedCandidates += len(candidates)
		lastEndpointID = nextEndpointID
		for _, item := range candidates {
			if item.endpointID == scope.EndpointID {
				continue
			}
			if networkDirectMembershipAllowsTx(tx, scope.NetworkID, item.endpointID,
				item.principalID, "broadcast.receive", at) != nil {
				continue
			}
			evidence, err := readNetworkCollaborationPeerKeyEvidenceTx(tx, scope.NetworkID,
				item.endpointID, e2ee.NetworkCollaborationPurposeBroadcast, at)
			if err != nil {
				if errors.Is(err, ErrNetworkPermission) || errors.Is(err, ErrNetworkDirectKeyUnavailable) ||
					errors.Is(err, sql.ErrNoRows) {
					continue
				}
				return nil, err
			}
			if evidence.Manifest.PrincipalID != item.principalID {
				continue
			}
			readers = append(readers, networkBroadcastSnapshotMemberFromEvidence(evidence))
			if len(readers) > networkBroadcastMaxRecipients {
				return nil, ErrNetworkBroadcastRecipientLimit
			}
		}
	}
	sort.Slice(readers, func(i, j int) bool { return readers[i].EndpointID < readers[j].EndpointID })
	claims := networkBroadcastSnapshotClaims{Version: 1, Purpose: e2ee.NetworkCollaborationPurposeBroadcast,
		NetworkID: scope.NetworkID, Publisher: networkBroadcastSnapshotMemberFromEvidence(publisher),
		Readers: readers}
	canonical, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("cicada/network/broadcast-recipient-snapshot/v1\x00"), canonical...))
	result := &NetworkBroadcastRecipientSnapshot{NetworkID: scope.NetworkID,
		PublisherEndpointID: scope.EndpointID, SnapshotDigest: hex.EncodeToString(digest[:]),
		Recipients: make([]NetworkBroadcastSnapshotRecipient, 0, len(readers))}
	for _, reader := range readers {
		result.Recipients = append(result.Recipients,
			NetworkBroadcastSnapshotRecipient{EndpointID: reader.EndpointID})
	}
	return result, nil
}

// PreviewNetworkBroadcastRecipients freezes the exact currently eligible
// Endpoint set into an Owner-key/grant/revision digest. It returns IDs only.
func (s *Store) PreviewNetworkBroadcastRecipients(scope NetworkAccessScope) (*NetworkBroadcastRecipientSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snapshot, err := networkBroadcastSnapshotTx(tx, scope, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func loadNetworkBroadcastTx(tx *sql.Tx, id string) (*NetworkBroadcast, error) {
	var broadcast NetworkBroadcast
	err := tx.QueryRow(`SELECT id,network_id,publisher_endpoint_id,status,revision,
expires_at,created_at,updated_at FROM network_broadcasts_v2 WHERE id=?`, id).Scan(
		&broadcast.ID, &broadcast.NetworkID, &broadcast.PublisherEndpointID,
		&broadcast.Status, &broadcast.Revision, &broadcast.ExpiresAt,
		&broadcast.CreatedAt, &broadcast.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNetworkBroadcastUnavailable
	}
	return &broadcast, err
}

func networkBroadcastRouteGuardTx(tx *sql.Tx, networkID, publisherEndpointID,
	recipientEndpointID, broadcastID, messageID string, at time.Time, requireReady bool) error {
	parsedID, reserved := networkBroadcastIDFromMessageID(messageID)
	if !reserved || parsedID != broadcastID {
		return ErrNetworkBroadcastUnavailable
	}
	var savedNetwork, sender, receiver, purpose, kind, inboxState string
	var createdAt string
	err := tx.QueryRow(`SELECT route.network_id,route.sender_endpoint_id,route.receiver_endpoint_id,
route.key_purpose,message.kind,inbox.state,route.created_at
FROM network_direct_message_routes_v2 route
JOIN fabric_messages message ON message.id=route.message_id
JOIN relay_v2_inbox inbox ON inbox.message_id=route.message_id
WHERE route.message_id=?`, messageID).Scan(&savedNetwork, &sender, &receiver,
		&purpose, &kind, &inboxState, &createdAt)
	if err != nil || savedNetwork != networkID || sender != publisherEndpointID ||
		receiver != recipientEndpointID || purpose != e2ee.NetworkCollaborationPurposeBroadcast ||
		kind != "send" || (requireReady && inboxState != RelayInboxReady) {
		return ErrNetworkBroadcastUnavailable
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != createdAt ||
		!created.Add(networkBroadcastMaxAge).After(at) {
		return ErrNetworkBroadcastExpired
	}
	return networkGuardCollaborationMessageTx(tx, messageID, networkID,
		e2ee.NetworkCollaborationPurposeBroadcast, at)
}

func readNetworkBroadcastRecipientsTx(tx *sql.Tx, broadcastID string) ([]NetworkBroadcastRecipientState, error) {
	rows, err := tx.Query(`SELECT recipient.endpoint_id,recipient.message_id,inbox.state
FROM network_broadcast_recipients_v2 recipient
LEFT JOIN relay_v2_inbox inbox ON inbox.message_id=recipient.message_id
WHERE recipient.broadcast_id=? ORDER BY recipient.endpoint_id`, broadcastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NetworkBroadcastRecipientState, 0)
	for rows.Next() {
		var item NetworkBroadcastRecipientState
		var state sql.NullString
		if err := rows.Scan(&item.EndpointID, &item.MessageID, &state); err != nil {
			return nil, err
		}
		item.State = state.String
		if item.State == "" {
			item.State = "UNAVAILABLE"
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func broadcastInputsMatch(a, b []NetworkBroadcastPublishRecipient) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]NetworkBroadcastPublishRecipient(nil), a...)
	right := append([]NetworkBroadcastPublishRecipient(nil), b...)
	sort.Slice(left, func(i, j int) bool { return left[i].EndpointID < left[j].EndpointID })
	sort.Slice(right, func(i, j int) bool { return right[i].EndpointID < right[j].EndpointID })
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func networkBroadcastRecipientsAsInputTx(tx *sql.Tx, broadcastID string) ([]NetworkBroadcastPublishRecipient, error) {
	rows, err := tx.Query(`SELECT endpoint_id,message_id FROM network_broadcast_recipients_v2
WHERE broadcast_id=? ORDER BY endpoint_id`, broadcastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []NetworkBroadcastPublishRecipient{}
	for rows.Next() {
		var item NetworkBroadcastPublishRecipient
		if err := rows.Scan(&item.EndpointID, &item.MessageID); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// PublishNetworkBroadcast commits one fixed Network recipient snapshot after
// every sealed per-reader SEND is already durable. Metadata contains only IDs
// and digest/revision fences; it never contains broadcast plaintext.
func (s *Store) PublishNetworkBroadcast(scope NetworkAccessScope,
	input NetworkBroadcastPublishInput) (*NetworkBroadcast, error) {
	at := time.Now().UTC()
	if !networkBroadcastIDValid(input.BroadcastID) || !networkBroadcastDigestValid(input.SnapshotDigest) ||
		len(input.Recipients) == 0 || len(input.Recipients) > networkBroadcastMaxRecipients {
		return nil, ErrNetworkBroadcastUnavailable
	}
	deadline, ok := networkBroadcastDeadline(input.ExpiresAt, at)
	if !ok {
		return nil, ErrNetworkBroadcastUnavailable
	}
	seenEndpoint, seenMessage := map[string]bool{}, map[string]bool{}
	for _, item := range input.Recipients {
		if item.EndpointID == "" || item.MessageID == "" || seenEndpoint[item.EndpointID] || seenMessage[item.MessageID] {
			return nil, ErrNetworkBroadcastUnavailable
		}
		seenEndpoint[item.EndpointID], seenMessage[item.MessageID] = true, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := networkGuardAccessTx(tx, scope, "broadcast.publish", at); err != nil {
		return nil, err
	}
	if existing, err := loadNetworkBroadcastTx(tx, input.BroadcastID); err == nil {
		if existing.NetworkID != scope.NetworkID || existing.PublisherEndpointID != scope.EndpointID ||
			existing.ExpiresAt != input.ExpiresAt {
			return nil, ErrNetworkConflict
		}
		oldRecipients, err := networkBroadcastRecipientsAsInputTx(tx, input.BroadcastID)
		if err != nil || !broadcastInputsMatch(oldRecipients, input.Recipients) {
			return nil, ErrNetworkConflict
		}
		if existing.Status != "PUBLISHED" || existing.Revision != 1 {
			return nil, ErrNetworkConflict
		}
		recipients, err := readNetworkBroadcastRecipientsTx(tx, input.BroadcastID)
		if err != nil {
			return nil, err
		}
		existing.RecipientCount, existing.Recipients = len(recipients), recipients
		if !deadline.After(at) {
			existing.Status = "EXPIRED"
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	} else if !errors.Is(err, ErrNetworkBroadcastUnavailable) {
		return nil, err
	}
	snapshot, err := networkBroadcastSnapshotTx(tx, scope, at)
	if err != nil {
		return nil, err
	}
	if snapshot.SnapshotDigest != input.SnapshotDigest || len(snapshot.Recipients) != len(input.Recipients) {
		return nil, ErrNetworkBroadcastSnapshotChanged
	}
	for _, candidate := range snapshot.Recipients {
		if !seenEndpoint[candidate.EndpointID] {
			return nil, ErrNetworkBroadcastSnapshotChanged
		}
	}
	for _, item := range input.Recipients {
		if item.EndpointID == scope.EndpointID {
			return nil, ErrNetworkBroadcastUnavailable
		}
		if err := networkBroadcastRouteGuardTx(tx, scope.NetworkID, scope.EndpointID,
			item.EndpointID, input.BroadcastID, item.MessageID, at, true); err != nil {
			return nil, err
		}
		var createdAt string
		if err := tx.QueryRow(`SELECT created_at FROM network_direct_message_routes_v2
WHERE message_id=?`, item.MessageID).Scan(&createdAt); err != nil {
			return nil, ErrNetworkBroadcastUnavailable
		}
		created, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil || created.UTC().Format(time.RFC3339Nano) != createdAt ||
			deadline.After(created.Add(networkBroadcastMaxAge)) {
			return nil, ErrNetworkBroadcastExpired
		}
	}
	var retained int
	if err := tx.QueryRow(`SELECT count(*) FROM network_broadcasts_v2 WHERE network_id=?`,
		scope.NetworkID).Scan(&retained); err != nil {
		return nil, err
	}
	if retained >= networkBroadcastMaxRetained {
		return nil, ErrNetworkBroadcastQuota
	}
	stamp := at.Format(time.RFC3339Nano)
	_, err = tx.Exec(`INSERT INTO network_broadcasts_v2
(id,network_id,publisher_endpoint_id,publisher_principal_id,snapshot_digest,
expires_at,status,revision,created_at,updated_at)
VALUES(?,?,?,?,?,?,'PUBLISHED',1,?,?)`, input.BroadcastID, scope.NetworkID,
		scope.EndpointID, scope.PrincipalID, input.SnapshotDigest, deadline.Format(time.RFC3339Nano), stamp, stamp)
	if err != nil {
		return nil, err
	}
	for _, item := range input.Recipients {
		if _, err := tx.Exec(`INSERT INTO network_broadcast_recipients_v2
(broadcast_id,endpoint_id,message_id,created_at) VALUES(?,?,?,?)`, input.BroadcastID,
			item.EndpointID, item.MessageID, stamp); err != nil {
			return nil, err
		}
	}
	recipients, err := readNetworkBroadcastRecipientsTx(tx, input.BroadcastID)
	if err != nil {
		return nil, err
	}
	broadcast := &NetworkBroadcast{ID: input.BroadcastID, NetworkID: scope.NetworkID,
		PublisherEndpointID: scope.EndpointID, Status: "PUBLISHED", Revision: 1,
		RecipientCount: len(recipients), Recipients: recipients,
		ExpiresAt: deadline.Format(time.RFC3339Nano), CreatedAt: stamp, UpdatedAt: stamp}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return broadcast, nil
}

// networkBroadcastDeliveryForRouteTx is a preclaim and pre-injection gate. A
// reserved SEND without its exact fixed snapshot stays READY until metadata
// commits or its bounded 24-hour route window expires.
func networkBroadcastDeliveryForRouteTx(tx *sql.Tx, networkID, messageID,
	senderEndpointID, receiverEndpointID string, at time.Time) (*NetworkBroadcastDeliveryAuthorization, error) {
	broadcastID, reserved := networkBroadcastIDFromMessageID(messageID)
	if !reserved {
		return nil, nil
	}
	if broadcastID == "" {
		return nil, ErrNetworkBroadcastUnavailable
	}
	if err := networkBroadcastRouteGuardTx(tx, networkID, senderEndpointID,
		receiverEndpointID, broadcastID, messageID, at, false); err != nil {
		return nil, err
	}
	broadcast, err := loadNetworkBroadcastTx(tx, broadcastID)
	if errors.Is(err, ErrNetworkBroadcastUnavailable) {
		var createdAt string
		if queryErr := tx.QueryRow(`SELECT created_at FROM network_direct_message_routes_v2
WHERE message_id=? AND network_id=?`, messageID, networkID).Scan(&createdAt); queryErr != nil {
			return nil, ErrNetworkBroadcastUnavailable
		}
		created, parseErr := time.Parse(time.RFC3339Nano, createdAt)
		if parseErr != nil || created.UTC().Format(time.RFC3339Nano) != createdAt ||
			!created.Add(networkBroadcastMaxAge).After(at) {
			return nil, ErrNetworkBroadcastExpired
		}
		return nil, ErrNetworkBroadcastPending
	}
	if err != nil || broadcast.NetworkID != networkID ||
		broadcast.PublisherEndpointID != senderEndpointID || broadcast.Status != "PUBLISHED" {
		return nil, ErrNetworkBroadcastUnavailable
	}
	deadline, err := time.Parse(time.RFC3339Nano, broadcast.ExpiresAt)
	if err != nil || deadline.UTC().Format(time.RFC3339Nano) != broadcast.ExpiresAt || !deadline.After(at) {
		return nil, ErrNetworkBroadcastExpired
	}
	var savedMessageID string
	if err := tx.QueryRow(`SELECT message_id FROM network_broadcast_recipients_v2
WHERE broadcast_id=? AND endpoint_id=?`, broadcastID, receiverEndpointID).Scan(&savedMessageID); err != nil || savedMessageID != messageID {
		return nil, ErrNetworkBroadcastUnavailable
	}
	return &NetworkBroadcastDeliveryAuthorization{NetworkID: networkID,
		BroadcastID: broadcastID, MessageID: messageID,
		SenderEndpointID: senderEndpointID, ReceiverEndpointID: receiverEndpointID,
		Revision: broadcast.Revision, ExpiresAt: broadcast.ExpiresAt,
		Status: broadcast.Status}, nil
}

// GetNetworkBroadcast returns the publisher's exact per-recipient relay state
// or the single receiver's own state. A reader never gets the snapshot roster.
func (s *Store) GetNetworkBroadcast(scope NetworkAccessScope, broadcastID string) (*NetworkBroadcast, error) {
	if !networkBroadcastIDValid(broadcastID) {
		return nil, ErrNetworkBroadcastUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	broadcast, err := loadNetworkBroadcastTx(tx, broadcastID)
	if err != nil || broadcast.NetworkID != scope.NetworkID {
		return nil, ErrNetworkBroadcastUnavailable
	}
	if scope.EndpointID == broadcast.PublisherEndpointID {
		if err := networkGuardAccessTx(tx, scope, "broadcast.publish", at); err != nil {
			return nil, err
		}
		recipients, err := readNetworkBroadcastRecipientsTx(tx, broadcastID)
		if err != nil {
			return nil, err
		}
		broadcast.RecipientCount, broadcast.Recipients = len(recipients), recipients
	} else {
		if err := networkGuardAccessTx(tx, scope, "broadcast.receive", at); err != nil {
			return nil, err
		}
		var messageID, senderEndpointID string
		if err := tx.QueryRow(`SELECT recipient.message_id,broadcast.publisher_endpoint_id
FROM network_broadcast_recipients_v2 recipient
JOIN network_broadcasts_v2 broadcast ON broadcast.id=recipient.broadcast_id
WHERE recipient.broadcast_id=? AND recipient.endpoint_id=?`, broadcastID,
			scope.EndpointID).Scan(&messageID, &senderEndpointID); err != nil {
			return nil, ErrNetworkBroadcastUnavailable
		}
		if _, err := networkBroadcastDeliveryForRouteTx(tx, scope.NetworkID,
			messageID, senderEndpointID, scope.EndpointID, at); err != nil {
			return nil, err
		}
		rows, err := readNetworkBroadcastRecipientsTx(tx, broadcastID)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if row.EndpointID == scope.EndpointID {
				broadcast.DeliveryState = row.State
				break
			}
		}
	}
	deadline, err := time.Parse(time.RFC3339Nano, broadcast.ExpiresAt)
	if err != nil || !deadline.After(at) {
		broadcast.Status = "EXPIRED"
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return broadcast, nil
}
