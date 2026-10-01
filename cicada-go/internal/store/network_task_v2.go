package store

// Network Task offers share the SharedTask status/revision/owner-epoch contract,
// while their content is carried only by existing, signed NetworkDirect sealed
// SEND messages. The Hub never stores offer or result prose in these tables.

import (
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	networkTaskMaxReaders          = 16
	networkTaskMaxPendingPublisher = 64
	networkTaskMaxRetainedNetwork  = 4096
	networkTaskPendingRouteMaxAge  = 24 * time.Hour
)

var ErrNetworkTaskMigrationBlocked = errors.New("legacy Network Task route requires a newly sealed TASK-purpose message")

// NetworkTaskOffer is route and responsibility metadata, not task content.
// OfferMessageID is populated only for the addressed Endpoint.
type NetworkTaskOffer struct {
	ID                     string   `json:"task_id"`
	NetworkID              string   `json:"network_id"`
	PublisherPrincipalID   string   `json:"publisher_principal_id"`
	PublisherEndpointID    string   `json:"publisher_endpoint_id"`
	OfferMessageID         string   `json:"offer_message_id,omitempty"`
	RecipientCount         int      `json:"recipient_count"`
	Status                 string   `json:"status"`
	Revision               int64    `json:"revision"`
	OwnerPrincipalID       string   `json:"owner_principal_id,omitempty"`
	OwnerEndpointID        string   `json:"owner_endpoint_id,omitempty"`
	OwnerEpoch             int64    `json:"owner_epoch"`
	ClaimKey               string   `json:"-"`
	LeaseExpiresAt         string   `json:"lease_expires_at,omitempty"`
	AcceptedResultID       string   `json:"accepted_result_id,omitempty"`
	PendingResultID        string   `json:"pending_result_id,omitempty"`
	PendingResultMessageID string   `json:"pending_result_message_id,omitempty"`
	ExpiresAt              string   `json:"expires_at"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
	NotifyEndpointIDs      []string `json:"-"`
	DeliveryState          string   `json:"delivery_state,omitempty"`
}

type NetworkTaskOfferInput struct {
	TaskID          string   `json:"task_id"`
	ExpiresAt       string   `json:"expires_at"`
	OfferMessageIDs []string `json:"offer_message_ids"`
}

type NetworkTaskResultInput struct {
	TaskID           string `json:"task_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	OwnerEpoch       int64  `json:"owner_epoch"`
	ResultMessageID  string `json:"result_message_id"`
}

type NetworkTaskResult struct {
	ID                   string `json:"result_id"`
	TaskID               string `json:"task_id"`
	SubmitterPrincipalID string `json:"submitter_principal_id"`
	SubmitterEndpointID  string `json:"submitter_endpoint_id"`
	OwnerEpoch           int64  `json:"owner_epoch"`
	ResultMessageID      string `json:"result_message_id"`
	Authority            string `json:"authority"`
	CreatedAt            string `json:"created_at"`
	NotifyEndpointID     string `json:"-"`
}

// NetworkTaskDeliveryAuthorization is a fresh, body-free proof that a reserved
// Network Task SEND has the exact committed responsibility route needed before
// a Node may persist or inject its plaintext.
type NetworkTaskDeliveryAuthorization struct {
	NetworkID          string `json:"network_id"`
	MessageID          string `json:"message_id"`
	TaskID             string `json:"task_id"`
	Kind               string `json:"kind"`
	SenderEndpointID   string `json:"sender_endpoint_id"`
	ReceiverEndpointID string `json:"receiver_endpoint_id"`
	OwnerEndpointID    string `json:"owner_endpoint_id,omitempty"`
	OwnerEpoch         int64  `json:"owner_epoch"`
	Revision           int64  `json:"revision"`
	Status             string `json:"status"`
	ExpiresAt          string `json:"expires_at"`
}

func (s *Store) initializeNetworkTaskSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS network_task_offers_v2 (
 id TEXT PRIMARY KEY, network_id TEXT NOT NULL, publisher_principal_id TEXT NOT NULL,
 publisher_endpoint_id TEXT NOT NULL, expires_at TEXT NOT NULL,
 status TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 owner_principal_id TEXT NOT NULL DEFAULT '', owner_endpoint_id TEXT NOT NULL DEFAULT '',
 owner_epoch INTEGER NOT NULL DEFAULT 0, claim_key TEXT NOT NULL DEFAULT '',
 lease_expires_at TEXT NOT NULL DEFAULT '', accepted_result_id TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(network_id) REFERENCES networks_v2(id));
CREATE INDEX IF NOT EXISTS network_task_offers_v2_network_status_idx
 ON network_task_offers_v2(network_id,status,created_at);
CREATE TABLE IF NOT EXISTS network_task_readers_v2 (
 task_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, message_id TEXT NOT NULL UNIQUE,
 PRIMARY KEY(task_id,endpoint_id),
 FOREIGN KEY(task_id) REFERENCES network_task_offers_v2(id),
 FOREIGN KEY(message_id) REFERENCES network_direct_message_routes_v2(message_id));
CREATE TABLE IF NOT EXISTS network_task_results_v2 (
 id TEXT PRIMARY KEY, task_id TEXT NOT NULL, submitter_principal_id TEXT NOT NULL,
 submitter_endpoint_id TEXT NOT NULL, owner_epoch INTEGER NOT NULL,
 message_id TEXT NOT NULL UNIQUE, authority TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(task_id) REFERENCES network_task_offers_v2(id),
 FOREIGN KEY(message_id) REFERENCES network_direct_message_routes_v2(message_id));
CREATE INDEX IF NOT EXISTS network_task_results_v2_task_idx
 ON network_task_results_v2(task_id,created_at);`)
	return err
}

const networkTaskColumns = `id,network_id,publisher_principal_id,publisher_endpoint_id,expires_at,status,revision,owner_principal_id,owner_endpoint_id,owner_epoch,claim_key,lease_expires_at,accepted_result_id,created_at,updated_at`

func scanNetworkTask(row interface{ Scan(...any) error }) (*NetworkTaskOffer, error) {
	var task NetworkTaskOffer
	err := row.Scan(&task.ID, &task.NetworkID, &task.PublisherPrincipalID,
		&task.PublisherEndpointID, &task.ExpiresAt, &task.Status, &task.Revision,
		&task.OwnerPrincipalID, &task.OwnerEndpointID, &task.OwnerEpoch, &task.ClaimKey,
		&task.LeaseExpiresAt, &task.AcceptedResultID, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSharedTaskNotFound
	}
	return &task, err
}

func loadNetworkTaskTx(tx *sql.Tx, id string) (*NetworkTaskOffer, error) {
	return scanNetworkTask(tx.QueryRow(`SELECT `+networkTaskColumns+` FROM network_task_offers_v2 WHERE id=?`, id))
}

func networkTaskIDValid(id string) bool {
	if len(id) < 24 || len(id) > 96 || !strings.HasPrefix(id, "ntask_") {
		return false
	}
	for _, b := range []byte(id) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

func networkTaskDeadline(value string, at time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && deadline.UTC().Format(time.RFC3339Nano) == value &&
		deadline.After(at) && !deadline.After(at.Add(24*time.Hour))
}

func networkTaskIDFromMessageID(messageID string) (string, string, bool) {
	if !strings.HasPrefix(messageID, "ntask_") {
		return "", "", false
	}
	separator := strings.IndexByte(messageID, ':')
	if separator < 0 {
		return "", "", true
	}
	taskID := messageID[:separator]
	if !networkTaskIDValid(taskID) || len(messageID) > 256 {
		return "", "", true
	}
	return taskID, messageID[separator+1:], true
}

func networkTaskMessageRouteCreatedAtTx(tx *sql.Tx, networkID, messageID string) (time.Time, error) {
	var createdAt string
	if err := tx.QueryRow(`SELECT created_at FROM network_direct_message_routes_v2
WHERE message_id=? AND network_id=?`, messageID, networkID).Scan(&createdAt); err != nil {
		return time.Time{}, ErrNetworkPermission
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != createdAt {
		return time.Time{}, ErrNetworkPermission
	}
	return created, nil
}

func networkTaskPendingMessageExpiredTx(tx *sql.Tx, networkID, messageID string, at time.Time) (bool, error) {
	created, err := networkTaskMessageRouteCreatedAtTx(tx, networkID, messageID)
	if err != nil {
		return false, err
	}
	return !created.Add(networkTaskPendingRouteMaxAge).After(at), nil
}

// networkTaskLegacyDirectRouteTx identifies preserved v42 Task messages whose
// Relay route was admitted under the Direct purpose. The row and ciphertext
// remain historical evidence, but this purpose migration never silently
// reseals them or grants the old route new delivery authority.
func networkTaskLegacyDirectRouteTx(tx *sql.Tx, networkID, messageID string) (bool, error) {
	if _, _, reserved := networkTaskIDFromMessageID(messageID); !reserved {
		return false, nil
	}
	var kind, purpose string
	err := tx.QueryRow(`SELECT message.kind,route.key_purpose
FROM network_direct_message_routes_v2 route
JOIN fabric_messages message ON message.id=route.message_id
WHERE route.message_id=? AND route.network_id=?`, messageID, networkID).Scan(&kind, &purpose)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return kind == "send" && purpose == "DIRECT", nil
}

// networkTaskDeliveryForRouteTx requires a reserved task SEND to be linked to
// current, exact offer/result metadata. No prose or sealed bytes are returned.
// An absent row is a retryable race between Relay acceptance and the following
// task metadata commit; all mismatched, expired, or terminal routes fail closed.
func networkTaskDeliveryForRouteTx(tx *sql.Tx, networkID, messageID,
	senderEndpointID, receiverEndpointID string, at time.Time) (*NetworkTaskDeliveryAuthorization, error) {
	taskID, suffix, reserved := networkTaskIDFromMessageID(messageID)
	if !reserved {
		return nil, nil
	}
	if taskID == "" || suffix == "" {
		return nil, ErrNetworkTaskUnavailable
	}
	if strings.HasPrefix(suffix, "offer:") {
		if len(suffix) <= len("offer:") {
			return nil, ErrNetworkTaskUnavailable
		}
		if err := networkTaskRouteTx(tx, networkID, messageID, senderEndpointID,
			receiverEndpointID, taskID+":offer:", at); err != nil {
			if errors.Is(err, ErrNetworkTaskMigrationBlocked) || errors.Is(err, ErrNetworkPermission) {
				return nil, err
			}
			return nil, ErrNetworkTaskUnavailable
		}
		task, err := loadNetworkTaskTx(tx, taskID)
		if errors.Is(err, ErrSharedTaskNotFound) {
			expired, expiryErr := networkTaskPendingMessageExpiredTx(tx, networkID, messageID, at)
			if expiryErr != nil {
				return nil, expiryErr
			}
			if expired {
				return nil, ErrNetworkTaskExpired
			}
			return nil, ErrNetworkTaskPending
		}
		if err != nil || task.NetworkID != networkID || task.PublisherEndpointID != senderEndpointID {
			return nil, ErrNetworkTaskUnavailable
		}
		var linkedMessageID string
		if err := tx.QueryRow(`SELECT message_id FROM network_task_readers_v2
WHERE task_id=? AND endpoint_id=?`, taskID, receiverEndpointID).Scan(&linkedMessageID); err != nil {
			return nil, ErrNetworkTaskUnavailable
		}
		if linkedMessageID != messageID {
			return nil, ErrNetworkTaskUnavailable
		}
		deadline, err := time.Parse(time.RFC3339Nano, task.ExpiresAt)
		if err != nil || !deadline.After(at) {
			return nil, ErrNetworkTaskExpired
		}
		receiverPrincipalID := networkTaskPrincipalTx(tx, receiverEndpointID)
		winnerIdentity := task.Status == SharedTaskClaimed &&
			task.OwnerEndpointID == receiverEndpointID && task.OwnerPrincipalID == receiverPrincipalID
		if winnerIdentity && !sharedTaskLeaseActive(task.LeaseExpiresAt) {
			return nil, ErrNetworkTaskLeaseExpired
		}
		winnerDelivery := winnerIdentity && sharedTaskLeaseActive(task.LeaseExpiresAt)
		if task.Status != SharedTaskReady && !winnerDelivery {
			if task.Status == SharedTaskClaimed || task.Status == SharedTaskResultSubmitted || task.Status == SharedTaskCompleted {
				return nil, ErrNetworkTaskAlreadyClaimed
			}
			return nil, ErrNetworkTaskUnavailable
		}
		if networkDirectMembershipAllowsTx(tx, networkID, senderEndpointID,
			task.PublisherPrincipalID, "task.offer.publish", at) != nil ||
			networkDirectMembershipAllowsTx(tx, networkID, receiverEndpointID,
				receiverPrincipalID, "task.offer.list", at) != nil {
			return nil, ErrNetworkPermission
		}
		return &NetworkTaskDeliveryAuthorization{NetworkID: networkID, MessageID: messageID,
			TaskID: task.ID, Kind: "offer", SenderEndpointID: senderEndpointID,
			ReceiverEndpointID: receiverEndpointID, OwnerEndpointID: task.OwnerEndpointID,
			OwnerEpoch: task.OwnerEpoch, Revision: task.Revision,
			Status: task.Status, ExpiresAt: task.ExpiresAt}, nil
	}
	if !strings.HasPrefix(suffix, "result:") {
		return nil, ErrNetworkTaskUnavailable
	}
	resultRoute := strings.TrimPrefix(suffix, "result:")
	separator := strings.IndexByte(resultRoute, ':')
	if separator <= 0 || separator == len(resultRoute)-1 {
		return nil, ErrNetworkTaskUnavailable
	}
	epoch, err := strconv.ParseInt(resultRoute[:separator], 10, 64)
	if err != nil || epoch <= 0 || strconv.FormatInt(epoch, 10) != resultRoute[:separator] {
		return nil, ErrNetworkTaskUnavailable
	}
	prefix := taskID + ":result:" + strconv.FormatInt(epoch, 10) + ":"
	if err := networkTaskRouteTx(tx, networkID, messageID, senderEndpointID,
		receiverEndpointID, prefix, at); err != nil {
		if errors.Is(err, ErrNetworkTaskMigrationBlocked) || errors.Is(err, ErrNetworkPermission) {
			return nil, err
		}
		return nil, ErrNetworkTaskUnavailable
	}
	task, taskErr := loadNetworkTaskTx(tx, taskID)
	if errors.Is(taskErr, ErrSharedTaskNotFound) {
		expired, expiryErr := networkTaskPendingMessageExpiredTx(tx, networkID, messageID, at)
		if expiryErr != nil {
			return nil, expiryErr
		}
		if expired {
			return nil, ErrNetworkTaskExpired
		}
		return nil, ErrNetworkTaskPending
	}
	if taskErr != nil || task.NetworkID != networkID || task.PublisherEndpointID != receiverEndpointID ||
		task.OwnerEndpointID != senderEndpointID || task.OwnerEpoch != epoch {
		return nil, ErrNetworkTaskUnavailable
	}
	deadline, err := time.Parse(time.RFC3339Nano, task.ExpiresAt)
	if err != nil || !deadline.After(at) {
		return nil, ErrNetworkTaskExpired
	}
	var result NetworkTaskResult
	err = tx.QueryRow(`SELECT id,task_id,submitter_principal_id,submitter_endpoint_id,
owner_epoch,message_id,authority,created_at FROM network_task_results_v2 WHERE message_id=?`,
		messageID).Scan(&result.ID, &result.TaskID, &result.SubmitterPrincipalID,
		&result.SubmitterEndpointID, &result.OwnerEpoch, &result.ResultMessageID,
		&result.Authority, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if task.Status != SharedTaskClaimed || !sharedTaskLeaseActive(task.LeaseExpiresAt) {
			return nil, ErrNetworkTaskUnavailable
		}
		if err := networkDirectMembershipAllowsTx(tx, networkID, senderEndpointID,
			task.OwnerPrincipalID, "task.offer.result", at); err != nil {
			return nil, ErrNetworkPermission
		}
		if err := networkDirectMembershipAllowsTx(tx, networkID, receiverEndpointID,
			task.PublisherPrincipalID, "task.offer.accept", at); err != nil {
			return nil, ErrNetworkPermission
		}
		return nil, ErrNetworkTaskPending
	}
	if err != nil || result.TaskID != taskID || result.SubmitterEndpointID != senderEndpointID ||
		result.OwnerEpoch != epoch || result.Authority != "PENDING" ||
		task.Status != SharedTaskResultSubmitted {
		return nil, ErrNetworkTaskUnavailable
	}
	if err := networkDirectMembershipAllowsTx(tx, networkID, senderEndpointID,
		result.SubmitterPrincipalID, "task.offer.result", at); err != nil {
		return nil, ErrNetworkPermission
	}
	if err := networkDirectMembershipAllowsTx(tx, networkID, receiverEndpointID,
		task.PublisherPrincipalID, "task.offer.accept", at); err != nil {
		return nil, ErrNetworkPermission
	}
	return &NetworkTaskDeliveryAuthorization{NetworkID: networkID, MessageID: messageID,
		TaskID: task.ID, Kind: "result", SenderEndpointID: senderEndpointID,
		ReceiverEndpointID: receiverEndpointID, OwnerEndpointID: task.OwnerEndpointID,
		OwnerEpoch: result.OwnerEpoch,
		Revision:   task.Revision, Status: task.Status, ExpiresAt: task.ExpiresAt}, nil
}

func networkTaskRouteTx(tx *sql.Tx, networkID, messageID, senderID, receiverID, prefix string, at time.Time) error {
	if !strings.HasPrefix(messageID, prefix) || len(messageID) > 256 || len(messageID) <= len(prefix) {
		return ErrNetworkPermission
	}
	var savedNetwork, sender, receiver, kind, keyPurpose string
	var ciphertextLength int
	err := tx.QueryRow(`SELECT r.network_id,r.sender_endpoint_id,r.receiver_endpoint_id,m.kind,length(p.ciphertext),r.key_purpose
FROM network_direct_message_routes_v2 r JOIN fabric_messages m ON m.id=r.message_id
JOIN relay_v2_message_payloads p ON p.message_id=m.id AND p.payload_mode='SEALED_V1'
	WHERE r.message_id=?`, messageID).Scan(&savedNetwork, &sender, &receiver, &kind, &ciphertextLength, &keyPurpose)
	if err != nil || savedNetwork != networkID || sender != senderID || (receiverID != "" && receiver != receiverID) || kind != "send" {
		return ErrNetworkPermission
	}
	if keyPurpose != e2ee.NetworkCollaborationPurposeTask {
		return ErrNetworkTaskMigrationBlocked
	}
	if ciphertextLength <= 0 || ciphertextLength > 256*1024 {
		return ErrNetworkPermission
	}
	return networkGuardCollaborationMessageTx(tx, messageID, networkID,
		e2ee.NetworkCollaborationPurposeTask, at)
}

func networkTaskVisibleTx(tx *sql.Tx, scope NetworkAccessScope, task *NetworkTaskOffer, at time.Time) error {
	if task.NetworkID != scope.NetworkID {
		return ErrSharedTaskNotFound
	}
	if task.PublisherEndpointID == scope.EndpointID {
		return nil
	}
	err := tx.QueryRow(`SELECT message_id FROM network_task_readers_v2 WHERE task_id=? AND endpoint_id=?`, task.ID, scope.EndpointID).Scan(&task.OfferMessageID)
	if err != nil {
		return ErrSharedTaskNotFound
	}
	if err := networkTaskRouteTx(tx, task.NetworkID, task.OfferMessageID,
		task.PublisherEndpointID, scope.EndpointID, task.ID+":offer:", at); err != nil {
		return ErrSharedTaskNotFound
	}
	return nil
}

func networkTaskDeliveryStateTx(tx *sql.Tx, taskID string) string {
	var total, typed int
	if err := tx.QueryRow(`SELECT count(*),sum(CASE WHEN route.key_purpose='TASK' THEN 1 ELSE 0 END)
FROM network_task_readers_v2 reader
LEFT JOIN network_direct_message_routes_v2 route ON route.message_id=reader.message_id
WHERE reader.task_id=?`, taskID).Scan(&total, &typed); err != nil {
		return "UNAVAILABLE"
	}
	if total == 0 || typed != total {
		return "MIGRATION_BLOCKED"
	}
	return "CURRENT"
}

func (s *Store) PublishNetworkTaskOffer(scope NetworkAccessScope, input NetworkTaskOfferInput) (*NetworkTaskOffer, error) {
	at := time.Now().UTC()
	if !networkTaskIDValid(input.TaskID) || !networkTaskDeadline(input.ExpiresAt, at) ||
		len(input.OfferMessageIDs) == 0 || len(input.OfferMessageIDs) > networkTaskMaxReaders {
		return nil, ErrNetworkConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	if err = networkGuardAccessTx(tx, scope, "task.offer.publish", at); err != nil {
		return nil, err
	}
	targets := make(map[string]string, len(input.OfferMessageIDs))
	for _, messageID := range input.OfferMessageIDs {
		var networkID, senderID, receiverID, routeCreatedAt string
		if err = tx.QueryRow(`SELECT network_id,sender_endpoint_id,receiver_endpoint_id,created_at FROM network_direct_message_routes_v2 WHERE message_id=?`, messageID).Scan(&networkID, &senderID, &receiverID, &routeCreatedAt); err != nil || networkID != scope.NetworkID || senderID != scope.EndpointID || receiverID == scope.EndpointID {
			return nil, ErrNetworkPermission
		}
		if err = networkTaskRouteTx(tx, scope.NetworkID, messageID, scope.EndpointID, receiverID, input.TaskID+":offer:", at); err != nil {
			return nil, err
		}
		created, parseErr := time.Parse(time.RFC3339Nano, routeCreatedAt)
		deadline, deadlineErr := time.Parse(time.RFC3339Nano, input.ExpiresAt)
		if parseErr != nil || deadlineErr != nil || deadline.After(created.Add(networkTaskPendingRouteMaxAge)) {
			return nil, ErrNetworkConflict
		}
		if err = networkDirectMembershipAllowsTx(tx, scope.NetworkID, receiverID, networkTaskPrincipalTx(tx, receiverID), "task.offer.list", at); err != nil {
			return nil, err
		}
		if _, exists := targets[receiverID]; exists {
			return nil, ErrNetworkConflict
		}
		targets[receiverID] = messageID
	}
	previous, err := loadNetworkTaskTx(tx, input.TaskID)
	if err == nil {
		if previous.NetworkID != scope.NetworkID || previous.PublisherEndpointID != scope.EndpointID || previous.ExpiresAt != input.ExpiresAt {
			return nil, ErrSharedTaskConflict
		}
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM network_task_readers_v2 WHERE task_id=?`, input.TaskID).Scan(&count); err != nil {
			return nil, err
		}
		if count != len(targets) {
			return nil, ErrSharedTaskConflict
		}
		previous.RecipientCount = count
		for endpointID, messageID := range targets {
			var saved string
			if err = tx.QueryRow(`SELECT message_id FROM network_task_readers_v2 WHERE task_id=? AND endpoint_id=?`, input.TaskID, endpointID).Scan(&saved); err != nil || saved != messageID {
				return nil, ErrSharedTaskConflict
			}
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		previous.NotifyEndpointIDs = make([]string, 0, len(targets))
		for endpointID := range targets {
			previous.NotifyEndpointIDs = append(previous.NotifyEndpointIDs, endpointID)
		}
		sort.Strings(previous.NotifyEndpointIDs)
		return previous, nil
	}
	if !errors.Is(err, ErrSharedTaskNotFound) {
		return nil, err
	}
	var pending, retained int
	if err = tx.QueryRow(`SELECT count(*) FROM network_task_offers_v2
WHERE network_id=? AND publisher_endpoint_id=? AND status IN (?,?,?)
AND cicada_network_expiry_allows(expires_at,?)=1`, scope.NetworkID,
		scope.EndpointID, SharedTaskReady, SharedTaskClaimed, SharedTaskResultSubmitted,
		at.Format(time.RFC3339Nano)).Scan(&pending); err != nil {
		return nil, err
	}
	if err = tx.QueryRow(`SELECT count(*) FROM network_task_offers_v2 WHERE network_id=?`,
		scope.NetworkID).Scan(&retained); err != nil {
		return nil, err
	}
	if pending >= networkTaskMaxPendingPublisher || retained >= networkTaskMaxRetainedNetwork {
		return nil, ErrNetworkConflict
	}
	stamp := now()
	_, err = tx.Exec(`INSERT INTO network_task_offers_v2
(id,network_id,publisher_principal_id,publisher_endpoint_id,expires_at,status,revision,created_at,updated_at)
VALUES(?,?,?,?,?,?,1,?,?)`, input.TaskID, scope.NetworkID, scope.PrincipalID, scope.EndpointID, input.ExpiresAt, SharedTaskReady, stamp, stamp)
	if err != nil {
		return nil, err
	}
	for endpointID, messageID := range targets {
		if _, err = tx.Exec(`INSERT INTO network_task_readers_v2(task_id,endpoint_id,message_id) VALUES(?,?,?)`, input.TaskID, endpointID, messageID); err != nil {
			return nil, err
		}
	}
	task, err := loadNetworkTaskTx(tx, input.TaskID)
	if err != nil {
		return nil, err
	}
	task.RecipientCount = len(targets)
	task.NotifyEndpointIDs = make([]string, 0, len(targets))
	for endpointID := range targets {
		task.NotifyEndpointIDs = append(task.NotifyEndpointIDs, endpointID)
	}
	sort.Strings(task.NotifyEndpointIDs)
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func networkTaskPrincipalTx(tx *sql.Tx, endpointID string) string {
	var principalID string
	_ = tx.QueryRow(`SELECT principal_id FROM fabric_endpoints WHERE id=?`, endpointID).Scan(&principalID)
	return principalID
}

func (s *Store) GetNetworkTaskOffer(scope NetworkAccessScope, taskID string) (*NetworkTaskOffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err = networkGuardAccessTx(tx, scope, "task.offer.list", at); err != nil {
		return nil, err
	}
	task, err := loadNetworkTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = networkTaskVisibleTx(tx, scope, task, at); err != nil {
		return nil, err
	}
	if err = tx.QueryRow(`SELECT count(*) FROM network_task_readers_v2 WHERE task_id=?`, taskID).Scan(&task.RecipientCount); err != nil {
		return nil, err
	}
	if scope.EndpointID == task.PublisherEndpointID {
		task.DeliveryState = networkTaskDeliveryStateTx(tx, taskID)
	}
	if scope.EndpointID != task.PublisherEndpointID {
		// A reader may learn that the Task is complete, but never receives
		// publisher-side result identifiers or the accepted-result reference.
		task.AcceptedResultID = ""
	} else if task.Status == SharedTaskResultSubmitted {
		var resultID, messageID, submitterEndpointID, authority string
		var ownerEpoch int64
		err = tx.QueryRow(`SELECT id,message_id,submitter_endpoint_id,owner_epoch,authority
FROM network_task_results_v2 WHERE task_id=? AND authority='PENDING' ORDER BY created_at DESC,id DESC LIMIT 1`,
			taskID).Scan(&resultID, &messageID, &submitterEndpointID, &ownerEpoch, &authority)
		if err != nil || resultID == "" || messageID == "" || ownerEpoch != task.OwnerEpoch ||
			submitterEndpointID != task.OwnerEndpointID || authority != "PENDING" {
			return nil, ErrSharedTaskConflict
		}
		if _, err = networkTaskDeliveryForRouteTx(tx, task.NetworkID, messageID,
			task.OwnerEndpointID, task.PublisherEndpointID, at); err != nil {
			return nil, err
		}
		task.PendingResultID = resultID
		task.PendingResultMessageID = messageID
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *Store) ListNetworkTaskOffers(scope NetworkAccessScope, limit int) ([]NetworkTaskOffer, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Now().UTC()
	if err = networkGuardAccessTx(tx, scope, "task.offer.list", at); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+networkTaskColumns+` FROM network_task_offers_v2 t WHERE network_id=?
AND (publisher_endpoint_id=? OR EXISTS(SELECT 1 FROM network_task_readers_v2 r WHERE r.task_id=t.id AND r.endpoint_id=?))
ORDER BY created_at DESC,id DESC LIMIT ?`, scope.NetworkID, scope.EndpointID, scope.EndpointID, limit)
	if err != nil {
		return nil, err
	}
	var tasks []NetworkTaskOffer
	for rows.Next() {
		task, scanErr := scanNetworkTask(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		tasks = append(tasks, *task)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	visible := tasks[:0]
	for _, task := range tasks {
		if networkTaskVisibleTx(tx, scope, &task, at) != nil {
			continue
		}
		if err = tx.QueryRow(`SELECT count(*) FROM network_task_readers_v2 WHERE task_id=?`, task.ID).Scan(&task.RecipientCount); err != nil {
			return nil, err
		}
		if scope.EndpointID == task.PublisherEndpointID {
			task.DeliveryState = networkTaskDeliveryStateTx(tx, task.ID)
		}
		if scope.EndpointID != task.PublisherEndpointID {
			task.AcceptedResultID = ""
		}
		visible = append(visible, task)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return visible, nil
}

func (s *Store) ClaimNetworkTaskOffer(scope NetworkAccessScope, taskID string, expectedRevision int64, key string, leaseSeconds int) (*NetworkTaskOffer, error) {
	if key == "" || len(key) > 256 {
		return nil, ErrSharedTaskConflict
	}
	if leaseSeconds <= 0 {
		leaseSeconds = 300
	}
	if leaseSeconds > 3600 {
		leaseSeconds = 3600
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if err = networkGuardAccessTx(tx, scope, "task.offer.claim", at); err != nil {
		return nil, err
	}
	task, err := loadNetworkTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = networkTaskVisibleTx(tx, scope, task, at); err != nil {
		return nil, err
	}
	if task.PublisherEndpointID == scope.EndpointID {
		return nil, ErrNetworkPermission
	}
	deadline, parseErr := time.Parse(time.RFC3339Nano, task.ExpiresAt)
	if parseErr != nil || !deadline.After(at) {
		return nil, ErrSharedTaskConflict
	}
	if task.Status == SharedTaskClaimed && task.ClaimKey == key && task.OwnerEndpointID == scope.EndpointID && task.OwnerPrincipalID == scope.PrincipalID && sharedTaskLeaseActive(task.LeaseExpiresAt) {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return task, nil
	}
	if task.Revision != expectedRevision ||
		(task.Status != SharedTaskReady && !(task.Status == SharedTaskClaimed && !sharedTaskLeaseActive(task.LeaseExpiresAt))) {
		return nil, ErrSharedTaskConflict
	}
	untilTime := at.Add(time.Duration(leaseSeconds) * time.Second)
	if untilTime.After(deadline) {
		untilTime = deadline
	}
	until := untilTime.Format(time.RFC3339Nano)
	updated, err := tx.Exec(`UPDATE network_task_offers_v2 SET status=?,owner_principal_id=?,owner_endpoint_id=?,
claim_key=?,owner_epoch=owner_epoch+1,lease_expires_at=?,revision=revision+1,updated_at=?
WHERE id=? AND revision=? AND status=?`, SharedTaskClaimed, scope.PrincipalID, scope.EndpointID,
		key, until, now(), taskID, expectedRevision, task.Status)
	if err != nil {
		return nil, err
	}
	n, _ := updated.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadNetworkTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}

func (s *Store) SubmitNetworkTaskResult(scope NetworkAccessScope, input NetworkTaskResultInput) (*NetworkTaskResult, error) {
	if input.ResultMessageID == "" || input.OwnerEpoch <= 0 {
		return nil, ErrSharedTaskConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if err = networkGuardAccessTx(tx, scope, "task.offer.result", at); err != nil {
		return nil, err
	}
	task, err := loadNetworkTaskTx(tx, input.TaskID)
	if err != nil {
		return nil, err
	}
	if task.NetworkID != scope.NetworkID || task.OwnerEndpointID != scope.EndpointID || task.OwnerPrincipalID != scope.PrincipalID {
		return nil, ErrNetworkPermission
	}
	prefix := task.ID + ":result:" + strconv.FormatInt(input.OwnerEpoch, 10) + ":"
	if err = networkTaskRouteTx(tx, task.NetworkID, input.ResultMessageID, scope.EndpointID, task.PublisherEndpointID, prefix, at); err != nil {
		return nil, err
	}
	var prior NetworkTaskResult
	err = tx.QueryRow(`SELECT id,task_id,submitter_principal_id,submitter_endpoint_id,owner_epoch,message_id,authority,created_at FROM network_task_results_v2 WHERE message_id=?`, input.ResultMessageID).Scan(&prior.ID, &prior.TaskID, &prior.SubmitterPrincipalID, &prior.SubmitterEndpointID, &prior.OwnerEpoch, &prior.ResultMessageID, &prior.Authority, &prior.CreatedAt)
	if err == nil {
		if prior.TaskID != task.ID || prior.SubmitterEndpointID != scope.EndpointID || prior.OwnerEpoch != input.OwnerEpoch ||
			prior.OwnerEpoch != task.OwnerEpoch || (task.Status != SharedTaskResultSubmitted &&
			!(task.Status == SharedTaskCompleted && task.AcceptedResultID == prior.ID)) {
			return nil, ErrSharedTaskConflict
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return &prior, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	deadline, parseErr := time.Parse(time.RFC3339Nano, task.ExpiresAt)
	if parseErr != nil || !deadline.After(at) {
		return nil, ErrSharedTaskConflict
	}
	if task.Revision != input.ExpectedRevision || task.OwnerEpoch != input.OwnerEpoch || task.Status != SharedTaskClaimed || !sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return nil, ErrSharedTaskStaleOwner
	}
	result := &NetworkTaskResult{ID: NewID("nresult"), TaskID: task.ID, SubmitterPrincipalID: scope.PrincipalID, SubmitterEndpointID: scope.EndpointID, OwnerEpoch: input.OwnerEpoch, ResultMessageID: input.ResultMessageID, Authority: "PENDING", CreatedAt: now(), NotifyEndpointID: task.PublisherEndpointID}
	_, err = tx.Exec(`INSERT INTO network_task_results_v2(id,task_id,submitter_principal_id,submitter_endpoint_id,owner_epoch,message_id,authority,created_at) VALUES(?,?,?,?,?,?,?,?)`, result.ID, result.TaskID, result.SubmitterPrincipalID, result.SubmitterEndpointID, result.OwnerEpoch, result.ResultMessageID, result.Authority, result.CreatedAt)
	if err != nil {
		return nil, err
	}
	updated, err := tx.Exec(`UPDATE network_task_offers_v2 SET status=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND owner_epoch=? AND status=?`, SharedTaskResultSubmitted, now(), task.ID, input.ExpectedRevision, input.OwnerEpoch, SharedTaskClaimed)
	if err != nil {
		return nil, err
	}
	n, _ := updated.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) AcceptNetworkTaskResult(scope NetworkAccessScope, taskID, resultID string, expectedRevision int64) (*NetworkTaskOffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = acquireSharedTaskWrite(tx); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if err = networkGuardAccessTx(tx, scope, "task.offer.accept", at); err != nil {
		return nil, err
	}
	task, err := loadNetworkTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if task.NetworkID != scope.NetworkID || task.PublisherEndpointID != scope.EndpointID || task.PublisherPrincipalID != scope.PrincipalID {
		return nil, ErrNetworkPermission
	}
	var result NetworkTaskResult
	err = tx.QueryRow(`SELECT id,task_id,submitter_principal_id,submitter_endpoint_id,owner_epoch,message_id,authority,created_at FROM network_task_results_v2 WHERE id=? AND task_id=?`, resultID, taskID).Scan(&result.ID, &result.TaskID, &result.SubmitterPrincipalID, &result.SubmitterEndpointID, &result.OwnerEpoch, &result.ResultMessageID, &result.Authority, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSharedTaskResultNotFound
	}
	if err != nil {
		return nil, err
	}
	prefix := task.ID + ":result:" + strconv.FormatInt(result.OwnerEpoch, 10) + ":"
	if err = networkTaskRouteTx(tx, task.NetworkID, result.ResultMessageID, result.SubmitterEndpointID, scope.EndpointID, prefix, at); err != nil {
		return nil, err
	}
	if task.Status == SharedTaskCompleted && task.AcceptedResultID == resultID && result.Authority == "ACCEPTED" {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return task, nil
	}
	deadline, parseErr := time.Parse(time.RFC3339Nano, task.ExpiresAt)
	if parseErr != nil || !deadline.After(at) {
		return nil, ErrSharedTaskConflict
	}
	if task.Revision != expectedRevision || task.Status != SharedTaskResultSubmitted || result.Authority != "PENDING" || result.OwnerEpoch != task.OwnerEpoch || result.SubmitterEndpointID != task.OwnerEndpointID {
		return nil, ErrSharedTaskConflict
	}
	_, err = tx.Exec(`UPDATE network_task_results_v2 SET authority='ACCEPTED' WHERE id=? AND authority='PENDING'`, resultID)
	if err != nil {
		return nil, err
	}
	updated, err := tx.Exec(`UPDATE network_task_offers_v2 SET status=?,accepted_result_id=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND status=?`, SharedTaskCompleted, resultID, now(), taskID, expectedRevision, SharedTaskResultSubmitted)
	if err != nil {
		return nil, err
	}
	n, _ := updated.RowsAffected()
	if n != 1 {
		return nil, ErrSharedTaskConflict
	}
	task, err = loadNetworkTaskTx(tx, taskID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return task, nil
}
