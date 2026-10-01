package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	CommunicationLinkReviewWaiting       = "WAITING_REVIEW"
	CommunicationLinkReviewApproved      = "APPROVED"
	CommunicationLinkReviewRejected      = "REJECTED"
	CommunicationLinkReviewExpiredStatus = "EXPIRED"
	CommunicationLinkReviewStale         = "STALE"
)

// CommunicationLinkMessageReview contains only routing metadata and a sealed
// message digest. It never returns ciphertext, decoded content, or reviewer
// roster data.
type CommunicationLinkMessageReview struct {
	MessageID          string `json:"message_id"`
	LinkID             string `json:"link_id"`
	RouteKind          string `json:"route_kind"`
	RequestID          string `json:"request_id,omitempty"`
	SenderEndpointID   string `json:"sender_endpoint_id"`
	ReceiverEndpointID string `json:"receiver_endpoint_id"`
	MessageDigest      string `json:"message_digest"`
	PolicyVersion      int64  `json:"policy_version"`
	ReviewerEndpointID string `json:"reviewer_endpoint_id"`
	ReviewerGroupID    string `json:"reviewer_group_id"`
	ReviewerIndex      int    `json:"reviewer_index"`
	OwnerEpoch         int64  `json:"owner_epoch"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
	ExpiresAt          string `json:"expires_at"`
	Status             string `json:"status"`
	Version            int64  `json:"version"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	DecidedAt          string `json:"decided_at,omitempty"`
}

type storedCommunicationLinkMessageReview struct {
	CommunicationLinkMessageReview
	LinkVersion     int64
	PolicyDigest    string
	SenderGroupID   string
	ReceiverGroupID string
	Reviewers       []CommunicationLinkReviewer
}

type CommunicationLinkMessageReviewPage struct {
	Items      []CommunicationLinkMessageReview `json:"items"`
	NextCursor string                           `json:"next_cursor,omitempty"`
}

const communicationLinkMessageReviewColumns = `message_id,link_id,link_version,policy_version,policy_digest,
route_kind,request_id,sender_endpoint_id,sender_group_id,receiver_endpoint_id,receiver_group_id,message_digest,
reviewers_json,reviewer_index,owner_epoch,lease_expires_at,expires_at,status,version,created_at,updated_at,decided_at`

func scanCommunicationLinkMessageReview(row interface{ Scan(...any) error }) (*storedCommunicationLinkMessageReview, error) {
	var result storedCommunicationLinkMessageReview
	var reviewersJSON string
	err := row.Scan(&result.MessageID, &result.LinkID, &result.LinkVersion,
		&result.PolicyVersion, &result.PolicyDigest, &result.RouteKind, &result.RequestID,
		&result.SenderEndpointID, &result.SenderGroupID, &result.ReceiverEndpointID,
		&result.ReceiverGroupID, &result.MessageDigest, &reviewersJSON,
		&result.ReviewerIndex, &result.OwnerEpoch, &result.LeaseExpiresAt,
		&result.ExpiresAt, &result.Status, &result.Version, &result.CreatedAt,
		&result.UpdatedAt, &result.DecidedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(reviewersJSON), &result.Reviewers); err != nil || len(result.Reviewers) == 0 ||
		result.ReviewerIndex < 0 || result.ReviewerIndex >= len(result.Reviewers) {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	assigned := result.Reviewers[result.ReviewerIndex]
	result.ReviewerEndpointID = assigned.EndpointID
	result.ReviewerGroupID = assigned.GroupID
	return &result, nil
}

func reviewFromStored(stored *storedCommunicationLinkMessageReview) *CommunicationLinkMessageReview {
	if stored == nil {
		return nil
	}
	result := stored.CommunicationLinkMessageReview
	return &result
}

func ensureCommunicationLinkMessageReviewTx(tx *sql.Tx, link CommunicationLink,
	record *RelaySealedV1Record, at time.Time) error {
	if record == nil || record.PayloadMode != RelayPayloadModeSealedV1 ||
		record.Security.AuthorizationRef != communicationLinkAuthorizationRefPrefix+link.ID ||
		record.Security.Digest == "" || record.Security.Digest != relayCiphertextDigest(record.Ciphertext) {
		return ErrCommunicationLinkRelayDenied
	}
	policyVersion, policyDigest, err := communicationLinkReviewHeadTx(tx, link.ID)
	if err != nil {
		return err
	}
	if policyVersion == 0 {
		return nil
	}
	policy, policyExpiresAt, err := readCurrentCommunicationLinkReviewPolicyTx(tx, link, at)
	if err != nil {
		return err
	}
	if policy.Mode == CommunicationLinkReviewNone {
		return nil
	}
	if policy.Mode != CommunicationLinkReviewMetadata || len(policy.Reviewers) == 0 {
		return ErrCommunicationLinkReviewPolicy
	}
	prior, priorErr := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+`
FROM communication_link_message_reviews_v2 WHERE message_id=?`, record.Route.MessageID))
	if priorErr == nil {
		if prior.LinkID != link.ID || prior.MessageDigest != record.Security.Digest ||
			prior.RouteKind != record.Route.Kind || prior.PolicyVersion != policyVersion || prior.PolicyDigest != policyDigest ||
			prior.RequestID != record.Route.RequestID || prior.SenderEndpointID != record.Route.SenderEndpointID ||
			prior.ReceiverEndpointID != record.Route.ReceiverEndpointID || !sameCommunicationLinkReviewers(prior.Reviewers, policy.Reviewers) {
			return ErrCommunicationLinkReviewConflict
		}
		return nil
	}
	if !errors.Is(priorErr, sql.ErrNoRows) {
		return priorErr
	}
	var inboxState string
	err = tx.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=? AND recipient_endpoint_id=?`,
		record.Route.MessageID, record.Route.ReceiverEndpointID).Scan(&inboxState)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRelayMessageNotFound
	}
	if err != nil {
		return err
	}
	if inboxState != RelayInboxReady {
		// Idempotent retries of an already terminal message do not create a new
		// review obligation after the Link policy was later changed.
		return nil
	}
	if err := expireCommunicationLinkReviewQueueTx(tx, link.ID, at); err != nil {
		return err
	}
	var pending int
	if err := tx.QueryRow(`SELECT count(*) FROM communication_link_message_reviews_v2
WHERE link_id=? AND status=?`, link.ID, CommunicationLinkReviewWaiting).Scan(&pending); err != nil {
		return err
	}
	if pending >= communicationLinkReviewMaxPending {
		return ErrCommunicationLinkReviewConflict
	}
	expires, err := time.Parse(time.RFC3339Nano, link.ExpiresAt)
	if err != nil {
		return ErrCommunicationLinkReviewPolicy
	}
	policyExpiry, err := time.Parse(time.RFC3339Nano, policyExpiresAt)
	if err != nil || !policyExpiry.After(at) {
		return ErrCommunicationLinkReviewPolicy
	}
	if policyExpiry.Before(expires) {
		expires = policyExpiry
	}
	maxAge := at.Add(time.Duration(policy.MaxReviewAgeSeconds) * time.Second)
	if maxAge.Before(expires) {
		expires = maxAge
	}
	if record.Route.RequestID != "" {
		request, err := relayLoadRequestTx(tx, record.Route.RequestID)
		if err != nil || request == nil {
			return ErrRelayRequestNotFound
		}
		requestExpiry, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if err != nil {
			return ErrCommunicationLinkReviewPolicy
		}
		if requestExpiry.Before(expires) {
			expires = requestExpiry
		}
	}
	if !expires.After(at) {
		return ErrCommunicationLinkReviewExpired
	}
	reviewersJSON, err := json.Marshal(policy.Reviewers)
	if err != nil {
		return err
	}
	stamp := at.UTC().Format(time.RFC3339Nano)
	lease := at.Add(time.Duration(policy.ReviewerLeaseSeconds) * time.Second)
	if lease.After(expires) {
		lease = expires
	}
	_, err = tx.Exec(`INSERT INTO communication_link_message_reviews_v2
(message_id,link_id,link_version,policy_version,policy_digest,route_kind,request_id,
 sender_endpoint_id,sender_group_id,receiver_endpoint_id,receiver_group_id,message_digest,
 reviewers_json,reviewer_index,owner_epoch,lease_expires_at,expires_at,status,version,created_at,updated_at,decided_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'')`, record.Route.MessageID, link.ID, link.Version,
		policyVersion, policyDigest, record.Route.Kind, record.Route.RequestID,
		record.Route.SenderEndpointID, record.Security.SenderGroupID,
		record.Route.ReceiverEndpointID, record.Security.ReceiverGroupID,
		record.Security.Digest, string(reviewersJSON), 0, 1,
		lease.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano),
		CommunicationLinkReviewWaiting, 1, stamp, stamp)
	if err != nil {
		return err
	}
	for index, reviewer := range policy.Reviewers {
		if _, err := tx.Exec(`INSERT INTO communication_link_message_review_candidates_v2
(message_id,reviewer_endpoint_id,reviewer_group_id,reviewer_index) VALUES(?,?,?,?)`,
			record.Route.MessageID, reviewer.EndpointID, reviewer.GroupID, index); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO communication_link_review_events_v2
(message_id,event_type,prior_status,next_status,reviewer_endpoint_id,owner_epoch,version,created_at)
VALUES(?,?,?,?,?,?,?,?)`, record.Route.MessageID, "WAITING_REVIEW", "", CommunicationLinkReviewWaiting,
		policy.Reviewers[0].EndpointID, 1, 1, stamp)
	return err
}

func sameCommunicationLinkReviewers(left, right []CommunicationLinkReviewer) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func communicationLinkReviewGateTx(tx *sql.Tx, record *RelaySealedV1Record, at time.Time, allowWaiting bool) error {
	if record == nil || !strings.HasPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
		return ErrCommunicationLinkRelayDenied
	}
	linkID := strings.TrimPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+` FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link == nil {
		return ErrCommunicationLinkRelayDenied
	}
	policyVersion, policyDigest, err := communicationLinkReviewHeadTx(tx, link.ID)
	if err != nil {
		return err
	}
	if policyVersion == 0 {
		return nil
	}
	policy, _, err := readCurrentCommunicationLinkReviewPolicyTx(tx, *link, at)
	if err != nil {
		return ErrCommunicationLinkReviewPolicy
	}
	if policy.Mode == CommunicationLinkReviewNone {
		return nil
	}
	review, err := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+`
FROM communication_link_message_reviews_v2 WHERE message_id=?`, record.Route.MessageID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCommunicationLinkReviewPending
	}
	if err != nil || review.LinkID != link.ID || review.LinkVersion != link.Version ||
		review.PolicyVersion != policyVersion || review.PolicyDigest != policyDigest ||
		review.MessageDigest != record.Security.Digest || review.RouteKind != record.Route.Kind ||
		review.RequestID != record.Route.RequestID || review.SenderEndpointID != record.Route.SenderEndpointID ||
		review.SenderGroupID != record.Security.SenderGroupID ||
		review.ReceiverEndpointID != record.Route.ReceiverEndpointID ||
		review.ReceiverGroupID != record.Security.ReceiverGroupID ||
		!sameCommunicationLinkReviewers(review.Reviewers, policy.Reviewers) {
		return ErrCommunicationLinkReviewPolicy
	}
	expires, err := time.Parse(time.RFC3339Nano, review.ExpiresAt)
	if err != nil {
		return ErrCommunicationLinkReviewPolicy
	}
	if !expires.After(at) && review.Status == CommunicationLinkReviewWaiting {
		return ErrCommunicationLinkReviewExpired
	}
	switch review.Status {
	case CommunicationLinkReviewApproved:
		return nil
	case CommunicationLinkReviewWaiting:
		if allowWaiting {
			return nil
		}
		return ErrCommunicationLinkReviewPending
	case CommunicationLinkReviewRejected:
		return ErrCommunicationLinkReviewRejected
	case CommunicationLinkReviewExpiredStatus:
		return ErrCommunicationLinkReviewExpired
	default:
		return ErrCommunicationLinkReviewPolicy
	}
}

func (s *Store) ListCommunicationLinkMessageReviewsForActor(scope NativeActorScope, limit int) ([]CommunicationLinkMessageReview, error) {
	page, err := s.ListCommunicationLinkMessageReviewsPageForActor(scope, "", limit)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// ListCommunicationLinkMessageReviewsPageForActor uses an exact reviewer
// Endpoint/Group index and validates each returned Link route and current
// policy in the same transaction. Cursor advances across stale rows.
func (s *Store) ListCommunicationLinkMessageReviewsPageForActor(scope NativeActorScope,
	cursor string, limit int) (*CommunicationLinkMessageReviewPage, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if len(cursor) > 256 || strings.TrimSpace(cursor) != cursor {
		return nil, ErrRelayCursor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := guardNativeActorTx(tx, scope, "link.review", now); err != nil {
		return nil, err
	}
	result := &CommunicationLinkMessageReviewPage{Items: make([]CommunicationLinkMessageReview, 0, limit)}
	scanLimit := limit * 4
	if scanLimit < 20 {
		scanLimit = 20
	}
	if scanLimit > 400 {
		scanLimit = 400
	}
	// Query candidate IDs only: both joined tables have a message_id column,
	// and the reviewer index makes paging proportional to this actor's queue.
	rows, err := tx.Query(`SELECT candidate.message_id
FROM communication_link_message_review_candidates_v2 candidate
JOIN communication_link_message_reviews_v2 review ON review.message_id=candidate.message_id
WHERE candidate.reviewer_endpoint_id=? AND candidate.reviewer_group_id=?
  AND review.status=? AND review.message_id>?
ORDER BY review.message_id LIMIT ?`, scope.EndpointID, scope.GroupID,
		CommunicationLinkReviewWaiting, cursor, scanLimit+1)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, scanLimit+1)
	for rows.Next() {
		var messageID string
		if err := rows.Scan(&messageID); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, messageID)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hasMore := len(ids) > scanLimit
	if hasMore {
		ids = ids[:scanLimit]
	}
	lastProcessed := cursor
	for _, messageID := range ids {
		review, err := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+
			communicationLinkMessageReviewColumns+` FROM communication_link_message_reviews_v2 WHERE message_id=?`, messageID))
		if err != nil {
			return nil, err
		}
		lastProcessed = messageID
		expires, expiryErr := time.Parse(time.RFC3339Nano, review.ExpiresAt)
		if expiryErr == nil && !expires.After(now) {
			if err := expireCommunicationLinkReviewTx(tx, review, now); err != nil {
				return nil, err
			}
			continue
		}
		if expiryErr != nil || !reviewContainsReviewer(review, scope.EndpointID, scope.GroupID) {
			continue
		}
		if _, _, routeErr := communicationLinkReviewCurrentRouteTx(tx, review, now); routeErr == nil {
			result.Items = append(result.Items, *reviewFromStored(review))
			if len(result.Items) == limit {
				break
			}
		}
	}
	if hasMore || lastProcessed != cursor && len(result.Items) == limit {
		result.NextCursor = lastProcessed
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) GetCommunicationLinkMessageReviewForActor(scope NativeActorScope, messageID string) (*CommunicationLinkMessageReview, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" || len(messageID) > 256 {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := guardNativeActorTx(tx, scope, "link.review", now); err != nil {
		return nil, ErrNetworkPermission
	}
	review, err := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+`
FROM communication_link_message_reviews_v2 WHERE message_id=?`, messageID))
	if err != nil || !reviewContainsReviewer(review, scope.EndpointID, scope.GroupID) {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	if review.Status == CommunicationLinkReviewWaiting {
		if _, _, err := communicationLinkReviewCurrentRouteTx(tx, review, now); err != nil {
			return nil, err
		}
	} else if _, _, _, err := communicationLinkReviewCurrentPolicyTx(tx, review, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return reviewFromStored(review), nil
}

// ClaimNextCommunicationLinkReviewForActor performs explicit, bounded
// failover only after the assigned reviewer lease expires. The next reviewer
// is taken from the owner-approved immutable list, never from caller input.
func (s *Store) ClaimNextCommunicationLinkReviewForActor(scope NativeActorScope, messageID string,
	expectedVersion, expectedOwnerEpoch int64) (*CommunicationLinkMessageReview, error) {
	return s.claimNextCommunicationLinkReview(scope, messageID, expectedVersion, expectedOwnerEpoch)
}

func (s *Store) claimNextCommunicationLinkReview(scope NativeActorScope, messageID string,
	expectedVersion, expectedOwnerEpoch int64) (*CommunicationLinkMessageReview, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" || expectedVersion <= 0 || expectedOwnerEpoch <= 0 {
		return nil, ErrVersionConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	review, err := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+`
FROM communication_link_message_reviews_v2 WHERE message_id=?`, messageID))
	if err != nil || review.Status != CommunicationLinkReviewWaiting || review.Version != expectedVersion ||
		review.OwnerEpoch != expectedOwnerEpoch {
		return nil, ErrVersionConflict
	}
	_, policy, err := communicationLinkReviewCurrentRouteTx(tx, review, now)
	if err != nil {
		return nil, err
	}
	if review.ReviewerIndex >= policy.MaxFailovers || review.ReviewerIndex+1 >= len(review.Reviewers) {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	next := review.Reviewers[review.ReviewerIndex+1]
	if scope.EndpointID != next.EndpointID || scope.GroupID != next.GroupID {
		return nil, ErrNetworkPermission
	}
	if err := guardNativeActorTx(tx, scope, "link.review", now); err != nil {
		return nil, ErrNetworkPermission
	}
	leaseExpiry, err := time.Parse(time.RFC3339Nano, review.LeaseExpiresAt)
	messageExpiry, expiryErr := time.Parse(time.RFC3339Nano, review.ExpiresAt)
	if err != nil || expiryErr != nil || leaseExpiry.After(now) || !messageExpiry.After(now) {
		return nil, ErrCommunicationLinkReviewConflict
	}
	oldStatus, oldVersion := review.Status, review.Version
	lease := now.Add(time.Duration(policy.ReviewerLeaseSeconds) * time.Second)
	if lease.After(messageExpiry) {
		lease = messageExpiry
	}
	stamp := now.Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE communication_link_message_reviews_v2 SET reviewer_index=?,owner_epoch=owner_epoch+1,
lease_expires_at=?,version=version+1,updated_at=? WHERE message_id=? AND status=? AND version=? AND owner_epoch=?`,
		review.ReviewerIndex+1, lease.Format(time.RFC3339Nano), stamp, messageID,
		CommunicationLinkReviewWaiting, expectedVersion, expectedOwnerEpoch)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrVersionConflict
	}
	if _, err := tx.Exec(`INSERT INTO communication_link_review_events_v2
(message_id,event_type,prior_status,next_status,reviewer_endpoint_id,owner_epoch,version,created_at)
VALUES(?,?,?,?,?,?,?,?)`, messageID, "REVIEWER_FAILOVER", oldStatus, oldStatus, next.EndpointID,
		expectedOwnerEpoch+1, oldVersion+1, stamp); err != nil {
		return nil, err
	}
	review, err = scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+
		` FROM communication_link_message_reviews_v2 WHERE message_id=?`, messageID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return reviewFromStored(review), nil
}

func (s *Store) DecideCommunicationLinkMessageReviewForActor(scope NativeActorScope, messageID string,
	expectedVersion, expectedOwnerEpoch int64, decision string) (*CommunicationLinkMessageReview, error) {
	messageID = strings.TrimSpace(messageID)
	decision = strings.ToUpper(strings.TrimSpace(decision))
	if messageID == "" || expectedVersion <= 0 || expectedOwnerEpoch <= 0 ||
		(decision != CommunicationLinkReviewApproved && decision != CommunicationLinkReviewRejected) {
		return nil, ErrCommunicationLinkReviewPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	review, err := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+
		` FROM communication_link_message_reviews_v2 WHERE message_id=?`, messageID))
	if err != nil {
		return nil, ErrVersionConflict
	}
	if review.Status != CommunicationLinkReviewWaiting {
		if (review.Status == decision) && review.Version == expectedVersion+1 && review.OwnerEpoch == expectedOwnerEpoch &&
			scope.EndpointID == review.ReviewerEndpointID && scope.GroupID == review.ReviewerGroupID {
			if err := guardNativeActorTx(tx, scope, "link.review", now); err != nil {
				return nil, ErrNetworkPermission
			}
			if _, _, _, err := communicationLinkReviewCurrentPolicyTx(tx, review, now); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return reviewFromStored(review), nil
		}
		return nil, ErrVersionConflict
	}
	if review.Version != expectedVersion || review.OwnerEpoch != expectedOwnerEpoch {
		return nil, ErrVersionConflict
	}
	if scope.EndpointID != review.ReviewerEndpointID || scope.GroupID != review.ReviewerGroupID {
		return nil, ErrNetworkPermission
	}
	if err := guardNativeActorTx(tx, scope, "link.review", now); err != nil {
		return nil, ErrNetworkPermission
	}
	_, _, err = communicationLinkReviewCurrentRouteTx(tx, review, now)
	if err != nil {
		return nil, err
	}
	lease, err := time.Parse(time.RFC3339Nano, review.LeaseExpiresAt)
	if err != nil || !lease.After(now) {
		return nil, ErrCommunicationLinkReviewConflict
	}
	if err := updateCommunicationLinkReviewStateTx(tx, review, decision, "REVIEW_"+decision, scope.EndpointID, now); err != nil {
		return nil, err
	}
	if decision == CommunicationLinkReviewRejected {
		if err := failCommunicationLinkReviewedMessageTx(tx, review, now,
			"LINK_REVIEW_REJECTED", "communication link reviewer rejected the sealed message", "metadata review rejected"); err != nil {
			return nil, err
		}
	}
	updated, err := scanCommunicationLinkMessageReview(tx.QueryRow(`SELECT `+communicationLinkMessageReviewColumns+
		` FROM communication_link_message_reviews_v2 WHERE message_id=?`, messageID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return reviewFromStored(updated), nil
}

func reviewContainsReviewer(review *storedCommunicationLinkMessageReview, endpointID, groupID string) bool {
	if review == nil {
		return false
	}
	for _, candidate := range review.Reviewers {
		if candidate.EndpointID == endpointID && candidate.GroupID == groupID {
			return true
		}
	}
	return false
}

func communicationLinkReviewCurrentRouteTx(tx *sql.Tx, review *storedCommunicationLinkMessageReview,
	at time.Time) (*CommunicationLink, CommunicationLinkReviewPolicy, error) {
	link, policy, record, err := communicationLinkReviewCurrentPolicyTx(tx, review, at)
	if err != nil {
		return nil, CommunicationLinkReviewPolicy{}, err
	}
	if err := validateQueuedCommunicationLinkSealedSendWithReviewTx(tx, record, at, true); err != nil {
		return nil, CommunicationLinkReviewPolicy{}, err
	}
	return link, policy, nil
}

// communicationLinkReviewCurrentPolicyTx guards metadata visibility against
// the current Link, Owner proofs, policy head and exact reviewer list without
// requiring the message's Relay request to remain OPEN/queueable. That permits
// an authorized reviewer to recover a terminal decision after delivery.
func communicationLinkReviewCurrentPolicyTx(tx *sql.Tx, review *storedCommunicationLinkMessageReview,
	at time.Time) (*CommunicationLink, CommunicationLinkReviewPolicy, *RelaySealedV1Record, error) {
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+` FROM communication_links_v2 WHERE id=?`, review.LinkID))
	if err != nil || link == nil || link.Version != review.LinkVersion || link.State != CommunicationLinkProposed {
		return nil, CommunicationLinkReviewPolicy{}, nil, ErrCommunicationLinkReviewPolicy
	}
	policyVersion, policyDigest, err := communicationLinkReviewHeadTx(tx, link.ID)
	if err != nil {
		return nil, CommunicationLinkReviewPolicy{}, nil, ErrCommunicationLinkReviewPolicy
	}
	if policyVersion != review.PolicyVersion || policyDigest != review.PolicyDigest {
		return nil, CommunicationLinkReviewPolicy{}, nil, ErrCommunicationLinkReviewPolicy
	}
	policy, _, err := readCurrentCommunicationLinkReviewPolicyTx(tx, *link, at)
	if err != nil {
		return nil, CommunicationLinkReviewPolicy{}, nil, ErrCommunicationLinkReviewPolicy
	}
	if policy.Mode != CommunicationLinkReviewMetadata || !sameCommunicationLinkReviewers(policy.Reviewers, review.Reviewers) {
		return nil, CommunicationLinkReviewPolicy{}, nil, ErrCommunicationLinkReviewPolicy
	}
	record, err := relaySealedV1RecordTx(tx, review.MessageID)
	if err != nil || record == nil || record.Route.Kind != review.RouteKind ||
		record.Route.MessageID != review.MessageID || record.Security.Digest != review.MessageDigest ||
		record.Route.RequestID != review.RequestID || record.Route.SenderEndpointID != review.SenderEndpointID ||
		record.Route.ReceiverEndpointID != review.ReceiverEndpointID ||
		record.Security.SenderGroupID != review.SenderGroupID || record.Security.ReceiverGroupID != review.ReceiverGroupID {
		return nil, CommunicationLinkReviewPolicy{}, nil, ErrCommunicationLinkReviewPolicy
	}
	return link, policy, record, nil
}

func updateCommunicationLinkReviewStateTx(tx *sql.Tx, review *storedCommunicationLinkMessageReview,
	status, eventType, reviewerEndpointID string, at time.Time) error {
	if review == nil || review.Status != CommunicationLinkReviewWaiting || status == CommunicationLinkReviewWaiting {
		return ErrVersionConflict
	}
	stamp := at.UTC().Format(time.RFC3339Nano)
	result, err := tx.Exec(`UPDATE communication_link_message_reviews_v2 SET status=?,version=version+1,
updated_at=?,decided_at=? WHERE message_id=? AND status=? AND version=? AND owner_epoch=?`,
		status, stamp, stamp, review.MessageID, CommunicationLinkReviewWaiting, review.Version, review.OwnerEpoch)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrVersionConflict
	}
	_, err = tx.Exec(`INSERT INTO communication_link_review_events_v2
(message_id,event_type,prior_status,next_status,reviewer_endpoint_id,owner_epoch,version,created_at)
VALUES(?,?,?,?,?,?,?,?)`, review.MessageID, eventType, review.Status, status,
		reviewerEndpointID, review.OwnerEpoch, review.Version+1, stamp)
	return err
}

func expireCommunicationLinkReviewQueueTx(tx *sql.Tx, linkID string, at time.Time) error {
	rows, err := tx.Query(`SELECT `+communicationLinkMessageReviewColumns+`
FROM communication_link_message_reviews_v2 WHERE link_id=? AND status=?`,
		linkID, CommunicationLinkReviewWaiting)
	if err != nil {
		return err
	}
	pending := make([]*storedCommunicationLinkMessageReview, 0)
	for rows.Next() {
		review, err := scanCommunicationLinkMessageReview(rows)
		if err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, review)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, review := range pending {
		expires, err := time.Parse(time.RFC3339Nano, review.ExpiresAt)
		if err != nil {
			return ErrCommunicationLinkReviewPolicy
		}
		if !expires.After(at) {
			if err := expireCommunicationLinkReviewTx(tx, review, at); err != nil {
				return err
			}
		}
	}
	return nil
}

func expireCommunicationLinkReviewTx(tx *sql.Tx, review *storedCommunicationLinkMessageReview, at time.Time) error {
	if err := updateCommunicationLinkReviewStateTx(tx, review, CommunicationLinkReviewExpiredStatus,
		"EXPIRED", "", at); err != nil {
		return err
	}
	return failCommunicationLinkReviewedMessageTx(tx, review, at,
		"LINK_REVIEW_EXPIRED", "communication link metadata review expired", "metadata review expired")
}

func failCommunicationLinkReviewedMessageTx(tx *sql.Tx, review *storedCommunicationLinkMessageReview, at time.Time,
	requestCancelCode, requestCancelReason, messageReason string) error {
	item, err := scanRelayInboxItem(tx.QueryRow(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id=i.message_id WHERE i.message_id=? AND i.recipient_endpoint_id=?`,
		review.MessageID, review.ReceiverEndpointID))
	if err != nil || item == nil {
		return ErrRelayMessageNotFound
	}
	if item.State == RelayInboxReady {
		if err := failQueuedSealedCommunicationLinkTx(tx, item, at.Format(time.RFC3339Nano), messageReason); err != nil {
			return err
		}
	}
	if review.RequestID != "" {
		request, err := relayLoadRequestTx(tx, review.RequestID)
		if err != nil {
			return err
		}
		if request != nil && (request.State == FabricRequestOpen || request.State == FabricRequestCancelRequested) {
			if _, err := relayMarkRequestCancellationTx(tx, request.RequestID, FabricRequestCancelled,
				requestCancelCode, requestCancelReason, at.Format(time.RFC3339Nano)); err != nil {
				return err
			}
		}
	}
	return nil
}

func communicationLinkReviewQueueError(err error) bool {
	return errors.Is(err, ErrCommunicationLinkReviewPending) || errors.Is(err, ErrCommunicationLinkReviewExpired)
}
