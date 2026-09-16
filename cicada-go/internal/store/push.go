package store

import (
	"database/sql"
	"errors"
	"strings"
)

// UpsertPushSubscription installs or refreshes a browser subscription. The
// endpoint is the stable identity supplied by the browser's Push API.
func (s *Store) UpsertPushSubscription(subscription PushSubscription) (*PushSubscription, error) {
	subscription.ID = strings.TrimSpace(subscription.ID)
	if subscription.ID == "" {
		subscription.ID = NewID("push")
	}
	subscription.Endpoint = strings.TrimSpace(subscription.Endpoint)
	subscription.P256DH = strings.TrimSpace(subscription.P256DH)
	subscription.Auth = strings.TrimSpace(subscription.Auth)
	if subscription.Endpoint == "" || subscription.P256DH == "" || subscription.Auth == "" {
		return nil, errors.New("push subscription endpoint and keys are required")
	}
	nowAt := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO push_subscriptions
	(id, endpoint, p256dh, auth, user_agent, last_error, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(endpoint) DO UPDATE SET
	  p256dh = excluded.p256dh,
	  auth = excluded.auth,
	  user_agent = excluded.user_agent,
	  last_error = '',
	  updated_at = excluded.updated_at`,
		subscription.ID, subscription.Endpoint, subscription.P256DH, subscription.Auth,
		subscription.UserAgent, "", nowAt, nowAt)
	if err != nil {
		return nil, err
	}
	return s.getPushSubscriptionLocked(subscription.Endpoint)
}

func (s *Store) getPushSubscriptionLocked(endpoint string) (*PushSubscription, error) {
	var subscription PushSubscription
	err := s.db.QueryRow(`SELECT id, endpoint, p256dh, auth, user_agent, last_error, created_at, updated_at
	FROM push_subscriptions WHERE endpoint = ?`, endpoint).Scan(
		&subscription.ID, &subscription.Endpoint, &subscription.P256DH, &subscription.Auth,
		&subscription.UserAgent, &subscription.LastError, &subscription.CreatedAt, &subscription.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &subscription, nil
}

// GetPushSubscription looks up a subscription by its opaque local id.
func (s *Store) GetPushSubscription(id string) (*PushSubscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var subscription PushSubscription
	err := s.db.QueryRow(`SELECT id, endpoint, p256dh, auth, user_agent, last_error, created_at, updated_at
	FROM push_subscriptions WHERE id = ?`, strings.TrimSpace(id)).Scan(
		&subscription.ID, &subscription.Endpoint, &subscription.P256DH, &subscription.Auth,
		&subscription.UserAgent, &subscription.LastError, &subscription.CreatedAt, &subscription.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &subscription, nil
}

// ListPushSubscriptions returns all currently registered browser endpoints.
func (s *Store) ListPushSubscriptions() ([]PushSubscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, endpoint, p256dh, auth, user_agent, last_error, created_at, updated_at
	FROM push_subscriptions ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PushSubscription{}
	for rows.Next() {
		var subscription PushSubscription
		if err := rows.Scan(&subscription.ID, &subscription.Endpoint, &subscription.P256DH, &subscription.Auth,
			&subscription.UserAgent, &subscription.LastError, &subscription.CreatedAt, &subscription.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, subscription)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// DeletePushSubscription removes an endpoint after browser unsubscribe or a
// push service's permanent 404/410 response.
func (s *Store) DeletePushSubscription(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM push_subscriptions WHERE id = ?`, strings.TrimSpace(id))
	return err
}

// SetPushSubscriptionError keeps transient delivery diagnostics durable while
// avoiding a second notification about the delivery failure itself.
func (s *Store) SetPushSubscriptionError(id, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE push_subscriptions SET last_error = ?, updated_at = ? WHERE id = ?`,
		strings.TrimSpace(message), now(), strings.TrimSpace(id))
	return err
}
