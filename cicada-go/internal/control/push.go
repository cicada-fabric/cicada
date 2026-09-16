package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/cicada-ai/cicada/internal/store"
)

const (
	maxPushEndpointBytes = 4096
	maxPushKeyBytes      = 512
	maxPushErrorBytes    = 512
)

// PushSubscriptionInput mirrors the browser PushSubscription JSON shape while
// keeping the local user-agent label optional.
type PushSubscriptionInput struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256DH string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	UserAgent string `json:"user_agent,omitempty"`
}

// PushSubscriptionRegistration intentionally omits the endpoint keys from the
// response. A client can retain its own PushSubscription object; the keys are
// only needed by Control when it encrypts a delivery.
type PushSubscriptionRegistration struct {
	ID        string `json:"id"`
	Endpoint  string `json:"endpoint"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type PushConfig struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key,omitempty"`
	Subject   string `json:"subject,omitempty"`
}

func (c *Control) PushConfiguration() PushConfig {
	return PushConfig{
		Enabled:   c.pushEnabled(),
		PublicKey: c.config.PushVAPIDPublicKey,
		Subject:   c.config.PushVAPIDSubject,
	}
}

func (c *Control) pushEnabled() bool {
	return strings.TrimSpace(c.config.PushVAPIDPublicKey) != "" &&
		strings.TrimSpace(c.config.PushVAPIDPrivateKey) != "" &&
		strings.TrimSpace(c.config.PushVAPIDSubject) != ""
}

func validatePushEndpoint(raw string) error {
	if len(raw) == 0 || len(raw) > maxPushEndpointBytes {
		return errors.New("push endpoint must be between 1 and 4096 bytes")
	}
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || target == nil || target.Scheme != "https" || target.Hostname() == "" {
		return errors.New("push endpoint must be an absolute HTTPS URL")
	}
	if target.User != nil || target.Fragment != "" || target.Opaque != "" {
		return errors.New("push endpoint cannot contain credentials, fragments, or opaque data")
	}
	return nil
}

func validatePushKey(name, value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxPushKeyBytes {
		return fmt.Errorf("push subscription %s key is required and bounded", name)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("push subscription %s key contains invalid characters", name)
	}
	return nil
}

func (c *Control) RegisterPushSubscription(input PushSubscriptionInput) (*PushSubscriptionRegistration, error) {
	if !c.pushEnabled() {
		return nil, errors.New("push notifications are not configured")
	}
	endpoint := strings.TrimSpace(input.Endpoint)
	if err := validatePushEndpoint(endpoint); err != nil {
		return nil, err
	}
	if err := validatePushKey("p256dh", input.Keys.P256DH); err != nil {
		return nil, err
	}
	if err := validatePushKey("auth", input.Keys.Auth); err != nil {
		return nil, err
	}
	if len(input.UserAgent) > 512 || strings.ContainsAny(input.UserAgent, "\r\n") {
		return nil, errors.New("push subscription user agent is invalid")
	}
	subscription, err := c.store.UpsertPushSubscription(store.PushSubscription{
		Endpoint: endpoint, P256DH: input.Keys.P256DH, Auth: input.Keys.Auth,
		UserAgent: strings.TrimSpace(input.UserAgent),
	})
	if err != nil {
		return nil, err
	}
	return &PushSubscriptionRegistration{ID: subscription.ID, Endpoint: subscription.Endpoint,
		CreatedAt: subscription.CreatedAt, UpdatedAt: subscription.UpdatedAt}, nil
}

func (c *Control) DeletePushSubscription(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("push subscription id is required")
	}
	return c.store.DeletePushSubscription(id)
}

type pushNotificationPayload struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Priority  string `json:"priority"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	GoalID    string `json:"goal_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

func boundedPushText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// deliverPushNotification encrypts and sends one durable notification to all
// registered browsers. P3 timeline events are deliberately excluded from push.
func (c *Control) deliverPushNotification(ctx context.Context, notification *store.Notification) {
	if notification == nil || !c.pushEnabled() || strings.EqualFold(notification.Priority, "P3") {
		return
	}
	payload, err := json.Marshal(pushNotificationPayload{
		ID: notification.ID, Kind: notification.Kind, Priority: notification.Priority,
		Title: boundedPushText(notification.Title, 200), Body: boundedPushText(notification.Body, 2200),
		GoalID: notification.GoalID, CreatedAt: notification.CreatedAt,
	})
	if err != nil {
		return
	}
	subscriptions, err := c.store.ListPushSubscriptions()
	if err != nil {
		return
	}
	urgency := webpush.UrgencyNormal
	if notification.Priority == "P0" || notification.Priority == "P1" {
		urgency = webpush.UrgencyHigh
	}
	options := &webpush.Options{
		HTTPClient:      safeExternalHTTPClient(),
		Subscriber:      c.config.PushVAPIDSubject,
		VAPIDPublicKey:  c.config.PushVAPIDPublicKey,
		VAPIDPrivateKey: c.config.PushVAPIDPrivateKey,
		TTL:             86400,
		Urgency:         urgency,
		VapidExpiration: time.Now().Add(12 * time.Hour),
	}
	for _, subscription := range subscriptions {
		response, sendErr := webpush.SendNotificationWithContext(ctx, payload, &webpush.Subscription{
			Endpoint: subscription.Endpoint,
			Keys:     webpush.Keys{P256dh: subscription.P256DH, Auth: subscription.Auth},
		}, options)
		if response != nil {
			_ = response.Body.Close()
			if response.StatusCode == 404 || response.StatusCode == 410 {
				_ = c.store.DeletePushSubscription(subscription.ID)
				continue
			}
			if response.StatusCode >= 200 && response.StatusCode < 300 && sendErr == nil {
				_ = c.store.SetPushSubscriptionError(subscription.ID, "")
				continue
			}
			if sendErr == nil {
				sendErr = fmt.Errorf("push service returned %s", response.Status)
			}
		}
		if sendErr != nil {
			message := boundedPushText(sendErr.Error(), maxPushErrorBytes)
			_ = c.store.SetPushSubscriptionError(subscription.ID, message)
		}
	}
}
