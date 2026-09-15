package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// IngestExternalEvent accepts signed connector webhooks. The body is stored
// before routing so a transient downstream failure never loses an event.
func (c *Control) IngestExternalEvent(connector, externalID, eventType, signature string, payload []byte, goalID string) (*store.ExternalEvent, error) {
	connector = strings.TrimSpace(connector)
	externalID = strings.TrimSpace(externalID)
	eventType = strings.TrimSpace(eventType)
	if connector == "" || externalID == "" || eventType == "" {
		return nil, errors.New("connector, event id, and event type are required")
	}
	if len(payload) == 0 || len(payload) > 1<<20 || !json.Valid(payload) {
		return nil, errors.New("payload must be valid JSON and at most 1 MiB")
	}
	if goalID != "" {
		goal, err := c.store.GetGoal(goalID)
		if err != nil {
			return nil, err
		}
		if goal == nil {
			return nil, os.ErrNotExist
		}
	}
	if !validWebhookSignature(c.config.WebhookSecret, payload, signature) {
		return nil, errors.New("invalid connector signature")
	}
	if existing, err := c.store.GetExternalEventByKey(connector, externalID); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	event, err := c.store.CreateExternalEvent(store.ExternalEvent{
		Connector: connector, ExternalID: externalID, EventType: eventType,
		Payload: json.RawMessage(payload), Signature: signature, GoalID: goalID,
	})
	if err != nil {
		return nil, err
	}
	if goalID != "" {
		_, _ = c.store.AppendEvent(goalID, "", "ExternalEventReceived", map[string]any{
			"connector": connector, "external_id": externalID, "event_type": eventType,
		})
	} else {
		c.notify("", "connector."+connector, "P1", "External connector event", fmt.Sprintf("%s: %s", connector, eventType))
	}
	return event, nil
}

func validWebhookSignature(secret string, payload []byte, presented string) bool {
	secret = strings.TrimSpace(secret)
	presented = strings.TrimSpace(presented)
	if secret == "" || presented == "" {
		return false
	}
	presented = strings.TrimPrefix(presented, "sha256=")
	decoded, err := hex.DecodeString(presented)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hmac.Equal(decoded, mac.Sum(nil))
}

func (c *Control) ExternalEvents(connector string) ([]store.ExternalEvent, error) {
	return c.store.ListExternalEvents(strings.TrimSpace(connector))
}

func (c *Control) ExternalEvent(id string) (*store.ExternalEvent, error) {
	return c.store.GetExternalEvent(id)
}
