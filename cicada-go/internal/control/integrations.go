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
	if !validWebhookSignature(c.webhookSecret(connector), payload, signature) {
		return nil, errors.New("invalid connector signature")
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
		// A concurrent delivery may win the unique connector/external_id key
		// between the lookup above and the insert. Return the durable winner.
		if existing, lookupErr := c.store.GetExternalEventByKey(connector, externalID); lookupErr == nil && existing != nil {
			return existing, nil
		}
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

func (c *Control) webhookSecret(connector string) string {
	if c.config.ConnectorSecrets != nil {
		if secret := strings.TrimSpace(c.config.ConnectorSecrets[strings.ToLower(connector)]); secret != "" {
			return secret
		}
	}
	return c.config.WebhookSecret
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

// TriageExternalEvent records a human or connector classification. Linking an
// event to a Goal is explicit so inbound messages never silently become work.
func (c *Control) TriageExternalEvent(id, status, goalID string) (*store.ExternalEvent, error) {
	id, status, goalID = strings.TrimSpace(id), strings.TrimSpace(status), strings.TrimSpace(goalID)
	if id == "" {
		return nil, errors.New("external event id is required")
	}
	switch status {
	case "classified", "linked", "ignored", "action_required":
	default:
		return nil, fmt.Errorf("unsupported external event triage status: %s", status)
	}
	event, err := c.store.GetExternalEvent(id)
	if err != nil {
		return nil, err
	}
	if event == nil {
		return nil, os.ErrNotExist
	}
	if goalID != "" {
		goal, goalErr := c.store.GetGoal(goalID)
		if goalErr != nil {
			return nil, goalErr
		}
		if goal == nil {
			return nil, os.ErrNotExist
		}
	}
	if status == "linked" && goalID == "" {
		goalID = event.GoalID
		if goalID == "" {
			return nil, errors.New("linked external event requires goal_id")
		}
	}
	if goalID == "" {
		goalID = event.GoalID
	}
	updated, err := c.store.UpdateExternalEventTriage(id, status, goalID)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, os.ErrNotExist
	}
	auditGoal := updated.GoalID
	if auditGoal != "" {
		_, _ = c.store.AppendEvent(auditGoal, "", "ExternalEventTriaged", map[string]any{
			"event_id": updated.ID, "connector": updated.Connector, "status": status,
		})
	}
	if status == "action_required" {
		c.notify(auditGoal, "connector."+updated.Connector, "P1", "External action requires review", updated.EventType)
	}
	return updated, nil
}
