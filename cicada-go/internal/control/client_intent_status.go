package control

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// ClientIntentProgress keeps durable acceptance separate from the result of
// Control's management work. DONE means dispatch finished; the associated
// Intent status records whether it resolved, failed, or needs more input.
type ClientIntentProgress struct {
	Job    *store.ClientIntent `json:"job"`
	Intent *store.Intent       `json:"intent"`
}

func (c *Control) ClientIntentStatus(ownerID, intentID string) (*ClientIntentProgress, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	job, err := c.store.GetClientIntent(strings.TrimSpace(intentID))
	if err != nil {
		return nil, err
	}
	intent, err := c.store.GetIntent(job.IntentID)
	if err != nil {
		return nil, err
	}
	if intent == nil {
		return nil, store.ErrClientIntentNotFound
	}
	return &ClientIntentProgress{Job: job, Intent: intent}, nil
}
