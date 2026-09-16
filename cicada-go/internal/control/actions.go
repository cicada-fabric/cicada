package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// ExternalActionInput describes an external capability request. Credentials,
// cookies, and request headers are deliberately absent; an executor must
// obtain them from its isolated secret boundary after policy approval.
type ExternalActionInput struct {
	GoalID   string          `json:"goal_id"`
	WorkerID string          `json:"worker_id"`
	Kind     string          `json:"kind"`
	Method   string          `json:"method"`
	URL      string          `json:"url"`
	Payload  json.RawMessage `json:"payload"`
}

// RequestExternalAction persists an audited request without performing any
// network operation. Destructive capabilities always require human approval.
func (c *Control) RequestExternalAction(input ExternalActionInput) (*store.ExternalAction, error) {
	goalID := strings.TrimSpace(input.GoalID)
	workerID := strings.TrimSpace(input.WorkerID)
	if goalID == "" || workerID == "" {
		return nil, errors.New("goal_id and worker_id are required")
	}
	goal, err := c.store.GetGoal(goalID)
	if err != nil {
		return nil, err
	}
	if goal == nil {
		return nil, errors.New("goal not found")
	}
	worker, err := c.store.GetWorker(workerID)
	if err != nil {
		return nil, err
	}
	if worker == nil || worker.GoalID != goalID {
		return nil, errors.New("worker does not belong to goal")
	}
	kind, err := normalizeExternalActionKind(input.Kind)
	if err != nil {
		return nil, err
	}
	method, err := normalizeExternalMethod(input.Method)
	if err != nil {
		return nil, err
	}
	target, err := validateExternalURL(input.URL)
	if err != nil {
		return nil, err
	}
	payload, err := validateExternalPayload(input.Payload)
	if err != nil {
		return nil, err
	}
	permissionErr := error(nil)
	_, permissionErr = c.checkExternalPermission(goalID, kind, target.Hostname())
	if errors.Is(permissionErr, ErrPermissionDenied) {
		return nil, permissionErr
	}
	if permissionErr != nil && !errors.Is(permissionErr, ErrPermissionApproval) {
		return nil, permissionErr
	}
	requiresApproval := errors.Is(permissionErr, ErrPermissionApproval) || externalActionIsDestructive(kind, method)
	status := "queued"
	if requiresApproval {
		status = "pending_approval"
	}
	action, err := c.store.CreateExternalAction(store.ExternalAction{
		GoalID: goalID, WorkerID: workerID, Kind: kind, Method: method,
		URL: target.String(), Domain: target.Hostname(), Payload: payload, Status: status,
	})
	if err != nil {
		return nil, err
	}
	if requiresApproval {
		approval, approvalErr := c.store.CreateApproval(store.NewID("approval"), goalID, workerID,
			"external_action", map[string]any{
				"action_id": action.ID, "kind": kind, "method": method,
				"domain": target.Hostname(), "url": target.Redacted(),
			})
		if approvalErr != nil {
			_, _ = c.store.UpdateExternalActionStatus(action.ID, "rejected", "{}", approvalErr.Error())
			return nil, approvalErr
		}
		action, err = c.store.AttachExternalActionApproval(action.ID, approval.ID)
		if err != nil {
			return nil, err
		}
		c.notify(goalID, "external_action.approval", "P1", "External action needs approval",
			fmt.Sprintf("%s on %s", kind, target.Hostname()))
	}
	_, _ = c.store.AppendEvent(goalID, workerID, "ExternalActionRequested", map[string]any{
		"action_id": action.ID, "kind": kind, "method": method,
		"domain": target.Hostname(), "status": action.Status,
	})
	return action, nil
}

func (c *Control) ExternalActions(goalID, status string) ([]store.ExternalAction, error) {
	return c.store.ListExternalActions(strings.TrimSpace(goalID), strings.TrimSpace(status))
}

func (c *Control) ExternalAction(id string) (*store.ExternalAction, error) {
	return c.store.GetExternalAction(strings.TrimSpace(id))
}

// ClaimExternalAction is the narrow handoff to an isolated executor. The
// executor performs its own egress and credential checks; Control only changes
// the durable state after rechecking the current goal policy.
func (c *Control) ClaimExternalAction(id string) (*store.ExternalAction, error) {
	action, err := c.store.GetExternalAction(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if action == nil {
		return nil, errors.New("external action not found")
	}
	if action.Status != "queued" {
		return action, nil
	}
	_, permissionErr := c.checkExternalPermission(action.GoalID, action.Kind, action.Domain)
	if errors.Is(permissionErr, ErrPermissionDenied) {
		_, _ = c.store.UpdateExternalActionStatus(action.ID, "rejected", "{}", permissionErr.Error())
		return nil, permissionErr
	}
	if errors.Is(permissionErr, ErrPermissionApproval) {
		approved := false
		if action.ApprovalID != "" {
			approval, _ := c.store.GetApproval(action.ApprovalID)
			approved = approval != nil && approval.Status == "resolved" &&
				(approval.Decision == "accept" || approval.Decision == "acceptForSession")
		}
		if !approved {
			return nil, permissionErr
		}
	} else if permissionErr != nil {
		return nil, permissionErr
	}
	action, err = c.store.ClaimExternalAction(action.ID)
	if err != nil {
		return nil, err
	}
	if action != nil && action.Status == "running" {
		_, _ = c.store.AppendEvent(action.GoalID, action.WorkerID, "ExternalActionClaimed", map[string]any{"action_id": action.ID})
	}
	return action, nil
}

func (c *Control) CompleteExternalAction(id string, result json.RawMessage, actionError string) (*store.ExternalAction, error) {
	action, err := c.store.GetExternalAction(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if action == nil {
		return nil, errors.New("external action not found")
	}
	if action.Status != "running" {
		return nil, fmt.Errorf("external action is %s", action.Status)
	}
	validated, err := validateExternalPayload(result)
	if err != nil {
		return nil, fmt.Errorf("validate action result: %w", err)
	}
	terminal := "completed"
	if strings.TrimSpace(actionError) != "" {
		terminal = "failed"
	}
	action, err = c.store.CompleteExternalAction(action.ID, terminal, string(validated), strings.TrimSpace(actionError))
	if err != nil {
		return nil, err
	}
	_, _ = c.store.AppendEvent(action.GoalID, action.WorkerID, "ExternalActionCompleted", map[string]any{
		"action_id": action.ID, "status": terminal,
	})
	return action, nil
}

func (c *Control) CancelExternalAction(id string) (*store.ExternalAction, error) {
	action, err := c.store.CancelExternalAction(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if action == nil {
		return nil, errors.New("external action not found")
	}
	if action.Status == "cancelled" {
		_, _ = c.store.AppendEvent(action.GoalID, action.WorkerID, "ExternalActionCancelled", map[string]any{"action_id": action.ID})
	}
	return action, nil
}

func normalizeExternalActionKind(kind string) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "search", "fetch", "browser", "authenticated_browser", "form_fill", "download", "external_api":
		return kind, nil
	default:
		return "", fmt.Errorf("unsupported external action kind: %s", kind)
	}
}

func normalizeExternalMethod(method string) (string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
		return method, nil
	default:
		return "", fmt.Errorf("unsupported external action method: %s", method)
	}
}

func (c *Control) checkExternalPermission(goalID, kind, domain string) (string, error) {
	permission, err := c.store.LookupPermission("goal", goalID, "external."+kind, domain)
	if err != nil {
		return "", err
	}
	if permission == nil {
		// External access is opt-in. A caller may install an allow rule for a
		// domain, but an absent rule still requires a human decision.
		return "approval", ErrPermissionApproval
	}
	return c.CheckPermission("goal", goalID, "external."+kind, domain)
}

func validateExternalURL(raw string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || target == nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" {
		return nil, errors.New("external action url must be an absolute http or https URL")
	}
	if target.Opaque != "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("external action url cannot contain credentials or fragments")
	}
	if sensitiveQuery(target.Query()) {
		return nil, errors.New("external action url cannot contain credential-like query parameters")
	}
	if ip := net.ParseIP(target.Hostname()); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()) {
		return nil, errors.New("external action url cannot target a private or local IP")
	}
	target.Host = strings.ToLower(target.Host)
	return target, nil
}

func validateExternalPayload(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if len(raw) > 1<<20 || !json.Valid(raw) {
		return nil, errors.New("external action data must be valid JSON and at most 1 MiB")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if containsSecretField(value) {
		return nil, errors.New("external action data cannot contain credentials, cookies, or auth material")
	}
	return append(json.RawMessage(nil), raw...), nil
}

func containsSecretField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if strings.Contains(key, "password") || strings.Contains(key, "secret") ||
				strings.Contains(key, "credential") || strings.Contains(key, "cookie") ||
				strings.Contains(key, "authorization") || strings.HasSuffix(key, "_token") || key == "token" || key == "api_key" {
				return true
			}
			if containsSecretField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSecretField(child) {
				return true
			}
		}
	}
	return false
}

func sensitiveQuery(values url.Values) bool {
	for key := range values {
		key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password") || key == "key" || strings.Contains(key, "auth") {
			return true
		}
	}
	return false
}

func externalActionIsDestructive(kind, method string) bool {
	if kind == "authenticated_browser" || kind == "form_fill" || kind == "external_api" {
		return true
	}
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}
