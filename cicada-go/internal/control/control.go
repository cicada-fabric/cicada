// Package control implements Cicada's Goal, Monitor, and Native Codex worker
// lifecycle. It deliberately talks to Codex through its stable CLI boundary;
// the app-server adapter can be added behind the same worker interface later.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type Config struct {
	StateDir          string
	WorkspaceRoot     string
	IdentityFile      string
	CodexBinary       string
	WorkerTimeout     time.Duration
	MaxRecoveries     int
	MonitorInterval   time.Duration
	MachineStaleAfter time.Duration
	MonitorStallAfter time.Duration
}

func DefaultConfig() Config {
	timeout := 30 * time.Minute
	if value := os.Getenv("CICADA_WORKER_TIMEOUT_SECONDS"); value != "" {
		if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
			timeout = seconds
		}
	}
	recoveries := 2
	if value := os.Getenv("CICADA_MAX_RECOVERIES"); value != "" {
		var parsed int
		if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil && parsed >= 0 {
			recoveries = parsed
		}
	}
	monitorInterval := 30 * time.Second
	if value := os.Getenv("CICADA_MONITOR_INTERVAL_SECONDS"); value != "" {
		if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
			monitorInterval = seconds
		}
	}
	staleAfter := 2 * time.Minute
	if value := os.Getenv("CICADA_MACHINE_STALE_SECONDS"); value != "" {
		if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
			staleAfter = seconds
		}
	}
	stallAfter := 5 * time.Minute
	if value := os.Getenv("CICADA_MONITOR_STALL_SECONDS"); value != "" {
		if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
			stallAfter = seconds
		}
	}
	return Config{
		StateDir:          envOr("CICADA_STATE_DIR", "/state"),
		WorkspaceRoot:     envOr("CICADA_WORKSPACE_ROOT", "/workspace"),
		IdentityFile:      envOr("CICADA_E2EE_IDENTITY_FILE", ""),
		CodexBinary:       envOr("CICADA_CODEX_BIN", "codex"),
		WorkerTimeout:     timeout,
		MaxRecoveries:     recoveries,
		MonitorInterval:   monitorInterval,
		MachineStaleAfter: staleAfter,
		MonitorStallAfter: stallAfter,
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

type Control struct {
	config          Config
	store           *store.Store
	mu              sync.Mutex
	running         map[string]runningWorker
	identity        *e2ee.Identity
	approvalMu      sync.Mutex
	approvalWaiters map[string]chan string
	shutdown        chan struct{}
	wg              sync.WaitGroup
	closed          bool
}

type runningWorker struct {
	cancel context.CancelFunc
}

var (
	ErrPermissionDenied   = errors.New("permission denied")
	ErrPermissionApproval = errors.New("permission requires approval")
)

func New(config Config) (*Control, error) {
	if err := os.MkdirAll(config.WorkspaceRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	persistence, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		return nil, err
	}
	control := &Control{
		config:          config,
		store:           persistence,
		running:         make(map[string]runningWorker),
		approvalWaiters: make(map[string]chan string),
		shutdown:        make(chan struct{}),
	}
	identityPath := config.IdentityFile
	if identityPath == "" {
		identityPath = filepath.Join(config.StateDir, "e2ee", "identity.json")
	}
	identity, err := loadIdentity(identityPath)
	if err != nil {
		persistence.Close()
		return nil, err
	}
	control.identity = identity
	if err := control.registerLocalMachines(); err != nil {
		persistence.Close()
		return nil, err
	}
	return control, nil
}

func loadIdentity(path string) (*e2ee.Identity, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create E2EE identity directory: %w", err)
	}
	if data, err := os.ReadFile(path); err == nil {
		identity, decodeErr := e2ee.UnmarshalIdentity(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		_ = os.Chmod(path, 0o600)
		return identity, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read E2EE identity: %w", err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	data, err := identity.MarshalBinary()
	if err != nil {
		return nil, err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return nil, fmt.Errorf("write E2EE identity: %w", err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		_ = os.Remove(temporary)
		return nil, err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("install E2EE identity: %w", err)
	}
	return identity, nil
}

func (c *Control) registerLocalMachines() error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "local"
	}
	_, err = c.store.UpsertMachine("control-local", "Control ("+hostname+")", map[string]any{
		"role": "control", "os": "linux", "harnesses": []string{"codex"},
	}, "available")
	if err != nil {
		return err
	}
	_, err = c.store.UpsertMachine("worker-local", "Worker ("+hostname+")", map[string]any{
		"role": "worker", "os": "linux", "harnesses": []string{"codex"},
		"workspace_root": c.config.WorkspaceRoot,
	}, "available")
	return err
}

func (c *Control) Start() error {
	workers, err := c.store.ListInflightWorkers()
	if err != nil {
		return err
	}
	for _, worker := range workers {
		status := "recovering"
		_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
			Status: &status, ClearPID: true,
			LastError: stringPtr("control restarted"),
		})
		_, _ = c.store.AppendEvent(worker.GoalID, worker.ID, "WorkerRecoveryStarted", map[string]any{
			"reason": "control restarted",
		})
		c.launchWorker(worker.ID, "Control restarted; inspect the current workspace and continue.")
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.monitorLoop()
	}()
	return nil
}

func (c *Control) monitorLoop() {
	interval := c.config.MonitorInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.evaluateMonitors()
		case <-c.shutdown:
			return
		}
	}
}

func (c *Control) evaluateMonitors() {
	if c.config.MachineStaleAfter > 0 {
		cutoff := time.Now().UTC().Add(-c.config.MachineStaleAfter).Format(time.RFC3339)
		_, _ = c.store.MarkStaleMachines(cutoff)
	}
	goals, err := c.store.ListGoals()
	if err != nil {
		return
	}
	for _, goal := range goals {
		if goal.Deadline != "" {
			if deadline, parseErr := time.Parse(time.RFC3339, goal.Deadline); parseErr == nil && time.Now().UTC().After(deadline) && goal.Status != "completed" && goal.Status != "failed" && goal.Status != "cancelled" {
				_, _ = c.store.AppendEvent(goal.ID, "", "GoalDeadlineExceeded", map[string]any{"deadline": goal.Deadline})
				c.notify(goal.ID, "goal.deadline", "P0", "Goal deadline exceeded", "The configured deadline has passed; the goal was stopped.")
				_, _ = c.StopGoal(goal.ID)
				continue
			}
		}
		if goal.MonitorID == "" || goal.Status != "running" {
			continue
		}
		worker, workerErr := c.store.GetWorkerForGoal(goal.ID)
		if workerErr != nil || worker == nil || worker.Status != "running" {
			continue
		}
		monitor, monitorErr := c.store.GetMonitor(goal.MonitorID)
		if monitorErr != nil || monitor == nil {
			continue
		}
		lastActivity := monitor.LastEventAt
		if lastActivity == "" {
			lastActivity = worker.StartedAt
		}
		stalledFor := time.Duration(0)
		if parsed, parseErr := time.Parse(time.RFC3339, lastActivity); parseErr == nil {
			stalledFor = time.Since(parsed)
		}
		_, _ = c.store.AppendEvent(goal.ID, worker.ID, "MonitorEvaluated", map[string]any{
			"worker_status": worker.Status, "last_event_at": lastActivity, "stalled_for_seconds": int64(stalledFor.Seconds()),
		})
		if c.config.MonitorStallAfter > 0 && stalledFor >= c.config.MonitorStallAfter && monitor.Status != "correction_pending" && worker.Attempt <= 1 {
			command := "The monitor detected no Codex progress for " + stalledFor.Round(time.Second).String() + ". Inspect the current workspace and thread, diagnose the stall, and continue the goal."
			if _, commandErr := c.store.EnqueueCommand(goal.ID, worker.ID, command); commandErr == nil {
				_, _ = c.store.AppendEvent(goal.ID, worker.ID, "MonitorCorrectionQueued", map[string]any{"reason": "worker stalled", "stalled_for_seconds": int64(stalledFor.Seconds())})
				_ = c.store.TouchMonitor(monitor.ID, "correction_pending")
				c.notify(goal.ID, "monitor.stalled", "P1", "Worker appears stalled", command)
			}
		}
	}
}

func (c *Control) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.shutdown)
	for _, worker := range c.running {
		worker.cancel()
	}
	c.mu.Unlock()

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return c.store.Close()
}

func (c *Control) Machines() ([]store.Machine, error) {
	c.sweepStaleMachines()
	return c.store.ListMachines()
}

func (c *Control) RegisterMachine(id, name string, capabilities map[string]any, status string) (*store.Machine, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" {
		return nil, errors.New("machine id and name are required")
	}
	if status == "" {
		status = "available"
	}
	if !validMachineStatus(status) {
		return nil, fmt.Errorf("unsupported machine status: %s", status)
	}
	return c.store.UpsertMachine(id, name, capabilities, status)
}

func (c *Control) HeartbeatMachine(id, status string, capabilities map[string]any) (*store.Machine, error) {
	machine, err := c.store.GetMachine(id)
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, os.ErrNotExist
	}
	if status == "" {
		status = machine.Status
		if status == "offline" {
			status = "available"
		}
	}
	if !validMachineStatus(status) {
		return nil, fmt.Errorf("unsupported machine status: %s", status)
	}
	if capabilities == nil {
		capabilities = machine.Capabilities
	}
	return c.store.UpsertMachine(machine.ID, machine.Name, capabilities, status)
}

func validMachineStatus(status string) bool {
	switch status {
	case "available", "idle", "busy", "offline", "draining":
		return true
	default:
		return false
	}
}

func (c *Control) sweepStaleMachines() {
	if c.config.MachineStaleAfter <= 0 {
		return
	}
	cutoff := time.Now().UTC().Add(-c.config.MachineStaleAfter).Format(time.RFC3339)
	_, _ = c.store.MarkStaleMachines(cutoff)
}

func (c *Control) Workers() ([]store.Worker, error) { return c.store.ListWorkers() }

func (c *Control) Approvals(pendingOnly bool) ([]store.Approval, error) {
	return c.store.ListApprovals(pendingOnly)
}

func (c *Control) Notifications(unreadOnly bool) ([]store.Notification, error) {
	return c.store.ListNotifications(unreadOnly)
}

func (c *Control) MarkNotificationRead(id string) (*store.Notification, error) {
	notification, err := c.store.MarkNotificationRead(id)
	if err != nil {
		return nil, err
	}
	if notification == nil {
		return nil, os.ErrNotExist
	}
	return notification, nil
}

func (c *Control) notify(goalID, kind, priority, title, body string) {
	_, _ = c.store.CreateNotification(store.Notification{
		GoalID: goalID, Kind: kind, Priority: priority, Title: title, Body: body,
	})
}

func (c *Control) Identity() e2ee.PublicIdentity {
	if c.identity == nil {
		return e2ee.PublicIdentity{}
	}
	return c.identity.Public()
}

func (c *Control) Contacts() ([]store.Contact, error) { return c.store.ListContacts() }

func (c *Control) Contact(id string) (*store.Contact, error) { return c.store.GetContact(id) }

func (c *Control) CreateContact(label string, identity e2ee.PublicIdentity) (*store.Contact, error) {
	if err := e2ee.ValidatePublicIdentity(identity); err != nil {
		return nil, fmt.Errorf("validate contact identity: %w", err)
	}
	return c.store.CreateContact(store.Contact{Label: label, Identity: identity})
}

type PermissionInput struct {
	ID          string `json:"id"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	Effect      string `json:"effect"`
}

func (c *Control) Permissions(subjectType, subjectID string) ([]store.Permission, error) {
	return c.store.ListPermissions(subjectType, subjectID)
}

func (c *Control) SetPermission(input PermissionInput) (*store.Permission, error) {
	input.SubjectType = strings.TrimSpace(input.SubjectType)
	input.SubjectID = strings.TrimSpace(input.SubjectID)
	input.Action = strings.TrimSpace(input.Action)
	input.Resource = strings.TrimSpace(input.Resource)
	input.Effect = strings.TrimSpace(strings.ToLower(input.Effect))
	switch input.SubjectType {
	case "contact", "goal", "workspace", "machine", "global":
	default:
		return nil, fmt.Errorf("unsupported permission subject_type: %s", input.SubjectType)
	}
	if input.SubjectID == "" || input.Action == "" {
		return nil, errors.New("permission subject_id and action are required")
	}
	if input.Effect != "allow" && input.Effect != "approval" && input.Effect != "deny" {
		return nil, fmt.Errorf("unsupported permission effect: %s", input.Effect)
	}
	return c.store.UpsertPermission(store.Permission{
		ID: input.ID, SubjectType: input.SubjectType, SubjectID: input.SubjectID,
		Action: input.Action, Resource: input.Resource, Effect: input.Effect,
	})
}

func (c *Control) Permission(id string) (*store.Permission, error) {
	return c.store.GetPermission(id)
}

func (c *Control) DeletePermission(id string) error {
	deleted, err := c.store.DeletePermission(id)
	if err != nil {
		return err
	}
	if !deleted {
		return os.ErrNotExist
	}
	return nil
}

// CheckPermission resolves the most specific rule. No rule means allow for
// local MVP operations; callers can install a global deny/approval default
// and then add narrow allow rules for trusted workflows.
func (c *Control) CheckPermission(subjectType, subjectID, action, resource string) (string, error) {
	permission, err := c.store.LookupPermission(strings.TrimSpace(subjectType), strings.TrimSpace(subjectID), strings.TrimSpace(action), strings.TrimSpace(resource))
	if err != nil {
		return "", err
	}
	if permission == nil {
		return "allow", nil
	}
	switch permission.Effect {
	case "allow":
		return "allow", nil
	case "approval":
		return "approval", ErrPermissionApproval
	case "deny":
		return "deny", ErrPermissionDenied
	default:
		return "", fmt.Errorf("unsupported stored permission effect: %s", permission.Effect)
	}
}

func (c *Control) PeerMessages(contactID string) ([]store.PeerMessage, error) {
	return c.store.ListPeerMessages(contactID)
}

func (c *Control) SendPeerMessage(contactID, message string, aad []byte) (*store.PeerMessage, error) {
	if c.identity == nil {
		return nil, errors.New("local E2EE identity is unavailable")
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, errors.New("message is required")
	}
	contact, err := c.store.GetContact(contactID)
	if err != nil {
		return nil, err
	}
	if contact == nil {
		return nil, os.ErrNotExist
	}
	if contact.Status != "trusted" {
		return nil, fmt.Errorf("contact is not trusted: %s", contact.Status)
	}
	if _, permissionErr := c.CheckPermission("contact", contactID, "peer.message", ""); permissionErr != nil {
		return nil, permissionErr
	}
	sequence, err := c.store.AllocateContactSequence(contactID)
	if err != nil {
		return nil, err
	}
	envelope, err := e2ee.Seal(c.identity, contact.Identity, []byte(message), aad, sequence)
	if err != nil {
		return nil, err
	}
	local := c.Identity()
	return c.store.CreatePeerMessage(store.PeerMessage{
		ContactID: contactID, Direction: "outbound", SenderID: local.ID,
		RecipientID: contact.Identity.ID, Sequence: sequence, Envelope: envelope, Status: "queued",
	})
}

func (c *Control) ReceivePeerMessage(contactID string, envelope, aad []byte) ([]byte, *store.PeerMessage, error) {
	if c.identity == nil {
		return nil, nil, errors.New("local E2EE identity is unavailable")
	}
	contact, err := c.store.GetContact(contactID)
	if err != nil {
		return nil, nil, err
	}
	if contact == nil {
		return nil, nil, os.ErrNotExist
	}
	if contact.Status != "trusted" {
		return nil, nil, fmt.Errorf("contact is not trusted: %s", contact.Status)
	}
	if _, permissionErr := c.CheckPermission("contact", contactID, "peer.receive", ""); permissionErr != nil {
		return nil, nil, permissionErr
	}
	plaintext, sequence, err := e2ee.Open(c.identity, contact.Identity, envelope, aad)
	if err != nil {
		return nil, nil, err
	}
	if err := c.store.AcceptContactSequence(contactID, sequence); err != nil {
		return nil, nil, err
	}
	local := c.Identity()
	message, err := c.store.CreatePeerMessage(store.PeerMessage{
		ContactID: contactID, Direction: "inbound", SenderID: contact.Identity.ID,
		RecipientID: local.ID, Sequence: sequence, Envelope: envelope, Status: "received",
	})
	if err != nil {
		return nil, nil, err
	}
	c.notify("", "peer.message", "P2", "New peer message", "An encrypted message was received from "+contact.Label+".")
	return plaintext, message, nil
}

func (c *Control) Ideas(status string) ([]store.Idea, error) { return c.store.ListIdeas(status) }

func (c *Control) Idea(id string) (*store.Idea, error) { return c.store.GetIdea(id) }

type IdeaInput struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Source      string `json:"source"`
	Status      string `json:"status"`
	Rationale   string `json:"rationale"`
	RevisitWhen string `json:"revisit_when"`
}

func (c *Control) CreateIdea(input IdeaInput) (*store.Idea, error) {
	if input.Status != "" && !validIdeaStatus(input.Status) {
		return nil, fmt.Errorf("unsupported idea status: %s", input.Status)
	}
	return c.store.CreateIdea(store.Idea{
		Title: input.Title, Description: input.Description, Source: input.Source,
		Status: input.Status, Rationale: input.Rationale, RevisitWhen: input.RevisitWhen,
	})
}

func validIdeaStatus(status string) bool {
	switch status {
	case "inbox", "researching", "parked", "ready", "started", "completed", "archived":
		return true
	default:
		return false
	}
}

func (c *Control) UpdateIdea(id, status, rationale, revisitWhen string) (*store.Idea, error) {
	idea, err := c.store.GetIdea(id)
	if err != nil {
		return nil, err
	}
	if idea == nil {
		return nil, os.ErrNotExist
	}
	if status == "" {
		status = idea.Status
	}
	if !validIdeaStatus(status) {
		return nil, fmt.Errorf("unsupported idea status: %s", status)
	}
	if rationale == "" {
		rationale = idea.Rationale
	}
	if revisitWhen == "" {
		revisitWhen = idea.RevisitWhen
	}
	return c.store.UpdateIdea(id, status, rationale, revisitWhen, idea.GoalID)
}

func (c *Control) ResearchIdea(id string) (*store.Goal, error) {
	idea, err := c.store.GetIdea(id)
	if err != nil {
		return nil, err
	}
	if idea == nil {
		return nil, os.ErrNotExist
	}
	if idea.GoalID != "" && (idea.Status == "researching" || idea.Status == "started") {
		return nil, fmt.Errorf("idea already linked to goal: %s", idea.GoalID)
	}
	goal, err := c.CreateGoal(GoalInput{
		Objective:       "Research this idea and return an evidence-backed recommendation without executing it:\n\n" + idea.Description,
		SuccessCriteria: "Summarize feasibility, relevant evidence, risks, and a clear recommendation.",
		Constraints:     "Research and analysis only. Do not implement code, change external systems, or commit to execution.",
	})
	if err != nil {
		return nil, err
	}
	if _, err := c.store.UpdateIdea(id, "researching", idea.Rationale, idea.RevisitWhen, goal.ID); err != nil {
		return nil, err
	}
	_, _ = c.store.AppendEvent(goal.ID, "", "IdeaResearchStarted", map[string]any{"idea_id": id})
	return goal, nil
}

func (c *Control) PromoteIdea(id string, input GoalInput) (*store.Goal, error) {
	idea, err := c.store.GetIdea(id)
	if err != nil {
		return nil, err
	}
	if idea == nil {
		return nil, os.ErrNotExist
	}
	if idea.Status == "started" || idea.Status == "completed" {
		return nil, fmt.Errorf("idea is already %s", idea.Status)
	}
	if strings.TrimSpace(input.Objective) == "" {
		input.Objective = idea.Description
	}
	if input.SuccessCriteria == "" {
		input.SuccessCriteria = "Decide and explain what evidence demonstrates completion."
	}
	goal, err := c.CreateGoal(input)
	if err != nil {
		return nil, err
	}
	if _, err := c.store.UpdateIdea(id, "started", idea.Rationale, idea.RevisitWhen, goal.ID); err != nil {
		return nil, err
	}
	_, _ = c.store.AppendEvent(goal.ID, "", "IdeaPromoted", map[string]any{"idea_id": id})
	return goal, nil
}

func (c *Control) Workspaces(goalID string) ([]store.Workspace, error) {
	return c.store.ListWorkspaces(goalID)
}

func (c *Control) Workspace(id string) (*store.Workspace, error) { return c.store.GetWorkspace(id) }

type WorkspaceInput struct {
	GoalID   string `json:"goal_id"`
	Path     string `json:"path"`
	Source   string `json:"source"`
	Revision string `json:"revision"`
}

func (c *Control) CreateWorkspace(input WorkspaceInput) (*store.Workspace, error) {
	path, err := c.workspacePath(input.Path)
	if err != nil {
		return nil, err
	}
	if input.GoalID != "" {
		goal, err := c.store.GetGoal(input.GoalID)
		if err != nil {
			return nil, err
		}
		if goal == nil {
			return nil, os.ErrNotExist
		}
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace directory: %w", err)
	}
	return c.store.CreateWorkspace(store.NewID("workspace"), input.GoalID, path, input.Source, input.Revision)
}

func (c *Control) UpdateWorkspace(id, status, revision string) (*store.Workspace, error) {
	workspace, err := c.store.GetWorkspace(id)
	if err != nil {
		return nil, err
	}
	if workspace == nil {
		return nil, os.ErrNotExist
	}
	if status == "" {
		status = workspace.Status
	}
	if revision == "" {
		revision = workspace.Revision
	}
	return c.store.UpdateWorkspace(id, status, revision)
}

func (c *Control) WorkspaceAction(id, action, targetPath string) (*store.Workspace, error) {
	workspace, err := c.store.GetWorkspace(id)
	if err != nil {
		return nil, err
	}
	if workspace == nil {
		return nil, os.ErrNotExist
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "resume":
		if err := os.MkdirAll(workspace.Path, 0o755); err != nil {
			return nil, fmt.Errorf("resume workspace: %w", err)
		}
		return c.store.UpdateWorkspace(id, "active", workspace.Revision)
	case "archive":
		return c.store.UpdateWorkspace(id, "archived", workspace.Revision)
	case "snapshot":
		revision := workspace.Revision
		if value, gitErr := gitRevision(workspace.Path); gitErr == nil && value != "" {
			revision = value
		}
		if revision == "" {
			revision = time.Now().UTC().Format("20060102T150405Z")
		}
		return c.store.UpdateWorkspace(id, "snapshot", revision)
	case "migrate":
		target, err := c.workspacePath(targetPath)
		if err != nil {
			return nil, err
		}
		if target == workspace.Path {
			return nil, errors.New("migration target must differ from current workspace")
		}
		if err := copyWorkspace(workspace.Path, target); err != nil {
			return nil, err
		}
		return c.store.UpdateWorkspaceLocation(id, target, "active", workspace.Revision)
	default:
		return nil, fmt.Errorf("unsupported workspace action: %s", action)
	}
}

func (c *Control) workspacePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("workspace path is required")
	}
	root, err := filepath.Abs(c.config.WorkspaceRoot)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("workspace path must stay inside workspace root")
	}
	return resolved, nil
}

func gitRevision(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func copyWorkspace(source, target string) error {
	if source == "" || target == "" {
		return errors.New("workspace source and target are required")
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("create migration target: %w", err)
	}
	if entries, err := os.ReadDir(target); err != nil {
		return fmt.Errorf("inspect migration target: %w", err)
	} else if len(entries) > 0 {
		return fmt.Errorf("migration target is not empty: %s", target)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read workspace for migration: %w", err)
	}
	for _, entry := range entries {
		if err := copyWorkspaceEntry(filepath.Join(source, entry.Name()), filepath.Join(target, entry.Name()), entry); err != nil {
			return err
		}
	}
	return nil
}

func copyWorkspaceEntry(source, target string, entry os.DirEntry) error {
	info, err := entry.Info()
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
			return err
		}
		children, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := copyWorkspaceEntry(filepath.Join(source, child.Name()), filepath.Join(target, child.Name()), child); err != nil {
				return err
			}
		}
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("workspace migration refuses symlink: %s", source)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func (c *Control) Memories(scope, namespace string) ([]store.Memory, error) {
	return c.store.ListMemories(scope, namespace)
}

func (c *Control) CreateMemory(memory store.Memory) (*store.Memory, error) {
	return c.store.CreateMemory(memory)
}

func (c *Control) Artifacts(goalID string) ([]store.Artifact, error) {
	return c.store.ListArtifacts(goalID)
}

func (c *Control) CreateArtifact(artifact store.Artifact) (*store.Artifact, error) {
	if artifact.GoalID != "" {
		goal, err := c.store.GetGoal(artifact.GoalID)
		if err != nil {
			return nil, err
		}
		if goal == nil {
			return nil, os.ErrNotExist
		}
	}
	return c.store.CreateArtifact(artifact)
}

func (c *Control) ResolveApproval(id, decision string) (*store.Approval, error) {
	switch decision {
	case "approve", "approved", "accept":
		decision = "accept"
	case "approve_for_session", "approved_for_session", "acceptForSession":
		decision = "acceptForSession"
	case "deny", "denied", "decline", "cancel", "abort":
		decision = "decline"
	default:
		return nil, fmt.Errorf("unsupported approval decision: %s", decision)
	}
	approval, err := c.store.GetApproval(id)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, os.ErrNotExist
	}
	if approval.Status == "pending" {
		c.approvalMu.Lock()
		waiter := c.approvalWaiters[id]
		c.approvalMu.Unlock()
		if waiter != nil {
			select {
			case waiter <- decision:
			default:
			}
		}
	}
	return c.store.ResolveApproval(id, decision)
}

func (c *Control) Events(goalID string, after int64) ([]store.Event, error) {
	return c.store.ListEvents(goalID, after, 200)
}

func (c *Control) Goals() ([]store.Goal, error) {
	goals, err := c.store.ListGoals()
	if err != nil {
		return nil, err
	}
	for index := range goals {
		if err := c.decorate(&goals[index]); err != nil {
			return nil, err
		}
	}
	return goals, nil
}

func (c *Control) Goal(id string) (*store.Goal, error) {
	goal, err := c.store.GetGoal(id)
	if err != nil || goal == nil {
		return goal, err
	}
	if err := c.decorate(goal); err != nil {
		return nil, err
	}
	return goal, nil
}

func (c *Control) decorate(goal *store.Goal) error {
	worker, err := c.store.GetWorkerForGoal(goal.ID)
	if err != nil {
		return err
	}
	workers, err := c.store.ListWorkersForGoal(goal.ID)
	if err != nil {
		return err
	}
	events, err := c.store.ListEvents(goal.ID, 0, 20)
	if err != nil {
		return err
	}
	goal.Worker, goal.Workers, goal.Events = worker, workers, events
	if goal.MonitorID != "" {
		monitor, err := c.store.GetMonitor(goal.MonitorID)
		if err != nil {
			return err
		}
		goal.Monitor = monitor
	}
	return nil
}

type GoalInput struct {
	Objective       string         `json:"objective"`
	SuccessCriteria string         `json:"success_criteria"`
	Constraints     string         `json:"constraints"`
	Priority        int            `json:"priority"`
	Deadline        string         `json:"deadline"`
	Budget          map[string]any `json:"budget"`
	Resources       map[string]any `json:"resources"`
	MachineID       string         `json:"machine_id"`
	Harness         string         `json:"harness"`
}

// ThreadMessage is a durable, Control-mediated message between two Native
// Codex threads. The event IDs are used as the message ID so the message and
// its delivery audit trail remain in the same append-only event log.
type ThreadMessage struct {
	ID           int64  `json:"id"`
	FromWorkerID string `json:"from_worker_id"`
	ToWorkerID   string `json:"to_worker_id"`
	FromThreadID string `json:"from_thread_id,omitempty"`
	ToThreadID   string `json:"to_thread_id,omitempty"`
	Message      string `json:"message"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
}

func (c *Control) CreateGoal(input GoalInput) (*store.Goal, error) {
	input.Objective = strings.TrimSpace(input.Objective)
	if input.Objective == "" {
		return nil, errors.New("objective is required")
	}
	if input.Priority == 0 {
		input.Priority = 50
	}
	if input.Priority < 0 {
		input.Priority = 0
	}
	if input.Priority > 100 {
		input.Priority = 100
	}
	if input.Deadline != "" {
		if deadline, err := time.Parse(time.RFC3339, input.Deadline); err != nil || deadline.IsZero() {
			return nil, errors.New("deadline must be an RFC3339 timestamp")
		}
	}
	harness := strings.ToLower(strings.TrimSpace(input.Harness))
	if harness == "" {
		harness = "codex"
	}
	if harness != "codex" {
		return nil, fmt.Errorf("harness %q is not installed; MVP supports codex", harness)
	}
	resources := input.Resources
	if resources == nil {
		resources = map[string]any{}
	}
	if _, exists := resources["required_harness"]; !exists {
		resources["required_harness"] = harness
	}
	machineID, err := c.chooseMachine(input.MachineID, resources)
	if err != nil {
		return nil, err
	}
	goalID, monitorID := store.NewID("goal"), store.NewID("monitor")
	workspace := filepath.Join(c.config.WorkspaceRoot, "goals", goalID)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return nil, fmt.Errorf("create goal workspace: %w", err)
	}
	_, err = c.store.CreateGoalWithDetails(goalID, input.Objective, input.SuccessCriteria, input.Constraints,
		input.Priority, input.Deadline, input.Budget, input.Resources, machineID, monitorID, workspace)
	if err != nil {
		return nil, err
	}
	if _, err := c.store.CreateWorkspace(store.NewID("workspace"), goalID, workspace, "goal", ""); err != nil {
		return nil, err
	}
	if _, err := c.store.CreateMonitor(monitorID, goalID, "supervise"); err != nil {
		return nil, err
	}
	worker, err := c.store.CreateWorkerAtHarness(store.NewID("worker"), goalID, machineID, harness,
		filepath.Join(workspace, ".cicada-last-message"), workspace)
	if err != nil {
		return nil, err
	}
	if _, err := c.store.AppendEvent(goalID, worker.ID, "GoalCreated", map[string]any{
		"objective": input.Objective, "machine_id": machineID, "workspace": workspace,
	}); err != nil {
		return nil, err
	}
	if _, err := c.store.AppendEvent(goalID, worker.ID, "WorkerQueued", map[string]any{"harness": "codex"}); err != nil {
		return nil, err
	}
	c.launchWorker(worker.ID, "")
	return c.Goal(goalID)
}

type WorkerInput struct {
	MachineID string         `json:"machine_id"`
	Resources map[string]any `json:"resources"`
	Harness   string         `json:"harness"`
	Prompt    string         `json:"prompt"`
}

func (c *Control) AddWorker(goalID string, input WorkerInput) (*store.Worker, error) {
	goal, err := c.store.GetGoal(goalID)
	if err != nil {
		return nil, err
	}
	if goal == nil {
		return nil, os.ErrNotExist
	}
	if goal.Status == "completed" || goal.Status == "failed" || goal.Status == "cancelled" {
		return nil, fmt.Errorf("goal is already %s", goal.Status)
	}
	harness := strings.ToLower(strings.TrimSpace(input.Harness))
	if harness == "" {
		harness = "codex"
	}
	if harness != "codex" {
		return nil, fmt.Errorf("harness %q is not installed; MVP supports codex", harness)
	}
	resources := input.Resources
	if resources == nil {
		resources = map[string]any{}
	}
	if _, exists := resources["required_harness"]; !exists {
		resources["required_harness"] = harness
	}
	machineID, err := c.chooseMachine(input.MachineID, resources)
	if err != nil {
		return nil, err
	}
	workerID := store.NewID("worker")
	workspace := filepath.Join(goal.Workspace, "workers", workerID)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return nil, fmt.Errorf("create worker workspace: %w", err)
	}
	if _, err := c.store.CreateWorkspace(store.NewID("workspace"), goalID, workspace, "worker", ""); err != nil {
		return nil, err
	}
	worker, err := c.store.CreateWorkerAtHarness(workerID, goalID, machineID, harness, filepath.Join(workspace, ".cicada-last-message"), workspace)
	if err != nil {
		return nil, err
	}
	if _, err := c.store.AppendEvent(goalID, workerID, "WorkerQueued", map[string]any{
		"harness": worker.Harness, "machine_id": machineID, "workspace": workspace,
	}); err != nil {
		return nil, err
	}
	prompt := strings.TrimSpace(input.Prompt)
	if prompt == "" {
		prompt = c.initialPrompt(*goal)
	}
	c.launchWorker(worker.ID, prompt)
	return c.store.GetWorker(worker.ID)
}

func (c *Control) chooseMachine(requested string, resources map[string]any) (string, error) {
	c.sweepStaleMachines()
	if requested != "" {
		machine, err := c.store.GetMachine(requested)
		if err != nil {
			return "", err
		}
		if machine == nil {
			return "", fmt.Errorf("unknown machine: %s", requested)
		}
		if machine.Status != "available" && machine.Status != "idle" {
			return "", fmt.Errorf("machine is not available: %s", requested)
		}
		if !machineMatches(*machine, resources) {
			return "", fmt.Errorf("machine does not satisfy requested resources: %s", requested)
		}
		return requested, nil
	}
	machines, err := c.store.ListMachines()
	if err != nil {
		return "", err
	}
	for _, machine := range machines {
		if machine.ID == "worker-local" && machine.Status == "available" && machineMatches(machine, resources) {
			return machine.ID, nil
		}
	}
	for _, machine := range machines {
		if machine.Status == "available" && machineMatches(machine, resources) {
			return machine.ID, nil
		}
	}
	return "", errors.New("no available machine")
}

func machineMatches(machine store.Machine, resources map[string]any) bool {
	if len(resources) == 0 {
		return true
	}
	for key, required := range resources {
		switch key {
		case "harness", "required_harness":
			name, ok := required.(string)
			if !ok || !containsString(machine.Capabilities["harnesses"], name) {
				return false
			}
		case "os", "arch", "accelerator":
			if fmt.Sprint(machine.Capabilities[key]) != fmt.Sprint(required) {
				return false
			}
		case "min_memory_gb":
			requiredValue, ok := numberValue(required)
			availableValue, available := numberValue(machine.Capabilities["memory_gb"])
			if !ok || !available || availableValue < requiredValue {
				return false
			}
		default:
			actual, exists := machine.Capabilities[key]
			if !exists || fmt.Sprint(actual) != fmt.Sprint(required) {
				return false
			}
		}
	}
	return true
}

func containsString(value any, wanted string) bool {
	switch values := value.(type) {
	case []string:
		for _, item := range values {
			if item == wanted {
				return true
			}
		}
	case []any:
		for _, item := range values {
			if fmt.Sprint(item) == wanted {
				return true
			}
		}
	case string:
		return values == wanted
	}
	return false
}

func numberValue(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func (c *Control) SendCommand(goalID, command string) (*store.Command, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, errors.New("command is required")
	}
	goal, err := c.store.GetGoal(goalID)
	if err != nil {
		return nil, err
	}
	if goal == nil {
		return nil, os.ErrNotExist
	}
	if goal.Status == "completed" || goal.Status == "failed" || goal.Status == "cancelled" {
		return nil, fmt.Errorf("goal is already %s", goal.Status)
	}
	worker, err := c.store.GetWorkerForGoal(goalID)
	if err != nil {
		return nil, err
	}
	workerID := ""
	if worker != nil {
		workerID = worker.ID
	}
	item, err := c.store.EnqueueCommand(goalID, workerID, command)
	if err != nil {
		return nil, err
	}
	_, err = c.store.AppendEvent(goalID, workerID, "MonitorCommandQueued", map[string]any{"command_id": item.ID})
	if err == nil {
		_ = c.store.TouchMonitor(goal.MonitorID, "active")
	}
	return item, err
}

// SendThreadMessage routes a message between two logical workers. Running
// workers receive it through the normal monitor command queue; a completed
// worker is re-launched on its existing Codex thread so the conversation can
// continue without losing context.
func (c *Control) SendThreadMessage(fromWorkerID, toWorkerID, message string) (*ThreadMessage, error) {
	fromWorkerID = strings.TrimSpace(fromWorkerID)
	toWorkerID = strings.TrimSpace(toWorkerID)
	message = strings.TrimSpace(message)
	if fromWorkerID == "" || toWorkerID == "" || message == "" {
		return nil, errors.New("from_worker_id, to_worker_id, and message are required")
	}
	if fromWorkerID == toWorkerID {
		return nil, errors.New("thread message requires two different workers")
	}
	from, err := c.store.GetWorker(fromWorkerID)
	if err != nil {
		return nil, err
	}
	to, err := c.store.GetWorker(toWorkerID)
	if err != nil {
		return nil, err
	}
	if from == nil || to == nil {
		return nil, os.ErrNotExist
	}
	fromGoal, err := c.store.GetGoal(from.GoalID)
	if err != nil {
		return nil, err
	}
	toGoal, err := c.store.GetGoal(to.GoalID)
	if err != nil {
		return nil, err
	}
	if fromGoal == nil || toGoal == nil {
		return nil, os.ErrNotExist
	}
	payload := map[string]any{
		"from_worker_id": fromWorkerID,
		"to_worker_id":   toWorkerID,
		"from_thread_id": from.ThreadID,
		"to_thread_id":   to.ThreadID,
		"message":        message,
	}
	sent, err := c.store.AppendEvent(from.GoalID, fromWorkerID, "PeerMessageSent", payload)
	if err != nil {
		return nil, err
	}
	receivedPayload := map[string]any{
		"message_id":     sent.ID,
		"from_worker_id": fromWorkerID,
		"from_thread_id": from.ThreadID,
		"message":        message,
	}
	if _, err := c.store.AppendEvent(to.GoalID, toWorkerID, "PeerMessageReceived", receivedPayload); err != nil {
		return nil, err
	}
	_ = c.store.TouchMonitor(toGoal.MonitorID, "active")

	peerPrompt := "A peer Codex thread sent this message. Incorporate it into the current goal and reply with your updated conclusion. Do not use tools for this thread-to-thread exchange unless the message explicitly asks for a tool action.\n\n" + message
	active := false
	c.mu.Lock()
	_, active = c.running[toWorkerID]
	c.mu.Unlock()
	status := "queued"
	if active || to.Status == "running" || to.Status == "recovering" || to.Status == "queued" {
		if _, err := c.store.EnqueueCommand(to.GoalID, toWorkerID, peerPrompt); err != nil {
			return nil, err
		}
		_, _ = c.store.AppendEvent(to.GoalID, toWorkerID, "PeerMessageQueued", map[string]any{"message_id": sent.ID})
		status = "queued"
	} else {
		machine, machineErr := c.store.GetMachine(to.MachineID)
		if machineErr != nil {
			return nil, machineErr
		}
		if machine == nil || (machine.Status != "available" && machine.Status != "idle") {
			return nil, fmt.Errorf("destination machine is not available: %s", to.MachineID)
		}
		queued := "queued"
		if _, err := c.store.UpdateWorker(to.ID, store.WorkerUpdate{Status: &queued, ClearPID: true, LastError: stringPtr("")}); err != nil {
			return nil, err
		}
		if _, err := c.store.UpdateGoal(to.GoalID, queued, toGoal.Summary); err != nil {
			return nil, err
		}
		_, _ = c.store.AppendEvent(to.GoalID, toWorkerID, "PeerMessageDispatched", map[string]any{"message_id": sent.ID})
		c.launchWorker(toWorkerID, peerPrompt)
		status = "dispatched"
	}
	return &ThreadMessage{
		ID: sent.ID, FromWorkerID: fromWorkerID, ToWorkerID: toWorkerID,
		FromThreadID: from.ThreadID, ToThreadID: to.ThreadID,
		Message: message, Status: status, CreatedAt: sent.CreatedAt,
	}, nil
}

func (c *Control) StopGoal(goalID string) (*store.Goal, error) {
	goal, err := c.store.GetGoal(goalID)
	if err != nil || goal == nil {
		return goal, err
	}
	worker, err := c.store.GetWorkerForGoal(goalID)
	if err != nil {
		return nil, err
	}
	if worker != nil {
		c.mu.Lock()
		if active, ok := c.running[worker.ID]; ok {
			active.cancel()
		}
		c.mu.Unlock()
		status := "cancelled"
		_, _ = c.store.UpdateWorker(worker.ID, store.WorkerUpdate{Status: &status, ClearPID: true, EndedAt: stringPtr(storeNow())})
		_, _ = c.store.AppendEvent(goalID, worker.ID, "WorkerCancelled", map[string]any{})
	}
	status := "cancelled"
	if _, err := c.store.UpdateGoal(goalID, status, ""); err != nil {
		return nil, err
	}
	_, _ = c.store.AppendEvent(goalID, "", "GoalCancelled", map[string]any{})
	return c.Goal(goalID)
}

func (c *Control) launchWorker(workerID, recoveryPrompt string) {
	c.mu.Lock()
	if _, exists := c.running[workerID]; exists {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.running[workerID] = runningWorker{cancel: cancel}
	c.wg.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.wg.Done()
		defer func() {
			c.mu.Lock()
			delete(c.running, workerID)
			c.mu.Unlock()
		}()
		c.workerLoop(ctx, workerID, recoveryPrompt)
	}()
}

func (c *Control) workerLoop(ctx context.Context, workerID, recoveryPrompt string) {
	worker, err := c.store.GetWorker(workerID)
	if err != nil || worker == nil {
		return
	}
	machineID := worker.MachineID
	defer func() { _ = c.store.SetMachineStatus(machineID, "available") }()
	goal, err := c.store.GetGoal(worker.GoalID)
	if err != nil || goal == nil {
		return
	}
	attempt := worker.Attempt
	prompt := c.initialPrompt(*goal)
	if recoveryPrompt != "" {
		prompt = recoveryPrompt
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.shutdown:
			return
		default:
		}
		attempt++
		runningStatus := "running"
		_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{
			Status: &runningStatus, Attempt: &attempt, StartedAt: stringPtr(storeNow()), ClearPID: true,
		})
		_ = c.store.SetMachineStatus(machineID, "busy")
		_, _ = c.store.UpdateGoal(goal.ID, "running", goal.Summary)
		_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerStarted", map[string]any{
			"attempt": attempt, "prompt_kind": map[bool]string{true: "recovery", false: "goal"}[recoveryPrompt != ""],
		})
		result := c.runCodex(ctx, *goal, workerID, prompt)
		if result.ThreadID != "" {
			_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{ThreadID: &result.ThreadID})
		}
		worker, _ = c.store.GetWorker(workerID)
		if worker == nil {
			return
		}
		if ctx.Err() != nil || worker.Status == "cancelled" {
			return
		}
		if result.ExitCode == 0 {
			commands, commandErr := c.store.ClaimPendingCommands(goal.ID)
			if commandErr != nil {
				c.finishFailure(goal, workerID, attempt, commandErr.Error())
				return
			}
			if len(commands) > 0 {
				_, _ = c.store.AppendEvent(goal.ID, workerID, "MonitorCommandSent", map[string]any{"count": len(commands)})
				_ = c.store.TouchMonitor(goal.MonitorID, "active")
				parts := make([]string, 0, len(commands))
				for _, command := range commands {
					parts = append(parts, command.Command)
				}
				prompt = "The monitor has provided the following correction. Apply it to the current goal, verify the result, and continue:\n\n" + strings.Join(parts, "\n\n")
				recoveryPrompt = ""
				continue
			}
			summary := readSummary(worker.ResponseFile)
			artifact, artifactErr := c.store.CreateArtifact(store.Artifact{
				GoalID: goal.ID, WorkerID: workerID, Name: "worker-final-message",
				Path: worker.ResponseFile, Kind: "worker-summary", Evidence: summary,
			})
			if artifactErr == nil {
				_, _ = c.store.AppendEvent(goal.ID, workerID, "ArtifactProduced", map[string]any{
					"artifact_id": artifact.ID, "path": artifact.Path, "kind": artifact.Kind,
				})
			}
			completed := "completed"
			_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{Status: &completed, ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: stringPtr("")})
			evidence := []any{}
			if artifact != nil {
				evidence = append(evidence, map[string]any{"artifact_id": artifact.ID, "kind": artifact.Kind, "path": artifact.Path})
			}
			_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerCompleted", map[string]any{"summary": tail(summary, 4000)})
			_, _ = c.store.AppendEvent(goal.ID, workerID, "GoalCompleted", map[string]any{"summary": tail(summary, 4000)})
			// Publish the terminal Goal state last so clients that observe
			// status=completed can also read the completion events and evidence.
			_, _ = c.store.UpdateGoalDetails(goal.ID, completed, summary, "completed", summary, evidence)
			c.notify(goal.ID, "goal.completed", "P2", "Goal completed", summary)
			_ = c.store.SetMachineStatus(worker.MachineID, "available")
			return
		}

		errorText := tail(result.Output, 4000)
		if errorText == "" {
			errorText = fmt.Sprintf("Codex exited with status %d", result.ExitCode)
		}
		recovering := "recovering"
		_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{Status: &recovering, ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &errorText})
		_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerFailed", map[string]any{"return_code": result.ExitCode, "error": errorText})
		if attempt > c.config.MaxRecoveries {
			c.finishFailure(goal, workerID, attempt, errorText)
			return
		}
		_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerRecovered", map[string]any{"attempt": attempt + 1})
		prompt = "The previous worker attempt ended unexpectedly. Inspect the existing workspace and recent output, diagnose the failure, then continue toward the original goal.\n\n" + c.initialPrompt(*goal)
		recoveryPrompt = prompt
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(attempt) * 2 * time.Second):
		}
	}
}

func (c *Control) finishFailure(goal *store.Goal, workerID string, attempt int, message string) {
	failed := "failed"
	_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{Status: &failed, ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: &message})
	_, _ = c.store.UpdateGoal(goal.ID, failed, message)
	_, _ = c.store.AppendEvent(goal.ID, workerID, "GoalBlocked", map[string]any{"attempt": attempt, "reason": message})
	c.notify(goal.ID, "goal.blocked", "P0", "Goal needs attention", message)
	_ = c.store.SetMachineStatus(goal.MachineID, "available")
}

type codexResult struct {
	ExitCode int
	ThreadID string
	Summary  string
	Output   string
}

func (c *Control) runCodex(parent context.Context, goal store.Goal, workerID, prompt string) codexResult {
	result := c.runAppServer(parent, goal, workerID, prompt)
	return codexResult{ExitCode: result.ExitCode, ThreadID: result.ThreadID, Output: result.Output, Summary: result.Summary}
}

func (c *Control) runExecCodex(parent context.Context, goal store.Goal, workerID, prompt string) codexResult {
	worker, err := c.store.GetWorker(workerID)
	if err != nil || worker == nil {
		return codexResult{ExitCode: 1, Output: "worker not found"}
	}
	workspace := goal.Workspace
	if worker.Workspace != "" {
		workspace = worker.Workspace
	}
	args := []string{"exec"}
	if worker.ThreadID != "" {
		args = append(args, "resume", worker.ThreadID, "--skip-git-repo-check")
	} else {
		args = append(args, "--skip-git-repo-check", "-C", goal.Workspace)
	}
	args = append(args, "--json", "--output-last-message", worker.ResponseFile, "-")
	ctx, cancel := context.WithTimeout(parent, c.config.WorkerTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "codex", args...)
	command.Dir = workspace
	command.Env = append(os.Environ(), "CODEX_HOME="+envOr("CODEX_HOME", "/state"))
	stdout, err := command.StdoutPipe()
	if err != nil {
		return codexResult{ExitCode: 1, Output: err.Error()}
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return codexResult{ExitCode: 1, Output: err.Error()}
	}
	command.Stdin = strings.NewReader(prompt)
	if err := command.Start(); err != nil {
		return codexResult{ExitCode: 1, Output: err.Error()}
	}
	pid := command.Process.Pid
	status := "busy"
	_ = c.store.SetMachineStatus(worker.MachineID, status)
	_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{PID: &pid})
	stdoutDone := make(chan []byte, 1)
	stderrDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(stdout)
		stdoutDone <- data
	}()
	go func() {
		data, _ := io.ReadAll(stderr)
		stderrDone <- data
	}()
	waitErr := command.Wait()
	stdoutData, stderrData := <-stdoutDone, <-stderrDone
	output := string(stdoutData) + string(stderrData)
	threadID := worker.ThreadID
	for _, line := range strings.Split(string(stdoutData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		if eventType, _ := event["type"].(string); eventType == "thread.started" {
			threadID, _ = event["thread_id"].(string)
		}
		_, _ = c.store.AppendEvent(goal.ID, workerID, "CodexEvent", event)
	}
	exitCode := 0
	if waitErr != nil {
		exitCode = command.ProcessState.ExitCode()
		if exitCode == -1 {
			exitCode = 124
		}
	}
	if ctx.Err() != nil && exitCode == 0 {
		exitCode = 124
	}
	return codexResult{ExitCode: exitCode, ThreadID: threadID, Output: tail(output, 8000)}
}

func (c *Control) initialPrompt(goal store.Goal) string {
	criteria := goal.SuccessCriteria
	if criteria == "" {
		criteria = "Decide and explain what evidence demonstrates completion."
	}
	constraints := goal.Constraints
	if constraints == "" {
		constraints = "Stay inside the workspace and request approval before irreversible actions."
	}
	return "You are a Cicada Native Codex worker. Work toward this Goal autonomously.\n\n" +
		"OBJECTIVE:\n" + goal.Objective + "\n\n" +
		"SUCCESS CRITERIA:\n" + criteria + "\n\n" +
		"CONSTRAINTS:\n" + constraints + "\n\n" +
		"Inspect the current workspace before acting. Make concrete progress, verify your work, and finish with a concise evidence-backed summary for the monitor. Do not claim completion without evidence."
}

func readSummary(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		return "Codex completed without a saved final message. Inspect Codex events for evidence."
	}
	return strings.TrimSpace(string(data))
}

func tail(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[len(value)-max:]
}

func stringPtr(value string) *string { return &value }

func storeNow() string { return time.Now().UTC().Format(time.RFC3339) }
