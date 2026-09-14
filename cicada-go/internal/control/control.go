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

	"github.com/cicada-ai/cicada/internal/store"
)

type Config struct {
	StateDir      string
	WorkspaceRoot string
	CodexBinary   string
	WorkerTimeout time.Duration
	MaxRecoveries int
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
	return Config{
		StateDir:      envOr("CICADA_STATE_DIR", "/state"),
		WorkspaceRoot: envOr("CICADA_WORKSPACE_ROOT", "/workspace"),
		CodexBinary:   envOr("CICADA_CODEX_BIN", "codex"),
		WorkerTimeout: timeout,
		MaxRecoveries: recoveries,
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
	approvalMu      sync.Mutex
	approvalWaiters map[string]chan string
	shutdown        chan struct{}
	wg              sync.WaitGroup
	closed          bool
}

type runningWorker struct {
	cancel context.CancelFunc
}

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
	if err := control.registerLocalMachines(); err != nil {
		persistence.Close()
		return nil, err
	}
	return control, nil
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
	return nil
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

func (c *Control) Machines() ([]store.Machine, error) { return c.store.ListMachines() }

func (c *Control) RegisterMachine(id, name string, capabilities map[string]any, status string) (*store.Machine, error) {
	if status == "" {
		status = "available"
	}
	return c.store.UpsertMachine(id, name, capabilities, status)
}

func (c *Control) Workers() ([]store.Worker, error) { return c.store.ListWorkers() }

func (c *Control) Approvals(pendingOnly bool) ([]store.Approval, error) {
	return c.store.ListApprovals(pendingOnly)
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
	events, err := c.store.ListEvents(goal.ID, 0, 20)
	if err != nil {
		return err
	}
	goal.Worker, goal.Events = worker, events
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
	Objective       string `json:"objective"`
	SuccessCriteria string `json:"success_criteria"`
	Constraints     string `json:"constraints"`
	Priority        int    `json:"priority"`
	MachineID       string `json:"machine_id"`
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
	machineID, err := c.chooseMachine(input.MachineID)
	if err != nil {
		return nil, err
	}
	goalID, monitorID := store.NewID("goal"), store.NewID("monitor")
	workspace := filepath.Join(c.config.WorkspaceRoot, "goals", goalID)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return nil, fmt.Errorf("create goal workspace: %w", err)
	}
	_, err = c.store.CreateGoal(goalID, input.Objective, input.SuccessCriteria, input.Constraints,
		input.Priority, machineID, monitorID, workspace)
	if err != nil {
		return nil, err
	}
	if _, err := c.store.CreateMonitor(monitorID, goalID, "supervise"); err != nil {
		return nil, err
	}
	worker, err := c.store.CreateWorker(store.NewID("worker"), goalID, machineID,
		filepath.Join(workspace, ".cicada-last-message"))
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

func (c *Control) chooseMachine(requested string) (string, error) {
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
		return requested, nil
	}
	machines, err := c.store.ListMachines()
	if err != nil {
		return "", err
	}
	for _, machine := range machines {
		if machine.ID == "worker-local" && machine.Status == "available" {
			return machine.ID, nil
		}
	}
	for _, machine := range machines {
		if machine.Status == "available" {
			return machine.ID, nil
		}
	}
	return "", errors.New("no available machine")
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
				parts := make([]string, 0, len(commands))
				for _, command := range commands {
					parts = append(parts, command.Command)
				}
				prompt = "The monitor has provided the following correction. Apply it to the current goal, verify the result, and continue:\n\n" + strings.Join(parts, "\n\n")
				recoveryPrompt = ""
				continue
			}
			summary := readSummary(worker.ResponseFile)
			completed := "completed"
			_, _ = c.store.UpdateWorker(workerID, store.WorkerUpdate{Status: &completed, ClearPID: true, EndedAt: stringPtr(storeNow()), LastError: stringPtr("")})
			_, _ = c.store.UpdateGoal(goal.ID, completed, summary)
			_, _ = c.store.AppendEvent(goal.ID, workerID, "WorkerCompleted", map[string]any{"summary": tail(summary, 4000)})
			_, _ = c.store.AppendEvent(goal.ID, workerID, "GoalCompleted", map[string]any{"summary": tail(summary, 4000)})
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
	command.Dir = goal.Workspace
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
