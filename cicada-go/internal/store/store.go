// Package store persists Cicada's control-plane objects in SQLite.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Machine struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Status       string         `json:"status"`
	Capabilities map[string]any `json:"capabilities"`
	LastSeen     string         `json:"last_seen"`
	CreatedAt    string         `json:"created_at"`
}

type Goal struct {
	ID              string   `json:"id"`
	Objective       string   `json:"objective"`
	SuccessCriteria string   `json:"success_criteria"`
	Constraints     string   `json:"constraints"`
	Priority        int      `json:"priority"`
	Status          string   `json:"status"`
	MachineID       string   `json:"machine_id"`
	MonitorID       string   `json:"monitor_id"`
	Workspace       string   `json:"workspace"`
	Summary         string   `json:"summary"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
	Worker          *Worker  `json:"worker,omitempty"`
	Monitor         *Monitor `json:"monitor,omitempty"`
	Events          []Event  `json:"events,omitempty"`
}

// Monitor is the durable supervisor binding for a Goal. The MVP monitor is
// deliberately small: it records whether supervision is active and when the
// last event or correction was observed. More advanced policies can be added
// without changing the Goal/Worker relationship.
type Monitor struct {
	ID          string `json:"id"`
	GoalID      string `json:"goal_id"`
	Status      string `json:"status"`
	Policy      string `json:"policy"`
	LastEventAt string `json:"last_event_at,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Worker struct {
	ID           string `json:"id"`
	GoalID       string `json:"goal_id"`
	MachineID    string `json:"machine_id"`
	Harness      string `json:"harness"`
	Status       string `json:"status"`
	PID          *int   `json:"pid,omitempty"`
	ThreadID     string `json:"thread_id,omitempty"`
	Attempt      int    `json:"attempt"`
	StartedAt    string `json:"started_at,omitempty"`
	EndedAt      string `json:"ended_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	ResponseFile string `json:"response_file"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type Event struct {
	ID        int64           `json:"id"`
	GoalID    string          `json:"goal_id"`
	WorkerID  string          `json:"worker_id,omitempty"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt string          `json:"created_at"`
}

type Command struct {
	ID         int64  `json:"id"`
	GoalID     string `json:"goal_id"`
	WorkerID   string `json:"worker_id,omitempty"`
	Command    string `json:"command"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	ConsumedAt string `json:"consumed_at,omitempty"`
}

type Approval struct {
	ID         string          `json:"id"`
	GoalID     string          `json:"goal_id"`
	WorkerID   string          `json:"worker_id"`
	Method     string          `json:"method"`
	Request    json.RawMessage `json:"request"`
	Status     string          `json:"status"`
	Decision   string          `json:"decision,omitempty"`
	CreatedAt  string          `json:"created_at"`
	ResolvedAt string          `json:"resolved_at,omitempty"`
}

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initialize() error {
	_, err := s.db.Exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS machines (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  last_seen TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY,
  objective TEXT NOT NULL,
  success_criteria TEXT NOT NULL DEFAULT '',
  constraints TEXT NOT NULL DEFAULT '',
  priority INTEGER NOT NULL DEFAULT 50,
  status TEXT NOT NULL,
  machine_id TEXT,
  monitor_id TEXT NOT NULL,
  workspace TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(machine_id) REFERENCES machines(id)
);
CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  policy TEXT NOT NULL DEFAULT 'supervise',
  last_event_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id)
);
CREATE TABLE IF NOT EXISTS workers (
  id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL,
  machine_id TEXT NOT NULL,
  harness TEXT NOT NULL,
  status TEXT NOT NULL,
  pid INTEGER,
  thread_id TEXT,
  attempt INTEGER NOT NULL DEFAULT 0,
  started_at TEXT,
  ended_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  response_file TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(machine_id) REFERENCES machines(id)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  goal_id TEXT NOT NULL,
  worker_id TEXT,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(worker_id) REFERENCES workers(id)
);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  goal_id TEXT NOT NULL,
  worker_id TEXT,
  command TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  consumed_at TEXT,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(worker_id) REFERENCES workers(id)
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  method TEXT NOT NULL,
  request_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  decision TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(worker_id) REFERENCES workers(id)
);
CREATE INDEX IF NOT EXISTS events_goal_idx ON events(goal_id, id);
CREATE INDEX IF NOT EXISTS commands_pending_idx ON commands(goal_id, status, id);
CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals(status, created_at);
`)
	if err != nil {
		return fmt.Errorf("initialize sqlite schema: %w", err)
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func NewID(prefix string) string {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(bytes[:])
}

func (s *Store) UpsertMachine(id, name string, capabilities map[string]any, status string) (*Machine, error) {
	if capabilities == nil {
		capabilities = map[string]any{}
	}
	capabilitiesJSON, err := json.Marshal(capabilities)
	if err != nil {
		return nil, fmt.Errorf("encode machine capabilities: %w", err)
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`
INSERT INTO machines (id, name, status, capabilities_json, last_seen, created_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, status=excluded.status,
  capabilities_json=excluded.capabilities_json, last_seen=excluded.last_seen
`, id, name, status, string(capabilitiesJSON), timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("upsert machine: %w", err)
	}
	return s.getMachineLocked(id)
}

func (s *Store) getMachineLocked(id string) (*Machine, error) {
	var machine Machine
	var capabilitiesJSON string
	err := s.db.QueryRow(`SELECT id, name, status, capabilities_json, last_seen, created_at FROM machines WHERE id = ?`, id).
		Scan(&machine.ID, &machine.Name, &machine.Status, &capabilitiesJSON, &machine.LastSeen, &machine.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(capabilitiesJSON), &machine.Capabilities); err != nil {
		return nil, fmt.Errorf("decode machine capabilities: %w", err)
	}
	return &machine, nil
}

func (s *Store) GetMachine(id string) (*Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getMachineLocked(id)
}

func (s *Store) ListMachines() ([]Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, name, status, capabilities_json, last_seen, created_at FROM machines ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Machine
	for rows.Next() {
		var machine Machine
		var capabilitiesJSON string
		if err := rows.Scan(&machine.ID, &machine.Name, &machine.Status, &capabilitiesJSON, &machine.LastSeen, &machine.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(capabilitiesJSON), &machine.Capabilities); err != nil {
			return nil, err
		}
		result = append(result, machine)
	}
	return result, rows.Err()
}

func (s *Store) SetMachineStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE machines SET status = ?, last_seen = ? WHERE id = ?`, status, now(), id)
	return err
}

func (s *Store) CreateGoal(id, objective, successCriteria, constraints string, priority int, machineID, monitorID, workspace string) (*Goal, error) {
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO goals
(id, objective, success_criteria, constraints, priority, status, machine_id, monitor_id, workspace, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)`, id, objective, successCriteria, constraints, priority, machineID, monitorID, workspace, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create goal: %w", err)
	}
	return s.getGoalLocked(id)
}

func (s *Store) getGoalLocked(id string) (*Goal, error) {
	var goal Goal
	var machineID, summary sql.NullString
	err := s.db.QueryRow(`SELECT id, objective, success_criteria, constraints, priority, status,
machine_id, monitor_id, workspace, summary, created_at, updated_at FROM goals WHERE id = ?`, id).
		Scan(&goal.ID, &goal.Objective, &goal.SuccessCriteria, &goal.Constraints, &goal.Priority, &goal.Status,
			&machineID, &goal.MonitorID, &goal.Workspace, &summary, &goal.CreatedAt, &goal.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	goal.MachineID = machineID.String
	goal.Summary = summary.String
	return &goal, nil
}

func (s *Store) GetGoal(id string) (*Goal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getGoalLocked(id)
}

func (s *Store) ListGoals() ([]Goal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, objective, success_criteria, constraints, priority, status,
machine_id, monitor_id, workspace, summary, created_at, updated_at FROM goals ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Goal
	for rows.Next() {
		var goal Goal
		var machineID, summary sql.NullString
		if err := rows.Scan(&goal.ID, &goal.Objective, &goal.SuccessCriteria, &goal.Constraints, &goal.Priority, &goal.Status,
			&machineID, &goal.MonitorID, &goal.Workspace, &summary, &goal.CreatedAt, &goal.UpdatedAt); err != nil {
			return nil, err
		}
		goal.MachineID = machineID.String
		goal.Summary = summary.String
		result = append(result, goal)
	}
	return result, rows.Err()
}

func (s *Store) UpdateGoal(id, status, summary string) (*Goal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE goals SET status = ?, summary = ?, updated_at = ? WHERE id = ?`, status, summary, now(), id)
	if err != nil {
		return nil, err
	}
	return s.getGoalLocked(id)
}

func (s *Store) CreateMonitor(id, goalID, policy string) (*Monitor, error) {
	if policy == "" {
		policy = "supervise"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO monitors (id, goal_id, status, policy, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?)`, id, goalID, policy, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create monitor: %w", err)
	}
	return s.getMonitorLocked(id)
}

func (s *Store) getMonitorLocked(id string) (*Monitor, error) {
	var monitor Monitor
	var lastEventAt sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, status, policy, last_event_at, created_at, updated_at FROM monitors WHERE id = ?`, id).
		Scan(&monitor.ID, &monitor.GoalID, &monitor.Status, &monitor.Policy, &lastEventAt, &monitor.CreatedAt, &monitor.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	monitor.LastEventAt = lastEventAt.String
	return &monitor, nil
}

func (s *Store) GetMonitor(id string) (*Monitor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getMonitorLocked(id)
}

func (s *Store) TouchMonitor(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == "" {
		status = "active"
	}
	_, err := s.db.Exec(`UPDATE monitors SET status = ?, last_event_at = ?, updated_at = ? WHERE id = ?`, status, now(), now(), id)
	return err
}

func (s *Store) CreateWorker(id, goalID, machineID, responseFile string) (*Worker, error) {
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO workers
(id, goal_id, machine_id, harness, status, response_file, created_at, updated_at)
VALUES (?, ?, ?, 'codex', 'queued', ?, ?, ?)`, id, goalID, machineID, responseFile, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create worker: %w", err)
	}
	return s.getWorkerLocked(id)
}

func (s *Store) getWorkerLocked(id string) (*Worker, error) {
	var worker Worker
	var pid sql.NullInt64
	var threadID, startedAt, endedAt, lastError sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, machine_id, harness, status, pid, thread_id, attempt,
started_at, ended_at, last_error, response_file, created_at, updated_at FROM workers WHERE id = ?`, id).
		Scan(&worker.ID, &worker.GoalID, &worker.MachineID, &worker.Harness, &worker.Status, &pid, &threadID, &worker.Attempt,
			&startedAt, &endedAt, &lastError, &worker.ResponseFile, &worker.CreatedAt, &worker.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if pid.Valid {
		value := int(pid.Int64)
		worker.PID = &value
	}
	worker.ThreadID, worker.StartedAt, worker.EndedAt, worker.LastError = threadID.String, startedAt.String, endedAt.String, lastError.String
	return &worker, nil
}

func (s *Store) GetWorker(id string) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getWorkerLocked(id)
}

func (s *Store) GetWorkerForGoal(goalID string) (*Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err := s.db.QueryRow(`SELECT id FROM workers WHERE goal_id = ? ORDER BY created_at DESC LIMIT 1`, goalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.getWorkerLocked(id)
}

func (s *Store) ListWorkers() ([]Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM workers ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var result []Worker
	for _, id := range ids {
		worker, err := s.getWorkerLocked(id)
		if err != nil {
			return nil, err
		}
		if worker != nil {
			result = append(result, *worker)
		}
	}
	return result, nil
}

func (s *Store) ListInflightWorkers() ([]Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM workers WHERE status IN ('queued', 'running', 'recovering') ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var result []Worker
	for _, id := range ids {
		worker, err := s.getWorkerLocked(id)
		if err != nil {
			return nil, err
		}
		if worker != nil {
			result = append(result, *worker)
		}
	}
	return result, nil
}

type WorkerUpdate struct {
	Status    *string
	PID       *int
	ClearPID  bool
	ThreadID  *string
	Attempt   *int
	StartedAt *string
	EndedAt   *string
	LastError *string
}

func (s *Store) UpdateWorker(id string, update WorkerUpdate) (*Worker, error) {
	assignments := []string{"updated_at = ?"}
	args := []any{now()}
	if update.Status != nil {
		assignments = append(assignments, "status = ?")
		args = append(args, *update.Status)
	}
	if update.ClearPID {
		assignments = append(assignments, "pid = NULL")
	} else if update.PID != nil {
		assignments = append(assignments, "pid = ?")
		args = append(args, *update.PID)
	}
	if update.ThreadID != nil {
		assignments = append(assignments, "thread_id = ?")
		args = append(args, *update.ThreadID)
	}
	if update.Attempt != nil {
		assignments = append(assignments, "attempt = ?")
		args = append(args, *update.Attempt)
	}
	if update.StartedAt != nil {
		assignments = append(assignments, "started_at = ?")
		args = append(args, *update.StartedAt)
	}
	if update.EndedAt != nil {
		assignments = append(assignments, "ended_at = ?")
		args = append(args, *update.EndedAt)
	}
	if update.LastError != nil {
		assignments = append(assignments, "last_error = ?")
		args = append(args, *update.LastError)
	}
	args = append(args, id)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE workers SET "+join(assignments, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return nil, err
	}
	return s.getWorkerLocked(id)
}

func join(values []string, separator string) string {
	result := ""
	for i, value := range values {
		if i > 0 {
			result += separator
		}
		result += value
	}
	return result
}

func (s *Store) AppendEvent(goalID, workerID, eventType string, payload any) (*Event, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(payloadJSON) == 0 {
		payloadJSON = []byte(`{}`)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`INSERT INTO events (goal_id, worker_id, type, payload_json, created_at) VALUES (?, ?, ?, ?, ?)`, goalID, nullableString(workerID), eventType, string(payloadJSON), now())
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.getEventLocked(id)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *Store) getEventLocked(id int64) (*Event, error) {
	var event Event
	var workerID, payload string
	err := s.db.QueryRow(`SELECT id, goal_id, worker_id, type, payload_json, created_at FROM events WHERE id = ?`, id).
		Scan(&event.ID, &event.GoalID, &workerID, &event.Type, &payload, &event.CreatedAt)
	if err != nil {
		return nil, err
	}
	event.WorkerID = workerID
	event.Payload = json.RawMessage(payload)
	return &event, nil
}

func (s *Store) ListEvents(goalID string, after int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, goal_id, worker_id, type, payload_json, created_at FROM events WHERE goal_id = ? AND id > ? ORDER BY id LIMIT ?`, goalID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Event
	for rows.Next() {
		var event Event
		var workerID, payload string
		if err := rows.Scan(&event.ID, &event.GoalID, &workerID, &event.Type, &payload, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.WorkerID = workerID
		event.Payload = json.RawMessage(payload)
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) EnqueueCommand(goalID, workerID, command string) (*Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`INSERT INTO commands (goal_id, worker_id, command, created_at) VALUES (?, ?, ?, ?)`, goalID, nullableString(workerID), command, now())
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.getCommandLocked(id)
}

func (s *Store) getCommandLocked(id int64) (*Command, error) {
	var command Command
	var workerID, consumedAt sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, worker_id, command, status, created_at, consumed_at FROM commands WHERE id = ?`, id).
		Scan(&command.ID, &command.GoalID, &workerID, &command.Command, &command.Status, &command.CreatedAt, &consumedAt)
	if err != nil {
		return nil, err
	}
	command.WorkerID, command.ConsumedAt = workerID.String, consumedAt.String
	return &command, nil
}

func (s *Store) ClaimPendingCommands(goalID string) ([]Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timestamp := now()
	rows, err := s.db.Query(`SELECT id FROM commands WHERE goal_id = ? AND status = 'pending' ORDER BY id`, goalID)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := s.db.Exec(`UPDATE commands SET status = 'consumed', consumed_at = ? WHERE id = ?`, timestamp, id); err != nil {
			return nil, err
		}
	}
	result := make([]Command, 0, len(ids))
	for _, id := range ids {
		command, err := s.getCommandLocked(id)
		if err != nil {
			return nil, err
		}
		result = append(result, *command)
	}
	return result, nil
}

func (s *Store) CreateApproval(id, goalID, workerID, method string, request any) (*Approval, error) {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO approvals (id, goal_id, worker_id, method, request_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`, id, goalID, workerID, method, string(requestJSON), now())
	if err != nil {
		return nil, err
	}
	return s.getApprovalLocked(id)
}

func (s *Store) getApprovalLocked(id string) (*Approval, error) {
	var approval Approval
	var request, decision, resolvedAt sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, worker_id, method, request_json, status, decision, created_at, resolved_at FROM approvals WHERE id = ?`, id).
		Scan(&approval.ID, &approval.GoalID, &approval.WorkerID, &approval.Method, &request, &approval.Status, &decision, &approval.CreatedAt, &resolvedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	approval.Request = json.RawMessage(request.String)
	approval.Decision, approval.ResolvedAt = decision.String, resolvedAt.String
	return &approval, nil
}

func (s *Store) GetApproval(id string) (*Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getApprovalLocked(id)
}

func (s *Store) ListApprovals(pendingOnly bool) ([]Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM approvals ORDER BY created_at DESC`
	if pendingOnly {
		query = `SELECT id FROM approvals WHERE status = 'pending' ORDER BY created_at`
	}
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var result []Approval
	for _, id := range ids {
		approval, err := s.getApprovalLocked(id)
		if err != nil {
			return nil, err
		}
		if approval != nil {
			result = append(result, *approval)
		}
	}
	return result, nil
}

func (s *Store) ResolveApproval(id, decision string) (*Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE approvals SET status = 'resolved', decision = ?, resolved_at = ? WHERE id = ? AND status = 'pending'`, decision, now(), id)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		return s.getApprovalLocked(id)
	}
	return s.getApprovalLocked(id)
}
