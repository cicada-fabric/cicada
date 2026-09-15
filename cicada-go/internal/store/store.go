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
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
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
	ID              string         `json:"id"`
	Objective       string         `json:"objective"`
	SuccessCriteria string         `json:"success_criteria"`
	Constraints     string         `json:"constraints"`
	Priority        int            `json:"priority"`
	Deadline        string         `json:"deadline,omitempty"`
	Budget          map[string]any `json:"budget,omitempty"`
	Resources       map[string]any `json:"resources,omitempty"`
	CurrentState    string         `json:"current_state,omitempty"`
	Evidence        []any          `json:"evidence,omitempty"`
	Outcome         string         `json:"outcome,omitempty"`
	Status          string         `json:"status"`
	MachineID       string         `json:"machine_id"`
	MonitorID       string         `json:"monitor_id"`
	Workspace       string         `json:"workspace"`
	Summary         string         `json:"summary"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
	Worker          *Worker        `json:"worker,omitempty"`
	Monitor         *Monitor       `json:"monitor,omitempty"`
	Events          []Event        `json:"events,omitempty"`
}

// Idea is an uncommitted intention. It can be researched and parked without
// creating a worker; promotion creates a normal Goal when the user decides to
// execute it.
type Idea struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Source      string `json:"source,omitempty"`
	Status      string `json:"status"`
	Rationale   string `json:"rationale,omitempty"`
	RevisitWhen string `json:"revisit_when,omitempty"`
	GoalID      string `json:"goal_id,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Workspace struct {
	ID        string `json:"id"`
	GoalID    string `json:"goal_id,omitempty"`
	Path      string `json:"path"`
	Source    string `json:"source,omitempty"`
	Revision  string `json:"revision,omitempty"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type Memory struct {
	ID         string `json:"id"`
	Scope      string `json:"scope"`
	Namespace  string `json:"namespace,omitempty"`
	Content    string `json:"content"`
	Source     string `json:"source,omitempty"`
	Importance int    `json:"importance"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type Artifact struct {
	ID          string `json:"id"`
	GoalID      string `json:"goal_id,omitempty"`
	WorkerID    string `json:"worker_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Digest      string `json:"digest,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

type Contact struct {
	ID                string              `json:"id"`
	Label             string              `json:"label"`
	Identity          e2ee.PublicIdentity `json:"identity"`
	Status            string              `json:"status"`
	SendSequence      uint64              `json:"send_sequence"`
	ReceivedSequences []uint64            `json:"-"`
	CreatedAt         string              `json:"created_at"`
	UpdatedAt         string              `json:"updated_at"`
}

// PeerMessage stores the opaque envelope and delivery metadata. Plaintext is
// intentionally absent: the relay/control database must not become a second
// copy of a peer conversation.
type PeerMessage struct {
	ID          string          `json:"id"`
	ContactID   string          `json:"contact_id"`
	Direction   string          `json:"direction"`
	SenderID    string          `json:"sender_id"`
	RecipientID string          `json:"recipient_id"`
	Sequence    uint64          `json:"sequence"`
	Envelope    json.RawMessage `json:"envelope"`
	Status      string          `json:"status"`
	CreatedAt   string          `json:"created_at"`
	DeliveredAt string          `json:"delivered_at,omitempty"`
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
  deadline TEXT,
  budget_json TEXT NOT NULL DEFAULT '{}',
  resources_json TEXT NOT NULL DEFAULT '{}',
  current_state TEXT NOT NULL DEFAULT '',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  outcome TEXT NOT NULL DEFAULT '',
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
CREATE TABLE IF NOT EXISTS ideas (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'inbox',
  rationale TEXT NOT NULL DEFAULT '',
  revisit_when TEXT NOT NULL DEFAULT '',
  goal_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id)
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  goal_id TEXT,
  path TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL DEFAULT '',
  revision TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id)
);
CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  namespace TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  importance INTEGER NOT NULL DEFAULT 50,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  goal_id TEXT,
  worker_id TEXT,
  workspace_id TEXT,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'file',
  digest TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'available',
  created_at TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id),
  FOREIGN KEY(worker_id) REFERENCES workers(id),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);
CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  identity_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'trusted',
  send_sequence INTEGER NOT NULL DEFAULT 0,
  received_sequences_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peer_messages (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  direction TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  FOREIGN KEY(contact_id) REFERENCES contacts(id)
);
CREATE INDEX IF NOT EXISTS events_goal_idx ON events(goal_id, id);
CREATE INDEX IF NOT EXISTS commands_pending_idx ON commands(goal_id, status, id);
CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals(status, created_at);
CREATE INDEX IF NOT EXISTS ideas_status_idx ON ideas(status, updated_at);
CREATE INDEX IF NOT EXISTS memories_scope_idx ON memories(scope, namespace, updated_at);
CREATE INDEX IF NOT EXISTS artifacts_goal_idx ON artifacts(goal_id, created_at);
CREATE INDEX IF NOT EXISTS peer_messages_contact_idx ON peer_messages(contact_id, created_at);
`)
	if err != nil {
		return fmt.Errorf("initialize sqlite schema: %w", err)
	}
	// Databases created by the first MVP do not have the richer Goal columns.
	// Keep initialization backward compatible so an upgrade never discards the
	// durable worker/event history already on disk.
	for _, column := range []struct {
		name string
		ddl  string
	}{
		{"deadline", `ALTER TABLE goals ADD COLUMN deadline TEXT`},
		{"budget_json", `ALTER TABLE goals ADD COLUMN budget_json TEXT NOT NULL DEFAULT '{}'`},
		{"resources_json", `ALTER TABLE goals ADD COLUMN resources_json TEXT NOT NULL DEFAULT '{}'`},
		{"current_state", `ALTER TABLE goals ADD COLUMN current_state TEXT NOT NULL DEFAULT ''`},
		{"evidence_json", `ALTER TABLE goals ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '[]'`},
		{"outcome", `ALTER TABLE goals ADD COLUMN outcome TEXT NOT NULL DEFAULT ''`},
	} {
		if err := s.ensureColumn("goals", column.name, column.ddl); err != nil {
			return err
		}
	}
	// Populate the workspace registry for goals created by the MVP schema.
	// INSERT OR IGNORE makes this safe to run on every startup.
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO workspaces (id, goal_id, path, source, status, created_at, updated_at)
SELECT 'workspace_' || id, id, workspace, 'goal', 'active', created_at, updated_at
FROM goals WHERE workspace <> ''`); err != nil {
		return fmt.Errorf("backfill goal workspaces: %w", err)
	}
	return nil
}

func (s *Store) ensureColumn(table, column, ddl string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, pk int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("read %s schema: %w", table, err)
		}
		if name == column {
			if err := rows.Close(); err != nil {
				return fmt.Errorf("close %s schema: %w", table, err)
			}
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read %s schema: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s schema: %w", table, err)
	}
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
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
	return s.CreateGoalWithDetails(id, objective, successCriteria, constraints, priority, "", nil, nil, machineID, monitorID, workspace)
}

func (s *Store) CreateGoalWithDetails(id, objective, successCriteria, constraints string, priority int, deadline string, budget, resources map[string]any, machineID, monitorID, workspace string) (*Goal, error) {
	if budget == nil {
		budget = map[string]any{}
	}
	if resources == nil {
		resources = map[string]any{}
	}
	budgetJSON, err := json.Marshal(budget)
	if err != nil {
		return nil, fmt.Errorf("encode goal budget: %w", err)
	}
	resourcesJSON, err := json.Marshal(resources)
	if err != nil {
		return nil, fmt.Errorf("encode goal resources: %w", err)
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO goals
(id, objective, success_criteria, constraints, priority, deadline, budget_json, resources_json, status, machine_id, monitor_id, workspace, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)`, id, objective, successCriteria, constraints, priority, nullableString(deadline), string(budgetJSON), string(resourcesJSON), machineID, monitorID, workspace, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create goal: %w", err)
	}
	return s.getGoalLocked(id)
}

func (s *Store) getGoalLocked(id string) (*Goal, error) {
	var goal Goal
	var machineID, summary, deadline, budgetJSON, resourcesJSON, currentState, evidenceJSON, outcome sql.NullString
	err := s.db.QueryRow(`SELECT id, objective, success_criteria, constraints, priority, deadline, budget_json,
resources_json, current_state, evidence_json, outcome, status, machine_id, monitor_id, workspace, summary,
created_at, updated_at FROM goals WHERE id = ?`, id).
		Scan(&goal.ID, &goal.Objective, &goal.SuccessCriteria, &goal.Constraints, &goal.Priority, &deadline, &budgetJSON,
			&resourcesJSON, &currentState, &evidenceJSON, &outcome, &goal.Status, &machineID, &goal.MonitorID,
			&goal.Workspace, &summary, &goal.CreatedAt, &goal.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	goal.MachineID = machineID.String
	goal.Summary = summary.String
	goal.Deadline = deadline.String
	goal.CurrentState = currentState.String
	goal.Outcome = outcome.String
	if budgetJSON.String != "" {
		if err := json.Unmarshal([]byte(budgetJSON.String), &goal.Budget); err != nil {
			return nil, fmt.Errorf("decode goal budget: %w", err)
		}
	}
	if resourcesJSON.String != "" {
		if err := json.Unmarshal([]byte(resourcesJSON.String), &goal.Resources); err != nil {
			return nil, fmt.Errorf("decode goal resources: %w", err)
		}
	}
	if evidenceJSON.String != "" {
		if err := json.Unmarshal([]byte(evidenceJSON.String), &goal.Evidence); err != nil {
			return nil, fmt.Errorf("decode goal evidence: %w", err)
		}
	}
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
	rows, err := s.db.Query(`SELECT id, objective, success_criteria, constraints, priority, deadline, budget_json,
resources_json, current_state, evidence_json, outcome, status, machine_id, monitor_id, workspace, summary,
created_at, updated_at FROM goals ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Goal
	for rows.Next() {
		var goal Goal
		var machineID, summary, deadline, budgetJSON, resourcesJSON, currentState, evidenceJSON, outcome sql.NullString
		if err := rows.Scan(&goal.ID, &goal.Objective, &goal.SuccessCriteria, &goal.Constraints, &goal.Priority, &deadline,
			&budgetJSON, &resourcesJSON, &currentState, &evidenceJSON, &outcome, &goal.Status, &machineID,
			&goal.MonitorID, &goal.Workspace, &summary, &goal.CreatedAt, &goal.UpdatedAt); err != nil {
			return nil, err
		}
		goal.MachineID = machineID.String
		goal.Summary = summary.String
		goal.Deadline = deadline.String
		goal.CurrentState = currentState.String
		goal.Outcome = outcome.String
		if budgetJSON.String != "" {
			if err := json.Unmarshal([]byte(budgetJSON.String), &goal.Budget); err != nil {
				return nil, err
			}
		}
		if resourcesJSON.String != "" {
			if err := json.Unmarshal([]byte(resourcesJSON.String), &goal.Resources); err != nil {
				return nil, err
			}
		}
		if evidenceJSON.String != "" {
			if err := json.Unmarshal([]byte(evidenceJSON.String), &goal.Evidence); err != nil {
				return nil, err
			}
		}
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

func (s *Store) UpdateGoalDetails(id, status, summary, currentState, outcome string, evidence []any) (*Goal, error) {
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("encode goal evidence: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`UPDATE goals SET status = ?, summary = ?, current_state = ?, outcome = ?, evidence_json = ?, updated_at = ? WHERE id = ?`,
		status, summary, currentState, outcome, string(evidenceJSON), now(), id)
	if err != nil {
		return nil, err
	}
	return s.getGoalLocked(id)
}

func (s *Store) CreateWorkspace(id, goalID, path, source, revision string) (*Workspace, error) {
	if path == "" {
		return nil, errors.New("workspace path is required")
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO workspaces (id, goal_id, path, source, revision, status, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`, id, nullableString(goalID), path, source, revision, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	return s.getWorkspaceLocked(id)
}

func (s *Store) getWorkspaceLocked(id string) (*Workspace, error) {
	var workspace Workspace
	var goalID, source, revision sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, path, source, revision, status, created_at, updated_at FROM workspaces WHERE id = ?`, id).
		Scan(&workspace.ID, &goalID, &workspace.Path, &source, &revision, &workspace.Status, &workspace.CreatedAt, &workspace.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	workspace.GoalID, workspace.Source, workspace.Revision = goalID.String, source.String, revision.String
	return &workspace, nil
}

func (s *Store) GetWorkspace(id string) (*Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getWorkspaceLocked(id)
}

func (s *Store) ListWorkspaces(goalID string) ([]Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM workspaces ORDER BY created_at DESC`
	args := []any{}
	if goalID != "" {
		query = `SELECT id FROM workspaces WHERE goal_id = ? ORDER BY created_at DESC`
		args = append(args, goalID)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
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
	var result []Workspace
	for _, id := range ids {
		workspace, err := s.getWorkspaceLocked(id)
		if err != nil {
			return nil, err
		}
		if workspace != nil {
			result = append(result, *workspace)
		}
	}
	return result, rows.Err()
}

func (s *Store) UpdateWorkspace(id, status, revision string) (*Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE workspaces SET status = ?, revision = ?, updated_at = ? WHERE id = ?`, status, revision, now(), id)
	if err != nil {
		return nil, err
	}
	return s.getWorkspaceLocked(id)
}

func (s *Store) CreateIdea(idea Idea) (*Idea, error) {
	idea.ID = strings.TrimSpace(idea.ID)
	if idea.ID == "" {
		idea.ID = NewID("idea")
	}
	idea.Title = strings.TrimSpace(idea.Title)
	idea.Description = strings.TrimSpace(idea.Description)
	if idea.Title == "" || idea.Description == "" {
		return nil, errors.New("idea title and description are required")
	}
	if idea.Status == "" {
		idea.Status = "inbox"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO ideas (id, title, description, source, status, rationale, revisit_when, goal_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, idea.ID, idea.Title, idea.Description, idea.Source, idea.Status, idea.Rationale, idea.RevisitWhen, nullableString(idea.GoalID), timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create idea: %w", err)
	}
	return s.getIdeaLocked(idea.ID)
}

func (s *Store) getIdeaLocked(id string) (*Idea, error) {
	var idea Idea
	var source, rationale, revisitWhen, goalID sql.NullString
	err := s.db.QueryRow(`SELECT id, title, description, source, status, rationale, revisit_when, goal_id, created_at, updated_at FROM ideas WHERE id = ?`, id).
		Scan(&idea.ID, &idea.Title, &idea.Description, &source, &idea.Status, &rationale, &revisitWhen, &goalID, &idea.CreatedAt, &idea.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	idea.Source, idea.Rationale, idea.RevisitWhen, idea.GoalID = source.String, rationale.String, revisitWhen.String, goalID.String
	return &idea, nil
}

func (s *Store) GetIdea(id string) (*Idea, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getIdeaLocked(id)
}

func (s *Store) ListIdeas(status string) ([]Idea, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM ideas ORDER BY updated_at DESC`
	args := []any{}
	if status != "" {
		query = `SELECT id FROM ideas WHERE status = ? ORDER BY updated_at DESC`
		args = append(args, status)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
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
	var result []Idea
	for _, id := range ids {
		idea, err := s.getIdeaLocked(id)
		if err != nil {
			return nil, err
		}
		if idea != nil {
			result = append(result, *idea)
		}
	}
	return result, rows.Err()
}

func (s *Store) UpdateIdea(id string, status, rationale, revisitWhen, goalID string) (*Idea, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE ideas SET status = ?, rationale = ?, revisit_when = ?, goal_id = ?, updated_at = ? WHERE id = ?`,
		status, rationale, revisitWhen, nullableString(goalID), now(), id)
	if err != nil {
		return nil, err
	}
	return s.getIdeaLocked(id)
}

func (s *Store) CreateMemory(memory Memory) (*Memory, error) {
	memory.ID = strings.TrimSpace(memory.ID)
	if memory.ID == "" {
		memory.ID = NewID("memory")
	}
	memory.Scope = strings.TrimSpace(memory.Scope)
	memory.Content = strings.TrimSpace(memory.Content)
	if memory.Scope == "" || memory.Content == "" {
		return nil, errors.New("memory scope and content are required")
	}
	if memory.Importance <= 0 {
		memory.Importance = 50
	}
	if memory.Importance > 100 {
		memory.Importance = 100
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO memories (id, scope, namespace, content, source, importance, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, memory.ID, memory.Scope, memory.Namespace, memory.Content, memory.Source, memory.Importance, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create memory: %w", err)
	}
	return s.getMemoryLocked(memory.ID)
}

func (s *Store) getMemoryLocked(id string) (*Memory, error) {
	var memory Memory
	var namespace, source sql.NullString
	err := s.db.QueryRow(`SELECT id, scope, namespace, content, source, importance, created_at, updated_at FROM memories WHERE id = ?`, id).
		Scan(&memory.ID, &memory.Scope, &namespace, &memory.Content, &source, &memory.Importance, &memory.CreatedAt, &memory.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	memory.Namespace, memory.Source = namespace.String, source.String
	return &memory, nil
}

func (s *Store) ListMemories(scope, namespace string) ([]Memory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM memories ORDER BY importance DESC, updated_at DESC`
	args := []any{}
	if scope != "" && namespace != "" {
		query = `SELECT id FROM memories WHERE scope = ? AND namespace = ? ORDER BY importance DESC, updated_at DESC`
		args = append(args, scope, namespace)
	} else if scope != "" {
		query = `SELECT id FROM memories WHERE scope = ? ORDER BY importance DESC, updated_at DESC`
		args = append(args, scope)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
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
	var result []Memory
	for _, id := range ids {
		memory, err := s.getMemoryLocked(id)
		if err != nil {
			return nil, err
		}
		if memory != nil {
			result = append(result, *memory)
		}
	}
	return result, rows.Err()
}

func (s *Store) CreateArtifact(artifact Artifact) (*Artifact, error) {
	artifact.ID = strings.TrimSpace(artifact.ID)
	if artifact.ID == "" {
		artifact.ID = NewID("artifact")
	}
	artifact.Name = strings.TrimSpace(artifact.Name)
	artifact.Path = strings.TrimSpace(artifact.Path)
	if artifact.Name == "" || artifact.Path == "" {
		return nil, errors.New("artifact name and path are required")
	}
	if artifact.Kind == "" {
		artifact.Kind = "file"
	}
	if artifact.Status == "" {
		artifact.Status = "available"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO artifacts (id, goal_id, worker_id, workspace_id, name, path, kind, digest, evidence, status, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, artifact.ID, nullableString(artifact.GoalID), nullableString(artifact.WorkerID), nullableString(artifact.WorkspaceID), artifact.Name, artifact.Path, artifact.Kind, artifact.Digest, artifact.Evidence, artifact.Status, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create artifact: %w", err)
	}
	return s.getArtifactLocked(artifact.ID)
}

func (s *Store) getArtifactLocked(id string) (*Artifact, error) {
	var artifact Artifact
	var goalID, workerID, workspaceID, digest, evidence sql.NullString
	err := s.db.QueryRow(`SELECT id, goal_id, worker_id, workspace_id, name, path, kind, digest, evidence, status, created_at FROM artifacts WHERE id = ?`, id).
		Scan(&artifact.ID, &goalID, &workerID, &workspaceID, &artifact.Name, &artifact.Path, &artifact.Kind, &digest, &evidence, &artifact.Status, &artifact.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	artifact.GoalID, artifact.WorkerID, artifact.WorkspaceID = goalID.String, workerID.String, workspaceID.String
	artifact.Digest, artifact.Evidence = digest.String, evidence.String
	return &artifact, nil
}

func (s *Store) ListArtifacts(goalID string) ([]Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM artifacts ORDER BY created_at DESC`
	args := []any{}
	if goalID != "" {
		query = `SELECT id FROM artifacts WHERE goal_id = ? ORDER BY created_at DESC`
		args = append(args, goalID)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
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
	var result []Artifact
	for _, id := range ids {
		artifact, err := s.getArtifactLocked(id)
		if err != nil {
			return nil, err
		}
		if artifact != nil {
			result = append(result, *artifact)
		}
	}
	return result, rows.Err()
}

var ErrPeerReplay = errors.New("peer message sequence already received")

func (s *Store) CreateContact(contact Contact) (*Contact, error) {
	contact.ID = strings.TrimSpace(contact.ID)
	if contact.ID == "" {
		contact.ID = NewID("contact")
	}
	contact.Label = strings.TrimSpace(contact.Label)
	if contact.Label == "" {
		contact.Label = contact.Identity.ID
	}
	if contact.Identity.ID == "" {
		return nil, errors.New("contact identity is required")
	}
	if contact.Status == "" {
		contact.Status = "trusted"
	}
	identityJSON, err := json.Marshal(contact.Identity)
	if err != nil {
		return nil, fmt.Errorf("encode contact identity: %w", err)
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO contacts (id, label, identity_json, status, send_sequence, received_sequences_json, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, '[]', ?, ?)`, contact.ID, contact.Label, string(identityJSON), contact.Status, contact.SendSequence, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create contact: %w", err)
	}
	return s.getContactLocked(contact.ID)
}

func (s *Store) getContactLocked(id string) (*Contact, error) {
	var contact Contact
	var identityJSON, receivedJSON string
	err := s.db.QueryRow(`SELECT id, label, identity_json, status, send_sequence, received_sequences_json, created_at, updated_at FROM contacts WHERE id = ?`, id).
		Scan(&contact.ID, &contact.Label, &identityJSON, &contact.Status, &contact.SendSequence, &receivedJSON, &contact.CreatedAt, &contact.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(identityJSON), &contact.Identity); err != nil {
		return nil, fmt.Errorf("decode contact identity: %w", err)
	}
	if receivedJSON != "" {
		if err := json.Unmarshal([]byte(receivedJSON), &contact.ReceivedSequences); err != nil {
			return nil, fmt.Errorf("decode contact replay state: %w", err)
		}
	}
	return &contact, nil
}

func (s *Store) GetContact(id string) (*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getContactLocked(id)
}

func (s *Store) ListContacts() ([]Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM contacts ORDER BY created_at`)
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
	result := make([]Contact, 0, len(ids))
	for _, id := range ids {
		contact, err := s.getContactLocked(id)
		if err != nil {
			return nil, err
		}
		if contact != nil {
			result = append(result, *contact)
		}
	}
	return result, nil
}

// AllocateContactSequence atomically returns the next outbound sequence.
func (s *Store) AllocateContactSequence(id string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE contacts SET send_sequence = send_sequence + 1, updated_at = ? WHERE id = ?`, now(), id)
	if err != nil {
		return 0, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if changed == 0 {
		return 0, os.ErrNotExist
	}
	var sequence uint64
	if err := s.db.QueryRow(`SELECT send_sequence FROM contacts WHERE id = ?`, id).Scan(&sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

// AcceptContactSequence persists replay protection across Control restarts.
func (s *Store) AcceptContactSequence(id string, sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	contact, err := s.getContactLocked(id)
	if err != nil {
		return err
	}
	if contact == nil {
		return os.ErrNotExist
	}
	for _, seen := range contact.ReceivedSequences {
		if seen == sequence {
			return ErrPeerReplay
		}
	}
	if len(contact.ReceivedSequences) >= 4096 {
		contact.ReceivedSequences = contact.ReceivedSequences[1:]
	}
	contact.ReceivedSequences = append(contact.ReceivedSequences, sequence)
	receivedJSON, err := json.Marshal(contact.ReceivedSequences)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE contacts SET received_sequences_json = ?, updated_at = ? WHERE id = ?`, string(receivedJSON), now(), id)
	return err
}

func (s *Store) CreatePeerMessage(message PeerMessage) (*PeerMessage, error) {
	message.ID = strings.TrimSpace(message.ID)
	if message.ID == "" {
		message.ID = NewID("peer_message")
	}
	message.ContactID = strings.TrimSpace(message.ContactID)
	message.Direction = strings.TrimSpace(message.Direction)
	if message.ContactID == "" || message.Direction == "" || len(message.Envelope) == 0 {
		return nil, errors.New("peer message contact, direction, and envelope are required")
	}
	if message.Status == "" {
		message.Status = "queued"
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO peer_messages (id, contact_id, direction, sender_id, recipient_id, sequence, envelope_json, status, created_at, delivered_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, message.ID, message.ContactID, message.Direction, message.SenderID, message.RecipientID, message.Sequence, string(message.Envelope), message.Status, timestamp, nullableString(message.DeliveredAt))
	if err != nil {
		return nil, fmt.Errorf("create peer message: %w", err)
	}
	return s.getPeerMessageLocked(message.ID)
}

func (s *Store) getPeerMessageLocked(id string) (*PeerMessage, error) {
	var message PeerMessage
	var envelope, deliveredAt sql.NullString
	err := s.db.QueryRow(`SELECT id, contact_id, direction, sender_id, recipient_id, sequence, envelope_json, status, created_at, delivered_at FROM peer_messages WHERE id = ?`, id).
		Scan(&message.ID, &message.ContactID, &message.Direction, &message.SenderID, &message.RecipientID, &message.Sequence, &envelope, &message.Status, &message.CreatedAt, &deliveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	message.Envelope = json.RawMessage(envelope.String)
	message.DeliveredAt = deliveredAt.String
	return &message, nil
}

func (s *Store) ListPeerMessages(contactID string) ([]PeerMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT id FROM peer_messages ORDER BY created_at`
	args := []any{}
	if contactID != "" {
		query = `SELECT id FROM peer_messages WHERE contact_id = ? ORDER BY created_at`
		args = append(args, contactID)
	}
	rows, err := s.db.Query(query, args...)
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
	result := make([]PeerMessage, 0, len(ids))
	for _, id := range ids {
		message, err := s.getPeerMessageLocked(id)
		if err != nil {
			return nil, err
		}
		if message != nil {
			result = append(result, *message)
		}
	}
	return result, nil
}

func (s *Store) MarkPeerMessageDelivered(id string) (*PeerMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE peer_messages SET status = 'delivered', delivered_at = ? WHERE id = ?`, now(), id)
	if err != nil {
		return nil, err
	}
	return s.getPeerMessageLocked(id)
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
