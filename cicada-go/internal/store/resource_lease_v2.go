package store

// Resource Lease is one authority per physical conflict key, independent of
// Group. Only managed_blob writes are executor-fenced here; GPU/workspace
// leases remain explicitly advisory until their real executors enforce them.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	ResourceAvailable     = "AVAILABLE"
	ResourceActive        = "ACTIVE"
	ResourceQuarantined   = "RECONCILIATION_REQUIRED"
	LeaseActive           = "ACTIVE"
	LeaseReleased         = "RELEASED"
	LeaseUncertain        = "RECONCILIATION_REQUIRED"
	LeaseAdvisory         = "advisory"
	LeaseExecutorEnforced = "executor_enforced"
)

var (
	ErrResourceInvalid        = errors.New("resource identity is invalid")
	ErrResourceBusy           = errors.New("resource is held or needs reconciliation")
	ErrResourceLeaseNotFound  = errors.New("resource lease not found")
	ErrResourceStaleEpoch     = errors.New("resource fencing epoch is stale")
	ErrResourceLeaseExpired   = errors.New("resource lease has expired")
	ErrResourceReconciliation = errors.New("resource stop confirmation and evidence are required")
)

type ResourceLease struct {
	ID                string `json:"lease_id"`
	ResourceID        string `json:"resource_id"`
	HolderGroupID     string `json:"scope_group_id"`
	HolderTaskID      string `json:"holder_task_id"`
	HolderPrincipalID string `json:"holder_principal_id"`
	FencingEpoch      int64  `json:"fencing_epoch"`
	Mode              string `json:"mode"`
	Enforcement       string `json:"enforcement"`
	State             string `json:"state"`
	ExpiresAt         string `json:"expires_at"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type ResourceLeaseRequest struct {
	ResourceID  string `json:"resource_id"`
	GroupID     string `json:"group_id"`
	TaskID      string `json:"task_id"`
	PrincipalID string `json:"principal_id"`
	TTLSeconds  int    `json:"ttl_seconds"`
}

func (s *Store) initializeResourceLeaseV2Schema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS resource_v2_authority (
 resource_id TEXT PRIMARY KEY, fencing_epoch INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL, current_lease_id TEXT NOT NULL DEFAULT '',
 reconciliation_evidence TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_v2_leases (
 id TEXT PRIMARY KEY, resource_id TEXT NOT NULL, holder_group_id TEXT NOT NULL,
 holder_task_id TEXT NOT NULL, holder_principal_id TEXT NOT NULL,
 fencing_epoch INTEGER NOT NULL, mode TEXT NOT NULL, enforcement TEXT NOT NULL,
 state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(resource_id) REFERENCES resource_v2_authority(resource_id),
 UNIQUE(resource_id,fencing_epoch)
);
CREATE INDEX IF NOT EXISTS resource_v2_leases_holder_idx ON resource_v2_leases(holder_group_id,holder_task_id,state);
CREATE TABLE IF NOT EXISTS resource_v2_managed_blobs (
 resource_id TEXT PRIMARY KEY, value BLOB NOT NULL, digest TEXT NOT NULL,
 writer_lease_id TEXT NOT NULL, writer_epoch INTEGER NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(resource_id) REFERENCES resource_v2_authority(resource_id)
);`)
	return err
}

func validResourceToken(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func resourceEnforcement(resourceID string) (string, error) {
	parts := strings.Split(resourceID, "/")
	switch {
	case len(parts) == 4 && parts[0] == "machine" && parts[2] == "gpu" && validResourceToken(parts[1]):
		index, err := strconv.Atoi(parts[3])
		if err != nil || index < 0 {
			return "", ErrResourceInvalid
		}
		return LeaseAdvisory, nil
	case len(parts) == 3 && parts[0] == "workspace" && parts[2] == "write" && validResourceToken(parts[1]):
		return LeaseAdvisory, nil
	case len(parts) == 3 && parts[0] == "managed_blob" && parts[2] == "write" && validResourceToken(parts[1]):
		return LeaseExecutorEnforced, nil
	default:
		return "", ErrResourceInvalid
	}
}

const resourceLeaseColumns = `id,resource_id,holder_group_id,holder_task_id,holder_principal_id,fencing_epoch,mode,enforcement,state,expires_at,created_at,updated_at`

func scanResourceLease(row interface{ Scan(...any) error }) (*ResourceLease, error) {
	var lease ResourceLease
	err := row.Scan(&lease.ID, &lease.ResourceID, &lease.HolderGroupID, &lease.HolderTaskID, &lease.HolderPrincipalID, &lease.FencingEpoch,
		&lease.Mode, &lease.Enforcement, &lease.State, &lease.ExpiresAt, &lease.CreatedAt, &lease.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrResourceLeaseNotFound
	}
	if err != nil {
		return nil, err
	}
	return &lease, nil
}

func (s *Store) GetResourceLease(id string) (*ResourceLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return scanResourceLease(s.db.QueryRow(`SELECT `+resourceLeaseColumns+` FROM resource_v2_leases WHERE id=?`, id))
}

func (s *Store) AcquireResourceLease(input ResourceLeaseRequest) (*ResourceLease, error) {
	enforcement, err := resourceEnforcement(input.ResourceID)
	if err != nil {
		return nil, err
	}
	if input.GroupID == "" || input.TaskID == "" || input.PrincipalID == "" {
		return nil, ErrResourceInvalid
	}
	if input.TTLSeconds <= 0 {
		input.TTLSeconds = 300
	}
	if input.TTLSeconds > 3600 {
		input.TTLSeconds = 3600
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Acquire a serialized SQLite writer before inspecting the shared authority.
	if _, err = tx.Exec(`INSERT OR IGNORE INTO resource_v2_authority(resource_id,fencing_epoch,state,updated_at) VALUES(?,0,?,?)`, input.ResourceID, ResourceAvailable, now()); err != nil {
		return nil, err
	}
	var epoch int64
	var state, currentID string
	if err = tx.QueryRow(`SELECT fencing_epoch,state,current_lease_id FROM resource_v2_authority WHERE resource_id=?`, input.ResourceID).Scan(&epoch, &state, &currentID); err != nil {
		return nil, err
	}
	if state == ResourceActive && currentID != "" {
		current, err := scanResourceLease(tx.QueryRow(`SELECT `+resourceLeaseColumns+` FROM resource_v2_leases WHERE id=?`, currentID))
		if err != nil {
			return nil, err
		}
		if !resourceLeaseCurrent(current) {
			_, err = tx.Exec(`UPDATE resource_v2_authority SET state=?,updated_at=? WHERE resource_id=? AND fencing_epoch=?`, ResourceQuarantined, now(), input.ResourceID, epoch)
			if err != nil {
				return nil, err
			}
			_, err = tx.Exec(`UPDATE resource_v2_leases SET state=?,updated_at=? WHERE id=?`, LeaseUncertain, now(), currentID)
			if err != nil {
				return nil, err
			}
			if err = tx.Commit(); err != nil {
				return nil, err
			}
			return nil, ErrResourceBusy
		}
	}
	if state != ResourceAvailable {
		return nil, ErrResourceBusy
	}
	task, err := loadSharedTaskTx(tx, input.TaskID)
	if err != nil {
		return nil, err
	}
	if task.GroupID != input.GroupID || task.OwnerPrincipalID != input.PrincipalID ||
		(task.Status != SharedTaskClaimed && task.Status != SharedTaskRunning) || !sharedTaskLeaseActive(task.LeaseExpiresAt) {
		return nil, ErrSharedTaskStaleOwner
	}
	lease := &ResourceLease{ID: NewID("lease"), ResourceID: input.ResourceID, HolderGroupID: input.GroupID, HolderTaskID: input.TaskID,
		HolderPrincipalID: input.PrincipalID, FencingEpoch: epoch + 1, Mode: "exclusive", Enforcement: enforcement, State: LeaseActive,
		ExpiresAt: time.Now().UTC().Add(time.Duration(input.TTLSeconds) * time.Second).Format(time.RFC3339Nano), CreatedAt: now(), UpdatedAt: now()}
	if _, err = tx.Exec(`INSERT INTO resource_v2_leases (`+resourceLeaseColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		lease.ID, lease.ResourceID, lease.HolderGroupID, lease.HolderTaskID, lease.HolderPrincipalID, lease.FencingEpoch, lease.Mode,
		lease.Enforcement, lease.State, lease.ExpiresAt, lease.CreatedAt, lease.UpdatedAt); err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE resource_v2_authority SET fencing_epoch=?,state=?,current_lease_id=?,reconciliation_evidence='',updated_at=?
 WHERE resource_id=? AND fencing_epoch=? AND state=?`, lease.FencingEpoch, ResourceActive, lease.ID, now(), lease.ResourceID, epoch, ResourceAvailable)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrResourceBusy
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return lease, nil
}

func resourceLeaseCurrent(lease *ResourceLease) bool {
	deadline, err := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	return err == nil && lease.State == LeaseActive && time.Now().UTC().Before(deadline)
}

func resourceLeaseActorTx(tx *sql.Tx, scope *NativeActorScope,
	lease *ResourceLease, action string) error {
	if scope == nil {
		return nil // Explicit trusted-local Store primitive.
	}
	if lease.HolderGroupID != scope.GroupID || lease.HolderPrincipalID != scope.PrincipalID {
		return ErrNetworkPermission
	}
	return guardNativeActorTx(tx, *scope, action, time.Now().UTC())
}

func (s *Store) RenewResourceLease(id string, epoch int64, principalID string, ttlSeconds int) (*ResourceLease, error) {
	return s.renewResourceLease(id, epoch, principalID, ttlSeconds, nil)
}

func (s *Store) RenewResourceLeaseForActor(scope NativeActorScope,
	id string, epoch int64, ttlSeconds int) (*ResourceLease, error) {
	return s.renewResourceLease(id, epoch, scope.PrincipalID, ttlSeconds, &scope)
}

func (s *Store) renewResourceLease(id string, epoch int64, principalID string,
	ttlSeconds int, scope *NativeActorScope) (*ResourceLease, error) {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	if ttlSeconds > 3600 {
		ttlSeconds = 3600
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE resource_v2_authority SET updated_at=updated_at WHERE resource_id=(SELECT resource_id FROM resource_v2_leases WHERE id=?)`, id); err != nil {
		return nil, err
	}
	lease, err := scanResourceLease(tx.QueryRow(`SELECT `+resourceLeaseColumns+` FROM resource_v2_leases WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if err := resourceLeaseActorTx(tx, scope, lease, "task.claim"); err != nil {
		return nil, err
	}
	if lease.FencingEpoch != epoch || lease.HolderPrincipalID != principalID {
		return nil, ErrResourceStaleEpoch
	}
	if !resourceLeaseCurrent(lease) {
		return nil, ErrResourceLeaseExpired
	}
	var current string
	var state string
	if err = tx.QueryRow(`SELECT current_lease_id,state FROM resource_v2_authority WHERE resource_id=?`, lease.ResourceID).Scan(&current, &state); err != nil {
		return nil, err
	}
	if current != id || state != ResourceActive {
		return nil, ErrResourceStaleEpoch
	}
	lease.ExpiresAt = time.Now().UTC().Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339Nano)
	lease.UpdatedAt = now()
	if _, err = tx.Exec(`UPDATE resource_v2_leases SET expires_at=?,updated_at=? WHERE id=? AND fencing_epoch=? AND state=?`, lease.ExpiresAt, lease.UpdatedAt, id, epoch, LeaseActive); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return lease, nil
}

// QuarantineResourceLease deliberately does not release a live/expired
// physical resource. A separate stop confirmation reconciles it.
func (s *Store) QuarantineResourceLease(id string, epoch int64, principalID string) (*ResourceLease, error) {
	return s.quarantineResourceLease(id, epoch, principalID, nil)
}

func (s *Store) QuarantineResourceLeaseForActor(scope NativeActorScope,
	id string, epoch int64) (*ResourceLease, error) {
	return s.quarantineResourceLease(id, epoch, scope.PrincipalID, &scope)
}

func (s *Store) quarantineResourceLease(id string, epoch int64, principalID string,
	scope *NativeActorScope) (*ResourceLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE resource_v2_authority SET updated_at=updated_at WHERE resource_id=(SELECT resource_id FROM resource_v2_leases WHERE id=?)`, id); err != nil {
		return nil, err
	}
	lease, err := scanResourceLease(tx.QueryRow(`SELECT `+resourceLeaseColumns+` FROM resource_v2_leases WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if err := resourceLeaseActorTx(tx, scope, lease, "task.claim"); err != nil {
		return nil, err
	}
	if lease.FencingEpoch != epoch || lease.HolderPrincipalID != principalID {
		return nil, ErrResourceStaleEpoch
	}
	var current string
	if err = tx.QueryRow(`SELECT current_lease_id FROM resource_v2_authority WHERE resource_id=?`, lease.ResourceID).Scan(&current); err != nil {
		return nil, err
	}
	if current != id {
		return nil, ErrResourceStaleEpoch
	}
	if _, err = tx.Exec(`UPDATE resource_v2_authority SET state=?,updated_at=? WHERE resource_id=?`, ResourceQuarantined, now(), lease.ResourceID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE resource_v2_leases SET state=?,updated_at=? WHERE id=?`, LeaseUncertain, now(), id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	lease.State = LeaseUncertain
	return lease, nil
}

func (s *Store) ReconcileResourceLease(resourceID string, expectedEpoch int64, stoppedConfirmed bool, evidence string) error {
	if !stoppedConfirmed || strings.TrimSpace(evidence) == "" {
		return ErrResourceReconciliation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE resource_v2_authority SET state=?,current_lease_id='',reconciliation_evidence=?,updated_at=?
 WHERE resource_id=? AND fencing_epoch=? AND state=?`, ResourceAvailable, evidence, now(), resourceID, expectedEpoch, ResourceQuarantined)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return ErrResourceStaleEpoch
	}
	if _, err = tx.Exec(`UPDATE resource_v2_leases SET state=?,updated_at=? WHERE resource_id=? AND fencing_epoch=?`, LeaseReleased, now(), resourceID, expectedEpoch); err != nil {
		return err
	}
	return tx.Commit()
}

// WriteManagedBlob is an actual bounded executor operation: the lease and
// fencing epoch are checked in the same SQLite transaction as the write.
// It says nothing about arbitrary filesystem or shell actions.
func (s *Store) WriteManagedBlob(id string, epoch int64, principalID string, body []byte) (string, error) {
	return s.writeManagedBlob(id, epoch, principalID, body, nil)
}

func (s *Store) WriteManagedBlobForActor(scope NativeActorScope,
	id string, epoch int64, body []byte) (string, error) {
	return s.writeManagedBlob(id, epoch, scope.PrincipalID, body, &scope)
}

func (s *Store) writeManagedBlob(id string, epoch int64, principalID string,
	body []byte, scope *NativeActorScope) (string, error) {
	if len(body) > 16<<20 {
		return "", errors.New("managed blob exceeds 16 MiB")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE resource_v2_authority SET updated_at=updated_at WHERE resource_id=(SELECT resource_id FROM resource_v2_leases WHERE id=?)`, id); err != nil {
		return "", err
	}
	lease, err := scanResourceLease(tx.QueryRow(`SELECT `+resourceLeaseColumns+` FROM resource_v2_leases WHERE id=?`, id))
	if err != nil {
		return "", err
	}
	if err := resourceLeaseActorTx(tx, scope, lease, "resource.execute"); err != nil {
		return "", err
	}
	if lease.FencingEpoch != epoch || lease.HolderPrincipalID != principalID || lease.Enforcement != LeaseExecutorEnforced || !strings.HasPrefix(lease.ResourceID, "managed_blob/") {
		return "", ErrResourceStaleEpoch
	}
	if !resourceLeaseCurrent(lease) {
		return "", ErrResourceLeaseExpired
	}
	var authorityEpoch int64
	var state, current string
	if err = tx.QueryRow(`SELECT fencing_epoch,state,current_lease_id FROM resource_v2_authority WHERE resource_id=?`, lease.ResourceID).Scan(&authorityEpoch, &state, &current); err != nil {
		return "", err
	}
	if authorityEpoch != epoch || state != ResourceActive || current != id {
		return "", ErrResourceStaleEpoch
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	_, err = tx.Exec(`INSERT INTO resource_v2_managed_blobs(resource_id,value,digest,writer_lease_id,writer_epoch,updated_at)
 VALUES(?,?,?,?,?,?) ON CONFLICT(resource_id) DO UPDATE SET value=excluded.value,digest=excluded.digest,
 writer_lease_id=excluded.writer_lease_id,writer_epoch=excluded.writer_epoch,updated_at=excluded.updated_at`,
		lease.ResourceID, body, digest, id, epoch, now())
	if err != nil {
		return "", fmt.Errorf("write managed blob: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return digest, nil
}
