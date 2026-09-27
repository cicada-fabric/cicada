package store

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var ErrLegacyArtifactAPIDisabled = errors.New("legacy Artifact API requires a configured management token after scoped ArtifactRefs exist")
var ErrLegacyArtifactGuardUnavailable = errors.New("legacy Artifact API access guard is unavailable")

// HasScopedArtifactRefs lets the legacy management HTTP facade fail closed
// when it has no configured manager authentication. A v1 Artifact row may be
// the source of a scoped v2 reference and must not become an anonymous alias.
func (s *Store) HasScopedArtifactRefs() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasScopedArtifactRefsLocked()
}

func (s *Store) hasScopedArtifactRefsLocked() (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT count(*) FROM artifact_v2_refs LIMIT 1`).Scan(&count)
	return count != 0, err
}

// withLegacyArtifactAccess serializes the compatibility check with the v1
// operation. ArtifactRef creation uses the same Store mutex, so a request
// cannot pass the check, race with publication, then read the legacy row.
func (s *Store) withLegacyArtifactAccess(action func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	scoped, err := s.hasScopedArtifactRefsLocked()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLegacyArtifactGuardUnavailable, err)
	}
	if scoped {
		return ErrLegacyArtifactAPIDisabled
	}
	return action()
}

// ListArtifactsIfNoScopedRefs preserves the legacy list API until the first
// scoped ArtifactRef is published, while checking and listing atomically.
func (s *Store) ListArtifactsIfNoScopedRefs(goalID string) ([]Artifact, error) {
	var artifacts []Artifact
	err := s.withLegacyArtifactAccess(func() error {
		var err error
		artifacts, err = s.listArtifactsLocked(goalID)
		return err
	})
	return artifacts, err
}

// CreateArtifactIfNoScopedRefs preserves anonymous legacy creation only while
// no scoped reference exists. The insert shares a mutex with v2 publication.
func (s *Store) CreateArtifactIfNoScopedRefs(artifact Artifact) (*Artifact, error) {
	var created *Artifact
	err := s.withLegacyArtifactAccess(func() error {
		if artifact.GoalID != "" {
			goal, err := s.getGoalLocked(artifact.GoalID)
			if err != nil {
				return err
			}
			if goal == nil {
				return os.ErrNotExist
			}
		}
		var err error
		created, err = s.createArtifactLocked(artifact)
		return err
	})
	return created, err
}

func (s *Store) createArtifactLocked(artifact Artifact) (*Artifact, error) {
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
	_, err := s.db.Exec(`INSERT INTO artifacts (id, goal_id, worker_id, workspace_id, name, path, kind, digest, evidence, status, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, artifact.ID, nullableString(artifact.GoalID), nullableString(artifact.WorkerID), nullableString(artifact.WorkspaceID), artifact.Name, artifact.Path, artifact.Kind, artifact.Digest, artifact.Evidence, artifact.Status, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create artifact: %w", err)
	}
	return s.getArtifactLocked(artifact.ID)
}

func (s *Store) listArtifactsLocked(goalID string) ([]Artifact, error) {
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
			_ = rows.Close()
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
	return result, nil
}
