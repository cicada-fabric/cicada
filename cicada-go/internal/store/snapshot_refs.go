package store

// WorkspaceSnapshotDigests returns the durable roots that protect CAS
// archives from garbage collection. Workspace pointers protect the current
// resume state; snapshot artifacts protect historical evidence recorded by a
// Goal.
func (s *Store) WorkspaceSnapshotDigests() (map[string]struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
SELECT snapshot_digest FROM workspaces WHERE snapshot_digest <> ''
UNION
SELECT digest FROM artifacts WHERE kind = 'workspace-snapshot' AND digest <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]struct{})
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, err
		}
		if digest != "" {
			result[digest] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
