package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Attachment is metadata for user-provided bytes or a user-provided link.
// Control owns the file path; the store never reads the content.
type Attachment struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MimeType  string `json:"mime_type"`
	SourceURL string `json:"source_url,omitempty"`
	Path      string `json:"path,omitempty"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

func (s *Store) CreateAttachment(attachment Attachment) (*Attachment, error) {
	attachment.ID = strings.TrimSpace(attachment.ID)
	attachment.Name = strings.TrimSpace(attachment.Name)
	if attachment.ID == "" {
		attachment.ID = NewID("attachment")
	}
	if attachment.Name == "" {
		return nil, errors.New("attachment name is required")
	}
	if attachment.MimeType == "" {
		attachment.MimeType = "application/octet-stream"
	}
	if attachment.Size < 0 {
		return nil, errors.New("attachment size cannot be negative")
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO attachments
(id, name, mime_type, source_url, path, size, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, attachment.ID, attachment.Name, attachment.MimeType,
		attachment.SourceURL, attachment.Path, attachment.Size, timestamp)
	if err != nil {
		return nil, fmt.Errorf("create attachment: %w", err)
	}
	return s.getAttachmentLocked(attachment.ID)
}

func (s *Store) GetAttachment(id string) (*Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getAttachmentLocked(id)
}

func (s *Store) getAttachmentLocked(id string) (*Attachment, error) {
	var attachment Attachment
	err := s.db.QueryRow(`SELECT id, name, mime_type, source_url, path, size, created_at
FROM attachments WHERE id = ?`, id).Scan(&attachment.ID, &attachment.Name, &attachment.MimeType,
		&attachment.SourceURL, &attachment.Path, &attachment.Size, &attachment.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &attachment, nil
}
