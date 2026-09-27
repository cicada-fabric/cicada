package control

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	maxAttachmentBytes   = 8 << 20
	maxIntentAttachments = 5
)

type AttachmentInput struct {
	Name          string `json:"name"`
	MimeType      string `json:"mime_type"`
	ContentBase64 string `json:"content_base64,omitempty"`
	SourceURL     string `json:"source_url,omitempty"`
}

func (c *Control) CreateAttachment(input AttachmentInput) (*store.Attachment, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.MimeType = strings.TrimSpace(input.MimeType)
	input.SourceURL = strings.TrimSpace(input.SourceURL)
	if input.Name == "" {
		return nil, errors.New("attachment name is required")
	}
	if len(input.Name) > 255 || len(input.MimeType) > 200 {
		return nil, errors.New("attachment metadata is too long")
	}
	if input.ContentBase64 == "" && input.SourceURL == "" {
		return nil, errors.New("attachment content or source_url is required")
	}
	if input.SourceURL != "" {
		parsed, err := url.Parse(input.SourceURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return nil, errors.New("source_url must be an http or https URL without credentials")
		}
	}
	var content []byte
	if input.ContentBase64 != "" {
		var err error
		content, err = base64.StdEncoding.DecodeString(input.ContentBase64)
		if err != nil {
			return nil, fmt.Errorf("decode attachment content: %w", err)
		}
		if len(content) > maxAttachmentBytes {
			return nil, fmt.Errorf("attachment exceeds %d bytes", maxAttachmentBytes)
		}
	}
	attachmentID := store.NewID("attachment")
	path := ""
	if len(content) > 0 {
		directory := filepath.Join(c.config.StateDir, "attachments")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create attachment directory: %w", err)
		}
		path = filepath.Join(directory, attachmentID+".bin")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return nil, fmt.Errorf("store attachment bytes: %w", err)
		}
	}
	created, err := c.store.CreateAttachment(store.Attachment{
		ID: attachmentID, Name: input.Name, MimeType: input.MimeType,
		SourceURL: input.SourceURL, Path: path, Size: int64(len(content)),
	})
	if err != nil {
		if path != "" {
			_ = os.Remove(path)
		}
		return nil, err
	}
	return created, nil
}

func (c *Control) Attachment(id string) (*store.Attachment, error) {
	return c.store.GetAttachment(strings.TrimSpace(id))
}

func (c *Control) prepareIntentAttachments(input *IntentInput) error {
	if len(input.Attachments) > maxIntentAttachments {
		return fmt.Errorf("an intent can reference at most %d attachments", maxIntentAttachments)
	}
	if len(input.Attachments) == 0 {
		return nil
	}
	resources := input.Goal.Resources
	if resources == nil {
		resources = map[string]any{}
	}
	entries := make([]map[string]any, 0, len(input.Attachments))
	seen := map[string]bool{}
	for _, id := range input.Attachments {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		attachment, err := c.store.GetAttachment(id)
		if err != nil {
			return err
		}
		if attachment == nil {
			return fmt.Errorf("attachment not found: %s", id)
		}
		entries = append(entries, map[string]any{
			"id": attachment.ID, "name": attachment.Name, "mime_type": attachment.MimeType,
			"path": attachment.Path, "source_url": attachment.SourceURL, "size": attachment.Size,
		})
	}
	resources["attachments"] = entries
	input.Goal.Resources = resources
	return nil
}
