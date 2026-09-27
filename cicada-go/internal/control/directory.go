package control

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func (c *Control) SignDirectoryAnnouncement(label string, endpoints []string, expiresAt time.Time) ([]byte, error) {
	if c.identity == nil {
		return nil, errors.New("local E2EE identity is unavailable")
	}
	return c.identity.SignDirectoryAnnouncement(label, endpoints, expiresAt)
}

// PublishDirectoryAnnouncement verifies the signature before persisting a
// public rendezvous record. It never creates a trusted Contact.
func (c *Control) PublishDirectoryAnnouncement(announcement []byte) (*store.DirectoryRecord, error) {
	identity, label, endpoints, expiresAt, err := e2ee.VerifyDirectoryAnnouncement(announcement)
	if err != nil {
		return nil, err
	}
	if c.identity != nil && identity.ID == c.identity.Public().ID {
		return nil, errors.New("cannot publish the local identity as a remote directory record")
	}
	if existing, err := c.store.GetDirectoryRecordByRemoteID(identity.ID); err != nil {
		return nil, err
	} else if existing != nil && existing.Status == "active" && existing.ExpiresAt == expiresAt.UTC().Format(time.RFC3339) && string(existing.Announcement) == string(announcement) {
		return existing, nil
	}
	return c.store.UpsertDirectoryRecord(store.DirectoryRecord{
		RemoteID: identity.ID, Label: label, Identity: identity, Endpoints: endpoints,
		Announcement: announcement, ExpiresAt: expiresAt.UTC().Format(time.RFC3339), Status: "active",
	})
}

func (c *Control) DirectoryRecords(activeOnly bool) ([]store.DirectoryRecord, error) {
	if _, err := c.store.ReapExpiredDirectoryRecords(time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	return c.store.ListDirectoryRecords(activeOnly)
}

func (c *Control) DirectoryRecord(id string) (*store.DirectoryRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, os.ErrNotExist
	}
	if _, err := c.store.ReapExpiredDirectoryRecords(time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	record, err := c.store.GetDirectoryRecord(id)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, os.ErrNotExist
	}
	if record.Status != "active" {
		return nil, fmt.Errorf("directory record is %s", record.Status)
	}
	return record, nil
}
