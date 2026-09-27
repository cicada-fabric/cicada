package control

import (
	"testing"
	"time"
)

func TestDirectoryRecordDoesNotCreateTrustedContact(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	peer := newTestControl(t, "success")
	announcement, err := peer.SignDirectoryAnnouncement("Peer", []string{"https://peer.example/federation"}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	record, err := controlPlane.PublishDirectoryAnnouncement(announcement)
	if err != nil || record.Status != "active" {
		t.Fatalf("directory publish failed: %#v err=%v", record, err)
	}
	contacts, err := controlPlane.Contacts()
	if err != nil || len(contacts) != 0 {
		t.Fatalf("directory publication created contacts: %#v err=%v", contacts, err)
	}
	if _, err := controlPlane.DirectoryRecord(record.RemoteID); err != nil {
		t.Fatal(err)
	}
}
