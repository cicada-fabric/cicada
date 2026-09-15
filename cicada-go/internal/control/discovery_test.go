package control

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestContactDiscoveryStaysPendingUntilTrust(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	peer, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := peer.SignContactAnnouncement("Bob")
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlPlane.SubmitContactDiscovery(announcement)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := controlPlane.SubmitContactDiscovery(announcement)
	if err != nil || duplicate.ID != request.ID {
		t.Fatalf("discovery was not idempotent: request=%#v duplicate=%#v err=%v", request, duplicate, err)
	}
	if request.Status != "pending" || request.RemoteID != peer.Public().ID {
		t.Fatalf("unexpected discovery request: %#v", request)
	}
	accepted, err := controlPlane.AcceptContactDiscovery(request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Status != "accepted" || accepted.ContactID == "" {
		t.Fatalf("discovery acceptance was not durable: %#v", accepted)
	}
	contact, err := controlPlane.Contact(accepted.ContactID)
	if err != nil || contact.Status != "pending" {
		t.Fatalf("accepted discovery was trusted automatically: contact=%#v err=%v", contact, err)
	}
	if _, err := controlPlane.SendPeerMessage(contact.ID, "should wait", nil); err == nil {
		t.Fatal("pending discovered contact was allowed to send")
	}
	repeated, err := controlPlane.AcceptContactDiscovery(request.ID)
	if err != nil || repeated.ContactID != contact.ID {
		t.Fatalf("repeated acceptance was not idempotent: request=%#v err=%v", repeated, err)
	}
	contacts, err := controlPlane.Contacts()
	if err != nil || len(contacts) != 1 {
		t.Fatalf("repeated acceptance created duplicate contacts: contacts=%#v err=%v", contacts, err)
	}
}

func TestContactDiscoveryRejectsTamperedAnnouncement(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	peer, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := peer.SignContactAnnouncement("Bob")
	if err != nil {
		t.Fatal(err)
	}
	announcement[len(announcement)-3] ^= 1
	if _, err := controlPlane.SubmitContactDiscovery(announcement); err == nil {
		t.Fatal("tampered contact announcement was accepted")
	}
}

func TestContactAnnouncementSigningUsesLocalIdentity(t *testing.T) {
	root := t.TempDir()
	controlPlane, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer controlPlane.Shutdown(context.Background())
	announcement, err := controlPlane.SignContactAnnouncement("Alice")
	if err != nil {
		t.Fatal(err)
	}
	identity, label, err := e2ee.VerifyContactAnnouncement(announcement)
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != controlPlane.Identity().ID || label != "Alice" {
		t.Fatalf("unexpected signed announcement: identity=%s label=%q", identity.ID, label)
	}
	if _, err := controlPlane.SubmitContactDiscovery(announcement); err == nil {
		t.Fatal("local identity was accepted as a remote discovery request")
	}
}
