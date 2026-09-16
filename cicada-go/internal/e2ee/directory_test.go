package e2ee

import (
	"testing"
	"time"
)

func TestDirectoryAnnouncementRoundTrip(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	data, err := identity.SignDirectoryAnnouncement("Alice", []string{"https://alice.example/federation"}, expires)
	if err != nil {
		t.Fatal(err)
	}
	public, label, endpoints, gotExpiry, err := VerifyDirectoryAnnouncement(data)
	if err != nil || public.ID != identity.Public().ID || label != "Alice" || len(endpoints) != 1 || !gotExpiry.Equal(expires.Truncate(time.Second)) {
		t.Fatalf("directory result public=%q label=%q endpoints=%v expiry=%s err=%v", public.ID, label, endpoints, gotExpiry, err)
	}
}

func TestDirectoryAnnouncementRejectsCredentialEndpoint(t *testing.T) {
	identity, _ := NewIdentity()
	if _, err := identity.SignDirectoryAnnouncement("Alice", []string{"https://user:secret@example.com/rendezvous"}, time.Now().UTC().Add(time.Hour)); err == nil {
		t.Fatal("credential-bearing directory endpoint was accepted")
	}
}
