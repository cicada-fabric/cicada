package store

import "testing"

func TestCommunicationLinkClientListIsPagedAndOwnerScoped(t *testing.T) {
	f := newExternalThreadInviteTestFixture(t)
	acceptedIDs := map[string]bool{}
	for range 3 {
		invite := f.createInvite(t)
		accepted, err := f.store.AcceptExternalThreadInvite(invite.Token, f.target.ownerID,
			f.target.endpointID, f.target.groupID)
		if err != nil {
			t.Fatal(err)
		}
		acceptedIDs[accepted.LinkID] = true
	}
	var cursor string
	seen := map[string]bool{}
	for {
		links, next, err := f.store.ListCommunicationLinksPageForOwner(f.source.ownerID, cursor, 1)
		if err != nil || len(links) != 1 || !acceptedIDs[links[0].ID] || seen[links[0].ID] {
			t.Fatalf("invalid source Link page: links=%#v next=%q err=%v", links, next, err)
		}
		seen[links[0].ID] = true
		if cursor == "" && next == "" {
			t.Fatal("first Link page silently truncated")
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 3 {
		t.Fatalf("paged Link list lost rows: seen=%d", len(seen))
	}
	if _, _, err := f.store.ListCommunicationLinksPageForOwner(f.target.ownerID, cursor, 1); err == nil {
		t.Fatal("Link cursor was transferable to another owner")
	}
	if outsider, next, err := f.store.ListCommunicationLinksPageForOwner("not-a-link-party", "", 50); err != nil ||
		len(outsider) != 0 || next != "" {
		t.Fatalf("outside owner saw Link metadata: links=%#v next=%q err=%v", outsider, next, err)
	}
}
