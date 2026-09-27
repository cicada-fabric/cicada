package store

import (
	"errors"
	"testing"
	"time"
)

func TestLegacyArtifactAccessSerializesWithScopedRefPublication(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()

	legacy, err := persistence.CreateArtifact(Artifact{
		ID: "legacy-race-fixture", Name: "race fixture", Path: "race-fixture.txt",
		Kind: "evidence", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	legacyReadDone := make(chan error, 1)
	go func() {
		legacyReadDone <- persistence.withLegacyArtifactAccess(func() error {
			close(entered)
			<-release
			artifacts, err := persistence.listArtifactsLocked("")
			if err == nil && (len(artifacts) != 1 || artifacts[0].ID != legacy.ID) {
				return errors.New("legacy fixture disappeared during guarded read")
			}
			return err
		})
	}()
	<-entered
	if persistence.mu.TryLock() {
		persistence.mu.Unlock()
		t.Fatal("legacy guard released the Store lock between access check and read")
	}

	refStarted := make(chan struct{})
	refDone := make(chan error, 1)
	go func() {
		close(refStarted)
		_, err := persistence.CreateArtifactRefV2(ArtifactRefV2Input{
			ArtifactID: legacy.ID, GroupID: "group-race-fixture",
			Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		})
		refDone <- err
	}()
	<-refStarted
	select {
	case err := <-refDone:
		t.Fatalf("scoped ref publication crossed an active legacy read: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-legacyReadDone; err != nil {
		t.Fatal(err)
	}
	if err := <-refDone; err != nil {
		t.Fatal(err)
	}

	if _, err := persistence.ListArtifactsIfNoScopedRefs(""); !errors.Is(err, ErrLegacyArtifactAPIDisabled) {
		t.Fatalf("legacy list remained available after scoped ref publication: %v", err)
	}
	if _, err := persistence.CreateArtifactIfNoScopedRefs(Artifact{Name: "late", Path: "late.txt"}); !errors.Is(err, ErrLegacyArtifactAPIDisabled) {
		t.Fatalf("legacy create remained available after scoped ref publication: %v", err)
	}
}
