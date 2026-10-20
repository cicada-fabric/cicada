package n3_test

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/store"
)

func appProfileCiphertexts(t *testing.T, f *hubFixture) map[string]string {
	t.Helper()
	paths := must(filepath.Glob(filepath.Join(f.dir, "synthetic-app", "vaults", "*.vault")))
	if len(paths) != 1 {
		t.Fatal("actual App did not retain exactly one encrypted profile")
	}
	images := make(map[string]string)
	for _, path := range paths {
		raw := must(os.ReadFile(path))
		if len(raw) == 0 {
			t.Fatal("actual encrypted profile is empty")
		}
		images[filepath.Base(path)] = hash(raw)
		clear(raw)
	}
	return images
}

// Observe the running Hub through a SQLite read-only connection. No session,
// pin, grant or other product state is inserted or updated by this helper.
func runningAccountSessionDigest(t *testing.T, f *hubFixture, s appcore.Snapshot) string {
	t.Helper()
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(f.dir, "synthetic-hub", "cicada.sqlite3"), RawQuery: "mode=ro"}).String()
	db := must(sql.Open("sqlite", dsn))
	defer db.Close()
	rows := must(db.Query(`SELECT session_id,account_id,owner_id,device_id,epoch,device_epoch,credential_version,token_digest,state,expires_at FROM hub_account_sessions_v1 WHERE account_id=? AND device_id=? ORDER BY session_id`, s.Account.AccountID, s.Account.DeviceID))
	defer rows.Close()
	var sessions []store.HubAccountSession
	for rows.Next() {
		var v store.HubAccountSession
		if rows.Scan(&v.ID, &v.AccountID, &v.OwnerID, &v.DeviceID, &v.Epoch, &v.DeviceEpoch, &v.CredentialVersion, &v.TokenDigest, &v.State, &v.ExpiresAt) != nil {
			t.Fatal("cannot observe the actual Hub session")
		}
		sessions = append(sessions, v)
	}
	if rows.Err() != nil || len(sessions) != 1 || sessions[0].State != "ACTIVE" || sessions[0].OwnerID != s.Account.OwnerID || sessions[0].ExpiresAt != s.Account.SessionExpiresAt {
		t.Fatal("actual Hub session does not match the authenticated App checkpoint")
	}
	raw := must(json.Marshal(sessions))
	defer clear(raw)
	return hash(raw) // Session/token coordinates are never written to evidence.
}

func TestN3HarnessActualAppGracefulCloseAndResume(t *testing.T) {
	f := newHubFixture(t)
	marker := filepath.Join(f.dir, "lifecycle-bootstrap.json")
	first := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, first.process, marker)
	var original appActorCheckpoint
	readJSON(t, marker, &original)
	profile := appProfileCiphertexts(t, f)
	session := runningAccountSessionDigest(t, f, original.Current)
	requests := len(f.proxy.snapshot())
	firstPID, hubPID := first.cmd.Process.Pid, f.hub.cmd.Process.Pid
	closeApp(t, f, first, 1)
	if !f.hub.running() || f.hub.cmd.Process.Pid != hubPID || len(f.proxy.snapshot()) != requests || !reflect.DeepEqual(profile, appProfileCiphertexts(t, f)) || runningAccountSessionDigest(t, f, original.Current) != session {
		t.Fatal("graceful close changed the encrypted profile, Hub session or network authority")
	}
	marker = filepath.Join(f.dir, "lifecycle-resume.json")
	resumed := startAppProcess(t, f, "resume", marker)
	awaitMarker(t, resumed.process, marker)
	var restored appActorCheckpoint
	readJSON(t, marker, &restored)
	a, b := original.Current, restored.Current
	if resumed.cmd.Process.Pid == firstPID || !f.hub.running() || f.hub.cmd.Process.Pid != hubPID ||
		a.Hub.HubID != b.Hub.HubID || a.Hub.Fingerprint != b.Hub.Fingerprint || a.Account.AccountID != b.Account.AccountID || a.Account.OwnerID != b.Account.OwnerID || a.Account.DeviceID != b.Account.DeviceID ||
		a.Account.OwnerFingerprint != b.Account.OwnerFingerprint || a.Account.SessionExpiresAt != b.Account.SessionExpiresAt || a.Authorization.ExpiresAt != b.Authorization.ExpiresAt || runningAccountSessionDigest(t, f, b) != session {
		t.Fatal("actual profile resume replaced the original identity, session or finite deadline")
	}
	closeApp(t, f, resumed, 1)
	t.Log("APP_LIFECYCLE_HARNESS_ONLY actual_Controller_Close=true exit_zero=true no_close_HTTP=true encrypted_profile_unchanged=true original_Hub_session_and_deadlines=true new_App_PID=true registration_NOT_RUN=true INST04_NOT_RUN=true Windows_NOT_RUN=true")
}
