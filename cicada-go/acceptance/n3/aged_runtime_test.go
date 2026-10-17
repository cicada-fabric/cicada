package n3_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type agedN2Receipt struct {
	AccountSessionExpiresAt string                                   `json:"original_account_session_expires_at"`
	SyntheticOnly           bool                                     `json:"synthetic_acceptance_only_never_deploy"`
	SourceHead              string                                   `json:"seed_source_head"`
	HubFP                   string                                   `json:"hub_fingerprint"`
	OwnerID                 string                                   `json:"owner_id"`
	DeviceID                string                                   `json:"device_id"`
	N2ExpiresAt             string                                   `json:"immutable_n2_expires_at"`
	StoppedAt               string                                   `json:"writers_stopped_at"`
	Keys                    map[appvault.Purpose]e2ee.PublicIdentity `json:"original_public_identities"`
}

// Explicit setup helper, excluded from all acceptance selectors. It retains a
// separate task-owned synthetic fixture so its immutable N2 lease ages under
// real wall time while independent runtime development continues.
func TestN3SeedRetainedN2Fixture(t *testing.T) {
	root := os.Getenv("CICADA_N3_RETAINED_FIXTURE")
	if root != "/state/retained-aged-n2" {
		t.Fatal("retained synthetic fixture requires its explicit owned Docker path")
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal("refusing to reuse or overwrite an existing retained fixture")
	}
	f := newHubFixtureAt(t, "--hub-only", root)
	marker := filepath.Join(root, "seed-app.json")
	app := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, app.process, marker)
	var checkpoint appActorCheckpoint
	readJSON(t, marker, &checkpoint)
	app.kill(t)
	f.hub.kill(t)
	if checkpoint.Current.Account.RootState != appcore.RootStateActive || !checkpoint.Current.Authorization.Confirmed {
		t.Fatal("retained fixture lacks genuine separate Root proof and account login")
	}
	receipt := agedN2Receipt{SyntheticOnly: true, SourceHead: os.Getenv("CICADA_N3_SEED_SOURCE_HEAD"),
		HubFP: checkpoint.Current.Hub.Fingerprint, OwnerID: checkpoint.Current.Account.OwnerID,
		DeviceID: checkpoint.Current.Account.DeviceID, N2ExpiresAt: checkpoint.Current.Authorization.ExpiresAt,
		StoppedAt: time.Now().UTC().Format(time.RFC3339Nano), Keys: ownedAppPublicKeys(t, f)}
	receipt.AccountSessionExpiresAt = checkpoint.Current.Account.SessionExpiresAt
	if receipt.SourceHead == "" || !must(time.Parse(time.RFC3339Nano, receipt.N2ExpiresAt)).After(time.Now().UTC()) {
		t.Fatal("retained seed provenance or original future finite deadline is missing")
	}
	writeJSON(t, filepath.Join(root, "synthetic-aged-n2-receipt.json"), receipt)
	// The public receipt contains only complete public identities and safe facts;
	// all configuration, DB keys, encrypted vault and synthetic tokens stay private.
	writeJSON(t, "/out/aged-n2-seed.json", receipt)
	t.Logf("SETUP_ONLY synthetic_N2_proof_and_login_real=true writers_stopped=true immutable_N2_expires_at=%s N3_NOT_RUN=true", receipt.N2ExpiresAt)
}

func TestN3ActualIdentityFlowAfterWallClockN2Expiry(t *testing.T) {
	root := os.Getenv("CICADA_N3_RETAINED_FIXTURE")
	if root == "" || !strings.HasPrefix(filepath.Clean(root), "/state/") {
		t.Fatal("real expired-N2 acceptance requires its explicit retained task fixture; no skip/pass")
	}
	var receipt agedN2Receipt
	readJSON(t, filepath.Join(root, "synthetic-aged-n2-receipt.json"), &receipt)
	expiry := must(time.Parse(time.RFC3339Nano, receipt.N2ExpiresAt))
	if !receipt.SyntheticOnly || receipt.SourceHead == "" || time.Now().UTC().Before(expiry) {
		t.Fatal("retained N2 lease has not genuinely expired under wall time")
	}
	f := &hubFixture{dir: root, parent: t, mode: "--hub-nodes-only"}
	readJSON(t, filepath.Join(root, "synthetic-config.json"), &f.cfg)
	loopback(t, f.cfg.Origin)
	db := must(store.New(filepath.Join(root, "synthetic-hub", "cicada.sqlite3")))
	originalLease := must(db.HubAppLease(receipt.OwnerID, receipt.DeviceID))
	if originalLease == nil {
		db.Close()
		t.Fatal("retained genuine N2 lease is absent")
	}
	beforeLease := must(json.Marshal(originalLease))
	defer clear(beforeLease)
	db.Close()
	// Verify the retained origin's port is free inside this disposable network
	// namespace. A collision is a fixture failure, never an identity/port reset.
	origin := must(net.ResolveTCPAddr("tcp", strings.TrimPrefix(f.cfg.Origin, "http://")))
	probe := must(net.ListenTCP("tcp", origin))
	probe.Close()
	f.start(t)
	f.proxy = newFaultProxy(t, f.cfg.Origin)
	marker := filepath.Join(root, "aged-app-resumed.json")
	app := startAppProcess(t, f, "resume-node", marker)
	awaitMarker(t, app.process, marker)
	var resumed appActorCheckpoint
	readJSON(t, marker, &resumed)
	if resumed.Current.Authorization.State != "EXPIRED" || resumed.Current.Authorization.Confirmed ||
		resumed.Current.Authorization.ExpiresAt != receipt.N2ExpiresAt ||
		resumed.Current.Account.DeviceID != receipt.DeviceID || resumed.Current.Account.OwnerID != receipt.OwnerID ||
		resumed.Current.Hub.Fingerprint != receipt.HubFP {
		t.Fatal("expired immutable N2 history blocked identity/N3 discovery or was silently renewed/replaced")
	}
	sequence := 0
	for _, available := range resumed.Current.AvailableActions {
		if available == appcore.ActionLogout {
			sequence++
			logout := commandApp(t, f, app, sequence, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionLogout}})
			if logout.ActionFailed {
				t.Fatal("retained still-live session could not be explicitly ended before fresh login")
			}
			break
		}
	}
	sequence++
	login := commandApp(t, f, app, sequence, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionLogin,
		Username: "synthetic-user", Password: syntheticPassword}})
	if login.ActionFailed || login.Current.Account.RootState != appcore.RootStateActive || !login.Current.Node.Available ||
		login.Current.Authorization.State != "EXPIRED" || login.Current.Authorization.ExpiresAt != receipt.N2ExpiresAt {
		t.Fatal("fresh real account login after natural N2 expiry was blocked or renewed N2 authority")
	}
	node := startNodeProcess(t, f, "synthetic-n3-after-real-n2-expiry")
	pending := node.awaitState(t, f, false)
	node.kill(t)
	sequence++
	preview := commandApp(t, f, app, sequence, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: pending.PendingCode}})
	if preview.ActionFailed || preview.Current.Node.Candidate == nil {
		t.Fatal("genuinely expired N2 lease prevented a new explicit N3 preview")
	}
	sequence++
	approved := commandApp(t, f, app, sequence, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionApproveNode,
		NodeReviewID: preview.Current.Node.Candidate.ReviewID, ConfirmNodeIdentity: true, ConfirmNodeAccess: true}})
	if approved.ActionFailed || !approved.Current.Node.Access.Confirmed || approved.Current.Node.Binding == nil ||
		approved.Current.Node.Binding.NodeID != node.id || approved.Current.Authorization.State != "EXPIRED" ||
		approved.Current.Authorization.ExpiresAt != receipt.N2ExpiresAt || approved.Current.Authorization.Confirmed {
		t.Fatal("explicit N3 after real N2 expiry failed or changed immutable N2 authority")
	}
	app.kill(t)
	if !reflect.DeepEqual(receipt.Keys, ownedAppPublicKeys(t, f)) {
		t.Fatal("real expired-N2 profile flow replaced a complete original public identity")
	}
	f.hub.kill(t)
	db = f.db(t)
	afterLease := must(json.Marshal(must(db.HubAppLease(receipt.OwnerID, receipt.DeviceID))))
	defer clear(afterLease)
	db.Close()
	if hash(beforeLease) != hash(afterLease) {
		t.Fatal("N3 after natural expiry changed the complete original persisted N2 lease")
	}
	t.Logf("ACTUAL_N3 immutable_N2_expired_under_real_wall_time=true seed_source=%s no_new_installer_or_Root_ceremony=true same_original_keys=true independent_new_finite_N3=true original_N2_expiry=%s", receipt.SourceHead, receipt.N2ExpiresAt)
}
