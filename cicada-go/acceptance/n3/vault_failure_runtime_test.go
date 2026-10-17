package n3_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3ActualVaultFailureStopsBeforeSecretSend(t *testing.T) {
	f := newNodeHubFixture(t)
	marker := filepath.Join(f.dir, "disk-bootstrap.json")
	first := startAppProcess(t, f, "bootstrap", marker)
	awaitMarker(t, first.process, marker)
	first.kill(t)
	keys := ownedAppPublicKeys(t, f)
	marker = filepath.Join(f.dir, "disk-resume.json")
	app := startAppProcess(t, f, "resume-node", marker)
	awaitMarker(t, app.process, marker)
	paths := must(filepath.Glob(filepath.Join(f.dir, "synthetic-app", "vaults", "*.vault")))
	if len(paths) != 1 {
		t.Fatal("owned disk-fault fixture lacks its unique original vault")
	}
	path := paths[0]
	before := readPrivate(t, path)
	defer clear(before)
	blocked := path + ".owned-fault"
	if os.Rename(path, blocked) != nil {
		t.Fatal("owned vault persistence fault could not be armed")
	}
	// Preserve and restore the exact original file even if an assertion fails.
	t.Cleanup(func() { _ = os.Rename(blocked, path) })
	traceBefore := len(f.proxy.snapshot())
	failed := commandApp(t, f, app, 1, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: "222222222222"}})
	if !failed.ActionFailed || failed.Current.Node.Access.Confirmed {
		t.Fatal("failed durable pending commit retained new Node permission")
	}
	for _, exchange := range f.proxy.snapshot()[traceBefore:] {
		if exchange.Path == "/v2/client/rpc" {
			t.Fatal("local persistence failure sent a Client business request")
		}
		for _, operation := range []string{wire.OperationAppNodePrepare, wire.OperationAppNodeComplete, wire.OperationAppNodeStatus, wire.OperationAppNodeCancel, wire.OperationAppNodeReconcile} {
			if exchange.Path == wire.AppNodeHTTPPath(operation) {
				t.Fatal("local persistence failure sent a secret packet from memory-only state")
			}
		}
	}
	blockedIdentity := commandApp(t, f, app, 2, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionGenerateOwner}})
	if !blockedIdentity.ActionFailed {
		t.Fatal("poisoned local actor regenerated an Owner identity")
	}
	app.kill(t)
	if hash(readPrivate(t, blocked)) != hash(before) || os.Rename(blocked, path) != nil || !reflect.DeepEqual(keys, ownedAppPublicKeys(t, f)) {
		t.Fatal("local disk fault changed or replaced the original encrypted identity state")
	}
	t.Log("ACTUAL_N3 real_vault_persistence_failure=true zero_secret_POSTs=true no_memory_only_pending_send=true original_keys_and_encrypted_image_retained=true")
}
