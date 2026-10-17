package n3_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3ActualAppUnsupportedCapabilitiesSendNoSecrets(t *testing.T) {
	for _, mode := range []string{"actual-legacy-hub", "unsupported-before-forward", "unknown-profile-before-forward"} {
		t.Run(mode, func(t *testing.T) {
			f := newHubFixture(t) // A real supported N2 Hub without N3 services.
			if mode != "actual-legacy-hub" {
				f.proxy.arm(wire.AppNodeCapabilitiesPath, mode, 1)
			}
			marker := filepath.Join(f.dir, "unsupported-app-ready.json")
			app := startAppProcess(t, f, "bootstrap", marker)
			awaitMarker(t, app.process, marker)
			var checkpoint appActorCheckpoint
			readJSON(t, marker, &checkpoint)
			if checkpoint.Current.Node.Available || checkpoint.Current.Node.Pending || checkpoint.Current.Node.Access.Confirmed {
				t.Fatal("unsupported public discovery became N3 authority or pending work")
			}
			result := commandApp(t, f, app, 1, appActorCommand{Action: &appcore.Action{Kind: appcore.ActionPreviewNode, NodeCode: "222222222222"}})
			if !result.ActionFailed || result.Current.Node.Pending {
				t.Fatal("unsupported N3 preview succeeded or created a pending secret operation")
			}
			app.kill(t)
			probes := 0
			for _, exchange := range f.proxy.snapshot() {
				if exchange.Path == wire.AppNodeCapabilitiesPath {
					probes++
				}
				if exchange.Path == "/v2/client/rpc" {
					t.Fatal("unsupported discovery sent Client business RPC")
				}
				for _, operation := range []string{wire.OperationAppNodePrepare, wire.OperationAppNodeComplete, wire.OperationAppNodeStatus, wire.OperationAppNodeCancel, wire.OperationAppNodeReconcile} {
					if exchange.Path == wire.AppNodeHTTPPath(operation) {
						t.Fatal("unsupported discovery sent an N3 secret POST, including bootstrap status")
					}
				}
			}
			if probes == 0 {
				t.Fatal("App never probed the actual N3 capability endpoint")
			}
			vault := ownedAppVault(t, f)
			for _, namespace := range []string{"appcore.node.v1", "appcore.node-recovery.v1"} {
				raw, _, found, err := vault.LoadState(namespace)
				if err != nil {
					t.Fatal("actual App's private Node state cannot be inspected")
				}
				if found && len(raw) > 0 {
					var fields map[string]json.RawMessage
					present := func(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }
					if json.Unmarshal(raw, &fields) != nil || present(fields["pending"]) || present(fields["request"]) {
						t.Fatal("unsupported discovery persisted a new N3 pending request")
					}
				}
				clear(raw)
			}
			vault.Close()
			t.Logf("ACTUAL_APP_N3_GUARD unsupported=%s secret_posts=0 new_pending=0 N3_full_chain_NOT_RUN=true", mode)
		})
	}
}
