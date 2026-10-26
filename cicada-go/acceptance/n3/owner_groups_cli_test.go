package n3_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Actual external operator CLI. The native SID selects an existing protected
// Host record; it is never manufactured or supplied as a fake Hook event.
// This action changes only local admission. Current Group authority is checked
// independently by the caller, and cannot be inferred from CLI exit zero.
func ownerGroupsCLIAdmission(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, identity ownerGroupsIdentity, operation string) {
	t.Helper()
	if operation != "join" && operation != "leave" {
		t.Fatal("unreviewed external native operator action")
	}
	before := ownerGroupsStoredIdentities(t, v, actors, host.originalSIDs)
	var found bool
	for _, original := range before {
		if original == identity {
			found = true
		}
	}
	if !found {
		t.Fatal("external CLI selector is not an original native Host identity")
	}
	binary := filepath.Join(actors.prefix, "components/node/bin/cicada")
	if hash(readPrivateBinary(t, binary)) != hash(readPrivateBinary(t, os.Getenv("CICADA_N3_CICADA_BINARY"))) {
		t.Fatal("external registration CLI differs from the pinned product executable")
	}
	arguments := []string{operation, "--thread", identity.SID, "--user-root", actors.prefix,
		"--hub-id", v.f.cfg.Hub.HubID, "--node-id", v.actualNode.id}
	if operation == "join" {
		db := nodePairReadOnlyDB(t, filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3"))
		var name string
		err := db.QueryRow(`SELECT name FROM fabric_endpoints WHERE id=? AND native_session_id=? AND machine_id=?`,
			identity.Endpoint, identity.SID, identity.NodeID).Scan(&name)
		db.Close()
		if err != nil || name == "" {
			t.Fatal("external CLI cannot recover the original registered display name")
		}
		arguments = append(arguments, "--name", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env, command.Dir, command.Stdout, command.Stderr = actors.environment, identity.Workspace, actors.log, actors.log
	if command.Run() != nil {
		t.Fatal("actual external CLI did not complete the local admission action")
	}
	if !reflect.DeepEqual(before, ownerGroupsStoredIdentities(t, v, actors, host.originalSIDs)) {
		t.Fatal("external CLI replaced an original native SID, Endpoint, key, workspace or binding")
	}
	host.command(t, ownerGroupsHostCommand{Action: "checkpoint"})
}
