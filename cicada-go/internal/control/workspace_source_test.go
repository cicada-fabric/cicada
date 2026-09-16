package control

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalWorkerPreparesPinnedGitWorkspace(t *testing.T) {
	git := fakeWorkspaceGit(t)
	t.Setenv("CICADA_GIT_BIN", git)
	t.Setenv("API_KEY", "must-not-reach-git")
	controlPlane := newTestControl(t, "success")
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "read the provisioned repository", Harness: "shell",
		Resources: map[string]any{
			"argv": []any{"/bin/cat", "evidence.txt"},
			"workspace_source": map[string]any{
				"kind": "git", "url": "https://93.184.216.34/example/repository.git", "revision": "main",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	final := waitTestGoal(t, controlPlane, goal.ID)
	if final.Status != "completed" || final.Summary != "WORKSPACE_READY" {
		t.Fatalf("provisioned local Goal=%#v", final)
	}
	workspaces, err := controlPlane.Workspaces(goal.ID)
	if err != nil || len(workspaces) != 1 || workspaces[0].Revision != "abcdef0123456789" || workspaces[0].Source != "git" {
		t.Fatalf("workspace provenance was not persisted: %#v err=%v", workspaces, err)
	}
	events, err := controlPlane.Events(goal.ID, 0)
	if err != nil || !eventTypes(events)["WorkspacePrepared"] {
		t.Fatalf("WorkspacePrepared event missing: %v err=%v", eventTypes(events), err)
	}
}

func fakeWorkspaceGit(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	script := `#!/bin/sh
set -eu
test -z "${API_KEY:-}"
repository=''
previous=''
for argument in "$@"; do
  if [ "$previous" = '-C' ]; then repository="$argument"; fi
  previous="$argument"
done
case " $* " in
  *' init --quiet '*)
    for argument in "$@"; do target="$argument"; done
    mkdir -p "$target/.git"
    ;;
  *' checkout --quiet '*) printf 'WORKSPACE_READY\n' > "$repository/evidence.txt" ;;
  *' rev-parse HEAD '*) printf 'abcdef0123456789\n' ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRemoteWorkspaceCloneHonorsGoalPermission(t *testing.T) {
	controlPlane := newTestControl(t, "success")
	if _, err := controlPlane.RegisterMachine("remote-source", "Remote source", map[string]any{"harnesses": []string{"shell"}}, "available"); err != nil {
		t.Fatal(err)
	}
	goal, err := controlPlane.CreateGoal(GoalInput{
		Objective: "prepare a denied repository", MachineID: "remote-source", Harness: "shell",
		Resources: map[string]any{
			"argv":             []any{"/bin/true"},
			"workspace_source": map[string]any{"url": "https://93.184.216.34/example/repository.git"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.SetPermission(PermissionInput{
		SubjectType: "goal", SubjectID: goal.ID, Action: "workspace.clone",
		Resource: "93.184.216.34", Effect: "deny",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := controlPlane.MachineJobs("remote-source"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("denied workspace source was dispatched: %v", err)
	}
}
