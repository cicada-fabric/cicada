package n3_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is an OS-boundary gate on a real App-approved Node, not acceptance of
// the pending domain authorization/context profile. The host runs the actual
// other-UID process; this unprivileged fixture cannot setuid or invoke Docker.
func TestN3CodexProductOtherUIDPrivateBoundary(t *testing.T) {
	control := os.Getenv("CICADA_N3_OTHER_UID_CONTROL")
	if control != "/state/other-uid-control" {
		t.Fatal("explicit owned host-probe control directory required")
	}
	v := newCodexProductFixture(t, "1h")
	v.requireEmptyOwnerDirectory(t)
	state := v.actualNode.statePath()
	identity := filepath.Join(filepath.Dir(state), "identity.json")
	for _, path := range []string{state, identity} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("original actual Node private target missing")
		}
	}
	// Only this disposable container's exact per-UID runtime directory is read.
	// Long original state roots use the production socket here, not a QA socket.
	sockets := must(filepath.Glob("/tmp/cicada-j-1000/*.sock"))
	if len(sockets) != 1 {
		t.Fatal("one actual Node private runtime socket required")
	}
	writeJSON(t, filepath.Join(control, "request.json"), map[string]any{
		"synthetic": true, "owner_uid": 1000,
		"private_files":   []map[string]string{{"label": "node_control_state", "path": state}, {"label": "node_private_identity", "path": identity}},
		"private_sockets": []map[string]string{{"label": "node_context_join_ipc", "path": sockets[0]}},
	})
	result := filepath.Join(control, "result.json")
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(result); err == nil {
			break
		}
		if !v.actualNode.running() || !v.f.hub.running() {
			t.Fatal("actual Node/Hub stopped during other-UID probe")
		}
		time.Sleep(25 * time.Millisecond)
	}
	var observed struct {
		Scope, Status string
		Exit          int `json:"probe_exit_code"`
		Owner         struct {
			Status string
			UID    int
		} `json:"owner_precondition"`
		Observation struct {
			UID, GID int
			Checks   []struct {
				Label  string
				Denied bool `json:"permission_denied"`
				Errno  int
			}
		}
	}
	readJSON(t, result, &observed)
	if observed.Scope != "OTHER_UID_OS_BOUNDARY_ONLY_NOT_DOMAIN_ACCEPTANCE" || observed.Status != "OBSERVED_DENIAL" || observed.Exit != 0 ||
		observed.Owner.Status != "OBSERVED_OWNER_ACCESS" || observed.Owner.UID != 1000 || observed.Observation.UID != 1001 || observed.Observation.GID != 1000 || len(observed.Observation.Checks) != 3 {
		t.Fatal("actual other-UID result or original owner access missing")
	}
	labels := map[string]bool{"node_control_state": false, "node_private_identity": false, "node_context_join_ipc": false}
	for _, check := range observed.Observation.Checks {
		seen, found := labels[check.Label]
		if !found || seen || !check.Denied || (check.Errno != 13 && check.Errno != 1) {
			t.Fatal("other UID gained access or target was merely missing/unavailable")
		}
		labels[check.Label] = true
	}
	bound := v.actualNode.awaitState(t, v.f, true)
	if bound.BindingID != v.bound.BindingID || bound.NodeKeyEpoch != v.bound.NodeKeyEpoch || bound.NodeFingerprint != v.bound.NodeFingerprint {
		t.Fatal("other-UID probe changed the original Node authority")
	}
	v.requireEmptyOwnerDirectory(t)
	t.Log("OTHER_UID_PRIVATE_BOUNDARY owner_uid1000_actual_access=true probe_uid1001_gid1000=true private_files2_and_real_Node_IPC1=EACCES_OR_EPERM key_bytes_read=false IPC_payloads_sent=false domain_context_signing_Pair_Windows=NOT_RUN")
}
