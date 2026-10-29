package n3_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func ownerGroupsColdControlActors(t *testing.T, v *codexProductFixture) nativePeerActors {
	t.Helper()
	prefix := filepath.Join(v.root, "cold-control-selected-root")
	if os.Mkdir(prefix, 0755) != nil || os.Chmod(prefix, 0755) != nil {
		t.Fatal("cold control installation root unavailable")
	}
	log := must(os.OpenFile(filepath.Join(v.root, "private-cold-control.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	var assets [][]string
	for _, path := range []string{".agents/plugins/cicada/.codex-plugin/plugin.json", ".agents/plugins/cicada/.mcp.json",
		".agents/plugins/cicada/hooks/hooks.json", ".agents/plugins/cicada/skills/cicada-network/SKILL.md", ".agents/plugins/marketplace.json"} {
		assets = append(assets, []string{path, hash(readPrivate(t, filepath.Join("/repo", path)))})
	}
	binary := os.Getenv("CICADA_N3_CICADA_BINARY")
	assetHash := hash(must(json.Marshal(map[string]any{"format": "cicada.codex-plugin-assets.v1", "files": assets})))
	install := exec.Command(binary, "components", "install", "--prefix", prefix, "--components", "node", "--binary", binary,
		"--sha256", hash(readPrivateBinary(t, binary)), "--licenses", "/licenses", "--codex-plugin-assets", "/repo", "--codex-plugin-sha256", assetHash)
	install.Env, install.Stdout, install.Stderr = v.environment, log, log
	if install.Run() != nil || hash(readPrivateBinary(t, filepath.Join(prefix, "components/node/bin/cicada"))) != hash(readPrivateBinary(t, binary)) {
		t.Fatal("cold control real file installation failed")
	}
	return nativePeerActors{prefix: prefix, environment: v.environment, log: log, outbox: filepath.Join(filepath.Dir(v.mcpState), "outbox.sqlite3")}
}

// Real App-approved original Node, real TCP Hub and persistent production DB.
// No Host, native Thread, model call, synthetic Owner signer or SQL grant.
func TestN3OwnerGroupsColdRevocationLifecycleControl(t *testing.T) {
	if os.Getenv("CICADA_N3_CICADA_BINARY") == "" {
		t.Skip("requires the existing disposable N3 product fixture")
	}
	for _, kind := range []string{"OwnerKey", "NodeBinding"} {
		t.Run(kind, func(t *testing.T) {
			v := newCodexProductFixture(t, "1s")
			actors := ownerGroupsColdControlActors(t, v)
			closeLocalDomainApp(t, v)
			db := must(store.New(filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3")))
			if kind == "OwnerKey" {
				key := must(db.GetOwnerApprovalKey(v.original.Account.OwnerID, v.original.Account.LocalOwnerKeyID))
				if key.State != store.OwnerApprovalKeyActive {
					t.Fatal("cold control lacks its actual active original Owner key")
				}
				must(db.RevokeOwnerApprovalKeyLocal(key.OwnerID, key.KeyID, key.Version))
			} else {
				must(db.RevokeNodeDeviceBinding(v.original.Account.OwnerID, v.bound.BindingID, int64(v.bound.BindingVersion)))
			}
			if db.Close() != nil {
				t.Fatal("cold control revocation Store did not close")
			}
			from := len(v.f.proxy.snapshot())
			observed := restartOwnerGroupsRevokedNode(t, v, actors)
			if observed.Node.State != "EXITED" || observed.Node.ExitCode == nil || *observed.Node.ExitCode != 1 ||
				len(observed.AuthRefusals) == 0 || observed.Stderr.TerminalReason == "UNKNOWN" {
				t.Fatal("cold control has not observed a definite original credential-rejection exit")
			}
			denials := 0
			for _, ex := range v.f.proxy.snapshot()[from:] {
				if ex.Forwarded && (ex.Status == 401 || ex.Status == 403) &&
					(ex.Path == "/v2/node/control/rpc" || strings.HasPrefix(ex.Path, "/v2/relay/nodes/"+v.actualNode.id+"/")) {
					denials++
				}
			}
			if denials == 0 {
				t.Fatal("cold auth-rejection control lacks an actual original-Node HTTP refusal")
			}
			t.Logf("OWNER_GROUPS_COLD_AUTH_REJECTION authority=%s actual_Node_HTTP_refusals=%d", kind, denials)

			// Actual CLI abnormal exit against the same live Hub cannot be accepted
			// merely because its exit code happens to equal the auth-denial code.
			private := must(os.CreateTemp(v.root, "private-cold-abnormal-stderr-*.log"))
			t.Cleanup(func() { private.Close() })
			command := exec.Command(filepath.Join(actors.prefix, "components/node/bin/cicada"), "machine", "agent", "--synthetic-cold-control-invalid-flag")
			command.Env, command.Stderr = v.environment, private
			badStarted := time.Now()
			bad := startProcess(t, command)
			select {
			case <-bad.done:
			case <-time.After(5 * time.Second):
				t.Fatal("bounded abnormal CLI control did not exit")
			}
			abnormal := ownerGroupsObserveCold(v, actors.prefix, private.Name(), observed.Before, badStarted)
			abnormal.Node = ownerGroupsColdProcessState(bad)
			if ownerGroupsColdRefusal(abnormal) != "NODE_EXIT_NOT_PROVEN_AUTH_REJECTION" {
				t.Fatal("an abnormal original CLI exit passed the cold gate")
			}
			t.Logf("OWNER_GROUPS_COLD_NEGATIVE kind=ABNORMAL_EXIT diagnostic=%s", must(json.Marshal(abnormal)))
			changed := observed
			changed.After.KeySHA256 = hash([]byte("SYNTHETIC_CHANGED_KEY_DIGEST_ONLY_NO_FILE_WRITE"))
			if ownerGroupsColdRefusal(changed) != "ORIGINAL_IDENTITY_CHANGED_OR_UNKNOWN" {
				t.Fatal("cold gate accepted a changed original key digest")
			}
			v.f.hub.kill(t)
			// Keep the actual valid auth-denial evidence while changing only the
			// freshly observed Hub/Node liveness and original identity snapshot.
			unavailable := observed
			unavailable.Observed = time.Now().UTC().Format(time.RFC3339Nano)
			unavailable.Node, unavailable.Hub = ownerGroupsColdProcessState(v.actualNode.process), ownerGroupsColdProcessState(v.f.hub)
			unavailable.After = ownerGroupsColdOriginalIdentity(v, actors.prefix)
			if ownerGroupsColdRefusal(unavailable) != "HUB_NOT_RUNNING" {
				t.Fatal("cold gate accepted an unavailable actual Hub")
			}
			t.Logf("OWNER_GROUPS_COLD_NEGATIVE kind=HUB_STOPPED diagnostic=%s", must(json.Marshal(unavailable)))
			t.Logf("OWNER_GROUPS_COLD_CONTROL authority=%s actual_App_and_Node=true original_identity_preserved=true auth_rejection_exit=true abnormal_exit_denied=true Hub_unavailable_denied=true native_Threads_started=0 M7_accepted=false", kind)
		})
	}
}

func TestN3OwnerGroupsColdDiagnosticChild(t *testing.T) {
	if os.Getenv("CICADA_N3_SYNTHETIC_COLD_PANIC") == "1" {
		panic("SYNTHETIC_COLD_SECRET_DO_NOT_EXPORT")
	}
}

// Diagnostic privacy/negative oracle only, never product revocation acceptance.
func TestN3OwnerGroupsColdDiagnosticDoesNotAcceptUnknownExit(t *testing.T) {
	const secret = "SYNTHETIC_COLD_SECRET_DO_NOT_EXPORT"
	const prefix = "Node credential was revoked or rotated; stopping machine agent: Hub API returned "
	for _, test := range []struct {
		name, body, reason string
	}{
		{"unauthorized", prefix + "401 Unauthorized: " + secret + "\n", "NODE_CREDENTIAL_REVOKED_HTTP_401"},
		{"forbidden", prefix + "403 Forbidden: " + secret + "\n", "NODE_CREDENTIAL_REVOKED_HTTP_403"},
		{"unrelated", "unrelated 401 Unauthorized: " + secret + "\n", "UNKNOWN"},
		{"earlier_only", prefix + "401 Unauthorized: " + secret + "\nother failure\n", "UNKNOWN"},
		{"wrong_status", prefix + "500 Internal Server Error: " + secret + "\n", "UNKNOWN"},
		{"panic_then_marker", "panic: " + secret + "\n" + prefix + "401 Unauthorized: redacted\n", "UNKNOWN"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-stderr")
			if os.WriteFile(path, []byte(test.body), 0600) != nil {
				t.Fatal("synthetic private stderr unavailable")
			}
			d := ownerGroupsColdStderrState(path)
			encoded := must(json.Marshal(d))
			if d.TerminalReason != test.reason || d.ReadCode != "COMPLETE" || bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, []byte(path)) {
				t.Fatal("cold stderr closed classification/privacy mismatch")
			}
		})
	}
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if ownerGroupsColdStderrState(missing).ReadCode != "UNAVAILABLE" {
		t.Fatal("missing stderr became an observed auth result")
	}
	large := filepath.Join(root, "oversized")
	if os.WriteFile(large, bytes.Repeat([]byte("x"), 65537), 0600) != nil || ownerGroupsColdStderrState(large).ReadCode != "OVERSIZED" {
		t.Fatal("oversized stderr was not bounded")
	}
	link := filepath.Join(root, "symlink")
	if os.Symlink(large, link) != nil || ownerGroupsColdStderrState(link).ReadCode != "NON_REGULAR" {
		t.Fatal("symlink stderr was followed")
	}
	private := must(os.CreateTemp(root, "private-panic-stderr-*.log"))
	t.Cleanup(func() { private.Close() })
	command := exec.Command(os.Args[0], "-test.run=^TestN3OwnerGroupsColdDiagnosticChild$")
	command.Env = append(os.Environ(), "CICADA_N3_SYNTHETIC_COLD_PANIC=1")
	command.Stdout, command.Stderr = private, private
	child := startProcess(t, command)
	select {
	case <-child.done:
	case <-time.After(5 * time.Second):
		t.Fatal("private diagnostic panic child did not exit")
	}
	panicState := ownerGroupsColdStderrState(private.Name())
	if !panicState.PanicReported || panicState.TerminalReason != "UNKNOWN" || bytes.Contains(must(json.Marshal(panicState)), []byte(secret)) {
		t.Fatal("actual panic became a credential-rejection result or leaked its body")
	}
	one := 1
	digest := hash([]byte("SYNTHETIC_COLD_PRIVACY_ORACLE_ONLY"))
	identity := ownerGroupsColdIdentity{ReadCode: "COMPLETE", RootSHA256: digest, UserRootSHA256: digest, KeySHA256: digest, CredentialSHA256: digest, BindingSHA256: digest}
	base := ownerGroupsColdObservation{Node: ownerGroupsColdProcess{State: "EXITED", ExitCode: &one}, Hub: ownerGroupsColdProcess{State: "RUNNING"},
		Before: identity, After: identity, Stderr: panicState}
	if ownerGroupsColdRefusal(base) != "STDERR_UNKNOWN_OR_PANIC" {
		t.Fatal("cold gate accepted an actual panic")
	}
	base.Stderr = ownerGroupsColdStderr{ReadCode: "COMPLETE", TerminalReason: "UNKNOWN"}
	if ownerGroupsColdRefusal(base) != "NODE_EXIT_NOT_PROVEN_AUTH_REJECTION" {
		t.Fatal("cold gate accepted an unclassified nonzero exit")
	}
	base.Stderr.TerminalReason = "NODE_CREDENTIAL_REJECTION_REPORTED"
	if ownerGroupsColdRefusal(base) != "NODE_EXIT_NOT_PROVEN_AUTH_REJECTION" {
		t.Fatal("a fixed stderr marker without actual post-start HTTP auth refusal passed the cold gate")
	}
}
