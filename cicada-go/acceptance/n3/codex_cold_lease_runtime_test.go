package n3_test

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

type coldCLIResult struct {
	Status          string             `json:"status"`
	Failure         string             `json:"failure_category"`
	SID             string             `json:"native_session_id"`
	Record          string             `json:"native_record"`
	LiteralRequests int                `json:"literal_provider_requests"`
	Requests        []json.RawMessage  `json:"provider_http_requests"`
	Actor           fabric.NetworkCard `json:"host_actor"`
	GuardDenied     bool               `json:"host_current_guard_denied"`
}

func (v *codexProductFixture) coldCLI(t *testing.T, phase, operation string, options map[string]any) coldCLIResult {
	t.Helper()
	config, result := filepath.Join(v.root, "private-"+phase+"-config.json"), filepath.Join(v.root, "private-"+phase+"-result.json")
	values := map[string]any{"root": v.root, "workspace": v.workspace, "codex_home": v.codexHome, "environment": v.environment,
		"codex_binary": "/tools/codex", "codex_sha256": "399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215",
		"marketplace": "/repo", "step": phase, "operation": operation, "result": result, "require_unique_literal_titles": true}
	for key, value := range options {
		values[key] = value
	}
	writeJSON(t, config, values)
	log := must(os.OpenFile(filepath.Join(v.root, "private-"+phase+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command("/usr/bin/python3", "/qa/scripts/fixtures/native-pair/codex_product_cli.py", config)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = v.environment, v.workspace, log, log
	p := startProcess(t, cmd)
	select {
	case <-p.done:
	case <-time.After(120 * time.Second):
		t.Fatal("actual cold CLI phase exceeded deadline", phase)
	}
	var reply coldCLIResult
	readJSON(t, result, &reply)
	if p.cmd.ProcessState.ExitCode() != 0 || reply.Status != "SCOPED_PASS" {
		t.Logf("COLD_CLI phase=%s failure_category=%q exit=%d", phase, reply.Failure, p.cmd.ProcessState.ExitCode())
		t.Fatal("actual cold CLI phase failed", phase)
	}
	if operation != "host-whoami" && (reply.LiteralRequests != 0 || len(reply.Requests) != 0 || reply.SID == "") {
		t.Fatal("cold literal phase used a provider or lacks actual native identity")
	}
	return reply
}

// Only public fields are decoded. The actual private token is never copied,
// forwarded by the parent, or used to manufacture a Join/consent.
type coldSession struct {
	Scope        string `json:"scope"`
	Origin       string `json:"api_origin"`
	SID          string `json:"native_session_id"`
	Node         string `json:"node_id"`
	Workspace    string `json:"workspace"`
	Group        string `json:"group_id"`
	Endpoint     string `json:"endpoint_id"`
	Binding      string `json:"binding_id"`
	Epoch        uint64 `json:"binding_epoch"`
	Lease        string `json:"lease_expires_at"`
	path, digest string
}

func (v *codexProductFixture) coldSession(t *testing.T, sid string) coldSession {
	t.Helper()
	paths := must(filepath.Glob(filepath.Join(filepath.Dir(v.mcpState), "scopes", "*.json")))
	var found []coldSession
	for _, path := range paths {
		raw := readPrivate(t, path)
		var disk struct {
			Version  int           `json:"version"`
			Sessions []coldSession `json:"sessions"`
		}
		err := json.Unmarshal(raw, &disk)
		if err != nil {
			clear(raw)
			t.Fatal("actual persisted scope is invalid")
		}
		for _, session := range disk.Sessions {
			if session.SID == sid {
				session.path, session.digest = path, hash(raw)
				found = append(found, session)
			}
		}
		clear(raw)
	}
	if len(found) != 1 {
		t.Fatal("actual native SID lacks one original persisted Join scope")
	}
	s := found[0]
	if s.Origin != v.f.cfg.Origin || s.Node != v.actualNode.id || s.Workspace != v.workspace || s.Scope == "" || s.Group == "" || s.Endpoint == "" || s.Binding == "" || s.Epoch == 0 {
		t.Fatal("actual persisted Join changed its original native coordinates")
	}
	return s
}

type coldMarker struct {
	State     string `json:"state"`
	Frozen    string `json:"frozen_digest"`
	Known     string `json:"known_lease_expires_at"`
	Ceiling   string `json:"peer_ceiling"`
	Operation string `json:"join_operation_id"`
	Join      struct {
		SID       string `json:"native_session_id"`
		Workspace string `json:"workspace"`
		Slot      string `json:"slot"`
	} `json:"join"`
}

func (v *codexProductFixture) coldMarkers(t *testing.T) map[string]coldMarker {
	t.Helper()
	var state struct {
		Markers map[string]coldMarker `json:"managed_pair_leases"`
	}
	readJSON(t, v.actualNode.statePath(), &state)
	if len(state.Markers) != 2 {
		t.Fatal("actual named connects did not retain exactly two bounded original lease records")
	}
	return state.Markers
}

func (v *codexProductFixture) restartColdNode(t *testing.T) {
	t.Helper()
	id := v.actualNode.id
	v.actualNode.kill(t)
	readyFrom := len(v.f.proxy.snapshot())
	v.actualNode = startNodeProcessEnvironment(t, v.f, id, false, v.environment)
	bound := v.actualNode.awaitState(t, v.f, true)
	if bound.BindingID != v.bound.BindingID || bound.BindingVersion != v.bound.BindingVersion || bound.NodeKeyEpoch != v.bound.NodeKeyEpoch || bound.NodeKeyID != v.bound.NodeKeyID || bound.NodeFingerprint != v.bound.NodeFingerprint {
		t.Fatal("cold Node restart replaced its approved original binding/key")
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range v.f.proxy.snapshot()[readyFrom:] {
			if ex.Method == http.MethodPost && ex.Path == "/v2/relay/nodes/"+id+"/claim" && ex.Forwarded && ex.Status == http.StatusOK {
				return
			}
		}
		if !v.actualNode.running() {
			v.actualNode.reportFailure(t)
			t.Fatal("cold original Node exited during restart")
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.actualNode.reportFailure(t)
	t.Fatal("cold original Node bridge did not reconcile after restart")
}

func (v *codexProductFixture) coldOwnerPin(t *testing.T) {
	t.Helper()
	publicPath := filepath.Join(v.root, "actual-app-owner-public.json")
	s := v.do(appcore.Action{Kind: appcore.ActionExportOwnerPublic, PublicExportPath: publicPath})
	var public e2ee.PublicIdentity
	readJSON(t, publicPath, &public)
	if public.ID != s.Account.LocalOwnerKeyID || must(nodekeys.PeerKeyFingerprint(public)) != s.Account.OwnerPeerFingerprint {
		t.Fatal("actual exported Owner public identity differs from the actual App display")
	}
	v.actualNode.kill(t)
	cmd := exec.Command(os.Getenv("CICADA_N3_CICADA_BINARY"), "machine", "trust-owner-key", "--id", v.actualNode.id, "--state-dir", v.actualNode.state, "--writer-root", v.actualNode.state,
		"--owner-id", s.Account.OwnerID, "--public", publicPath, "--expect-key-id", s.Account.LocalOwnerKeyID, "--expect-fingerprint", s.Account.OwnerPeerFingerprint)
	cmd.Env = v.environment
	if cmd.Run() != nil {
		t.Fatal("existing independent public Owner pin command failed")
	}
	v.restartColdNode(t)
	t.Log("COLD_PRECONDITION actual_App_public_export=true explicit_existing_Owner_pin=true manual_channel=true automatic_FB03=false no_private_Owner_key=true")
}

func retainColdCLIDiagnostics(t *testing.T, v *codexProductFixture) {
	t.Helper()
	destination := filepath.Join("/state/private-cold-diagnostics", hash([]byte(v.root))[:16])
	if os.MkdirAll(destination, 0700) != nil {
		t.Error("cold private diagnostics unavailable")
		return
	}
	paths := must(filepath.Glob(filepath.Join(v.root, "cli-*")))
	for _, sourceRoot := range paths {
		_ = filepath.WalkDir(sourceRoot, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			info, e := entry.Info()
			if e != nil || !info.Mode().IsRegular() || info.Size() > harnessPacketLimit {
				return nil
			}
			relative, e := filepath.Rel(v.root, path)
			if e != nil {
				return e
			}
			target := filepath.Join(destination, relative)
			if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
				return e
			}
			raw := readPrivate(t, path)
			atomicPrivate(t, target, raw)
			clear(raw)
			return nil
		})
	}
	for _, path := range must(filepath.Glob(filepath.Join(v.root, "private-*-result.json"))) {
		raw := readPrivate(t, path)
		atomicPrivate(t, filepath.Join(destination, filepath.Base(path)), raw)
		clear(raw)
	}
	t.Log("COLD_PRIVATE_DIAGNOSTICS retained=true credentials_or_vaults_exported=false")
}

func TestN3CodexProductColdLeaseBeforeFirstTool(t *testing.T) {
	v := newCodexProductFixture(t, "1s")
	t.Cleanup(func() { retainColdCLIDiagnostics(t, v) })
	v.coldOwnerPin(t)
	canary := filepath.Join(v.workspace, "synthetic-native-workspace-canary.txt")
	atomicPrivate(t, canary, []byte("SYNTHETIC original native workspace; retain through cold lease and revoke\n"))
	canaryHash := hash(readPrivate(t, canary))
	label := "SyntheticColdPair"
	prepared := v.do(appcore.Action{Kind: appcore.ActionPreparePair, Pair: appcore.PairAction{Label: label}})
	if prepared.Pair.PairID == "" || prepared.Pair.ReviewID == "" {
		t.Fatal("actual App lacks its original bootstrap review")
	}
	created := v.do(appcore.Action{Kind: appcore.ActionCompletePair, Pair: appcore.PairAction{PairID: prepared.Pair.PairID, ReviewID: prepared.Pair.ReviewID, ConfirmBootstrap: true}})
	if created.Pair.State != string(wire.NativePairWaitingJoin) || created.Pair.NodeID != v.actualNode.id {
		t.Fatal("actual App did not bootstrap only its original empty Pair")
	}
	a := v.coldCLI(t, "cold-setup", "literal-setup", nil)
	b := v.coldCLI(t, "cold-register-b", "literal-command", map[string]any{"prompt": "cicada join SyntheticColdB"})
	if a.SID == b.SID {
		t.Fatal("actual native Runtime reused the original Thread identity")
	}
	for _, selection := range []struct{ sid, slot string }{{a.SID, "A"}, {b.SID, "B"}} {
		v.coldCLI(t, "cold-connect-"+strings.ToLower(selection.slot), "literal-command", map[string]any{"resume_sid": selection.sid, "prompt": "cicada connect " + label + " " + selection.slot})
	}
	sessions := [2]coldSession{v.coldSession(t, a.SID), v.coldSession(t, b.SID)}
	observed := v.do(appcore.Action{Kind: appcore.ActionRefreshPair})
	if !observed.Pair.Current || observed.Pair.State != string(wire.NativePairWaitingConsent) {
		t.Fatal("actual App lacks two current original native candidates")
	}
	for i, slot := range observed.Pair.Slots {
		s := sessions[i]
		if slot.NativeSessionID != s.SID || slot.EndpointID != s.Endpoint || slot.BindingID != s.Binding || slot.BindingEpoch != s.Epoch || slot.CandidateKeyID == "" || slot.ConsentRecorded {
			t.Fatal("authenticated current Pair SID/Endpoint/BindingEpoch differs from actual CLI record/cache")
		}
	}
	reviewed := v.do(appcore.Action{Kind: appcore.ActionPreparePairConsent, Pair: appcore.PairAction{PairID: created.Pair.PairID}})
	first := v.do(appcore.Action{Kind: appcore.ActionApprovePairSlot, Pair: appcore.PairAction{PairID: created.Pair.PairID, ReviewID: reviewed.Pair.ReviewID, Slot: "A", ConfirmSlot: true}})
	active := v.do(appcore.Action{Kind: appcore.ActionApprovePairSlot, Pair: appcore.PairAction{PairID: created.Pair.PairID, ReviewID: first.Pair.ReviewID, Slot: "B", ConfirmSlot: true}})
	if active.Pair.State != string(wire.NativePairActive) || !active.Pair.Current {
		t.Fatal("actual App dual consent did not activate its original Pair")
	}
	original := v.coldMarkers(t)
	deadline := time.Time{}
	for _, s := range sessions {
		end := must(time.Parse(time.RFC3339Nano, s.Lease))
		remaining := time.Until(end)
		if remaining < 4*time.Minute || remaining > 5*time.Minute+5*time.Second {
			t.Fatal("cold test did not observe an unshortened original default five-minute lease")
		}
		if end.After(deadline) {
			deadline = end
		}
	}
	v.restartColdNode(t)
	startTrace := len(v.f.proxy.snapshot())
	coldStart := time.Now()
	t.Logf("COLD_LEASE_START wall_UTC=%s original_latest_deadline_UTC=%s no_shortening=true first_MCP_tool_started=false", coldStart.UTC().Format(time.RFC3339Nano), deadline.UTC().Format(time.RFC3339Nano))
	deadline = deadline.Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !v.actualNode.running() {
			v.actualNode.reportFailure(t)
			t.Fatal("actual Node exited during original cold lease")
		}
		time.Sleep(10 * time.Second)
		t.Logf("COLD_LEASE elapsed_seconds=%.0f original_deadline_crossed=%t real_model_turns=0 first_MCP_tool_started=false", time.Since(coldStart).Seconds(), !time.Now().Before(deadline.Add(-10*time.Second)))
	}
	currentMarkers := v.coldMarkers(t)
	for id, old := range original {
		current, ok := currentMarkers[id]
		if !ok || old.Frozen == "" || current.Frozen != old.Frozen || current.Operation != old.Operation || current.Join != old.Join || current.State != "ACTIVE" || !time.Now().Before(must(time.Parse(time.RFC3339Nano, current.Known))) || current.Known == old.Known {
			t.Fatal("actual keeper did not maintain only its frozen original lease through Node restart/cold wait")
		}
	}
	beats := map[string]int{}
	for _, ex := range v.f.proxy.snapshot()[startTrace:] {
		if ex.Path == "/v2/fabric/whoami" {
			t.Fatal("cold interval performed a business identity query before the first actual Host tool")
		}
		if ex.Method == http.MethodPost && ex.Path == "/v2/fabric/heartbeat" && ex.Status == http.StatusOK {
			var actor fabric.Actor
			if json.Unmarshal(ex.response, &actor) == nil {
				beats[actor.EndpointID]++
			}
		}
	}
	for _, s := range sessions {
		if beats[s.Endpoint] < 2 || hash(readPrivate(t, s.path)) != s.digest {
			t.Fatal("cold renewal lacked actual endpoint responses or rewrote original caller cache")
		}
	}
	expected := map[string]any{"endpoint_id": sessions[0].Endpoint, "group_id": sessions[0].Group, "native_session_id": a.SID, "node_id": v.actualNode.id, "workspace": v.workspace, "binding_id": sessions[0].Binding, "binding_epoch": sessions[0].Epoch}
	v.coldCLI(t, "cold-first-tool", "host-whoami", map[string]any{"resume_sid": a.SID, "expected_actor": expected})
	refreshed := v.do(appcore.Action{Kind: appcore.ActionRefreshPair})
	revoked := v.do(appcore.Action{Kind: appcore.ActionRevokePair, Pair: appcore.PairAction{PairID: created.Pair.PairID, ReviewID: refreshed.Pair.StateReviewID, ConfirmRevoke: true}})
	if revoked.Pair.State != string(wire.NativePairRevoked) {
		t.Fatal("actual App did not revoke the original Pair")
	}
	time.Sleep(35 * time.Second)
	for _, m := range v.coldMarkers(t) {
		if m.State != "STOPPED" {
			t.Fatal("actual keeper retained renewable state after current authorization was revoked")
		}
	}
	v.coldCLI(t, "cold-revoked-tool", "host-whoami", map[string]any{"resume_sid": a.SID, "expect_guard_denied": true})
	if hash(readPrivate(t, canary)) != canaryHash {
		t.Fatal("cold/revocation flow changed the original native workspace")
	}
	for _, record := range []string{a.Record, b.Record} {
		if info, err := os.Lstat(record); err != nil || !info.Mode().IsRegular() {
			t.Fatal("cold/revocation flow removed an original native record")
		}
	}
	t.Logf("COLD_LEASE_PASS actual_default_five_minutes=true cold_seconds=%.0f Node_restart=true actual_App_dual_consent=true actual_SID_Endpoint_BindingEpoch=true actual_first_Host_whoami=true revocation_denied=true manual_Owner_pin_prerequisite=true native_queue_model=NOT_RUN Windows=NOT_RUN", time.Since(coldStart).Seconds())
}
