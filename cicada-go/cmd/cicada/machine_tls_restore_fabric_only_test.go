package main

// These children are disposable test-binary dispatchers. They never construct
// Control, start a model, clear a recovery hold, or initialize a deployment.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

const tlsRestoreChildEnv = "CICADA_SYNTHETIC_TLS_RESTORE_CHILD"

type tlsRestoreQueryResult struct {
	RestoreDigest string                  `json:"restore_digest"`
	PlanDigest    string                  `json:"plan_digest"`
	AgentMayStart bool                    `json:"agent_may_start"`
	Status        nodewire.RecoveryStatus `json:"status"`
}

func TestMachineTLSRestoreFabricOnlyNativeCLI(t *testing.T) {
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" || !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal("requested native profile unavailable")
		}
		t.Log("typed unavailable: native restore/CLI gate not executed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMachineTLSRestoreFabricOnlyChild$", "-test.v")
	cmd.Env = tlsRestoreEnvironment(tlsRestoreChildEnv+"=scenario", "CICADA_SYNTHETIC_TLS_RESTORE_ROOT="+t.TempDir())
	// A timed-out scenario cannot orphan its Hub/CLI grandchildren while the
	// parent removes their private fixture directory. Successful children join
	// normally; only the failure deadline kills the isolated process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	output, err := cmd.CombinedOutput()
	// Children print only public phase names. Command JSON and sealed packets
	// remain in private buffers, including on failure.
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "phase=") {
			t.Log(line)
		}
	}
	if err != nil {
		t.Fatal("isolated full TLS restore gate failed; sensitive child output suppressed")
	}
}

func TestMachineTLSRestoreFabricOnlyChild(t *testing.T) {
	switch os.Getenv(tlsRestoreChildEnv) {
	case "scenario":
		tlsRestoreScenario(t, os.Getenv("CICADA_SYNTHETIC_TLS_RESTORE_ROOT"))
	case "cli":
		runtimeStartupDNS(t)
		var args []string
		if json.Unmarshal([]byte(os.Getenv("CICADA_SYNTHETIC_TLS_RESTORE_ARGS")), &args) != nil {
			os.Exit(2)
		}
		os.Args = append([]string{"cicada"}, args...)
		main()     // Actual production dispatcher; failures exit nonzero.
		os.Exit(0) // Keep the command's JSON separate from the Go test footer.
	case "hub":
		var args []string
		if json.Unmarshal([]byte(os.Getenv("CICADA_SYNTHETIC_TLS_RESTORE_ARGS")), &args) != nil {
			t.Fatal("phase=hub-invalid-arguments")
		}
		started := time.Now()
		t.Log("phase=hub-start")
		if err := serve(args); err != nil { // Actual --fabric-only dispatcher.
			t.Fatal("phase=hub-serve-failed")
		}
		t.Logf("phase=hub-joined elapsed=%s", time.Since(started).Round(time.Millisecond))
	}
}

func tlsRestoreEnvironment(extra ...string) []string {
	// No caller's resident Hub, identity path or transport config is inherited.
	var env []string
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(key, "CICADA_") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, extra...)
}

func tlsRestoreCLI(t *testing.T, success bool, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal("CLI arguments")
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMachineTLSRestoreFabricOnlyChild$")
	cmd.Env = tlsRestoreEnvironment(tlsRestoreChildEnv+"=cli", "CICADA_SYNTHETIC_TLS_RESTORE_ARGS="+string(encoded))
	var output, diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostics
	err = cmd.Run()
	if ctx.Err() != nil || (err == nil) != success || (!success && output.Len() != 0) {
		t.Fatal("actual CLI exit/output contract failed; payload and diagnostics suppressed")
	}
	return output.Bytes()
}

func tlsRestoreAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("reserve synthetic listener")
	}
	address := l.Addr().String()
	if l.Close() != nil {
		t.Fatal("release synthetic reservation")
	}
	return address
}

type tlsRestoreHub struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan error
	front  string
	closed bool
}

func tlsRestoreStartHub(t *testing.T, hubDir, configPath string) *tlsRestoreHub {
	t.Helper()
	front := tlsRestoreAddress(t)
	_, port, _ := net.SplitHostPort(front)
	args, _ := json.Marshal([]string{"--host", "127.0.0.1", "--port", port, "--fabric-only", "--node-pqtls-config", configPath})
	ctx, cancel := context.WithTimeout(context.Background(), 280*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMachineTLSRestoreFabricOnlyChild$", "-test.v")
	cmd.Env = tlsRestoreEnvironment(tlsRestoreChildEnv+"=hub", "CICADA_SYNTHETIC_TLS_RESTORE_ARGS="+string(args), "CICADA_STATE_DIR="+hubDir)
	// The public production listener messages are sufficient for readiness.
	// Discard all child diagnostics to avoid emitting any Store/key payload.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal("start actual Fabric-only child")
	}
	h := &tlsRestoreHub{cmd: cmd, cancel: cancel, done: make(chan error, 1), front: front}
	go func() { h.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !h.closed {
			h.cmd.Process.Kill()
			<-h.done
			h.cancel()
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-h.done:
			h.closed = true
			h.cancel()
			t.Fatal("actual Fabric-only child exited before readiness")
		default:
		}
		conn, err := net.DialTimeout("tcp", front, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return h // Both listeners are acquired before the front starts.
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual Fabric-only child readiness deadline")
	return nil
}

func tlsRestoreRejectHubStartup(t *testing.T, hubDir, configPath string) {
	t.Helper()
	front := tlsRestoreAddress(t)
	_, port, _ := net.SplitHostPort(front)
	args, _ := json.Marshal([]string{"--host", "127.0.0.1", "--port", port, "--fabric-only", "--node-pqtls-config", configPath})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMachineTLSRestoreFabricOnlyChild$")
	cmd.Env = tlsRestoreEnvironment(tlsRestoreChildEnv+"=hub", "CICADA_SYNTHETIC_TLS_RESTORE_ARGS="+string(args), "CICADA_STATE_DIR="+hubDir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err == nil || ctx.Err() != nil {
		t.Fatal("unsafe/missing existing Hub identity was accepted or hung")
	}
}

func (h *tlsRestoreHub) stop(t *testing.T) {
	t.Helper()
	if h.closed {
		t.Fatal("duplicate fixture shutdown")
	}
	if err := h.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("signal actual Fabric-only shutdown")
	}
	select {
	case err := <-h.done:
		h.closed = true
		h.cancel()
		if err != nil {
			t.Fatal("actual Fabric-only child did not join with exit zero")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("actual Fabric-only child shutdown deadline")
	}
}

func tlsRestoreRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read disposable fixture")
	}
	return b
}

func tlsRestoreJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode disposable fixture")
	}
	runtimeStartupWrite(t, path, b)
}

func tlsRestoreTrees(t *testing.T, f runtimeStartupFixture) string {
	t.Helper()
	a, err := recoveryTreeDigest(f.StateRoot)
	if err != nil {
		t.Fatal("inventory restored state")
	}
	b, err := recoveryTreeDigest(f.WriterRoot)
	if err != nil {
		t.Fatal("inventory retained WriterRoot")
	}
	return a + b
}

// Fingerprint the logical admission/outbox tables, rather than SQLite's
// transient WAL bytes. This reader never migrates or checkpoints a live Hub.
func tlsRestoreReceipts(t *testing.T, dbPath string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal("read actual Hub receipts")
	}
	defer db.Close()
	names, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'node_control%rpc%' ORDER BY name`)
	if err != nil {
		t.Fatal("receipt inventory")
	}
	var tables []string
	for names.Next() {
		var name string
		if names.Scan(&name) != nil {
			t.Fatal("receipt table name")
		}
		tables = append(tables, name)
	}
	if names.Err() != nil || names.Close() != nil || len(tables) < 2 {
		t.Fatal("missing actual admission tables")
	}
	h := sha256.New()
	for _, table := range tables {
		rows, err := db.Query(`SELECT * FROM "` + table + `" ORDER BY rowid`)
		if err != nil {
			t.Fatal("receipt rows")
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal("receipt columns")
		}
		fmt.Fprintln(h, table)
		for rows.Next() {
			values, targets := make([]any, len(columns)), make([]any, len(columns))
			for i := range values {
				targets[i] = &values[i]
			}
			if rows.Scan(targets...) != nil {
				t.Fatal("receipt scan")
			}
			b, err := json.Marshal(values)
			if err != nil {
				t.Fatal("receipt fingerprint")
			}
			h.Write(b)
		}
		if rows.Err() != nil || rows.Close() != nil {
			t.Fatal("receipt read completion")
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func tlsRestoreSeed(t *testing.T, f runtimeStartupFixture) []nodewire.RecoveryOperationQuery {
	t.Helper()
	runtimeStartupPersistApplicationState(t, f)
	ledger, err := nodeinbox.OpenProviderAdmissionLedger(filepath.Join(f.WriterRoot, "node-provider-admission.sqlite3"))
	if err != nil {
		t.Fatal("synthetic shared admission ledger")
	}
	if _, err = ledger.AdmitProviderAttempt(context.Background(), nodeinbox.ProviderAdmissionRequest{ExecutionID: "synthetic-restore-provider", ProviderID: "synthetic-no-runtime", AdmissionIntent: strings.Repeat("a", 64)}); err != nil || ledger.Close() != nil {
		t.Fatal("synthetic admission witness")
	}
	history, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(f.WriterRoot, "node-native-context-history.sqlite3"))
	if err != nil || history.Close() != nil {
		t.Fatal("synthetic shared history")
	}
	crypto, err := nodekeys.OpenCryptoState(machineNodeStateDir(f.StateRoot, f.Binding.NodeID))
	if err != nil {
		t.Fatal("synthetic crypto state")
	}
	for i := 0; i < 9; i++ {
		if _, err := crypto.ReserveOutboundSequence(context.Background(), "synthetic-endpoint", "synthetic-stream"); err != nil {
			t.Fatal("synthetic counter witness")
		}
	}
	if _, err := crypto.AcceptInbound(context.Background(), "synthetic-endpoint", "synthetic-peer", "synthetic-replay", 11, []byte(`{"synthetic":"opaque"}`)); err != nil || crypto.Close() != nil {
		t.Fatal("synthetic replay witness")
	}
	db, err := store.New(f.DBPath)
	if err != nil {
		t.Fatal("seed actual Store receipts")
	}
	defer db.Close()
	b := machineTLSWireBinding(nodetransport.TLSLocalBinding{Control: *f.Binding})
	var queries []nodewire.RecoveryOperationQuery
	for _, seq := range []uint64{7, 8, 9, 40} {
		r := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: seq, OperationID: "synthetic-restore-" + strconv.FormatUint(seq, 10), Operation: "node.binding.status", SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
		packet, err := nodewire.SealRequest(f.Node, f.Hub.Public(), b, r, []byte(`{}`))
		if err != nil {
			t.Fatal("synthetic encrypted pending packet")
		}
		input := store.NodeControlRPCInput{CredentialDigest: f.Binding.CredentialDigest, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKey.ID, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: seq, OperationID: r.OperationID, Operation: r.Operation, RequestDigest: nodewire.RecoveryDigest(packet)}
		if seq != 9 {
			if _, _, err := db.BeginNodeControlRPC(input); err != nil {
				t.Fatal("synthetic actual admission")
			}
			if seq == 8 {
				if db.MarkNodeControlRPCUncertain(input) != nil {
					t.Fatal("synthetic uncertain receipt")
				}
			} else {
				responseRoute := r
				responseRoute.Direction = nodewire.DirectionResponse
				responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
				responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
				response, err := nodewire.SealResponse(f.Hub, f.Node.Public(), b, responseRoute, []byte(`{}`))
				if err != nil || db.CompleteNodeControlRPC(store.NodeControlRPCCompletion{NodeControlRPCInput: input, ResponsePacket: response}) != nil {
					t.Fatal("synthetic complete receipt")
				}
			}
		}
		if seq != 40 {
			queries = append(queries, nodewire.RecoveryOperationQuery{OperationID: r.OperationID, Sequence: seq, RequestDigest: input.RequestDigest})
		}
		if seq == 7 {
			_, statePath := machineNodeControlPaths(f.StateRoot, b.NodeID)
			var state machineNodeControlState
			if json.Unmarshal(tlsRestoreRead(t, statePath), &state) != nil {
				t.Fatal("synthetic accepted state")
			}
			state.Sequence, state.PendingSequence, state.PendingOperationID, state.PendingOperation, state.PendingPacket = seq, seq, r.OperationID, r.Operation, packet
			tlsRestoreJSON(t, statePath, state)
		}
	}
	return queries
}

func tlsRestoreScenario(t *testing.T, root string) {
	started := time.Now()
	phase := func(name string) { t.Logf("phase=%s elapsed=%s", name, time.Since(started).Round(time.Millisecond)) }
	runtimeStartupDNS(t)
	address := tlsRestoreAddress(t)
	_, port, _ := net.SplitHostPort(address)
	hubDir := filepath.Join(root, "synthetic-hub")
	f := runtimeStartupBuildScoped(t, hubDir, "https://hub.synthetic.invalid:"+port, filepath.Join(root, "retained-writer-root"), "synthetic-restore-tls-node")
	queries := tlsRestoreSeed(t, f)
	// The production Fabric-only dispatcher opens this exact existing database
	// and identity layout, not a test-constructed equivalent Handler.
	productionDB := filepath.Join(hubDir, "cicada.sqlite3")
	if os.Rename(f.DBPath, productionDB) != nil || os.MkdirAll(filepath.Join(hubDir, "e2ee"), 0700) != nil {
		t.Fatal("existing synthetic Hub layout")
	}
	f.DBPath = productionDB
	secret, err := f.Hub.MarshalBinary()
	if err != nil {
		t.Fatal("serialize existing synthetic Hub identity")
	}
	runtimeStartupWrite(t, filepath.Join(hubDir, "e2ee", "identity.json"), secret)
	runtimeStartupWrite(t, filepath.Join(hubDir, "e2ee", "node-control-identity.json"), secret)
	clear(secret)
	f.HubConfig.Listen = address
	hubConfig := filepath.Join(hubDir, "hub-pqtls.json")
	tlsRestoreJSON(t, hubConfig, f.HubConfig)
	phase("actual-owner-device-grant-stage-ack-activate-apply")
	hub := tlsRestoreStartHub(t, hubDir, hubConfig)
	phase("actual-fabric-only-hub-ready")
	backup := filepath.Join(root, "private-backup")
	var backed nodebackup.BackupReport
	if json.Unmarshal(tlsRestoreCLI(t, true, "machine", "backup", "--id", f.Binding.NodeID, "--state-dir", f.StateRoot, "--writer-root", f.WriterRoot, "--output", backup), &backed) != nil || backed.Manifest.FormatVersion != nodebackup.TLSFormatVersion || backed.Manifest.TLSMaterial == nil {
		t.Fatal("actual backup missing TLS format/material")
	}
	var verified nodebackup.Manifest
	if json.Unmarshal(tlsRestoreCLI(t, true, "machine", "verify", "--backup", backup), &verified) != nil || !verified.Complete || verified.TLSMaterial == nil || len(verified.TLSMaterial.Floors) != 1 {
		t.Fatal("actual TLS archive verification")
	}
	floorPath := filepath.Join(f.WriterRoot, ".node-tls-floors", verified.TLSMaterial.Floors[0].Path)
	floorBytes := tlsRestoreRead(t, floorPath)
	floorInfo, err := os.Lstat(floorPath)
	if err != nil {
		t.Fatal("retained floor identity")
	}
	// Synthetic crash loses the selected Node subtree and the archived shared
	// ledgers under both real maintenance locks. TLS material and the
	// independently retained floor stay. Existing unregistered shared ledgers
	// cannot be overwritten by Restore, even when their bytes match the archive.
	cap, err := nodetransport.AcquireTLSMaintenanceRead(f.StateRoot, f.WriterRoot, f.Binding.HubID, f.Binding.NodeID)
	if err != nil {
		t.Fatal("synthetic crash maintenance scope")
	}
	if os.Rename(machineNodeStateDir(f.StateRoot, f.Binding.NodeID), filepath.Join(root, "retired-private-node")) != nil {
		t.Fatal("synthetic selected-subtree crash")
	}
	for _, name := range []string{"node-provider-admission.sqlite3", "node-native-context-history.sqlite3"} {
		if os.Rename(filepath.Join(f.WriterRoot, name), filepath.Join(root, "retired-private-"+name)) != nil {
			t.Fatal("synthetic archived shared-ledger crash")
		}
	}
	if cap.Close() != nil {
		t.Fatal("release synthetic crash maintenance locks")
	}
	var restored nodebackup.RestoreReport
	if json.Unmarshal(tlsRestoreCLI(t, true, "machine", "restore", "--backup", backup, "--state-dir", f.StateRoot, "--writer-root", f.WriterRoot), &restored) != nil || !restored.Quarantined {
		t.Fatal("actual same-absolute-root quarantined restore")
	}
	phase("actual-backup-verify-restore")
	var inspection nodebackup.RecoveryInspectReport
	if json.Unmarshal(tlsRestoreCLI(t, true, "machine", "recovery", "inspect", "--backup", backup, "--state-dir", f.StateRoot, "--writer-root", f.WriterRoot), &inspection) != nil || inspection.AgentMayStart || inspection.QuarantineStatus != "pending" || inspection.CryptoState.HighestLocalSequence != 9 || inspection.CryptoState.ReplayRecords != 1 {
		t.Fatal("actual held restore inspection/counter witnesses")
	}
	plan := strings.Repeat("a", 64)
	queryArgs := []string{"machine", "recovery", "query", "--backup", backup, "--state-dir", f.StateRoot, "--writer-root", f.WriterRoot, "--plan-sha256", plan, "--node-pqtls-config", f.NodeConfigSource(t)}
	before, receipts := tlsRestoreTrees(t, f), tlsRestoreReceipts(t, f.DBPath)
	assertUnchanged := func() {
		t.Helper()
		if tlsRestoreTrees(t, f) != before || tlsRestoreReceipts(t, f.DBPath) != receipts {
			t.Fatal("read-only recovery changed keys/counters/holds/floors/receipts")
		}
		info, err := os.Lstat(floorPath)
		if err != nil || !os.SameFile(info, floorInfo) || !bytes.Equal(tlsRestoreRead(t, floorPath), floorBytes) {
			t.Fatal("independent retained TLS floor replaced or changed")
		}
	}
	checkCLI := func() tlsRestoreQueryResult {
		t.Helper()
		var result tlsRestoreQueryResult
		if json.Unmarshal(tlsRestoreCLI(t, true, queryArgs...), &result) != nil || result.AgentMayStart || result.RestoreDigest != inspection.BackupManifestSHA256 || result.PlanDigest != plan || result.Status.AcceptedHighwater != 40 || len(result.Status.Operations) != 1 || result.Status.Operations[0].State != store.NodeControlRPCComplete {
			t.Fatal("actual Fabric-only TLS CLI recovery result")
		}
		assertUnchanged()
		return result
	}
	checkCLI()
	checkCLI() // Each independent dispatcher invocation makes new random queries.
	phase("actual-cli-fresh-current-and-recovery-readonly-repeat")
	// Additional metadata queries use the same genuine held capability and
	// production query adapter; no uncertain operation is ever re-executed.
	cap, err = nodetransport.AcquireTLSMaintenanceRead(f.StateRoot, f.WriterRoot, f.Binding.HubID, f.Binding.NodeID)
	if err != nil {
		t.Fatal("held read-only recovery capability")
	}
	client, token, err := loadMachineRecoveryClient(f.StateRoot, f.Binding.NodeID)
	if err != nil {
		t.Fatal("existing restored client")
	}
	q := nodewire.RecoveryRequest{Nonce: make([]byte, 32), Origin: client.base, CredentialDigest: fabric.HashSessionCredential(token), RestoreDigest: inspection.BackupManifestSHA256, PlanDigest: plan, Operations: queries}
	if _, err := rand.Read(q.Nonce); err != nil {
		t.Fatal("fresh recovery nonce")
	}
	packet, err := nodewire.SealRecoveryRequest(f.Node, machineNodeControlBindingFromState(client), q)
	if err != nil {
		t.Fatal("seal fresh metadata-only recovery request")
	}
	hubContext := machineHubContext{HubID: f.Binding.HubID, NodeID: f.Binding.NodeID, Origin: client.base, StateDir: f.StateRoot, WriterRoot: f.WriterRoot, Token: token}
	for _, scope := range []struct{ state, writer, hub, node string }{
		{f.StateRoot + "-foreign", f.WriterRoot, f.Binding.HubID, f.Binding.NodeID},
		{f.StateRoot, f.WriterRoot + "-foreign", f.Binding.HubID, f.Binding.NodeID},
		{f.StateRoot, f.WriterRoot, "synthetic-foreign-hub", f.Binding.NodeID},
		{f.StateRoot, f.WriterRoot, f.Binding.HubID, "synthetic-foreign-node"},
	} {
		if _, err := cap.ReadAcceptedBinding(scope.state, scope.writer, scope.hub, scope.node); !errors.Is(err, nodetransport.ErrTLSInstall) {
			t.Fatal("maintenance scope widened")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	status, err := machineTLSRecoveryQuery(ctx, cap, &hubContext, f.NodeConfigSource(t), client, token, q, packet)
	cancel()
	if err != nil || len(status.Operations) != 3 || status.Operations[0].State != "COMPLETE" || status.Operations[1].State != "UNCERTAIN" || status.Operations[2].State != "NOT_RECORDED" || cap.Close() != nil {
		t.Fatal("held metadata COMPLETE/UNCERTAIN/NOT_RECORDED")
	}
	if _, err := cap.ReadAcceptedBinding(f.StateRoot, f.WriterRoot, f.Binding.HubID, f.Binding.NodeID); !errors.Is(err, nodetransport.ErrTLSRuntimeClosed) {
		t.Fatal("closed maintenance capability reused")
	}
	if err := configureMachinePQTransport(&hubContext, f.NodeConfigSource(t)); !errors.Is(err, nodetransport.ErrTLSRecoveryQuarantine) || hubContext.TLSRuntime != nil || hubContext.NodeTransport != nil {
		t.Fatal("held recovery published a normal runtime")
	}
	assertUnchanged()
	phase("metadata-three-states-no-reexecution")
	// No plaintext/front-door fallback and no restoration/startup permission.
	request, _ := http.NewRequest(http.MethodPost, "http://"+hub.front+"/v2/node/control/rpc", bytes.NewReader(packet))
	request.Header.Set("Authorization", "CicadaNode "+f.Token)
	plain := &http.Client{Timeout: 5 * time.Second}
	response, err := plain.Do(request)
	if err != nil {
		t.Fatal("public front-door negative probe")
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("plaintext recovery front-door admitted")
	}
	if code := tlsRestoreNativePOST(t, f, address, client.state.PendingPacket); code != http.StatusServiceUnavailable {
		t.Fatal("Fabric-only started ordinary Control RPC or replayed a stored result")
	}
	tlsRestoreCLI(t, false, queryArgs[:len(queryArgs)-2]...)
	for _, acquire := range []func() (io.Closer, error){
		func() (io.Closer, error) { return nodelock.AcquireWriterRootExclusive(f.WriterRoot) },
		func() (io.Closer, error) { return nodelock.AcquireMaintenanceExclusive(f.StateRoot, f.Binding.NodeID) },
	} {
		held, err := acquire()
		if err != nil {
			t.Fatal("hold actual exclusive lock")
		}
		tlsRestoreCLI(t, false, queryArgs...)
		if held.Close() != nil {
			t.Fatal("release negative lock fixture")
		}
		assertUnchanged()
	}
	for _, path := range []string{floorPath, f.NodeConfig.CertificateFile} {
		original := tlsRestoreRead(t, path)
		runtimeStartupWrite(t, path, []byte("SYNTHETIC invalid material/floor"))
		mutated := tlsRestoreTrees(t, f)
		tlsRestoreCLI(t, false, queryArgs...)
		if tlsRestoreTrees(t, f) != mutated {
			t.Fatal("rejected material/floor query wrote state")
		}
		runtimeStartupWrite(t, path, original)
		assertUnchanged()
	}
	phase("plaintext-config-floor-material-locks-denied")
	hub.stop(t)
	baseDB := tlsRestoreRead(t, f.DBPath)
	// Actual durable revocation APIs, each on the disposable reset Hub while
	// its process is stopped. No real key is rotated and Node state stays held.
	for _, negative := range []struct {
		name string
		edit func(*store.Store) error
	}{
		{"tls-revoked", func(s *store.Store) error { return s.RevokeNodeTLSGrantLocal(f.RequestID, f.ActiveVersion) }},
		{"owner-key-revoked", func(s *store.Store) error {
			_, e := s.RevokeOwnerApprovalKeyLocal(f.Binding.OwnerID, f.Binding.OwnerKeyID, 1)
			return e
		}},
		{"owner-device-revoked", func(s *store.Store) error {
			_, e := s.RevokeClientDevice(f.Binding.OwnerID, f.Binding.ClientDeviceID, 1)
			return e
		}},
		{"node-control-epoch-advanced", func(s *store.Store) error { return tlsRestoreAdvanceApplicationEpoch(s, f) }},
		{"credential-rotated", func(s *store.Store) error {
			_, digest, e := fabric.NewNodeCredential()
			if e != nil {
				return e
			}
			_, e = s.RotateNodeCredential(f.Binding.NodeID, digest)
			return e
		}},
	} {
		runtimeStartupWrite(t, f.DBPath, baseDB)
		db, err := store.New(f.DBPath)
		if err != nil {
			t.Fatal("open disposable revocation case")
		}
		if negative.edit(db) != nil || db.Close() != nil {
			t.Fatal("prepare actual revocation case")
		}
		hub = tlsRestoreStartHub(t, hubDir, hubConfig)
		deniedReceipts := tlsRestoreReceipts(t, f.DBPath)
		tlsRestoreCLI(t, false, queryArgs...)
		if tlsRestoreTrees(t, f) != before || tlsRestoreReceipts(t, f.DBPath) != deniedReceipts {
			t.Fatal("revoked current/Guard query wrote state")
		}
		hub.stop(t)
		phase(negative.name + "-denied")
	}
	runtimeStartupWrite(t, f.DBPath, baseDB)
	// Config peers only narrow current Store authority. A stale/mismatched
	// approved TLS epoch does not become current merely by editing this file.
	f.HubConfig.Peers[0].Identity.TLSEpoch++
	tlsRestoreJSON(t, hubConfig, f.HubConfig)
	hub = tlsRestoreStartHub(t, hubDir, hubConfig)
	tlsRestoreCLI(t, false, queryArgs...)
	assertUnchanged()
	hub.stop(t)
	f.HubConfig.Peers[0].Identity.TLSEpoch--
	tlsRestoreJSON(t, hubConfig, f.HubConfig)
	phase("epoch-config-cannot-authorize-denied")
	controlIdentity := filepath.Join(hubDir, "e2ee", "node-control-identity.json")
	identityBytes := tlsRestoreRead(t, controlIdentity)
	if os.Rename(controlIdentity, controlIdentity+".retired") != nil {
		t.Fatal("synthetic missing Hub identity")
	}
	tlsRestoreRejectHubStartup(t, hubDir, hubConfig)
	if _, err := os.Lstat(controlIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing Hub identity initialized by startup")
	}
	if os.Rename(controlIdentity+".retired", controlIdentity) != nil || os.Chmod(controlIdentity, 0644) != nil {
		t.Fatal("synthetic unsafe Hub identity")
	}
	tlsRestoreRejectHubStartup(t, hubDir, hubConfig)
	if info, err := os.Lstat(controlIdentity); err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("unsafe Hub identity repaired by startup")
	}
	if os.Chmod(controlIdentity, 0600) != nil {
		t.Fatal("restore synthetic identity mode")
	}
	foreign, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("synthetic foreign Hub application identity")
	}
	foreignBytes, err := foreign.MarshalBinary()
	if err != nil {
		t.Fatal("synthetic foreign Hub identity encoding")
	}
	runtimeStartupWrite(t, controlIdentity, foreignBytes)
	clear(foreignBytes)
	hub = tlsRestoreStartHub(t, hubDir, hubConfig)
	tlsRestoreCLI(t, false, queryArgs...)
	assertUnchanged()
	hub.stop(t)
	runtimeStartupWrite(t, controlIdentity, identityBytes)
	clear(identityBytes)
	phase("existing-hub-identity-missing-unsafe-foreign-denied")
	// The signed origin remains unchanged through the test-only two-native-TLS
	// fault proxy. ListenAddress is separate private Hub network configuration.
	upstream := tlsRestoreAddress(t)
	f.HubConfig.Listen = upstream
	tlsRestoreJSON(t, hubConfig, f.HubConfig)
	hub = tlsRestoreStartHub(t, hubDir, hubConfig)
	proxy := tlsRestoreLostReplyProxy(t, f, address, upstream)
	receipts = tlsRestoreReceipts(t, f.DBPath)
	tlsRestoreCLI(t, false, queryArgs...)
	assertUnchanged()
	checkCLI()
	proxy.assertFresh(t)
	phase("lost-readonly-reply-independent-fresh-cli-success")
	// Restoring the unchanged absolute-path manifest to another StateRoot is
	// structurally possible, but cannot authorize that different TLS scope.
	newRoot := filepath.Join(root, "different-absolute-state-root")
	tlsRestoreCLI(t, true, "machine", "restore", "--backup", backup, "--state-dir", newRoot, "--writer-root", f.WriterRoot)
	var relocated nodebackup.RecoveryInspectReport
	if json.Unmarshal(tlsRestoreCLI(t, true, "machine", "recovery", "inspect", "--backup", backup, "--state-dir", newRoot, "--writer-root", f.WriterRoot), &relocated) != nil || relocated.AgentMayStart {
		t.Fatal("relocated restore must stay held")
	}
	relocatedArgs := append([]string(nil), queryArgs...)
	for i := range relocatedArgs {
		if relocatedArgs[i] == f.StateRoot {
			relocatedArgs[i] = newRoot
		}
	}
	newConfig := filepath.Join(newRoot, ".node-tls", verified.TLSMaterial.Scopes[0].Bucket, "active.json")
	relocatedArgs[len(relocatedArgs)-1] = newConfig
	newBefore, err := recoveryTreeDigest(newRoot)
	if err != nil {
		t.Fatal("relocated state inventory")
	}
	tlsRestoreCLI(t, false, relocatedArgs...)
	newAfter, err := recoveryTreeDigest(newRoot)
	if err != nil || newBefore != newAfter {
		t.Fatal("rejected absolute-scope query changed restored state")
	}
	info, err := os.Lstat(floorPath)
	if err != nil || !os.SameFile(info, floorInfo) || !bytes.Equal(tlsRestoreRead(t, floorPath), floorBytes) {
		t.Fatal("relocation replaced independent floor")
	}
	if tlsRestoreReceipts(t, f.DBPath) != receipts {
		t.Fatal("relocation query changed actual Hub receipts")
	}
	proxy.close(t)
	hub.stop(t)
	phase("different-absolute-state-root-denied")
	phase("complete-all-children-joined-quarantine-retained")
}

func tlsRestoreAdvanceApplicationEpoch(s *store.Store, f runtimeStartupFixture) error {
	// Honor the real five-second bootstrap reissue cooldown. The prior approval
	// is at or after its request's creation, so this bounded wait cannot bypass
	// that fence or rely on cryptography/CLI steps taking a particular duration.
	approved, err := time.Parse(time.RFC3339Nano, f.Binding.ApprovedAt)
	if err != nil {
		return err
	}
	if pause := time.Until(approved.Add(6 * time.Second)); pause > 0 {
		if pause > 6*time.Second {
			return errors.New("synthetic approval time is in the future")
		}
		time.Sleep(pause)
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.Binding.HubID, NodeID: f.Binding.NodeID, RequestNonce: nonce, CredentialDigest: f.Binding.CredentialDigest, NodePublicIdentity: node.Public(), HubPublicIdentity: f.Hub.Public(), HubKeyVersion: f.Binding.HubKeyVersion})
	if err != nil {
		return err
	}
	proof, err := e2ee.Seal(node, f.Hub.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		return err
	}
	code := nodewire.RecoveryDigest([]byte("SYNTHETIC disposable Node application epoch upgrade"))
	candidate, err := s.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{Mode: store.NodeControlPairingUpgrade, NodeID: f.Binding.NodeID, NodeName: "synthetic-restore-epoch-negative", CredentialDigest: f.Binding.CredentialDigest, CodeDigest: code, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubPublicIdentity: f.Hub.Public(), HubKeyVersion: f.Binding.HubKeyVersion, HubFingerprint: nodewire.IdentityFingerprint(f.Hub.Public()), TargetBindingID: f.Binding.OwnerBindingID, ExpiresAt: time.Now().Add(2 * time.Minute)})
	if err != nil {
		return err
	}
	current, err := s.ConfirmNodeControlKeyRequest(f.Binding.OwnerID, f.Binding.ClientDeviceID, code, candidate.Version, candidate.CandidateDigest, candidate.HubNodeControlKeyID, candidate.HubNodeControlFingerprint)
	if err != nil {
		return err
	}
	if current.NodeKeyEpoch <= f.Binding.NodeKeyEpoch {
		return errors.New("synthetic epoch upgrade did not advance")
	}
	return nil
}

func tlsRestoreNativePOST(t *testing.T, f runtimeStartupFixture, address string, packet []byte) int {
	t.Helper()
	pq, err := pqtls.NewClient(f.NodeConfig.TLSConfig())
	if err != nil {
		t.Fatal("actual negative native client")
	}
	transport, err := pq.HTTPTransport(address)
	if err != nil {
		t.Fatal("actual negative native transport")
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("synthetic redirect denied") }}
	req, err := http.NewRequest(http.MethodPost, "https://"+address+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		t.Fatal("actual negative native request")
	}
	req.Header.Set("Authorization", "CicadaNode "+f.Token)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("actual native negative transport failed")
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func (f runtimeStartupFixture) NodeConfigSource(t *testing.T) string {
	t.Helper()
	h := sha256.Sum256([]byte(f.Binding.HubID + "\x00" + f.Binding.NodeID))
	return filepath.Join(f.StateRoot, ".node-tls", hex.EncodeToString(h[:]), "active.json")
}

type tlsRestoreProxy struct {
	server                  *http.Server
	done                    chan error
	transport               *http.Transport
	mu                      sync.Mutex
	recoveryIDs, currentIDs []string
	lost                    bool
	bad                     bool
}

func tlsRestoreLostReplyProxy(t *testing.T, f runtimeStartupFixture, listen, upstream string) *tlsRestoreProxy {
	t.Helper()
	pq, err := pqtls.NewClient(f.NodeConfig.TLSConfig())
	if err != nil {
		t.Fatal("synthetic proxy actual Node TLS client")
	}
	transport, err := pq.HTTPTransport(upstream)
	if err != nil {
		t.Fatal("synthetic proxy native upstream transport")
	}
	l, err := pqtls.Listen("tcp", listen, f.HubConfig.TLSConfig())
	if err != nil {
		t.Fatal("synthetic proxy actual native downstream listener")
	}
	p := &tlsRestoreProxy{done: make(chan error, 1), transport: transport}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("synthetic proxy redirect denied") }}
	p.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ConnContext: pqtls.HTTPConnContext, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, nodewire.MaxTLSCurrentPacketBytes+1))
		r.Body.Close()
		packet, decodeErr := nodewire.DecodePacket(data)
		if err != nil || decodeErr != nil || r.Method != http.MethodPost || r.URL.Path != "/v2/node/control/rpc" || len(data) > nodewire.MaxTLSCurrentPacketBytes {
			http.Error(w, "synthetic denied", 403)
			return
		}
		maxPacket := nodewire.MaxRecoveryPacketBytes
		p.mu.Lock()
		if packet.Route.Operation == nodewire.RecoveryOperation {
			p.recoveryIDs = append(p.recoveryIDs, packet.Route.OperationID)
		} else if nodewire.IsTLSCurrentRoute(packet.Route) {
			maxPacket = nodewire.MaxTLSCurrentPacketBytes
			p.currentIDs = append(p.currentIDs, packet.Route.OperationID)
		} else {
			p.bad = true
			p.mu.Unlock()
			http.Error(w, "synthetic operation denied", 403)
			return
		}
		p.mu.Unlock()
		if len(data) > maxPacket {
			http.Error(w, "synthetic request bound", 403)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://"+upstream+"/v2/node/control/rpc", bytes.NewReader(data))
		if err != nil {
			http.Error(w, "synthetic denied", 403)
			return
		}
		request.Header = r.Header.Clone()
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "synthetic upstream failed", 503)
			return
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxPacket)+1))
		response.Body.Close()
		if err != nil || len(body) > maxPacket {
			http.Error(w, "synthetic bound", 503)
			return
		}
		p.mu.Lock()
		lose := packet.Route.Operation == nodewire.RecoveryOperation && !p.lost && response.StatusCode == http.StatusOK
		if lose {
			p.lost = true
		}
		p.mu.Unlock()
		if lose {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				p.mu.Lock()
				p.bad = true
				p.mu.Unlock()
				http.Error(w, "synthetic fault unavailable", 503)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				p.mu.Lock()
				p.bad = true
				p.mu.Unlock()
				return
			}
			conn.Close() // Sealed successful reply lost; no plaintext/body logged.
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		w.Write(body)
	})}
	go func() { p.done <- p.server.Serve(l) }()
	t.Cleanup(func() { p.server.Close(); transport.CloseIdleConnections() })
	return p
}

func (p *tlsRestoreProxy) assertFresh(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bad || !p.lost || len(p.recoveryIDs) != 2 || p.recoveryIDs[0] == p.recoveryIDs[1] || len(p.currentIDs) < 2 {
		t.Fatal("lost reply did not use two independent fresh CLI requests")
	}
	seen := map[string]bool{}
	for _, id := range p.currentIDs {
		if seen[id] {
			t.Fatal("current nonce reused across independent CLI reads")
		}
		seen[id] = true
	}
}

func (p *tlsRestoreProxy) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if p.server.Shutdown(ctx) != nil {
		t.Fatal("synthetic native proxy shutdown")
	}
	p.server.Close()
	if err := <-p.done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal("synthetic native proxy join")
	}
	p.transport.CloseIdleConnections()
}
