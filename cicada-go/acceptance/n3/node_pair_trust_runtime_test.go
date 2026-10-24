package n3_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

// The actual Node receives only --hub-address. The Hub descriptor exists for
// the independently bootstrapped App and read-only test observations; it is
// never passed to the Node or installed as its trust by this driver.
type nodePairFixture struct {
	hub                           *directIPHub
	app                           *directIPApp
	original                      appcore.Snapshot
	node                          *nodeProcess
	binary, home, state, userRoot string
	environment                   []string
	code                          string // Private actual TTY -> actual App only.
	local                         wire.NodePairTrustCode
	mode                          string
	dial                          string
}

func TestN3NodePairTrustAcceptance(t *testing.T) {
	if os.Getenv("CICADA_N3_NODE_PAIR_TRUST") != "1" {
		t.Skip("NODE_PAIR_TRUST_NOT_RUN: explicit isolated gate is off")
	}
	t.Run("NPT01_AddressOnlyBootstrap", nodePairAddressOnly)
	t.Run("NPT02_SecretNeverUploaded", nodePairSecretNeverUploaded)
	t.Run("NPT03_FakeHubOwnerRefused", nodePairFakeHubOwnerRefused)
	t.Run("NPT04_ExactCandidateAndPossession", nodePairExactCandidateAndPossession)
	t.Run("NPT05_LegacyConfirmRequiresACK", nodePairLegacyConfirmRequiresACK)
	t.Run("NPT06_CodeLimitsExpiryRevocation", nodePairCodeLimitsExpiryRevocation)
	t.Run("NPT07_ConcurrentAndExactReplay", nodePairConcurrentAndExactReplay)
	t.Run("NPT08_OriginalResponseLoss", nodePairOriginalResponseLoss)
	t.Run("NPT09_AppClosedAndRestart", nodePairAppClosedAndRestart)
	t.Run("NPT10_OwnerPinConflict", nodePairOwnerPinConflict)
	t.Run("NPT11_ExistingBindingTrustOnly", nodePairExistingBindingTrustOnly)
	t.Run("NPT12_ZeroBusinessRights", nodePairZeroBusinessRights)
}

func nodePairReadOnlyDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	if !must(os.Stat(path)).Mode().IsRegular() {
		t.Fatal("owned persistent observation database unavailable")
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
	db := must(sql.Open("sqlite", uri))
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func newNodePairFixture(t *testing.T, host string) *nodePairFixture {
	return newNodePairFixtureWithBoundary(t, host, nil)
}

func newNodePairFixtureWithBoundary(t *testing.T, host string, boundary func(*nodePairFixture) string) *nodePairFixture {
	t.Helper()
	f := newDirectIPHub(t, host)
	a, original := f.activateApp(t)
	v := &nodePairFixture{hub: f, app: a, original: original, home: filepath.Join(f.dir, "owned-node-home"), mode: wire.NodePairTrustInitial}
	v.userRoot = filepath.Join(v.home, ".cicada")
	v.state = filepath.Join(v.userRoot, "node", "state")
	v.binary = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(f.binary))), "node", "bin", "cicada")
	for _, dir := range []string{v.home, v.userRoot, v.state, filepath.Join(v.userRoot, "mcp"), filepath.Join(v.home, "tmp")} {
		if os.MkdirAll(dir, 0700) != nil {
			t.Fatal("owned address-only Node fixture directory unavailable")
		}
	}
	v.environment = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + v.home,
		"CODEX_HOME=" + filepath.Join(v.home, "codex-unused"), "TMPDIR=" + filepath.Join(v.home, "tmp"), "LANG=C.UTF-8"}
	if boundary != nil {
		v.dial = boundary(v)
	}
	v.start(t)
	v.awaitCommittedCandidate(t)
	v.readCode(t)
	return v
}

func (v *nodePairFixture) readCode(t *testing.T) {
	t.Helper()
	argv := []string{v.binary, "machine", "pairing-code", "--id", v.node.id, "--state-dir", v.state}
	v.code = nodePairPrivateTTYCode(t, v.hub.dir, argv, v.environment)
	v.local = must(wire.DecodeNodePairTrustCode(v.code, time.Now().UTC()))
	t.Cleanup(func() { clear(v.local.OOBSecret) })
	nodePairRedirectRefusesCode(t, argv, v.environment, v.code)
}

func (v *nodePairFixture) start(t *testing.T) {
	t.Helper()
	id := "synthetic-n3-node-pair"
	if v.node != nil {
		id = v.node.id
	}
	address := v.hub.address
	if v.dial != "" {
		address = v.dial
	}
	args := []string{"machine", "agent", "--relay-only", "--id", id, "--name", "SYNTHETIC address-only Node",
		"--hub-address", address, "--state-dir", v.state, "--interval", "1s", "--user-root", v.userRoot,
		"--mcp-session-state-file", filepath.Join(v.userRoot, "mcp", "sessions.json"),
		"--mcp-outbox-state-file", filepath.Join(v.userRoot, "mcp", "outbox.sqlite3")}
	cmd := exec.Command(v.binary, args...)
	cmd.Env = v.environment
	log := must(os.OpenFile(filepath.Join(v.state, "private-process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600))
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log
	v.node = &nodeProcess{process: startProcess(t, cmd), id: id, state: v.state}
}

func (v *nodePairFixture) awaitCommittedCandidate(t *testing.T) {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var count int
		err := db.QueryRowContext(ctx, `SELECT count(*) FROM hub_node_pair_trust_v1 WHERE node_id=? AND mode=? AND state=? AND oob_commitment<>''`,
			v.node.id, v.mode, wire.NodePairTrustPending).Scan(&count)
		if err != nil {
			t.Fatal("actual Hub did not expose its delivered persistent Node-pair candidate relation")
		}
		if count == 1 {
			return // Observation only; the secret code still comes from the real CLI.
		}
		if count > 1 || !v.node.running() {
			t.Fatal("actual address-only Node failed or created duplicate live candidates")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual address-only Node did not durably commit its own candidate before deadline")
}

func nodePairContainsSecret(raw []byte, code string, secret []byte) bool {
	if bytes.Contains(raw, []byte(code)) || bytes.Contains(raw, []byte(wire.NodePairTrustCodePrefix)) {
		return true
	}
	for _, value := range [][]byte{secret, []byte(base64.RawURLEncoding.EncodeToString(secret)),
		[]byte(base64.StdEncoding.EncodeToString(secret)), []byte(hex.EncodeToString(secret))} {
		if bytes.Contains(raw, value) {
			return true
		}
	}
	return false
}

func (v *nodePairFixture) action(t *testing.T, a appcore.Action) appcore.Snapshot {
	t.Helper()
	time.Sleep(time.Second) // Keep the existing account rate bucket meaningful.
	reply := v.app.command(t, directIPAppCommand{Action: &a})
	s := reply.Snapshot
	if reply.ActionFailed || s.Account.OwnerID != v.original.Account.OwnerID || s.Account.DeviceID != v.original.Account.DeviceID ||
		s.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID || s.Hub.Fingerprint != v.original.Hub.Fingerprint ||
		s.Management != appcore.ManagementUnavailable {
		stage := "NONE"
		if s.Node.Pairing != nil {
			stage = s.Node.Pairing.State
		}
		t.Fatalf("actual Node-pair App action failed: action=%s error=%s pairing=%s account=%s Root=%s Owner_same=%t device_same=%t key_same=%t Hub_same=%t management_unavailable=%t Node_pending=%t Node_error=%s Hub_verified=%t actions=%v", a.Kind,
			s.ErrorCode, stage, s.Account.State, s.Account.RootState, s.Account.OwnerID == v.original.Account.OwnerID,
			s.Account.DeviceID == v.original.Account.DeviceID, s.Account.LocalOwnerKeyID == v.original.Account.LocalOwnerKeyID,
			s.Hub.Fingerprint == v.original.Hub.Fingerprint, s.Management == appcore.ManagementUnavailable, s.Node.Pending, s.Node.ErrorCode, s.Hub.Verified, s.AvailableActions)
	}
	raw := must(json.Marshal(s))
	defer clear(raw)
	if nodePairContainsSecret(raw, v.code, v.local.OOBSecret) {
		t.Fatal("actual App snapshot disclosed secret pairing material")
	}
	return s
}

func (v *nodePairFixture) review(t *testing.T) appcore.Snapshot {
	t.Helper()
	s := v.action(t, appcore.Action{Kind: appcore.ActionReviewNodePairing, DevicePairingCode: v.code})
	if s.Node.Pairing == nil || s.Node.Pairing.State != "REVIEW" || s.Node.Pairing.ReviewID == "" || s.Node.Pairing.NodeID != v.node.id || s.Node.Binding != nil {
		t.Fatal("actual App did not review the exact Node code without creating a binding")
	}
	return s
}

func (v *nodePairFixture) approve(t *testing.T) appcore.Snapshot {
	t.Helper()
	s := v.review(t)
	s = v.action(t, appcore.Action{Kind: appcore.ActionApproveNodePairing, NodePairingReviewID: s.Node.Pairing.ReviewID, ConfirmNodePairing: true})
	if s.Node.Pairing == nil || s.Node.Pairing.State != wire.NodePairTrustOwnerApproved || s.Node.Binding != nil {
		t.Fatal("actual App treated Owner approval as completed Node admission")
	}
	return s
}

func (v *nodePairFixture) awaitACK(t *testing.T) appcore.Snapshot {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		s := v.action(t, appcore.Action{Kind: appcore.ActionRefreshNodePairing})
		if s.Node.Pairing != nil && s.Node.Pairing.State == wire.NodePairTrustACKed {
			if s.Node.Binding == nil || s.Node.Binding.ID == "" || s.Node.Binding.NodeID != v.node.id {
				t.Fatal("actual App ACK projection omitted the original cryptographic binding")
			}
			return s
		}
	}
	t.Fatal("actual Node did not ACK the original approval before the bounded deadline")
	return appcore.Snapshot{}
}

func (v *nodePairFixture) assertAutomaticOwnerPin(t *testing.T, s appcore.Snapshot) {
	t.Helper()
	dir := filepath.Join(v.state, "nodes", "node-"+url.PathEscape(v.node.id))
	db := nodePairReadOnlyDB(t, filepath.Join(dir, "node-crypto-state.sqlite"))
	rows := must(db.Query(`SELECT key_id,public_identity_json,fingerprint,state,version FROM node_crypto_owner_key_trust WHERE owner_id=?`, s.Account.OwnerID))
	defer rows.Close()
	count := 0
	for rows.Next() {
		var keyID, raw, fingerprint, state string
		var version uint64
		if rows.Scan(&keyID, &raw, &fingerprint, &state, &version) != nil {
			t.Fatal("actual Node independent public trust record is unreadable")
		}
		var public e2ee.PublicIdentity
		if json.Unmarshal([]byte(raw), &public) != nil || e2ee.ValidatePublicIdentity(public) != nil || keyID != public.ID ||
			keyID != s.Account.LocalOwnerKeyID || fingerprint != s.Account.OwnerPeerFingerprint ||
			must(nodekeys.PeerKeyFingerprint(public)) != fingerprint || state != nodekeys.NodeOwnerKeyTrustActive || version != 1 {
			t.Fatal("actual Node automatic Owner pin differs from the independently displayed original App key")
		}
		count++
	}
	if rows.Err() != nil || count != 1 {
		t.Fatal("actual Node automatic Owner trust is missing or has extra same-Owner keys")
	}
}

func nodePairFacts(t *testing.T, name string, facts map[string]bool) {
	t.Helper()
	raw := must(json.Marshal(struct {
		Case     string          `json:"case"`
		Observed map[string]bool `json:"observed"`
	}{name, facts}))
	t.Logf("NODE_PAIR_TRUST_FACTS %s", raw)
}

func nodePairAddressOnly(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		var v *nodePairFixture
		if host == "127.0.0.1" {
			v = newNodePairFixtureWithBoundary(t, host, func(v *nodePairFixture) string {
				nodePairInstallConsumerFiles(t, v)
				return "" // Actual direct native TLS, no Hub-side boundary.
			})
		} else {
			v = newNodePairFixture(t, host)
		}
		v.approve(t)
		s := v.awaitACK(t)
		v.assertAutomaticOwnerPin(t, s)
		adapter := &hubFixture{dir: v.hub.dir, cfg: fixtureConfig{Origin: v.hub.material.Origin, Hub: v.hub.descriptor.Claims.Hub}}
		bound := v.node.awaitState(t, adapter, true)
		if bound.BindingID != s.Node.Binding.ID || bound.BindingVersion != s.Node.Binding.Version || !v.node.running() {
			t.Fatal("actual address-only Node persisted a different admission from the actual App")
		}
		log := readPrivate(t, filepath.Join(v.state, "private-process.log"))
		if nodePairContainsSecret(log, v.code, v.local.OOBSecret) {
			clear(log)
			t.Fatal("background Node logged its secret pairing code")
		}
		clear(log)
		if host == "127.0.0.1" {
			nodePairAutomaticPinConsumer(t, v)
		}
	}
	nodePairFacts(t, "NPT01_AddressOnlyBootstrap", map[string]bool{"actual_Hub_App_Node": true, "IPv4": true, "IPv6": true,
		"no_manual_descriptor_or_Owner_key": true, "actual_private_TTY_code": true,
		"automatic_pin_existing_daemon_MCP": true, "zero_model_provider_posts": true})
}

func (v *nodePairFixture) side(t *testing.T) (wire.NodePairTrustContext, string) {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	defer db.Close()
	var raw, state string
	if db.QueryRow(`SELECT context_json,state FROM hub_node_pair_trust_v1 WHERE attempt_id=? AND node_id=?`,
		v.local.AttemptID, v.node.id).Scan(&raw, &state) != nil {
		t.Fatal("actual Hub lost the original Node-pair attempt")
	}
	var c wire.NodePairTrustContext
	if json.Unmarshal([]byte(raw), &c) != nil || must(wire.NodePairTrustContextDigest(c)) != v.local.ContextDigest {
		t.Fatal("actual Hub changed the original Node-pair context")
	}
	return c, state
}

func (v *nodePairFixture) awaitHubACK(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, state := v.side(t)
		if state == wire.NodePairTrustACKed {
			return
		}
		if !v.node.running() || state != wire.NodePairTrustOwnerApproved {
			t.Fatal("actual restarted Node failed to ACK its original durable approval")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("actual Node required a live App or new approval to finish ACK")
}

func (v *nodePairFixture) resumeApp(t *testing.T) appcore.Snapshot {
	return v.resumeAppAddress(t, v.hub.address)
}

func (v *nodePairFixture) resumeAppAddress(t *testing.T, address string) appcore.Snapshot {
	t.Helper()
	v.app = startDirectIPApp(t, v.app.dir)
	discovered := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if discovered.ActionFailed || len(discovered.Snapshot.Profiles) != 1 {
		t.Fatal("actual App lost its sole original scoped profile")
	}
	resumed := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: discovered.Snapshot.Profiles[0].ID, HubAddress: address}})
	if resumed.ActionFailed || !resumed.Snapshot.Hub.Verified || resumed.Snapshot.Account.OwnerID != v.original.Account.OwnerID ||
		resumed.Snapshot.Account.DeviceID != v.original.Account.DeviceID || resumed.Snapshot.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID {
		t.Fatal("actual App restart replaced its original Hub/Owner/device identity")
	}
	return resumed.Snapshot
}

type nodePairSavedOperation struct {
	Operation  string          `json:"operation"`
	Body       json.RawMessage `json:"body"`
	Request    []byte          `json:"request"`
	Response   []byte          `json:"response"`
	Applied    bool            `json:"applied"`
	BodyDigest string          `json:"body_digest,omitempty"`
}

type nodePairSavedConfirmation struct {
	Operation                string                        `json:"operation"`
	Request                  []byte                        `json:"request"`
	Response                 []byte                        `json:"response"`
	Applied                  bool                          `json:"applied"`
	ExpectedResponseSequence uint64                        `json:"expected_response_sequence"`
	GrantClaims              *e2ee.OwnerAppNodeGrantClaims `json:"grant_claims"`
}

type nodePairSavedApp struct {
	PairTrust *struct {
		Code                json.RawMessage             `json:"code"`
		Stage               string                      `json:"stage"`
		Pending             *nodePairSavedOperation     `json:"pending"`
		Recovery            *nodePairSavedOperation     `json:"recovery"`
		Confirmation        *nodePairSavedConfirmation  `json:"confirmation"`
		OwnerProof          []byte                      `json:"owner_proof"`
		Capsule             []byte                      `json:"capsule"`
		Approval            *wire.NodePairTrustApproval `json:"approval"`
		FencedOperation     string                      `json:"fenced_operation"`
		FencedRequestDigest string                      `json:"fenced_request_digest"`
	} `json:"pair_trust"`
}

func (s *nodePairSavedApp) clear() {
	if s == nil || s.PairTrust == nil {
		return
	}
	p := s.PairTrust
	clear(p.Code)
	for _, op := range []*nodePairSavedOperation{p.Pending, p.Recovery} {
		if op != nil {
			clear(op.Body)
			clear(op.Request)
			clear(op.Response)
		}
	}
	if p.Confirmation != nil {
		clear(p.Confirmation.Request)
		clear(p.Confirmation.Response)
	}
	clear(p.OwnerProof)
	clear(p.Capsule)
}

// Copy only a coherent atomic encrypted image, then authenticate it through
// the real synthetic Linux vault protector under a different private path.
// Never acquire the live original vault lock or retrieve any Owner private key.
func (v *nodePairFixture) copiedAppState(t *testing.T) *nodePairSavedApp {
	t.Helper()
	saved, err := nodePairCopiedAppState(v.hub, v.app.dir)
	if err != nil {
		t.Fatal("coherent copied encrypted App Node-pair state unavailable")
	}
	return saved
}

func nodePairCopiedAppState(hub *directIPHub, appDir string) (*nodePairSavedApp, error) {
	scope := directIPScope(hub)
	scopeRaw, err := json.Marshal(scope)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(appDir, "home", ".cicada", "app", "vaults", hash(scopeRaw)+".vault")
	image, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(image)
	if len(image) > 8<<20 {
		return nil, wire.ErrInvalid
	}
	dir, err := os.MkdirTemp(hub.dir, "private-pair-vault-copy-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "copy.vault")
	if err = os.WriteFile(copyPath, image, 0600); err != nil {
		return nil, err
	}
	protector, err := appvault.NewPasswordProtector([]byte("Synthetic N3 acceptance vault passphrase"))
	if err != nil {
		return nil, err
	}
	vault, err := appvault.Open(copyPath, scope, protector)
	if err != nil {
		protector.Close()
		return nil, err
	}
	defer vault.Close()
	raw, _, found, err := vault.LoadState("appcore.node.v1")
	defer clear(raw)
	if err != nil || !found {
		return nil, wire.ErrInvalid
	}
	var saved nodePairSavedApp
	if json.Unmarshal(raw, &saved) != nil || saved.PairTrust == nil {
		return nil, wire.ErrInvalid
	}
	// App and N3 use one existing mutually exclusive encrypted recovery slot.
	// Inspect that actual slot rather than guessing from a transient stage.
	recoveryRaw, _, found, err := vault.LoadState("appcore.node-recovery.v1")
	defer clear(recoveryRaw)
	if err != nil {
		saved.clear()
		return nil, err
	}
	// A cleared existing recovery namespace is a versioned nil-payload
	// tombstone, just as production loadNodeRecord treats it. Its generation
	// remains present; there is no recovery JSON to decode or target to infer.
	if found && len(recoveryRaw) != 0 {
		var recovery struct {
			PairTrust *struct {
				Scope          appvault.Scope         `json:"scope"`
				AttemptID      string                 `json:"attempt_id"`
				OriginalDigest string                 `json:"original_packet_digest"`
				Operation      nodePairSavedOperation `json:"operation"`
			} `json:"pair_trust_recovery"`
		}
		if json.Unmarshal(recoveryRaw, &recovery) != nil {
			saved.clear()
			return nil, wire.ErrInvalid
		}
		if r := recovery.PairTrust; r != nil {
			p := saved.PairTrust.Pending
			var h wire.NodePairTrustPacket
			if p == nil || json.Unmarshal(p.Request, &h) != nil || r.Scope != scope || r.AttemptID != h.AttemptID ||
				r.OriginalDigest != wire.NodePairTrustPacketDigest(p.Request) || r.Operation.Operation != wire.OperationNodePairTrustReconcile {
				saved.clear()
				return nil, wire.ErrInvalid
			}
			saved.PairTrust.Recovery = &r.Operation
		}
	}
	return &saved, nil
}

func nodePairAppClosedAndRestart(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	originalContext, _ := v.side(t)
	oldNodePID := v.node.cmd.Process.Pid
	v.node.kill(t) // Hold the actual Node before Owner approval, not a guessed TLS record.
	v.approve(t)
	before := v.copiedAppState(t)
	defer before.clear()
	if before.PairTrust.Confirmation == nil || before.PairTrust.Confirmation.Applied || len(before.PairTrust.Confirmation.Request) == 0 ||
		len(before.PairTrust.Confirmation.Response) != 0 || before.PairTrust.Confirmation.ExpectedResponseSequence == 0 {
		t.Fatal("actual App did not retain its exact unconfirmed original before close")
	}
	_, state := v.side(t)
	if state != wire.NodePairTrustOwnerApproved {
		t.Fatal("actual Hub did not retain the original bounded Owner approval")
	}
	oldAppPID := v.app.cmd.Process.Pid
	v.app.command(t, directIPAppCommand{Close: true})
	if v.app.running() {
		t.Fatal("actual App did not close before Node ACK")
	}
	keys := directIPKeyDigests(t, v.hub.state)
	oldHubPID := v.hub.hub.cmd.Process.Pid
	v.hub.hub.kill(t)
	v.hub.start(t)
	if v.hub.hub.cmd.Process.Pid == oldHubPID || !reflect.DeepEqual(keys, directIPKeyDigests(t, v.hub.state)) {
		t.Fatal("actual Hub restart replaced its retained keys or process")
	}
	v.start(t)
	if v.node.cmd.Process.Pid == oldNodePID {
		t.Fatal("actual Node did not restart")
	}
	v.awaitHubACK(t)
	if v.app.running() {
		t.Fatal("Node ACK depended on a replacement/live App process")
	}
	currentContext, _ := v.side(t)
	if !reflect.DeepEqual(currentContext, originalContext) {
		t.Fatal("actual Hub/Node restart replaced the original attempt or public candidate")
	}
	v.resumeApp(t)
	if v.app.cmd.Process.Pid == oldAppPID {
		t.Fatal("actual App did not restart")
	}
	s := v.awaitACK(t)
	after := v.copiedAppState(t)
	defer after.clear()
	if after.PairTrust.Confirmation == nil || !after.PairTrust.Confirmation.Applied || len(after.PairTrust.Confirmation.Response) == 0 ||
		!bytes.Equal(before.PairTrust.Confirmation.Request, after.PairTrust.Confirmation.Request) ||
		before.PairTrust.Confirmation.ExpectedResponseSequence != after.PairTrust.Confirmation.ExpectedResponseSequence ||
		!bytes.Equal(before.PairTrust.OwnerProof, after.PairTrust.OwnerProof) || !bytes.Equal(before.PairTrust.Capsule, after.PairTrust.Capsule) {
		t.Fatal("actual App restart resealed the original confirmation, proof or capsule")
	}
	v.assertAutomaticOwnerPin(t, s)
	adapter := &hubFixture{dir: v.hub.dir, cfg: fixtureConfig{Origin: v.hub.material.Origin, Hub: v.hub.descriptor.Claims.Hub}}
	bound := v.node.awaitState(t, adapter, true)
	if originalContext.Candidate == nil || bound.NodeKeyID != originalContext.Candidate.NodePublic.ID ||
		bound.NodeKeyEpoch != originalContext.Candidate.NodeKeyEpoch || bound.BindingID != s.Node.Binding.ID {
		t.Fatal("actual restarted Node changed the original key, epoch or binding")
	}
	nodePairFacts(t, "NPT09_AppClosedAndRestart", map[string]bool{"normal_App_close_before_ACK": true,
		"no_live_App_callback": true, "actual_Hub_Node_App_restart": true, "original_keys_pin_and_pending_bytes": true})
}
