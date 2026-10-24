package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestNodePairLocalSealedSecretRetainsOriginalKeyAndRejectsSubstitution(t *testing.T) {
	f := newNativeNodeFixture(t)
	root := t.TempDir()
	nodeID := "SYNTHETIC-local-sealed"
	client, e := openMachineNodeControlClient(root, f.d.Claims.Origin, nodeID)
	if e != nil {
		t.Fatal(e)
	}
	keyPath, _ := machineNodeControlPaths(root, nodeID)
	keyBefore, e := os.ReadFile(keyPath)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(keyBefore)
	s := &machineNodePairState{Version: 1, NodeID: nodeID, AttemptID: strings.Repeat("ac", 16), DescriptorText: f.text, DialAddress: "127.0.0.1:443", Secret: bytes.Repeat([]byte{0x53}, 32), Stage: "NEW"}
	defer clear(s.Secret)
	if e = saveMachineNodePairState(root, client.identity, s); e != nil {
		t.Fatal(e)
	}
	path := machineNodePairStatePath(root, nodeID)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(s.Secret))) || bytes.Contains(raw, []byte("oob_secret")) {
		t.Fatal("plaintext S entered outer state")
	}
	loaded, e := loadMachineNodePairState(root, nodeID, client.identity)
	if e != nil || !bytes.Equal(loaded.Secret, s.Secret) {
		t.Fatal("original sealed secret not recovered", e)
	}
	clear(loaded.Secret)
	keyAfter, e := os.ReadFile(keyPath)
	if e != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("local sealing replaced Node identity", e)
	}
	clear(keyAfter)
	wrong, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = loadMachineNodePairState(root, nodeID, wrong); e == nil {
		t.Fatal("another Node opened local S")
	}
	var envelope machineNodePairLocalEnvelope
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("outer envelope")
	}
	envelope.AttemptID = strings.Repeat("ad", 16)
	altered, _ := json.Marshal(envelope)
	if e = os.WriteFile(path, altered, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadMachineNodePairState(root, nodeID, client.identity); e == nil {
		t.Fatal("different attempt opened local S")
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = loadMachineNodePairState(root, nodeID, client.identity); e == nil {
		t.Fatal("public secret file accepted")
	}
	if e = saveMachineNodePairState(root, client.identity, s); e == nil {
		t.Fatal("invalid old file silently overwritten")
	}
}

func TestNodePairLocalSecretRejectsSymlinksAndAmbiguousJSON(t *testing.T) {
	f := newNativeNodeFixture(t)
	root := t.TempDir()
	nodeID := "SYNTHETIC-local-link"
	client, e := openMachineNodeControlClient(root, f.d.Claims.Origin, nodeID)
	if e != nil {
		t.Fatal(e)
	}
	s := &machineNodePairState{Version: 1, NodeID: nodeID, AttemptID: strings.Repeat("ae", 16), DescriptorText: f.text, DialAddress: "127.0.0.1:443", Secret: bytes.Repeat([]byte{0x54}, 32), Stage: "NEW"}
	defer clear(s.Secret)
	if e = saveMachineNodePairState(root, client.identity, s); e != nil {
		t.Fatal(e)
	}
	path := machineNodePairStatePath(root, nodeID)
	moved := path + ".retained"
	if e = os.Rename(path, moved); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(moved, path); e != nil {
		t.Fatal(e)
	}
	if _, e = loadMachineNodePairState(root, nodeID, client.identity); e == nil {
		t.Fatal("symlink secret accepted")
	}
	link := filepath.Join(t.TempDir(), "root-link")
	if e = os.Symlink(root, link); e != nil {
		t.Fatal(e)
	}
	if machineNodePairNoSymlinkPath(machineNodeStateDir(link, nodeID)) == nil {
		t.Fatal("symlink state parent admitted")
	}
	var body machineNodePairState
	if machineNodePairStrictJSON([]byte(`{"version":1,"unknown":true}`), &body) == nil || machineNodePairStrictJSON([]byte(`{} {}`), &body) == nil {
		t.Fatal("ambiguous local state accepted")
	}
}

func TestNodePairLocalIssuedIncludesPollAndCancelAliases(t *testing.T) {
	const stamp = "2026-10-24T08:00:00Z"
	for _, b := range []any{wire.NodePairTrustStart{IssuedAt: stamp}, wire.NodePairTrustExistingStart{IssuedAt: stamp}, wire.NodePairTrustCommit{IssuedAt: stamp}, wire.NodePairTrustPoll{IssuedAt: stamp}, wire.NodePairTrustCancel{IssuedAt: stamp}, wire.NodePairTrustACK{IssuedAt: stamp}} {
		if machineNodePairIssued(b) != stamp {
			t.Fatal("closed operation alias lost its issued time")
		}
	}
}

func TestNodePairLocalTTYEnforcesConsoleAndNoLogFallback(t *testing.T) {
	if os.Getenv("CICADA_SYNTHETIC_PAIR_CODE_HELPER") == "1" {
		e := machineNodePairingCodeCommand([]string{"--id", os.Getenv("CICADA_SYNTHETIC_PAIR_NODE"), "--state-dir", os.Getenv("CICADA_SYNTHETIC_PAIR_STATE")}, os.Stdout)
		if e != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	f := newNodePairLocalFixture(t)
	_, s := f.pending(t)
	defer clear(s.Secret)
	var logs bytes.Buffer
	if e := machineNodePairDisplayCode(s, &logs); e == nil || logs.Len() != 0 {
		t.Fatal("redirected output received a secret")
	}
	if e := machineNodePairingCodeCommand([]string{"--id", f.node, "--state-dir", f.state}, &logs); e == nil || logs.Len() != 0 {
		t.Fatal("companion log fallback exposed a secret")
	}
	code, e := wire.EncodeNodePairTrustCode(*s.Context, s.Selector, s.Secret)
	if e != nil {
		t.Fatal(e)
	}
	expected := sha256.Sum256([]byte(code))
	script := `import errno,hashlib,json,os,pty,subprocess,sys
master,slave=pty.openpty()
env=dict(os.environ,CICADA_SYNTHETIC_PAIR_CODE_HELPER='1',CICADA_SYNTHETIC_PAIR_NODE=sys.argv[2],CICADA_SYNTHETIC_PAIR_STATE=sys.argv[3])
p=subprocess.Popen([sys.argv[1],'-test.run=^TestNodePairLocalTTYEnforcesConsoleAndNoLogFallback$'],stdin=slave,stdout=slave,stderr=slave,env=env)
os.close(slave)
data=b''
while True:
 try:
  part=os.read(master,8192)
  if not part:break
  data+=part
 except OSError as e:
  if e.errno==errno.EIO:break
  raise
os.close(master)
status=p.wait(timeout=10)
lines=data.replace(b'\r\n',b'\n').splitlines()
codes=[x for x in lines if x.startswith(b'cicada-npt1.')]
print(json.dumps(dict(status=status,lines=len(lines),codes=len(codes),digest=hashlib.sha256(codes[0]).hexdigest() if len(codes)==1 else '')))
`
	child := exec.Command("python3", "-c", script, os.Args[0], f.node, f.state)
	raw, e := child.Output()
	if e != nil {
		t.Fatal("actual PTY helper failed", e)
	}
	var result struct {
		Status, Lines, Codes int
		Digest               string
	}
	if json.Unmarshal(raw, &result) != nil || result.Status != 0 || result.Lines != 1 || result.Codes != 1 || result.Digest != hex.EncodeToString(expected[:]) {
		t.Fatal("actual TTY did not display exactly the retained one code")
	}
}

func TestNodePairLocalTerminalErrorsPreserveOriginalEvidence(t *testing.T) {
	f := newNodePairLocalFixture(t)
	c, s := f.pending(t)
	defer clear(s.Secret)
	q := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if e := newMachineNodePairRequest(f.state, c.identity, s, f.native.d.Claims.Hub, wire.OperationNodePairTrustPoll, q); e != nil {
		t.Fatal(e)
	}
	original := append([]byte(nil), s.PendingPacket...)
	body := append([]byte(nil), s.PendingBody...)
	unknown := wire.NodePairTrustResult{State: wire.NodePairTrustExpired, ErrorCode: "OUTCOME_UNCERTAIN"}
	if e := applyMachineNodePairResult(f.state, c, s, f.native.d, unknown, []byte("SYNTHETIC authenticated upstream uncertainty")); !errors.Is(e, errMachineNodePairPending) || !bytes.Equal(s.PendingPacket, original) {
		t.Fatal("uncertainty discarded original")
	}
	terminal := wire.NodePairTrustResult{State: wire.NodePairTrustExpired, ErrorCode: wire.NodePairTrustExpired}
	if e := applyMachineNodePairResult(f.state, c, s, f.native.d, terminal, []byte("SYNTHETIC authenticated upstream terminal receipt")); e != nil {
		t.Fatal(e)
	}
	recovered, e := loadMachineNodePairState(f.state, f.node, c.identity)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(recovered.Secret)
	if recovered.Stage != wire.NodePairTrustExpired || recovered.PendingOperation != "" || recovered.TerminalOriginal == nil || !bytes.Equal(recovered.TerminalOriginal.Packet, original) || !bytes.Equal(recovered.TerminalOriginal.Body, body) || recovered.Binding != nil {
		t.Fatal("terminal lost original evidence or invented binding")
	}
}

func TestNodePairLocalACKCannotRollBackVerifiedDialLocator(t *testing.T) {
	s := &machineNodePairState{DescriptorText: "SYNTHETIC already-authenticated descriptor", DialAddress: "127.0.0.1:1443"}
	if address, e := retainedMachineNodePairRouting(machineNodeControlState{}, s); e != nil || address != s.DialAddress {
		t.Fatal("first binding did not install its verified routing", e)
	}
	old := machineNodeControlState{BindingID: "SYNTHETIC-binding", HubTransportDescriptor: s.DescriptorText, HubDialAddress: "127.0.0.1:2443", Sequence: 42, PendingOperationID: "SYNTHETIC-preserved-original"}
	before, _ := json.Marshal(old)
	if address, e := retainedMachineNodePairRouting(old, s); e != nil || address != old.HubDialAddress || address == s.DialAddress {
		t.Fatal("historical ACK rolled back a later verified locator", e)
	}
	after, _ := json.Marshal(old)
	if !bytes.Equal(before, after) {
		t.Fatal("routing check changed binding/counter evidence")
	}
	for _, kind := range []string{"missing-descriptor", "missing-address", "wrong-descriptor", "invalid-address", "unbound-partial"} {
		broken := old
		switch kind {
		case "missing-descriptor":
			broken.HubTransportDescriptor = ""
		case "missing-address":
			broken.HubDialAddress = ""
		case "wrong-descriptor":
			broken.HubTransportDescriptor += "-different"
		case "invalid-address":
			broken.HubDialAddress = "https://SYNTHETIC.invalid"
		case "unbound-partial":
			broken.BindingID = ""
		}
		if _, e := retainedMachineNodePairRouting(broken, s); e == nil {
			t.Fatal("corrupt original routing silently repaired", kind)
		}
	}
}
