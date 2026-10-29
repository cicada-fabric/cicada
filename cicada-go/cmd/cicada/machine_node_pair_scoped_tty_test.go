package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestNodePairScopedCodeUsesOriginalCompanionTTYOnly(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	_, s := f.load(t)
	defer clear(s.Secret)
	var logs bytes.Buffer
	if machineNodePairScopedDisplayCode(s, &logs) == nil || logs.Len() != 0 {
		t.Fatal("scoped secret entered redirected output")
	}
	if machineNodePairingCodeCommand([]string{"--id", f.f.node, "--state-dir", f.f.state}, &logs) == nil || logs.Len() != 0 {
		t.Fatal("companion leaked scoped code to logs")
	}
	code, err := wire.EncodeNodePairTrustScopedCode(*s.Context, s.Selector, s.Secret)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(code))
	// Reuse the existing companion subprocess entry; no new daemon/driver.
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
codes=[x for x in lines if x.startswith(b'cicada-npts1.')]
print(json.dumps(dict(status=status,lines=len(lines),codes=len(codes),digest=hashlib.sha256(codes[0]).hexdigest() if len(codes)==1 else '')))
`
	raw, err := exec.Command("python3", "-c", script, os.Args[0], f.f.node, f.f.state).Output()
	if err != nil {
		t.Fatal("scoped companion PTY failed", err)
	}
	var result struct {
		Status, Lines, Codes int
		Digest               string
	}
	if json.Unmarshal(raw, &result) != nil || result.Status != 0 || result.Lines != 1 || result.Codes != 1 || result.Digest != hex.EncodeToString(expected[:]) {
		t.Fatal("companion did not print exactly the original scoped code")
	}
}
