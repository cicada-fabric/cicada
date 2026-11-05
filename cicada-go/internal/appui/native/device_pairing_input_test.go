package native

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Visibly synthetic local parser input, never a credential for deployment.
// It proves no Hub/candidate/authorization property; production still checks
// the exact independently pinned Hub and cryptographic context in appcore.
func syntheticDevicePairingCode(t *testing.T, long bool) string {
	t.Helper()
	origin, hub, node := "https://synthetic.invalid", "synthetic_hub", "synthetic-node"
	if long {
		origin = "https://" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".synthetic.invalid"
		hub = "synthetic_" + strings.Repeat("a", 80)
		node = "synthetic-" + strings.Repeat("n", 80)
	}
	fields := []any{2, origin, hub, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 32), strings.Repeat("d", 64), "23456789ABCD", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x23}, 32)), time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), node}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	code := wire.NodePairTrustScopedCodePrefix + base64.RawURLEncoding.EncodeToString(raw)
	parsed, err := wire.DecodeNodePairTrustScopedCode(code, time.Now())
	clear(parsed.OOBSecret)
	if err != nil {
		t.Fatal("synthetic UI parser fixture invalid", err)
	}
	return code
}

func TestDevicePairingInputPreservesCaseAndRejectsOverflow(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
		ready             bool
	}{
		{"case-preserving", "cicada-npt1.AaZz019_SyNtHeTiC", "cicada-npt1.AaZz019_SyNtHeTiC", false},
		{"outer-space", " \tcicada-npt1.AaZz019_SyNtHeTiC\r\n", "cicada-npt1.AaZz019_SyNtHeTiC", false},
		{"empty", " \t ", "", false},
		{"maximum", "cicada-npts1." + strings.Repeat("A", devicePairingInputBytes-len("cicada-npts1.")), "cicada-npts1." + strings.Repeat("A", devicePairingInputBytes-len("cicada-npts1.")), true},
		{"oversized", strings.Repeat("A", devicePairingInputBytes+1), strings.Repeat("A", devicePairingInputBytes+1), false},
		{"larger-paste", strings.Repeat("A", 2048), strings.Repeat("A", devicePairingInputBytes+1), false},
		{"byte-limit", strings.Repeat("密", 600), strings.Repeat("密", 600), false},
		{"scoped-code", "cicada-npts1.AaZz019_SyNtHeTiC", "cicada-npts1.AaZz019_SyNtHeTiC", true},
		{"legacy-overflow", "cicada-npt1." + strings.Repeat("A", 1024), "cicada-npt1." + strings.Repeat("A", 1024), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			editor := newDevicePairingEditor()
			editor.Insert(test.input)
			got, ready := devicePairingInput(&editor)
			if got != test.want || ready != test.ready || !editor.SingleLine || editor.Mask == 0 {
				t.Fatal("device pairing input changed case, lost overflow rejection or exposed unmasked text")
			}
		})
	}
}
