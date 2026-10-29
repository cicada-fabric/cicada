package native

import (
	"strings"
	"testing"
)

func TestDevicePairingInputPreservesCaseAndRejectsOverflow(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
		ready             bool
	}{
		{"case-preserving", "cicada-npt1.AaZz019_SyNtHeTiC", "cicada-npt1.AaZz019_SyNtHeTiC", true},
		{"outer-space", " \tcicada-npt1.AaZz019_SyNtHeTiC\r\n", "cicada-npt1.AaZz019_SyNtHeTiC", true},
		{"empty", " \t ", "", false},
		{"maximum", strings.Repeat("A", devicePairingInputBytes), strings.Repeat("A", devicePairingInputBytes), true},
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
