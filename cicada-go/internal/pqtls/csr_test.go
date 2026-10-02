package pqtls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestTLSCSRPrivateKeyRedactionDestroyAndConcurrentExport(t *testing.T) {
	secret := []byte("CICADA SYNTHETIC SECRET HANDLE TEST ONLY")
	k := TLSPrivateKey{state: &tlsPrivateKeyState{pem: bytes.Clone(secret)}}
	alias := k
	defer k.Destroy()
	for _, text := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%#v", &k)} {
		if bytes.Contains([]byte(text), secret) || text != "pqtls.TLSPrivateKey[redacted]" {
			t.Fatal("private handle formatting did not redact")
		}
	}
	if b, err := json.Marshal(k); err == nil || !errors.Is(err, ErrConfig) || len(b) != 0 {
		t.Fatal("private handle was JSON-serializable")
	}
	exported, err := k.ExportPEM()
	if err != nil || !bytes.Equal(exported, secret) {
		t.Fatal("explicit export failed")
	}
	exported[0] = 'X'
	clear(exported)
	retained := k.state.pem
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 32; j++ {
				copy, err := k.ExportPEM()
				if err == nil && !bytes.Equal(copy, secret) {
					t.Error("export aliased caller-owned memory")
				}
				clear(copy)
			}
		}()
	}
	k.Destroy()
	workers.Wait()
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("Destroy retained private bytes")
	}
	if b, err := k.ExportPEM(); !errors.Is(err, ErrConfig) || b != nil {
		t.Fatal("destroyed handle exported")
	}
	if b, err := alias.ExportPEM(); !errors.Is(err, ErrConfig) || b != nil {
		t.Fatal("copied handle did not share destruction state")
	}
	TLSPrivateKey{}.Destroy()
	if b, err := (TLSPrivateKey{}).ExportPEM(); !errors.Is(err, ErrConfig) || b != nil {
		t.Fatal("empty handle exported")
	}
}

func TestTLSCSRParametersRejectAmbiguousNames(t *testing.T) {
	for _, p := range []TLSCSRParameters{
		{}, {Role: "owner", DNSName: "node.synthetic.invalid"}, {Role: "node", DNSName: "*.synthetic.invalid"},
		{Role: "hub", DNSName: "127.0.0.1"}, {Role: "hub", DNSName: "NODE.synthetic.invalid"},
		{Role: "node", DNSName: "node.synthetic.invalid,DNS:other.invalid"}, {Role: "node", DNSName: "node.invalid\x00"},
		{Role: "node", DNSName: "-node.invalid"}, {Role: "hub", DNSName: "node.invalid."},
	} {
		if validTLSCSRParameters(p) {
			t.Fatal("ambiguous CSR parameters accepted")
		}
	}
}
