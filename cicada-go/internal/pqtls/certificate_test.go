package pqtls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTLSCertificateIssuerOpaqueDestroyAndAliases(t *testing.T) {
	secret := []byte("CICADA SYNTHETIC ISSUER HANDLE TEST ONLY")
	s := TLSIssuer{state: &tlsIssuerState{keyPEM: bytes.Clone(secret)}}
	alias := s
	retained := s.state.keyPEM
	for _, v := range []string{fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%#v", &s)} {
		if v != "pqtls.TLSIssuer[redacted]" || bytes.Contains([]byte(v), secret) {
			t.Fatal("issuer handle formatting leaked")
		}
	}
	if b, err := json.Marshal(s); err == nil || !errors.Is(err, ErrConfig) || len(b) != 0 {
		t.Fatal("issuer handle serialized")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); alias.Destroy() }()
	}
	s.Destroy()
	workers.Wait()
	if alias.state != s.state || len(alias.state.keyPEM) != 0 || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("issuer aliases did not share clearing")
	}
	TLSIssuer{}.Destroy()
}

func TestTLSCertificateParametersAndPEMBounds(t *testing.T) {
	at := time.Unix(1800000000, 0).UTC()
	p := TLSLeafParameters{TLSCSRParameters: TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"}, NotBefore: at, NotAfter: at.Add(time.Hour)}
	p.Serial[15] = 1
	p.ExpectedSPKIHash[0] = 1
	if !validLeafParameters(p, at) {
		t.Fatal("valid leaf parameters rejected")
	}
	for _, mutate := range []func(*TLSLeafParameters){
		func(v *TLSLeafParameters) { v.Serial = [16]byte{} }, func(v *TLSLeafParameters) { v.ExpectedSPKIHash = [32]byte{} },
		func(v *TLSLeafParameters) { v.NotAfter = at.Add(MaxTLSLeafLifetime + time.Second) },
		func(v *TLSLeafParameters) { v.NotBefore = at.Add(time.Second); v.NotAfter = at },
		func(v *TLSLeafParameters) { v.NotBefore = at.Add(time.Nanosecond) },
		func(v *TLSLeafParameters) { v.DNSName = "*.synthetic.invalid" },
	} {
		bad := p
		mutate(&bad)
		if validLeafParameters(bad, at) {
			t.Fatal("invalid leaf parameters accepted")
		}
	}
	if _, err := certificatePEMBlocks(bytes.Repeat([]byte("x"), MaxTLSCertificatePEMBytes+1), "CERTIFICATE", 1); !errors.Is(err, ErrCertificate) {
		t.Fatal("oversized certificate accepted")
	}
}
