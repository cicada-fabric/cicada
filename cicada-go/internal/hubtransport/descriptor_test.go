package hubtransport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

var syntheticTime = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// SyntheticDescriptorForTest is exported only in the test binary so the
// external compatibility test can exercise the existing App parser unchanged.
func SyntheticDescriptorForTest(t *testing.T) Descriptor { return newFixture(t).d }

type fixture struct {
	hub   *e2ee.Identity
	d     Descriptor
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	leaf  tls.Certificate
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	hub, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	origin, err := DefaultOrigin("hub_SYNTHETIC_transport_test_only")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC TRANSPORT TEST CA ONLY"}, IsCA: true,
		BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(origin)
	f := fixture{hub: hub, ca: root, caKey: key}
	f.leaf = f.makeLeaf(t, u.Hostname(), root.NotBefore, root.NotAfter)
	leaf, err := x509.ParseCertificate(f.leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	h := wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_SYNTHETIC_transport_test_only", Public: hub.Public(), KeyVersion: 1, Suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"}
	fp, err := wire.HubFingerprint(h)
	if err != nil {
		t.Fatal(err)
	}
	c := Claims{Format: DescriptorFormat, Version: Version, Origin: origin, Hub: h, HubFingerprint: fp, NodeControl: node.Public(), NodeControlKeyVersion: 1,
		TransportEpoch: 1, ServerName: u.Hostname(), RootCertificateDER: root.Raw, ServerSPKISHA256: hex.EncodeToString(pin[:])}
	f.d, err = SignDescriptor(hub, c)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) makeLeaf(t *testing.T, name string, before, after time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CICADA SYNTHETIC TRANSPORT TEST LEAF ONLY"},
		DNSNames: []string{name}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, &key.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func copyDescriptor(t *testing.T, d Descriptor) Descriptor {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var result Descriptor
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("copy descriptor")
	}
	return result
}

func activation(t *testing.T, d Descriptor) string {
	t.Helper()
	m := wire.ActivationMaterial{Format: wire.ActivationFormat, Version: 1, Purpose: wire.PurposeInitialActivation, Origin: d.Claims.Origin, HubID: d.Claims.Hub.HubID,
		HubFingerprint: d.Claims.HubFingerprint, AccountID: "account_SYNTHETIC", OwnerID: "human_SYNTHETIC", ActivationID: strings.Repeat("a", 32), SetupEpoch: 1, AccountEpoch: 1,
		Code: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, wire.CodeBytes)), IssuedAt: syntheticTime.Format(time.RFC3339Nano), ExpiresAt: syntheticTime.Add(time.Hour).Format(time.RFC3339Nano)}
	code, err := wire.EncodeActivationCode(m)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestDefaultOriginStableAndDNSLabel(t *testing.T) {
	got, err := DefaultOrigin("hub_SYNTHETIC_transport_test_only")
	if err != nil || got == "" {
		t.Fatal("origin rejected")
	}
	label := strings.TrimSuffix(strings.TrimPrefix(got, "https://h-"), ".cicada.invalid")
	if len(label) != 52 || len(strings.Split(strings.TrimPrefix(got, "https://"), ".")[0]) > 63 {
		t.Fatal("invalid DNS label length")
	}
	if got != "https://h-5jvj243d45yyiwckemvvtzuar4luuyvvhqjm4enldzxxu247ffpa.cicada.invalid" {
		t.Fatal("origin derivation changed")
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			t.Fatal("invalid base32 label")
		}
	}
	other, _ := DefaultOrigin("hub_SYNTHETIC_other")
	if got == other {
		t.Fatal("Hub IDs collide")
	}
	for _, id := range []string{"", " bad", "bad/id", "bad\x00id", strings.Repeat("x", 129)} {
		if _, err := DefaultOrigin(id); err == nil {
			t.Fatal("invalid Hub ID accepted")
		}
	}
}

func TestDescriptorBindingRejectsTampering(t *testing.T) {
	f := newFixture(t)
	if ValidateDescriptor(f.d, syntheticTime) != nil {
		t.Fatal("valid descriptor rejected")
	}
	cases := map[string]func(*Descriptor){
		"version":      func(d *Descriptor) { d.Claims.Version++ },
		"origin":       func(d *Descriptor) { d.Claims.Origin = "https://foreign.synthetic.invalid" },
		"hub pin":      func(d *Descriptor) { d.Claims.HubFingerprint = strings.Repeat("0", 64) },
		"hub key":      func(d *Descriptor) { d.Claims.Hub.Public.KEMPublic[0] ^= 1 },
		"node key":     func(d *Descriptor) { d.Claims.NodeControl.KEMPublic[0] ^= 1 },
		"node version": func(d *Descriptor) { d.Claims.NodeControlKeyVersion++ },
		"epoch":        func(d *Descriptor) { d.Claims.TransportEpoch++ },
		"root":         func(d *Descriptor) { d.Claims.RootCertificateDER[10] ^= 1 },
		"server pin":   func(d *Descriptor) { d.Claims.ServerSPKISHA256 = strings.Repeat("0", 64) },
		"signature":    func(d *Descriptor) { d.Signature[0] ^= 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := copyDescriptor(t, f.d)
			change(&d)
			if ValidateDescriptor(d, syntheticTime) == nil {
				t.Fatal("tampered descriptor verified")
			}
		})
	}
	if ValidateDescriptor(f.d, f.ca.NotAfter) == nil || ValidateDescriptor(f.d, f.ca.NotBefore.Add(-time.Second)) == nil {
		t.Fatal("invalid CA time accepted")
	}
	if MatchNodeControl(f.d, f.d.Claims.Hub.HubID, f.d.Claims.NodeControl, 1, nodewire.IdentityFingerprint(f.d.Claims.NodeControl)) != nil {
		t.Fatal("valid Node-Control metadata rejected")
	}
	if MatchNodeControl(f.d, "foreign", f.d.Claims.NodeControl, 1, nodewire.IdentityFingerprint(f.d.Claims.NodeControl)) == nil {
		t.Fatal("foreign Node-Control metadata accepted")
	}
}

func TestBootstrapPreservesV1AndRejectsCrossBinding(t *testing.T) {
	f := newFixture(t)
	code := activation(t, f.d)
	encoded, err := EncodeBootstrap(f.d, code)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeBootstrap(encoded)
	if err != nil || b.ActivationCode != code || !reflect.DeepEqual(b.Descriptor, f.d) {
		t.Fatal("bootstrap changed original material")
	}
	m, err := ValidateBootstrap(b, syntheticTime.Add(time.Minute))
	if err != nil {
		t.Fatal("live activation rejected")
	}
	if _, err := ValidateBootstrap(b, syntheticTime.Add(2*time.Hour)); err == nil {
		t.Fatal("expired activation accepted")
	}
	if strings.Contains(fmt.Sprint(b), code) || strings.Contains(fmt.Sprintf("%#v", b), code) {
		t.Fatal("bootstrap formatting exposes secret")
	}
	for _, field := range []string{"origin", "hub", "fingerprint"} {
		t.Run(field, func(t *testing.T) {
			bad := m
			switch field {
			case "origin":
				bad.Origin = "https://foreign.synthetic.invalid"
			case "hub":
				bad.HubID = "hub_foreign"
			case "fingerprint":
				bad.HubFingerprint = strings.Repeat("0", 64)
			}
			inner, err := wire.EncodeActivationCode(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = EncodeBootstrap(f.d, inner); err == nil {
				t.Fatal("cross-Hub activation accepted")
			}
		})
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	public := owner.Public()
	m.Purpose = wire.PurposeLegacyContinuation
	m.ExpectedOwnerPublic = &public
	m.AllowLoopbackHTTP = true
	legacy, err := wire.EncodeActivationCode(m)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := EncodeBootstrap(f.d, legacy)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBootstrap(wrapped)
	if err != nil || restored.ActivationCode != legacy {
		t.Fatal("legacy bytes changed")
	}
}

func TestCodecsRejectNoncanonicalAndOversizedInput(t *testing.T) {
	f := newFixture(t)
	text, err := EncodeDescriptor(f.d)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeDescriptor(text)
	if err != nil || !reflect.DeepEqual(d, f.d) {
		t.Fatal("descriptor round trip failed")
	}
	raw, _ := json.Marshal(f.d)
	invalid := []string{"", text + "=", text + "\n", BootstrapPrefix + strings.TrimPrefix(text, DescriptorPrefix), DescriptorPrefix + strings.Repeat("A", MaxDescriptorText),
		DescriptorPrefix + base64.RawURLEncoding.EncodeToString(append(raw, ' ')),
		DescriptorPrefix + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), []byte("{}")...)),
		DescriptorPrefix + base64.RawURLEncoding.EncodeToString(append([]byte("{\"unknown\":null,"), raw[1:]...)),
		DescriptorPrefix + base64.RawURLEncoding.EncodeToString(append([]byte("{\"claims\":null,"), raw[1:]...)),
	}
	for i, v := range invalid {
		if _, err := DecodeDescriptor(v); err == nil {
			t.Fatalf("invalid descriptor %d accepted", i)
		}
	}
	wrapped, err := EncodeBootstrap(f.d, activation(t, f.d))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{text, wrapped + "=", wrapped + "\n", BootstrapPrefix + strings.Repeat("A", MaxBootstrapText)} {
		if _, err := DecodeBootstrap(v); err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
}
