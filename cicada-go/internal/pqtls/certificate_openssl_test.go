//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type certificateFixture struct {
	dir              string
	chain, root, key []byte
	at               time.Time
}

func certificateRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read synthetic certificate fixture")
	}
	return data
}
func certificateCLI(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, opensslExecutable, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("official synthetic certificate CLI failed; output suppressed")
	}
	return out
}
func newCertificateFixture(t *testing.T, rootAlgorithm, issuerAlgorithm, issuerConstraints, issuerUsage, issuerEKU string) certificateFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private synthetic CA directory")
	}
	certificateCLI(t, dir, "req", "-new", "-x509", "-newkey", rootAlgorithm, "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=CICADA SYNTHETIC ROOT ONLY",
		"-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
	certificateCLI(t, dir, "req", "-new", "-newkey", issuerAlgorithm, "-noenc", "-keyout", "issuer.key", "-out", "issuer.csr", "-subj", "/CN=CICADA SYNTHETIC ISSUER ONLY")
	ext := issuerConstraints + "\n" + issuerUsage + "\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
	if issuerEKU != "" {
		ext += issuerEKU + "\n"
	}
	extPath := csrPrivateFile(t, dir, "issuer.ext", []byte(ext))
	certificateCLI(t, dir, "x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "issuer.pem", "-days", "1", "-extfile", extPath)
	root := certificateRead(t, filepath.Join(dir, "root.pem"))
	issuer := certificateRead(t, filepath.Join(dir, "issuer.pem"))
	key := certificateRead(t, filepath.Join(dir, "issuer.key"))
	t.Cleanup(func() { clear(key) })
	return certificateFixture{dir: dir, chain: append(issuer, root...), root: root, key: key, at: time.Now().UTC().Truncate(time.Second)}
}
func normalCertificateFixture(t *testing.T) certificateFixture {
	return newCertificateFixture(t, "ML-DSA-65", "ML-DSA-65", "basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign", "")
}
func certificateRequest(t *testing.T, role string, at time.Time) (TLSPrivateKey, TLSCSRProfile, TLSLeafParameters) {
	t.Helper()
	p := TLSCSRParameters{Role: role, DNSName: role + ".synthetic.invalid"}
	key, csr, err := GenerateTLSCSR(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	params := TLSLeafParameters{TLSCSRParameters: p, NotBefore: at, NotAfter: at.Add(time.Hour), ExpectedSPKIHash: csr.SPKIDERHash}
	params.Serial[15] = 1
	return key, csr, params
}

func TestTLSCertificateIssueInspectAndOfficialVerify(t *testing.T) {
	f := normalCertificateFixture(t)
	for _, role := range []string{"node", "hub"} {
		t.Run(role, func(t *testing.T) {
			s, ip, err := ImportTLSIssuer(f.chain, f.key, f.root, role, f.at)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Destroy()
			key, csr, p := certificateRequest(t, role, f.at)
			leaf, err := s.IssueTLSLeaf(csr.CSRPEM, p, f.at)
			if err != nil {
				t.Fatal(err)
			}
			if leaf.SPKIDERHash != csr.SPKIDERHash || leaf.CSRDERHash != csr.CSRDERHash || leaf.IssuerCertificateHash != ip.CertificateDERHash || !leaf.VerifiedNotAfter.Equal(p.NotAfter) {
				t.Fatal("issued public receipt mismatch")
			}
			checked, err := InspectTLSLeaf(leaf.CertificatePEM, f.chain, f.root, p, f.at)
			if err != nil || checked.CertificateDERHash != leaf.CertificateDERHash || checked.SPKIDERHash != leaf.SPKIDERHash || checked.CSRDERHash != [32]byte{} {
				t.Fatal("issued leaf strict inspection failed")
			}
			leafPath := csrPrivateFile(t, f.dir, role+".pem", leaf.CertificatePEM)
			purpose := map[string]string{"node": "sslclient", "hub": "sslserver"}[role]
			out := certificateCLI(t, f.dir, "verify", "-x509_strict", "-auth_level", "3", "-purpose", purpose, "-verify_hostname", p.DNSName, "-attime", fmtCertificateTime(f.at), "-CAfile", "root.pem", "-untrusted", "issuer.pem", leafPath)
			if !bytes.Contains(out, []byte(": OK")) {
				t.Fatal("official certificate verifier did not confirm")
			}
			text := certificateCLI(t, f.dir, "x509", "-in", leafPath, "-text", "-noout")
			if !bytes.Contains(text, []byte("X509v3 Subject Alternative Name: critical")) || !bytes.Contains(text, []byte("DNS:"+p.DNSName)) {
				t.Fatal("empty-subject leaf lacks critical exact SAN")
			}
			private, err := key.ExportPEM()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			keyPath := csrPrivateFile(t, f.dir, role+".key", private)
			spkiPath := filepath.Join(f.dir, role+".spki.der")
			certificateCLI(t, f.dir, "pkey", "-in", keyPath, "-pubout", "-outform", "DER", "-out", spkiPath)
			if sha256.Sum256(certificateRead(t, spkiPath)) != leaf.SPKIDERHash {
				t.Fatal("official exported key SPKI differs from signed leaf")
			}
		})
	}
}
func fmtCertificateTime(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func TestTLSCertificateRejectIssuerKeyCAAlgorithmPurposeAndTime(t *testing.T) {
	cases := []struct{ name, rootAlgorithm, issuerAlgorithm, constraints, usage, eku, role string }{
		{"wrong_mldsa", "ML-DSA-65", "ML-DSA-44", "basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign", "", "node"},
		{"classical_issuer", "ML-DSA-65", "RSA:2048", "basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign", "", "node"},
		{"classical_root", "RSA:2048", "ML-DSA-65", "basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign", "", "node"},
		{"not_ca", "ML-DSA-65", "ML-DSA-65", "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", "", "node"},
		{"wrong_pathlen", "ML-DSA-65", "ML-DSA-65", "basicConstraints=critical,CA:TRUE,pathlen:1", "keyUsage=critical,keyCertSign,cRLSign", "", "node"},
		{"missing_sign_usage", "ML-DSA-65", "ML-DSA-65", "basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,digitalSignature", "", "node"},
		{"wrong_purpose", "ML-DSA-65", "ML-DSA-65", "basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign", "extendedKeyUsage=serverAuth", "node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCertificateFixture(t, tc.rootAlgorithm, tc.issuerAlgorithm, tc.constraints, tc.usage, tc.eku)
			s, _, err := ImportTLSIssuer(f.chain, f.key, f.root, tc.role, f.at)
			defer s.Destroy()
			if err == nil || s.state != nil {
				t.Fatal("invalid issuer accepted")
			}
		})
	}
	f := normalCertificateFixture(t)
	other := normalCertificateFixture(t)
	for name, mutate := range map[string]func() ([]byte, []byte, []byte, time.Time){
		"wrong_key":     func() ([]byte, []byte, []byte, time.Time) { return f.chain, other.key, f.root, f.at },
		"wrong_trust":   func() ([]byte, []byte, []byte, time.Time) { return f.chain, f.key, other.root, f.at },
		"expired":       func() ([]byte, []byte, []byte, time.Time) { return f.chain, f.key, f.root, f.at.Add(48 * time.Hour) },
		"not_yet_valid": func() ([]byte, []byte, []byte, time.Time) { return f.chain, f.key, f.root, f.at.Add(-time.Hour) },
		"root_as_issuer": func() ([]byte, []byte, []byte, time.Time) {
			return f.root, certificateRead(t, filepath.Join(f.dir, "root.key")), f.root, f.at
		},
		"multiple_key_pem": func() ([]byte, []byte, []byte, time.Time) {
			return f.chain, append(bytes.Clone(f.key), f.key...), f.root, f.at
		},
		"key_trailing_data": func() ([]byte, []byte, []byte, time.Time) {
			return f.chain, append(bytes.Clone(f.key), []byte("trailing")...), f.root, f.at
		},
	} {
		t.Run(name, func(t *testing.T) {
			chain, key, trust, at := mutate()
			copy := bytes.Clone(key)
			defer clear(copy)
			s, _, err := ImportTLSIssuer(chain, copy, trust, "node", at)
			defer s.Destroy()
			if err == nil || s.state != nil {
				t.Fatal("invalid issuer input accepted")
			}
		})
	}
}

func TestTLSCertificateRejectCSRExpectationAndLeafSubstitution(t *testing.T) {
	f := normalCertificateFixture(t)
	s, _, err := ImportTLSIssuer(f.chain, f.key, f.root, "node", f.at)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	_, csr, p := certificateRequest(t, "node", f.at)
	leaf, err := s.IssueTLSLeaf(csr.CSRPEM, p, f.at)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TLSLeafParameters){
		"DNS": func(v *TLSLeafParameters) { v.DNSName = "other.synthetic.invalid" }, "role": func(v *TLSLeafParameters) { v.Role = "hub" },
		"serial": func(v *TLSLeafParameters) { v.Serial[15] = 2 }, "SPKI": func(v *TLSLeafParameters) { v.ExpectedSPKIHash[0] ^= 1 },
		"not_before": func(v *TLSLeafParameters) { v.NotBefore = v.NotBefore.Add(time.Second) }, "not_after": func(v *TLSLeafParameters) { v.NotAfter = v.NotAfter.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			mutate(&bad)
			if got, err := InspectTLSLeaf(leaf.CertificatePEM, f.chain, f.root, bad, f.at); err == nil || len(got.CertificatePEM) > 0 {
				t.Fatal("substituted leaf expectation accepted")
			}
		})
	}
	for name, input := range map[string][]byte{
		"multiple": append(bytes.Clone(leaf.CertificatePEM), leaf.CertificatePEM...), "trailing": append(bytes.Clone(leaf.CertificatePEM), []byte("trailing")...),
		"invalid_prefix": append([]byte("-----BEGIN CERTIFICATE-----\nBAD\n-----END CERTIFICATE-----\n"), leaf.CertificatePEM...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectTLSLeaf(input, f.chain, f.root, p, f.at); err == nil {
				t.Fatal("bad certificate envelope accepted")
			}
		})
	}
	block, _ := pem.Decode(leaf.CertificatePEM)
	bad := bytes.Clone(block.Bytes)
	bad[len(bad)-1] ^= 1
	for name, input := range map[string][]byte{"signature": bad, "DER_tail": append(bytes.Clone(block.Bytes), 0)} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectTLSLeaf(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: input}), f.chain, f.root, p, f.at); err == nil {
				t.Fatal("tampered/trailing certificate DER accepted")
			}
		})
	}
	badp := p
	badp.ExpectedSPKIHash[0] ^= 1
	if _, err := s.IssueTLSLeaf(csr.CSRPEM, badp, f.at); !errors.Is(err, ErrProfile) {
		t.Fatal("CSR expected key mismatch signed")
	}
	badp = p
	badp.NotAfter = badp.NotBefore.Add(MaxTLSLeafLifetime + time.Second)
	if _, err := s.IssueTLSLeaf(csr.CSRPEM, badp, f.at); !errors.Is(err, ErrConfig) {
		t.Fatal("overlong lifetime signed")
	}
	if _, err := s.IssueTLSLeaf(csr.CSRPEM, p, f.at.Add(2*time.Hour)); !errors.Is(err, ErrCertificateValidity) {
		t.Fatal("already expired leaf signed")
	}
	t.Run("exclusive_leaf_expiry", func(t *testing.T) {
		if _, err := InspectTLSLeaf(leaf.CertificatePEM, f.chain, f.root, p, p.NotAfter); !errors.Is(err, ErrCertificateValidity) {
			t.Fatal("leaf retained authority at exclusive expiry")
		}
	})
	t.Run("issuer_window", func(t *testing.T) {
		boundedIssuer, info, err := ImportTLSIssuer(f.chain, f.key, f.root, "node", f.at)
		if err != nil {
			t.Fatal(err)
		}
		defer boundedIssuer.Destroy()
		bad := p
		bad.NotBefore = f.at.Add(time.Minute)
		bad.NotAfter = info.VerifiedNotAfter.Add(time.Second)
		if _, err := s.IssueTLSLeaf(csr.CSRPEM, bad, bad.NotBefore); !errors.Is(err, ErrCertificateValidity) {
			t.Fatal("leaf outlived issuer chain")
		}
	})
}

func TestTLSCertificateRejectMaliciousCSRBeforeSigning(t *testing.T) {
	f := normalCertificateFixture(t)
	s, _, err := ImportTLSIssuer(f.chain, f.key, f.root, "node", f.at)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	_, _, p := certificateRequest(t, "node", f.at)
	for _, kind := range []string{"unknown-extension", "classical", "wrong-role", "subject-cn"} {
		t.Run(kind, func(t *testing.T) {
			algorithm := "ML-DSA-65"
			subject := "/"
			eku := "extendedKeyUsage=clientAuth"
			if kind == "classical" {
				algorithm = "RSA:2048"
			}
			if kind == "subject-cn" {
				subject = "/CN=CICADA SYNTHETIC CSR ONLY"
			}
			if kind == "wrong-role" {
				eku = "extendedKeyUsage=serverAuth"
			}
			path := filepath.Join(f.dir, kind+".csr")
			args := []string{"req", "-new", "-newkey", algorithm, "-noenc", "-keyout", kind + ".key", "-out", path, "-subj", subject,
				"-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", eku, "-addext", "subjectAltName=DNS:" + p.DNSName}
			if kind == "unknown-extension" {
				args = append(args, "-addext", "1.2.3.4=DER:05:00")
			}
			certificateCLI(t, f.dir, args...)
			if got, err := s.IssueTLSLeaf(certificateRead(t, path), p, f.at); !errors.Is(err, ErrProfile) || len(got.CertificatePEM) != 0 {
				t.Fatal("malicious CSR reached certificate output")
			}
		})
	}
	_, csr, params := certificateRequest(t, "node", f.at)
	block, _ := pem.Decode(csr.CSRPEM)
	damaged := bytes.Clone(block.Bytes)
	damaged[len(damaged)-1] ^= 1
	if got, err := s.IssueTLSLeaf(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: damaged}), params, f.at); !errors.Is(err, ErrCSR) || len(got.CertificatePEM) != 0 {
		t.Fatal("tampered CSR signed")
	}
}

func TestTLSCertificateConcurrentIssueDestroyAndInvalidCleanup(t *testing.T) {
	f := normalCertificateFixture(t)
	s, _, err := ImportTLSIssuer(f.chain, f.key, f.root, "node", f.at)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	_, csr, p := certificateRequest(t, "node", f.at)
	alias := s
	started := make(chan struct{}, 8)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			v := p
			v.Serial[15] = byte(i + 1)
			for j := 0; j < 4; j++ {
				leaf, err := alias.IssueTLSLeaf(csr.CSRPEM, v, f.at)
				if err != nil {
					if !errors.Is(err, ErrIssuer) {
						t.Error("concurrent issue unexpected error")
					}
					return
				}
				if j == 0 {
					started <- struct{}{}
				}
				if _, err := InspectTLSLeaf(leaf.CertificatePEM, f.chain, f.root, v, f.at); err != nil {
					t.Error("concurrent leaf inspect failed")
				}
				if _, err := InspectTLSLeaf([]byte("malformed"), f.chain, f.root, v, f.at); !errors.Is(err, ErrCertificate) {
					t.Error("invalid cleanup path accepted")
				}
			}
		}(i)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no concurrent issuer operation completed")
	}
	s.Destroy()
	workers.Wait()
	if _, err := alias.IssueTLSLeaf(csr.CSRPEM, p, f.at); !errors.Is(err, ErrIssuer) {
		t.Fatal("destroyed issuer alias signed")
	}
}

func TestTLSCertificateOnlyModeRejectsOtherSelectors(t *testing.T) {
	if os.Getenv("PQTLS_TEST_CERTIFICATE_ONLY") != "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("find certificate test binary")
	}
	for _, pattern := range []string{".", "^TestExactProfileAndSPKIPin$", "^TestTLSCertificate|TestTLSCSR"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, executable, "-test.run", pattern)
		out, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("other selectors are NOT_RUN")) || bytes.Contains(out, []byte("=== RUN")) {
			t.Fatal("certificate-only mode admitted other tests")
		}
	}
}

func TestTLSCertificateRejectSignedMaliciousProfilesAndCAKeyReuse(t *testing.T) {
	f := normalCertificateFixture(t)
	s, _, err := ImportTLSIssuer(f.chain, f.key, f.root, "node", f.at)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	_, csr, p := certificateRequest(t, "node", f.at)
	leaf, err := s.IssueTLSLeaf(csr.CSRPEM, p, f.at)
	if err != nil {
		t.Fatal(err)
	}
	leafPath := csrPrivateFile(t, f.dir, "valid-leaf.pem", leaf.CertificatePEM)
	helper := filepath.Join(f.dir, "synthetic-certificate-fixture")
	stage := filepath.Dir(filepath.Dir(opensslExecutable))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cc", "-Wall", "-Wextra", "-Werror", "-I"+filepath.Join(stage, "include"), "testdata/certificate-invalid-fixture.c",
		"-L"+filepath.Join(stage, "lib"), "-Wl,-rpath,"+filepath.Join(stage, "lib"), "-lcrypto", "-o", helper)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile official-API certificate fixture helper: %s", out)
	}
	for _, mutation := range []string{"noncritical-san", "duplicate-extension", "unknown-extension", "subject-cn", "wrong-signature-oid"} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(f.dir, mutation+".pem")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, helper, mutation, leafPath, filepath.Join(f.dir, "issuer.key"), path)
			if _, err := cmd.CombinedOutput(); err != nil {
				t.Fatal("official-API certificate mutation failed")
			}
			if got, err := InspectTLSLeaf(certificateRead(t, path), f.chain, f.root, p, f.at); !errors.Is(err, ErrProfile) || len(got.CertificatePEM) != 0 {
				t.Fatal("signed malicious certificate profile accepted")
			}
		})
	}
	for _, name := range []string{"issuer", "root"} {
		t.Run("reuse_"+name, func(t *testing.T) {
			path := filepath.Join(f.dir, "reuse-"+name+".csr")
			certificateCLI(t, f.dir, "req", "-new", "-key", name+".key", "-out", path, "-subj", "/",
				"-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=clientAuth", "-addext", "subjectAltName=DNS:"+p.DNSName)
			input := certificateRead(t, path)
			request, err := InspectTLSCSR(input, p.TLSCSRParameters)
			if err != nil {
				t.Fatal("CA reuse CSR fixture not a strict valid possession proof")
			}
			bad := p
			bad.ExpectedSPKIHash = request.SPKIDERHash
			if got, err := s.IssueTLSLeaf(input, bad, f.at); !errors.Is(err, ErrProfile) || len(got.CertificatePEM) != 0 {
				t.Fatal("issuer/root key was reused as a TLS leaf")
			}
		})
	}
}
