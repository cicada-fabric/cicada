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
	"strings"
	"sync"
	"testing"
	"time"
)

func csrOfficial(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, opensslExecutable, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("official OpenSSL CSR-only command failed (output suppressed)")
	}
	return output
}

func csrPrivateFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create synthetic private CSR test file")
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("write synthetic private CSR test file")
	}
	return path
}

func TestTLSCSRGeneratedProfileAndOfficialVerification(t *testing.T) {
	var previous [32]byte
	for _, role := range []string{"node", "hub"} {
		t.Run(role, func(t *testing.T) {
			p := TLSCSRParameters{Role: role, DNSName: role + ".synthetic.invalid"}
			key, profile, err := GenerateTLSCSR(p)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			if profile.Parameters != p || profile.KeyAlgorithm != "ML-DSA-65" || profile.SignatureAlgorithm != "ML-DSA-65" || len(profile.SPKIDER) == 0 {
				t.Fatal("generated CSR profile incomplete")
			}
			block, rest := pem.Decode(profile.CSRPEM)
			if block == nil || len(rest) != 0 || sha256.Sum256(block.Bytes) != profile.CSRDERHash || sha256.Sum256(profile.SPKIDER) != profile.SPKIDERHash {
				t.Fatal("public CSR/SPKI receipt mismatch")
			}
			if previous == profile.SPKIDERHash {
				t.Fatal("Hub and Node reused a generated key")
			}
			previous = profile.SPKIDERHash
			checked, err := InspectTLSCSR(profile.CSRPEM, p)
			if err != nil || checked.CSRDERHash != profile.CSRDERHash || checked.SPKIDERHash != profile.SPKIDERHash {
				t.Fatal("generated CSR inspection failed")
			}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal("private CSR test directory")
			}
			private, err := key.ExportPEM()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			privatePath := csrPrivateFile(t, dir, "synthetic-only.key", private)
			csrPath := csrPrivateFile(t, dir, "synthetic-only.csr", profile.CSRPEM)
			verification := csrOfficial(t, dir, "req", "-in", csrPath, "-verify", "-noout")
			if !bytes.Contains(verification, []byte("verify OK")) {
				t.Fatal("official CSR verifier did not confirm proof")
			}
			spkiPath := filepath.Join(dir, "public-only.spki.der")
			csrOfficial(t, dir, "pkey", "-in", privatePath, "-pubout", "-outform", "DER", "-out", spkiPath)
			spki, err := os.ReadFile(spkiPath)
			if err != nil || !bytes.Equal(spki, profile.SPKIDER) {
				t.Fatal("exported private key differs from CSR public key")
			}
			text := csrOfficial(t, dir, "req", "-in", csrPath, "-text", "-noout")
			for _, expected := range []string{"CA:FALSE", "Digital Signature", "DNS:" + p.DNSName, "Signature Algorithm: ML-DSA-65"} {
				if !bytes.Contains(text, []byte(expected)) {
					t.Fatal("official CSR profile differs from requested profile")
				}
			}
			wrong := p
			wrong.Role = map[string]string{"node": "hub", "hub": "node"}[role]
			if _, err := InspectTLSCSR(profile.CSRPEM, wrong); !errors.Is(err, ErrProfile) {
				t.Fatal("role substitution accepted")
			}
			wrong = p
			wrong.DNSName = "other.synthetic.invalid"
			if _, err := InspectTLSCSR(profile.CSRPEM, wrong); !errors.Is(err, ErrProfile) {
				t.Fatal("DNS substitution accepted")
			}
		})
	}
}

func TestTLSCSRRejectMalformedAndMultipleInputs(t *testing.T) {
	p := TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"}
	key, profile, err := GenerateTLSCSR(p)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	block, _ := pem.Decode(profile.CSRPEM)
	corrupted := bytes.Clone(block.Bytes)
	corrupted[len(corrupted)-1] ^= 1
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Comment": "synthetic"}, Bytes: block.Bytes})
	inputs := map[string][]byte{
		"empty": nil, "oversized": bytes.Repeat([]byte("x"), MaxTLSCSRPEMBytes+1),
		"leading_junk":               append([]byte("untrusted prefix\n"), profile.CSRPEM...),
		"trailing_junk":              append(bytes.Clone(profile.CSRPEM), []byte("untrusted suffix")...),
		"two_requests":               append(bytes.Clone(profile.CSRPEM), profile.CSRPEM...),
		"invalid_then_valid_request": append([]byte("-----BEGIN CERTIFICATE REQUEST-----\nINVALID\n-----END CERTIFICATE REQUEST-----\n"), profile.CSRPEM...),
		"pem_headers":                withHeaders,
		"wrong_pem_kind":             pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block.Bytes}),
		"truncated_der":              pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes[:len(block.Bytes)-1]}),
		"trailing_der":               pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: append(bytes.Clone(block.Bytes), 0)}),
		"tampered_signature":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: corrupted}),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			got, err := InspectTLSCSR(input, p)
			if !errors.Is(err, ErrCSR) || len(got.CSRPEM) != 0 {
				t.Fatal("malformed CSR accepted or returned material")
			}
		})
	}
	if _, err := InspectTLSCSR(append([]byte(" \t\r\n"), append(bytes.Clone(profile.CSRPEM), '\n')...), p); err != nil {
		t.Fatal("legal PEM surrounding whitespace rejected")
	}
}

func TestTLSCSRRejectOfficialWrongKeysSubjectsAndExtensions(t *testing.T) {
	base := []string{"basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", "extendedKeyUsage=clientAuth", "subjectAltName=DNS:node.synthetic.invalid"}
	cases := []struct {
		name, key, subject string
		extensions         []string
	}{
		{"classical_rsa", "RSA:2048", "/", base},
		{"classical_ec", "EC", "/", base},
		{"wrong_mldsa44", "ML-DSA-44", "/", base},
		{"wrong_mldsa87", "ML-DSA-87", "/", base},
		{"extra_subject", "ML-DSA-65", "/CN=node.synthetic.invalid", base},
		{"missing_extensions", "ML-DSA-65", "/", nil},
		{"cn_fallback", "ML-DSA-65", "/CN=node.synthetic.invalid", base[:3]},
		{"ca_requested", "ML-DSA-65", "/", append([]string{"basicConstraints=critical,CA:TRUE"}, base[1:]...)},
		{"wrong_key_usage", "ML-DSA-65", "/", []string{base[0], "keyUsage=critical,digitalSignature,keyCertSign", base[2], base[3]}},
		{"extra_eku", "ML-DSA-65", "/", []string{base[0], base[1], "extendedKeyUsage=clientAuth,serverAuth", base[3]}},
		{"wrong_criticality", "ML-DSA-65", "/", []string{"basicConstraints=CA:FALSE", base[1], base[2], base[3]}},
		{"wildcard_san", "ML-DSA-65", "/", append(append([]string{}, base[:3]...), "subjectAltName=DNS:*.synthetic.invalid")},
		{"multiple_sans", "ML-DSA-65", "/", append(append([]string{}, base[:3]...), "subjectAltName=DNS:node.synthetic.invalid,DNS:other.invalid")},
		{"ip_san", "ML-DSA-65", "/", append(append([]string{}, base[:3]...), "subjectAltName=IP:127.0.0.1")},
		{"unknown_extension", "ML-DSA-65", "/", append(append([]string{}, base...), "1.2.3.4=DER:05:00")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal("private CSR test directory")
			}
			args := []string{"req", "-new", "-newkey", tc.key, "-noenc", "-keyout", filepath.Join(dir, "synthetic-only.key"), "-out", filepath.Join(dir, "synthetic-only.csr"), "-subj", tc.subject}
			if tc.key == "EC" {
				args = append(args, "-pkeyopt", "ec_paramgen_curve:P-256")
			}
			for _, ext := range tc.extensions {
				args = append(args, "-addext", ext)
			}
			csrOfficial(t, dir, args...)
			csr, err := os.ReadFile(filepath.Join(dir, "synthetic-only.csr"))
			if err != nil {
				t.Fatal("read synthetic public CSR")
			}
			if got, err := InspectTLSCSR(csr, TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"}); !errors.Is(err, ErrProfile) || len(got.CSRPEM) != 0 {
				t.Fatal("unauthorized CSR key/profile accepted")
			}
		})
	}
}

func TestTLSCSRRejectLibraryConstructedAttributesAndSignatureOID(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private CSR test directory")
	}
	helper := filepath.Join(dir, "synthetic-csr-fixture")
	stage := filepath.Dir(filepath.Dir(opensslExecutable))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cc", "-Wall", "-Wextra", "-Werror", "-I"+filepath.Join(stage, "include"),
		"testdata/csr-invalid-fixture.c", "-L"+filepath.Join(stage, "lib"), "-Wl,-rpath,"+filepath.Join(stage, "lib"), "-lcrypto", "-o", helper)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Compiler diagnostics do not contain key/CSR bytes.
		t.Fatalf("compile official-API synthetic CSR helper: %s", output)
	}
	p := TLSCSRParameters{Role: "node", DNSName: "node.synthetic.invalid"}
	key, profile, err := GenerateTLSCSR(p)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	private, err := key.ExportPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	keyPath := csrPrivateFile(t, dir, "synthetic-only.key", private)
	csrPath := csrPrivateFile(t, dir, "synthetic-only.csr", profile.CSRPEM)
	for _, mutation := range []string{"duplicate-extension", "duplicate-attribute", "extra-attribute", "wrong-signature-oid"} {
		t.Run(mutation, func(t *testing.T) {
			outputPath := filepath.Join(dir, mutation+".csr")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, helper, mutation, csrPath, keyPath, outputPath)
			if _, err := cmd.CombinedOutput(); err != nil {
				t.Fatal("official-API synthetic CSR mutation failed")
			}
			csr, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatal("read synthetic public CSR mutation")
			}
			if mutation != "wrong-signature-oid" {
				if out := csrOfficial(t, dir, "req", "-in", outputPath, "-verify", "-noout"); !bytes.Contains(out, []byte("verify OK")) {
					t.Fatal("mutated profile fixture lacks a valid possession proof")
				}
			}
			if got, err := InspectTLSCSR(csr, p); !errors.Is(err, ErrProfile) || len(got.CSRPEM) != 0 {
				t.Fatal("extra CSR attribute/extension or wrong signature OID accepted")
			}
		})
	}
}

func TestTLSCSRConcurrentNativeContextCleanup(t *testing.T) {
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 8; j++ {
				p := TLSCSRParameters{Role: "node", DNSName: "concurrent.synthetic.invalid"}
				key, profile, err := GenerateTLSCSR(p)
				if err != nil {
					t.Error("concurrent native CSR generation failed")
					return
				}
				got, err := InspectTLSCSR(profile.CSRPEM, p)
				// Exercise fresh-context parse/profile error cleanup repeatedly.
				_, malformed := InspectTLSCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0}}), p)
				_, mismatch := InspectTLSCSR(profile.CSRPEM, TLSCSRParameters{Role: "hub", DNSName: p.DNSName})
				key.Destroy()
				if err != nil || got.SPKIDERHash != profile.SPKIDERHash || !errors.Is(malformed, ErrCSR) || !errors.Is(mismatch, ErrProfile) {
					t.Error("concurrent native CSR inspection failed")
					return
				}
			}
		}()
	}
	workers.Wait()
}

func TestTLSCSRInvalidParametersDoNotGenerateMaterial(t *testing.T) {
	p := TLSCSRParameters{Role: "node", DNSName: strings.Repeat("a", 64) + ".invalid"}
	key, profile, err := GenerateTLSCSR(p)
	if !errors.Is(err, ErrConfig) || key.state != nil || len(profile.CSRPEM) != 0 {
		t.Fatal("invalid DNS generated material")
	}
	if _, err := InspectTLSCSR(nil, p); !errors.Is(err, ErrConfig) {
		t.Fatal("invalid expected DNS accepted")
	}
}

func TestTLSCSROnlyModeRejectsOtherSelectors(t *testing.T) {
	if os.Getenv("PQTLS_TEST_CSR_ONLY") != "1" {
		// The ordinary transport TestMain already created its chain fixtures.
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("find synthetic CSR test executable")
	}
	for _, pattern := range []string{".", "^TestExactProfileAndSPKIPin$", "^TestTLSCSR|TestExactProfileAndSPKIPin$"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, executable, "-test.run", pattern)
		output, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("other selectors are NOT_RUN")) || bytes.Contains(output, []byte("=== RUN")) {
			t.Fatal("CSR-only mode silently admitted a non-CSR selector")
		}
	}
}
