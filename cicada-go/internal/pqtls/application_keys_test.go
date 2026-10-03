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
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestTLSApplicationKeySeparationUnavailable(t *testing.T) {
	if tlsApplicationNativeBuild {
		if err := Available(); err != nil {
			t.Fatal("native comparison provider is unexpectedly unavailable")
		}
		return // Native behavior has its own assertions below.
	}
	err := CheckTLSCSRApplicationKeySeparation(nil, TLSCSRParameters{}, nil)
	var typed *Error
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &typed) {
		t.Fatal("application key comparison did not fail closed with typed unavailable")
	}
	if public, err := tlsApplicationSigningPublicFromSPKI(nil); public != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable SPKI conversion returned material or allowed")
	}
	if err := checkTLSApplicationSigningPublicSeparation(nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable native comparison allowed")
	}
	if hash, err := TLSIssuerSigningSPKIHash(nil); hash != [32]byte{} || !errors.Is(err, ErrUnavailable) || !errors.As(err, &typed) {
		t.Fatal("unavailable issuer signing public key extraction allowed")
	}
	if profile, err := (TLSIssuer{}).Profile(time.Time{}); profile != (TLSIssuerProfile{}) || !errors.Is(err, ErrUnavailable) || !errors.As(err, &typed) {
		t.Fatal("unavailable opaque issuer profile returned material or allowed")
	}
}

func tlsApplicationTestCSR(t *testing.T) (TLSCSRParameters, TLSCSRProfile, []byte, []byte) {
	t.Helper()
	p := TLSCSRParameters{Role: "node", DNSName: "separation.synthetic.invalid"}
	key, profile, err := GenerateTLSCSR(p)
	if err != nil {
		t.Fatal("generate synthetic comparison CSR")
	}
	key.Destroy()
	raw, err := tlsApplicationSigningPublicFromSPKI(profile.SPKIDER)
	if err != nil || len(raw) != tlsApplicationSigningPublicBytes {
		t.Fatal("official SPKI/raw ML-DSA-65 roundtrip failed")
	}
	application, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("generate independent synthetic CIRCL identity")
	}
	independent := application.Public().SigningPublic
	if len(independent) != tlsApplicationSigningPublicBytes || bytes.Equal(raw, independent) {
		t.Fatal("synthetic TLS and CIRCL signing keys are not independent")
	}
	return p, profile, raw, independent
}

func TestTLSApplicationKeySeparationActualKeysAndBounds(t *testing.T) {
	if !tlsApplicationNativeBuild {
		return // The unavailable test above verifies the real default/CGO-off path.
	}
	if err := Available(); err != nil {
		t.Fatal("native comparison provider is unexpectedly unavailable")
	}
	p, profile, raw, independent := tlsApplicationTestCSR(t)
	if err := CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, [][]byte{independent}); err != nil {
		t.Fatal("independent CIRCL raw signing key rejected")
	}
	for _, inventory := range [][][]byte{{raw}, {independent, raw}, {raw, independent}} {
		err := CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, inventory)
		var typed *Error
		if !errors.Is(err, ErrTLSApplicationKeyReuse) || !errors.As(err, &typed) {
			t.Fatal("actual same TLS raw signing key reuse was not rejected")
		}
	}
	full := make([][]byte, MaxTLSApplicationSigningPublicKeys)
	for i := range full {
		full[i] = independent
	}
	if err := CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, full); err != nil {
		t.Fatal("complete bounded distinct inventory rejected")
	}
	full[len(full)-1] = raw
	if !errors.Is(CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, full), ErrTLSApplicationKeyReuse) {
		t.Fatal("last inventory signing key was not compared")
	}
	for _, inventory := range [][][]byte{nil, {}, {nil}, {independent[:len(independent)-1]}, {append(bytes.Clone(independent), 0)}, append(full, independent), {independent, nil}} {
		if !errors.Is(CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, inventory), ErrConfig) {
			t.Fatal("empty, malformed or oversized inventory accepted")
		}
	}
	if !errors.Is(CheckTLSCSRApplicationKeySeparation(nil, p, [][]byte{independent}), ErrCSR) {
		t.Fatal("malformed CSR accepted")
	}
	if !errors.Is(CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, TLSCSRParameters{Role: "hub", DNSName: p.DNSName}, [][]byte{independent}), ErrProfile) {
		t.Fatal("wrong CSR role accepted")
	}
	if _, err := tlsApplicationSigningPublicFromSPKI(append(bytes.Clone(profile.SPKIDER), 0)); !errors.Is(err, ErrProfile) {
		t.Fatal("trailing SPKI bytes accepted by official decoder")
	}
	if _, err := tlsApplicationSigningPublicFromSPKI([]byte{0x30, 0}); !errors.Is(err, ErrProfile) {
		t.Fatal("malformed SPKI accepted")
	}
	if !errors.Is(checkTLSApplicationSigningPublicSeparation(raw[:len(raw)-1], independent), ErrConfig) ||
		!errors.Is(checkTLSApplicationSigningPublicSeparation(raw, independent[:len(independent)-1]), ErrConfig) {
		t.Fatal("native input bounds accepted malformed public key")
	}
}

func TestTLSApplicationKeySeparationConcurrentCleanup(t *testing.T) {
	if !tlsApplicationNativeBuild {
		return // Default/CGO-off unavailability is asserted separately, not skipped.
	}
	if err := Available(); err != nil {
		t.Fatal("native comparison provider is unexpectedly unavailable")
	}
	p, profile, raw, independent := tlsApplicationTestCSR(t)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 16; j++ {
				if err := CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, [][]byte{independent}); err != nil {
					t.Error("concurrent independent signing key comparison failed")
					return
				}
				if !errors.Is(CheckTLSCSRApplicationKeySeparation(profile.CSRPEM, p, [][]byte{independent, raw}), ErrTLSApplicationKeyReuse) {
					t.Error("concurrent application key reuse comparison allowed")
					return
				}
				if _, err := tlsApplicationSigningPublicFromSPKI(nil); !errors.Is(err, ErrProfile) {
					t.Error("concurrent malformed SPKI cleanup changed result")
					return
				}
			}
		}()
	}
	workers.Wait()
}

func tlsApplicationOfficial(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	executable := os.Getenv("PQTLS_TEST_OPENSSL")
	if executable == "" {
		t.Fatal("accepted official OpenSSL test executable missing")
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("official synthetic issuer fixture failed; output suppressed")
	}
	return out
}

func TestTLSApplicationIssuerSigningSPKI(t *testing.T) {
	if !tlsApplicationNativeBuild {
		return // Typed default/CGO-off unavailability is asserted above.
	}
	if err := Available(); err != nil {
		t.Fatal("native issuer key extractor is unexpectedly unavailable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private synthetic issuer fixture directory")
	}
	tlsApplicationOfficial(t, dir, "req", "-new", "-x509", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "issuer.key", "-out", "issuer.pem", "-days", "1", "-subj", "/CN=CICADA SYNTHETIC PUBLIC EXTRACTION ONLY", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign")
	first, err := os.ReadFile(filepath.Join(dir, "issuer.pem"))
	if err != nil {
		t.Fatal("read synthetic public issuer certificate")
	}
	publicPEM := tlsApplicationOfficial(t, dir, "x509", "-in", "issuer.pem", "-pubkey", "-noout")
	if err := os.WriteFile(filepath.Join(dir, "public.pem"), publicPEM, 0600); err != nil {
		t.Fatal("write synthetic public key fixture")
	}
	spki := tlsApplicationOfficial(t, dir, "pkey", "-pubin", "-in", "public.pem", "-outform", "DER")
	expected := sha256.Sum256(spki)
	for name, chain := range map[string][]byte{"single_issuer": first, "bounded_public_chain": bytes.Repeat(first, MaxTLSIssuerChainLength)} {
		t.Run(name, func(t *testing.T) {
			if hash, err := TLSIssuerSigningSPKIHash(chain); err != nil || hash != expected || hash == [32]byte{} {
				t.Fatal("actual issuer key did not match independent official SPKI")
			}
		})
	}
	tlsApplicationOfficial(t, dir, "req", "-new", "-x509", "-key", "issuer.key", "-out", "renewed.pem", "-days", "1", "-set_serial", "99", "-subj", "/CN=CICADA SYNTHETIC RENEWED PUBLIC ONLY")
	renewed, err := os.ReadFile(filepath.Join(dir, "renewed.pem"))
	if err != nil {
		t.Fatal("read synthetic renewed public certificate")
	}
	t.Run("renewed_certificate_same_signing_key", func(t *testing.T) {
		if bytes.Equal(first, renewed) {
			t.Fatal("synthetic renewal did not change certificate bytes")
		}
		if hash, err := TLSIssuerSigningSPKIHash(renewed); err != nil || hash != expected {
			t.Fatal("issuer certificate renewal changed actual signing-key namespace")
		}
	})
	block, _ := pem.Decode(first)
	for name, input := range map[string][]byte{
		"empty":           nil,
		"non_certificate": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes}),
		"pem_headers":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Synthetic": "only"}, Bytes: block.Bytes}),
		"trailing_text":   append(bytes.Clone(first), []byte("SYNTHETIC JUNK")...),
		"too_many_blocks": bytes.Repeat(first, MaxTLSIssuerChainLength+1),
		"malformed_der":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0}}),
		"trailing_der":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: append(bytes.Clone(block.Bytes), 0)}),
	} {
		t.Run(name, func(t *testing.T) {
			if hash, err := TLSIssuerSigningSPKIHash(input); !errors.Is(err, ErrIssuer) || hash != [32]byte{} {
				t.Fatal("invalid issuer input returned a usable key namespace")
			}
		})
	}
	tlsApplicationOfficial(t, dir, "req", "-new", "-x509", "-newkey", "RSA:2048", "-noenc", "-keyout", "wrong.key", "-out", "wrong.pem", "-days", "1", "-subj", "/CN=CICADA SYNTHETIC WRONG ALGORITHM ONLY")
	wrong, err := os.ReadFile(filepath.Join(dir, "wrong.pem"))
	if err != nil {
		t.Fatal("read synthetic wrong algorithm certificate")
	}
	t.Run("wrong_signing_algorithm", func(t *testing.T) {
		if hash, err := TLSIssuerSigningSPKIHash(wrong); !errors.Is(err, ErrProfile) || hash != [32]byte{} {
			t.Fatal("classical issuer key became a Node TLS signing-key namespace")
		}
	})
	t.Run("concurrent_success_error_cleanup", func(t *testing.T) {
		var workers sync.WaitGroup
		for n := 0; n < 8; n++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for j := 0; j < 8; j++ {
					if hash, err := TLSIssuerSigningSPKIHash(first); err != nil || hash != expected {
						t.Error("concurrent issuer key extraction failed")
						return
					}
					if hash, err := TLSIssuerSigningSPKIHash(wrong); !errors.Is(err, ErrProfile) || hash != [32]byte{} {
						t.Error("concurrent wrong issuer key extraction allowed")
						return
					}
				}
			}()
		}
		workers.Wait()
	})
}

func TestTLSApplicationOpaqueIssuerProfile(t *testing.T) {
	if !tlsApplicationNativeBuild {
		return // Typed default/CGO-off unavailability is asserted above.
	}
	if err := Available(); err != nil {
		t.Fatal("native opaque issuer inspector is unexpectedly unavailable")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private synthetic issuer inspection directory")
	}
	tlsApplicationOfficial(t, dir, "req", "-new", "-x509", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=CICADA SYNTHETIC ROOT PROFILE ONLY", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
	tlsApplicationOfficial(t, dir, "req", "-new", "-newkey", "ML-DSA-65", "-noenc", "-keyout", "issuer.key", "-out", "issuer.csr", "-subj", "/CN=CICADA SYNTHETIC ISSUER PROFILE ONLY")
	ext := []byte("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
	if err := os.WriteFile(filepath.Join(dir, "issuer.ext"), ext, 0600); err != nil {
		t.Fatal("write synthetic issuer constraints")
	}
	tlsApplicationOfficial(t, dir, "x509", "-req", "-in", "issuer.csr", "-CA", "root.pem", "-CAkey", "root.key", "-set_serial", "7", "-out", "issuer.pem", "-days", "1", "-extfile", "issuer.ext")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("read synthetic issuer inspection material")
		}
		return data
	}
	root, cert, private := read("root.pem"), read("issuer.pem"), read("issuer.key")
	defer clear(private)
	chain := append(bytes.Clone(cert), root...)
	at := time.Now().UTC().Truncate(time.Second)
	issuer, expected, err := ImportTLSIssuer(chain, private, root, "node", at)
	if err != nil {
		t.Fatal("strict import of synthetic inspection issuer failed")
	}
	defer issuer.Destroy()
	t.Run("actual_opaque_tuple", func(t *testing.T) {
		profile, err := issuer.Profile(at)
		if err != nil || profile != expected {
			t.Fatal("opaque issuer tuple differs from independently imported actual tuple")
		}
		hash, err := TLSIssuerSigningSPKIHash(chain)
		if err != nil || hash != profile.SPKIDERHash {
			t.Fatal("opaque handle signing key differs from actual public certificate")
		}
	})
	t.Run("wrong_and_destroyed_handles", func(t *testing.T) {
		for _, handle := range []TLSIssuer{{}, {state: &tlsIssuerState{role: "owner", keyPEM: []byte("SYNTHETIC INVALID KEY ONLY")}}} {
			if profile, err := handle.Profile(at); !errors.Is(err, ErrIssuer) || profile != (TLSIssuerProfile{}) {
				t.Fatal("empty or wrong-purpose opaque handle returned a public authority tuple")
			}
		}
		dead, _, err := ImportTLSIssuer(chain, private, root, "node", at)
		if err != nil {
			t.Fatal("import destroy fixture")
		}
		dead.Destroy()
		if profile, err := dead.Profile(at); !errors.Is(err, ErrIssuer) || profile != (TLSIssuerProfile{}) {
			t.Fatal("destroyed opaque issuer remained usable")
		}
	})
	t.Run("invalid_time", func(t *testing.T) {
		for _, when := range []time.Time{{}, at.Add(time.Nanosecond), at.In(time.FixedZone("synthetic", 3600))} {
			if profile, err := issuer.Profile(when); !errors.Is(err, ErrConfig) || profile != (TLSIssuerProfile{}) {
				t.Fatal("ambiguous opaque issuer verification time accepted")
			}
		}
	})
	t.Run("expired_actual_chain", func(t *testing.T) {
		profile, err := issuer.Profile(at.Add(48 * time.Hour))
		var typed *Error
		if err == nil || !errors.As(err, &typed) || profile != (TLSIssuerProfile{}) {
			t.Fatal("expired opaque issuer chain returned a public authority tuple")
		}
	})
	t.Run("concurrent_inspection_and_destroy", func(t *testing.T) {
		shared, _, err := ImportTLSIssuer(chain, private, root, "node", at)
		if err != nil {
			t.Fatal("import concurrent synthetic issuer")
		}
		defer shared.Destroy()
		var workers sync.WaitGroup
		for n := 0; n < 8; n++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for j := 0; j < 8; j++ {
					profile, err := shared.Profile(at)
					if err == nil && profile != expected || err != nil && (!errors.Is(err, ErrIssuer) || profile != (TLSIssuerProfile{})) {
						t.Error("opaque issuer inspection/destruction did not serialize")
						return
					}
				}
			}()
		}
		shared.Destroy()
		workers.Wait()
		if profile, err := shared.Profile(at); !errors.Is(err, ErrIssuer) || profile != (TLSIssuerProfile{}) {
			t.Fatal("destroyed concurrent opaque handle returned a tuple")
		}
	})
}
