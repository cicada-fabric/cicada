package hubtransport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func createTestProfile(t *testing.T) (fixture, string, *Profile) {
	t.Helper()
	f := newFixture(t)
	root := filepath.Join(t.TempDir(), "SYNTHETIC-native-state")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := InitializeProfile(root, f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, f.d.Claims.Origin, "")
	if err != nil {
		t.Fatal(err)
	}
	return f, root, p
}

func readTestProfile(t *testing.T, root string) privateProfile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "native-tls", profileName))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var data privateProfile
	if readProfileJSON(raw, &data) != nil {
		t.Fatal("private profile invalid")
	}
	return data
}

func TestProfileRestartConcurrentInitAndExactDescriptor(t *testing.T) {
	f, root, first := createTestProfile(t)
	path := filepath.Join(root, "native-tls", profileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(path), 0700}, {path, 0600}, {filepath.Join(filepath.Dir(path), ".lock"), 0600}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatal("unsafe profile mode")
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := InitializeProfile(root, f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, f.d.Claims.Origin, first.DescriptorText())
			if err != nil || p.DescriptorText() != first.DescriptorText() {
				t.Error("repeat init changed signed descriptor")
			}
		}()
	}
	wg.Wait()
	loaded, err := LoadProfile(root, first.DescriptorText())
	if err != nil || loaded.DescriptorText() != first.DescriptorText() {
		t.Fatal("restart changed binding")
	}
	// Recover the exact bundle that was persisted before a Store pin commit.
	recovered, err := InitializeProfile(root, f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, f.d.Claims.Origin, "")
	if err != nil || recovered.DescriptorText() != first.DescriptorText() {
		t.Fatal("lost local pin commit re-signed descriptor")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("idempotent init rewrote bundle")
	}
	clear(after)
	d, err := DecodeDescriptor(first.DescriptorText())
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	s.TLS = loaded.TLSConfig()
	s.StartTLS()
	defer s.Close()
	client, err := NewHTTPClient(d, s.Listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(d.Claims.Origin + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("profile TLS failed")
	}
}

func TestProfileConcurrentPristineInitUsesOneCAAndKey(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := InitializeProfile(root, f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, f.d.Claims.Origin, "")
			if err != nil {
				t.Error(err)
				return
			}
			results <- p.DescriptorText()
		}()
	}
	wg.Wait()
	close(results)
	var first string
	for text := range results {
		if first == "" {
			first = text
		}
		if first != text {
			t.Fatal("concurrent init replaced TLS identity")
		}
	}
	if first == "" {
		t.Fatal("no profile initialized")
	}
}

func TestProfileRejectsMissingCorruptMixedAndUnprotectedMaterial(t *testing.T) {
	for _, fault := range []string{"missing-file", "missing-directory", "missing-service-key", "wrong-ca-key", "mixed-epoch", "mode", "symlink", "lock-mode"} {
		t.Run(fault, func(t *testing.T) {
			f, root, p := createTestProfile(t)
			path := filepath.Join(root, "native-tls", profileName)
			data := readTestProfile(t, root)
			defer data.clear()
			switch fault {
			case "missing-file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "missing-directory":
				if err := os.RemoveAll(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "lock-mode":
				if err := os.Chmod(filepath.Join(filepath.Dir(path), ".lock"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".retained", path); err != nil {
					t.Fatal(err)
				}
			default:
				switch fault {
				case "missing-service-key":
					data.ServiceKeyDER = nil
				case "wrong-ca-key":
					data.CAKeyDER = bytes.Clone(data.ServiceKeyDER)
				case "mixed-epoch":
					d, err := DecodeDescriptor(data.Descriptor)
					if err != nil {
						t.Fatal(err)
					}
					d.Claims.TransportEpoch++
					d, err = SignDescriptor(f.hub, d.Claims)
					if err != nil {
						t.Fatal(err)
					}
					data.Descriptor, err = EncodeDescriptor(d)
					if err != nil {
						t.Fatal(err)
					}
				}
				raw, err := json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				clear(raw)
			}
			before, _ := os.ReadFile(path)
			defer clear(before)
			if _, err := LoadProfile(root, p.DescriptorText()); err == nil {
				t.Fatal("damaged profile loaded")
			}
			if _, err := InitializeProfile(root, f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, f.d.Claims.Origin, p.DescriptorText()); err == nil {
				t.Fatal("damaged profile regenerated")
			}
			after, _ := os.ReadFile(path)
			defer clear(after)
			if !bytes.Equal(before, after) {
				t.Fatal("failed load/init replaced material")
			}
		})
	}
}

func TestProfileExpiredRestartAndHandshakeRenewSameKeys(t *testing.T) {
	for _, viaHandshake := range []bool{false, true} {
		t.Run(map[bool]string{false: "restart", true: "handshake"}[viaHandshake], func(t *testing.T) {
			f := newFixture(t)
			root := t.TempDir()
			data, err := newPrivateProfile(f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, f.d.Claims.Origin, time.Now().Add(-100*24*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			defer data.clear()
			dir, err := profileDirectory(root, true)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := profileLock(dir, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = saveProfile(filepath.Join(dir, profileName), data, false); err != nil {
				t.Fatal(err)
			}
			lock.Close()
			oldLeaf := bytes.Clone(data.LeafDER)
			var loaded *Profile
			if viaHandshake {
				loaded, _, _, err = checkPrivateProfile(data, time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				loaded.stateDir = root
				if _, err = loaded.TLSConfig().GetCertificate(&tls.ClientHelloInfo{}); err != nil {
					t.Fatal(err)
				}
			} else {
				loaded, err = LoadProfile(root, data.Descriptor)
				if err != nil {
					t.Fatal(err)
				}
			}
			after := readTestProfile(t, root)
			defer after.clear()
			if loaded.DescriptorText() != data.Descriptor || after.Descriptor != data.Descriptor || !bytes.Equal(after.CAKeyDER, data.CAKeyDER) || !bytes.Equal(after.ServiceKeyDER, data.ServiceKeyDER) || bytes.Equal(after.LeafDER, oldLeaf) {
				t.Fatal("renewal replaced stable identity or failed to renew")
			}
			leaf, err := x509.ParseCertificate(after.LeafDER)
			if err != nil || !leaf.NotAfter.After(time.Now().Add(89*24*time.Hour)) {
				t.Fatal("renewed leaf lifetime invalid")
			}
		})
	}
}

func TestProfileInvalidHTTPOriginDoesNotCreateNativeMarker(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	if _, err := InitializeProfile(root, f.hub, f.d.Claims.Hub, f.d.Claims.NodeControl, "http://127.0.0.1:8787", ""); err == nil {
		t.Fatal("HTTP scope accepted")
	}
	if present, err := ProfilePresent(root); err != nil || present {
		t.Fatal("rejected initialization changed legacy mode")
	}
}
