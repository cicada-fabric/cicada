package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestHubActivationIssuerIsLocalProtectedAndPreservesIdentities(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	var output bytes.Buffer
	if err := hubSetupCommand([]string{"--state-dir", state, "--owner-label", "Synthetic activation CLI", "--origin", "https://hub.synthetic.invalid", "--public-config", filepath.Join(root, "public.json")}, &output); err != nil {
		t.Fatal(err)
	}
	keys := map[string][]byte{}
	for _, name := range []string{"identity.json", "client-control-identity.json", "node-control-identity.json"} {
		raw, err := os.ReadFile(filepath.Join(state, "e2ee", name))
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = raw
	}
	codePath := filepath.Join(root, "activation.code")
	output.Reset()
	if err := hubActivationIssueCommand([]string{"--state-dir", state, "--purpose", "initial", "--code-file", codePath}, &output); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(codePath)
	if err != nil {
		t.Fatal(err)
	}
	material, err := wire.DecodeActivationCode(strings.TrimSuffix(string(raw), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if material.Purpose != wire.PurposeInitialActivation || material.ExpectedOwnerPublic != nil || strings.Contains(output.String(), material.Code) || strings.Contains(output.String(), wire.ActivationCodePrefix) {
		t.Fatal("issuer exposed or broadened finite authority")
	}
	info, err := os.Stat(codePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("activation output is not protected")
	}
	if err = hubActivationIssueCommand([]string{"--state-dir", state, "--purpose", "initial", "--code-file", codePath}, &output); err == nil {
		t.Fatal("existing activation file overwritten")
	}
	if err = hubActivationIssueCommand([]string{"--state-dir", state, "--purpose", "legacy-pending", "--owner-key-id", "unknown", "--owner-fingerprint", strings.Repeat("a", 64), "--code-file", filepath.Join(root, "unknown.code")}, &output); err == nil {
		t.Fatal("unknown legacy Owner authorized")
	}
	for name, before := range keys {
		after, err := os.ReadFile(filepath.Join(state, "e2ee", name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("issuer changed Hub identity")
		}
	}
}

func TestHubActivationIssuerPreservesConfiguredPeerPath(t *testing.T) {
	for _, configuredPeerExists := range []bool{true, false} {
		t.Run(map[bool]string{true: "custom peer without default", false: "missing custom peer with default"}[configuredPeerExists], func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			customPeer := filepath.Join(root, "custom-peer", "identity.json")
			if configuredPeerExists {
				t.Setenv("CICADA_E2EE_IDENTITY_FILE", customPeer)
			} else {
				t.Setenv("CICADA_E2EE_IDENTITY_FILE", "")
			}
			var output bytes.Buffer
			if err := hubSetupCommand([]string{"--state-dir", state, "--owner-label", "Synthetic configured peer", "--origin", "https://custom-peer.synthetic.invalid", "--public-config", filepath.Join(root, "public.json")}, &output); err != nil {
				t.Fatal(err)
			}
			existingPeer := customPeer
			if !configuredPeerExists {
				existingPeer = filepath.Join(state, "e2ee", "identity.json")
				t.Setenv("CICADA_E2EE_IDENTITY_FILE", customPeer)
			}
			before, err := os.ReadFile(existingPeer)
			if err != nil {
				t.Fatal(err)
			}
			output.Reset()
			err = hubActivationIssueCommand([]string{"--state-dir", state, "--purpose", "initial", "--code-file", filepath.Join(root, "activation.code")}, &output)
			if configuredPeerExists && err != nil {
				t.Fatal("configured existing peer was rejected")
			}
			if !configuredPeerExists {
				if err == nil {
					t.Fatal("missing configured peer was accepted")
				}
				if _, statErr := os.Lstat(customPeer); !os.IsNotExist(statErr) {
					t.Fatal("activation issuer generated a replacement peer identity")
				}
			}
			after, err := os.ReadFile(existingPeer)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("activation issuer changed the existing peer identity")
			}
		})
	}
}
