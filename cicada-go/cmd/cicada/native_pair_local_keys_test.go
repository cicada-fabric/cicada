package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func TestNativePairOriginalKeyCannotBeReplacedAfterMissingOrCorruptFile(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			const endpoint = "synthetic-pair-endpoint"
			identity, err := loadNativePairPublicationIdentity(root, endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}
			original := identity.Public()
			again, err := loadNativePairPublicationIdentity(root, endpoint, &original)
			if err != nil || !sameMCPKeyPublic(again.Public(), original) {
				t.Fatal("original key was not reused", err)
			}
			var keyFile string
			if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() {
					if keyFile != "" {
						t.Fatal("unexpected extra identity file")
					}
					keyFile = path
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if keyFile == "" {
				t.Fatal("private identity file absent")
			}
			if mode == "missing" {
				err = os.Remove(keyFile)
			} else {
				err = os.WriteFile(keyFile, []byte("synthetic-corrupt-identity"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadNativePairPublicationIdentity(root, endpoint, &original); err == nil {
				t.Fatal("original key loss silently created replacement")
			}
			if mode == "missing" {
				if _, err := nodekeys.LoadExisting(root, endpoint); err == nil {
					t.Fatal("failed recovery created a new private key")
				}
			}
		})
	}
}
