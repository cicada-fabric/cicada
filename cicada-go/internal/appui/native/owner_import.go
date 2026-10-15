package native

import (
	"bytes"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

var errOwnerImportCancelled = errors.New("Owner file selection cancelled")

var errEncryptedOwnerPEMUnsupported = errors.New("encrypted Owner PKCS#8 PEM is unsupported")

func chooseOwnerImport(locale appui.Locale) (*appcore.OwnerImport, error) {
	privateKEM, kemPrivatePath, err := readSelectedPEM(appui.Text(locale, "account.select_kem_private"), true, 1<<20)
	if err != nil {
		return nil, err
	}
	defer clear(privateKEM)
	privateSigning, signingPrivatePath, err := readSelectedPEM(appui.Text(locale, "account.select_signing_private"), true, 1<<20)
	if err != nil {
		return nil, err
	}
	defer clear(privateSigning)
	publicKEM, kemPublicPath, err := readSelectedPEM(appui.Text(locale, "account.select_kem_public"), false, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(publicKEM)
	publicSigning, signingPublicPath, err := readSelectedPEM(appui.Text(locale, "account.select_signing_public"), false, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(publicSigning)

	paths := []string{kemPrivatePath, signingPrivatePath, kemPublicPath, signingPublicPath}
	for i := range paths {
		for j := 0; j < i; j++ {
			if samePath(paths[i], paths[j]) {
				return nil, errors.New("select four distinct Owner PEM files")
			}
		}
	}
	return &appcore.OwnerImport{
		KEMPrivatePKCS8:     bytes.Clone(privateKEM),
		SigningPrivatePKCS8: bytes.Clone(privateSigning),
		KEMPublicSPKI:       bytes.Clone(publicKEM),
		SigningPublicSPKI:   bytes.Clone(publicSigning),
	}, nil
}

func readSelectedPEM(title string, private bool, limit int64) ([]byte, string, error) {
	path, err := choosePEMFile(title)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, "", errors.New("selected Owner PEM file is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", errors.New("selected Owner PEM file could not be opened")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		clear(data)
		return nil, "", errors.New("selected Owner PEM file exceeds its size limit")
	}
	block, rest := pem.Decode(data)
	if block != nil {
		defer clear(block.Bytes)
	}
	if block != nil && private && block.Type == "ENCRYPTED PRIVATE KEY" {
		clear(data)
		clear(block.Bytes)
		return nil, "", errEncryptedOwnerPEMUnsupported
	}
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || !validPEMType(block.Type, private) {
		clear(data)
		return nil, "", errors.New("selected Owner PEM has an unexpected public/private key type")
	}
	return data, filepath.Clean(path), nil
}

func validPEMType(blockType string, private bool) bool {
	if private {
		return blockType == "PRIVATE KEY"
	}
	return blockType == "PUBLIC KEY"
}

func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		// Treat path canonicalization failure as a collision so import fails
		// closed instead of accepting an ambiguous duplicate selection.
		return true
	}
	return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
}
