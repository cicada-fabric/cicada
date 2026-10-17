package appcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// This is the existing nodekeys.PeerKeyFingerprint encoding. Keep the small
// public-key computation local: importing nodekeys into the App links its
// SQLite state implementation. Compatibility is checked against that API in tests.
func ownerPeerKeyFingerprint(public e2ee.PublicIdentity) (string, error) {
	if err := e2ee.ValidatePublicIdentity(public); err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("cicada/nodekeys/peer-key-fingerprint/v1\x00"))
	_, _ = hash.Write(public.KEMPublic)
	_, _ = hash.Write(public.SigningPublic)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (c *nativeController) canExportOwnerPublic() bool {
	return !c.storageFault && !c.profileRecoveryRequired && c.vault != nil && c.nodeAccountReady() &&
		!c.hasNodePending() && !c.hasPairPending() && canBeginOperation(c.state.Pending) && c.state.Recovery == nil
}

// Export only Public(), never a vault/identity serialization. O_EXCL prevents
// replacing a private key or any existing user file selected by mistake.
func (c *nativeController) exportOwnerPublic(path string) error {
	if !c.canExportOwnerPublic() || path == "" || !filepath.IsAbs(path) {
		return ErrInvalidAction
	}
	public := c.owner.Public()
	if _, err := ownerPeerKeyFingerprint(public); err != nil {
		return err
	}
	raw, err := json.Marshal(public)
	if err != nil {
		return err
	}
	defer clear(raw)
	path = filepath.Clean(path)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return c.fail(PhaseUnavailable, "APP_OWNER_PUBLIC_EXPORT_FAILED", err)
	}
	_, writeErr := file.Write(append(raw, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return c.fail(PhaseUnavailable, "APP_OWNER_PUBLIC_EXPORT_FAILED", os.ErrInvalid)
	}
	c.publish()
	return nil
}
