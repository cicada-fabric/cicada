// Package hubidentity owns durable Hub transport identities, independently of
// Control business, models and workspaces. Existing file paths are unchanged.
package hubidentity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/gofrs/flock"
)

// Set keeps the existing independent Peer, Client-Control and Node-Control
// application identities. None of them is an Owner approval private key.
type Set struct {
	Peer          *e2ee.Identity
	ClientControl *e2ee.Identity
	NodeControl   *e2ee.Identity
}

// LoadOrCreate reuses every existing key, failing on unreadable/corrupt state.
// The caller must hold its normal StateDir startup/restore guard. Only absent
// identities are created through the existing per-file locking and fsync path.
func LoadOrCreate(stateDir, peerFile string) (Set, error) {
	if peerFile == "" {
		peerFile = filepath.Join(stateDir, "e2ee", "identity.json")
	}
	peer, err := LoadIdentity(peerFile)
	if err != nil {
		return Set{}, err
	}
	return LoadApplicationIdentities(stateDir, peer)
}

// LoadApplicationIdentities preserves legacy constructor ordering: the caller
// may check its manager association after loading Peer and before loading the
// separate application identities.
func LoadApplicationIdentities(stateDir string, peer *e2ee.Identity) (Set, error) {
	if peer == nil {
		return Set{}, errors.New("nil Hub peer identity")
	}
	client, err := LoadIdentity(filepath.Join(stateDir, "e2ee", "client-control-identity.json"))
	if err != nil {
		return Set{}, err
	}
	node, err := LoadIdentity(filepath.Join(stateDir, "e2ee", "node-control-identity.json"))
	if err != nil {
		return Set{}, err
	}
	return Set{Peer: peer, ClientControl: client, NodeControl: node}, nil
}

// LoadIdentity preserves the established identity file lifecycle. It does not
// repair or rotate existing key material after a decode/read failure.
func LoadIdentity(path string) (*e2ee.Identity, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create E2EE identity directory: %w", err)
	}
	// Serialize only identity load/create across independent local processes.
	// The StateDir startup lock is shared and cannot protect first creation.
	lockPath := path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err = file.Close(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(lockPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("E2EE identity lock is not a private regular file")
	}
	lock := flock.New(lockPath, flock.SetFlag(os.O_RDONLY))
	if err = lock.Lock(); err != nil {
		return nil, err
	}
	defer lock.Close()
	held, err := lock.Stat()
	current, statErr := os.Lstat(lockPath)
	if err != nil || statErr != nil || !os.SameFile(held, current) || !current.Mode().IsRegular() || current.Mode().Perm() != 0o600 {
		return nil, errors.New("E2EE identity lock changed")
	}
	if data, err := os.ReadFile(path); err == nil {
		identity, decodeErr := e2ee.UnmarshalIdentity(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		_ = os.Chmod(path, 0o600)
		return identity, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read E2EE identity: %w", err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	data, err := identity.MarshalBinary()
	if err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return nil, fmt.Errorf("write E2EE identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return nil, fmt.Errorf("install E2EE identity: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return identity, nil
}
