package nodekeys

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

var ErrRuntimeTrustUnavailable = errors.New("read-only Node TLS local trust is unavailable")

const MaxRuntimeRetainedSigningPublicKeys = 1024

// RuntimeTrustRead is an existing private, checkpointed local trust snapshot.
// It must be opened under the runtime's maintenance/lifetime fence. Nonempty
// WAL/journal fails closed: immutable reads never pretend to include live WAL.
type RuntimeTrustRead struct {
	State       *CryptoState
	root        string
	fingerprint string
}

func runtimeRead(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > limit {
		return nil, ErrRuntimeTrustUnavailable
	}
	owner := reflect.ValueOf(info.Sys())
	if owner.Kind() == reflect.Ptr {
		owner = owner.Elem()
	}
	if owner.Kind() != reflect.Struct {
		return nil, ErrRuntimeTrustUnavailable
	}
	uid := owner.FieldByName("Uid")
	if !uid.IsValid() || uid.Uint() != uint64(os.Geteuid()) {
		return nil, ErrRuntimeTrustUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRuntimeTrustUnavailable
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || len(data) > int(limit) || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		clear(data)
		return nil, ErrRuntimeTrustUnavailable
	}
	return data, nil
}
func runtimeTrustFingerprint(root string) (string, error) {
	if inspectExistingStateDirectory(root) != nil {
		return "", ErrRuntimeTrustUnavailable
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != 0700 {
		return "", ErrRuntimeTrustUnavailable
	}
	db := filepath.Join(root, cryptoStateDBName)
	fingerprint := sha256.New()
	for _, suffix := range []string{"-wal", "-journal", "-shm"} {
		info, err := os.Lstat(db + suffix)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprint(fingerprint, suffix+":absent")
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || suffix != "-shm" && info.Size() != 0 {
			return "", ErrRuntimeTrustUnavailable
		}
		fmt.Fprintf(fingerprint, "%s:%d:%d", suffix, info.Size(), info.ModTime().UnixNano())
		if info.Size() > 0 {
			data, err := runtimeRead(db+suffix, 4<<20)
			if err != nil {
				return "", err
			}
			fingerprint.Write(data)
			clear(data)
		}
	}
	data, err := runtimeRead(db, 64<<20)
	if err != nil {
		return "", err
	}
	defer clear(data)
	fingerprint.Write(data)
	return string(fingerprint.Sum(nil)), nil
}
func OpenExistingCryptoStateReadOnly(root string) (*RuntimeTrustRead, error) {
	abs, err := filepath.Abs(root)
	if err != nil || abs != root || filepath.Clean(root) != root {
		return nil, ErrRuntimeTrustUnavailable
	}
	fp, err := runtimeTrustFingerprint(root)
	if err != nil {
		return nil, err
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(root, cryptoStateDBName)), RawQuery: "mode=ro&immutable=1"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, ErrRuntimeTrustUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var version int
	if db.QueryRow(`SELECT version FROM node_crypto_schema WHERE singleton=1`).Scan(&version) != nil || version != cryptoSchemaVersion {
		db.Close()
		return nil, ErrRuntimeTrustUnavailable
	}
	r := &RuntimeTrustRead{State: &CryptoState{db: db}, root: root, fingerprint: fp}
	if r.CheckStable() != nil {
		r.Close()
		return nil, ErrRuntimeTrustUnavailable
	}
	return r, nil
}
func (r *RuntimeTrustRead) CheckStable() error {
	if r == nil || r.State == nil {
		return ErrRuntimeTrustUnavailable
	}
	fp, err := runtimeTrustFingerprint(r.root)
	if err != nil || fp != r.fingerprint {
		return ErrRuntimeTrustUnavailable
	}
	return nil
}
func (r *RuntimeTrustRead) Close() error {
	if r == nil || r.State == nil {
		return nil
	}
	return r.State.Close()
}

// RetainedSigningPublicKeys reads every retained Owner and peer public row,
// including revoked rows, and every existing Endpoint identity record. It
// returns no private material and cannot recover keys deleted before D2.
func (r *RuntimeTrustRead) RetainedSigningPublicKeys() ([][]byte, error) {
	if r.CheckStable() != nil {
		return nil, ErrRuntimeTrustUnavailable
	}
	unique := map[string][]byte{}
	add := func(p e2ee.PublicIdentity) error {
		if e2ee.ValidatePublicIdentity(p) != nil {
			return ErrRuntimeTrustUnavailable
		}
		unique[string(p.SigningPublic)] = bytes.Clone(p.SigningPublic)
		if len(unique) > MaxRuntimeRetainedSigningPublicKeys {
			return ErrRuntimeTrustUnavailable
		}
		return nil
	}
	for _, table := range []string{"node_crypto_owner_key_trust", "node_crypto_peer_pins"} {
		rows, err := r.State.db.Query(`SELECT public_identity_json FROM ` + table)
		if err != nil {
			return nil, ErrRuntimeTrustUnavailable
		}
		count := 0
		for rows.Next() {
			count++
			if count > 4096 {
				rows.Close()
				return nil, ErrRuntimeTrustUnavailable
			}
			var wire string
			var p e2ee.PublicIdentity
			if rows.Scan(&wire) != nil || len(wire) > 64<<10 || json.Unmarshal([]byte(wire), &p) != nil || add(p) != nil {
				rows.Close()
				return nil, ErrRuntimeTrustUnavailable
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, ErrRuntimeTrustUnavailable
		}
	}
	dir := filepath.Join(r.root, keyDirectoryName)
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrRuntimeTrustUnavailable
	}
	if err == nil {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || len(entries) > MaxRuntimeRetainedSigningPublicKeys {
			return nil, ErrRuntimeTrustUnavailable
		}
		for _, entry := range entries {
			if entry.IsDir() {
				return nil, ErrRuntimeTrustUnavailable
			}
			data, err := runtimeRead(filepath.Join(dir, entry.Name()), maxIdentityRecord)
			if err != nil {
				return nil, err
			}
			var record identityRecord
			d := json.NewDecoder(bytes.NewReader(data))
			d.DisallowUnknownFields()
			decodeErr := d.Decode(&record)
			trailing := d.Decode(new(any))
			clear(data)
			if decodeErr != nil || !errors.Is(trailing, io.EOF) || record.Version != diskVersion || validateEndpointID(record.EndpointID) != nil || identityPath(dir, record.EndpointID) != filepath.Join(dir, entry.Name()) {
				clear(record.Private)
				return nil, ErrRuntimeTrustUnavailable
			}
			identity, err := e2ee.UnmarshalIdentity(record.Private)
			clear(record.Private)
			if err != nil || identity.Public().ID != record.Public.ID || !bytes.Equal(identity.Public().SigningPublic, record.Public.SigningPublic) || !bytes.Equal(identity.Public().KEMPublic, record.Public.KEMPublic) || add(record.Public) != nil {
				return nil, ErrRuntimeTrustUnavailable
			}
		}
	}
	if r.CheckStable() != nil {
		return nil, ErrRuntimeTrustUnavailable
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([][]byte, 0, len(keys))
	for _, key := range keys {
		out = append(out, unique[key])
	}
	return out, nil
}
