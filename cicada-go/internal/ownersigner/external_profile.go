package ownersigner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/gofrs/flock"
)

const (
	externalProfileFormat  = "cicada.owner-signer-openssl.v1"
	externalProfileVersion = 1
	externalProfileFile    = "owner-signer-openssl.json"
	externalProfileLock    = ".owner-signer-openssl.lock"
)

var ErrNotExternalProfile = errors.New("Owner signer profile is not an external OpenSSL profile")

type externalOpenSSLState struct {
	ExecutableSHA256 string `json:"executable_sha256"`
	OpenSSLPaths
}

// externalProfileState contains public identity and path metadata only.
// Neither encrypted PEM bytes, passphrases, shared secrets nor plaintext
// bootstrap possessions are serialized here.
type externalProfileState struct {
	Format            string                     `json:"format"`
	Version           int                        `json:"version"`
	AccountID         string                     `json:"account_id"`
	OwnerID           string                     `json:"owner_id"`
	Origin            string                     `json:"origin"`
	AllowLoopbackHTTP bool                       `json:"allow_loopback_http"`
	Hub               clientoperator.HubIdentity `json:"hub"`
	OwnerPublic       e2ee.PublicIdentity        `json:"owner_public_identity"`
	Fingerprint       string                     `json:"fingerprint"`
	OpenSSL           externalOpenSSLState       `json:"openssl"`
	Bootstrap         *pendingBootstrap          `json:"bootstrap,omitempty"`
}

// ExternalProfile stores public pins and encrypted protocol packets. OpenSSL
// alone opens the existing encrypted private PEM files for each operation.
// Like Profile, a value is sequential-use only; the file lock protects only
// independent processes opening the same profile.
type ExternalProfile struct {
	dir    string
	lock   *flock.Flock
	state  externalProfileState
	ops    *OpenSSLOperations
	http   *http.Client
	broken bool
	closed bool
}

// PrepareExternal binds two existing encrypted OpenSSL private PEM paths to a
// public Owner identity and a complete independently supplied Hub connection.
// It never reads private PEM bytes and never overwrites an existing profile.
func PrepareExternal(dir string, connection ConnectionFile, owner e2ee.PublicIdentity, paths OpenSSLPaths) (*ExternalProfile, error) {
	if err := connection.Validate(); err != nil {
		return nil, err
	}
	if err := e2ee.ValidatePublicIdentity(owner); err != nil {
		return nil, errors.New("external Owner public identity is invalid")
	}
	abs, err := filepath.Abs(dir)
	if err != nil || !safePathText(abs) || filepath.Clean(abs) != abs {
		return nil, errors.New("Owner signer profile path is not absolute and canonical")
	}
	if err := validateExternalParent(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	paths, err = canonicalOpenSSLPaths(paths)
	if err != nil {
		return nil, err
	}
	if pathWithin(abs, paths.KEMPrivate) || pathWithin(abs, paths.SigningPrivate) || pathWithin(abs, paths.Executable) {
		return nil, errors.New("OpenSSL executable and encrypted Owner PEM files must remain outside the profile")
	}
	if err := CheckOpenSSL(paths.Executable); err != nil {
		return nil, err
	}
	if err := validateExternalPrivateFile(paths.KEMPrivate, maxExternalPEMBytes); err != nil {
		return nil, errors.New("ML-KEM encrypted private PEM path is unsafe")
	}
	if err := validateExternalPrivateFile(paths.SigningPrivate, maxExternalPEMBytes); err != nil {
		return nil, errors.New("ML-DSA encrypted private PEM path is unsafe")
	}
	executableHash, err := externalFileSHA256(paths.Executable)
	if err != nil {
		return nil, errors.New("OpenSSL executable cannot be pinned")
	}
	if err := createExternalPrivateDirectory(abs); err != nil {
		return nil, fmt.Errorf("create protected external Owner profile without overwrite: %w", err)
	}
	ops, err := NewOpenSSLOperations(paths, abs)
	if err != nil {
		_ = os.Remove(abs)
		return nil, err
	}
	p, err := acquireExternal(abs)
	if err != nil {
		_ = os.Remove(abs)
		return nil, err
	}
	p.ops = ops
	p.state = externalProfileState{Format: externalProfileFormat, Version: externalProfileVersion,
		AccountID: connection.AccountID, OwnerID: connection.OwnerID, Origin: connection.Origin,
		AllowLoopbackHTTP: connection.AllowLoopbackHTTP, Hub: connection.Hub, OwnerPublic: owner,
		Fingerprint: ownerbootstrap.Fingerprint(owner), OpenSSL: externalOpenSSLState{
			ExecutableSHA256: executableHash, OpenSSLPaths: paths,
		}}
	if err := p.configureHTTP(); err != nil {
		_ = p.Close()
		return nil, err
	}
	if err := p.save(); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

// OpenExternal returns ErrNotExternalProfile only when the dedicated metadata
// file is absent. A present but invalid external profile fails closed and must
// never fall through to the native-identity profile format.
func OpenExternal(dir string) (*ExternalProfile, error) {
	abs, err := filepath.Abs(dir)
	if err != nil || !safePathText(abs) || filepath.Clean(abs) != abs {
		return nil, errors.New("Owner signer profile path is not absolute and canonical")
	}
	metadataPath := filepath.Join(abs, externalProfileFile)
	if _, err := os.Lstat(metadataPath); errors.Is(err, os.ErrNotExist) {
		if _, lockErr := os.Lstat(filepath.Join(abs, externalProfileLock)); lockErr == nil {
			return nil, errors.New("external Owner profile marker exists but its metadata is missing")
		} else if !errors.Is(lockErr, os.ErrNotExist) {
			return nil, errors.New("external Owner profile marker cannot be inspected")
		}
		return nil, ErrNotExternalProfile
	} else if err != nil {
		return nil, errors.New("external Owner profile metadata is unavailable")
	}
	if err := checkExternalPrivateDirectory(abs); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(abs, profileFileName)); err == nil {
		return nil, errors.New("profile directory contains both native and external Owner signer formats")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("native Owner signer metadata cannot be inspected")
	}
	p, err := acquireExternal(abs)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = p.Close()
		}
	}()
	data, err := readExternalPrivateFile(filepath.Join(abs, externalProfileFile), maxProfileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotExternalProfile
	}
	if err != nil {
		return nil, errors.New("external Owner profile metadata is unavailable or has unsafe custody")
	}
	if err := decodeStrict(data, &p.state); err != nil {
		return nil, errors.New("external Owner profile metadata is invalid")
	}
	if err := validateExternalState(abs, p.state); err != nil {
		return nil, err
	}
	paths := p.state.OpenSSL.OpenSSLPaths
	hash, err := externalFileSHA256(paths.Executable)
	if err != nil || hash != p.state.OpenSSL.ExecutableSHA256 {
		return nil, errors.New("pinned OpenSSL executable changed or is unavailable")
	}
	p.ops, err = NewOpenSSLOperations(paths, abs)
	if err != nil {
		return nil, err
	}
	if err := p.configureHTTP(); err != nil {
		return nil, err
	}
	ok = true
	return p, nil
}

func acquireExternal(dir string) (*ExternalProfile, error) {
	if err := checkExternalPrivateDirectory(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, externalProfileLock)
	if err := createExternalPrivateFileAt(lockPath, nil); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, errors.New("could not create protected Owner profile lock")
		}
		if err := checkExternalPrivateFile(lockPath); err != nil {
			return nil, errors.New("external Owner profile lock has unsafe custody")
		}
	}
	lock := flock.New(lockPath, flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrBusy
	}
	if err := checkExternalPrivateFile(lockPath); err != nil {
		_ = lock.Unlock()
		return nil, errors.New("external Owner profile lock custody changed")
	}
	return &ExternalProfile{dir: dir, lock: lock}, nil
}

func (p *ExternalProfile) configureHTTP() error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	p.http = &http.Client{Timeout: 20 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Owner signer redirects are forbidden") }}
	return nil
}

func (p *ExternalProfile) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	if p.http != nil {
		p.http.CloseIdleConnections()
	}
	if p.lock == nil {
		return nil
	}
	err := p.lock.Unlock()
	p.lock = nil
	p.ops = nil
	return err
}

func (p *ExternalProfile) PublicManifest() PublicManifest {
	if p == nil || p.closed || p.ops == nil {
		return PublicManifest{}
	}
	return PublicManifest{Format: publicManifestFormat, AccountID: p.state.AccountID, OwnerID: p.state.OwnerID,
		OwnerPublic: p.state.OwnerPublic, Fingerprint: p.state.Fingerprint,
		Origin: p.state.Origin, AllowLoopbackHTTP: p.state.AllowLoopbackHTTP, Hub: p.state.Hub}
}

func (p *ExternalProfile) ExportManifest(path string) (string, error) {
	if err := p.requireUsable(); err != nil {
		return "", err
	}
	if strings.TrimSpace(path) == "" {
		path = filepath.Join(p.dir, "owner-public.json")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(p.PublicManifest(), "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if err := writeExternalPublicExclusiveOrSame(absolute, data); err != nil {
		return "", err
	}
	return absolute, nil
}

func (p *ExternalProfile) Bootstrap(ctx context.Context, pairBytes []byte, review func(BootstrapReview) error) (*ownerbootstrap.Receipt, error) {
	if err := p.requireUsable(); err != nil {
		return nil, err
	}
	if review == nil {
		return nil, ErrReview
	}
	if len(pairBytes) == 0 || len(pairBytes) > maxPairingFileBytes {
		return nil, ownerbootstrap.ErrInvalid
	}
	pair, err := decodePairFile(pairBytes)
	if err != nil || validateExternalProfilePair(p.state, pair) != nil {
		return nil, ErrMismatch
	}
	now := time.Now().UTC()
	if p.state.Bootstrap != nil {
		pending := p.state.Bootstrap
		if bytes.Equal(pending.PairFile, pairBytes) {
			if err := review(reviewFor(pair)); err != nil {
				return nil, ErrReview
			}
			return p.submitSaved(ctx)
		}
		if len(pending.Response) > 0 {
			return nil, ErrPending
		}
		oldPair, err := decodePairFile(pending.PairFile)
		if err != nil || validateExternalProfilePair(p.state, oldPair) != nil || validateSavedProofRoute(oldPair, pending.Proof) != nil {
			return nil, ErrPending
		}
		oldExpires, err := canonicalPairExpiry(oldPair)
		if err != nil || oldExpires.After(now) {
			return nil, ErrPending
		}
		// Authenticate the original signed challenge at its last valid instant.
		// This only recovers its transient possession to verify the Hub pin; it is
		// never stored and never used to create a replacement proof.
		oldPossession, err := ownerbootstrap.OpenChallengeWithPrivateOperations(p.state.OwnerPublic, p.ops, oldPair, oldExpires.Add(-time.Nanosecond))
		if err != nil {
			return nil, ErrPending
		}
		defer clear(oldPossession)
		if err := validatePairLifetime(pair, now); err != nil {
			return nil, err
		}
		possession, err := ownerbootstrap.OpenChallengeWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, now)
		if err != nil {
			return nil, errors.New("replacement Owner bootstrap challenge is not authenticated by the pinned Hub")
		}
		defer clear(possession)
		newExpires, err := canonicalPairExpiry(pair)
		if err != nil || newExpires.Add(-ownerbootstrap.MaxLifetime).Before(oldExpires) ||
			pair.Manifest.AuthorityID == oldPair.Manifest.AuthorityID || pair.Manifest.OperationID == oldPair.Manifest.OperationID ||
			pair.Manifest.Digest() == oldPair.Manifest.Digest() || bytes.Equal(pair.Challenge, oldPair.Challenge) {
			return nil, errors.New("replacement Owner bootstrap challenge is not a distinct post-expiry authority")
		}
		if err := review(reviewFor(pair)); err != nil {
			return nil, ErrReview
		}
		proof, err := ownerbootstrap.CreateProofFromPossessionWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, possession, now)
		if err != nil {
			return nil, errors.New("replacement Owner bootstrap proof could not be created")
		}
		p.state.Bootstrap = &pendingBootstrap{PairFile: append([]byte(nil), pairBytes...), Proof: append([]byte(nil), proof...)}
		if err := p.save(); err != nil {
			return nil, errors.New("could not persist replacement Owner bootstrap proof before sending")
		}
		return p.submitSaved(ctx)
	}
	if err := validatePairLifetime(pair, now); err != nil {
		return nil, err
	}
	possession, err := ownerbootstrap.OpenChallengeWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, now)
	if err != nil {
		return nil, errors.New("Owner bootstrap challenge is not authenticated by the pinned Hub")
	}
	defer clear(possession)
	if err := review(reviewFor(pair)); err != nil {
		return nil, ErrReview
	}
	proof, err := ownerbootstrap.CreateProofFromPossessionWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, possession, now)
	if err != nil {
		return nil, errors.New("Owner bootstrap proof could not be created")
	}
	p.state.Bootstrap = &pendingBootstrap{PairFile: append([]byte(nil), pairBytes...), Proof: append([]byte(nil), proof...)}
	if err := p.save(); err != nil {
		return nil, errors.New("could not persist exact Owner bootstrap proof before sending")
	}
	return p.submitSaved(ctx)
}

func (p *ExternalProfile) Recover(ctx context.Context, review func(BootstrapReview) error) (*ownerbootstrap.Receipt, error) {
	if err := p.requireUsable(); err != nil {
		return nil, err
	}
	if p.state.Bootstrap == nil {
		return nil, ErrNoPending
	}
	if len(p.state.Bootstrap.Response) > 0 {
		pair, err := decodePairFile(p.state.Bootstrap.PairFile)
		if err != nil || validateExternalProfilePair(p.state, pair) != nil {
			return nil, errors.New("cached Owner bootstrap receipt does not match this profile")
		}
		return ownerbootstrap.VerifyReceiptWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, p.state.Bootstrap.Response)
	}
	if review == nil || review(reviewForBytes(p.state.Bootstrap.PairFile)) != nil {
		return nil, ErrReview
	}
	return p.submitSaved(ctx)
}

func (p *ExternalProfile) submitSaved(ctx context.Context) (*ownerbootstrap.Receipt, error) {
	pending := p.state.Bootstrap
	if pending == nil {
		return nil, ErrNoPending
	}
	pair, err := decodePairFile(pending.PairFile)
	if err != nil || validateExternalProfilePair(p.state, pair) != nil || validateSavedProofRoute(pair, pending.Proof) != nil {
		return nil, ownerbootstrap.ErrInvalid
	}
	if len(pending.Response) > 0 {
		return ownerbootstrap.VerifyReceiptWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, pending.Response)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.state.Origin+"/v2/owner/bootstrap/accept", bytes.NewReader(pending.Proof))
	if err != nil {
		return nil, ErrUncertain
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.http.Do(request)
	if err != nil {
		return nil, ErrUncertain
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReceiptBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxReceiptBytes || (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated) {
		return nil, errors.New("Hub did not return an authenticated Owner bootstrap receipt")
	}
	receipt, err := ownerbootstrap.VerifyReceiptWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, body)
	if err != nil {
		return nil, errors.New("Hub Owner bootstrap receipt failed authentication")
	}
	pending.Response = append([]byte(nil), body...)
	if err := p.save(); err != nil {
		return nil, errors.New("Owner bootstrap succeeded but receipt persistence failed; recover the exact operation")
	}
	return receipt, nil
}

func (p *ExternalProfile) SignDeviceGrant(manifestBytes []byte, expiresAt time.Time, review func(GrantReview) error) ([]byte, error) {
	if err := p.requireUsable(); err != nil {
		return nil, err
	}
	if p.state.Bootstrap == nil || len(p.state.Bootstrap.Response) == 0 {
		return nil, errors.New("Owner device grants require this key's authenticated bootstrap receipt")
	}
	pair, err := decodePairFile(p.state.Bootstrap.PairFile)
	if err != nil || validateExternalProfilePair(p.state, pair) != nil {
		return nil, errors.New("Owner bootstrap receipt is not bound to this Owner profile")
	}
	if _, err := ownerbootstrap.VerifyReceiptWithPrivateOperations(p.state.OwnerPublic, p.ops, pair, p.state.Bootstrap.Response); err != nil {
		return nil, errors.New("Owner bootstrap receipt is not authenticated")
	}
	if review == nil || len(manifestBytes) == 0 || len(manifestBytes) > 64*1024 {
		return nil, ErrReview
	}
	var manifest clientoperator.EnrollmentManifest
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return nil, errors.New("Client enrollment manifest is invalid")
	}
	if manifest.Format != "cicada.owner-device-enrollment.v1" || manifest.Purpose != e2ee.OwnerDevicePurposeControl ||
		manifest.OwnerID != p.state.OwnerID || manifest.OwnerKeyID != p.state.OwnerPublic.ID || manifest.HubID != p.state.Hub.HubID ||
		!validID(manifest.OwnerID) || !validID(manifest.OwnerKeyID) || !validID(manifest.HubID) ||
		e2ee.ValidatePublicIdentity(manifest.DevicePublicIdentity) != nil || !validID(manifest.DeviceID) || !validID(manifest.DevicePublicIdentity.ID) {
		return nil, ErrMismatch
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(manifest.DevicePublicIdentity)
	if err != nil || fingerprint != manifest.DeviceKeyFingerprint || !validFingerprint(manifest.DeviceKeyFingerprint) {
		return nil, errors.New("Client manifest public-key fingerprint is invalid")
	}
	now := time.Now().UTC()
	if expiresAt.IsZero() || !expiresAt.After(now) || expiresAt.After(now.Add(24*time.Hour)) {
		return nil, errors.New("Owner device grant expiry must be in the future and within 24 hours")
	}
	reviewInfo := GrantReview{AccountID: p.state.AccountID, OwnerID: p.state.OwnerID, OwnerKeyID: p.state.OwnerPublic.ID,
		HubID: p.state.Hub.HubID, DeviceID: manifest.DeviceID, DeviceKeyID: manifest.DevicePublicIdentity.ID,
		DeviceFingerprint: fingerprint, Purpose: manifest.Purpose, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano)}
	if err := review(reviewInfo); err != nil {
		return nil, ErrReview
	}
	return e2ee.SignOwnerDeviceGrantWithSigner(p.state.OwnerPublic, p.state.OwnerID, manifest.DeviceID,
		manifest.DevicePublicIdentity, p.state.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, expiresAt.UTC(), p.ops.Sign)
}

func (p *ExternalProfile) requireUsable() error {
	if p == nil || p.closed || p.lock == nil || p.ops == nil || p.http == nil {
		return errors.New("external Owner signer profile is not open")
	}
	if p.broken {
		return errors.New("external Owner signer profile persistence failed; reopen before continuing")
	}
	return nil
}

func (p *ExternalProfile) save() error {
	if err := p.requireUsable(); err != nil {
		return err
	}
	data, err := json.Marshal(p.state)
	if err != nil {
		p.broken = true
		return err
	}
	if err := replaceExternalAtomic(filepath.Join(p.dir, externalProfileFile), data); err != nil {
		p.broken = true
		return err
	}
	return nil
}

func validateExternalState(dir string, state externalProfileState) error {
	canonical, err := ownerbootstrap.CanonicalOrigin(state.Origin, state.AllowLoopbackHTTP)
	if state.Format != externalProfileFormat || state.Version != externalProfileVersion ||
		!validID(state.AccountID) || !validID(state.OwnerID) || !safeDisplayText(state.Origin) || err != nil || canonical != state.Origin ||
		validateHub(state.Hub) != nil || e2ee.ValidatePublicIdentity(state.OwnerPublic) != nil ||
		!validFingerprint(state.Fingerprint) || state.Fingerprint != ownerbootstrap.Fingerprint(state.OwnerPublic) ||
		!validFingerprint(state.OpenSSL.ExecutableSHA256) {
		return errors.New("external Owner profile identity or Hub pin is invalid")
	}
	paths, err := canonicalOpenSSLPaths(state.OpenSSL.OpenSSLPaths)
	if err != nil || !reflect.DeepEqual(paths, state.OpenSSL.OpenSSLPaths) ||
		pathWithin(dir, paths.KEMPrivate) || pathWithin(dir, paths.SigningPrivate) || pathWithin(dir, paths.Executable) {
		return errors.New("external OpenSSL path metadata is invalid")
	}
	if state.Bootstrap != nil {
		if err := validatePending(state.Bootstrap); err != nil {
			return errors.New("external Owner bootstrap cache is invalid")
		}
		pair, err := decodePairFile(state.Bootstrap.PairFile)
		if err != nil || validateExternalProfilePair(state, pair) != nil || validateSavedProofRoute(pair, state.Bootstrap.Proof) != nil {
			return errors.New("external Owner bootstrap cache differs from its saved public pins")
		}
		if len(state.Bootstrap.Response) > 0 && len(state.Bootstrap.Response) > maxReceiptBytes {
			return errors.New("external Owner receipt cache is too large")
		}
	}
	return nil
}

func canonicalOpenSSLPaths(paths OpenSSLPaths) (OpenSSLPaths, error) {
	for _, path := range []string{paths.Executable, paths.KEMPrivate, paths.SigningPrivate} {
		if !filepath.IsAbs(path) || !safePathText(path) || filepath.Clean(path) != path {
			return OpenSSLPaths{}, errors.New("OpenSSL executable and encrypted PEM paths must be absolute and canonical")
		}
	}
	if paths.Executable == paths.KEMPrivate || paths.Executable == paths.SigningPrivate || paths.KEMPrivate == paths.SigningPrivate {
		return OpenSSLPaths{}, errors.New("OpenSSL executable and two encrypted PEM paths must be distinct")
	}
	return paths, nil
}

func validateExternalProfilePair(state externalProfileState, pair ownerbootstrap.PairingFile) error {
	if err := pair.Validate(time.Time{}); err != nil {
		return err
	}
	pairHub := clientoperator.HubIdentity{Contract: pair.Hub.Contract, HubID: pair.Hub.HubID,
		Public: pair.Hub.Public, KeyVersion: pair.Hub.KeyVersion, Suite: pair.Hub.Suite}
	if pair.Manifest.AccountID != state.AccountID || pair.Manifest.OwnerID != state.OwnerID || pair.Manifest.HubID != state.Hub.HubID ||
		pair.Origin != state.Origin || pair.AllowLoopbackHTTP != state.AllowLoopbackHTTP || !reflect.DeepEqual(pairHub, state.Hub) ||
		!reflect.DeepEqual(pair.Manifest.CandidatePublic, state.OwnerPublic) || pair.Manifest.CandidateFingerprint != state.Fingerprint {
		return ErrMismatch
	}
	return nil
}

func validateExternalParent(path string) error {
	return validateExternalParentDirectory(path)
}

// WriteGrantFileExclusive persists one signed public grant without overwrite.
// On Windows the grant is protected by an owner-and-System DACL; on Unix it
// has mode 0600. The grant output is not an Owner private key.
func WriteGrantFileExclusive(path string, data []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) != absolute || !safePathText(absolute) {
		return errors.New("private Owner grant output path is invalid")
	}
	return writeExternalPrivateExclusive(absolute, data)
}

// WriteGrantSummaryExclusive writes public-only grant scope JSON without
// overwriting an existing path. The caller must already have completed the
// interactive exact-scope review before it calls this method.
func WriteGrantSummaryExclusive(path string, data []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) != absolute || !safePathText(absolute) || len(data) == 0 || len(data) > 64*1024 {
		return errors.New("public grant summary output is invalid")
	}
	return writeExternalPublicExclusive(absolute, data)
}

func pathWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
