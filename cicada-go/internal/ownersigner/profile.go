// Package ownersigner implements the local Owner approval signer profile.
// Private keys remain on the operator machine; Hub communication is limited
// to the finite first-signer proof and the existing Client device grant.
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
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/gofrs/flock"
)

const (
	profileVersion       = 1
	profileFileName      = "owner-signer.json"
	profileLockName      = ".owner-signer.lock"
	publicManifestFormat = "cicada.owner-signer-public.v1"
	maxProfileBytes      = 2 << 20
	maxPairingFileBytes  = 256 << 10
	maxReceiptBytes      = 64 << 10
)

const ConnectionFileFormat = "cicada.hub-owner-connection.v1"
const ConnectionFilePurpose = ownerbootstrap.Purpose

var (
	ErrBusy      = errors.New("Owner signer profile is already in use")
	ErrPending   = errors.New("resume the saved Owner bootstrap operation before starting another")
	ErrNoPending = errors.New("Owner signer profile has no pending bootstrap operation")
	ErrMismatch  = errors.New("Owner signer material does not match the reviewed Hub, account, or key")
	ErrReview    = errors.New("Owner signer operation was not approved")
	ErrUncertain = errors.New("Owner bootstrap outcome is unknown; recover the saved operation")
)

// PublicManifest is safe to transfer to the Hub operator. Fingerprint covers
// the full serialized Owner identity, including both PQ public keys.
type PublicManifest struct {
	Format            string                     `json:"format"`
	AccountID         string                     `json:"account_id"`
	OwnerID           string                     `json:"owner_id"`
	OwnerPublic       e2ee.PublicIdentity        `json:"owner_public_identity"`
	Fingerprint       string                     `json:"fingerprint"`
	Origin            string                     `json:"origin"`
	AllowLoopbackHTTP bool                       `json:"allow_loopback_http"`
	Hub               clientoperator.HubIdentity `json:"hub"`
}

// ConnectionFile is the public deployment metadata exported locally by
// `cicada hub setup`. It is a transfer format, not a trust-on-first-use source:
// the recipient must receive and review this complete pin independently.
type ConnectionFile struct {
	Format            string                     `json:"format"`
	Version           int                        `json:"version"`
	Purpose           string                     `json:"purpose"`
	AccountID         string                     `json:"account_id"`
	OwnerID           string                     `json:"owner_id"`
	Origin            string                     `json:"origin"`
	AllowLoopbackHTTP bool                       `json:"allow_loopback_http"`
	Hub               clientoperator.HubIdentity `json:"hub"`
}

func (c ConnectionFile) Validate() error {
	origin, err := ownerbootstrap.CanonicalOrigin(c.Origin, c.AllowLoopbackHTTP)
	if c.Format != ConnectionFileFormat || c.Version != 1 || c.Purpose != ConnectionFilePurpose ||
		!validID(c.AccountID) || !validID(c.OwnerID) || !safeDisplayText(c.Origin) || err != nil || origin != c.Origin || validateHub(c.Hub) != nil {
		return errors.New("public Hub Owner connection file is invalid")
	}
	return nil
}

// BootstrapReview contains only public fields that the human must compare.
type BootstrapReview struct {
	AccountID   string
	OwnerID     string
	HubID       string
	Origin      string
	Purpose     string
	AuthorityID string
	OperationID string
	Fingerprint string
	ExpiresAt   string
}

// GrantReview describes the exact existing OwnerDeviceGrant scope to approve.
type GrantReview struct {
	AccountID         string
	OwnerID           string
	OwnerKeyID        string
	HubID             string
	DeviceID          string
	DeviceKeyID       string
	DeviceFingerprint string
	Purpose           string
	IssuedAt          string
	ExpiresAt         string
}

type pendingBootstrap struct {
	PairFile []byte `json:"pair_file"`
	Proof    []byte `json:"proof"`
	Response []byte `json:"response,omitempty"`
}

type profileState struct {
	Version           int                        `json:"version"`
	AccountID         string                     `json:"account_id"`
	OwnerID           string                     `json:"owner_id"`
	Origin            string                     `json:"origin"`
	AllowLoopbackHTTP bool                       `json:"allow_loopback_http"`
	Hub               clientoperator.HubIdentity `json:"hub"`
	PrivateIdentity   []byte                     `json:"owner_private_identity"`
	Bootstrap         *pendingBootstrap          `json:"bootstrap,omitempty"`
}

// The exclusive profile lock serializes independent processes. A Profile value
// itself is not concurrency-safe; callers must invoke its methods sequentially
// and close it after each command.
type Profile struct {
	dir    string
	lock   *flock.Flock
	state  profileState
	owner  *e2ee.Identity
	http   *http.Client
	broken bool
	closed bool
}

// Prepare creates a new private profile. A nil identity creates a new Owner
// key; a supplied identity is an explicit local import. The directory is
// created mode 0700 and existing profile state is never overwritten.
func Prepare(dir, accountID, ownerID, origin string, hub clientoperator.HubIdentity, allowLoopbackHTTP bool, identity *e2ee.Identity) (*Profile, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("Owner private custody requires Unix permissions; Windows ACL custody is not implemented")
	}
	accountID, ownerID = strings.TrimSpace(accountID), strings.TrimSpace(ownerID)
	if !validID(accountID) || !validID(ownerID) {
		return nil, errors.New("Owner account and principal IDs must be nonempty stable IDs")
	}
	canonicalOrigin, err := ownerbootstrap.CanonicalOrigin(origin, allowLoopbackHTTP)
	if err != nil || canonicalOrigin != origin || !safeDisplayText(origin) {
		return nil, errors.New("Owner signer origin must be an exact HTTPS origin (or explicit literal-loopback HTTP)")
	}
	if err := validateHub(hub); err != nil {
		return nil, err
	}
	if identity == nil {
		identity, err = e2ee.NewIdentity()
		if err != nil {
			return nil, fmt.Errorf("generate Owner approval identity: %w", err)
		}
	}
	if err := e2ee.ValidatePublicIdentity(identity.Public()); err != nil {
		return nil, errors.New("Owner private identity is invalid")
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		return nil, errors.New("Owner private identity cannot be serialized")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return nil, errors.New("Owner signer profile parent must exist without symlink components")
	}
	if err := os.Mkdir(abs, 0700); err != nil {
		return nil, fmt.Errorf("create Owner signer profile without overwrite: %w", err)
	}
	if err := os.Chmod(abs, 0700); err != nil {
		_ = os.Remove(abs)
		return nil, err
	}
	p, err := acquire(abs)
	if err != nil {
		return nil, err
	}
	p.owner = identity
	p.state = profileState{Version: profileVersion, AccountID: accountID, OwnerID: ownerID,
		Origin: canonicalOrigin, AllowLoopbackHTTP: allowLoopbackHTTP, Hub: hub, PrivateIdentity: private}
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

// Open loads an existing private profile and takes its exclusive writer lock.
func Open(dir string) (*Profile, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("Owner private custody requires Unix permissions; Windows ACL custody is not implemented")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, errors.New("Owner signer profile path must not contain symlink components")
	}
	p, err := acquire(abs)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = p.Close()
		}
	}()
	data, err := readRegular(filepath.Join(abs, profileFileName), 0600, maxProfileBytes)
	if err != nil {
		return nil, errors.New("Owner signer profile state is unavailable or has unsafe permissions")
	}
	if err := decodeStrict(data, &p.state); err != nil {
		return nil, errors.New("Owner signer profile state is invalid")
	}
	s := p.state
	canonicalOrigin, originErr := ownerbootstrap.CanonicalOrigin(s.Origin, s.AllowLoopbackHTTP)
	if originErr != nil || canonicalOrigin != s.Origin || s.Version != profileVersion ||
		!safeDisplayText(s.Origin) ||
		!validID(s.AccountID) || !validID(s.OwnerID) || validateHub(s.Hub) != nil ||
		len(s.PrivateIdentity) == 0 || len(s.PrivateIdentity) > 32768 {
		return nil, errors.New("Owner signer profile identity or trust pin is invalid")
	}
	p.owner, err = e2ee.UnmarshalIdentity(s.PrivateIdentity)
	if err != nil || e2ee.ValidatePublicIdentity(p.owner.Public()) != nil {
		return nil, errors.New("Owner signer private identity is invalid")
	}
	if s.Bootstrap != nil {
		if err := validatePending(s.Bootstrap); err != nil {
			return nil, errors.New("Owner signer pending operation is invalid")
		}
		pair, err := decodePairFile(s.Bootstrap.PairFile)
		if err != nil || validateProfilePair(s, p.owner, pair) != nil {
			return nil, errors.New("Owner signer pending operation differs from its saved trust pin")
		}
		if len(s.Bootstrap.Response) > 0 {
			if _, err := ownerbootstrap.VerifyReceipt(p.owner, pair, s.Bootstrap.Response); err != nil {
				return nil, errors.New("Owner signer cached bootstrap receipt is invalid")
			}
		}
	}
	if err := p.configureHTTP(); err != nil {
		return nil, err
	}
	ok = true
	return p, nil
}

func acquire(dir string) (*Profile, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, errors.New("Owner signer profile directory must have mode 0700")
	}
	lockPath := filepath.Join(dir, profileLockName)
	file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		err = file.Close()
	} else if errors.Is(err, os.ErrExist) {
		_, err = readRegular(lockPath, 0600, 0)
	}
	if err != nil {
		return nil, errors.New("Owner signer profile lock is unsafe")
	}
	lock := flock.New(lockPath, flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrBusy
	}
	return &Profile{dir: dir, lock: lock}, nil
}

func (p *Profile) configureHTTP() error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	p.http = &http.Client{Timeout: 20 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Owner signer redirects are forbidden") }}
	return nil
}

func (p *Profile) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	if p.http != nil {
		p.http.CloseIdleConnections()
	}
	var err error
	if p.lock != nil {
		err = p.lock.Unlock()
		p.lock = nil
	}
	p.owner = nil
	for i := range p.state.PrivateIdentity {
		p.state.PrivateIdentity[i] = 0
	}
	p.state.PrivateIdentity = nil
	return err
}

func (p *Profile) PublicManifest() PublicManifest {
	if p == nil || p.closed || p.owner == nil {
		return PublicManifest{}
	}
	return PublicManifest{Format: publicManifestFormat, AccountID: p.state.AccountID, OwnerID: p.state.OwnerID,
		OwnerPublic: p.owner.Public(), Fingerprint: ownerbootstrap.Fingerprint(p.owner.Public()),
		Origin: p.state.Origin, AllowLoopbackHTTP: p.state.AllowLoopbackHTTP, Hub: p.state.Hub}
}

// ExportManifest writes public identity and pin material without overwriting an
// existing file. The profile directory itself remains private.
func (p *Profile) ExportManifest(path string) (string, error) {
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
	if err := writePublicExclusiveOrSame(absolute, data); err != nil {
		return "", err
	}
	return absolute, nil
}

// Bootstrap validates a locally issued pairing file, requires an explicit
// review callback, persists the exact proof before HTTP, and stores the exact
// authenticated response before returning it. Exact retries reuse the saved
// proof. An expired unaccepted operation can be replaced only by a distinct
// authenticated challenge whose conservative issuance lower bound is after
// the old expiry, and only after another explicit review.
func (p *Profile) Bootstrap(ctx context.Context, pairBytes []byte, review func(BootstrapReview) error) (*ownerbootstrap.Receipt, error) {
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
	if err != nil {
		return nil, ownerbootstrap.ErrInvalid
	}
	now := time.Now().UTC()
	if err := validateProfilePair(p.state, p.owner, pair); err != nil {
		return nil, err
	}
	if err := validateAuthenticatedChallenge(p.owner, pair); err != nil {
		return nil, errors.New("Owner bootstrap challenge is not authenticated by the pinned Hub")
	}
	if p.state.Bootstrap != nil {
		pending := p.state.Bootstrap
		if bytes.Equal(pending.PairFile, pairBytes) {
			if err := review(reviewFor(pair)); err != nil {
				return nil, ErrReview
			}
			return p.submitSaved(ctx, nil)
		}
		if len(pending.Response) > 0 {
			return nil, ErrPending
		}
		oldPair, err := decodePairFile(pending.PairFile)
		if err != nil || validateProfilePair(p.state, p.owner, oldPair) != nil || validateAuthenticatedChallenge(p.owner, oldPair) != nil {
			return nil, ErrPending
		}
		if err := validateSavedProofRoute(oldPair, pending.Proof); err != nil {
			return nil, ErrPending
		}
		oldExpires, err := canonicalPairExpiry(oldPair)
		if err != nil || oldExpires.After(now) {
			return nil, ErrPending
		}
		if err := validatePairLifetime(pair, now); err != nil {
			return nil, err
		}
		newExpires, err := canonicalPairExpiry(pair)
		if err != nil || newExpires.Add(-ownerbootstrap.MaxLifetime).Before(oldExpires) ||
			pair.Manifest.AuthorityID == oldPair.Manifest.AuthorityID || pair.Manifest.OperationID == oldPair.Manifest.OperationID ||
			pair.Manifest.Digest() == oldPair.Manifest.Digest() || bytes.Equal(pair.Challenge, oldPair.Challenge) {
			return nil, errors.New("replacement Owner bootstrap challenge is not a distinct post-expiry authority")
		}
		if err := review(reviewFor(pair)); err != nil {
			return nil, ErrReview
		}
		proof, err := ownerbootstrap.CreateProof(p.owner, pair, now)
		if err != nil {
			return nil, errors.New("replacement Owner bootstrap proof could not be created")
		}
		p.state.Bootstrap = &pendingBootstrap{PairFile: append([]byte(nil), pairBytes...), Proof: append([]byte(nil), proof...)}
		if err := p.save(); err != nil {
			return nil, errors.New("could not persist replacement Owner bootstrap proof before sending")
		}
		return p.submitSaved(ctx, nil)
	}
	if err := validatePairLifetime(pair, now); err != nil {
		return nil, err
	}
	if err := review(reviewFor(pair)); err != nil {
		return nil, ErrReview
	}
	proof, err := ownerbootstrap.CreateProof(p.owner, pair, now)
	if err != nil {
		return nil, err
	}
	p.state.Bootstrap = &pendingBootstrap{PairFile: append([]byte(nil), pairBytes...), Proof: append([]byte(nil), proof...)}
	if err := p.save(); err != nil {
		return nil, errors.New("could not persist exact Owner bootstrap proof before sending")
	}
	return p.submitSaved(ctx, nil)
}

// Recover resends the exact persisted proof to the fixed accept endpoint. It
// never creates a new signature, operation ID, challenge or counter.
func (p *Profile) Recover(ctx context.Context, review func(BootstrapReview) error) (*ownerbootstrap.Receipt, error) {
	if err := p.requireUsable(); err != nil {
		return nil, err
	}
	if p.state.Bootstrap == nil {
		return nil, ErrNoPending
	}
	if review == nil {
		return nil, ErrReview
	}
	if p.state.Bootstrap.Response != nil {
		pair, _ := decodePairFile(p.state.Bootstrap.PairFile)
		return ownerbootstrap.VerifyReceipt(p.owner, pair, p.state.Bootstrap.Response)
	}
	if err := review(reviewForBytes(p.state.Bootstrap.PairFile)); err != nil {
		return nil, ErrReview
	}
	return p.submitSaved(ctx, nil)
}

func (p *Profile) submitSaved(ctx context.Context, review func(BootstrapReview) error) (*ownerbootstrap.Receipt, error) {
	pending := p.state.Bootstrap
	if pending == nil {
		return nil, ErrNoPending
	}
	pair, err := decodePairFile(pending.PairFile)
	if err != nil {
		return nil, ownerbootstrap.ErrInvalid
	}
	if err := validateProfilePair(p.state, p.owner, pair); err != nil {
		return nil, err
	}
	if pending.Response != nil {
		return ownerbootstrap.VerifyReceipt(p.owner, pair, pending.Response)
	}
	if review != nil {
		if err := review(reviewFor(pair)); err != nil {
			return nil, ErrReview
		}
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
	receipt, err := ownerbootstrap.VerifyReceipt(p.owner, pair, body)
	if err != nil {
		return nil, errors.New("Hub Owner bootstrap receipt failed authentication")
	}
	pending.Response = append([]byte(nil), body...)
	if err := p.save(); err != nil {
		return nil, errors.New("Owner bootstrap succeeded but receipt persistence failed; recover the exact operation")
	}
	return receipt, nil
}

// SignDeviceGrant signs the existing canonical OwnerDeviceGrant only after the
// caller confirms the complete public device scope through review.
func (p *Profile) SignDeviceGrant(manifestBytes []byte, expiresAt time.Time, review func(GrantReview) error) ([]byte, error) {
	if err := p.requireUsable(); err != nil {
		return nil, err
	}
	if p.state.Bootstrap == nil || len(p.state.Bootstrap.Response) == 0 {
		return nil, errors.New("Owner device grants require this key's authenticated bootstrap receipt")
	}
	pair, err := decodePairFile(p.state.Bootstrap.PairFile)
	if err != nil || validateProfilePair(p.state, p.owner, pair) != nil {
		return nil, errors.New("Owner bootstrap receipt is not bound to this Owner profile")
	}
	if _, err := ownerbootstrap.VerifyReceipt(p.owner, pair, p.state.Bootstrap.Response); err != nil {
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
		manifest.OwnerID != p.state.OwnerID || manifest.OwnerKeyID != p.owner.Public().ID || manifest.HubID != p.state.Hub.HubID ||
		!validID(manifest.OwnerID) || !validID(manifest.OwnerKeyID) || !validID(manifest.HubID) ||
		e2ee.ValidatePublicIdentity(manifest.DevicePublicIdentity) != nil || !validID(manifest.DeviceID) ||
		!validID(manifest.DevicePublicIdentity.ID) {
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
	reviewInfo := GrantReview{AccountID: p.state.AccountID, OwnerID: p.state.OwnerID, OwnerKeyID: p.owner.Public().ID,
		HubID: p.state.Hub.HubID, DeviceID: manifest.DeviceID, DeviceKeyID: manifest.DevicePublicIdentity.ID,
		DeviceFingerprint: fingerprint, Purpose: manifest.Purpose, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano)}
	if err := review(reviewInfo); err != nil {
		return nil, ErrReview
	}
	return p.owner.SignOwnerDeviceGrant(p.state.OwnerID, manifest.DeviceID, manifest.DevicePublicIdentity,
		p.state.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, expiresAt.UTC())
}

func (p *Profile) requireUsable() error {
	if p == nil || p.closed || p.lock == nil || p.owner == nil {
		return errors.New("Owner signer profile is not open")
	}
	if p.broken {
		return errors.New("Owner signer profile persistence failed; reopen before continuing")
	}
	return nil
}

func (p *Profile) save() error {
	if err := p.requireUsable(); err != nil {
		return err
	}
	data, err := json.Marshal(p.state)
	if err != nil {
		p.broken = true
		return err
	}
	if err := replaceAtomic(filepath.Join(p.dir, profileFileName), data, 0600); err != nil {
		p.broken = true
		return err
	}
	return nil
}

func validateHub(hub clientoperator.HubIdentity) error {
	if hub.Contract != "android-hub-v1" || !validID(hub.HubID) || hub.KeyVersion != 1 || hub.Suite != clientoperator.Suite ||
		e2ee.ValidatePublicIdentity(hub.Public) != nil {
		return errors.New("complete trusted Hub Client-Control identity is invalid")
	}
	return nil
}

func validID(v string) bool {
	if v == "" || len(v) > 128 || !utf8.ValidString(v) || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) || strings.ContainsRune("/\\", r) {
			return false
		}
	}
	return true
}

func validFingerprint(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func safeDisplayText(v string) bool {
	if !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func validateProfilePair(s profileState, owner *e2ee.Identity, pair ownerbootstrap.PairingFile) error {
	if err := pair.Validate(time.Time{}); err != nil {
		return err
	}
	pairHub := clientoperator.HubIdentity{Contract: pair.Hub.Contract, HubID: pair.Hub.HubID,
		Public: pair.Hub.Public, KeyVersion: pair.Hub.KeyVersion, Suite: pair.Hub.Suite}
	if pair.Manifest.AccountID != s.AccountID || pair.Manifest.OwnerID != s.OwnerID || pair.Manifest.HubID != s.Hub.HubID ||
		pair.Origin != s.Origin || pair.AllowLoopbackHTTP != s.AllowLoopbackHTTP || !reflect.DeepEqual(pairHub, s.Hub) ||
		!reflect.DeepEqual(pair.Manifest.CandidatePublic, owner.Public()) || pair.Manifest.CandidateFingerprint != ownerbootstrap.Fingerprint(owner.Public()) {
		return ErrMismatch
	}
	return nil
}

func validatePairLifetime(pair ownerbootstrap.PairingFile, now time.Time) error {
	expires, err := canonicalPairExpiry(pair)
	if err != nil || !expires.After(now) || expires.After(now.Add(ownerbootstrap.MaxLifetime)) {
		return errors.New("Owner bootstrap challenge is expired or exceeds the ten-minute limit")
	}
	return pair.Validate(now)
}

func canonicalPairExpiry(pair ownerbootstrap.PairingFile) (time.Time, error) {
	expires, err := time.Parse(time.RFC3339Nano, pair.Manifest.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != pair.Manifest.ExpiresAt {
		return time.Time{}, errors.New("Owner bootstrap challenge expiry is not canonical UTC RFC3339Nano")
	}
	return expires.UTC(), nil
}

// validateAuthenticatedChallenge verifies the pinned Hub's encrypted RESPONSE
// challenge before a human reviews its operation identifiers. The signed
// expiry is the only timestamp in the fixed wire manifest; MaxLifetime bounds
// how far issuance can precede it.
func validateAuthenticatedChallenge(owner *e2ee.Identity, pair ownerbootstrap.PairingFile) error {
	opened, err := clientwire.OpenResponse(owner, pair.Hub.Public, pair.Manifest.Binding(), pair.Challenge)
	if err != nil || !reflect.DeepEqual(opened.Route, pair.Route(clientwire.DirectionResponse, 1)) {
		return ownerbootstrap.ErrInvalid
	}
	var possession ownerbootstrap.Possession
	if json.Unmarshal(opened.Plaintext, &possession) != nil || possession.Format != ownerbootstrap.Format ||
		!reflect.DeepEqual(possession.Manifest, pair.Manifest) || len(possession.Nonce) != 32 {
		return ownerbootstrap.ErrInvalid
	}
	canonical, err := json.Marshal(possession)
	if err != nil || !bytes.Equal(canonical, opened.Plaintext) {
		return ownerbootstrap.ErrInvalid
	}
	return nil
}

// validateSavedProofRoute checks the locally persisted outbound packet's
// bounded framing and exact public route. The Owner cannot decrypt its own
// Hub-addressed proof; replacement safety comes from the authenticated Hub
// challenges and expiry ordering, not from treating that proof as authority.
func validateSavedProofRoute(pair ownerbootstrap.PairingFile, proof []byte) error {
	if len(proof) == 0 || len(proof) > maxReceiptBytes {
		return ownerbootstrap.ErrInvalid
	}
	var packet clientwire.Packet
	if decodeStrict(proof, &packet) != nil || len(packet.Envelope) == 0 ||
		!reflect.DeepEqual(packet.Route, pair.Route(clientwire.DirectionRequest, 1)) {
		return ownerbootstrap.ErrInvalid
	}
	return nil
}

func reviewFor(pair ownerbootstrap.PairingFile) BootstrapReview {
	m := pair.Manifest
	return BootstrapReview{AccountID: m.AccountID, OwnerID: m.OwnerID, HubID: m.HubID, Origin: pair.Origin,
		Purpose: m.Purpose, AuthorityID: m.AuthorityID, OperationID: m.OperationID,
		Fingerprint: m.CandidateFingerprint, ExpiresAt: m.ExpiresAt}
}

func reviewForBytes(data []byte) BootstrapReview {
	pair, _ := decodePairFile(data)
	return reviewFor(pair)
}

func decodePairFile(data []byte) (ownerbootstrap.PairingFile, error) {
	var pair ownerbootstrap.PairingFile
	if len(data) == 0 || len(data) > maxPairingFileBytes {
		return pair, ownerbootstrap.ErrInvalid
	}
	err := decodeStrict(data, &pair)
	return pair, err
}

func validatePending(p *pendingBootstrap) error {
	if p == nil || len(p.PairFile) == 0 || len(p.PairFile) > maxPairingFileBytes || len(p.Proof) == 0 || len(p.Proof) > maxReceiptBytes || len(p.Response) > maxReceiptBytes {
		return ownerbootstrap.ErrInvalid
	}
	if _, err := decodePairFile(p.PairFile); err != nil {
		return err
	}
	return nil
}

func decodeStrict(data []byte, dst any) error {
	if !utf8.Valid(data) {
		return errors.New("JSON input is not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func readRegular(path string, mode os.FileMode, max int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, errors.New("file path contains symlink components")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return nil, errors.New("file is not a regular file with required permissions")
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("file changed during open")
	}
	limit := max
	if limit <= 0 {
		limit = 1
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || (max > 0 && int64(len(data)) > max) {
		return nil, errors.New("file size is invalid")
	}
	return data, nil
}

func replaceAtomic(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	f, err := os.CreateTemp(parent, ".owner-signer-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create public manifest without overwrite: %w", err)
	}
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writePublicExclusiveOrSame(path string, data []byte) error {
	if existing, err := readPublicRegular(path, maxProfileBytes); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return errors.New("existing public manifest differs from this Owner profile")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeExclusive(path, data, 0644)
}

func readPublicRegular(path string, max int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0644 {
		return nil, errors.New("public file must be a regular file without symlinks")
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("public file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("public file size is invalid")
	}
	return data, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
