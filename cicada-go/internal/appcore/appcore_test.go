package appcore

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestActivationAndConnectionCardBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 15, 13, 0, 0, 0, time.UTC)
	claim := wire.ClaimCard{Format: wire.ClaimCardFormat, Version: 1, Purpose: wire.PurposeInitialClaim,
		Origin: "https://hub.synthetic.invalid", HubID: "hub_synthetic", HubFingerprint: strings.Repeat("a", 64),
		AccountID: "account_synthetic", OwnerID: "human_synthetic", ClaimID: strings.Repeat("b", 32),
		Code:     base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	activation, err := NewActivationCode(claim)
	if err != nil {
		t.Fatalf("NewActivationCode: %v", err)
	}
	encoded := activation.Encode()
	parsed, err := ParseActivationCode(encoded)
	if err != nil || parsed.card != claim {
		t.Fatal("activation code did not round-trip through strict wire framing")
	}
	logged := fmt.Sprintf("%v %#v %+v", activation, activation, Action{Kind: ActionConnect, ActivationCode: encoded, Password: "synthetic-password-secret"})
	if strings.Contains(logged, encoded) || strings.Contains(logged, claim.Code) || strings.Contains(logged, "synthetic-password-secret") {
		t.Fatal("activation code or password appeared in a formatted value")
	}
	if _, err := ParseActivationCode("https://hub.synthetic.invalid/" + encoded); err == nil {
		t.Fatal("activation code accepted as a URL")
	}

	connection := HubConnectionCard{Format: connectionCardFormat, Version: 1, Purpose: connectionCardPurpose,
		Origin: "https://hub.synthetic.invalid", HubID: claim.HubID, HubFingerprint: claim.HubFingerprint,
		AccountID: claim.AccountID, OwnerID: claim.OwnerID,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339Nano)}
	connectionText, err := connection.Encode()
	if err != nil {
		t.Fatalf("HubConnectionCard.Encode: %v", err)
	}
	decoded, err := ParseHubConnectionCard(connectionText, now)
	if err != nil || decoded != connection {
		t.Fatal("public Hub connection card did not round-trip")
	}
	if _, err := ParseHubConnectionCard(connectionText, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired public Hub connection card was accepted")
	}
}

func TestNativeCoreSnapshotAndPasswordPreflight(t *testing.T) {
	controller, err := NewController(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	first := controller.Snapshot()
	if first.Phase != PhaseNeedConnection || first.Management != ManagementUnavailable || first.Canvas.State != CanvasNoAuthorization {
		t.Fatalf("initial native snapshot overstated data or authority: %+v", first)
	}
	first.AvailableActions[0] = ActionLogout
	if got := controller.Snapshot(); got.AvailableActions[0] != ActionConnect {
		t.Fatal("Snapshot returned a mutable shared action slice")
	}
	for _, password := range []string{"short", "123456789", strings.Repeat("x", 1025), string([]byte{0xff, 0xfe})} {
		if validPasswordInput(password) {
			t.Fatal("local password preflight accepted input outside the server's basic length/UTF-8 bounds")
		}
	}
	for _, password := range []string{"0123456789", "correct-horse battery staple", "🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿"} {
		if !validPasswordInput(password) {
			t.Fatal("local password preflight rejected a valid minimum-length UTF-8 input")
		}
	}
}

func TestExistingOwnerImportCreatesEncryptedLocalVaultWithoutAuthority(t *testing.T) {
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub := wire.HubIdentity{Contract: "android-hub-v1", HubID: "hub_native_fixture", Public: identity.Public(),
		KeyVersion: 1, Suite: ownerbootstrap.Suite}
	fingerprint, err := wire.HubFingerprint(hub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var accountRequests atomic.Int32
	metadata := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/healthz":
			_ = json.NewEncoder(response).Encode(map[string]any{"status": "ok", "service": "cicada-hub",
				"version": "0.0.5", "stage": "test", "revision": "synthetic", "dirty": true,
				"source_fingerprint": "synthetic", "catalog_sha256": strings.Repeat("a", 64)})
		case "/v2/client/identity":
			_ = json.NewEncoder(response).Encode(hub)
		default:
			accountRequests.Add(1)
			http.Error(response, "no account operations in this metadata fixture", http.StatusForbidden)
		}
	}))
	defer metadata.Close()
	connection := HubConnectionCard{Format: connectionCardFormat, Version: 1, Purpose: connectionCardPurpose,
		Origin: metadata.URL, AllowLoopbackHTTP: true, HubID: hub.HubID, HubFingerprint: fingerprint,
		AccountID: "account_existing", OwnerID: "human_existing", IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	connectionText, err := connection.Encode()
	if err != nil {
		t.Fatal(err)
	}
	vaultRoot := filepath.Join(t.TempDir(), "vaults")
	openVault := func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		path, err := scopeVaultPath(vaultRoot, scope)
		if err != nil {
			return nil, err
		}
		protector, err := appvault.NewPasswordProtector([]byte("synthetic vault passphrase"))
		if err != nil {
			return nil, err
		}
		_, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			if !create {
				protector.Close()
				return nil, appvault.ErrStateNotFound
			}
			return appvault.Create(path, scope, protector)
		}
		if statErr != nil {
			protector.Close()
			return nil, statErr
		}
		return appvault.Open(path, scope, protector)
	}
	controller, err := NewController(Config{OpenVault: openVault, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if err := controller.Dispatch(context.Background(), Action{Kind: ActionConnect, ConnectionCard: connectionText}); err == nil {
		t.Fatal("existing account without an enrolled App-device vault unexpectedly unlocked")
	}
	if got := controller.Snapshot(); got.Phase != PhaseLocked || !got.Hub.Verified || !containsAction(got.AvailableActions, ActionImportOwner) {
		t.Fatalf("verified existing Hub did not offer safe local key import while locked: %+v", got)
	}
	invalid := &OwnerImport{KEMPrivatePKCS8: []byte("bad"), SigningPrivatePKCS8: []byte("bad"),
		KEMPublicSPKI: []byte("bad"), SigningPublicSPKI: []byte("bad")}
	if err := controller.Dispatch(context.Background(), Action{Kind: ActionImportOwner, OwnerImport: invalid}); err == nil {
		t.Fatal("malformed existing Owner key import succeeded")
	}
	if _, err := os.Stat(vaultRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid Owner key created or modified a vault before local import validation")
	}
	imported := syntheticOwnerImport(t)
	defer clear(imported.KEMPrivatePKCS8)
	defer clear(imported.SigningPrivatePKCS8)
	defer clear(imported.KEMPublicSPKI)
	defer clear(imported.SigningPublicSPKI)
	want, err := appkeys.ImportOwner(appkeys.ImportOwnerPEM{KEMPrivatePKCS8: imported.KEMPrivatePKCS8,
		SigningPrivatePKCS8: imported.SigningPrivatePKCS8, KEMPublicSPKI: imported.KEMPublicSPKI,
		SigningPublicSPKI: imported.SigningPublicSPKI})
	if err != nil {
		t.Fatal("synthetic existing Owner identity fixture is invalid")
	}
	wantKeyID := want.Public().ID
	want.Close()
	if err := controller.Dispatch(context.Background(), Action{Kind: ActionImportOwner, OwnerImport: &imported}); err != nil {
		t.Fatalf("import existing Owner identity: %v", err)
	}
	native := controller.(*nativeController)
	if native.owner == nil || native.owner.Public().ID != wantKeyID || native.device != nil {
		t.Fatal("Owner import changed the supplied key or invented an App-device registration")
	}
	entries, err := native.vault.List()
	if err != nil || len(entries) != 1 || entries[0].Purpose != appvault.PurposeOwnerSigner || entries[0].KeyID != wantKeyID {
		t.Fatal("existing Owner identity was not preserved as the sole encrypted local key")
	}
	if got := controller.Snapshot(); got.Phase != PhaseLocked || got.Account.LocalOwnerKeyPresent || got.Management != ManagementUnavailable || got.Canvas.State != CanvasNoAuthorization {
		t.Fatalf("local Owner import implied account, Root or management authority: %+v", got)
	}
	if accountRequests.Load() != 0 {
		t.Fatal("local Owner import attempted an account protocol operation")
	}
}

func syntheticOwnerImport(t *testing.T) OwnerImport {
	t.Helper()
	kemOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	signingOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	kemSeed := bytes.Repeat([]byte{0x31}, mlkem768.KeySeedSize)
	kemPublic, kemPrivate := mlkem768.NewKeyFromSeed(kemSeed)
	kemExpanded, err := kemPrivate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	kemChoice, err := asn1.Marshal(struct{ Seed, Expanded []byte }{kemSeed, kemExpanded})
	if err != nil {
		t.Fatal(err)
	}
	kemPrivatePEM := marshalPrivateKeyPEM(t, kemOID, kemChoice)
	kemPublicBytes, err := kemPublic.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	kemPublicPEM := marshalPublicKeyPEM(t, kemOID, kemPublicBytes)
	clear(kemSeed)
	clear(kemExpanded)
	clear(kemChoice)
	clear(kemPublicBytes)

	signingSeed := bytes.Repeat([]byte{0x53}, mldsa65.SeedSize)
	signingPublic, signingPrivate := mldsa65.Scheme().DeriveKey(signingSeed)
	signingExpanded, err := signingPrivate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signingChoice, err := asn1.Marshal(struct{ Seed, Expanded []byte }{signingSeed, signingExpanded})
	if err != nil {
		t.Fatal(err)
	}
	signingPrivatePEM := marshalPrivateKeyPEM(t, signingOID, signingChoice)
	signingPublicPEM, err := pki.MarshalPEMPublicKey(signingPublic)
	if err != nil {
		t.Fatal(err)
	}
	clear(signingSeed)
	clear(signingExpanded)
	clear(signingChoice)
	return OwnerImport{KEMPrivatePKCS8: kemPrivatePEM, SigningPrivatePKCS8: signingPrivatePEM,
		KEMPublicSPKI: kemPublicPEM, SigningPublicSPKI: signingPublicPEM}
}

func marshalPrivateKeyPEM(t *testing.T, oid asn1.ObjectIdentifier, private []byte) []byte {
	t.Helper()
	info := struct {
		Version   int
		Algorithm struct {
			OID        asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PrivateKey []byte
	}{Version: 0, PrivateKey: private}
	info.Algorithm.OID = oid
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func marshalPublicKeyPEM(t *testing.T, oid asn1.ObjectIdentifier, public []byte) []byte {
	t.Helper()
	info := struct {
		Algorithm struct {
			OID        asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PublicKey asn1.BitString
	}{}
	info.Algorithm.OID = oid
	info.PublicKey = asn1.BitString{Bytes: public, BitLength: len(public) * 8}
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
