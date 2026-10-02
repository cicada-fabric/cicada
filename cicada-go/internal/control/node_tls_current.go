package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

var ErrNodeTLSCurrentUnavailable = errors.New("current Node TLS authority is unavailable")

// LoadExistingNodeTLSHubIdentity reads the already provisioned application
// HubControl identity. No Control instance, replacement key, chmod or trust
// initialization is involved. Public material is checked against current DB
// authority again for each query.
func LoadExistingNodeTLSHubIdentity(path string) (*e2ee.Identity, error) {
	abs, err := filepath.Abs(path)
	if err != nil || abs != path || filepath.Clean(path) != path {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || current != path && !info.IsDir() {
			return nil, ErrNodeTLSCurrentUnavailable
		}
		if current == path {
			owner := reflect.ValueOf(info.Sys())
			if owner.Kind() == reflect.Ptr {
				owner = owner.Elem()
			}
			if owner.Kind() != reflect.Struct {
				return nil, ErrNodeTLSCurrentUnavailable
			}
			uid := owner.FieldByName("Uid")
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 1<<20 || !uid.IsValid() || uint64(os.Geteuid()) != uid.Uint() {
				return nil, ErrNodeTLSCurrentUnavailable
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	defer clear(data)
	identity, err := e2ee.UnmarshalIdentity(data)
	if err != nil {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	return identity, nil
}

// ReadNodeTLSCurrentPacket is pure authentication/state work. Both reads are
// independently fenced Store transactions; no RPC admission, cached response,
// job scheduler, planner or report is touched.
func ReadNodeTLSCurrentPacket(persistence *store.Store, hub *e2ee.Identity, credential, nodeID string, packet []byte) ([]byte, error) {
	if persistence == nil || hub == nil {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	read := func() (*store.NodeTLSAuthorityRecoveryStatus, error) {
		s, err := persistence.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: nodeID, CredentialDigest: credential})
		if err != nil {
			return nil, err
		}
		if s == nil || s.CurrentBinding == nil || s.CurrentActiveState != store.NodeTLSAuthorityCurrentVerified || s.CurrentActive == nil {
			return nil, ErrNodeTLSCurrentUnavailable
		}
		p := hub.Public()
		expected := s.CurrentBinding.HubPublicIdentity
		if p.ID != expected.ID || !bytes.Equal(p.SigningPublic, expected.SigningPublic) || !bytes.Equal(p.KEMPublic, expected.KEMPublic) {
			return nil, store.ErrNodeTLSAuthorityDenied
		}
		return s, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	q, err := nodewire.OpenTLSCurrentRequest(hub, nodeControlWireBinding(first.CurrentBinding), packet, time.Now().UTC())
	if err != nil || q.CredentialDigest != credential {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	second, err := read()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(first.CurrentBinding, second.CurrentBinding) || first.OwnerKeyVersion != second.OwnerKeyVersion || first.ClientDeviceVersion != second.ClientDeviceVersion || !reflect.DeepEqual(first.CurrentActive, second.CurrentActive) {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	a := second.CurrentActive
	binding, err := json.Marshal(second.CurrentBinding)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC().Truncate(time.Second)
	s := nodewire.TLSCurrentStatus{CurrentBinding: binding, OwnerKeyVersion: second.OwnerKeyVersion, ClientDeviceVersion: second.ClientDeviceVersion, ReadAt: at.Format(time.RFC3339), ExpiresAt: at.Add(nodewire.TLSCurrentLifetime).Format(time.RFC3339), CurrentAuthority: nodewire.TLSCurrentAuthority{State: a.State, RowVersion: a.RowVersion, ReservationVersion: a.ReservationVersion, Claims: a.Claims, Grant: a.Grant, CSRPEM: a.CSRPEM, IssuerChainPEM: a.IssuerChainPEM, TrustAnchorPEM: a.TrustAnchorPEM, LeafCertificatePEM: a.LeafCertificatePEM, LeafDERHash: a.LeafDERHash, InstallAck: a.InstallAck, Activation: a.Activation}}
	return nodewire.SealTLSCurrentResponse(hub, nodeControlWireBinding(second.CurrentBinding), q, packet, s, at)
}

func (c *Control) NodeTLSCurrentStatusPacket(credential, nodeID string, packet []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	return ReadNodeTLSCurrentPacket(c.store, c.nodeControlIdentity, credential, nodeID, packet)
}
