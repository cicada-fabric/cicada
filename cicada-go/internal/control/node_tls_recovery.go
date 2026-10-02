package control

import (
	"bytes"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// ReadNodeTLSRecoveryPacket authenticates a read-only recovery conversation
// without constructing Control business. hub must be the existing independently
// provisioned HubControl identity; neither the request nor its TLS material can
// supply a replacement. The caller must also enforce the actual PQTLS transport.
func ReadNodeTLSRecoveryPacket(persistence *store.Store, hub *e2ee.Identity, credentialDigest, nodeID string, packet []byte) ([]byte, error) {
	if persistence == nil || hub == nil {
		return nil, ErrNodeTLSCurrentUnavailable
	}
	if len(packet) == 0 || len(packet) > nodewire.MaxRecoveryPacketBytes {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	return readNodeTLSRecoveryPacket(persistence, hub, credentialDigest, nodeID, bytes.Clone(packet), persistence.ReadNodeTLSAuthorityRecoveryLocal)
}

// The package-private reader permits deterministic tests of a change between
// independent transactions. Production always supplies the real Store reader.
func readNodeTLSRecoveryPacket(persistence *store.Store, hub *e2ee.Identity, credentialDigest, nodeID string, packet []byte, readCurrent func(store.NodeTLSAuthorityStatusInput) (*store.NodeTLSAuthorityRecoveryStatus, error)) ([]byte, error) {
	read := func() (*store.NodeTLSAuthorityRecoveryStatus, error) {
		s, err := readCurrent(store.NodeTLSAuthorityStatusInput{NodeID: nodeID, CredentialDigest: credentialDigest})
		if err != nil {
			return nil, err
		}
		if s == nil || s.CurrentBinding == nil || s.CurrentActiveState != store.NodeTLSAuthorityCurrentVerified || s.CurrentActive == nil || s.CurrentActive.State != store.NodeTLSActive || s.OwnerKeyVersion == 0 || s.ClientDeviceVersion == 0 {
			return nil, ErrNodeTLSCurrentUnavailable
		}
		b := s.CurrentBinding
		actual, expected := hub.Public(), b.HubPublicIdentity
		if b.NodeID != nodeID || b.CredentialDigest != credentialDigest || actual.ID != expected.ID || !bytes.Equal(actual.SigningPublic, expected.SigningPublic) || !bytes.Equal(actual.KEMPublic, expected.KEMPublic) {
			return nil, store.ErrNodeTLSAuthorityDenied
		}
		return s, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	// No Store reader may run in this callback: the current-binding transaction
	// already holds Store.mu. Only compare its binding and authenticate the packet.
	b, q, status, err := persistence.NodeControlRecoveryStatus(credentialDigest, nodeID, func(b *store.NodeControlKeyBinding) (nodewire.RecoveryRequest, error) {
		if !reflect.DeepEqual(b, first.CurrentBinding) {
			return nodewire.RecoveryRequest{}, store.ErrNodeTLSAuthorityDenied
		}
		actual, expected := hub.Public(), b.HubPublicIdentity
		if actual.ID != expected.ID || !bytes.Equal(actual.SigningPublic, expected.SigningPublic) || !bytes.Equal(actual.KEMPublic, expected.KEMPublic) {
			return nodewire.RecoveryRequest{}, store.ErrNodeTLSAuthorityDenied
		}
		q, err := nodewire.OpenRecoveryRequest(hub, nodeControlWireBinding(b), packet)
		if err != nil || q.Origin != first.CurrentActive.Claims.ApplicationOrigin {
			return nodewire.RecoveryRequest{}, store.ErrNodeTLSAuthorityDenied
		}
		return q, nil
	})
	if err != nil {
		return nil, err
	}
	second, err := read()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(first.CurrentBinding, second.CurrentBinding) || !reflect.DeepEqual(b, second.CurrentBinding) || first.OwnerKeyVersion != second.OwnerKeyVersion || first.ClientDeviceVersion != second.ClientDeviceVersion || !reflect.DeepEqual(first.CurrentActive, second.CurrentActive) {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	// Pending progress and a higher burned reservation floor do not replace an
	// independently verified, still-valid ACTIVE. Each read verified its permanent
	// evidence; only the current authority tuple must remain exact here.
	return nodewire.SealRecoveryResponse(hub, nodeControlWireBinding(second.CurrentBinding), q, packet, status)
}
