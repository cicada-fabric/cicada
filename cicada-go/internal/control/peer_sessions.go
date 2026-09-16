package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// PeerSessionInfo is the safe, non-secret view exposed to clients.
type PeerSessionInfo struct {
	ContactID    string `json:"contact_id"`
	Epoch        uint64 `json:"epoch"`
	SendCount    uint64 `json:"send_count"`
	ReceiveCount uint64 `json:"receive_count"`
	Status       string `json:"status"`
	UpdatedAt    string `json:"updated_at"`
}

func sessionState(session *store.PeerSession) *e2ee.RatchetState {
	if session == nil {
		return nil
	}
	return &e2ee.RatchetState{Epoch: session.Epoch, RootKey: append([]byte(nil), session.RootKey...), SendChainKey: append([]byte(nil), session.SendChainKey...), ReceiveChainKey: append([]byte(nil), session.ReceiveChainKey...), SendCount: session.SendCount, ReceiveCount: session.ReceiveCount}
}

func storeSession(contactID string, state *e2ee.RatchetState, pending []byte, status string) store.PeerSession {
	return store.PeerSession{ContactID: contactID, Epoch: state.Epoch, RootKey: append([]byte(nil), state.RootKey...), SendChainKey: append([]byte(nil), state.SendChainKey...), ReceiveChainKey: append([]byte(nil), state.ReceiveChainKey...), SendCount: state.SendCount, ReceiveCount: state.ReceiveCount, PendingOffer: append([]byte(nil), pending...), Status: status}
}

func (c *Control) loadSendSession(contact *store.Contact) (*e2ee.RatchetState, []byte, error) {
	session, err := c.store.GetPeerSession(contact.ID)
	if err != nil {
		return nil, nil, err
	}
	if session != nil {
		state := sessionState(session)
		state.LocalID, state.RemoteID = c.Identity().ID, contact.Identity.ID
		return state, append([]byte(nil), session.PendingOffer...), nil
	}
	offer, root, err := e2ee.NewSessionOffer(c.identity, contact.Identity, 1)
	if err != nil {
		return nil, nil, err
	}
	state, err := e2ee.NewRatchetState(1, root, c.Identity().ID, contact.Identity.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := c.store.SavePeerSession(storeSession(contact.ID, state, offer, "active")); err != nil {
		return nil, nil, err
	}
	return state, offer, nil
}

func (c *Control) saveSession(contactID string, state *e2ee.RatchetState, pending []byte) error {
	if state == nil {
		return errors.New("nil ratchet state")
	}
	return c.store.SavePeerSession(storeSession(contactID, state, pending, "active"))
}

func (c *Control) openPeerEnvelope(contact *store.Contact, envelope, aad []byte) ([]byte, uint64, error) {
	var parsed e2ee.Envelope
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return nil, 0, err
	}
	if parsed.SessionEpoch == 0 {
		plaintext, sequence, err := e2ee.Open(c.identity, contact.Identity, envelope, aad)
		return plaintext, sequence, err
	}
	session, err := c.store.GetPeerSession(contact.ID)
	if err != nil {
		return nil, 0, err
	}
	state := sessionState(session)
	if state != nil {
		state.LocalID, state.RemoteID = c.Identity().ID, contact.Identity.ID
	}
	plaintext, next, err := e2ee.OpenRatchet(c.identity, contact.Identity, envelope, aad, state)
	if err != nil {
		if errors.Is(err, e2ee.ErrReplay) {
			return nil, 0, store.ErrPeerReplay
		}
		return nil, 0, err
	}
	if err := c.saveSession(contact.ID, next, nil); err != nil {
		return nil, 0, err
	}
	return plaintext, parsed.Sequence, nil
}

func (c *Control) PeerSession(contactID string) (*PeerSessionInfo, error) {
	contact, err := c.store.GetContact(strings.TrimSpace(contactID))
	if err != nil {
		return nil, err
	}
	if contact == nil {
		return nil, os.ErrNotExist
	}
	session, err := c.store.GetPeerSession(contact.ID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return &PeerSessionInfo{ContactID: contact.ID, Status: "uninitialized"}, nil
	}
	return &PeerSessionInfo{ContactID: contact.ID, Epoch: session.Epoch, SendCount: session.SendCount, ReceiveCount: session.ReceiveCount, Status: session.Status, UpdatedAt: session.UpdatedAt}, nil
}

// RotatePeerSession starts a new signed PQ session. The offer is sent with the
// next message and is never returned to the client because it is opaque,
// authenticated protocol data.
func (c *Control) RotatePeerSession(contactID string) (*PeerSessionInfo, error) {
	contact, err := c.store.GetContact(strings.TrimSpace(contactID))
	if err != nil {
		return nil, err
	}
	if contact == nil {
		return nil, os.ErrNotExist
	}
	if contact.Status != "trusted" {
		return nil, fmt.Errorf("contact is not trusted: %s", contact.Status)
	}
	if c.identity == nil {
		return nil, errors.New("local E2EE identity is unavailable")
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	current, err := c.store.GetPeerSession(contact.ID)
	if err != nil {
		return nil, err
	}
	epoch := uint64(1)
	if current != nil {
		epoch = current.Epoch + 1
	}
	offer, root, err := e2ee.NewSessionOffer(c.identity, contact.Identity, epoch)
	if err != nil {
		return nil, err
	}
	state, err := e2ee.NewRatchetState(epoch, root, c.Identity().ID, contact.Identity.ID)
	if err != nil {
		return nil, err
	}
	if err := c.store.SavePeerSession(storeSession(contact.ID, state, offer, "rotating")); err != nil {
		return nil, err
	}
	return &PeerSessionInfo{ContactID: contact.ID, Epoch: epoch, Status: "rotating"}, nil
}
