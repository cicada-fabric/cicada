package appcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const (
	appStateNamespace    = "appcore.state.v1"
	appSessionNamespace  = "appcore.session.v1"
	appStateFormat       = "cicada.native-app-state.v1"
	appSessionFormat     = "cicada.native-app-session.v1"
	maxDurablePacketSize = 380 * 1024
)

type durableState struct {
	Format           string               `json:"format"`
	Version          int                  `json:"version"`
	Connection       HubConnectionCard    `json:"connection"`
	DeviceID         string               `json:"device_id,omitempty"`
	DeviceKeyID      string               `json:"device_key_id,omitempty"`
	OwnerKeyID       string               `json:"owner_key_id,omitempty"`
	AccountID        string               `json:"account_id,omitempty"`
	OwnerID          string               `json:"owner_id,omitempty"`
	Username         string               `json:"username,omitempty"`
	AccountState     AccountState         `json:"account_state"`
	RootState        RootState            `json:"root_state"`
	OwnerKeyIDAtHub  string               `json:"owner_key_id_at_hub,omitempty"`
	OwnerFingerprint string               `json:"owner_fingerprint,omitempty"`
	ClaimChallenge   *wire.ClaimChallenge `json:"claim_challenge,omitempty"`
	LoginChallenge   *wire.LoginChallenge `json:"login_challenge,omitempty"`
	Pending          *pendingOperation    `json:"pending,omitempty"`
}

type pendingOperation struct {
	Operation string `json:"operation"`
	Request   []byte `json:"request"`
	Response  []byte `json:"response,omitempty"`
}

type durableSession struct {
	Format   string `json:"format"`
	Version  int    `json:"version"`
	Request  []byte `json:"request"`
	Response []byte `json:"response"`
}

func newDurableState(card HubConnectionCard) durableState {
	return durableState{Format: appStateFormat, Version: 1, Connection: card,
		AccountID: card.AccountID, OwnerID: card.OwnerID,
		AccountState: AccountStateLoginRequired, RootState: RootStateUnknown}
}

func decodeDurableState(data []byte) (durableState, error) {
	var state durableState
	if decodeStateJSON(data, &state) != nil || state.Format != appStateFormat || state.Version != 1 ||
		state.AccountState == "" || state.RootState == "" || validateConnectionCard(state.Connection, time.Time{}) != nil {
		return durableState{}, errors.New("invalid encrypted App state")
	}
	if state.Pending != nil {
		if accountRoutes[state.Pending.Operation] == "" || len(state.Pending.Request) == 0 || len(state.Pending.Request) > maxDurablePacketSize ||
			len(state.Pending.Response) > maxDurablePacketSize {
			return durableState{}, errors.New("invalid encrypted App state")
		}
		if _, err := wire.PreflightRequest(state.Pending.Request, state.Pending.Operation); err != nil {
			return durableState{}, errors.New("invalid encrypted App state")
		}
		if len(state.Pending.Response) != 0 {
			if _, err := wire.DecodePacket(state.Pending.Response); err != nil {
				return durableState{}, errors.New("invalid encrypted App state")
			}
		}
	}
	return state, nil
}

func encodeDurableState(state durableState) ([]byte, error) {
	data, err := json.Marshal(state)
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("App state exceeds local vault limit")
	}
	return data, nil
}

func decodeDurableSession(data []byte) (durableSession, error) {
	var session durableSession
	if decodeStateJSON(data, &session) != nil || session.Format != appSessionFormat || session.Version != 1 ||
		len(session.Request) == 0 || len(session.Request) > maxDurablePacketSize || len(session.Response) == 0 || len(session.Response) > maxDurablePacketSize {
		return durableSession{}, errors.New("invalid encrypted App session")
	}
	if _, err := wire.PreflightRequest(session.Request, wire.OperationLoginComplete); err != nil {
		return durableSession{}, errors.New("invalid encrypted App session")
	}
	if _, err := wire.DecodePacket(session.Response); err != nil {
		return durableSession{}, errors.New("invalid encrypted App session")
	}
	return session, nil
}

func encodeDurableSession(session durableSession) ([]byte, error) {
	data, err := json.Marshal(session)
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("App session exceeds local vault limit")
	}
	return data, nil
}

func decodeStateJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing App state")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("noncanonical App state")
	}
	return nil
}
