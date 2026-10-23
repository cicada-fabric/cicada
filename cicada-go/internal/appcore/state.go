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
	AccountDeviceEnrolled     bool                  `json:"account_device_enrolled,omitempty"`
	Format                    string                `json:"format"`
	Version                   int                   `json:"version"`
	Connection                HubConnectionCard     `json:"connection"`
	Transport                 *localTransportRecord `json:"transport,omitempty"`
	DeviceID                  string                `json:"device_id,omitempty"`
	DeviceKeyID               string                `json:"device_key_id,omitempty"`
	OwnerKeyID                string                `json:"owner_key_id,omitempty"`
	AccountID                 string                `json:"account_id,omitempty"`
	OwnerID                   string                `json:"owner_id,omitempty"`
	Username                  string                `json:"username,omitempty"`
	AccountState              AccountState          `json:"account_state"`
	RootState                 RootState             `json:"root_state"`
	OwnerKeyIDAtHub           string                `json:"owner_key_id_at_hub,omitempty"`
	OwnerFingerprint          string                `json:"owner_fingerprint,omitempty"`
	ClaimChallenge            *wire.ClaimChallenge  `json:"claim_challenge,omitempty"`
	LoginChallenge            *wire.LoginChallenge  `json:"login_challenge,omitempty"`
	Pending                   *pendingOperation     `json:"pending,omitempty"`
	Enrollment                *enrollmentState      `json:"enrollment,omitempty"`
	Recovery                  *pendingOperation     `json:"recovery,omitempty"`
	LastRecovery              *pendingOperation     `json:"last_recovery,omitempty"`
	PreviousActivationReceipt *pendingOperation     `json:"previous_activation_receipt,omitempty"`
	ObservedAccountEpoch      uint64                `json:"observed_account_epoch,omitempty"`
	ObservedDeviceEpoch       uint64                `json:"observed_device_epoch,omitempty"`
	RecoveryHistory           []recoveryDigest      `json:"recovery_history,omitempty"`
}

type recoveryDigest struct {
	Operation string `json:"operation"`
	Digest    string `json:"digest"`
	CreatedAt string `json:"created_at"`
}

type enrollmentState struct {
	Material      wire.ActivationMaterial   `json:"material"`
	Prepare       *wire.ActivationPrepare   `json:"prepare,omitempty"`
	PreparePacket []byte                    `json:"prepare_packet,omitempty"`
	Challenge     *wire.ActivationChallenge `json:"challenge,omitempty"`
	Result        *wire.ActivationResult    `json:"result,omitempty"`
	// The last activation packet is the target of fresh status observations.
	Target *pendingOperation `json:"target,omitempty"`
}

type pendingOperation struct {
	Operation string `json:"operation"`
	Request   []byte `json:"request"`
	Response  []byte `json:"response,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
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
		state.AccountState == "" || state.RootState == "" || validateConnectionCard(state.Connection, time.Time{}) != nil ||
		validateLocalTransport(state.Transport, state.Connection) != nil {
		return durableState{}, errors.New("invalid encrypted App state")
	}
	for _, pending := range []*pendingOperation{state.Pending, state.Recovery, state.LastRecovery, state.PreviousActivationReceipt} {
		if pending == nil {
			continue
		}
		if accountPath(pending.Operation) == "" || len(pending.Request) == 0 || len(pending.Request) > maxDurablePacketSize ||
			len(pending.Response) > maxDurablePacketSize {
			return durableState{}, errors.New("invalid encrypted App state")
		}
		if _, err := wire.PreflightRequest(pending.Request, pending.Operation); err != nil {
			return durableState{}, errors.New("invalid encrypted App state")
		}
		if len(pending.Response) != 0 {
			if _, err := wire.DecodePacket(pending.Response); err != nil {
				return durableState{}, errors.New("invalid encrypted App state")
			}
		}
	}
	if len(state.RecoveryHistory) > 8 || (state.Recovery != nil && state.Pending == nil && state.Enrollment == nil) {
		return durableState{}, errors.New("invalid encrypted App recovery state")
	}
	if state.Enrollment != nil && state.Enrollment.Target == nil && state.Pending != nil &&
		(state.Pending.Operation == wire.OperationActivationPrepare || state.Pending.Operation == wire.OperationActivationComplete) {
		state.Enrollment.Target = state.Pending
	}
	// N1 association was committed atomically with the registered login device.
	if state.Enrollment == nil && state.DeviceID != "" && state.OwnerKeyIDAtHub != "" {
		state.AccountDeviceEnrolled = true
	}
	if e := state.Enrollment; e != nil && e.Target != nil && e.Target.Operation == wire.OperationActivationComplete && e.Result != nil {
		r := e.Result
		if (r.Operation == wire.OperationActivationComplete && r.State == wire.ActivationCompleted) ||
			(r.Operation == wire.OperationActivationStatus && r.TargetOperation == wire.OperationActivationComplete && r.TargetState == wire.ActivationCompleted && len(r.ReceiptPacket) != 0) {
			state.AccountDeviceEnrolled = true
		}
	}
	return state, nil
}

func encodeDurableState(state durableState) ([]byte, error) {
	// While activation itself occupies the main slot, retain its exact packet
	// once. After login replaces that slot, Target retains the activation bytes
	// needed for authenticated status. This bounds nested recovery receipts.
	if state.Enrollment != nil && state.Enrollment.Target != nil && state.Pending != nil &&
		state.Enrollment.Target.Operation == state.Pending.Operation && bytes.Equal(state.Enrollment.Target.Request, state.Pending.Request) {
		e := *state.Enrollment
		e.Target = nil
		state.Enrollment = &e
	}
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
