package clientoperator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

type Response struct {
	RequestID   string          `json:"request_id"`
	OperationID string          `json:"operation_id"`
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Recovery    json.RawMessage `json:"recovery,omitempty"`
}

type HTTPError struct {
	Status int
	Code   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Client request returned HTTP %d (%s); saved operation retained", e.Status, e.Code)
}

func (p *Profile) request(ctx context.Context, method, path string, body []byte, want int) ([]byte, error) {
	if err := p.requireUsable(); err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, method, p.state.Origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	response, err := p.client.Do(r)
	if err != nil {
		return nil, errors.New("Client transport failed; saved operation retained")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(data) > 262144 {
		return nil, errors.New("invalid Client response size; saved operation retained")
	}
	if response.StatusCode != want {
		var code struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &code)
		// Only known public recovery codes may enter diagnostics. Server bodies
		// and arbitrary remote strings are never printed.
		switch code.Code {
		case "STILL_PROCESSING", "RECOVERY_REJECTED", "RECOVERY_UNAVAILABLE":
		default:
			code.Code = "REQUEST_REJECTED"
		}
		return nil, &HTTPError{Status: response.StatusCode, Code: code.Code}
	}
	return data, nil
}

func (p *Profile) verifyHub(ctx context.Context) error {
	data, err := p.request(ctx, http.MethodGet, "/v2/client/identity", nil, http.StatusOK)
	if err != nil {
		return err
	}
	var current HubIdentity
	if strictJSON(data, &current) != nil || current.HubID != p.state.Hub.HubID || current.Contract != p.state.Hub.Contract ||
		current.KeyVersion != p.state.Hub.KeyVersion || current.Suite != p.state.Hub.Suite ||
		current.Public.ID != p.state.Hub.Public.ID || !bytes.Equal(current.Public.KEMPublic, p.state.Hub.Public.KEMPublic) ||
		!bytes.Equal(current.Public.SigningPublic, p.state.Hub.Public.SigningPublic) {
		return errors.New("Hub identity differs from the independently supplied full pin")
	}
	return nil
}

type enrollmentBody struct {
	OwnerID      string              `json:"owner_id"`
	OwnerKeyID   string              `json:"owner_key_id"`
	DeviceID     string              `json:"device_id"`
	DevicePublic e2ee.PublicIdentity `json:"device_public_identity"`
	Grant        []byte              `json:"owner_device_grant"`
}

// Enroll preserves the exact grant and body before transport. If the response
// was lost, only the saved request can be retried, including after grant expiry.
func (p *Profile) Enroll(ctx context.Context, grant []byte) error {
	if p.state.Binding != nil {
		return errors.New("Client is already enrolled")
	}
	if p.state.Pending != nil {
		return ErrPending
	}
	if err := p.verifyHub(ctx); err != nil {
		return err
	}
	if p.state.Enrollment == nil {
		at := time.Now().UTC()
		if _, err := e2ee.VerifyOwnerDeviceGrant(grant, p.state.OwnerPublic, p.identity.Public(), p.state.OwnerID,
			p.state.OwnerPublic.ID, p.state.DeviceID, p.state.Hub.HubID, e2ee.OwnerDevicePurposeControl, at); err != nil {
			return errors.New("Owner Grant does not authorize this exact Client, Owner and pinned Hub")
		}
		body, err := json.Marshal(enrollmentBody{p.state.OwnerID, p.state.OwnerPublic.ID, p.state.DeviceID, p.identity.Public(), grant})
		if err != nil {
			return err
		}
		p.state.Enrollment = &enrollment{Body: body, ValidatedAt: at}
		if err = p.save(); err != nil {
			return err
		}
	} else {
		var original enrollmentBody
		if strictJSON(p.state.Enrollment.Body, &original) != nil || !bytes.Equal(original.Grant, grant) {
			return errors.New("pending enrollment requires the exact original Grant")
		}
		if p.state.Enrollment.ValidatedAt.IsZero() || p.state.Enrollment.ValidatedAt.After(time.Now()) {
			return errors.New("invalid enrollment validation time")
		}
		if _, err := e2ee.VerifyOwnerDeviceGrant(grant, p.state.OwnerPublic, p.identity.Public(), p.state.OwnerID,
			p.state.OwnerPublic.ID, p.state.DeviceID, p.state.Hub.HubID, e2ee.OwnerDevicePurposeControl, p.state.Enrollment.ValidatedAt); err != nil {
			return errors.New("saved enrollment Grant does not match current Client identity")
		}
		canonical, _ := json.Marshal(enrollmentBody{p.state.OwnerID, p.state.OwnerPublic.ID, p.state.DeviceID, p.identity.Public(), grant})
		if !bytes.Equal(canonical, p.state.Enrollment.Body) {
			return errors.New("saved enrollment body changed")
		}
	}
	data, err := p.request(ctx, http.MethodPost, "/v2/client/devices/enroll", p.state.Enrollment.Body, http.StatusCreated)
	if err != nil {
		return err
	}
	var reply struct {
		OwnerID          string `json:"owner_id"`
		DeviceID         string `json:"device_id"`
		SessionEpoch     uint64 `json:"session_epoch"`
		DeviceKeyVersion uint64 `json:"device_key_version"`
		State            string `json:"state"`
	}
	if strictJSON(data, &reply) != nil || reply.OwnerID != p.state.OwnerID || reply.DeviceID != p.state.DeviceID || reply.State != "ACTIVE" || reply.SessionEpoch == 0 || reply.DeviceKeyVersion != 1 {
		return errors.New("enrollment response differs from exact Client binding")
	}
	p.state.Binding = &clientwire.Binding{HubID: p.state.Hub.HubID, OwnerID: reply.OwnerID, DeviceID: reply.DeviceID, SessionEpoch: reply.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: reply.DeviceKeyVersion}
	p.state.Enrollment = nil
	return p.save()
}

func (p *Profile) Capabilities(ctx context.Context) (*Response, error) {
	return p.call(ctx, "session.capabilities", struct{}{})
}
func (p *Profile) Status(ctx context.Context) (*Response, error) {
	return p.call(ctx, "status.snapshot", struct{}{})
}
func (p *Profile) Nodes(ctx context.Context) (*Response, error) {
	return p.call(ctx, "nodes.list", struct{}{})
}

func (p *Profile) call(ctx context.Context, operation string, body any) (*Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.state.Binding == nil {
		return nil, errors.New("Client enrollment is required")
	}
	if p.state.Pending != nil {
		return nil, ErrPending
	}
	if p.state.Uncertain && operation == "nodes.confirm" {
		return nil, ErrUncertain
	}
	if p.state.NextRequest == math.MaxUint64 || p.state.NextResponse == math.MaxUint64 {
		return nil, errors.New("Client sequence exhausted")
	}
	if err := p.verifyHub(ctx); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var id [32]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, err
	}
	route := clientwire.Route{Version: 1, Direction: clientwire.DirectionRequest, HubID: p.state.Hub.HubID, OwnerID: p.state.OwnerID,
		DeviceID: p.state.DeviceID, SessionEpoch: p.state.Binding.SessionEpoch, Sequence: p.state.NextRequest, OperationID: "operator-" + hex.EncodeToString(id[:]),
		Operation: operation, SenderKeyID: p.identity.Public().ID, SenderKeyVersion: 1, ReceiverKeyID: p.state.Hub.Public.ID, ReceiverKeyVersion: 1}
	packet, err := clientwire.SealRequest(p.identity, p.state.Hub.Public, *p.state.Binding, route, plaintext)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.state.Pending = &pending{Packet: packet, Route: route, ResponseSequence: p.state.NextResponse}
	if err = p.save(); err != nil {
		return nil, err
	}
	return p.sendPending(ctx, "/v2/client/rpc")
}

// Retry sends only the original durable packet. The Hub's exact retry guard
// returns a cached response or refuses an already accepted uncertain action.
func (p *Profile) Retry(ctx context.Context) (*Response, error) {
	if err := p.verifyHub(ctx); err != nil {
		return nil, err
	}
	return p.sendPending(ctx, "/v2/client/rpc")
}

// Recover never redispatches a business operation, even if it was not accepted.
func (p *Profile) Recover(ctx context.Context) (*Response, error) {
	if err := p.verifyHub(ctx); err != nil {
		return nil, err
	}
	return p.sendPending(ctx, "/v2/client/rpc/recover")
}

func (p *Profile) sendPending(ctx context.Context, path string) (*Response, error) {
	saved := p.state.Pending
	if saved == nil || p.state.Binding == nil {
		return nil, errors.New("no saved Client operation")
	}
	var packet clientwire.Packet
	if strictJSON(saved.Packet, &packet) != nil || packet.Route != saved.Route || saved.Route.Sequence != p.state.NextRequest || saved.ResponseSequence != p.state.NextResponse {
		return nil, errors.New("saved Client packet or counters changed")
	}
	data, err := p.request(ctx, http.MethodPost, path, saved.Packet, http.StatusOK)
	if err != nil {
		return nil, err
	}
	opened, err := clientwire.OpenResponse(p.identity, p.state.Hub.Public, *p.state.Binding, data)
	if err != nil || opened.Route.OperationID != saved.Route.OperationID || opened.Route.Operation != saved.Route.Operation || opened.Route.Sequence != saved.ResponseSequence {
		return nil, errors.New("encrypted response differs from saved Client operation or response sequence")
	}
	var reply Response
	if strictJSON(opened.Plaintext, &reply) != nil || reply.RequestID == "" || reply.OperationID != saved.Route.OperationID {
		return nil, errors.New("invalid authenticated Client response")
	}
	if reply.ErrorCode == "OUTCOME_UNCERTAIN" && saved.Route.Operation == "nodes.confirm" {
		p.state.Uncertain = true
	}
	// Retain a successful preview together with sequence advancement. Losing a
	// response or crashing here must not leave a completed, unreviewable request.
	if saved.Route.Operation == "nodes.preview" && reply.OK {
		var candidate NodeCandidate
		if strictJSON(reply.Result, &candidate) != nil || !validCandidate(candidate, p.state.Hub.HubID) {
			return nil, errors.New("invalid authenticated Node candidate")
		}
		if p.state.Review == nil {
			return nil, errors.New("Node preview has no saved local request")
		}
		p.state.Review.Candidate = candidate
	}
	p.state.NextRequest++
	p.state.NextResponse++
	p.state.Pending = nil
	if saved.Route.Operation == "nodes.confirm" && reply.OK {
		p.state.Review = nil
	}
	if err = p.save(); err != nil {
		return nil, err
	}
	return &reply, nil
}
