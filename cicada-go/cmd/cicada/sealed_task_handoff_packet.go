package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

const sealedTaskHandoffPayloadType = "cicada.shared-task-handoff"

func validTaskHandoffToken(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, ":/\\\r\n\x00")
}

func parseTaskHandoffMessageID(messageID string) (handoffID string, deadline time.Time, ok bool) {
	suffix, found := strings.CutPrefix(messageID, "shared-task-handoff.v1:")
	if !found {
		return "", time.Time{}, false
	}
	millisText, handoffID, found := strings.Cut(suffix, ":")
	millis, err := strconv.ParseInt(millisText, 10, 64)
	if !found || err != nil || millis <= 0 || strconv.FormatInt(millis, 10) != millisText ||
		!validTaskHandoffToken(handoffID) {
		return "", time.Time{}, false
	}
	return handoffID, time.UnixMilli(millis).UTC(), true
}

// The packet carries responsibility prose only inside the signed Endpoint
// envelope. Hub metadata remains the separate authorization DTO.
type sealedTaskHandoffPayload struct {
	Type                 string                               `json:"type"`
	Version              int                                  `json:"version"`
	HandoffID            string                               `json:"handoff_id"`
	TaskID               string                               `json:"task_id"`
	GroupID              string                               `json:"group_id"`
	FromPrincipalID      string                               `json:"from_principal_id"`
	FromEndpointID       string                               `json:"from_endpoint_id"`
	ToPrincipalID        string                               `json:"to_principal_id"`
	ToEndpointID         string                               `json:"to_endpoint_id"`
	TaskRevision         int64                                `json:"task_revision"`
	FromOwnerEpoch       int64                                `json:"from_owner_epoch"`
	MessageID            string                               `json:"message_id"`
	ExpiresAt            string                               `json:"expires_at"`
	RequiredArtifactRefs []store.SealedTaskHandoffArtifactRef `json:"required_artifact_refs"`
	Body                 string                               `json:"body"`
}

func marshalSealedTaskHandoffPayload(payload sealedTaskHandoffPayload) ([]byte, error) {
	if payload.Type != sealedTaskHandoffPayloadType || payload.Version != 1 ||
		payload.HandoffID == "" || payload.TaskID == "" || payload.GroupID == "" ||
		payload.FromPrincipalID == "" || payload.FromEndpointID == "" ||
		payload.ToPrincipalID == "" || payload.ToEndpointID == "" ||
		payload.TaskRevision <= 0 || payload.FromOwnerEpoch <= 0 || payload.MessageID == "" ||
		payload.ExpiresAt == "" || strings.TrimSpace(payload.Body) == "" || len([]byte(payload.Body)) > 60*1024 ||
		len(payload.RequiredArtifactRefs) > 32 {
		return nil, errors.New("invalid sealed Task handoff packet")
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 64*1024 {
		return nil, errors.New("sealed Task handoff packet exceeds the bounded limit")
	}
	return encoded, nil
}

func decodeSealedTaskHandoffPayload(plaintext []byte) (*sealedTaskHandoffPayload, error) {
	if len(plaintext) == 0 || len(plaintext) > 64*1024 {
		return nil, errors.New("sealed Task handoff packet is outside the 64 KiB limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var packet sealedTaskHandoffPayload
	if err := decoder.Decode(&packet); err != nil {
		return nil, errors.New("sealed Task handoff packet is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("sealed Task handoff packet must contain one JSON value")
	}
	canonical, err := marshalSealedTaskHandoffPayload(packet)
	if err != nil || !bytes.Equal(canonical, plaintext) {
		return nil, errors.New("sealed Task handoff packet is not canonical")
	}
	return &packet, nil
}

func validateSealedTaskHandoffAuthorization(delivery fabric.NodeSealedDelivery,
	authorization crossNodeGroupDeliveryAuthorization) error {
	a := authorization.TaskHandoff
	if a == nil || a.HandoffID == "" || a.TaskID == "" || a.GroupID == "" ||
		a.FromPrincipalID == "" || a.FromEndpointID == "" || a.ToPrincipalID == "" ||
		a.ToEndpointID == "" || a.TaskRevision <= 0 || a.FromOwnerEpoch <= 0 ||
		a.MessageID != delivery.MessageID || a.MessageDigest != delivery.Digest ||
		a.GroupID != authorization.Receiver.GroupID || a.FromPrincipalID != authorization.Sender.PrincipalID ||
		a.FromEndpointID != delivery.Route.SenderEndpointID || a.ToPrincipalID != authorization.Receiver.PrincipalID ||
		a.ToEndpointID != delivery.RecipientEndpointID || a.ToEndpointID != delivery.Route.ReceiverEndpointID ||
		delivery.Route.Kind != "send" || delivery.Route.RequestID != "" || delivery.Route.ReplyTo != "" ||
		(a.Status != store.SealedTaskHandoffProposed && a.Status != store.SealedTaskHandoffTransferred) || a.Version <= 0 {
		return errors.New("sealed Task handoff authorization does not match its exact Group route")
	}
	deadline, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if err != nil || deadline.IsZero() || deadline.Nanosecond()%1_000_000 != 0 || !deadline.After(time.Now().UTC()) {
		return errors.New("sealed Task handoff authorization has an invalid or expired deadline")
	}
	handoffID, canonicalDeadline, ok := parseTaskHandoffMessageID(delivery.MessageID)
	if !ok || handoffID != a.HandoffID || canonicalDeadline.Format(time.RFC3339Nano) != a.ExpiresAt {
		return errors.New("sealed Task handoff message ID does not bind its canonical deadline")
	}
	return nil
}

func validateSealedTaskHandoffPayload(authorization *store.SealedTaskHandoffDeliveryAuthorization,
	messageID string, route store.RelaySealedV1Route, plaintext []byte) error {
	reserved := strings.HasPrefix(messageID, "shared-task-handoff.v1:")
	if !reserved {
		if authorization != nil {
			return errors.New("non-handoff Group message carried handoff authorization")
		}
		return nil
	}
	if authorization == nil {
		return errors.New("reserved Task handoff message has no current Hub authorization")
	}
	packet, err := decodeSealedTaskHandoffPayload(plaintext)
	if err != nil {
		return err
	}
	a := authorization
	if packet.HandoffID != a.HandoffID || packet.TaskID != a.TaskID || packet.GroupID != a.GroupID ||
		packet.FromPrincipalID != a.FromPrincipalID || packet.FromEndpointID != a.FromEndpointID ||
		packet.ToPrincipalID != a.ToPrincipalID || packet.ToEndpointID != a.ToEndpointID ||
		packet.TaskRevision != a.TaskRevision || packet.FromOwnerEpoch != a.FromOwnerEpoch ||
		packet.MessageID != messageID || packet.MessageID != a.MessageID || packet.ExpiresAt != a.ExpiresAt ||
		route.Kind != "send" || route.SenderEndpointID != packet.FromEndpointID ||
		route.ReceiverEndpointID != packet.ToEndpointID || route.RequestID != "" || route.ReplyTo != "" {
		return errors.New("decrypted Task handoff packet differs from its current route authorization")
	}
	want, err := json.Marshal(a.RequiredArtifactRefs)
	if err != nil {
		return errors.New("current Task handoff Artifact authorization is invalid")
	}
	got, err := json.Marshal(packet.RequiredArtifactRefs)
	if err != nil || !bytes.Equal(want, got) {
		return errors.New("decrypted Task handoff Artifact references differ from current authorization")
	}
	return nil
}
