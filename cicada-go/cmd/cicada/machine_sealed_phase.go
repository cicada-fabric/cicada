package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
)

const machineSealedPhaseLimit = 32

type machineSealedPhaseKey struct{}
type machineSealedPhaseWriterKey struct{}

type machineSealedPhaseRecord struct {
	Event           string `json:"event"`
	MessageID       string `json:"message_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	EndpointID      string `json:"endpoint_id,omitempty"`
	AttemptID       string `json:"local_attempt_id,omitempty"`
	RemoteAttemptID string `json:"remote_attempt_id,omitempty"`
	NativeSID       string `json:"native_sid,omitempty"`
	Phase           string `json:"phase"`
	State           string `json:"state"`
	ErrorClass      string `json:"error_class"`
}

// One synchronous poll or drain owns this observer. It has no queue, retained payload,
// retry or file output. IDs are bounded identifiers, never arbitrary log text.
type machineSealedPhaseObserver struct {
	writer io.Writer
	record machineSealedPhaseRecord
	rows   int
	active string
}

func machineSealedPhaseID(id string) string {
	if len(id) == 0 || len(id) > 192 {
		return ""
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':') {
			return ""
		}
	}
	return id
}

func newMachineSealedPhaseObserver(ctx context.Context, claim nodeinbox.Claim, entry machineRelayJournalEntry) *machineSealedPhaseObserver {
	// Read the opt-in once per attempt. The default path creates no observer or
	// JSON buffer, and does not wrap the existing lifecycle callback.
	if os.Getenv("CICADA_NODE_SEALED_PHASE_DEBUG") != "1" {
		return nil
	}
	writer, _ := ctx.Value(machineSealedPhaseWriterKey{}).(io.Writer)
	if writer == nil {
		writer = os.Stderr
	}
	return &machineSealedPhaseObserver{writer: writer, record: machineSealedPhaseRecord{
		Event: "NODE_SEALED_PHASE", MessageID: machineSealedPhaseID(claim.MessageID),
		RequestID: machineSealedPhaseID(entry.RequestID), EndpointID: machineSealedPhaseID(claim.EndpointID),
		AttemptID: machineSealedPhaseID(claim.AttemptID), NativeSID: machineSealedPhaseID(claim.SessionID),
		RemoteAttemptID: machineSealedPhaseID(entry.AttemptID),
	}}
}

func newMachineSealedPhaseContext(ctx context.Context, claim nodeinbox.Claim, entry machineRelayJournalEntry) (context.Context, *machineSealedPhaseObserver) {
	observer := newMachineSealedPhaseObserver(ctx, claim, entry)
	if observer == nil {
		return ctx, nil
	}
	ctx = context.WithValue(ctx, machineSealedPhaseKey{}, observer)
	dependencies := machineNativeDeliveryDependencies(ctx)
	previous := dependencies.observe
	dependencies.observe = func(phase string) {
		if previous != nil {
			previous(phase)
		}
		switch phase {
		case "writer_wait":
			observer.enter("WRITER_WAIT")
		case "queue_wait_succeeded":
			observer.emit("QUEUE_WAIT", "END", "NONE")
		case "accepted_durable":
			observer.emit("QUEUE_DURABLE", "END", "NONE")
		case "accepted_writer_closed":
			observer.emit("WRITER_CLOSED", "END", "NONE")
		}
	}
	return context.WithValue(ctx, machineNativeDeliveryLifecycleKey{}, dependencies), observer
}

func machineSealedPhaseFrom(ctx context.Context) *machineSealedPhaseObserver {
	observer, _ := ctx.Value(machineSealedPhaseKey{}).(*machineSealedPhaseObserver)
	return observer
}

func machineSealedPhaseError(err error) string {
	switch {
	case err == nil:
		return "NONE"
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case machineAPIHasStatus(err, http.StatusUnauthorized, http.StatusForbidden):
		return "AUTH_REJECTED"
	case machineAPIHasStatus(err, http.StatusNotFound, http.StatusGone):
		return "NOT_FOUND"
	case machineAPIHasStatus(err, http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity):
		return "AUTHORITY_INVALID"
	case errors.Is(err, os.ErrPermission):
		return "LOCAL_PERMISSION"
	case errors.Is(err, os.ErrNotExist):
		return "LOCAL_NOT_FOUND"
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		if networkError.Timeout() {
			return "TIMEOUT"
		}
		return "NETWORK_IO"
	}
	return "UNCLASSIFIED"
}

func (o *machineSealedPhaseObserver) emit(phase, state, errorClass string) {
	if o == nil || o.rows >= machineSealedPhaseLimit {
		return
	}
	switch phase {
	case "CLAIM_ROUTE", "AUTHORITY_HTTP", "CRYPTO_READ", "SEALED_VALIDATE", "LOCAL_CONTEXT", "OPERATION_SCOPE", "WRITER_WAIT",
		"INBOX_RECOVER", "JOURNAL_OPEN", "SEALED_CLAIM", "SEALED_ACCEPT", "GROUP_CLAIM", "GROUP_ACCEPT", "NETWORK_CLAIM", "NETWORK_ACCEPT", "PLAIN_CLAIM", "PLAIN_ACCEPT", "JOURNAL_RECONCILE", "INBOX_DRAIN",
		"NATIVE_QUEUE", "QUEUE_WAIT", "QUEUE_DURABLE", "WRITER_CLOSED":
	default:
		return
	}
	switch state {
	case "BEGIN", "END", "ERROR":
	default:
		return
	}
	switch errorClass {
	case "NONE", "CANCELLED", "TIMEOUT", "AUTH_REJECTED", "NOT_FOUND", "AUTHORITY_INVALID", "LOCAL_PERMISSION", "LOCAL_NOT_FOUND", "LOCAL_REJECTED", "NETWORK_IO", "UNCLASSIFIED":
	default:
		return
	}
	o.rows++
	record := o.record
	record.Phase, record.State, record.ErrorClass = phase, state, errorClass
	data, err := json.Marshal(record)
	if err == nil {
		// Logging failure cannot change an admission or its original error.
		_, _ = o.writer.Write(append(data, '\n'))
	}
}

func (o *machineSealedPhaseObserver) enter(phase string) {
	if o != nil {
		o.active = phase
		o.emit(phase, "BEGIN", "NONE")
	}
}

func (o *machineSealedPhaseObserver) finish(err error) {
	if o != nil && o.active != "" {
		phase := o.active
		o.active = ""
		o.end(phase, err)
	}
}

func (o *machineSealedPhaseObserver) end(phase string, err error) {
	if o == nil {
		return
	}
	state := "END"
	if err != nil {
		state = "ERROR"
	}
	o.emit(phase, state, machineSealedPhaseError(err))
}

func (o *machineSealedPhaseObserver) reject() {
	if o != nil && o.active != "" {
		o.emit(o.active, "ERROR", "LOCAL_REJECTED")
		o.active = ""
	}
}
