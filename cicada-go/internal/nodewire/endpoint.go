package nodewire

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	EndpointRegisterOperation    = "node.endpoint.register"
	EndpointLeaveOperation       = "node.endpoint.leave"
	NativePairAvailableOperation = "node.native_pair.available"
)

var (
	ErrEndpointContext     = errors.New("ENDPOINT_CONTEXT_INVALID")
	ErrEndpointConflict    = errors.New("ENDPOINT_STATE_CONFLICT")
	ErrEndpointUnavailable = errors.New("ENDPOINT_NOT_FOUND_OR_NOT_AUTHORIZED")
)

// EndpointRegistration is supplied by the trusted current-thread adapter, not
// by model arguments. Node and Owner are derived from the active PQ binding.
// Metadata is set on creation only; repeating registration never changes it.
type EndpointRegistration struct {
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Name            string `json:"name"`
	Workspace       string `json:"workspace"`
}

type EndpointLeave struct {
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	StateDigest     string `json:"state_digest"`
}

type EndpointRegistrationResult struct {
	EndpointID  string `json:"endpoint_id"`
	Name        string `json:"name"`
	Workspace   string `json:"workspace"`
	Presence    string `json:"presence"`
	Reused      bool   `json:"reused"`
	StateDigest string `json:"state_digest"`
}

type AvailableNativePairSlot struct {
	Slot       string `json:"slot"`
	Generation uint64 `json:"generation"`
}

type AvailableNativePair struct {
	PairID    string                    `json:"pair_id"`
	Label     string                    `json:"label"`
	JoinUntil string                    `json:"join_until"`
	Slots     []AvailableNativePairSlot `json:"slots"`
}

type AvailableNativePairs struct {
	Pairs     []AvailableNativePair `json:"pairs"`
	Truncated bool                  `json:"truncated"`
}

func ValidateEndpointContext(harness, sid string) error {
	if !endpointText(harness, 64) || !endpointText(sid, 256) {
		return ErrEndpointContext
	}
	return nil
}

func (v EndpointRegistration) Validate() error {
	if ValidateEndpointContext(v.Harness, v.NativeSessionID) != nil ||
		!endpointText(v.Name, 256) || !endpointText(v.Workspace, 4096) {
		return ErrEndpointContext
	}
	// Node paths may be Windows paths while Hub runs Linux. Do not clean them
	// against the Hub filesystem or infer a public alias from their basename.
	return nil
}

func (v EndpointLeave) Validate() error {
	if ValidateEndpointContext(v.Harness, v.NativeSessionID) != nil || len(v.StateDigest) != 64 {
		return ErrEndpointContext
	}
	for _, c := range v.StateDigest {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return ErrEndpointContext
			}
		}
	}
	return nil
}

func endpointText(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && strings.TrimSpace(v) == v &&
		!strings.ContainsFunc(v, unicode.IsControl)
}
