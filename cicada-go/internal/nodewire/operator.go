package nodewire

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

const (
	EndpointDirectoryOperation       = "node.endpoints.list"
	NodeOperatorProfile              = "node-operator"
	NodeOperatorContractRevision     = "node-operator-v1"
	NodeOperatorCapabilitiesFormat   = "cicada.node-operator-capabilities.v1"
	MaxNodeOperatorCapabilitiesBytes = 4096
	MaxEndpointDirectoryBytes        = 48 << 10
)

// This is Node-operator metadata, not an Endpoint directory.read grant.
type EndpointDirectoryRequest struct {
	Cursor          string `json:"cursor,omitempty"`
	Limit           int    `json:"limit,omitempty"`
	Harness         string `json:"harness,omitempty"`
	NativeSessionID string `json:"native_session_id,omitempty"`
}

func (q EndpointDirectoryRequest) Validate() error {
	if q.Limit < 0 || q.Limit > 64 || len(q.Cursor) > 256 || strings.TrimSpace(q.Cursor) != q.Cursor || (q.Cursor != "" && !endpointText(q.Cursor, 256)) ||
		(q.Harness == "") != (q.NativeSessionID == "") {
		return ErrEndpointContext
	}
	if q.Harness != "" && (ValidateEndpointContext(q.Harness, q.NativeSessionID) != nil || q.Cursor != "" || (q.Limit != 0 && q.Limit != 1)) {
		return ErrEndpointContext
	}
	return nil
}

type EndpointDirectoryCard struct {
	EndpointID      string `json:"endpoint_id"`
	Name            string `json:"name"`
	Workspace       string `json:"workspace"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Presence        string `json:"presence"`
	StateDigest     string `json:"state_digest"`
}

type EndpointDirectoryResult struct {
	NodeID     string                  `json:"node_id"`
	CapturedAt string                  `json:"captured_at"`
	Freshness  string                  `json:"freshness"`
	Endpoints  []EndpointDirectoryCard `json:"endpoints"`
	NextCursor string                  `json:"next_cursor"`
}

type NodeOperatorCapabilities struct {
	Format                 string   `json:"format"`
	ContractRevision       string   `json:"contract_revision"`
	Available              bool     `json:"available"`
	HubID                  string   `json:"hub_id"`
	NodeControlFingerprint string   `json:"node_control_fingerprint"`
	Operations             []string `json:"operations"`
	MaxPageRows            int      `json:"max_page_rows"`
	MaxPageBytes           int      `json:"max_page_bytes"`
}

func NodeOperatorOperations() []string {
	return []string{EndpointRegisterOperation, EndpointLeaveOperation, NativePairAvailableOperation, EndpointDirectoryOperation}
}

// The pin is the existing Owner-approved Node-Control key, not an unsigned
// replacement identity obtained from this public availability response.
func ParseNodeOperatorCapabilities(raw []byte, binding Binding) (NodeOperatorCapabilities, error) {
	var c NodeOperatorCapabilities
	if len(raw) == 0 || len(raw) > MaxNodeOperatorCapabilitiesBytes {
		return c, ErrEndpointContext
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return NodeOperatorCapabilities{}, ErrEndpointContext
	}
	var extra any
	if d.Decode(&extra) != io.EOF || c.Format != NodeOperatorCapabilitiesFormat || c.ContractRevision != NodeOperatorContractRevision ||
		c.HubID != binding.HubID || c.NodeControlFingerprint != IdentityFingerprint(binding.HubKey) ||
		!reflect.DeepEqual(c.Operations, NodeOperatorOperations()) || c.MaxPageRows != 64 || c.MaxPageBytes != MaxEndpointDirectoryBytes {
		return NodeOperatorCapabilities{}, ErrEndpointContext
	}
	return c, nil
}
