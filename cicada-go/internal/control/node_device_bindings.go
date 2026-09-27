package control

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

const (
	NodeDeviceCodeLifetime    = 10 * time.Minute
	NodeDeviceVerificationURI = "/client/device"
	nodeDeviceCodeAlphabet    = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
)

// NodeDeviceCode is the only information an unauthenticated Node receives
// from the pairing start operation. The Node keeps its own bearer locally;
// Control stores and later activates only its digest.
type NodeDeviceCode struct {
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
}

// StartNodeDeviceBinding creates a short-lived confirmation request. Callers
// must generate the Node bearer locally and submit only its existing
// fabric.HashSessionCredential digest. This method is deliberately unauthenticated
// and therefore returns no status or identity beyond the one-time code and URI.
func (c *Control) StartNodeDeviceBinding(nodeID, nodeName, nodeCredentialDigest string) (*NodeDeviceCode, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node device binding registry is unavailable")
	}
	nodeID = strings.TrimSpace(nodeID)
	nodeName = strings.TrimSpace(nodeName)
	if !validMachineID(nodeID) || nodeName == "" || len(nodeName) > 128 {
		return nil, errors.New("valid node_id and node name are required")
	}
	hubID, err := c.store.GetClientHubID()
	if err != nil {
		return nil, err
	}
	code, err := newNodeDeviceCode()
	if err != nil {
		return nil, err
	}
	expires := time.Now().UTC().Add(NodeDeviceCodeLifetime)
	codeDigest := nodeDeviceCodeDigest(hubID, code)
	if _, err := c.store.CreatePendingNodeDeviceBinding(nodeID, nodeName,
		nodeCredentialDigest, codeDigest, expires); err != nil {
		return nil, err
	}
	return &NodeDeviceCode{
		UserCode: formatNodeDeviceCode(code), VerificationURI: NodeDeviceVerificationURI,
	}, nil
}

// ConfirmNodeDeviceCode is intended only for the authenticated v2 Client RPC
// path. ownerID/deviceID must come from the accepted packet's trusted durable
// binding. Store rechecks the Client device and its active owner grant key in
// the same transaction that consumes the code and activates the credential.
func (c *Control) ConfirmNodeDeviceCode(ownerID, clientDeviceID, userCode string) (*store.NodeDeviceBinding, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node device binding registry is unavailable")
	}
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	code, err := normalizeNodeDeviceCode(userCode)
	if err != nil {
		return nil, err
	}
	hubID, err := c.store.GetClientHubID()
	if err != nil {
		return nil, err
	}
	return c.store.ConfirmPendingNodeDeviceBinding(ownerID, clientDeviceID,
		nodeDeviceCodeDigest(hubID, code))
}

// PreviewNodeDeviceCode is safe only behind the authenticated v2 Client RPC
// route. It shows which Node the code identifies; confirmation remains a
// separate explicit operation that consumes the code and activates its token.
func (c *Control) PreviewNodeDeviceCode(ownerID, clientDeviceID, userCode string) (*store.NodeDeviceBindingRequest, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node device binding registry is unavailable")
	}
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	code, err := normalizeNodeDeviceCode(userCode)
	if err != nil {
		return nil, err
	}
	hubID, err := c.store.GetClientHubID()
	if err != nil {
		return nil, err
	}
	return c.store.PreviewPendingNodeDeviceBinding(ownerID, clientDeviceID,
		nodeDeviceCodeDigest(hubID, code))
}

func (c *Control) NodeDeviceBindings(ownerID string) ([]store.NodeDeviceBinding, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.store.ListNodeDeviceBindings(ownerID)
}

func (c *Control) RevokeNodeDeviceBinding(ownerID, bindingID string, expectedVersion int64) (*store.NodeDeviceBinding, error) {
	if err := c.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, err
	}
	return c.store.RevokeNodeDeviceBinding(ownerID, bindingID, expectedVersion)
}

func newNodeDeviceCode() (string, error) {
	const codeLength = 12
	var random [codeLength]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	code := make([]byte, codeLength)
	for index, value := range random {
		code[index] = nodeDeviceCodeAlphabet[int(value)%len(nodeDeviceCodeAlphabet)]
	}
	return string(code), nil
}

func formatNodeDeviceCode(code string) string {
	if len(code) != 12 {
		return code
	}
	return code[:4] + "-" + code[4:8] + "-" + code[8:]
}

func normalizeNodeDeviceCode(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.NewReplacer("-", "", " ", "").Replace(value)
	if len(value) != 12 {
		return "", errors.New("Node device code must contain 12 characters")
	}
	for _, character := range value {
		if !strings.ContainsRune(nodeDeviceCodeAlphabet, character) {
			return "", errors.New("Node device code contains an invalid character")
		}
	}
	return value, nil
}

func nodeDeviceCodeDigest(hubID, code string) string {
	data := []byte("cicada-node-device-code-v1\x00" + strings.TrimSpace(hubID) + "\x00" + code)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
